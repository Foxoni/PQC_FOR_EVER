#!/usr/bin/env bash
# =============================================================================
# pqc_bench.sh — Benchmark PQC vs Cryptographie Classique sur réseau PME
# Projet de recherche — Guardia Cybersecurity School
#
# Usage : ./pqc_bench.sh --help
# Dépendances : openssl 3.x, oqs-provider, python3, nmap, tc
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# VERSION & CHEMINS
# =============================================================================
VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PY="${SCRIPT_DIR}/traffic_gen.py"

# =============================================================================
# VALEURS PAR DÉFAUT (surchargeables par CLI)
# =============================================================================
OUTPUT_DIR="${SCRIPT_DIR}/results"
TARGET=""
SERVER_IP=""
VM_ID=0
DURATION=30
MODE="classic"
PROFILES="all"
WAN_PROFILE="eu"
HANDSHAKE_COUNT=100
PRESET=""
ACTION="test"
SCAN_SUBNET=""
COLLECT_FILE=""

# =============================================================================
# PORTS
# =============================================================================
PORT_TLS=8443
PORT_MARKER=9999
TRAFFIC_PORT=5300      # TCP : file, stream, web, msg, voip (controle), jitter
TRAFFIC_UDP_PORT=5301  # UDP : voip et jitter (donnees bidirectionnelles)

# =============================================================================
# SUITES DE CHIFFREMENT TLS 1.3
# mlkem512 → AES-128-GCM (Cat.1, même niveau de sécurité symétrique)
# Tous les autres modes (classic inclus) → AES-256-GCM
# (Grover réduit AES-128 à ~64 bits face à un ordinateur quantique)
# =============================================================================
CIPHER_128="TLS_AES_128_GCM_SHA256"
CIPHER_256="TLS_AES_256_GCM_SHA384"

# Groupes TLS pour l'échange de clé (noms oqs-provider)
# Les modes sans entrée utilisent le groupe par défaut (X25519)
declare -A OQS_KEM_GROUP=(
    [mlkem512]="mlkem512"
    [mlkem768]="mlkem768"
    [mlkem1024]="mlkem1024"
    [hybrid-kem]="X25519MLKEM768"    # Mode 1 : hybride KEM seul
    [hybrid-full]="X25519MLKEM768"   # Mode 2 : hybride KEM + signature
    [slhdsa128]="X25519MLKEM768"     # Mode 5a : SLH-DSA + KEM hybride
    [slhdsa256]="X25519MLKEM768"     # Mode 5b : SLH-DSA-256 + KEM hybride
)

# Algorithmes de signature OQS pour la génération de certificats
# Les modes absents utilisent ECDSA P-256 (openssl standard)
declare -A OQS_SIG_ALG=(
    [mldsa44]="mldsa44"
    [mldsa65]="mldsa65"
    [mldsa87]="mldsa87"
    [hybrid-full]="p384_mldsa65"            # ECDSA P-384 + ML-DSA-65 (composite)
    [slhdsa128]="sphincssha2128ssimple"     # SLH-DSA-128s (FIPS 205)
    [slhdsa256]="sphincssha2256ssimple"     # SLH-DSA-256s (FIPS 205)
)

# Profils de latence WAN simulée via tc-netem
declare -A WAN_DELAY=(  [fr]="15ms"   [eu]="35ms"   [us]="80ms"  )
declare -A WAN_JITTER=( [fr]="3ms"    [eu]="8ms"    [us]="15ms"  )
declare -A WAN_LOSS=(   [fr]="0.05%"  [eu]="0.1%"   [us]="0.2%"  )

# =============================================================================
# MÉTRIQUES RÉSEAU — initialisées à -1 (convention "non mesuré")
# =============================================================================
NET_PING_MOY=-1; NET_PING_MIN=-1; NET_PING_MAX=-1; NET_PING_P99=-1
NET_JITTER=-1
NET_LOSS_PCT=-1; NET_LOSS_UDP_PCT=-1
HS_PKTS=-1; HS_BYTES=-1; HS_FRAG_PCT=-1
TCP_CONNECT_MS=-1; TTFB_MS=-1
CONN_ERRORS=0

# Capacités détectées au démarrage (set par check_network_caps)
CAN_HPING3=false; CAN_FPING=false; CAN_TSHARK=false
CAN_CURL=false; CAN_CAPTURE=false

# PIDs et fichiers temporaires des mesures en arrière-plan
_PING_PID=0; _PING_FILE=""
_JITTER_PID=0; _JITTER_FILE=""
_TSHARK_PID=0; _TSHARK_PCAP=""

# =============================================================================
# COULEURS (désactivées si pas de TTY)
# =============================================================================
if [[ -t 1 ]]; then
    RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
    BLUE='\033[0;34m' CYAN='\033[0;36m' BOLD='\033[1m' NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# =============================================================================
# UTILITAIRES
# =============================================================================
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERR]${NC}   $*" >&2; }
log_section() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${NC}\n"; }
die()         { log_error "$*"; exit 1; }

has_cmd()       { command -v "$1" &>/dev/null; }
require_root()  { [[ $EUID -eq 0 ]] || die "Nécessite sudo : sudo $0 $*"; }
timestamp()     { date +"%Y%m%dT%H%M%S"; }
now_ms()        { local t; t=$(date +%s%N); echo $(( t / 1000000 )); }  # ms : divise ns par 1e6 (compatible toutes versions de date)

local_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [[ -z "$ip" ]]; then
        log_warn "Impossible de détecter l'IP locale — utilisation de 127.0.0.1"
        ip="127.0.0.1"
    fi
    echo "$ip"
}

net_iface() {
    local iface
    iface=$(ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    if [[ -z "$iface" ]]; then
        iface=$(ip route show default 2>/dev/null | awk '/dev/ {print $5; exit}')
    fi
    echo "${iface:-eth0}"
}

# =============================================================================
# INSTALLATION DES DÉPENDANCES
# =============================================================================

cmd_install() {
    log_section "Installation des dépendances"
    require_root

    apt-get update -qq || log_warn "apt-get update a échoué — les paquets peuvent être obsolètes"
    apt-get install -y \
        nmap hping3 fping tcpdump tshark \
        openssl python3 python3-pip \
        curl wget git cmake gcc g++ \
        libtool libssl-dev pkg-config \
        iproute2 net-tools bc netcat-openbsd \
        || die "apt-get install a échoué — vérifiez votre connexion et vos sources APT"

    # Packages Python
    if ! pip3 install --quiet scapy psutil 2>/dev/null; then
        pip3 install --quiet --break-system-packages scapy psutil \
            || log_warn "pip3 install échoué — scapy/psutil peuvent être absents (monitoring CPU/RAM et trafic msg désactivés)"
    fi

    if openssl list -providers 2>/dev/null | grep -q oqsprovider; then
        log_ok "oqs-provider déjà installé"
    else
        _build_oqs_provider
    fi

    log_ok "Installation terminée — relancez sans sudo pour tester"
}

_build_oqs_provider() {
    local build="/tmp/oqs_build_$$"
    mkdir -p "$build"
    local log_file="/tmp/oqs_build_$$.log"

    log_info "Compilation de liboqs (Open Quantum Safe) — peut prendre 5-10 min..."
    git clone --depth 1 \
        https://github.com/open-quantum-safe/liboqs.git \
        "$build/liboqs" >> "$log_file" 2>&1 \
        || die "git clone liboqs échoué (voir $log_file)"

    cmake -S "$build/liboqs" -B "$build/liboqs/build" -Wno-dev \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        >> "$log_file" 2>&1 \
        || die "cmake liboqs échoué (voir $log_file)"
    make -C "$build/liboqs/build" -j"$(nproc)" install >> "$log_file" 2>&1 \
        || die "make liboqs échoué (voir $log_file)"
    ldconfig

    log_info "Compilation de oqs-provider pour OpenSSL 3..."
    git clone --depth 1 \
        https://github.com/open-quantum-safe/oqs-provider.git \
        "$build/oqs-provider" >> "$log_file" 2>&1 \
        || die "git clone oqs-provider échoué (voir $log_file)"

    cmake -S "$build/oqs-provider" -B "$build/oqs-provider/build" -Wno-dev \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        >> "$log_file" 2>&1 \
        || die "cmake oqs-provider échoué (voir $log_file)"
    make -C "$build/oqs-provider/build" -j"$(nproc)" install >> "$log_file" 2>&1 \
        || die "make oqs-provider échoué (voir $log_file)"

    _register_oqs_provider
    rm -rf "$build" "$log_file"
    log_ok "oqs-provider compilé et installé"
}

_register_oqs_provider() {
    local cnf
    cnf="$(openssl version -d | awk -F'"' '{print $2}')/openssl.cnf"
    grep -q oqsprovider "$cnf" 2>/dev/null && return

    # Détecter le chemin réel : cmake choisit le répertoire de modules de
    # l'OpenSSL système, qui varie selon la distro (Ubuntu 24+: /usr/lib/x86_64-linux-gnu/...)
    local provider_so
    provider_so=$(find /usr /opt -name "oqsprovider.so" 2>/dev/null | head -1)
    [[ -n "$provider_so" ]] || die "oqsprovider.so introuvable après compilation — consultez le log de build"

    cat >> "$cnf" <<CONF

# --- oqs-provider (Post-Quantum) ---
[provider_sect]
default     = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
module   = ${provider_so}
activate = 1
CONF
    log_ok "oqs-provider enregistré dans $cnf (module: $provider_so)"
}

check_deps() {
    local all_ok=true
    for cmd in openssl python3 ip tc; do
        has_cmd "$cmd" || { log_warn "Commande manquante : $cmd"; all_ok=false; }
    done
    openssl list -providers 2>/dev/null | grep -q oqsprovider \
        || log_warn "oqs-provider absent → modes PQC indisponibles (sudo $0 --install)"
    [[ -f "$SCRIPT_PY" ]] \
        || log_warn "traffic_gen.py introuvable dans $SCRIPT_DIR"
    [[ -f "$SCRIPT_DIR/traffic_server.py" ]] \
        || log_warn "traffic_server.py introuvable dans $SCRIPT_DIR — trafic indisponible"

    # Outils optionnels — absence = métriques réseau partielles (-1 dans le CSV)
    has_cmd hping3  || log_warn "hping3 absent  → TCP_connect_ms et Ping_p99_ms indisponibles"
    has_cmd tshark  || log_warn "tshark absent  → métriques handshake réseau indisponibles (Fragmentation_pct, Handshake_paquets, Handshake_octets)"
    has_cmd fping   || true   # fallback silencieux vers hping3 / ping

    check_network_caps
    $all_ok
}

check_network_caps() {
    has_cmd hping3 && CAN_HPING3=true  || CAN_HPING3=false
    has_cmd fping  && CAN_FPING=true   || CAN_FPING=false
    has_cmd tshark && CAN_TSHARK=true  || CAN_TSHARK=false
    has_cmd curl   && CAN_CURL=true    || CAN_CURL=false
    # Capture réseau = tshark disponible ET (root OU CAP_NET_RAW sur l'exécutable)
    local has_cap=false
    if [[ $EUID -eq 0 ]]; then
        has_cap=true
    elif has_cmd getcap && getcap "$(command -v tshark)" 2>/dev/null | grep -q "cap_net_raw"; then
        has_cap=true
    fi
    if $CAN_TSHARK && $has_cap; then
        CAN_CAPTURE=true
    else
        CAN_CAPTURE=false
        if $CAN_TSHARK; then
            log_warn "tshark présent mais droits insuffisants → capture désactivée"
            log_warn "  Option A : sudo python3 vm_agent.py (ou sudo ./pqc_bench.sh --test ...)"
            log_warn "  Option B : sudo setcap cap_net_raw,cap_net_admin=eip \$(which tshark)"
        fi
    fi
}

# =============================================================================
# MESURES RÉSEAU EN ARRIÈRE-PLAN
# =============================================================================

# Lance ping en continu pendant un événement de trafic.
# Appeler net_ping_start avant l'événement, net_ping_stop après.
net_ping_start() {
    local target="$1" duration="${2:-60}"
    if ! has_cmd ping; then
        log_warn "ping absent — métriques RTT indisponibles"
        _PING_PID=0; return
    fi
    _PING_FILE="/tmp/pqc_ping_$$.txt"
    local count=$(( duration * 2 + 30 ))   # 2 pings/s + marge
    ping -c "$count" -i 0.5 "$target" > "$_PING_FILE" 2>&1 &
    _PING_PID=$!
    sleep 0.2
    if ! kill -0 "$_PING_PID" 2>/dev/null; then
        log_warn "ping vers $target n'a pas démarré (hôte injoignable ?)"
        _PING_PID=0
    fi
}

net_ping_stop() {
    # SIGINT (pas SIGTERM) pour que ping imprime son résumé statistique avant de quitter
    [[ "$_PING_PID" -gt 0 ]] && { kill -INT "$_PING_PID" 2>/dev/null; wait "$_PING_PID" 2>/dev/null || true; }
    _PING_PID=0
    if [[ ! -f "$_PING_FILE" ]]; then
        NET_PING_MOY=-1; NET_PING_MIN=-1; NET_PING_MAX=-1; NET_PING_P99=-1; NET_LOSS_PCT=-1
        return
    fi
    # min/avg/max depuis la ligne "rtt min/avg/max/mdev"
    local stats
    stats=$(grep -E "^rtt|^round-trip" "$_PING_FILE" | grep -oE "[0-9]+\.[0-9]+/[0-9]+\.[0-9]+/[0-9]+\.[0-9]+" || true)
    if [[ -n "$stats" ]]; then
        NET_PING_MIN=$(echo "$stats" | cut -d'/' -f1)
        NET_PING_MOY=$(echo "$stats" | cut -d'/' -f2)
        NET_PING_MAX=$(echo "$stats" | cut -d'/' -f3)
        # P99 calculé sur les RTT individuels
        NET_PING_P99=$(grep -oE "time=[0-9.]+" "$_PING_FILE" | cut -d= -f2 \
            | python3 -c "
import sys, statistics
vals = sorted(float(l) for l in sys.stdin if l.strip())
if not vals: print(-1)
else:
    idx = max(0, int(len(vals) * 0.99) - 1)
    print(round(vals[idx], 2))" 2>/dev/null || echo -1)
    else
        NET_PING_MOY=-1; NET_PING_MIN=-1; NET_PING_MAX=-1; NET_PING_P99=-1
    fi
    local loss
    loss=$(grep -oE "[0-9.]+% packet loss" "$_PING_FILE" | grep -oE "[0-9.]+" || true)
    NET_LOSS_PCT="${loss:--1}"
    rm -f "$_PING_FILE"; _PING_FILE=""
}

# Lance une mesure jitter UDP en arrière-plan via traffic_server.py.
# Pertinent uniquement sur voip/stream — utilisé au niveau du run global.
net_jitter_start() {
    local target="$1" duration="${2:-60}"
    if [[ ! -f "$SCRIPT_DIR/traffic_server.py" ]]; then
        log_warn "traffic_server.py absent — métriques jitter/perte UDP indisponibles"
        _JITTER_PID=0; return
    fi
    _JITTER_FILE="/tmp/pqc_jitter_$$.json"
    python3 "$SCRIPT_PY" jitter "$target" "$duration" "$_JITTER_FILE" &
    _JITTER_PID=$!
}

net_jitter_stop() {
    [[ "$_JITTER_PID" -gt 0 ]] && wait "$_JITTER_PID" 2>/dev/null || true
    _JITTER_PID=0
    if [[ ! -f "$_JITTER_FILE" ]]; then
        NET_JITTER=-1; NET_LOSS_UDP_PCT=-1; return
    fi
    IFS=' ' read -r NET_JITTER NET_LOSS_UDP_PCT < <(python3 - "$_JITTER_FILE" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(round(float(d.get("jitter_ms", -1)), 3),
          round(float(d.get("lost_pct",   -1)), 3))
except Exception:
    print(-1, -1)
PYEOF
)
    rm -f "$_JITTER_FILE"; _JITTER_FILE=""
}

# Mesure le temps d'établissement TCP seul (avant TLS).
measure_tcp_connect() {
    local target="$1" port="${2:-$PORT_TLS}"
    if $CAN_HPING3; then
        local raw
        raw=$(hping3 -S -c 3 -p "$port" "$target" 2>/dev/null \
            | grep -oE "rtt=[0-9.]+" | grep -oE "[0-9.]+" || true)
        if [[ -n "$raw" ]]; then
            TCP_CONNECT_MS=$(echo "$raw" \
                | python3 -c "import sys,statistics; v=[float(l) for l in sys.stdin if l.strip()]; print(round(statistics.mean(v),2) if v else -1)" \
                2>/dev/null || echo -1)
            return
        fi
    fi
    # Fallback : /dev/tcp bash builtin
    local t0 t1
    t0=$(now_ms)
    if bash -c "exec 3>/dev/tcp/${target}/${port}" 2>/dev/null; then
        t1=$(now_ms); TCP_CONNECT_MS=$(( t1 - t0 ))
    else
        TCP_CONNECT_MS=-1
    fi
}

# Mesure le TTFB (TCP + TLS handshake complet) via openssl s_client avec les bons providers.
# curl ne supporte pas oqs-provider → impossible de négocier X25519MLKEM768/OQS.
# On réutilise openssl s_client (même binaire que le reste du bench) pour une mesure cohérente.
measure_ttfb() {
    local target="$1" port="${2:-$PORT_TLS}"
    local mode="${3:-$MODE}" cipher="${4:-}" provider_arg="${5:-}" groups_arg="${6:-}"
    [[ -z "$cipher" ]]       && cipher=$(get_cipher "$mode")
    [[ -z "$provider_arg" ]] && provider_arg=$(get_provider_args "$mode")
    [[ -z "$groups_arg" ]]   && groups_arg=$(get_groups_arg "$mode")

    local t0 t1
    t0=$(now_ms)
    # shellcheck disable=SC2086
    openssl s_client \
        -connect "${target}:${port}" \
        -tls1_3 \
        -ciphersuites "$cipher" \
        $groups_arg $provider_arg \
        -no_ign_eof \
        </dev/null 2>/dev/null
    local rc=$?
    t1=$(now_ms)
    if [[ $rc -eq 0 ]]; then
        TTFB_MS=$(( t1 - t0 ))
    else
        TTFB_MS=-1
    fi
}

# Démarre une capture tshark sur un handshake (le premier uniquement).
capture_hs_start() {
    local target="$1" port="${2:-$PORT_TLS}"
    if ! $CAN_CAPTURE; then return; fi
    _TSHARK_PCAP="/tmp/pqc_hs_cap_$$.pcap"

    # Interface vers la cible précise (pas 1.1.1.1 qui peut passer ailleurs)
    local iface
    iface=$(ip route get "$target" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
    iface="${iface:-$(net_iface)}"

    local tshark_log="/tmp/pqc_tshark_$$.log"
    tshark -i "$iface" -f "host ${target} and port ${port}" \
        -w "$_TSHARK_PCAP" > "$tshark_log" 2>&1 &
    _TSHARK_PID=$!

    # Attendre que tshark ait écrit l'en-tête PCAP (fichier non vide = capture active)
    # Timeout : 1s (10 × 100ms) pour supporter les VMs sous charge
    local i=0
    while [[ $i -lt 10 ]] && ! [[ -s "$_TSHARK_PCAP" ]]; do
        sleep 0.1
        (( i++ )) || true
    done

    if ! kill -0 "$_TSHARK_PID" 2>/dev/null; then
        log_warn "tshark n'a pas démarré sur $iface — $(head -1 "$tshark_log" 2>/dev/null)"
        rm -f "$tshark_log" "$_TSHARK_PCAP"
        _TSHARK_PID=0; _TSHARK_PCAP=""
    elif ! [[ -s "$_TSHARK_PCAP" ]]; then
        log_warn "tshark actif mais PCAP vide après 1s (interface: $iface) — capture ignorée"
        kill "$_TSHARK_PID" 2>/dev/null; wait "$_TSHARK_PID" 2>/dev/null || true
        rm -f "$tshark_log" "$_TSHARK_PCAP"
        _TSHARK_PID=0; _TSHARK_PCAP=""
    fi
    rm -f "$tshark_log"
}

capture_hs_stop() {
    [[ "$_TSHARK_PID" -le 0 ]] && return
    sleep 0.1   # laisser arriver les derniers paquets
    kill "$_TSHARK_PID" 2>/dev/null; wait "$_TSHARK_PID" 2>/dev/null || true
    _TSHARK_PID=0
    if [[ ! -f "$_TSHARK_PCAP" ]]; then
        HS_PKTS=-1; HS_BYTES=-1; HS_FRAG_PCT=-1; return
    fi
    IFS=' ' read -r HS_PKTS HS_BYTES HS_FRAG_PCT < <(python3 - "$_TSHARK_PCAP" <<'PYEOF'
import sys, subprocess
pcap = sys.argv[1]
try:
    r = subprocess.run(
        ["tshark", "-r", pcap, "-T", "fields",
         "-e", "frame.len", "-e", "ip.flags.mf", "-e", "ip.frag_offset"],
        capture_output=True, text=True)
    pkts = 0; total_bytes = 0; frag = 0
    for line in r.stdout.strip().splitlines():
        parts = line.split("\t")
        if not parts: continue
        pkts += 1
        try: total_bytes += int(parts[0])
        except (ValueError, IndexError): pass
        mf = parts[1] if len(parts) > 1 else ""
        fo = parts[2] if len(parts) > 2 else ""
        if mf == "1" or (fo and fo != "0"): frag += 1
    print(pkts, total_bytes, round(frag / pkts * 100, 2) if pkts else -1)
except Exception:
    print(-1, -1, -1)
PYEOF
)
    rm -f "$_TSHARK_PCAP"; _TSHARK_PCAP=""
}

# =============================================================================
# HELPERS CRYPTO
# =============================================================================
CERT_DIR="/tmp/pqc_certs_$$"
KEY_SIZE=0
CERT_SIZE=0

get_cipher() {
    # mlkem512 (Cat.1) reste en AES-128 ; tout le reste passe en AES-256
    case "$1" in
        mlkem512) echo "$CIPHER_128" ;;
        *)        echo "$CIPHER_256"  ;;
    esac
}

get_aes_bits() {
    case "$1" in
        mlkem512) echo "128" ;;
        *)        echo "256" ;;
    esac
}

get_provider_args() {
    # Un token par ligne pour rester compatible avec IFS=$'\n\t' (pas de split sur espace)
    case "$1" in
        classic) : ;;
        *) printf '%s\n' -provider oqsprovider -provider default ;;
    esac
}

get_groups_arg() {
    local grp="${OQS_KEM_GROUP[$1]:-}"
    # Un token par ligne pour rester compatible avec IFS=$'\n\t'
    [[ -n "$grp" ]] && printf '%s\n' -groups "$grp" || true
}

# Vrai si le mode utilise un certificat OQS (signature post-quantique ou hybride)
is_sig_mode() {
    [[ "$1" == mldsa* || "$1" == "hybrid-full" || "$1" == slhdsa* ]]
}

# Vrai si le mode utilise un échange de clé post-quantique
is_kem_mode() {
    [[ "$1" == mlkem* || "$1" == "hybrid-kem" || "$1" == "hybrid-full" || "$1" == slhdsa* ]]
}

_openssl_run() {
    local err
    if ! err=$(openssl "$@" 2>&1); then
        log_error "openssl $* → échec"
        log_error "$err"
        return 1
    fi
}

crypto_gen_certs() {
    local mode="$1"
    mkdir -p "$CERT_DIR"
    log_info "Génération des certificats (mode: $mode)..."

    local sig_alg="${OQS_SIG_ALG[$mode]:-}"

    if [[ -n "$sig_alg" ]]; then
        # mldsa*, hybrid-full, slhdsa* : certificat OQS (pure ou composite)
        _openssl_run genpkey -algorithm "$sig_alg" \
            -provider oqsprovider -provider default \
            -out "$CERT_DIR/server.key" \
            || {
                log_warn "Algorithmes de signature disponibles dans oqs-provider :"
                openssl list -signature-algorithms \
                    -provider oqsprovider -provider default 2>/dev/null \
                    | grep -i "dsa\|slh\|sphincs\|p256\|p384" || true
                die "Algorithme '${sig_alg}' non supporté par ce build d'oqs-provider — vérifiez la liste ci-dessus"
            }
        _openssl_run req -new -x509 \
            -key "$CERT_DIR/server.key" \
            -out "$CERT_DIR/server.crt" \
            -days 1 -subj "/CN=pqc-bench" \
            -provider oqsprovider -provider default \
            || die "Génération du certificat OQS impossible"
    else
        # classic, mlkem*, hybrid-kem : ECDSA P-256
        # (ML-KEM gère uniquement l'échange de clé, pas la signature)
        _openssl_run ecparam -name prime256v1 -genkey -noout \
            -out "$CERT_DIR/server.key" \
            || die "Génération de la clé ECDSA P-256 impossible"
        _openssl_run req -new -x509 \
            -key "$CERT_DIR/server.key" \
            -out "$CERT_DIR/server.crt" \
            -days 1 -subj "/CN=pqc-bench" \
            || die "Génération du certificat ECDSA impossible"
    fi

    KEY_SIZE=$(wc -c < "$CERT_DIR/server.key")
    CERT_SIZE=$(wc -c < "$CERT_DIR/server.crt")
    log_ok "Certificat : ${CERT_SIZE} B | Clé : ${KEY_SIZE} B"
}

# =============================================================================
# MESURE DU HANDSHAKE TLS
# =============================================================================
HS_MIN=0; HS_AVG=0; HS_MAX=0; HS_P99=0

measure_handshake() {
    local mode="$1" target="$2" count="${3:-$HANDSHAKE_COUNT}"
    local cipher provider_arg groups_arg timing_file

    cipher=$(get_cipher "$mode")
    provider_arg=$(get_provider_args "$mode")
    groups_arg=$(get_groups_arg "$mode")
    timing_file="/tmp/pqc_hs_$$.txt"
    : > "$timing_file"

    log_info "Mesure handshake TLS ($count itérations, cible: ${target}:${PORT_TLS})..."

    # Métriques réseau one-shot (avant le bulk, sur une connexion propre)
    measure_tcp_connect "$target" "$PORT_TLS"
    measure_ttfb        "$target" "$PORT_TLS" "$mode" "$cipher" "$provider_arg" "$groups_arg"

    local errors=0 t0 t1 ms capture_done=false
    for _ in $(seq 1 "$count"); do
        # Capturer le premier handshake uniquement (représentatif, évite le bruit)
        if ! $capture_done; then
            capture_hs_start "$target" "$PORT_TLS"
        fi

        t0=$(now_ms)
        # shellcheck disable=SC2086
        # -verify_return_error retiré : le cert est auto-signé (code 18), ce qui ferait
        # échouer chaque mesure alors que le handshake TLS est valide. On détecte l'échec
        # réel (ECONNREFUSED, handshake avorté) sur le code de retour sans ce flag.
        if openssl s_client \
            -connect "${target}:${PORT_TLS}" \
            -tls1_3 \
            -ciphersuites "$cipher" \
            $groups_arg $provider_arg \
            -CAfile "$CERT_DIR/server.crt" \
            -no_ign_eof \
            </dev/null 2>/dev/null; then
            t1=$(now_ms)
            ms=$(( t1 - t0 ))
            echo "$ms" >> "$timing_file"
        else
            (( errors++ )) || true
        fi

        if ! $capture_done; then
            capture_hs_stop
            capture_done=true
        fi
    done
    CONN_ERRORS=$errors

    if [[ "$errors" -eq "$count" ]]; then
        rm -f "$timing_file"
        die "Toutes les connexions TLS ont échoué (${errors}/${count}) — vérifiez que le serveur tourne en mode '${MODE}' sur ${TARGET}:${PORT_TLS}"
    fi

    # Calcul des percentiles via Python
    local stats_out
    if stats_out=$(python3 "$SCRIPT_PY" stats "$timing_file" 2>/dev/null); then
        IFS=' ' read -r HS_MIN HS_AVG HS_MAX HS_P99 <<< "$stats_out"
    else
        log_warn "Calcul des statistiques handshake échoué — valeurs mises à 0"
        HS_MIN=0; HS_AVG=0; HS_MAX=0; HS_P99=0
    fi
    rm -f "$timing_file"

    log_ok "Handshake ─ min:${HS_MIN}ms moy:${HS_AVG}ms max:${HS_MAX}ms p99:${HS_P99}ms | erreurs:${errors}/${count}"
    log_ok "Réseau    ─ TCP_connect:${TCP_CONNECT_MS}ms TTFB:${TTFB_MS}ms | pkts:${HS_PKTS} bytes:${HS_BYTES} frag:${HS_FRAG_PCT}%"
}

# =============================================================================
# MONITORING CPU / RAM (délégué à traffic_gen.py)
# =============================================================================
MONITOR_PID=""
MONITOR_FILE="/tmp/pqc_monitor_$$.csv"
CPU_AVG=0; RAM_AVG=0

start_monitor() {
    python3 "$SCRIPT_PY" monitor "$MONITOR_FILE" &
    MONITOR_PID=$!
}

stop_monitor() {
    [[ -z "${MONITOR_PID:-}" ]] && return
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    MONITOR_PID=""

    if [[ -f "$MONITOR_FILE" ]]; then
        local result
        if result=$(python3 "$SCRIPT_PY" avgres "$MONITOR_FILE" 2>/dev/null); then
            IFS=' ' read -r CPU_AVG RAM_AVG <<< "$result"
        else
            log_warn "Lecture monitoring CPU/RAM échouée — valeurs mises à 0"
            CPU_AVG=0; RAM_AVG=0
        fi
        rm -f "$MONITOR_FILE"
    fi
    log_info "CPU moy: ${CPU_AVG}% | RAM moy: ${RAM_AVG} MB"
}

# =============================================================================
# PROFILS DE TRAFIC — s'exécutent en PARALLÈLE via jobs Bash
# =============================================================================
TRAFFIC_PIDS=()
TRAFFIC_RESULTS=()

# --- Navigation web : petites requêtes TCP répétées en rafale ---
traffic_web() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_web_$$.json"
    log_info "  [web]    navigation HTTP — bursts TCP, petits paquets, 2 Mbps"
    python3 "$SCRIPT_PY" client web "$target" "$duration" "$result" &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("web:$result")
}

# --- Téléchargement fichier : flux TCP soutenu, gros buffers ---
traffic_file() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_file_$$.json"
    log_info "  [file]   upload/download PDF — TCP soutenu, gros buffers"
    python3 "$SCRIPT_PY" client file "$target" "$duration" "$result" &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("file:$result")
}

# --- Visioconférence : UDP bidirectionnel 30 Mbps ---
traffic_voip() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_voip_$$.json"
    log_info "  [voip]   visioconférence — UDP 1300B, ~30 Mbps, bidir"
    python3 "$SCRIPT_PY" client voip "$target" "$duration" "$result" &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("voip:$result")
}

# --- Streaming vidéo : TCP, gros débit descendant (serveur→client) ---
traffic_stream() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_stream_$$.json"
    log_info "  [stream] streaming vidéo — TCP inverse, haut débit"
    python3 "$SCRIPT_PY" client stream "$target" "$duration" "$result" &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("stream:$result")
}

# --- Messagerie : très petits paquets TCP, 200 Kbps ---
traffic_msg() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_msg_$$.json"
    log_info "  [msg]    messagerie/email — TCP 150B, 200 Kbps"
    python3 "$SCRIPT_PY" client msg "$target" "$duration" "$result" &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("msg:$result")
}

wait_traffic() {
    log_info "Attente fin des flux de trafic..."
    local pid
    for pid in "${TRAFFIC_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    TRAFFIC_PIDS=()
}

# =============================================================================
# COLLECTE ET ÉCRITURE DES MÉTRIQUES → CSV
# =============================================================================
collect_metrics() {
    local mode="$1" profiles_label="$2" target="$3"
    local ts vm_ip cipher aes_bits out_file

    ts=$(timestamp)
    vm_ip=$(local_ip)
    cipher=$(get_cipher "$mode")
    aes_bits=$(get_aes_bits "$mode")
    mkdir -p "$OUTPUT_DIR"
    out_file="${OUTPUT_DIR}/${vm_ip}_${mode}_${ts}.csv"

    log_info "Écriture → $out_file"

    {
        echo "Horodatage,VM_IP,Serveur_IP,Mode,Profil,Suite_chiffrement,AES_bits,\
Latence_min_ms,Latence_moy_ms,Latence_max_ms,Latence_p99_ms,\
Debit_Mbps,Handshake_moy_ms,Handshake_p99_ms,\
CPU_moy_pct,RAM_moy_Mo,Retransmissions_pct,Taille_cle_octets,Taille_cert_octets,\
Ping_moy_ms,Ping_min_ms,Ping_max_ms,Ping_p99_ms,\
Jitter_ms,Packet_loss_pct,Packet_loss_UDP_pct,\
Fragmentation_pct,Handshake_paquets,Handshake_octets,\
TCP_connect_ms,TTFB_ms,Connexions_echec"

        for entry in "${TRAFFIC_RESULTS[@]}"; do
            local profile result_file throughput retransmit jitter_val loss_udp_val
            profile="${entry%%:*}"
            result_file="${entry#*:}"

            [[ -f "$result_file" ]] || continue

            IFS=' ' read -r throughput retransmit < <(
                python3 "$SCRIPT_PY" parse_traffic "$result_file"
            )

            # Jitter et perte UDP uniquement sur voip et stream
            case "$profile" in
                voip|stream) jitter_val="$NET_JITTER"; loss_udp_val="$NET_LOSS_UDP_PCT" ;;
                *)           jitter_val=-1;            loss_udp_val=-1 ;;
            esac

            echo "${ts},${vm_ip},${target},${mode},${profile},${cipher},${aes_bits},\
${HS_MIN},${HS_AVG},${HS_MAX},${HS_P99},\
${throughput},${HS_AVG},${HS_P99},\
${CPU_AVG},${RAM_AVG},${retransmit},${KEY_SIZE},${CERT_SIZE},\
${NET_PING_MOY},${NET_PING_MIN},${NET_PING_MAX},${NET_PING_P99},\
${jitter_val},${NET_LOSS_PCT},${loss_udp_val},\
${HS_FRAG_PCT},${HS_PKTS},${HS_BYTES},\
${TCP_CONNECT_MS},${TTFB_MS},${CONN_ERRORS}"

            rm -f "$result_file"
        done
    } > "$out_file"

    TRAFFIC_RESULTS=()
    log_ok "Métriques sauvegardées : $out_file"
}

# Lit le JSON produit par traffic_presets.py et écrit les lignes CSV correspondantes.
# Chaque événement du preset devient une ligne (handshake_ms = handshake à ce moment précis).
collect_preset_metrics() {
    local preset_json="$1" mode="$2" target="$3" schedule_label="$4"
    local ts vm_ip cipher aes_bits out_file

    ts=$(timestamp)
    vm_ip=$(local_ip)
    cipher=$(get_cipher "$mode")
    aes_bits=$(get_aes_bits "$mode")
    mkdir -p "$OUTPUT_DIR"
    out_file="${OUTPUT_DIR}/${vm_ip}_${mode}_${schedule_label}_${ts}.csv"

    log_info "Écriture métriques preset → $out_file"

    python3 - "$preset_json" "$ts" "$vm_ip" "$target" \
              "$mode" "$cipher" "$aes_bits" \
              "$CPU_AVG" "$RAM_AVG" "$KEY_SIZE" "$CERT_SIZE" \
              "$NET_PING_MOY" "$NET_PING_MIN" "$NET_PING_MAX" "$NET_PING_P99" \
              "$NET_JITTER" "$NET_LOSS_PCT" "$NET_LOSS_UDP_PCT" \
              "$HS_FRAG_PCT" "$HS_PKTS" "$HS_BYTES" \
              "$TCP_CONNECT_MS" "$TTFB_MS" "$CONN_ERRORS" \
              "$out_file" <<'EOF'
import json, sys, csv

try:
    data = json.load(open(sys.argv[1]))
except (FileNotFoundError, json.JSONDecodeError) as exc:
    print(f"[ERR] Impossible de lire {sys.argv[1]}: {exc}", file=sys.stderr)
    sys.exit(1)

ts, vm_ip, target = sys.argv[2], sys.argv[3], sys.argv[4]
mode, cipher, aes_bits = sys.argv[5], sys.argv[6], sys.argv[7]
cpu, ram = sys.argv[8], sys.argv[9]
key_sz, cert_sz = sys.argv[10], sys.argv[11]
ping_moy, ping_min, ping_max, ping_p99 = sys.argv[12], sys.argv[13], sys.argv[14], sys.argv[15]
net_jitter, loss_pct, loss_udp_pct = sys.argv[16], sys.argv[17], sys.argv[18]
frag_pct, hs_pkts, hs_bytes = sys.argv[19], sys.argv[20], sys.argv[21]
tcp_connect, ttfb, conn_err = sys.argv[22], sys.argv[23], sys.argv[24]
outfile = sys.argv[25]

UDP_PROFILES = {"voip", "stream"}

fields = [
    "Horodatage","VM_IP","Serveur_IP","Mode","Type_test","Profil","Libelle",
    "Suite_chiffrement","AES_bits",
    "Delai_planifie_s","Duree_reelle_s",
    "Handshake_ms","Debit_Mbps",
    "CPU_moy_pct","RAM_moy_Mo","Retransmissions_pct",
    "Taille_cle_octets","Taille_cert_octets",
    "Ping_moy_ms","Ping_min_ms","Ping_max_ms","Ping_p99_ms",
    "Jitter_ms","Packet_loss_pct","Packet_loss_UDP_pct",
    "Fragmentation_pct","Handshake_paquets","Handshake_octets",
    "TCP_connect_ms","TTFB_ms","Connexions_echec",
]

try:
    with open(outfile, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in data.get("events", []):
            profil = e.get("type", "?")
            is_udp = profil in UDP_PROFILES
            w.writerow({
                "Horodatage": ts, "VM_IP": vm_ip, "Serveur_IP": target,
                "Mode": mode, "Type_test": data.get("schedule", "?"),
                "Profil": profil, "Libelle": e.get("label", ""),
                "Suite_chiffrement": cipher, "AES_bits": aes_bits,
                "Delai_planifie_s": e.get("planned_delay_s", 0),
                "Duree_reelle_s": e.get("actual_duration_s", 0),
                "Handshake_ms": e.get("handshake_ms", 0),
                "Debit_Mbps": e.get("throughput_mbps", 0),
                "CPU_moy_pct": cpu, "RAM_moy_Mo": ram,
                "Retransmissions_pct": e.get("retransmit_pct", 0),
                "Taille_cle_octets": key_sz, "Taille_cert_octets": cert_sz,
                "Ping_moy_ms": ping_moy, "Ping_min_ms": ping_min,
                "Ping_max_ms": ping_max, "Ping_p99_ms": ping_p99,
                "Jitter_ms":           net_jitter if is_udp else -1,
                "Packet_loss_pct":     loss_pct,
                "Packet_loss_UDP_pct": loss_udp_pct if is_udp else -1,
                "Fragmentation_pct":   frag_pct,
                "Handshake_paquets":   hs_pkts,
                "Handshake_octets":    hs_bytes,
                "TCP_connect_ms":      tcp_connect,
                "TTFB_ms":             ttfb,
                "Connexions_echec":    conn_err,
            })
except OSError as exc:
    print(f"[ERR] Écriture CSV {outfile}: {exc}", file=sys.stderr)
    sys.exit(1)
EOF

    if [[ $? -ne 0 ]]; then
        die "collect_preset_metrics : écriture du CSV échouée ($out_file)"
    fi
    log_ok "Métriques sauvegardées : $out_file"
}

# =============================================================================
# SIMULATION LATENCE WAN (tc-netem — nécessite root)
# =============================================================================
_WAN_IFACE=""

wan_apply() {
    local profile="${1:-eu}"

    if [[ -n "$SERVER_IP" ]]; then
        # IP explicite via --server-ip : trouver l'interface qui la porte
        _WAN_IFACE=$(ip -o addr show \
            | awk -v ip="$SERVER_IP" '/inet /{split($4,a,"/"); if(a[1]==ip){print $2; exit}}')
        if [[ -z "$_WAN_IFACE" ]]; then
            log_error "Aucune interface ne porte l'IP $SERVER_IP — vérifiez --server-ip"
            return 1
        fi
    else
        # Pas de --server-ip : compter les interfaces non-loopback avec une IPv4 globale
        local -a ifaces
        mapfile -t ifaces < <(ip -o addr show scope global | awk '/inet /{print $2}' | sort -u)
        case "${#ifaces[@]}" in
            0)
                log_warn "Aucune interface réseau détectée — simulation WAN désactivée"
                return 0
                ;;
            1)
                _WAN_IFACE="${ifaces[0]}"
                local auto_ip
                auto_ip=$(ip -o addr show dev "$_WAN_IFACE" \
                    | awk '/inet /{split($4,a,"/"); print a[1]; exit}')
                log_info "Interface auto-détectée : $_WAN_IFACE ($auto_ip)"
                ;;
            *)
                log_error "Plusieurs interfaces réseau détectées — impossible de choisir automatiquement."
                log_error "Relancez avec --server-ip <IP> en précisant l'IP de l'interface LAN vers les VMs :"
                local _if _ip
                for _if in "${ifaces[@]}"; do
                    _ip=$(ip -o addr show dev "$_if" \
                        | awk '/inet /{split($4,a,"/"); print a[1]; exit}')
                    log_error "    $_if  →  $_ip"
                done
                return 1
                ;;
        esac
    fi

    local delay="${WAN_DELAY[$profile]:-35ms}"
    local jitter="${WAN_JITTER[$profile]:-8ms}"
    local loss="${WAN_LOSS[$profile]:-0.1%}"

    tc qdisc del dev "$_WAN_IFACE" root 2>/dev/null || true
    local err
    if ! err=$(tc qdisc add dev "$_WAN_IFACE" root netem \
            delay "$delay" "$jitter" distribution normal \
            loss "$loss" 2>&1); then
        log_warn "tc netem échoué sur $_WAN_IFACE : $err"
        log_warn "Simulation WAN désactivée (netem/iproute2 manquant ou droits insuffisants)"
        return 0
    fi

    log_ok "Latence WAN ($profile) sur $_WAN_IFACE : delay=$delay ±$jitter, perte=$loss"
}

wan_remove() {
    # Si _WAN_IFACE est vide (wan_apply n'a pas abouti), rien à nettoyer
    [[ -z "${_WAN_IFACE:-}" ]] && return 0
    tc qdisc del dev "$_WAN_IFACE" root 2>/dev/null || true
    log_ok "Règle netem supprimée sur $_WAN_IFACE"
}

# =============================================================================
# MODE SERVEUR (VM WAN simulé)
# =============================================================================
_SERVER_PIDS=()
_SRV_MODE="unknown"
_SRV_WAN="?"
_SRV_MON_PID=0
_SRV_MON_FILE=""

_server_monitor_start() {
    _SRV_MON_FILE=$(mktemp /tmp/pqc_srv_mon_XXXXX.dat 2>/dev/null) || {
        log_warn "Impossible de créer le fichier temporaire de monitoring serveur"
        return 0
    }
    (
        # Première lecture pour initialiser les deltas CPU
        read -r _ cu cn cs ci cw cr cs2 _ < <(grep '^cpu ' /proc/stat 2>/dev/null) || true
        prev_total=$((cu + cn + cs + ci + cw + cr + cs2))
        prev_idle=$((ci + cw))

        while true; do
            sleep 5
            read -r _ cu cn cs ci cw cr cs2 _ < <(grep '^cpu ' /proc/stat 2>/dev/null) || continue
            total=$((cu + cn + cs + ci + cw + cr + cs2))
            dt=$((total - prev_total))
            di=$(( (ci + cw) - prev_idle ))
            [[ $dt -gt 0 ]] \
                && cpu_pct=$(awk "BEGIN{printf \"%.1f\",(1-$di/$dt)*100}") \
                || cpu_pct=0
            prev_total=$total
            prev_idle=$((ci + cw))

            ram_used=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%.0f",(t-a)/1024}' \
                /proc/meminfo 2>/dev/null) || ram_used=0

            rx=0; tx=0
            [[ -n "${_WAN_IFACE:-}" ]] && \
                read -r rx tx < <(awk -v iface="${_WAN_IFACE}:" \
                    '$1==iface{print $2,$10}' /proc/net/dev 2>/dev/null) || true

            echo "$cpu_pct $ram_used $rx $tx $(date +%s)"
        done
    ) >> "$_SRV_MON_FILE" &
    _SRV_MON_PID=$!
    log_info "Monitoring serveur démarré (PID $_SRV_MON_PID)"
}

_server_monitor_stop() {
    [[ ${_SRV_MON_PID:-0} -gt 0 ]] && { kill "$_SRV_MON_PID" 2>/dev/null || true; _SRV_MON_PID=0; }
    [[ ! -f "${_SRV_MON_FILE:-}" ]] && return 0

    local n=0 cpu_sum=0 ram_sum=0
    local first_rx=0 first_tx=0 first_ts=0 last_rx=0 last_tx=0 last_ts=0
    local cpu_pct ram_used rx tx ts

    while read -r cpu_pct ram_used rx tx ts; do
        [[ $n -eq 0 ]] && { first_rx=$rx; first_tx=$tx; first_ts=$ts; }
        last_rx=$rx; last_tx=$tx; last_ts=$ts
        cpu_sum=$(awk "BEGIN{printf \"%.2f\",$cpu_sum+$cpu_pct}")
        ram_sum=$(awk "BEGIN{printf \"%.0f\",$ram_sum+$ram_used}")
        n=$((n + 1))
    done < "$_SRV_MON_FILE"
    rm -f "$_SRV_MON_FILE"

    [[ $n -eq 0 ]] && return 0

    local cpu_avg ram_avg rx_mbps elapsed server_ip mfile
    cpu_avg=$(awk "BEGIN{printf \"%.1f\",$cpu_sum/$n}")
    ram_avg=$(awk "BEGIN{printf \"%.0f\",$ram_sum/$n}")
    elapsed=$(( last_ts - first_ts ))
    if [[ $elapsed -gt 0 ]]; then
        rx_mbps=$(awk "BEGIN{printf \"%.3f\",($last_rx-$first_rx)*8/$elapsed/1000000}")
    else
        rx_mbps=0
    fi

    server_ip="${SERVER_IP:-$(local_ip)}"
    mkdir -p "$OUTPUT_DIR"
    mfile="${OUTPUT_DIR}/server_metrics_${_SRV_MODE}_$(timestamp).json"
    printf '{\n  "source": "%s",\n  "mode": "%s",\n  "wan": "%s",\n  "type_test": "server",\n  "cpu_avg_pct": %s,\n  "ram_avg_mb": %s,\n  "rx_mbps": %s,\n  "wan_iface": "%s"\n}\n' \
        "$server_ip" "$_SRV_MODE" "$_SRV_WAN" \
        "$cpu_avg" "$ram_avg" "$rx_mbps" "${_WAN_IFACE:-}" \
        > "$mfile"
    log_ok "Métriques serveur ($n échantillons, durée $((elapsed))s) → $mfile"
}

_cleanup_server() {
    log_info "Arrêt du serveur..."
    local pid
    for pid in "${_SERVER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # openssl s_server et traffic_server tournent en subshell — peuvent survivre au kill du parent
    pkill -f "openssl s_server"   2>/dev/null || true
    pkill -f "traffic_server.py"  2>/dev/null || true
    sleep 0.3
    _server_monitor_stop
    rm -f "${SCRIPT_DIR}/.server_mode"
    [[ $EUID -eq 0 ]] && wan_remove
    rm -rf "$CERT_DIR"
}

_valid_server_mode() {
    case "$1" in
        classic|hybrid-kem|hybrid-full|\
        mlkem512|mlkem768|mlkem1024|\
        mldsa44|mldsa65|mldsa87|\
        slhdsa128|slhdsa256) return 0 ;;
        *) return 1 ;;
    esac
}

cmd_server() {
    local mode="${1:-classic}" wan_profile="${2:-eu}"

    if ! _valid_server_mode "$mode"; then
        log_error "Mode inconnu : '$mode'"
        echo ""
        usage_server
    fi

    log_section "MODE SERVEUR | crypto: $mode | WAN: $wan_profile"

    crypto_gen_certs "$mode"

    # Latence WAN (requiert root)
    trap '_cleanup_server' EXIT INT TERM
    if [[ $EUID -eq 0 ]]; then
        if ! wan_apply "$wan_profile"; then
            exit 1
        fi
    else
        log_warn "Non-root : simulation WAN désactivée (relancez avec sudo)"
    fi

    # Nettoyer une éventuelle instance traffic_server résiduelle
    pkill -f "traffic_server.py" 2>/dev/null || true
    sleep 0.2

    # Serveur de trafic custom (remplace le pool iperf3)
    if [[ ! -f "$SCRIPT_DIR/traffic_server.py" ]]; then
        log_warn "traffic_server.py introuvable — les métriques de débit seront indisponibles"
    else
        log_info "Démarrage traffic_server.py (TCP :$TRAFFIC_PORT  UDP :$TRAFFIC_UDP_PORT)..."
        local ts_log="/tmp/traffic_server_$$.log"
        python3 "$SCRIPT_DIR/traffic_server.py" \
            --tcp-port "$TRAFFIC_PORT" \
            --udp-port "$TRAFFIC_UDP_PORT" \
            > "$ts_log" 2>&1 &
        _SERVER_PIDS+=($!)
        sleep 0.5
        if grep -q "pret" "$ts_log" 2>/dev/null; then
            log_ok "traffic_server prêt (TCP :$TRAFFIC_PORT  UDP :$TRAFFIC_UDP_PORT)"
        else
            log_warn "traffic_server.py peut ne pas avoir démarré — vérifiez $ts_log"
        fi
    fi

    # Serveur TLS (boucle pour accepter des connexions successives)
    # Note : -groups n'est pas passé côté serveur — openssl s_server ne le supporte pas
    # sur toutes les versions. Le groupe KEM est négocié par le client dans son ClientHello.
    local cipher provider_arg
    cipher=$(get_cipher "$mode")
    provider_arg=$(get_provider_args "$mode")

    log_info "Démarrage TLS serveur (port $PORT_TLS, cipher: $cipher)..."
    (
        # shellcheck disable=SC2086
        while true; do
            err=$(openssl s_server \
                -cert "$CERT_DIR/server.crt" \
                -key  "$CERT_DIR/server.key" \
                -port "$PORT_TLS" \
                -tls1_3 \
                -ciphersuites "$cipher" \
                $provider_arg \
                -rev 2>&1) || {
                    # Filtrer les déconnexions normales (pas des vraies erreurs)
                    echo "$err" | grep -vqE "ACCEPT|read:errno=0|shutting down" \
                        && echo "[WARN] openssl s_server: $err" >&2
                }
            sleep 0.05
        done
    ) &
    _SERVER_PIDS+=($!)

    # Vérifier que le serveur TLS a bien démarré
    sleep 0.3
    if ! ss -tlnp 2>/dev/null | grep -q ":${PORT_TLS}"; then
        die "Le serveur TLS n'a pas pu écouter sur le port $PORT_TLS (port déjà utilisé ou erreur OpenSSL)"
    fi

    # Port marqueur (détection de déploiement par --scan)
    nc -lk -p "$PORT_MARKER" >/dev/null 2>&1 &
    _SERVER_PIDS+=($!)

    # Fichier d'etat lu par server_cli.py pour auto-detecter le mode et l'IP
    local bind_ip="${SERVER_IP:-$(local_ip)}"
    printf "mode=%s\nip=%s\n" "$mode" "$bind_ip" > "${SCRIPT_DIR}/.server_mode"

    log_ok "Serveur prêt — IP: ${bind_ip} | TLS: :${PORT_TLS} | traffic: TCP:${TRAFFIC_PORT} UDP:${TRAFFIC_UDP_PORT}"
    log_ok "Ctrl+C pour arrêter"
    _SRV_MODE="$mode"
    _SRV_WAN="$wan_profile"
    rm -f "${OUTPUT_DIR}"/server_metrics_"${mode}"_*.json 2>/dev/null || true
    _server_monitor_start
    wait
}

# =============================================================================
# MODE TEST (VM cliente) — trafic aléatoire ou preset prédéfini
# =============================================================================
cmd_test() {
    [[ -z "$TARGET" ]] && die "--target <IP> requis"
    check_deps || log_warn "Dépendances manquantes — résultats partiels possibles"

    trap 'rm -rf "$CERT_DIR"; stop_monitor; wait_traffic' EXIT INT TERM
    crypto_gen_certs "$MODE"

    if [[ -n "$PRESET" ]]; then
        # ── MODE PRESET : trafic staggeré prédéfini ──────────────────────────
        log_section "TEST PRESET $PRESET | mode: $MODE | cible: $TARGET"
        [[ -f "$SCRIPT_DIR/traffic_presets.py" ]] \
            || die "traffic_presets.py introuvable dans $SCRIPT_DIR"

        local preset_json="/tmp/pqc_preset_${PRESET}_$$.json"

        # Mesure handshake bulk (baseline statistique + métriques réseau one-shot)
        measure_handshake "$MODE" "$TARGET" "$HANDSHAKE_COUNT"

        # Monitoring CPU/RAM + mesures réseau en parallèle pendant le preset
        start_monitor
        net_ping_start   "$TARGET" 70
        net_jitter_start "$TARGET" 70

        log_info "Exécution preset $PRESET (60s, événements staggerés)..."
        local preset_err
        if ! preset_err=$(python3 "$SCRIPT_DIR/traffic_presets.py" run \
                --preset "$PRESET" \
                --target "$TARGET" \
                --mode   "$MODE" \
                --port-tls "$PORT_TLS" \
                --cert   "$CERT_DIR/server.crt" \
                --duration 60 \
                --vm-id  "$VM_ID" \
                --output "$preset_json" 2>&1); then
            log_warn "traffic_presets.py run a signalé une erreur : $preset_err"
        fi

        net_jitter_stop
        net_ping_stop
        stop_monitor

        if [[ ! -f "$preset_json" ]]; then
            die "Fichier de résultats absent après le preset ($preset_json) — test abandonné"
        fi

        local schedule_label
        schedule_label=$(python3 -c \
            "import json,sys; d=json.load(open(sys.argv[1])); \
             print(d.get('schedule','preset').replace(' ','_'))" \
            "$preset_json" 2>/dev/null || echo "preset_${PRESET}")

        collect_preset_metrics "$preset_json" "$MODE" "$TARGET" "$schedule_label"
        rm -f "$preset_json"

    else
        # ── MODE TRAFIC LIBRE : profils parallèles (comportement d'origine) ──
        log_section "TEST | mode: $MODE | profils: $PROFILES | cible: $TARGET | durée: ${DURATION}s"

        measure_handshake "$MODE" "$TARGET" "$HANDSHAKE_COUNT"
        start_monitor
        net_ping_start   "$TARGET" $(( DURATION + 15 ))
        net_jitter_start "$TARGET" $(( DURATION + 15 ))

        log_info "Démarrage des profils de trafic (en parallèle) :"
        local -a profile_list
        IFS=',' read -ra profile_list <<< "$PROFILES"

        for p in "${profile_list[@]}"; do
            case "$p" in
                web)    traffic_web    "$TARGET" "$DURATION" ;;
                file)   traffic_file   "$TARGET" "$DURATION" ;;
                voip)   traffic_voip   "$TARGET" "$DURATION" ;;
                stream) traffic_stream "$TARGET" "$DURATION" ;;
                msg)    traffic_msg    "$TARGET" "$DURATION" ;;
                all)
                    traffic_file   "$TARGET" "$DURATION"
                    traffic_voip   "$TARGET" "$DURATION"
                    traffic_stream "$TARGET" "$DURATION"
                    traffic_web    "$TARGET" "$DURATION"
                    traffic_msg    "$TARGET" "$DURATION"
                    ;;
                *) log_warn "Profil inconnu : $p" ;;
            esac
        done

        wait_traffic
        net_jitter_stop
        net_ping_stop
        stop_monitor
        collect_metrics "$MODE" "$PROFILES" "$TARGET"
    fi

    log_section "Test terminé"
}

# =============================================================================
# MODE TRAFIC ALÉATOIRE CONTINU
# Appelle traffic_presets.py continuous — 5 schedulers en boucle,
# un handshake PQC + traffic_server par connexion, jusqu'à --duration ou Ctrl+C.
# =============================================================================
cmd_random() {
    [[ -z "$TARGET" ]] && die "--target <IP> requis"
    check_deps || log_warn "Dépendances manquantes — résultats partiels possibles"

    local script_presets="$SCRIPT_DIR/traffic_presets.py"
    [[ -f "$script_presets" ]] || die "traffic_presets.py introuvable dans $SCRIPT_DIR"

    log_section "TRAFIC ALÉATOIRE CONTINU | mode: $MODE | cible: $TARGET"
    [[ "$DURATION" -gt 0 ]] \
        && log_info "Durée: ${DURATION}s" \
        || log_info "Durée: infinie — Ctrl+C pour arrêter"

    trap 'rm -rf "$CERT_DIR"; stop_monitor; net_ping_stop; net_jitter_stop' EXIT INT TERM
    crypto_gen_certs "$MODE"

    # Mesure handshake bulk en amont (baseline statistique propre)
    measure_handshake "$MODE" "$TARGET" "$HANDSHAKE_COUNT"

    start_monitor
    local random_dur=$(( DURATION > 0 ? DURATION + 15 : 3600 ))
    net_ping_start   "$TARGET" "$random_dur"
    net_jitter_start "$TARGET" "$random_dur"

    local out_json=""
    [[ "$DURATION" -gt 0 ]] && out_json="/tmp/pqc_random_$$.json"

    # Lance le trafic continu (bloquant jusqu'à fin de durée ou Ctrl+C)
    python3 "$script_presets" continuous \
        --target   "$TARGET" \
        --mode     "$MODE" \
        --port-tls "$PORT_TLS" \
        --cert     "$CERT_DIR/server.crt" \
        --duration "$DURATION" \
        --vm-id    "$VM_ID" \
        ${out_json:+--output "$out_json"} || true

    net_jitter_stop
    net_ping_stop
    stop_monitor

    if [[ -n "$out_json" && -f "$out_json" ]]; then
        collect_preset_metrics "$out_json" "$MODE" "$TARGET" "random_continu"
        rm -f "$out_json"
    fi

    log_section "Fin du trafic aléatoire"
}

# =============================================================================
# SCAN RÉSEAU
# =============================================================================
cmd_scan() {
    local subnet="${1:-}"
    if [[ -z "$subnet" ]]; then
        local lip
        lip=$(local_ip)
        subnet="${lip%.*}.0/24"
    fi

    log_section "SCAN RÉSEAU : $subnet"
    has_cmd nmap || die "nmap requis pour le scan"

    log_info "Ping sweep en cours..."
    local hosts
    hosts=$(nmap -sn "$subnet" -oG - 2>/dev/null | awk '/Up$/{print $2}')

    echo ""
    printf "${BOLD}%-18s %-22s %-25s${NC}\n" "IP" "HOSTNAME" "STATUT SCRIPT"
    printf '%s\n' "$(printf '─%.0s' {1..65})"

    local ip hostname status
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        hostname=$(nmap -sn "$ip" 2>/dev/null \
            | awk '/Nmap scan report/{gsub(/[()]/,""); print $NF}')

        if nc -z -w2 "$ip" "$PORT_MARKER" 2>/dev/null; then
            status="${GREEN}SCRIPT ACTIF${NC}"
        elif nc -z -w2 "$ip" 22 2>/dev/null; then
            status="${YELLOW}SSH OK — script absent${NC}"
        else
            status="${RED}INJOIGNABLE${NC}"
        fi

        printf "%-18s %-22s " "$ip" "${hostname:-?}"
        echo -e "$status"
    done <<< "$hosts"
    echo ""
}

# =============================================================================
# AGRÉGATION DES CSV (collecte depuis toutes les VMs)
# =============================================================================
cmd_collect_only() {
    local vms_file="${1:-}"
    local out_file="${OUTPUT_DIR}/aggregate_$(timestamp).csv"
    mkdir -p "$OUTPUT_DIR"

    log_section "AGRÉGATION DES RÉSULTATS"

    if [[ -n "$vms_file" && -f "$vms_file" ]]; then
        local tmp_dir="/tmp/pqc_collect_$$"
        mkdir -p "$tmp_dir"

        while IFS= read -r vm_ip; do
            [[ -z "$vm_ip" || "$vm_ip" =~ ^# ]] && continue
            log_info "Récupération CSV depuis $vm_ip..."
            scp -qr "${vm_ip}:${OUTPUT_DIR}/*.csv" "$tmp_dir/" 2>/dev/null \
                || log_warn "Impossible de récupérer les CSV depuis $vm_ip"
        done < "$vms_file"

        python3 "$SCRIPT_PY" aggregate "$out_file" "$tmp_dir/"*.csv 2>/dev/null
        rm -rf "$tmp_dir"
    else
        log_info "Agrégation des CSV locaux dans $OUTPUT_DIR..."
        # shellcheck disable=SC2046
        python3 "$SCRIPT_PY" aggregate "$out_file" \
            $(find "$OUTPUT_DIR" -name "*.csv" ! -name "aggregate_*" 2>/dev/null) \
            2>/dev/null || log_warn "Aucun CSV local trouvé"
    fi

    log_ok "Fichier agrégé : $out_file"
}

# =============================================================================
# AIDE SERVEUR
# =============================================================================
usage_server() {
    cat <<EOF
${BOLD}pqc_bench.sh v${VERSION}${NC} — Mode serveur

${BOLD}USAGE :${NC}
  sudo $0 --server --mode <MODE> [--wan-profile <WAN>] [--server-ip <IP>]

${BOLD}MODES DISPONIBLES :${NC}
  Priorité  Mode          KEM                    Signature                AES
  ─────────────────────────────────────────────────────────────────────────────
  ★★★       hybrid-full   X25519 + ML-KEM-768    ECDSA P-256 + ML-DSA-65  256   ${CYAN}← CNSA 2.0${NC}
  ★★☆       hybrid-kem    X25519 + ML-KEM-768    ECDSA P-256              256
  ★★☆       classic       X25519                 ECDSA P-256              256   baseline
  ★☆☆       mlkem768      ML-KEM-768             ECDSA P-256              256
  ★☆☆       mlkem1024     ML-KEM-1024            ECDSA P-256              256
  ★☆☆       mlkem512      ML-KEM-512             ECDSA P-256              128
  ★☆☆       mldsa65       X25519                 ML-DSA-65                256
  ★☆☆       mldsa44       X25519                 ML-DSA-44                256
  ★☆☆       mldsa87       X25519                 ML-DSA-87                256
  ☆☆☆       slhdsa128     X25519 + ML-KEM-768    SLH-DSA-128s             256   lent
  ☆☆☆       slhdsa256     X25519 + ML-KEM-768    SLH-DSA-256s             256   lent

${BOLD}OPTIONS :${NC}
  --wan-profile <WAN>   Latence injectee : fr (15ms) | eu (35ms) | us (80ms)
                        Necessite sudo  (tc-netem sur l'interface sortante)
  --server-ip <IP>      IP de l'interface LAN vers les VMs.
                        Obligatoire si le serveur a plusieurs interfaces réseau
                        (le script s'arrete avec la liste des interfaces detectees).
                        Avec une seule interface, detection automatique.

${BOLD}EXEMPLES :${NC}
  sudo $0 --server --mode hybrid-full --wan-profile eu                            # 1 interface
  sudo $0 --server --mode classic     --wan-profile fr --server-ip 192.168.1.1   # multi-NIC

${BOLD}NOTE :${NC}
  Le mode choisi ici est transmis automatiquement aux VMs clientes via .server_mode.
  Les VMs n'ont pas besoin de specifier --mode manuellement (server_cli.py le detecte).

EOF
    exit 0
}

# =============================================================================
# LISTE DES MODES
# =============================================================================
cmd_list_modes() {
    cat <<EOF
${BOLD}Modes cryptographiques disponibles — pqc_bench.sh v${VERSION}${NC}
Grille conforme NIST FIPS 203/204/205 et recommandations CNSA 2.0

${BOLD}Priorité  Mode          KEM                    Signature              AES   Objectif${NC}
─────────────────────────────────────────────────────────────────────────────────────────────
${CYAN}★★★${NC}       hybrid-full   X25519 + ML-KEM-768    ECDSA P-256 + ML-DSA-65  256   Cible CNSA 2.0 (référence)
${CYAN}★★☆${NC}       hybrid-kem    X25519 + ML-KEM-768    ECDSA P-256              256   Transition hybride KEM
${CYAN}★★☆${NC}       classic       X25519                 ECDSA P-256              256   Baseline classique
${CYAN}★☆☆${NC}       mlkem768      ML-KEM-768             ECDSA P-256              256   PQC pur KEM Cat.3
${CYAN}★☆☆${NC}       mlkem1024     ML-KEM-1024            ECDSA P-256              256   PQC pur KEM Cat.5
${CYAN}★☆☆${NC}       mlkem512      ML-KEM-512             ECDSA P-256              128   PQC pur KEM Cat.1
${CYAN}★☆☆${NC}       mldsa65       X25519                 ML-DSA-65                256   PQC pur Sig Cat.3
${CYAN}★☆☆${NC}       mldsa44       X25519                 ML-DSA-44                256   PQC pur Sig Cat.2
${CYAN}★☆☆${NC}       mldsa87       X25519                 ML-DSA-87                256   PQC pur Sig Cat.5
${CYAN}☆☆☆${NC}       slhdsa128     X25519 + ML-KEM-768    SLH-DSA-128s             256   Hash-based Sig (lent)
${CYAN}☆☆☆${NC}       slhdsa256     X25519 + ML-KEM-768    SLH-DSA-256s             256   Hash-based Sig (lent)

${BOLD}Notes :${NC}
  hybrid-full  Seul mode avec double protection KEM + Signature post-quantiques
               Certificat composite p384_mldsa65 (oqs-provider 0.5+)
  slhdsa*      Signatures basées sur hash (pas de réseau), très grandes mais robustes
               Alias liboqs : sphincssha2128ssimple / sphincssha2256ssimple
  classic      Baseline AES-256 (Grover réduit AES-128 à ~64 bits côté quantique)
EOF
    exit 0
}

# =============================================================================
# AIDE
# =============================================================================
usage() {
    cat <<EOF
${BOLD}pqc_bench.sh v${VERSION}${NC} — Benchmark PQC vs Classique sur réseau PME

${BOLD}USAGE :${NC}
  $0 [OPTIONS]

${BOLD}MODES PRINCIPAUX :${NC}
  (défaut)              Test client ponctuel (handshake bulk + profils en parallèle)
  --random              Trafic aléatoire CONTINU — connexions/handshakes staggerés
                          (5 schedulers indépendants, boucle jusqu'à --duration ou Ctrl+C)
  --server              Mode serveur WAN simulé (à lancer sur la VM WAN)
  --scan [SUBNET]       Cartographie du réseau (ex: 192.168.10.0/24)
  --collect-only [FILE] Agrège les CSV — FILE = liste d'IPs (une par ligne)
  --install             Installe toutes les dépendances (nécessite sudo)

${BOLD}OPTIONS TEST :${NC}
  --target <IP>         IP du serveur WAN cible ${RED}(obligatoire)${NC}
  --mode <MODE>         Mode cryptographique (défaut: classic)
                        Par ordre de priorité CNSA 2.0 :
      hybrid-full  ★★★  X25519+ML-KEM-768 / ECDSA P-256+ML-DSA-65 / AES-256  ${CYAN}← cible CNSA 2.0${NC}
      hybrid-kem   ★★☆  X25519+ML-KEM-768 / ECDSA P-256            / AES-256  transition hybride
      classic      ★★☆  X25519            / ECDSA P-256            / AES-256  baseline classique
      mlkem768     ★☆☆  ML-KEM-768        / ECDSA P-256            / AES-256  PQC pur KEM Cat.3
      mlkem1024    ★☆☆  ML-KEM-1024       / ECDSA P-256            / AES-256  PQC pur KEM Cat.5
      mlkem512     ★☆☆  ML-KEM-512        / ECDSA P-256            / AES-128  PQC pur KEM Cat.1
      mldsa65      ★☆☆  X25519            / ML-DSA-65              / AES-256  PQC pur Sig Cat.3
      mldsa44      ★☆☆  X25519            / ML-DSA-44              / AES-256  PQC pur Sig Cat.2
      mldsa87      ★☆☆  X25519            / ML-DSA-87              / AES-256  PQC pur Sig Cat.5
      slhdsa128    ☆☆☆  X25519+ML-KEM-768 / SLH-DSA-128s           / AES-256  hash-based (lent)
      slhdsa256    ☆☆☆  X25519+ML-KEM-768 / SLH-DSA-256s           / AES-256  hash-based (lent)
      (--list-modes pour le tableau complet avec les algorithmes liboqs)
  --preset <N>          Preset prédéfini 1-5 (trafic staggeré, 60s fixes) :
                          1=Secrétariat  2=Développeur  3=Manager
                          4=Commercial   5=IT Technicien
                          (voir: python3 traffic_presets.py list)
  --profile <PROFILS>   Trafic libre — profils en parallèle (virgule pour combiner)
                          web | file | voip | stream | msg | all
  --duration <sec>      Durée de chaque profil (mode --profile, défaut: 30)
  --hs-count <N>        Nombre d'itérations pour mesure handshake (défaut: 100)
  --output <DIR>        Répertoire de sortie CSV (défaut: ./results)
  --list-modes          Affiche le tableau détaillé des modes et quitte

${BOLD}OPTIONS SERVEUR :${NC}
  --wan-profile <p>     Profil latence WAN : fr (15ms) | eu (35ms) | us (80ms)

${BOLD}EXEMPLES :${NC}
  # Tableau détaillé des modes
  $0 --list-modes

  # Lancer le serveur WAN (VM derrière le pare-feu)
  sudo $0 --server --mode hybrid-full --wan-profile eu

  # Preset 3 — séquence comparative recommandée CNSA 2.0
  $0 --target 10.0.1.1 --mode classic      --preset 3
  $0 --target 10.0.1.1 --mode hybrid-kem   --preset 3
  $0 --target 10.0.1.1 --mode hybrid-full  --preset 3

  # Preset 4 (Commercial) — à lancer en parallèle avec preset 3 sur un autre PC
  $0 --target 10.0.1.1 --mode classic  --preset 4

  # Voir tous les presets disponibles
  python3 traffic_presets.py list

  # Trafic aléatoire continu — 5 min, puis passe au mode suivant
  $0 --target 10.0.1.1 --mode classic      --random --duration 300
  $0 --target 10.0.1.1 --mode hybrid-full  --random --duration 300

  # Trafic aléatoire infini — Ctrl+C pour arrêter manuellement
  $0 --target 10.0.1.1 --mode hybrid-kem   --random

  # Trafic libre ponctuel (non staggeré, charge max simultanée)
  $0 --target 10.0.1.1 --mode classic  --profile voip,file --duration 60

  # Scanner le réseau
  $0 --scan 192.168.10.0/24

  # Agréger les résultats de toutes les VMs
  $0 --collect-only vms.txt

EOF
    exit 0
}

# =============================================================================
# PARSING CLI
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)       ACTION="server" ;;
        --scan)
            ACTION="scan"
            if [[ "${2:-}" != --* && -n "${2:-}" ]]; then
                SCAN_SUBNET="$2"; shift
            fi
            ;;
        --collect-only)
            ACTION="collect"
            if [[ "${2:-}" != --* && -n "${2:-}" ]]; then
                COLLECT_FILE="$2"; shift
            fi
            ;;
        --install)      ACTION="install" ;;
        --random)       ACTION="random" ;;
        --target)       TARGET="$2";          shift ;;
        --mode)         MODE="$2";            shift ;;
        --preset)       PRESET="$2";          shift ;;
        --profile)      PROFILES="$2";        shift ;;
        --duration)     DURATION="$2";        shift ;;
        --hs-count)     HANDSHAKE_COUNT="$2"; shift ;;
        --output)       OUTPUT_DIR="$2";      shift ;;
        --wan-profile)  WAN_PROFILE="$2";     shift ;;
        --server-ip)    SERVER_IP="$2";       shift ;;
        --vm-id)        VM_ID="$2";           shift ;;
        -h|--help)
            if [[ "$ACTION" == "server" ]]; then usage_server; else usage; fi
            ;;
        --list-modes)   ACTION="list-modes" ;;
        *) log_warn "Option inconnue : $1 (ignorée)" ;;
    esac
    shift
done

# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
case "$ACTION" in
    install)    cmd_install ;;
    scan)       cmd_scan    "$SCAN_SUBNET" ;;
    server)     cmd_server  "$MODE" "$WAN_PROFILE" ;;
    collect)    cmd_collect_only "$COLLECT_FILE" ;;
    random)     cmd_random ;;
    list-modes) cmd_list_modes ;;
    test)       cmd_test ;;
esac
