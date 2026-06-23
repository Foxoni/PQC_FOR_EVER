#!/usr/bin/env bash
# =============================================================================
# pqc_bench.sh — Benchmark PQC vs Cryptographie Classique sur réseau PME
# Projet de recherche — Guardia Cybersecurity School
#
# Usage : ./pqc_bench.sh --help
# Dépendances : iperf3, openssl 3.x, oqs-provider, python3, nmap, tc
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
PORT_IPERF_FILE=5201
PORT_IPERF_VOIP=5202
PORT_IPERF_STREAM=5203
PORT_IPERF_WEB=5204
PORT_IPERF_MSG=5205
# Le pool serveur écoute de 5201 à 5210 (une instance par port)

# =============================================================================
# SUITES DE CHIFFREMENT TLS 1.3
# Baseline  → AES-128-GCM (norme actuelle, suffisant en classique)
# PQC 768+  → AES-256-GCM (recommandé NIST : Grover réduit AES-128 à ~64 bits)
# =============================================================================
CIPHER_128="TLS_AES_128_GCM_SHA256"
CIPHER_256="TLS_AES_256_GCM_SHA384"

# Groupes TLS pour l'échange de clé ML-KEM (noms oqs-provider)
declare -A OQS_KEM_GROUP=(
    [mlkem512]="mlkem512"
    [mlkem768]="mlkem768"
    [mlkem1024]="mlkem1024"
    [hybrid]="X25519MLKEM768"       # hybride recommandé NIST
)

# Algorithmes ML-DSA pour la génération de certificats
declare -A OQS_SIG_ALG=(
    [mldsa44]="mldsa44"
    [mldsa65]="mldsa65"
    [mldsa87]="mldsa87"
)

# Profils de latence WAN simulée via tc-netem
declare -A WAN_DELAY=(  [fr]="15ms"   [eu]="35ms"   [us]="80ms"  )
declare -A WAN_JITTER=( [fr]="3ms"    [eu]="8ms"    [us]="15ms"  )
declare -A WAN_LOSS=(   [fr]="0.05%"  [eu]="0.1%"   [us]="0.2%"  )

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
now_ms()        { date +%s%3N; }  # epoch en millisecondes (GNU date, Linux)

local_ip() {
    ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' \
    || hostname -I | awk '{print $1}'
}

net_iface() {
    ip route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' \
    || echo "eth0"
}

# =============================================================================
# INSTALLATION DES DÉPENDANCES
# =============================================================================

cmd_install() {
    log_section "Installation des dépendances"
    require_root

    apt-get update -qq
    apt-get install -y \
        nmap iperf3 hping3 tcpdump tshark \
        openssl python3 python3-pip \
        curl wget git cmake gcc g++ \
        libtool libssl-dev pkg-config \
        iproute2 net-tools bc netcat-openbsd

    # Packages Python
    pip3 install --quiet scapy psutil 2>/dev/null \
        || pip3 install --quiet --break-system-packages scapy psutil

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

    log_info "Compilation de liboqs (Open Quantum Safe)..."
    git clone --depth 1 \
        https://github.com/open-quantum-safe/liboqs.git \
        "$build/liboqs" 2>/dev/null

    cmake -S "$build/liboqs" -B "$build/liboqs/build" -Wno-dev \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        > /dev/null 2>&1
    make -C "$build/liboqs/build" -j"$(nproc)" install > /dev/null 2>&1
    ldconfig

    log_info "Compilation de oqs-provider pour OpenSSL 3..."
    git clone --depth 1 \
        https://github.com/open-quantum-safe/oqs-provider.git \
        "$build/oqs-provider" 2>/dev/null

    cmake -S "$build/oqs-provider" -B "$build/oqs-provider/build" -Wno-dev \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        > /dev/null 2>&1
    make -C "$build/oqs-provider/build" -j"$(nproc)" install > /dev/null 2>&1

    _register_oqs_provider
    rm -rf "$build"
    log_ok "oqs-provider compilé et installé"
}

_register_oqs_provider() {
    local cnf
    cnf="$(openssl version -d | awk -F'"' '{print $2}')/openssl.cnf"
    grep -q oqsprovider "$cnf" 2>/dev/null && return

    cat >> "$cnf" <<'CONF'

# --- oqs-provider (Post-Quantum) ---
[provider_sect]
default     = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
module   = /usr/local/lib/ossl-modules/oqsprovider.so
activate = 1
CONF
    log_ok "oqs-provider enregistré dans $cnf"
}

check_deps() {
    local all_ok=true
    for cmd in iperf3 openssl python3 ip tc; do
        has_cmd "$cmd" || { log_warn "Commande manquante : $cmd"; all_ok=false; }
    done
    openssl list -providers 2>/dev/null | grep -q oqsprovider \
        || log_warn "oqs-provider absent → modes PQC indisponibles (sudo $0 --install)"
    [[ -f "$SCRIPT_PY" ]] \
        || log_warn "traffic_gen.py introuvable dans $SCRIPT_DIR"
    $all_ok
}

# =============================================================================
# HELPERS CRYPTO
# =============================================================================
CERT_DIR="/tmp/pqc_certs_$$"
KEY_SIZE=0
CERT_SIZE=0

get_cipher() {
    # ML-KEM-512 reste en AES-128 (même niveau sécurité Cat.1)
    # Tous les modes PQC supérieurs passent en AES-256 (résistance Grover)
    case "$1" in
        classic|mlkem512) echo "$CIPHER_128" ;;
        *)                echo "$CIPHER_256"  ;;
    esac
}

get_aes_bits() {
    case "$1" in
        classic|mlkem512) echo "128" ;;
        *)                echo "256" ;;
    esac
}

# Arguments -provider à passer à openssl pour les modes PQC
get_provider_args() {
    case "$1" in
        classic) echo "" ;;
        *)       echo "-provider oqsprovider -provider default" ;;
    esac
}

# Argument -groups pour forcer le groupe KEM en TLS 1.3
get_groups_arg() {
    local grp="${OQS_KEM_GROUP[$1]:-}"
    [[ -n "$grp" ]] && echo "-groups $grp" || echo ""
}

is_sig_mode() { [[ "$1" == mldsa* ]]; }
is_kem_mode() { [[ "$1" == mlkem* || "$1" == "hybrid" ]]; }

crypto_gen_certs() {
    local mode="$1"
    mkdir -p "$CERT_DIR"
    log_info "Génération des certificats (mode: $mode)..."

    if is_sig_mode "$mode"; then
        # ML-DSA : le certificat lui-même utilise la clé post-quantique
        local alg="${OQS_SIG_ALG[$mode]}"
        openssl genpkey -algorithm "$alg" \
            -provider oqsprovider -provider default \
            -out "$CERT_DIR/server.key" 2>/dev/null
        openssl req -new -x509 \
            -key "$CERT_DIR/server.key" \
            -out "$CERT_DIR/server.crt" \
            -days 1 -subj "/CN=pqc-bench" \
            -provider oqsprovider -provider default 2>/dev/null
    else
        # Classique & ML-KEM : ECDSA P-256 pour l'authentification
        # (ML-KEM gère uniquement l'échange de clé, pas la signature)
        openssl ecparam -name prime256v1 -genkey -noout \
            -out "$CERT_DIR/server.key" 2>/dev/null
        openssl req -new -x509 \
            -key "$CERT_DIR/server.key" \
            -out "$CERT_DIR/server.crt" \
            -days 1 -subj "/CN=pqc-bench" 2>/dev/null
    fi

    KEY_SIZE=$(wc -c < "$CERT_DIR/server.key")
    CERT_SIZE=$(wc -c < "$CERT_DIR/server.crt")
    log_ok "Certificat : ${CERT_SIZE} B | Clé : ${KEY_SIZE} B"
}

# =============================================================================
# MESURE DU HANDSHAKE TLS
# =============================================================================
HS_MIN=0; HS_AVG=0; HS_MAX=0; HS_P99=0; HS_ERRORS=0

measure_handshake() {
    local mode="$1" target="$2" count="${3:-$HANDSHAKE_COUNT}"
    local cipher provider_arg groups_arg timing_file

    cipher=$(get_cipher "$mode")
    provider_arg=$(get_provider_args "$mode")
    groups_arg=$(get_groups_arg "$mode")
    timing_file="/tmp/pqc_hs_$$.txt"
    : > "$timing_file"

    log_info "Mesure handshake TLS ($count itérations, cible: ${target}:${PORT_TLS})..."

    local errors=0 t0 t1 ms
    for _ in $(seq 1 "$count"); do
        t0=$(now_ms)
        # shellcheck disable=SC2086
        if openssl s_client \
            -connect "${target}:${PORT_TLS}" \
            -tls1_3 \
            -ciphersuites "$cipher" \
            $groups_arg $provider_arg \
            -CAfile "$CERT_DIR/server.crt" \
            -verify_return_error \
            -no_ign_eof \
            </dev/null 2>/dev/null; then
            t1=$(now_ms)
            ms=$(( t1 - t0 ))
            echo "$ms" >> "$timing_file"
        else
            (( errors++ )) || true
        fi
    done
    HS_ERRORS=$errors

    # Calcul des percentiles via Python
    read -r HS_MIN HS_AVG HS_MAX HS_P99 < <(
        python3 "$SCRIPT_PY" stats "$timing_file"
    )
    rm -f "$timing_file"

    log_ok "Handshake ─ min:${HS_MIN}ms moy:${HS_AVG}ms max:${HS_MAX}ms p99:${HS_P99}ms | erreurs:${HS_ERRORS}/${count}"
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
        read -r CPU_AVG RAM_AVG < <(
            python3 "$SCRIPT_PY" avgres "$MONITOR_FILE"
        )
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
    log_info "  [web]    navigation HTTP — bursts TCP, petits paquets"

    iperf3 -c "$target" -p "$PORT_IPERF_WEB" -t "$duration" \
        -l 512 -b 2M \
        --json > "$result" 2>/dev/null &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("web:$result")
}

# --- Téléchargement fichier : flux TCP soutenu, gros buffers ---
traffic_file() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_file_$$.json"
    log_info "  [file]   upload/download PDF — TCP soutenu, gros buffers"

    iperf3 -c "$target" -p "$PORT_IPERF_FILE" -t "$duration" \
        -l 65536 \
        --json > "$result" 2>/dev/null &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("file:$result")
}

# --- Visioconférence : UDP, paquets réguliers ~1300 B, bidirectionnel ---
traffic_voip() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_voip_$$.json"
    log_info "  [voip]   visioconférence — UDP 1300B, ~30 Mbps, bidir"

    iperf3 -c "$target" -p "$PORT_IPERF_VOIP" -t "$duration" \
        -u -b 30M -l 1300 \
        --bidir \
        --json > "$result" 2>/dev/null &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("voip:$result")
}

# --- Streaming vidéo : TCP, gros débit descendant (serveur→client) ---
traffic_stream() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_stream_$$.json"
    log_info "  [stream] streaming vidéo — TCP inverse, haut débit"

    iperf3 -c "$target" -p "$PORT_IPERF_STREAM" -t "$duration" \
        -R -l 8192 \
        --json > "$result" 2>/dev/null &
    TRAFFIC_PIDS+=($!)
    TRAFFIC_RESULTS+=("stream:$result")
}

# --- Messagerie : très petits paquets TCP, faible bande passante ---
traffic_msg() {
    local target="$1" duration="$2"
    local result="/tmp/pqc_msg_$$.json"
    log_info "  [msg]    messagerie/email — TCP 150B, 200Kbps (port $PORT_IPERF_MSG)"

    iperf3 -c "$target" -p "$PORT_IPERF_MSG" -t "$duration" \
        -l 150 -b 200K \
        --json > "$result" 2>/dev/null &
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
        # En-tête CSV
        echo "Horodatage,VM_IP,Serveur_IP,Mode,Profil,Suite_chiffrement,AES_bits,\
Latence_min_ms,Latence_moy_ms,Latence_max_ms,Latence_p99_ms,\
Debit_Mbps,Handshake_moy_ms,Handshake_p99_ms,\
CPU_moy_pct,RAM_moy_Mo,Retransmissions_pct,Taille_cle_octets,Taille_cert_octets"

        for entry in "${TRAFFIC_RESULTS[@]}"; do
            local profile result_file throughput retransmit
            profile="${entry%%:*}"
            result_file="${entry#*:}"

            [[ -f "$result_file" ]] || continue

            # Extraction débit et retransmissions depuis JSON iperf3
            read -r throughput retransmit < <(
                python3 "$SCRIPT_PY" parse_iperf "$result_file"
            )

            echo "${ts},${vm_ip},${target},${mode},${profile},${cipher},${aes_bits},\
${HS_MIN},${HS_AVG},${HS_MAX},${HS_P99},\
${throughput},${HS_AVG},${HS_P99},\
${CPU_AVG},${RAM_AVG},${retransmit},${KEY_SIZE},${CERT_SIZE}"

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
              "$out_file" <<'EOF'
import json, sys, csv

data   = json.load(open(sys.argv[1]))
ts, vm_ip, target = sys.argv[2], sys.argv[3], sys.argv[4]
mode, cipher, aes_bits = sys.argv[5], sys.argv[6], sys.argv[7]
cpu, ram = sys.argv[8], sys.argv[9]
key_sz, cert_sz = sys.argv[10], sys.argv[11]
outfile = sys.argv[12]

fields = [
    "Horodatage","VM_IP","Serveur_IP","Mode","Type_test","Profil","Libelle",
    "Suite_chiffrement","AES_bits",
    "Delai_planifie_s","Duree_reelle_s",
    "Handshake_ms","Debit_Mbps",
    "CPU_moy_pct","RAM_moy_Mo","Retransmissions_pct",
    "Taille_cle_octets","Taille_cert_octets"
]

with open(outfile, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for e in data.get("events", []):
        w.writerow({
            "Horodatage": ts, "VM_IP": vm_ip, "Serveur_IP": target,
            "Mode": mode, "Type_test": data.get("schedule","?"),
            "Profil": e.get("type","?"), "Libelle": e.get("label",""),
            "Suite_chiffrement": cipher, "AES_bits": aes_bits,
            "Delai_planifie_s": e.get("planned_delay_s", 0),
            "Duree_reelle_s": e.get("actual_duration_s", 0),
            "Handshake_ms": e.get("handshake_ms", 0),
            "Debit_Mbps": e.get("throughput_mbps", 0),
            "CPU_moy_pct": cpu, "RAM_moy_Mo": ram,
            "Retransmissions_pct": e.get("retransmit_pct", 0),
            "Taille_cle_octets": key_sz, "Taille_cert_octets": cert_sz,
        })
EOF

    log_ok "Métriques sauvegardées : $out_file"
}

# =============================================================================
# SIMULATION LATENCE WAN (tc-netem — nécessite root)
# =============================================================================
_WAN_IFACE=""

wan_apply() {
    local profile="${1:-eu}"
    _WAN_IFACE=$(net_iface)

    local delay="${WAN_DELAY[$profile]:-35ms}"
    local jitter="${WAN_JITTER[$profile]:-8ms}"
    local loss="${WAN_LOSS[$profile]:-0.1%}"

    # Supprime une règle existante avant d'appliquer
    tc qdisc del dev "$_WAN_IFACE" root 2>/dev/null || true
    tc qdisc add dev "$_WAN_IFACE" root netem \
        delay "$delay" "$jitter" distribution normal \
        loss "$loss"

    log_ok "Latence WAN ($profile) sur $_WAN_IFACE : delay=$delay ±$jitter, perte=$loss"
}

wan_remove() {
    [[ -z "${_WAN_IFACE:-}" ]] && _WAN_IFACE=$(net_iface)
    tc qdisc del dev "$_WAN_IFACE" root 2>/dev/null || true
    log_ok "Règle netem supprimée sur $_WAN_IFACE"
}

# =============================================================================
# MODE SERVEUR (VM WAN simulé)
# =============================================================================
_SERVER_PIDS=()

_cleanup_server() {
    log_info "Arrêt du serveur..."
    local pid
    for pid in "${_SERVER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # openssl s_server tourne dans un subshell et peut survivre au kill du parent
    pkill -f "openssl s_server" 2>/dev/null || true
    pkill -f "iperf3 -s"        2>/dev/null || true
    sleep 0.3
    rm -f "${SCRIPT_DIR}/.server_mode"
    [[ $EUID -eq 0 ]] && wan_remove
    rm -rf "$CERT_DIR"
}

cmd_server() {
    local mode="${1:-classic}" wan_profile="${2:-eu}"
    log_section "MODE SERVEUR | crypto: $mode | WAN: $wan_profile"

    crypto_gen_certs "$mode"

    # Latence WAN (requiert root)
    if [[ $EUID -eq 0 ]]; then
        wan_apply "$wan_profile"
        trap '_cleanup_server' EXIT INT TERM
    else
        log_warn "Non-root : simulation WAN désactivée (relancez avec sudo)"
        trap '_cleanup_server' EXIT INT TERM
    fi

    # Pool iperf3 serveur — une instance par port
    log_info "Démarrage pool iperf3 (ports 5201–5210)..."
    local port
    for port in $(seq 5201 5210); do
        iperf3 -s -p "$port" \
            --logfile "/tmp/iperf3_${port}.log" &
        _SERVER_PIDS+=($!)
    done

    # Serveur TLS (boucle pour accepter des connexions successives)
    local cipher provider_arg groups_arg
    cipher=$(get_cipher "$mode")
    provider_arg=$(get_provider_args "$mode")
    groups_arg=$(get_groups_arg "$mode")

    log_info "Démarrage TLS serveur (port $PORT_TLS, cipher: $cipher)..."
    (
        # shellcheck disable=SC2086
        while true; do
            openssl s_server \
                -cert "$CERT_DIR/server.crt" \
                -key  "$CERT_DIR/server.key" \
                -port "$PORT_TLS" \
                -tls1_3 \
                -ciphersuites "$cipher" \
                $groups_arg $provider_arg \
                -rev 2>/dev/null || true
            sleep 0.05
        done
    ) &
    _SERVER_PIDS+=($!)

    # Port marqueur (détection de déploiement par --scan)
    nc -lk -p "$PORT_MARKER" >/dev/null 2>&1 &
    _SERVER_PIDS+=($!)

    # Fichier d'etat lu par server_cli.py pour auto-detecter le mode et l'IP
    local bind_ip="${SERVER_IP:-$(local_ip)}"
    printf "mode=%s\nip=%s\n" "$mode" "$bind_ip" > "${SCRIPT_DIR}/.server_mode"

    log_ok "Serveur prêt sur $(local_ip) — Ctrl+C pour arrêter"
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

        # Mesure handshake bulk (baseline statistique indépendante du trafic)
        measure_handshake "$MODE" "$TARGET" "$HANDSHAKE_COUNT"

        # Monitoring CPU/RAM pendant le preset
        start_monitor

        log_info "Exécution preset $PRESET (60s, événements staggerés)..."
        python3 "$SCRIPT_DIR/traffic_presets.py" run \
            --preset "$PRESET" \
            --target "$TARGET" \
            --mode   "$MODE" \
            --port-tls "$PORT_TLS" \
            --cert   "$CERT_DIR/server.crt" \
            --duration 60 \
            --output "$preset_json"

        stop_monitor

        # Lecture du label du preset pour nommer le fichier CSV
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
        stop_monitor
        collect_metrics "$MODE" "$PROFILES" "$TARGET"
    fi

    log_section "Test terminé"
}

# =============================================================================
# MODE TRAFIC ALÉATOIRE CONTINU
# Appelle traffic_presets.py continuous — 5 schedulers en boucle,
# un handshake PQC + iperf3 par connexion, jusqu'à --duration ou Ctrl+C.
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

    trap 'rm -rf "$CERT_DIR"; stop_monitor' EXIT INT TERM
    crypto_gen_certs "$MODE"

    # Mesure handshake bulk en amont (baseline statistique propre)
    measure_handshake "$MODE" "$TARGET" "$HANDSHAKE_COUNT"

    start_monitor

    local out_json=""
    [[ "$DURATION" -gt 0 ]] && out_json="/tmp/pqc_random_$$.json"

    # Lance le trafic continu (bloquant jusqu'à fin de durée ou Ctrl+C)
    python3 "$script_presets" continuous \
        --target   "$TARGET" \
        --mode     "$MODE" \
        --port-tls "$PORT_TLS" \
        --cert     "$CERT_DIR/server.crt" \
        --duration "$DURATION" \
        ${out_json:+--output "$out_json"} || true

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
  --mode <MODE>         Mode cryptographique :
      classic           TLS 1.3 + X25519 + AES-128-GCM  (baseline)
      mlkem512          ML-KEM-512  + AES-128-GCM  (FIPS 203 Cat.1)
      mlkem768          ML-KEM-768  + AES-256-GCM  (FIPS 203 Cat.3)
      mlkem1024         ML-KEM-1024 + AES-256-GCM  (FIPS 203 Cat.5)
      hybrid            X25519 + ML-KEM-768 + AES-256-GCM (hybride NIST)
      mldsa44           ML-DSA-44   + AES-256-GCM  (FIPS 204 Cat.2)
      mldsa65           ML-DSA-65   + AES-256-GCM  (FIPS 204 Cat.3)
      mldsa87           ML-DSA-87   + AES-256-GCM  (FIPS 204 Cat.5)
  --preset <N>          Preset prédéfini 1-5 (trafic staggeré, 60s fixes) :
                          1=Secrétariat  2=Développeur  3=Manager
                          4=Commercial   5=IT Technicien
                          (voir: python3 traffic_presets.py list)
  --profile <PROFILS>   Trafic libre — profils en parallèle (virgule pour combiner)
                          web | file | voip | stream | msg | all
  --duration <sec>      Durée de chaque profil (mode --profile, défaut: 30)
  --hs-count <N>        Nombre d'itérations pour mesure handshake (défaut: 100)
  --output <DIR>        Répertoire de sortie CSV (défaut: ./results)

${BOLD}OPTIONS SERVEUR :${NC}
  --wan-profile <p>     Profil latence WAN : fr (15ms) | eu (35ms) | us (80ms)

${BOLD}EXEMPLES :${NC}
  # Lancer le serveur WAN (VM derrière le pare-feu)
  sudo $0 --server --mode mlkem768 --wan-profile eu

  # Preset 3 (Manager) — classique puis PQC, même données → comparaison valide
  $0 --target 10.0.1.1 --mode classic  --preset 3
  $0 --target 10.0.1.1 --mode mlkem768 --preset 3

  # Preset 4 (Commercial) — à lancer en parallèle avec preset 3 sur un autre PC
  $0 --target 10.0.1.1 --mode classic  --preset 4

  # Voir tous les presets disponibles
  python3 traffic_presets.py list

  # Trafic aléatoire continu — 5 min, puis passe au mode suivant
  $0 --target 10.0.1.1 --mode classic  --random --duration 300
  $0 --target 10.0.1.1 --mode mlkem768 --random --duration 300

  # Trafic aléatoire infini — Ctrl+C pour arrêter manuellement
  $0 --target 10.0.1.1 --mode hybrid   --random

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
        -h|--help)      usage ;;
        *) log_warn "Option inconnue : $1 (ignorée)" ;;
    esac
    shift
done

# =============================================================================
# POINT D'ENTRÉE
# =============================================================================
case "$ACTION" in
    install) cmd_install ;;
    scan)    cmd_scan    "$SCAN_SUBNET" ;;
    server)  cmd_server  "$MODE" "$WAN_PROFILE" ;;
    collect) cmd_collect_only "$COLLECT_FILE" ;;
    random)  cmd_random ;;
    test)    cmd_test ;;
esac
