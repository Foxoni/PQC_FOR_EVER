#!/usr/bin/env python3
"""
traffic_presets.py — Presets de trafic prédéfinis + trafic aléatoire continu
pour le benchmark PQC. Chaque événement ouvre une nouvelle connexion TLS
→ nouveau handshake PQC à ce moment précis dans la session (réaliste).

Usage :
  python3 traffic_presets.py list
  python3 traffic_presets.py run        --preset 3 --target IP --mode mlkem768 [OPTIONS]
  python3 traffic_presets.py run        --random   --target IP --mode classic   [OPTIONS]
  python3 traffic_presets.py continuous            --target IP --mode mlkem768 [--duration 300]
"""

import argparse
import json
import os
import random
import signal
import socket
import struct
import subprocess
import threading
import time
from typing import Any

# =============================================================================
# PORTS traffic_server.py — serveur de trafic custom (remplace iperf3)
# =============================================================================
TRAFFIC_PORT     = 5300   # TCP : file, stream, web, msg, voip (controle), jitter
TRAFFIC_UDP_PORT = 5301   # UDP : voip et jitter (donnees bidirectionnelles)

# Header datagram UDP : magic(4) + session_id(4) + seq(4) + send_us(8) = 20 octets
_UDP_HDR   = struct.Struct("!IIIQ")
_UDP_MAGIC = 0xBEEFCAFE

TRAFFIC_TYPES = ("file", "voip", "stream", "web", "msg")

# =============================================================================
# CONFIG OPENSSL PAR MODE
# Chaque handshake TLS par événement utilise ces paramètres.
# =============================================================================
OPENSSL_CFG: dict[str, dict] = {
    "classic":     {"cipher": "TLS_AES_128_GCM_SHA256", "groups": "",               "pqc": False},
    "mlkem512":    {"cipher": "TLS_AES_128_GCM_SHA256", "groups": "mlkem512",       "pqc": True},
    "mlkem768":    {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "mlkem768",       "pqc": True},
    "mlkem1024":   {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "mlkem1024",      "pqc": True},
    "hybrid-kem":  {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "X25519MLKEM768", "pqc": True},
    "hybrid-full": {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "X25519MLKEM768", "pqc": True},
    "mldsa44":     {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "",               "pqc": True},
    "mldsa65":     {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "",               "pqc": True},
    "mldsa87":     {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "",               "pqc": True},
    "slhdsa128":   {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "X25519MLKEM768", "pqc": True},
    "slhdsa256":   {"cipher": "TLS_AES_256_GCM_SHA384", "groups": "X25519MLKEM768", "pqc": True},
}

# =============================================================================
# PRESETS PRÉDÉFINIS — 5 profils PME sur 60 secondes
#
# Chaque événement = {
#   type      : file | voip | stream | web | msg
#   delay_s   : délai avant démarrage (depuis t=0 du test)
#   duration_s: durée du flux
#   label     : description lisible pour les logs/CSV
# }
#
# REMARQUES IMPORTANTES :
# - Deux événements du même type peuvent se chevaucher sans problème — traffic_server.py
#   accepte N connexions simultanées sans contention de port.
# - Les presets 3 et 4 partagent une réunion vidéo démarrant à t≈22-23s,
#   simulant une équipe qui rejoint le même meeting avec 1s de décalage réaliste.
# - Le décalage dans les délais signifie que les handshakes PQC sont répartis
#   tout au long du test, pas concentrés au début.
# =============================================================================
PRESETS: dict[int, dict[str, Any]] = {
    1: {
        "name": "Secrétariat",
        "desc": "Bureautique léger — email intensif, navigation, pas de visio",
        "events": [
            {"type": "msg",    "delay_s":  0,  "duration_s": 10, "label": "Lecture emails matin"},
            {"type": "web",    "delay_s": 12,  "duration_s": 12, "label": "Navigation (recherche fournisseur)"},
            {"type": "msg",    "delay_s": 22,  "duration_s":  8, "label": "Réponses emails clients"},
            {"type": "web",    "delay_s": 33,  "duration_s":  8, "label": "Consultation portail RH"},
            {"type": "file",   "delay_s": 41,  "duration_s": 14, "label": "Téléchargement document PDF"},
            {"type": "msg",    "delay_s": 52,  "duration_s":  8, "label": "Emails fin de matinée"},
        ],
    },
    2: {
        "name": "Développeur",
        "desc": "Transferts git lourds — messagerie équipe, documentation",
        "events": [
            {"type": "web",    "delay_s":  0,  "duration_s": 10, "label": "Documentation / Stack Overflow"},
            {"type": "file",   "delay_s":  6,  "duration_s": 18, "label": "git push (upload)"},
            {"type": "msg",    "delay_s": 20,  "duration_s":  6, "label": "Chat équipe / Slack"},
            {"type": "file",   "delay_s": 28,  "duration_s": 18, "label": "Download dépendances npm/pip"},
            {"type": "web",    "delay_s": 38,  "duration_s":  8, "label": "Doc API / GitHub"},
            {"type": "msg",    "delay_s": 50,  "duration_s": 10, "label": "Code review / commentaires PR"},
        ],
    },
    3: {
        "name": "Manager",
        "desc": "Email + réunion vidéo d'équipe (rejoint à t=22s — synchro avec preset 4)",
        "events": [
            {"type": "msg",    "delay_s":  0,  "duration_s": 12, "label": "Lecture emails matinaux"},
            {"type": "web",    "delay_s": 10,  "duration_s":  8, "label": "Tableau de bord KPI"},
            # Le manager rejoint le meeting à t=22s, le commercial (preset 4) rejoint à t=23s
            {"type": "voip",   "delay_s": 22,  "duration_s": 30, "label": "Réunion équipe — manager rejoint"},
            {"type": "msg",    "delay_s": 50,  "duration_s": 10, "label": "CR réunion / email direction"},
        ],
    },
    4: {
        "name": "Commercial",
        "desc": "Prospection email + même réunion vidéo (rejoint à t=23s, 1s après manager)",
        "events": [
            {"type": "msg",    "delay_s":  0,  "duration_s": 12, "label": "Emails prospection"},
            {"type": "web",    "delay_s": 14,  "duration_s":  8, "label": "CRM en ligne (Salesforce)"},
            # 1 seconde de décalage réaliste par rapport au manager
            {"type": "voip",   "delay_s": 23,  "duration_s": 30, "label": "Réunion équipe — commercial rejoint"},
            {"type": "file",   "delay_s": 52,  "duration_s":  8, "label": "Téléchargement rapport commercial"},
        ],
    },
    5: {
        "name": "IT Technicien",
        "desc": "Gros volumes — ISO, backup, streaming tutoriel, monitoring",
        "events": [
            {"type": "file",   "delay_s":  0,  "duration_s": 22, "label": "Download image ISO / archive"},
            {"type": "web",    "delay_s": 18,  "duration_s":  8, "label": "Console monitoring (Grafana/Zabbix)"},
            {"type": "stream", "delay_s": 28,  "duration_s": 20, "label": "Streaming vidéo tutoriel"},
            {"type": "file",   "delay_s": 40,  "duration_s": 15, "label": "Upload backup serveur"},
            {"type": "msg",    "delay_s": 52,  "duration_s":  8, "label": "Alerte / ticket support"},
        ],
    },
}

# =============================================================================
# PARAMÈTRES DU MODE CONTINU ALÉATOIRE
#
# Chaque type de trafic a :
#   - Une durée de session aléatoire (min, max) en secondes
#   - Une pause aléatoire entre deux sessions (gap) — simule le "temps de réflexion"
#   - Un délai initial aléatoire au démarrage — évite que tout parte en même temps
#   - Un pool de labels descriptifs pour les logs/CSV
# =============================================================================
_RANDOM_DURATION: dict[str, tuple[float, float]] = {
    "msg":    (5,  15),   # un email se rédige en 5-15s de transfert
    "web":    (8,  20),   # une session de navigation dure 8-20s
    "file":   (15, 35),   # un gros fichier prend 15-35s
    "voip":   (25, 50),   # une visio dure au moins 25s
    "stream": (20, 40),   # un extrait vidéo dure 20-40s
}

# Pause entre deux connexions du même type (simule le "temps hors-ligne")
_RANDOM_GAP: dict[str, tuple[float, float]] = {
    "msg":    (8,  30),    # on lit/répond ses emails par intermittence
    "web":    (5,  20),    # navigation par rafales avec pauses
    "file":   (30, 120),   # on ne télécharge pas en continu
    "voip":   (120, 600),  # les réunions ne s'enchaînent pas (2-10 min entre)
    "stream": (40, 180),   # on regarde une vidéo, puis pause
}

# Délai initial par type — décale le démarrage pour éviter un spike à T0
_INITIAL_DELAY_MAX: dict[str, float] = {
    "msg":    5,    # les emails peuvent commencer dès le début
    "web":    10,   # navigation démarre rapidement
    "file":   20,   # les téléchargements démarrent un peu plus tard
    "voip":   40,   # une réunion commence rarement dans la première minute
    "stream": 25,   # le streaming commence après quelques minutes de travail
}

# Labels réalistes pour les logs et le CSV
_RANDOM_LABELS: dict[str, list[str]] = {
    "msg": [
        "Lecture emails", "Réponses emails", "Email prospection",
        "Notification chat", "Alerte monitoring", "CR réunion par email",
    ],
    "web": [
        "Navigation web", "Recherche documentation", "CRM en ligne",
        "Portail RH", "Dashboard Grafana", "Lecture actualités tech",
    ],
    "file": [
        "Téléchargement PDF", "git push/pull", "Download dépendances",
        "Upload backup", "Rapport commercial", "Mise à jour firmware",
    ],
    "voip": [
        "Réunion équipe", "Appel client", "Formation en ligne",
        "Support technique vidéo", "Démonstration produit",
    ],
    "stream": [
        "Streaming tutoriel", "Webinaire", "Formation vidéo",
        "Replay conférence", "Démo technique",
    ],
}

# =============================================================================
# GÉNÉRATION DE TRAFIC ALÉATOIRE — staggeré et réaliste (schedule one-shot)
# =============================================================================

def generate_random_schedule(duration: int = 60, seed: int | None = None) -> list[dict]:
    """
    Génère un planning aléatoire de trafic PME réaliste.
    Règle : jamais deux événements du MÊME type simultanément.
    Les délais sont construits séquentiellement par type pour garantir cela.
    """
    if seed is not None:
        random.seed(seed)

    events: list[dict] = []

    # Email : 2-4 envois répartis dans la session avec pauses naturelles
    t = random.uniform(0, 6)
    for i in range(random.randint(2, 4)):
        dur = random.uniform(5, 12)
        if t + dur >= duration:
            break
        events.append({"type": "msg", "delay_s": round(t, 1),
                        "duration_s": round(dur, 1), "label": f"Email #{i+1}"})
        t += dur + random.uniform(8, 20)   # pause entre deux sessions mail

    # Navigation web : 1-3 sessions
    t = random.uniform(5, 15)
    for i in range(random.randint(1, 3)):
        dur = random.uniform(8, 15)
        if t + dur >= duration:
            break
        events.append({"type": "web", "delay_s": round(t, 1),
                        "duration_s": round(dur, 1), "label": f"Navigation #{i+1}"})
        t += dur + random.uniform(10, 18)

    # Transfert fichier : 1-2 fois (pas tout le monde télécharge en permanence)
    t = random.uniform(0, 20)
    for i in range(random.randint(1, 2)):
        dur = random.uniform(12, 20)
        if t + dur >= duration:
            break
        events.append({"type": "file", "delay_s": round(t, 1),
                        "duration_s": round(dur, 1), "label": f"Fichier #{i+1}"})
        t += dur + random.uniform(15, 25)

    # Visioconférence : 60% de chance, démarre dans la première moitié du test
    if random.random() < 0.6:
        start = random.uniform(10, duration * 0.45)
        dur = random.uniform(15, min(28, duration - start - 2))
        if start + dur < duration:
            events.append({"type": "voip", "delay_s": round(start, 1),
                            "duration_s": round(dur, 1), "label": "Visioconférence"})

    # Streaming vidéo : 35% de chance
    if random.random() < 0.35:
        start = random.uniform(5, duration * 0.55)
        dur = random.uniform(15, min(22, duration - start - 2))
        if start + dur < duration:
            events.append({"type": "stream", "delay_s": round(start, 1),
                            "duration_s": round(dur, 1), "label": "Streaming vidéo"})

    return sorted(events, key=lambda e: e["delay_s"])

# =============================================================================
# HANDSHAKE TLS PAR ÉVÉNEMENT
# Simule la connexion initiale au serveur WAN lors du démarrage d'un service.
# C'est là que PQC intervient : échange de clé ML-KEM ou signature ML-DSA.
# =============================================================================

def measure_handshake_once(target: str, port: int, mode: str, cert: str) -> int:
    """
    Effectue UN handshake TLS et retourne la durée en ms (-1 si échec).
    Appelé au début de chaque événement pour simuler la connexion initiale.
    """
    cfg = OPENSSL_CFG.get(mode, OPENSSL_CFG["classic"])

    cmd = [
        "openssl", "s_client",
        "-connect", f"{target}:{port}",
        "-tls1_3",
        "-ciphersuites", cfg["cipher"],
        "-no_ign_eof",
    ]
    if cfg["groups"]:
        cmd += ["-groups", cfg["groups"]]
    if cfg["pqc"]:
        cmd += ["-provider", "oqsprovider", "-provider", "default"]
    if cert and os.path.isfile(cert):
        cmd += ["-CAfile", cert, "-verify_return_error"]
    else:
        cmd += ["-noverify"]

    t0 = time.monotonic()
    try:
        subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=6,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1

    return int((time.monotonic() - t0) * 1000)

# =============================================================================
# CLIENT TRAFFIC_SERVER.PY — remplace iperf3, zero contention de port
# =============================================================================

def _recv_line_tcp(sock: socket.socket, timeout: float = 15.0) -> str:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n")[0].decode(errors="replace")


def _tcp_upload(sock: socket.socket, duration: float, bps: float | None, chunk_size: int) -> None:
    """Envoie des donnees pendant `duration` secondes avec rate-limit optionnel."""
    payload = bytes(chunk_size)
    end     = time.monotonic() + duration
    if bps is None:
        while time.monotonic() < end:
            try:
                sock.sendall(payload)
            except OSError:
                break
    else:
        bytes_per_s = bps / 8
        tokens      = 0.0
        last        = time.monotonic()
        while time.monotonic() < end:
            now    = time.monotonic()
            tokens += (now - last) * bytes_per_s
            last   = now
            if tokens >= chunk_size:
                try:
                    sock.sendall(payload)
                    tokens -= chunk_size
                except OSError:
                    break
            else:
                time.sleep(max(0.0, (chunk_size - tokens) / bytes_per_s * 0.8))


def _run_traffic(target: str, etype: str, duration: float) -> tuple[float, float]:
    """
    Remplace _run_iperf(). Connexion au traffic_server.py via TCP 5300 (ou UDP 5301 pour voip).
    Retourne (throughput_mbps, 0.0) — sans retransmissions (metrique non pertinente).
    Supporte N connexions simultanées sans contention de port.
    """
    if etype == "voip":
        return _run_traffic_voip(target, duration)
    return _run_traffic_tcp(target, etype, duration)


def _run_traffic_tcp(target: str, etype: str, duration: float) -> tuple[float, float]:
    # bps limite en bits/s (None = illimite) ; chunk en octets
    BPS    = {"web": 2_000_000, "msg": 200_000}
    CHUNKS = {"file": 65536, "stream": 65536, "web": 512, "msg": 150}

    bps        = BPS.get(etype)            # None pour file/stream
    chunk_size = CHUNKS.get(etype, 4096)
    upload     = (etype != "stream")      # stream = serveur envoie vers client

    for attempt in range(3):
        try:
            with socket.create_connection((target, TRAFFIC_PORT), timeout=10) as sock:
                req = json.dumps({"type": etype, "duration": duration})
                sock.sendall((req + "\n").encode())
                resp = json.loads(_recv_line_tcp(sock))
                if not resp.get("ready"):
                    return 0.0, 0.0

                if upload:
                    _tcp_upload(sock, duration, bps, chunk_size)
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                else:
                    # stream : drainer les donnees envoyees par le serveur
                    sock.settimeout(2.0)
                    try:
                        while sock.recv(65536):
                            pass
                    except (socket.timeout, OSError):
                        pass

                result = json.loads(_recv_line_tcp(sock, timeout=duration + 30))
                return result.get("throughput_mbps", 0.0), 0.0

        except (ConnectionRefusedError, OSError):
            if attempt < 2:
                time.sleep(3)
        except Exception:
            return 0.0, 0.0

    return 0.0, 0.0


def _run_traffic_voip(target: str, duration: float) -> tuple[float, float]:
    """UDP bidirectionnel 8 Mbps (simule visioconference 4K) via traffic_server.py."""
    sid      = random.randint(1, 0x7FFFFFFF)
    bps      = 8_000_000 / 8        # bytes/s envoi client→serveur
    chunk    = 1300                  # taille datagramme (MTU-safe)
    payload  = os.urandom(chunk - _UDP_HDR.size)
    stop     = threading.Event()

    try:
        ctrl = socket.create_connection((target, TRAFFIC_PORT), timeout=10)
        req  = json.dumps({"type": "voip", "duration": duration, "session_id": sid})
        ctrl.sendall((req + "\n").encode())
        resp = json.loads(_recv_line_tcp(ctrl))
        if not resp.get("ready"):
            ctrl.close()
            return 0.0, 0.0

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def _send_udp() -> None:
            tokens = 0.0
            last   = time.monotonic()
            seq    = 0
            end_t  = time.monotonic() + duration
            while time.monotonic() < end_t and not stop.is_set():
                now    = time.monotonic()
                tokens += (now - last) * bps
                last   = now
                if tokens >= chunk:
                    ts  = int(time.monotonic() * 1_000_000)
                    hdr = _UDP_HDR.pack(_UDP_MAGIC, sid, seq, ts)
                    try:
                        udp.sendto(hdr + payload, (target, TRAFFIC_UDP_PORT))
                    except OSError:
                        break
                    tokens -= chunk
                    seq    += 1
                else:
                    time.sleep(max(0.0, (chunk - tokens) / bps * 0.8))

        def _recv_udp() -> None:
            udp.settimeout(1.0)
            while not stop.is_set():
                try:
                    udp.recvfrom(4096)
                except socket.timeout:
                    pass
                except OSError:
                    break

        t_send = threading.Thread(target=_send_udp, daemon=True)
        t_recv = threading.Thread(target=_recv_udp, daemon=True)
        t_send.start()
        t_recv.start()

        time.sleep(duration + 1.5)
        stop.set()
        t_send.join(timeout=3)
        t_recv.join(timeout=3)
        udp.close()

        result = json.loads(_recv_line_tcp(ctrl, timeout=15))
        ctrl.close()
        return result.get("throughput_mbps", 0.0), 0.0

    except Exception as _e:
        import sys as _sys
        print(f"[voip] erreur: {_e}", file=_sys.stderr, flush=True)
        try:
            ctrl.close()
        except Exception:
            pass
        return 0.0, 0.0

# =============================================================================
# EXÉCUTEUR D'UN ÉVÉNEMENT (lancé dans un thread)
# =============================================================================

def _run_event(
    event: dict,
    target: str,
    port_tls: int,
    mode: str,
    cert: str,
    results: list,
    lock: threading.Lock,
) -> None:
    """
    Exécute un événement du planning :
    1. Attend delay_s (staggering)
    2. Effectue un handshake TLS → PQC exercé à ce moment précis
    3. Lance le trafic via traffic_server.py
    4. Enregistre les métriques
    """
    etype    = event["type"]
    delay_s  = event["delay_s"]
    dur_s    = event["duration_s"]
    label    = event.get("label", etype)

    # --- 1. Attente du délai ---
    time.sleep(delay_s)
    actual_start = time.time()

    # --- 2. Handshake TLS (PQC ici) ---
    hs_ms = measure_handshake_once(target, port_tls, mode, cert)

    # --- 3. Trafic ---
    throughput_mbps, retransmit_pct = _run_traffic(target, etype, dur_s)
    actual_duration = round(time.time() - actual_start, 1)

    # --- 4. Enregistrement ---
    with lock:
        results.append({
            "type":             etype,
            "label":            label,
            "planned_delay_s":  delay_s,
            "actual_duration_s": actual_duration,
            "handshake_ms":     hs_ms,
            "throughput_mbps":  throughput_mbps,
            "retransmit_pct":   retransmit_pct,
        })
        status = "OK" if hs_ms >= 0 else "ERR"
        print(
            f"  [{status}] t+{delay_s:5.1f}s  {etype:<7}  "
            f"hs:{hs_ms:>5}ms  {throughput_mbps:>6.2f} Mbps  '{label}'",
            flush=True,
        )

# =============================================================================
# ORCHESTRATEUR : lance tous les événements en threads parallèles
# =============================================================================

def run_schedule(
    schedule: list[dict],
    target: str,
    port_tls: int,
    mode: str,
    cert: str,
) -> list[dict]:
    """
    Démarre tous les événements en parallèle via des threads.
    Chaque thread attend son delay_s avant de démarrer.
    Retourne la liste des résultats une fois tous les threads terminés.
    """
    results: list[dict] = []
    lock    = threading.Lock()
    threads = []

    for event in schedule:
        t = threading.Thread(
            target=_run_event,
            args=(event, target, port_tls, mode, cert, results, lock),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        # Timeout = durée max possible du dernier événement + marge
        max_wait = max(
            e["delay_s"] + e["duration_s"] for e in schedule
        ) + 30
        t.join(timeout=max_wait)

    return sorted(results, key=lambda r: r["planned_delay_s"])

# =============================================================================
# MODE CONTINU ALÉATOIRE
# Chaque type de trafic a son propre thread-scheduler qui boucle indéfiniment.
# Chaque itération : délai aléatoire → handshake TLS → traffic_server → pause → repeat.
# S'arrête après `duration` secondes (0 = jusqu'au Ctrl+C).
# =============================================================================

def run_continuous(
    target: str,
    port_tls: int,
    mode: str,
    cert: str,
    duration: int = 0,
    output_file: str = "",
) -> list[dict]:
    """
    Lance 5 threads-scheduleurs (un par type de trafic) en boucle continue.
    Chaque scheduler :
      1. Délai initial aléatoire (staggering au démarrage)
      2. Boucle : handshake TLS + traffic_server + pause aléatoire + recommence
    Le résultat est une liste d'événements enregistrés au fil du temps.
    """
    end_time       = time.time() + duration if duration > 0 else float("inf")
    t_global_start = time.time()
    stop_event     = threading.Event()

    # Capture propre de Ctrl+C sans tuer le processus brutal
    _prev_sigint  = signal.getsignal(signal.SIGINT)
    _prev_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT,  lambda *_: stop_event.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())

    results: list[dict] = []
    lock = threading.Lock()

    def scheduler(etype: str) -> None:
        """
        Thread dédié à un type de trafic.
        Génère des connexions en boucle avec des paramètres aléatoires.
        Génère des connexions séquentielles (l'une après l'autre) avec pause réaliste entre elles.
        """
        labels  = _RANDOM_LABELS[etype]
        count   = 0

        # Délai initial variable selon le type (ex: voip ne démarre pas à T0)
        initial_delay = random.uniform(0, _INITIAL_DELAY_MAX[etype])
        if stop_event.wait(timeout=initial_delay):
            return

        while not stop_event.is_set() and time.time() < end_time:
            dur   = random.uniform(*_RANDOM_DURATION[etype])
            label = labels[count % len(labels)]
            t_event_start = time.time()

            # Vérifie qu'on a le temps de finir l'événement avant la deadline
            if duration > 0 and t_event_start + dur >= end_time:
                break

            # ── Handshake TLS ── PQC exercé ICI, au moment de la connexion
            hs_ms = measure_handshake_once(target, port_tls, mode, cert)
            if stop_event.is_set():
                break

            # ── Trafic traffic_server.py ──
            throughput_mbps, retransmit_pct = _run_traffic(target, etype, dur)
            actual_dur = round(time.time() - t_event_start, 1)
            offset     = round(t_event_start - t_global_start, 1)

            with lock:
                results.append({
                    "type":              etype,
                    "label":             label,
                    "planned_delay_s":   offset,
                    "actual_duration_s": actual_dur,
                    "handshake_ms":      hs_ms,
                    "throughput_mbps":   throughput_mbps,
                    "retransmit_pct":    retransmit_pct,
                })
                status = "OK" if hs_ms >= 0 else "ERR"
                print(
                    f"  [{status}] t+{offset:>5.0f}s  {etype:<7}  "
                    f"hs:{hs_ms:>5}ms  {throughput_mbps:>6.2f} Mbps  '{label}'",
                    flush=True,
                )

            count += 1
            if stop_event.is_set():
                break

            # ── Pause réaliste avant la prochaine connexion du même type ──
            gap      = random.uniform(*_RANDOM_GAP[etype])
            deadline = end_time - time.time()
            wait     = min(gap, deadline) if duration > 0 else gap
            stop_event.wait(timeout=max(0.0, wait))

    # Démarrage de tous les schedulers
    schedulers = [
        threading.Thread(target=scheduler, args=(etype,), daemon=True)
        for etype in TRAFFIC_TYPES
    ]
    for t in schedulers:
        t.start()

    dur_label = f"{duration}s" if duration > 0 else "infinie (Ctrl+C pour arrêter)"
    print(f"\nTrafic continu aléatoire | mode: {mode} | cible: {target}:{port_tls} | durée: {dur_label}")
    print(f"\n{'':5} {'t_start':>8}  {'type':<7}  {'handshake':>10}  {'débit':>10}  label")
    print("─" * 72)

    try:
        while not stop_event.is_set() and time.time() < end_time:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

    print("\nArrêt — attente fin des connexions en cours...")
    for t in schedulers:
        t.join(timeout=90)

    # Restaure les handlers de signaux originaux
    signal.signal(signal.SIGINT,  _prev_sigint)
    signal.signal(signal.SIGTERM, _prev_sigterm)

    elapsed = round(time.time() - t_global_start, 1)
    results_sorted = sorted(results, key=lambda r: r["planned_delay_s"])
    print(f"─ Terminé en {elapsed}s — {len(results_sorted)} événements enregistrés ─")

    if output_file:
        out = {
            "schedule":         "continuous_random",
            "schedule_label":   "Trafic aléatoire continu",
            "mode":             mode,
            "target":           target,
            "total_duration_s": elapsed,
            "events":           results_sorted,
        }
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)
        print(f"Résultats → {output_file}")

    return results_sorted

# =============================================================================
# SOUS-COMMANDES CLI
# =============================================================================

def cmd_list() -> None:
    print(f"\n{'Preset':<8} {'Nom':<18} Description")
    print("─" * 72)
    for n, p in PRESETS.items():
        print(f"  {n:<6} {p['name']:<18} {p['desc']}")
        for e in p["events"]:
            print(f"         t={e['delay_s']:>4.0f}s  [{e['type']:<7}]  {e['label']}")
        print()


def cmd_run(args: argparse.Namespace) -> None:
    # Sélection du planning
    if args.preset:
        preset = PRESETS[args.preset]
        schedule = preset["events"]
        schedule_name = f"preset_{args.preset}"
        schedule_label = preset["name"]
        print(f"\nPreset {args.preset} — {preset['name']} : {preset['desc']}")
    else:
        schedule = generate_random_schedule(duration=args.duration, seed=args.seed)
        schedule_name  = "random"
        schedule_label = "Trafic aléatoire"
        print(f"\nPlanning aléatoire généré ({len(schedule)} événements) :")
        for e in schedule:
            print(f"  t+{e['delay_s']:>5.1f}s  [{e['type']:<7}]  {e['label']}")

    print(
        f"Cible: {args.target}:{args.port_tls}  |  Mode: {args.mode}  "
        f"|  Durée max: {args.duration}s\n"
    )
    print(f"{'':5} {'t_start':>8}  {'type':<7}  {'handshake':>10}  {'débit':>10}  label")
    print("─" * 72)

    # Exécution
    t_global = time.time()
    results  = run_schedule(
        schedule  = schedule,
        target    = args.target,
        port_tls  = args.port_tls,
        mode      = args.mode,
        cert      = args.cert,
    )
    elapsed = round(time.time() - t_global, 1)

    print(f"\n─ Test terminé en {elapsed}s ─")

    # Écriture du JSON de résultats
    output = {
        "schedule":       schedule_name,
        "schedule_label": schedule_label,
        "mode":           args.mode,
        "target":         args.target,
        "total_duration_s": elapsed,
        "events":         results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Résultats → {args.output}")

# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --- list ---
    sub.add_parser("list", help="Affiche les 5 presets disponibles")

    # --- run ---
    run_p = sub.add_parser("run", help="Exécute un preset ou du trafic aléatoire")
    group = run_p.add_mutually_exclusive_group(required=True)
    group.add_argument("--preset", type=int, choices=[1, 2, 3, 4, 5],
                       metavar="N", help="Preset 1-5")
    group.add_argument("--random", action="store_true",
                       help="Trafic aléatoire staggeré")
    run_p.add_argument("--target",   required=True, help="IP du serveur WAN")
    run_p.add_argument("--mode",     default="classic",
                       choices=list(OPENSSL_CFG), help="Mode cryptographique")
    run_p.add_argument("--port-tls", type=int, default=8443, dest="port_tls",
                       help="Port TLS du serveur (défaut: 8443)")
    run_p.add_argument("--cert",     default="",
                       help="Chemin vers le certificat CA pour validation TLS")
    run_p.add_argument("--duration", type=int, default=60,
                       help="Durée max du test en secondes (défaut: 60)")
    run_p.add_argument("--seed",     type=int, default=None,
                       help="Graine aléatoire (reproductibilité du mode --random)")
    run_p.add_argument("--output",   required=True,
                       help="Fichier JSON de sortie des résultats")
    run_p.add_argument("--vm-id",   type=int, default=0, dest="vm_id",
                       help="(conservé pour compatibilité, non utilisé avec traffic_server)")

    # --- continuous ---
    cont_p = sub.add_parser(
        "continuous",
        help="Trafic aléatoire continu — boucle jusqu'à --duration ou Ctrl+C",
    )
    cont_p.add_argument("--target",   required=True, help="IP du serveur WAN")
    cont_p.add_argument("--mode",     default="classic",
                        choices=list(OPENSSL_CFG), help="Mode cryptographique")
    cont_p.add_argument("--port-tls", type=int, default=8443, dest="port_tls",
                        help="Port TLS (défaut: 8443)")
    cont_p.add_argument("--cert",     default="",
                        help="Certificat CA pour validation TLS")
    cont_p.add_argument("--duration", type=int, default=0,
                        help="Durée en secondes (0 = infini, Ctrl+C pour arrêter)")
    cont_p.add_argument("--output",   default="",
                        help="Fichier JSON de sortie (optionnel)")
    cont_p.add_argument("--vm-id",   type=int, default=0, dest="vm_id",
                        help="(conservé pour compatibilité, non utilisé avec traffic_server)")

    args = parser.parse_args()

    if args.cmd == "list":
        cmd_list()
    elif args.cmd == "run":
        cmd_run(args)
    elif args.cmd == "continuous":
        run_continuous(
            target      = args.target,
            port_tls    = args.port_tls,
            mode        = args.mode,
            cert        = args.cert,
            duration    = args.duration,
            output_file = args.output,
        )


if __name__ == "__main__":
    main()
