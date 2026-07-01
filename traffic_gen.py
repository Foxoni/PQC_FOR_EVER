#!/usr/bin/env python3
"""
traffic_gen.py — Module Python pour pqc_bench.sh
Sous-commandes :
  monitor  <outfile>                  Enregistre CPU/RAM toutes les 500ms
  avgres   <monitor.csv>              Calcule moyennes CPU/RAM
  stats    <timing.txt>               Calcule min/avg/max/p99 (ms)
  parse_iperf <result.json>           Extrait débit et retransmissions iperf3
  msg      <target> <port> <dur> <out> Envoie petits paquets irréguliers (scapy)
  aggregate <out.csv> <in1.csv> ...   Fusionne plusieurs CSV en un seul
"""

import sys
import os
import json
import csv
import time
import signal
import socket
import random
import statistics


# =============================================================================
# SOUS-COMMANDE : monitor
# Échantillonne CPU et RAM toutes les ~500ms jusqu'au SIGTERM/SIGINT.
# Appelé en background par pqc_bench.sh, tué par stop_monitor().
# =============================================================================
def cmd_monitor(outfile: str) -> None:
    try:
        import psutil
    except ImportError:
        sys.exit("psutil requis : pip3 install psutil")

    running = [True]
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGINT,  lambda *_: running.__setitem__(0, False))

    with open(outfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "cpu_pct", "ram_mb"])
        while running[0]:
            writer.writerow([
                int(time.time()),
                psutil.cpu_percent(interval=0.5),
                round(psutil.virtual_memory().used / 1024 / 1024, 1),
            ])
            f.flush()


# =============================================================================
# SOUS-COMMANDE : avgres
# Lit le CSV produit par monitor et imprime "cpu_avg ram_avg" sur stdout.
# =============================================================================
def cmd_avgres(monitor_csv: str) -> None:
    rows = list(csv.DictReader(open(monitor_csv)))
    if not rows:
        print("0 0")
        return

    cpus = [float(r["cpu_pct"]) for r in rows if r.get("cpu_pct")]
    rams = [float(r["ram_mb"])  for r in rows if r.get("ram_mb")]

    cpu_avg = round(statistics.mean(cpus), 1) if cpus else 0.0
    ram_avg = round(statistics.mean(rams), 1) if rams else 0.0
    print(f"{cpu_avg} {ram_avg}")


# =============================================================================
# SOUS-COMMANDE : stats
# Lit une liste de valeurs entières (une par ligne) et imprime
# "min avg max p99" sur stdout. Utilisé pour les temps de handshake.
# =============================================================================
def cmd_stats(timing_file: str) -> None:
    try:
        vals = [int(l) for l in open(timing_file) if l.strip()]
    except FileNotFoundError:
        print("0 0 0 0")
        return

    if not vals:
        print("0 0 0 0")
        return

    vals.sort()
    n = len(vals)
    p99_idx = max(0, int(n * 0.99) - 1)

    vmin = vals[0]
    vavg = round(statistics.mean(vals))
    vmax = vals[-1]
    vp99 = vals[p99_idx]

    print(f"{vmin} {vavg} {vmax} {vp99}")


# =============================================================================
# SOUS-COMMANDE : parse_iperf
# Lit le JSON produit par iperf3 et imprime "throughput_mbps retransmit_pct".
# Gère les formats TCP et UDP, et le mode --bidir (VoIP).
# =============================================================================
def cmd_parse_iperf(result_file: str) -> None:
    try:
        data = json.load(open(result_file))
    except (FileNotFoundError, json.JSONDecodeError):
        print("0 0")
        return

    end = data.get("end", {})

    # Débit : somme reçue (TCP) ou envoyée (UDP)
    throughput_bps = 0.0
    for key in ("sum_received", "sum_sent", "sum"):
        if key in end:
            throughput_bps = end[key].get("bits_per_second", 0.0)
            break
    # Mode bidir : deux flux, on prend le total
    if "sum_bidir_reverse" in end:
        rev = end["sum_bidir_reverse"].get("bits_per_second", 0.0)
        throughput_bps = max(throughput_bps, rev)

    throughput_mbps = round(throughput_bps / 1e6, 2)

    # Retransmissions TCP — sum_sent n'a pas de champ "packets" pour TCP (c'est UDP qui l'a).
    # On estime le nombre de segments utiles depuis les octets transférés (MSS typique 1460).
    sent        = end.get("sum_sent", {})
    retrans     = sent.get("retransmits", 0) or 0
    bytes_sent  = sent.get("bytes", 0) or 0
    useful_segs = bytes_sent / 1460
    total_segs  = useful_segs + retrans
    retransmit_pct = round(retrans / total_segs * 100, 3) if total_segs > 0 else 0.0

    print(f"{throughput_mbps} {retransmit_pct}")


# =============================================================================
# SOUS-COMMANDE : msg
# Simule du trafic messagerie : petits paquets TCP de taille variable,
# envoyés à intervalles irréguliers (profil chat / email).
# N'utilise PAS Scapy pour éviter les droits root côté client.
# =============================================================================
def cmd_msg(target: str, port: int, duration: int, outfile: str) -> None:
    end_time = time.time() + duration
    packets_sent = 0
    errors = 0

    while time.time() < end_time:
        # Taille variable : 50–800 octets (email court à pièce jointe légère)
        size = random.randint(50, 800)
        # Délai irrégulier : 0.05s (burst) à 2.0s (long silence)
        delay = random.choices(
            [random.uniform(0.05, 0.3), random.uniform(0.5, 2.0)],
            weights=[0.7, 0.3],
        )[0]

        try:
            with socket.create_connection((target, port), timeout=2.0) as s:
                s.sendall(os.urandom(size))
            packets_sent += 1
        except OSError:
            errors += 1

        time.sleep(delay)

    result = {
        "profile": "msg",
        "packets_sent": packets_sent,
        "errors": errors,
        "duration_s": duration,
    }
    with open(outfile, "w") as f:
        json.dump(result, f)


# =============================================================================
# SOUS-COMMANDE : aggregate
# Fusionne plusieurs fichiers CSV (même schéma) en un seul,
# en ne gardant l'en-tête que du premier fichier.
# =============================================================================
def cmd_aggregate(outfile: str, *input_files: str) -> None:
    valid = [f for f in input_files if os.path.isfile(f)]
    if not valid:
        print(f"[aggregate] Aucun fichier CSV trouvé", file=sys.stderr)
        return

    with open(outfile, "w", newline="") as fout:
        writer = None
        for path in valid:
            with open(path, newline="") as fin:
                reader = csv.DictReader(fin)
                if writer is None:
                    writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
                    writer.writeheader()
                for row in reader:
                    writer.writerow(row)

    print(f"[aggregate] {len(valid)} fichier(s) fusionné(s) → {outfile}")


# =============================================================================
# DISPATCHER
# =============================================================================
def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    subcmd = sys.argv[1]

    if subcmd == "monitor" and len(sys.argv) == 3:
        cmd_monitor(sys.argv[2])

    elif subcmd == "avgres" and len(sys.argv) == 3:
        cmd_avgres(sys.argv[2])

    elif subcmd == "stats" and len(sys.argv) == 3:
        cmd_stats(sys.argv[2])

    elif subcmd == "parse_iperf" and len(sys.argv) == 3:
        cmd_parse_iperf(sys.argv[2])

    elif subcmd == "msg" and len(sys.argv) == 6:
        cmd_msg(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])

    elif subcmd == "aggregate" and len(sys.argv) >= 4:
        cmd_aggregate(sys.argv[2], *sys.argv[3:])

    else:
        print(f"Usage invalide : {' '.join(sys.argv)}", file=sys.stderr)
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
