#!/usr/bin/env python3
"""
traffic_gen.py — Module Python pour pqc_bench.sh
Sous-commandes :
  monitor      <outfile>                   Enregistre CPU/RAM toutes les 500ms
  avgres       <monitor.csv>               Calcule moyennes CPU/RAM
  stats        <timing.txt>                Calcule min/avg/max/p99 (ms)
  parse_traffic <result.json>              Extrait debit depuis JSON traffic_server
  client       <type> <target> <dur> <out> Client trafic TCP vers traffic_server
  jitter       <target> <dur> <out>        Mesure jitter UDP via traffic_server
  aggregate    <out.csv> <in1.csv> ...     Fusionne plusieurs CSV en un seul
"""

import csv
import json
import os
import random
import signal
import socket
import struct
import sys
import threading
import time
import statistics

# Ports traffic_server.py
_TCP_PORT = 5300
_UDP_PORT = 5301
_HDR      = struct.Struct("!IIIQ")    # magic(4)+sid(4)+seq(4)+ts_us(8)
_MAGIC    = 0xBEEFCAFE


# =============================================================================
# SOUS-COMMANDE : monitor
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
    n      = len(vals)
    p99_idx = max(0, int(n * 0.99) - 1)

    print(f"{vals[0]} {round(statistics.mean(vals))} {vals[-1]} {vals[p99_idx]}")


# =============================================================================
# SOUS-COMMANDE : parse_traffic
# Lit le JSON produit par traffic_server.py et imprime "throughput_mbps 0.0".
# Conserve aussi parse_iperf comme alias pour compatibilite avec l'ancien code.
# =============================================================================
def cmd_parse_traffic(result_file: str) -> None:
    try:
        data = json.load(open(result_file))
    except (FileNotFoundError, json.JSONDecodeError):
        print("0 0")
        return

    if "error" in data and data.get("throughput_mbps", 0.0) == 0.0:
        print("0 0")
        return

    mbps = round(float(data.get("throughput_mbps", 0.0)), 3)
    print(f"{mbps} 0.0")


# =============================================================================
# HELPERS CLIENT TCP
# =============================================================================

def _recv_line(sock: socket.socket, timeout: float = 15.0) -> str:
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n")[0].decode(errors="replace")


def _tcp_upload(sock: socket.socket, duration: float, bps: float | None,
                chunk_size: int) -> None:
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
        tokens = 0.0
        last   = time.monotonic()
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


# =============================================================================
# SOUS-COMMANDE : client
# Client trafic TCP vers traffic_server.py. Ecrit JSON resultat dans outfile.
# Types : file, stream, web, msg, voip
# =============================================================================
def cmd_client(etype: str, target: str, duration: int, outfile: str) -> None:
    if etype == "voip":
        result = _client_voip(target, duration)
    else:
        result = _client_tcp(etype, target, duration)
    with open(outfile, "w") as f:
        json.dump(result, f)


def _client_tcp(etype: str, target: str, duration: int) -> dict:
    BPS    = {"web": 2_000_000, "msg": 200_000}
    CHUNKS = {"file": 65536, "stream": 65536, "web": 512, "msg": 150}

    bps        = BPS.get(etype)
    chunk_size = CHUNKS.get(etype, 4096)
    upload     = (etype != "stream")

    for attempt in range(3):
        try:
            with socket.create_connection((target, _TCP_PORT), timeout=10) as sock:
                sock.sendall((json.dumps({"type": etype, "duration": duration}) + "\n").encode())
                resp = json.loads(_recv_line(sock))
                if not resp.get("ready"):
                    return {"throughput_mbps": 0.0, "error": "not ready"}

                if upload:
                    _tcp_upload(sock, duration, bps, chunk_size)
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                else:
                    sock.settimeout(2.0)
                    try:
                        while sock.recv(65536):
                            pass
                    except (socket.timeout, OSError):
                        pass

                return json.loads(_recv_line(sock, timeout=duration + 30))
        except (ConnectionRefusedError, OSError):
            if attempt < 2:
                time.sleep(3)
        except Exception as e:
            return {"throughput_mbps": 0.0, "error": str(e)}

    return {"throughput_mbps": 0.0, "error": "connexion impossible apres 3 tentatives"}


def _client_voip(target: str, duration: int) -> dict:
    sid     = random.randint(1, 0x7FFFFFFF)
    bps     = 30_000_000 / 8
    chunk   = 1300
    payload = os.urandom(chunk - _HDR.size)
    stop    = threading.Event()
    ctrl    = None
    udp     = None

    try:
        ctrl = socket.create_connection((target, _TCP_PORT), timeout=10)
        ctrl.sendall((json.dumps({"type": "voip", "duration": duration,
                                  "session_id": sid}) + "\n").encode())
        resp = json.loads(_recv_line(ctrl))
        if not resp.get("ready"):
            return {"throughput_mbps": 0.0, "error": "not ready"}

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def _send() -> None:
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
                    hdr = _HDR.pack(_MAGIC, sid, seq, ts)
                    try:
                        udp.sendto(hdr + payload, (target, _UDP_PORT))
                    except OSError:
                        break
                    tokens -= chunk
                    seq    += 1
                else:
                    time.sleep(max(0.0, (chunk - tokens) / bps * 0.8))

        def _recv() -> None:
            udp.settimeout(1.0)
            while not stop.is_set():
                try:
                    udp.recvfrom(4096)
                except socket.timeout:
                    pass
                except OSError:
                    break

        t_s = threading.Thread(target=_send, daemon=True)
        t_r = threading.Thread(target=_recv, daemon=True)
        t_s.start()
        t_r.start()
        time.sleep(duration + 1.5)
        stop.set()
        t_s.join(timeout=3)
        t_r.join(timeout=3)

        result = json.loads(_recv_line(ctrl, timeout=15))
        return result

    except Exception as e:
        return {"throughput_mbps": 0.0, "error": str(e)}
    finally:
        stop.set()
        if udp:
            try:
                udp.close()
            except OSError:
                pass
        if ctrl:
            try:
                ctrl.close()
            except OSError:
                pass


# =============================================================================
# SOUS-COMMANDE : jitter
# Mesure jitter UDP via traffic_server.py. Ecrit JSON dans outfile.
# Utilise type="jitter" (1 Mbps bidir) pour ne pas saturer le lien.
# =============================================================================
def cmd_jitter(target: str, duration: int, outfile: str) -> None:
    sid     = random.randint(1, 0x7FFFFFFF)
    bps     = 1_000_000 / 8      # bytes/s
    chunk   = 200
    payload = os.urandom(chunk - _HDR.size)
    stop    = threading.Event()
    ctrl    = None
    udp     = None

    try:
        ctrl = socket.create_connection((target, _TCP_PORT), timeout=10)
        ctrl.sendall((json.dumps({"type": "jitter", "duration": duration,
                                  "session_id": sid}) + "\n").encode())
        resp = json.loads(_recv_line(ctrl))
        if not resp.get("ready"):
            raise RuntimeError("server not ready")

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def _send() -> None:
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
                    hdr = _HDR.pack(_MAGIC, sid, seq, ts)
                    try:
                        udp.sendto(hdr + payload, (target, _UDP_PORT))
                    except OSError:
                        break
                    tokens -= chunk
                    seq    += 1
                else:
                    time.sleep(max(0.0, (chunk - tokens) / bps * 0.8))

        def _recv() -> None:
            udp.settimeout(1.0)
            while not stop.is_set():
                try:
                    udp.recvfrom(4096)
                except socket.timeout:
                    pass
                except OSError:
                    break

        t_s = threading.Thread(target=_send, daemon=True)
        t_r = threading.Thread(target=_recv, daemon=True)
        t_s.start()
        t_r.start()
        time.sleep(duration + 1.5)
        stop.set()
        t_s.join(timeout=3)
        t_r.join(timeout=3)

        result = json.loads(_recv_line(ctrl, timeout=15))

    except Exception as e:
        result = {"jitter_ms": -1, "lost_pct": -1, "throughput_mbps": 0.0, "error": str(e)}
    finally:
        stop.set()
        if udp:
            try:
                udp.close()
            except OSError:
                pass
        if ctrl:
            try:
                ctrl.close()
            except OSError:
                pass

    with open(outfile, "w") as f:
        json.dump(result, f)


# =============================================================================
# SOUS-COMMANDE : aggregate
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

    elif subcmd in ("parse_traffic", "parse_iperf") and len(sys.argv) == 3:
        # parse_iperf conservé comme alias pour compatibilité
        cmd_parse_traffic(sys.argv[2])

    elif subcmd == "client" and len(sys.argv) == 6:
        # client <type> <target> <duration> <outfile>
        cmd_client(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])

    elif subcmd == "jitter" and len(sys.argv) == 5:
        # jitter <target> <duration> <outfile>
        cmd_jitter(sys.argv[2], int(sys.argv[3]), sys.argv[4])

    elif subcmd == "aggregate" and len(sys.argv) >= 4:
        cmd_aggregate(sys.argv[2], *sys.argv[3:])

    else:
        print(f"Usage invalide : {' '.join(sys.argv)}", file=sys.stderr)
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
