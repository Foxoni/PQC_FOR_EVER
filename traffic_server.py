#!/usr/bin/env python3
"""
traffic_server.py — Serveur de trafic multi-client pour benchmark PQC.
Remplace le pool de 10 instances iperf3 par un seul processus.

  TCP 5300 : file, stream, web, msg, voip (controle), jitter (controle)
  UDP 5301 : voip et jitter (donnees bidirectionnelles)

Protocole par connexion TCP :
  Client → Serveur : {"type":"file","duration":22,"session_id":0}\n
  Serveur → Client : {"ready":true}\n
  ... echange de donnees ...
  Serveur → Client : {"throughput_mbps":45.2,"bytes":1234567,"jitter_ms":null,"lost_pct":null}\n

Usage :
    python3 traffic_server.py [--tcp-port 5300] [--udp-port 5301]
"""

import json
import os
import socket
import struct
import sys
import threading
import time

TCP_PORT = 5300
UDP_PORT = 5301
CHUNK    = 65536
PAYLOAD  = os.urandom(CHUNK)

# Header datagram UDP : magic(4) + session_id(4) + seq(4) + send_us(8) = 20 octets
_HDR   = struct.Struct("!IIIQ")
MAGIC  = 0xBEEFCAFE

# Socket UDP partagee entre le thread recepteur et les threads emetteurs par session
_udp_sock: socket.socket | None = None

# =============================================================================
# Sessions UDP (voip / jitter)
# =============================================================================

class _UdpSession:
    def __init__(self, sid: int, duration: float, bps: float):
        self.sid      = sid
        self.duration = duration
        self.bps      = bps          # bytes/s
        self.addr     = None         # (ip, port) client, set au premier paquet recu
        self.start    = None         # time.monotonic() du premier paquet
        self.rx_pkts  = 0
        self.rx_bytes = 0
        self.max_seq  = -1
        self._j_acc   = 0.0
        self._last_rx : float | None = None
        self._last_tx_us: int  | None = None
        self.jitter_ms = 0.0
        self.done      = threading.Event()
        self.lock      = threading.Lock()

    def on_packet(self, data: bytes, addr: tuple, now: float) -> None:
        with self.lock:
            if len(data) < _HDR.size:
                return
            magic, _, seq, tx_us = _HDR.unpack_from(data)
            if magic != MAGIC:
                return
            if self.start is None:
                self.start = now
                self.addr  = addr
            self.rx_pkts  += 1
            self.rx_bytes += len(data)
            if seq > self.max_seq:
                self.max_seq = seq
            # Jitter RFC 3550
            if self._last_rx is not None:
                d_arr = now - self._last_rx
                d_tx  = (tx_us - self._last_tx_us) / 1_000_000
                self._j_acc += (abs(d_arr - d_tx) - self._j_acc) / 16
                self.jitter_ms = round(self._j_acc * 1000, 3)
            self._last_rx    = now
            self._last_tx_us = tx_us

    @property
    def result(self) -> dict:
        with self.lock:
            elapsed   = (time.monotonic() - self.start) if self.start else 0.001
            tput      = round(self.rx_bytes * 8 / elapsed / 1e6, 3)
            expected  = self.max_seq + 1 if self.max_seq >= 0 else 0
            lost      = round((1 - self.rx_pkts / max(expected, 1)) * 100, 3) if expected else 0.0
        return {
            "throughput_mbps": tput,
            "bytes":           self.rx_bytes,
            "jitter_ms":       self.jitter_ms,
            "lost_pct":        lost,
        }


_sessions: dict[int, _UdpSession] = {}
_ses_lock  = threading.Lock()


# =============================================================================
# Thread recepteur UDP global
# =============================================================================

def _udp_receiver(udp_port: int) -> None:
    global _udp_sock
    _udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Buffer 4 MB pour absorber les rafales voip (plusieurs VMs simultanees)
    _udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    try:
        _udp_sock.bind(("0.0.0.0", udp_port))
    except OSError as e:
        print(f"[traffic_server] ERREUR bind UDP :{udp_port} → {e}", file=sys.stderr)
        return
    _udp_sock.settimeout(1.0)
    print(f"[traffic_server] UDP :{udp_port} pret", flush=True)

    while True:
        try:
            data, addr = _udp_sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        now = time.monotonic()
        if len(data) < _HDR.size:
            continue
        _, sid, _, _ = _HDR.unpack_from(data)
        with _ses_lock:
            ses = _sessions.get(sid)
        if ses:
            ses.on_packet(data, addr, now)


# =============================================================================
# Thread emetteur UDP par session (bidir)
# =============================================================================

def _udp_sender(ses: _UdpSession) -> None:
    chunk    = 1300
    payload  = os.urandom(chunk - _HDR.size)
    bps      = ses.bps
    tokens   = 0.0
    last     = time.monotonic()
    seq      = 0
    end_t    = time.monotonic() + ses.duration + 1.0

    while time.monotonic() < end_t and not ses.done.is_set():
        if ses.addr is None:
            time.sleep(0.01)
            continue

        now    = time.monotonic()
        tokens += (now - last) * bps
        last   = now

        if tokens >= chunk:
            ts  = int(time.monotonic() * 1_000_000)
            hdr = _HDR.pack(MAGIC, ses.sid, seq, ts)
            try:
                _udp_sock.sendto(hdr + payload, ses.addr)
            except OSError:
                break
            tokens -= chunk
            seq    += 1
        else:
            wait = (chunk - tokens) / bps
            time.sleep(min(wait * 0.8, 0.005))


# =============================================================================
# Helpers TCP
# =============================================================================

def _recv_line(conn: socket.socket, timeout: float = 15.0) -> str:
    conn.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf.split(b"\n")[0].decode(errors="replace")


def _send_result(conn: socket.socket, result: dict) -> None:
    conn.sendall((json.dumps(result) + "\n").encode())


def _send_data(conn: socket.socket, duration: float) -> tuple[int, float]:
    """Envoie des donnees (stream / download)."""
    end   = time.monotonic() + duration
    start = time.monotonic()
    total = 0
    while time.monotonic() < end:
        try:
            n = conn.send(PAYLOAD)
            if n == 0:
                break
            total += n
        except (BrokenPipeError, ConnectionResetError, OSError):
            break
    return total, max(time.monotonic() - start, 0.001)


def _recv_data(conn: socket.socket, timeout: float) -> tuple[int, float]:
    """Recoit des donnees jusqu'a EOF ou timeout inactivite (file/web/msg / upload)."""
    conn.settimeout(2.0)
    total    = 0
    start    = None
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            data = conn.recv(CHUNK)
            if not data:
                break
            if start is None:
                start = time.monotonic()
            total += len(data)
        except socket.timeout:
            if start is not None:
                break
        except (ConnectionResetError, OSError):
            break

    elapsed = time.monotonic() - (start if start else time.monotonic())
    return total, max(elapsed, 0.001)


# =============================================================================
# Handler UDP session (voip / jitter)
# =============================================================================

def _handle_udp_session(conn: socket.socket, ttype: str,
                         duration: float, sid: int) -> None:
    bps = {
        "voip":   8_000_000 / 8,   # 8 Mbps bidir (visioconf 4K realiste)
        "jitter": 1_000_000 / 8,
    }.get(ttype, 1_000_000 / 8)

    ses = _UdpSession(sid, duration, bps)
    with _ses_lock:
        _sessions[sid] = ses

    conn.sendall(b'{"ready":true}\n')

    sender = threading.Thread(target=_udp_sender, args=(ses,), daemon=True)
    sender.start()

    time.sleep(duration + 2.0)
    ses.done.set()
    sender.join(timeout=3.0)

    with _ses_lock:
        _sessions.pop(sid, None)

    _send_result(conn, ses.result)


# =============================================================================
# Handler TCP principal (un thread par connexion)
# =============================================================================

def _handle_tcp(conn: socket.socket, addr: tuple) -> None:
    try:
        line = _recv_line(conn)
        if not line:
            return
        req = json.loads(line)
    except Exception as e:
        try:
            _send_result(conn, {"error": str(e), "throughput_mbps": 0.0,
                                "bytes": 0, "jitter_ms": None, "lost_pct": None})
        except OSError:
            pass
        conn.close()
        return

    ttype    = req.get("type", "")
    duration = float(req.get("duration", 10))
    sid      = int(req.get("session_id", 0))

    try:
        if ttype in ("voip", "jitter"):
            _handle_udp_session(conn, ttype, duration, sid)

        elif ttype == "stream":
            conn.sendall(b'{"ready":true}\n')
            total, elapsed = _send_data(conn, duration)
            _send_result(conn, {
                "throughput_mbps": round(total * 8 / elapsed / 1e6, 3),
                "bytes":           total,
                "jitter_ms":       None,
                "lost_pct":        None,
            })

        elif ttype in ("file", "web", "msg"):
            conn.sendall(b'{"ready":true}\n')
            total, elapsed = _recv_data(conn, duration + 10)
            _send_result(conn, {
                "throughput_mbps": round(total * 8 / elapsed / 1e6, 3),
                "bytes":           total,
                "jitter_ms":       None,
                "lost_pct":        None,
            })

        else:
            _send_result(conn, {"error": f"type inconnu: {ttype!r}",
                                "throughput_mbps": 0.0, "bytes": 0,
                                "jitter_ms": None, "lost_pct": None})

    except Exception as e:
        try:
            _send_result(conn, {"error": str(e), "throughput_mbps": 0.0,
                                "bytes": 0, "jitter_ms": None, "lost_pct": None})
        except OSError:
            pass
    finally:
        conn.close()


# =============================================================================
# Point d'entree
# =============================================================================

def main() -> None:
    tcp_port = TCP_PORT
    udp_port = UDP_PORT

    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--tcp-port" and i + 1 < len(args):
            tcp_port = int(args[i + 1])
        elif arg == "--udp-port" and i + 1 < len(args):
            udp_port = int(args[i + 1])

    # Thread recepteur UDP (demarre en premier pour etre pret avant les connexions TCP)
    threading.Thread(target=_udp_receiver, args=(udp_port,),
                     daemon=True, name="udp-recv").start()
    time.sleep(0.2)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", tcp_port))
        except OSError as e:
            print(f"[traffic_server] ERREUR bind TCP :{tcp_port} → {e}", file=sys.stderr)
            sys.exit(1)
        srv.listen(64)
        print(f"[traffic_server] TCP :{tcp_port}  UDP :{udp_port}  pret", flush=True)

        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            threading.Thread(
                target=_handle_tcp, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
