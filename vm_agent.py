#!/usr/bin/env python3
"""
vm_agent.py - Daemon de controle sur chaque VM de test PQC.
Ecoute sur TCP 9998, repond aux commandes JSON de server_cli.py.

Etats : idle -> configured -> armed -> running -> done

Lancement :
    python3 vm_agent.py [--port PORT]
"""

import sys
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

PORT       = 9998
SCRIPT_DIR = Path(__file__).resolve().parent
BENCH      = SCRIPT_DIR / "pqc_bench.sh"
RESULTS    = SCRIPT_DIR / "results"
LOG_TAIL   = 20   # nombre de lignes retournees par STATUS et GET_LOGS


class VMAgent:
    def __init__(self):
        self._lock      = threading.Lock()
        self.state      = "idle"
        self.cfg        = {}
        self.proc       = None
        self.outfile    = None   # trouve apres la fin du test
        self.logfile    = None
        self.returncode = None
        self._run_start = 0.0

    # ------------------------------------------------------------------ #
    # Handlers                                                             #
    # ------------------------------------------------------------------ #

    def _tail(self, n=LOG_TAIL):
        if not self.logfile or not Path(self.logfile).exists():
            return []
        lines = Path(self.logfile).read_text(errors="replace").splitlines()
        return lines[-n:]

    def _find_output_csv(self):
        """Trouve le CSV genere par pqc_bench.sh dans RESULTS apres le debut du test."""
        mode = self.cfg.get("mode", "")
        best, best_mtime = None, self._run_start - 1
        for p in RESULTS.glob("*.csv"):
            try:
                mtime = p.stat().st_mtime
            except OSError:
                continue
            if mode in p.name and mtime > self._run_start:
                if mtime > best_mtime:
                    best, best_mtime = p, mtime
        return str(best) if best else None

    def _status(self, _req):
        with self._lock:
            if self.proc and self.proc.poll() is not None and self.state == "running":
                self.returncode = self.proc.returncode
                self.outfile    = self._find_output_csv()
                self.state      = "done"
            return {
                "ok":          True,
                "state":       self.state,
                "config":      self.cfg,
                "returncode":  self.returncode,
                "has_results": bool(self.outfile and Path(self.outfile).exists()),
                "last_log":    self._tail(5),
            }

    def _configure(self, req):
        with self._lock:
            if self.state == "running":
                return {"ok": False, "error": "test en cours, impossible de configurer"}
            self.cfg = {
                "target":      req.get("target"),
                "preset":      req.get("preset"),
                "mode":        req.get("mode", "mlkem768"),
                "wan_profile": req.get("wan_profile", "eu"),
                "duration":    req.get("duration"),
            }
            if not self.cfg["target"]:
                return {"ok": False, "error": "parametre --target manquant (IP du serveur WAN)"}
            RESULTS.mkdir(exist_ok=True)
            tag          = f"p{self.cfg['preset']}" if self.cfg["preset"] is not None else "r"
            base         = f"{self.cfg['mode']}_{tag}"
            self.outfile    = None
            self.logfile    = str(RESULTS / f"log_{base}.txt")
            self.returncode = None
            self.state      = "configured"
            return {"ok": True, "state": self.state, "config": self.cfg}

    def _arm(self, _req):
        with self._lock:
            if self.state not in ("configured", "done"):
                return {"ok": False, "error": f"etat '{self.state}' invalide pour arm"}
            self.state = "armed"
            return {"ok": True, "state": self.state}

    def _start(self, _req):
        with self._lock:
            if self.state != "armed":
                return {"ok": False, "error": f"etat '{self.state}' invalide pour start"}

            # pqc_bench.sh traite --output comme un DOSSIER, pas un fichier
            cmd = ["bash", str(BENCH), "--test",
                   "--target", self.cfg["target"],
                   "--mode",   self.cfg["mode"],
                   "--output", str(RESULTS)]
            if self.cfg.get("preset") is not None:
                cmd += ["--preset", str(self.cfg["preset"])]
            if self.cfg.get("wan_profile"):
                cmd += ["--wan-profile", self.cfg["wan_profile"]]
            if self.cfg.get("duration"):
                cmd += ["--duration", str(self.cfg["duration"])]

            self._run_start = time.time()
            try:
                logfd = open(self.logfile, "w")
            except OSError as exc:
                return {"ok": False, "error": f"impossible d'ouvrir le fichier de log : {exc}"}

            try:
                self.proc = subprocess.Popen(cmd, cwd=str(SCRIPT_DIR),
                                             stdout=logfd,
                                             stderr=subprocess.STDOUT)
            except OSError as exc:
                logfd.close()
                return {"ok": False, "error": f"impossible de lancer pqc_bench.sh : {exc}"}
            finally:
                logfd.close()

            self.state = "running"
            pid = self.proc.pid

        def _watch():
            self.proc.wait()
            with self._lock:
                if self.state == "running":
                    self.returncode = self.proc.returncode
                    self.outfile    = self._find_output_csv()
                    self.state      = "done"
                    if self.returncode != 0:
                        print(f"[vm_agent] pqc_bench.sh terminé avec code {self.returncode}", flush=True)

        threading.Thread(target=_watch, daemon=True).start()
        return {"ok": True, "state": "running", "pid": pid}

    def _reset(self, _req):
        with self._lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
            self.proc       = None
            self.outfile    = None
            self.logfile    = None
            self.returncode = None
            self._run_start = 0.0
            self.cfg        = {}
            self.state      = "idle"
            return {"ok": True, "state": "idle"}

    def _get_results(self, _req):
        path = self.outfile
        if not path or not Path(path).exists():
            return {"ok": False, "error": "aucun fichier de resultats"}
        return {"ok": True, "content": Path(path).read_text(), "file": path}

    def _get_logs(self, req):
        if not self.logfile or not Path(self.logfile).exists():
            return {"ok": False, "error": "aucun fichier de log"}
        n    = int(req.get("lines", 50))
        tail = self._tail(n)
        return {
            "ok":         True,
            "log":        "\n".join(tail),
            "file":       self.logfile,
            "returncode": self.returncode,
            "state":      self.state,
        }

    def _preflight(self, _req):
        """Vérifie que l'environnement local est prêt pour un benchmark."""
        checks = []

        def _ok(name, detail=""):
            checks.append({"name": name, "status": "ok", "detail": detail})

        def _warn(name, detail=""):
            checks.append({"name": name, "status": "warn", "detail": detail})

        def _fail(name, detail=""):
            checks.append({"name": name, "status": "fail", "detail": detail})

        # — Configuration —
        with self._lock:
            cfg   = dict(self.cfg)
            state = self.state

        target = cfg.get("target", "")
        mode   = cfg.get("mode", "")

        if not target or not mode:
            _fail("configuration", f"VM non configurée (état: {state}) — lancez 'set' puis 'arm'")
            return {"ok": True, "checks": checks}
        _ok("configuration", f"mode={mode}  target={target}")

        # — Outils —
        TOOLS = [
            ("openssl", True,  "TLS impossible sans openssl"),
            ("iperf3",  False, "métriques débit/jitter indisponibles"),
            ("ping",    False, "métriques latence indisponibles"),
            ("tshark",  False, "capture paquets indisponible"),
            ("python3", False, "calculs de stats limités"),
            ("ip",      False, "détection d'interface limitée"),
        ]
        for tool, critical, reason in TOOLS:
            if shutil.which(tool):
                _ok(f"outil:{tool}")
            elif critical:
                _fail(f"outil:{tool}", reason)
            else:
                _warn(f"outil:{tool}", reason)

        # — OQS provider (requis pour tout mode non-classic) —
        if mode != "classic" and shutil.which("openssl"):
            try:
                r = subprocess.run(
                    ["openssl", "list", "-providers"],
                    capture_output=True, text=True, timeout=5
                )
                if "oqsprovider" in r.stdout:
                    _ok("openssl:oqs-provider")
                else:
                    _fail("openssl:oqs-provider",
                          "oqs-provider absent — 'openssl list -providers' ne le montre pas")
            except Exception as e:
                _warn("openssl:oqs-provider", f"vérification échouée : {e}")
        else:
            _ok("openssl:oqs-provider", "non requis (mode classic)")

        # — Droits tshark (root ou CAP_NET_RAW) —
        if shutil.which("tshark"):
            if os.geteuid() == 0:
                _ok("droits:tshark", "root")
            else:
                try:
                    tshark_bin = shutil.which("tshark")
                    r = subprocess.run(
                        ["getcap", tshark_bin],
                        capture_output=True, text=True, timeout=3
                    )
                    if "cap_net_raw" in r.stdout:
                        _ok("droits:tshark", "CAP_NET_RAW présent")
                    else:
                        _warn("droits:tshark",
                              "ni root ni CAP_NET_RAW — tshark ne pourra pas capturer")
                except Exception:
                    _warn("droits:tshark", "impossible de vérifier les capabilities (getcap absent ?)")

        # — Connectivité réseau —
        # Ping simple vers la cible
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                _ok("réseau:ping", f"{target} joignable")
            else:
                _fail("réseau:ping", f"{target} injoignable — vérifiez l'IP et le routage")
        except Exception as e:
            _warn("réseau:ping", f"ping échoué : {e}")

        # Port TLS (8443)
        try:
            with socket.create_connection((target, 8443), timeout=3):
                _ok("réseau:tls-8443", f"{target}:8443 ouvert")
        except OSError:
            _fail("réseau:tls-8443",
                  f"{target}:8443 inaccessible — serveur démarré ? (pqc_bench.sh --server)")

        # Ports iperf3 (5201-5210) — TCP control channel
        iperf3_found = None
        for port in range(5201, 5211):
            try:
                with socket.create_connection((target, port), timeout=1):
                    iperf3_found = port
                    break
            except OSError:
                continue
        if iperf3_found:
            _ok("réseau:iperf3", f"{target}:{iperf3_found} accessible (pool 5201-5210)")
        else:
            _warn("réseau:iperf3",
                  f"aucun port iperf3 (5201-5210) accessible sur {target} — métriques débit/jitter manquantes")

        return {"ok": True, "checks": checks}

    _DISPATCH = {
        "STATUS":      _status,
        "CONFIGURE":   _configure,
        "ARM":         _arm,
        "START":       _start,
        "RESET":       _reset,
        "GET_RESULTS": _get_results,
        "GET_LOGS":    _get_logs,
        "PREFLIGHT":   _preflight,
    }

    # ------------------------------------------------------------------ #
    # Gestion des connexions entrantes                                     #
    # ------------------------------------------------------------------ #

    def handle(self, conn):
        try:
            conn.settimeout(15.0)
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 65536:
                    resp = {"ok": False, "error": "message trop grand (>64 Ko)"}
                    conn.sendall((json.dumps(resp) + "\n").encode())
                    return
            req  = json.loads(buf.split(b"\n")[0])
            fn   = self._DISPATCH.get(req.get("cmd", "").upper())
            resp = fn(self, req) if fn else {"ok": False, "error": "commande inconnue"}
        except TimeoutError:
            resp = {"ok": False, "error": "timeout lecture commande"}
        except json.JSONDecodeError as e:
            resp = {"ok": False, "error": f"JSON invalide : {e}"}
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        try:
            conn.sendall((json.dumps(resp) + "\n").encode())
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Point d'entree                                                               #
# --------------------------------------------------------------------------- #

def main():
    port = PORT
    if "--port" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("--port") + 1])
        except (IndexError, ValueError):
            print("Usage: vm_agent.py [--port PORT]", file=sys.stderr)
            sys.exit(1)

    if not BENCH.exists():
        print(f"[vm_agent] ERREUR : pqc_bench.sh introuvable dans {SCRIPT_DIR}", file=sys.stderr)
        sys.exit(1)

    agent = VMAgent()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", port))
        except OSError as exc:
            print(f"[vm_agent] ERREUR bind :{port} → {exc}", file=sys.stderr)
            print(f"[vm_agent] Le port {port} est déjà utilisé ? Essayez --port <autre>", file=sys.stderr)
            sys.exit(1)
        srv.listen(16)
        print(f"[vm_agent] ecoute :{port}  bench={BENCH}")

        while True:
            try:
                conn, addr = srv.accept()
            except OSError as exc:
                print(f"[vm_agent] accept() échoué : {exc}", file=sys.stderr)
                continue
            threading.Thread(target=agent.handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
