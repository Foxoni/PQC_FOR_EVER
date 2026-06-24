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

    _DISPATCH = {
        "STATUS":      _status,
        "CONFIGURE":   _configure,
        "ARM":         _arm,
        "START":       _start,
        "RESET":       _reset,
        "GET_RESULTS": _get_results,
        "GET_LOGS":    _get_logs,
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
