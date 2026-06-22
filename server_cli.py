#!/usr/bin/env python3
"""
server_cli.py - CLI central pour orchestrer les VMs de test PQC.
Tourne sur le serveur WAN, contacte les agents vm_agent.py sur TCP 9998.

Usage :
    python3 server_cli.py [--subnet 192.168.1.0/24]

Commandes disponibles :
    scan [subnet]                                 Decouverte des agents sur le reseau
    list                                          Tableau des VMs connues et leur etat
    set <ip|all> --mode MODE [--preset N] [...]   Configure une ou toutes les VMs
    arm [all|<ip>]                                Met les VMs configurees en standby
    launch                                        Lance toutes les VMs armed simultanement
    status [all|<ip>]                             Poll l'etat des VMs
    reset [all|<ip>]                              Remet en idle (kill si en cours)
    results [--output FILE]                       Collecte et compile les CSV
    help / exit
"""

import sys
import json
import socket
import csv
import io
import time
import statistics
import threading
import ipaddress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

AGENT_PORT   = 9998
RESULTS_DIR  = Path("results")
SCAN_WORKERS = 64
SCAN_TIMEOUT = 0.5


class VM:
    __slots__ = ("ip", "state", "config", "last_seen")

    def __init__(self, ip):
        self.ip        = ip
        self.state     = "unknown"
        self.config    = {}
        self.last_seen = None


class ServerCLI:

    def __init__(self, default_subnet=None):
        self.vms    = {}
        self.subnet = default_subnet

    # ------------------------------------------------------------------ #
    # Transport JSON                                                       #
    # ------------------------------------------------------------------ #

    def _send(self, ip, req, timeout=5.0):
        """Envoie req JSON a l'agent ip:AGENT_PORT, renvoie la reponse JSON."""
        try:
            with socket.create_connection((ip, AGENT_PORT), timeout=timeout) as s:
                s.sendall((json.dumps(req) + "\n").encode())
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                return json.loads(buf.split(b"\n")[0])
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------ #
    # Commandes                                                            #
    # ------------------------------------------------------------------ #

    def cmd_scan(self, args):
        subnet = args[0] if args else self.subnet
        if not subnet:
            print("Usage: scan <subnet>  ex: scan 192.168.1.0/24"); return
        self.subnet = subnet

        try:
            hosts = list(ipaddress.ip_network(subnet, strict=False).hosts())
        except ValueError as e:
            print(f"Sous-reseau invalide: {e}"); return

        print(f"Scan de {len(hosts)} adresses ({subnet})...")
        found = 0

        def probe(ip):
            r = self._send(str(ip), {"cmd": "STATUS"}, timeout=SCAN_TIMEOUT)
            return (str(ip), r) if r.get("ok") else None

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            futures = {ex.submit(probe, h): h for h in hosts}
            for future in as_completed(futures):
                pair = future.result()
                if pair:
                    ip, status = pair
                    vm = self.vms.setdefault(ip, VM(ip))
                    vm.state     = status.get("state", "unknown")
                    vm.config    = status.get("config", {})
                    vm.last_seen = datetime.now().strftime("%H:%M:%S")
                    found += 1
                    print(f"  {ip:17s}  [{vm.state}]")

        print(f"{found} agent(s) detecte(s).")

    def cmd_list(self, args):
        if not self.vms:
            print("Aucune VM connue. Lancez 'scan <subnet>' d'abord."); return

        print(f"\n{'IP':17s}  {'ETAT':12s}  {'PRESET':7s}  {'MODE':16s}  {'WAN':5s}  VU A")
        print("-" * 72)
        for ip, vm in sorted(self.vms.items()):
            print(f"{ip:17s}  {vm.state:12s}  {str(vm.config.get('preset', '-')):7s}"
                  f"  {vm.config.get('mode', '-'):16s}  {vm.config.get('wan_profile', '-'):5s}"
                  f"  {vm.last_seen or '-'}")
        print()

    def cmd_set(self, args):
        """set <ip|all> --mode MODE --target IP [--preset N] [--wan-profile WAN] [--duration D]"""
        if not args:
            print("Usage: set <ip|all> --mode MODE --target IP [--preset N] [--wan-profile eu] [--duration 60]")
            return

        target = args[0]
        cfg, i = {}, 1
        while i < len(args):
            flag = args[i]
            if flag in ("--preset", "--mode", "--wan-profile", "--duration", "--target") and i + 1 < len(args):
                key      = flag.lstrip("-").replace("-", "_")
                raw      = args[i + 1]
                cfg[key] = int(raw) if key in ("preset", "duration") else raw
                i += 2
            else:
                i += 1

        if "mode" not in cfg:
            print("--mode requis"); return
        if "target" not in cfg:
            print("--target requis (IP du serveur WAN)"); return

        targets = sorted(self.vms) if target == "all" else [target]
        for ip in targets:
            r = self._send(ip, {"cmd": "CONFIGURE", **cfg})
            print(f"  {ip}: {'OK' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                vm = self.vms.setdefault(ip, VM(ip))
                vm.state  = "configured"
                vm.config = cfg

    def cmd_arm(self, args):
        target  = args[0] if args else "all"
        targets = sorted(self.vms) if target == "all" else [target]
        for ip in targets:
            r = self._send(ip, {"cmd": "ARM"})
            print(f"  {ip}: {'armed' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                self.vms.setdefault(ip, VM(ip)).state = "armed"

    def cmd_launch(self, args):
        armed = [ip for ip, vm in self.vms.items() if vm.state == "armed"]
        if not armed:
            print("Aucune VM armed. Utilisez 'arm [all]' d'abord."); return

        print(f"Connexion aux {len(armed)} VM(s) pour lancement synchronise...")
        results   = {}
        ready_n   = [0]
        rlock     = threading.Lock()
        all_ready = threading.Event()
        go        = threading.Event()

        def fire(ip):
            def _signal():
                with rlock:
                    ready_n[0] += 1
                    if ready_n[0] == len(armed):
                        all_ready.set()
            try:
                with socket.create_connection((ip, AGENT_PORT), timeout=10) as s:
                    _signal()
                    if not go.wait(timeout=15):
                        results[ip] = {"ok": False, "error": "timeout go"}
                        return
                    s.sendall((json.dumps({"cmd": "START"}) + "\n").encode())
                    buf = b""
                    while b"\n" not in buf:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    results[ip] = (json.loads(buf.split(b"\n")[0])
                                   if buf.strip() else {"ok": False, "error": "reponse vide"})
            except Exception as e:
                results[ip] = {"ok": False, "error": str(e)}
                _signal()

        threads = [threading.Thread(target=fire, args=(ip,), daemon=True) for ip in armed]
        for t in threads:
            t.start()

        if not all_ready.wait(timeout=12):
            print(f"  {ready_n[0]}/{len(armed)} VMs connectees — lancement quand meme")

        t0 = time.perf_counter()
        go.set()
        for t in threads:
            t.join(timeout=20)
        print(f"Signal envoye en {(time.perf_counter() - t0) * 1000:.0f} ms")

        for ip, r in sorted(results.items()):
            if r.get("ok"):
                self.vms[ip].state = "running"
                print(f"  {ip}: demarre (pid {r.get('pid')})")
            else:
                print(f"  {ip}: ERREUR — {r.get('error')}")

    def cmd_status(self, args):
        target  = args[0] if args else "all"
        targets = sorted(self.vms) if target == "all" else [target]
        for ip in targets:
            r = self._send(ip, {"cmd": "STATUS"})
            if r.get("ok"):
                vm = self.vms.setdefault(ip, VM(ip))
                vm.state  = r["state"]
                vm.config = r.get("config", vm.config)
                rc        = r.get("returncode")
                rc_str    = f"  rc={rc}" if rc is not None else ""
                print(f"  {ip}: {r['state']}{rc_str}  {r.get('config', {})}")
                if r.get("last_log"):
                    for line in r["last_log"]:
                        print(f"    | {line}")
            else:
                print(f"  {ip}: injoignable — {r.get('error')}")

    def cmd_logs(self, args):
        """logs [<ip>|all] [--lines N]"""
        n       = 50
        if "--lines" in args:
            idx = args.index("--lines")
            if idx + 1 < len(args):
                n = int(args[idx + 1])
            args = [a for i, a in enumerate(args) if i not in (idx, idx + 1)]

        target  = args[0] if args else "all"
        targets = sorted(self.vms) if target == "all" else [target]
        for ip in targets:
            r = self._send(ip, {"cmd": "GET_LOGS", "lines": n}, timeout=10)
            print(f"\n{'='*60}")
            print(f"  {ip}  etat={r.get('state', '?')}  rc={r.get('returncode', '?')}")
            print(f"{'='*60}")
            if r.get("ok"):
                print(r.get("log", "(vide)"))
            else:
                print(f"  ERREUR: {r.get('error')}")
        print()

    def cmd_reset(self, args):
        target  = args[0] if args else "all"
        targets = sorted(self.vms) if target == "all" else [target]
        for ip in targets:
            r = self._send(ip, {"cmd": "RESET"})
            print(f"  {ip}: {'idle' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                self.vms.setdefault(ip, VM(ip)).state = "idle"

    def cmd_results(self, args):
        RESULTS_DIR.mkdir(exist_ok=True)
        outfile = "results_master.csv"
        if "--output" in args:
            idx = args.index("--output")
            if idx + 1 < len(args):
                outfile = args[idx + 1]

        all_rows   = []
        fieldnames = []
        errors     = []

        print("Collecte des resultats...")
        for ip in sorted(self.vms):
            r = self._send(ip, {"cmd": "GET_RESULTS"}, timeout=15)
            if not r.get("ok"):
                print(f"  {ip}: {r.get('error', 'pas de resultats')}")
                errors.append(ip)
                continue

            content = r.get("content", "").strip()
            if not content:
                print(f"  {ip}: CSV vide"); continue

            (RESULTS_DIR / f"result_{ip.replace('.', '_')}.csv").write_text(content)

            reader = csv.DictReader(io.StringIO(content))
            rows   = list(reader)
            if not rows:
                print(f"  {ip}: aucune donnee"); continue

            if not fieldnames:
                fieldnames = list(reader.fieldnames or [])
            for row in rows:
                row["vm_ip"] = ip
            all_rows.extend(rows)
            print(f"  {ip}: {len(rows)} ligne(s)")

        if not all_rows:
            print("Aucune donnee collectee."); return

        summary = self._make_summary(all_rows, fieldnames)

        with open(outfile, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["vm_ip"] + fieldnames, extrasaction="ignore")
            w.writeheader()
            w.writerows(all_rows)
            w.writerows(summary)

        print(f"\nMaster CSV: {outfile}")
        print(f"  {len(all_rows)} ligne(s) individuelle(s), {len(summary)} ligne(s) de synthese")
        if errors:
            print(f"  VMs sans resultats: {', '.join(errors)}")

    def _make_summary(self, rows, fieldnames):
        """Calcule des lignes de synthese globale par (mode, wan_profile)."""
        num_fields = [f for f in fieldnames if f not in ("mode", "wan_profile")]

        def _vals(grp, field):
            out = []
            for r in grp:
                try:
                    out.append(float(r[field]))
                except (ValueError, KeyError, TypeError):
                    pass
            return out

        groups = defaultdict(list)
        for row in rows:
            groups[(row.get("mode", "?"), row.get("wan_profile", "?"))].append(row)

        summary = []
        for (mode, wan), grp in sorted(groups.items()):
            n = len(grp)

            for label, fn in [
                (f"SUMMARY_AVG (n={n})",   statistics.mean),
                (f"SUMMARY_MIN (n={n})",   min),
                (f"SUMMARY_MAX (n={n})",   max),
            ]:
                srow = {"vm_ip": label, "mode": mode, "wan_profile": wan}
                for f in num_fields:
                    v = _vals(grp, f)
                    srow[f] = round(fn(v), 3) if v else ""
                summary.append(srow)

            if n > 1:
                srow = {"vm_ip": f"SUMMARY_STDDEV (n={n})", "mode": mode, "wan_profile": wan}
                for f in num_fields:
                    v = _vals(grp, f)
                    srow[f] = round(statistics.stdev(v), 3) if len(v) > 1 else ""
                summary.append(srow)

        return summary

    def cmd_help(self, _args):
        print("""
  scan [subnet]                                              Decouverte des agents (ex: 192.168.1.0/24)
  list                                                       Tableau des VMs et leur etat
  set <ip|all> --mode MODE --target IP [--preset N] [...]   Configure une ou toutes les VMs
  arm [all|<ip>]                                             Met les VMs configurees en standby
  launch                                                     Lance toutes les VMs armed simultanement
  status [all|<ip>]                                          Poll l'etat + derniers logs
  logs [all|<ip>] [--lines N]                                Affiche les logs de pqc_bench.sh (defaut 50 lignes)
  reset [all|<ip>]                                           Remet en idle (kill si en cours)
  results [--output FILE]                                    Collecte et compile les CSV en master
  help                                                       Cette aide
  exit / quit                                                Quitte le CLI
""")

    _CMDS = {
        "scan":    cmd_scan,
        "list":    cmd_list,
        "set":     cmd_set,
        "arm":     cmd_arm,
        "launch":  cmd_launch,
        "status":  cmd_status,
        "logs":    cmd_logs,
        "reset":   cmd_reset,
        "results": cmd_results,
        "help":    cmd_help,
    }

    # ------------------------------------------------------------------ #
    # Boucle principale                                                    #
    # ------------------------------------------------------------------ #

    def run(self):
        try:
            import readline  # noqa — historique des commandes sous Linux/Mac
        except ImportError:
            pass

        print("PQC Bench — Controleur central  (tapez 'help' pour l'aide)\n")
        while True:
            try:
                line = input("pqc> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue
            if line in ("exit", "quit"):
                break

            parts = line.split()
            fn    = self._CMDS.get(parts[0])
            if fn:
                try:
                    fn(self, parts[1:])
                except Exception as e:
                    print(f"Erreur: {e}")
            else:
                print(f"Commande inconnue: '{parts[0]}'. Tapez 'help'.")


# --------------------------------------------------------------------------- #
# Point d'entree                                                               #
# --------------------------------------------------------------------------- #

def main():
    import argparse
    p = argparse.ArgumentParser(description="PQC Bench — CLI central")
    p.add_argument("--subnet", default=None,
                   help="Sous-reseau par defaut (ex: 192.168.1.0/24)")
    a = p.parse_args()
    ServerCLI(default_subnet=a.subnet).run()


if __name__ == "__main__":
    main()
