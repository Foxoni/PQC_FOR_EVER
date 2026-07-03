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
    preflight [all|<ip>]                          Verifie l'environnement avant lancement
    launch [--force]                              Lance les VMs (preflight auto, --force ignore les FAIL)
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

AGENT_PORT       = 9998
RESULTS_DIR      = Path("results")
SCAN_WORKERS     = 64
SCAN_TIMEOUT     = 0.5
SERVER_MODE_FILE = Path(__file__).resolve().parent / ".server_mode"


class _SrvMonitor:
    """Collecte CPU/RAM/réseau pendant la durée exacte d'un test (launch → results)."""

    def __init__(self):
        self._thread  = None
        self._stop    = threading.Event()
        self._samples = []   # (cpu_pct, ram_mb, rx_bytes_cumul, timestamp)
        self._iface   = ""

    def start(self, iface: str = "") -> None:
        self._iface   = iface
        self._samples = []
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="srv-mon")
        self._thread.start()

    def stop(self) -> dict:
        """Arrête le monitoring et retourne les métriques moyennées, ou {} si pas de données."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

        if not self._samples:
            return {}

        cpus     = [s[0] for s in self._samples]
        rams     = [s[1] for s in self._samples]
        first_rx = self._samples[0][2]
        last_rx  = self._samples[-1][2]
        first_ts = self._samples[0][3]
        last_ts  = self._samples[-1][3]
        elapsed  = max(last_ts - first_ts, 1)

        return {
            "cpu_avg_pct": round(statistics.mean(cpus), 1),
            "ram_avg_mb":  round(statistics.mean(rams)),
            "rx_mbps":     round((last_rx - first_rx) * 8 / elapsed / 1e6, 3),
            "n_samples":   len(self._samples),
            "elapsed_s":   int(elapsed),
        }

    # ------------------------------------------------------------------
    # Lecture /proc (Linux uniquement — silencieux sur autres OS)
    # ------------------------------------------------------------------

    def _read_cpu(self):
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("cpu "):
                        v = [int(x) for x in line.split()[1:8]]
                        # user nice sys idle iowait irq softirq
                        return sum(v), v[3] + v[4]   # total, idle+iowait
        except OSError:
            pass
        return 0, 0

    def _read_ram(self):
        total = avail = 0
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        avail = int(line.split()[1])
                        break
        except OSError:
            pass
        return (total - avail) // 1024   # Mo

    def _read_rx(self):
        if not self._iface:
            return 0
        target = self._iface + ":"
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    parts = line.split()
                    if parts and parts[0] == target:
                        return int(parts[1])   # rx bytes cumulés
        except (OSError, ValueError, IndexError):
            pass
        return 0

    def _loop(self):
        prev_total, prev_idle = self._read_cpu()

        while not self._stop.wait(5):
            total, idle = self._read_cpu()
            dt = total - prev_total
            di = idle  - prev_idle
            cpu_pct = round((1 - di / dt) * 100, 1) if dt > 0 else 0.0
            prev_total, prev_idle = total, idle

            self._samples.append((
                cpu_pct,
                self._read_ram(),
                self._read_rx(),
                time.time(),
            ))


class VM:
    __slots__ = ("ip", "control_ip", "state", "config", "last_seen")

    def __init__(self, ip):
        self.ip         = ip
        self.control_ip = None   # IP interface contrôle (None = même que test)
        self.state      = "unknown"
        self.config     = {}
        self.last_seen  = None


class ServerCLI:

    def __init__(self, default_subnet=None):
        self.vms         = {}
        self.subnet      = default_subnet
        self._idx        = {}         # {id: test_ip} — assigne par cmd_scan
        self._freed_ids  = set()      # IDs libérés, réutilisables en priorité
        self._mon        = _SrvMonitor()
        self._mon_result = {}         # rempli par _watch_until_done quand le test se termine

    def _resolve(self, target):
        """Convertit 'all', '1', '2,3', ou une IP en liste d'IPs.
        Accepte aussi un mix : '1,192.168.1.5'."""
        if target == "all":
            return sorted(self.vms)
        ips = []
        for part in target.split(","):
            part = part.strip()
            try:
                n  = int(part)
                ip = self._idx.get(n)
                if ip:
                    ips.append(ip)
                else:
                    print(f"  [WARN] indice {n} inconnu — relancez scan")
            except ValueError:
                ips.append(part)   # deja une IP
        return ips

    # ------------------------------------------------------------------ #
    # Transport JSON                                                       #
    # ------------------------------------------------------------------ #

    def _send_raw(self, addr, req, timeout=5.0):
        """Connexion directe à addr:AGENT_PORT — pas de lookup VM."""
        try:
            with socket.create_connection((addr, AGENT_PORT), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall((json.dumps(req) + "\n").encode())
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 10 * 1024 * 1024:
                        return {"ok": False, "error": "reponse trop grande (>10 Mo)"}
                return json.loads(buf.split(b"\n")[0])
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"JSON invalide dans la reponse : {e}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _send(self, ip, req, timeout=5.0):
        """Envoie req à la VM identifiée par son IP test, via l'IP contrôle si disponible."""
        vm   = self.vms.get(ip)
        addr = vm.control_ip if (vm and vm.control_ip) else ip
        return self._send_raw(addr, req, timeout)

    # ------------------------------------------------------------------ #
    # Commandes                                                            #
    # ------------------------------------------------------------------ #

    def _next_scan_id(self):
        """Retourne le plus petit ID disponible (libérés en priorité, sinon max+1)."""
        if self._freed_ids:
            return min(self._freed_ids)
        used = set(self._idx.keys())
        return max(used) + 1 if used else 1

    def _scan_test(self, subnet, force_remove=False, force_keep=False):
        try:
            hosts = list(ipaddress.ip_network(subnet, strict=False).hosts())
        except ValueError as e:
            print(f"Sous-réseau invalide : {e}"); return

        print(f"Scan LAN test — {len(hosts)} adresses ({subnet})...")

        # Étape 1 : découverte des agents qui répondent
        alive = {}
        def probe(ip):
            r = self._send_raw(str(ip), {"cmd": "STATUS"}, timeout=SCAN_TIMEOUT)
            return (str(ip), r) if r.get("ok") else None

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            for fut in as_completed({ex.submit(probe, h): h for h in hosts}):
                pair = fut.result()
                if pair:
                    alive[pair[0]] = pair[1]

        found_ips  = set(alive.keys())
        ip_to_id   = {v: k for k, v in self._idx.items()}   # test_ip → id

        # Étape 2 : réconciliation des VMs connues qui n'ont pas répondu
        to_remove = []
        for ip, vm in list(self.vms.items()):
            if ip in found_ips or vm.state == "unreachable":
                continue
            vm_id  = ip_to_id.get(ip)
            id_str = f"ID {vm_id}" if vm_id is not None else "sans ID"

            if force_remove:
                to_remove.append((ip, vm_id))
                print(f"  [REMOVE] Agent {id_str} ({ip})")
            elif force_keep:
                vm.state = "unreachable"
                print(f"  [UNREACHABLE] Agent {id_str} ({ip}) marqué injoignable")
            else:
                ans = input(f"\n  Agent {id_str} ({ip}) introuvable — supprimer ? [y/N] ").strip().lower()
                if ans == "y":
                    to_remove.append((ip, vm_id))
                else:
                    vm.state = "unreachable"
                    print(f"    → conservé (unreachable)")

        for ip, vm_id in to_remove:
            if vm_id is not None:
                self._idx.pop(vm_id, None)
                self._freed_ids.add(vm_id)
            self.vms.pop(ip, None)
            vm_id_str = str(vm_id) if vm_id is not None else "?"
            print(f"    → {ip} supprimé, ID {vm_id_str} libéré")

        # Étape 3 : attribution / récupération des IDs pour les IPs trouvées
        for ip in sorted(found_ips, key=ipaddress.ip_address):
            status = alive[ip]
            r      = self._send_raw(ip, {"cmd": "GET_ID"}, timeout=2.0)
            agent_id = r.get("id") if r.get("ok") else None

            if agent_id is not None and self._idx.get(agent_id) == ip:
                # ID cohérent avec nos registres → réutiliser
                action = "existant"
                vm_id  = agent_id
            elif agent_id is not None and agent_id not in self._idx:
                # ID inconnu de nous (session précédente ?) → adopter
                self._freed_ids.discard(agent_id)
                self._idx[agent_id] = ip
                action = "adopté"
                vm_id  = agent_id
            else:
                # Pas d'ID ou conflit → assigner un nouvel ID
                vm_id = self._next_scan_id()
                self._freed_ids.discard(vm_id)
                self._idx[vm_id] = ip
                self._send_raw(ip, {"cmd": "ASSIGN_ID", "id": vm_id}, timeout=2.0)
                action = "nouveau" if agent_id is None else f"réassigné (conflit ID {agent_id})"

            vm           = self.vms.setdefault(ip, VM(ip))
            vm.state     = status.get("state", "unknown")
            vm.config    = status.get("config", {})
            vm.last_seen = datetime.now().strftime("%H:%M:%S")
            print(f"  [{vm_id}] {ip:17s}  [{vm.state}]  ({action})")

        print(f"\n{len(found_ips)} agent(s) détecté(s) sur le LAN test.")

    def _scan_control(self, subnet):
        try:
            hosts = list(ipaddress.ip_network(subnet, strict=False).hosts())
        except ValueError as e:
            print(f"Sous-réseau invalide : {e}"); return

        print(f"\nScan LAN contrôle — {len(hosts)} adresses ({subnet})...")

        found = []
        def probe_ctrl(ip):
            r = self._send_raw(str(ip), {"cmd": "GET_ID"}, timeout=SCAN_TIMEOUT)
            if r.get("ok") and r.get("id") is not None:
                return (str(ip), r["id"])
            return None

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            for fut in as_completed({ex.submit(probe_ctrl, h): h for h in hosts}):
                result = fut.result()
                if result:
                    found.append(result)

        found.sort(key=lambda p: ipaddress.ip_address(p[0]))

        matched = 0
        for ctrl_ip, vm_id in found:
            test_ip = self._idx.get(vm_id)
            if test_ip and test_ip in self.vms:
                self.vms[test_ip].control_ip = ctrl_ip
                print(f"  [{vm_id}] test={test_ip}  ctrl={ctrl_ip}  ✓")
                matched += 1
            else:
                print(f"  [?] {ctrl_ip} → ID {vm_id} inconnu (absent du scan test)")

        print(f"{matched}/{len(found)} liaison(s) contrôle établie(s).")

    def cmd_scan(self, args):
        force_remove   = "--force-remove" in args
        force_keep     = "--force-keep"   in args
        test_subnet    = None
        control_subnet = None

        if force_remove and force_keep:
            print("[ERR] --force-remove et --force-keep sont mutuellement exclusifs"); return

        i = 0
        while i < len(args):
            a = args[i]
            if a == "--test" and i + 1 < len(args):
                test_subnet = args[i + 1]; i += 2
            elif a == "--control" and i + 1 < len(args):
                control_subnet = args[i + 1]; i += 2
            elif not a.startswith("--"):
                test_subnet = a; i += 1   # compat positionnelle
            else:
                i += 1

        if not test_subnet:
            test_subnet = self.subnet

        if not test_subnet and not control_subnet:
            print("Usage: scan --test <subnet> [--control <subnet>] [--force-remove|--force-keep]")
            print("       scan <subnet>  (compat — équivalent à --test <subnet>)")
            return

        if test_subnet:
            self.subnet = test_subnet
            self._scan_test(test_subnet, force_remove, force_keep)

        if control_subnet:
            self._scan_control(control_subnet)

    def cmd_list(self, args):
        if not self.vms:
            print("Aucune VM connue. Lancez 'scan --test <subnet>' d'abord."); return

        idx_rev = {v: k for k, v in self._idx.items()}   # test_ip -> id
        print(f"\n{'#':3s}  {'IP TEST':17s}  {'IP CTRL':17s}  {'ETAT':12s}  "
              f"{'PRESET':7s}  {'MODE':16s}  {'WAN':5s}  VU A")
        print("-" * 100)
        for ip, vm in sorted(self.vms.items(),
                              key=lambda kv: ipaddress.ip_address(kv[0])):
            n    = str(idx_rev.get(ip, "-"))
            ctrl = vm.control_ip or "-"
            print(f"{n:3s}  {ip:17s}  {ctrl:17s}  {vm.state:12s}  "
                  f"{str(vm.config.get('preset', '-')):7s}  "
                  f"{vm.config.get('mode', '-'):16s}  "
                  f"{vm.config.get('wan_profile', '-'):5s}  "
                  f"{vm.last_seen or '-'}")
        print()

    def _server_state(self):
        """Lit mode et IP depuis le fichier d'etat ecrit par pqc_bench.sh --server.
        Format: 'mode=classic\\nip=192.168.x.1'
        Retourne un dict ou {} si fichier absent."""
        try:
            state = {}
            for line in SERVER_MODE_FILE.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    state[k.strip()] = v.strip()
            return state
        except OSError:
            return {}

    def cmd_set(self, args):
        """set <ip|all> [--preset N] [--wan-profile WAN] [--duration D]
        Le mode et l'IP cible sont lus automatiquement depuis le serveur."""
        if not args:
            print("Usage: set <ip|all> [--preset N] [--wan-profile eu] [--duration 60]")
            print("       --mode et --target sont auto-detectes depuis le serveur en cours")
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

        srv = self._server_state()

        # Auto-detection du mode
        if "mode" not in cfg:
            if not srv.get("mode"):
                print("ERREUR: serveur non demarre (lancer sudo ./pqc_bench.sh --server --mode MODE)"); return
            cfg["mode"] = srv["mode"]
            print(f"  [mode auto: {srv['mode']}]")
        elif srv.get("mode") and cfg["mode"] != srv["mode"]:
            print(f"ERREUR: mode '{cfg['mode']}' != mode du serveur '{srv['mode']}'")
            print(f"  Relancez le serveur avec --mode {cfg['mode']} ou omettez --mode.")
            return

        # Auto-detection de l'IP cible
        if "target" not in cfg:
            if not srv.get("ip"):
                print("ERREUR: --target requis (IP du serveur WAN introuvable dans .server_mode)"); return
            cfg["target"] = srv["ip"]
            print(f"  [target auto: {srv['ip']}]")


        idx_rev = {v: k for k, v in self._idx.items()}   # ip -> index scan
        for ip in self._resolve(target):
            vm_id = idx_rev.get(ip, 0)
            r = self._send(ip, {"cmd": "CONFIGURE", **cfg, "vm_id": vm_id})
            print(f"  {ip}: {'OK' if r.get('ok') else r.get('error', '?')}"
                  + (f"  [vm_id={vm_id}]" if vm_id else ""))
            if r.get("ok"):
                vm = self.vms.setdefault(ip, VM(ip))
                vm.state  = "configured"
                vm.config = {**cfg, "vm_id": vm_id}

    def cmd_arm(self, args):
        target = args[0] if args else "all"
        for ip in self._resolve(target):
            r = self._send(ip, {"cmd": "ARM"})
            print(f"  {ip}: {'armed' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                self.vms.setdefault(ip, VM(ip)).state = "armed"

    # ------------------------------------------------------------------ #
    # Pre-flight                                                          #
    # ------------------------------------------------------------------ #

    def _run_preflight(self, ips):
        """Envoie PREFLIGHT en parallèle, retourne {ip: response}."""
        results = {}
        lock = threading.Lock()

        def check(ip):
            r = self._send(ip, {"cmd": "PREFLIGHT"}, timeout=20)
            with lock:
                results[ip] = r

        with ThreadPoolExecutor(max_workers=max(len(ips), 1)) as ex:
            list(ex.map(check, ips))
        return results

    def _display_preflight(self, results):
        """Affiche les résultats preflight. Retourne True si au moins un FAIL."""
        has_fail = False
        for ip in sorted(results, key=lambda x: ipaddress.ip_address(x)):
            r = results[ip]
            if not r.get("ok"):
                print(f"  [{ip}] INJOIGNABLE — {r.get('error', '?')}")
                has_fail = True
                continue

            checks = r.get("checks", [])
            n_ok   = sum(1 for c in checks if c["status"] == "ok")
            n_warn = sum(1 for c in checks if c["status"] == "warn")
            n_fail = sum(1 for c in checks if c["status"] == "fail")

            if n_fail:
                has_fail = True

            suffix = ""
            if n_warn:
                suffix += f"  {n_warn} WARN"
            if n_fail:
                suffix += f"  {n_fail} FAIL"
            print(f"  [{ip}] {n_ok}/{len(checks)} ok{suffix}")

            for c in checks:
                if c["status"] in ("warn", "fail"):
                    mark   = "WARN" if c["status"] == "warn" else "FAIL"
                    detail = f" — {c['detail']}" if c.get("detail") else ""
                    print(f"      {mark}: {c['name']}{detail}")

        return has_fail

    def cmd_preflight(self, args):
        """preflight [all|<ip>]  Vérifie l'environnement de chaque VM avant lancement."""
        # Cible : VMs armed ou configured si rien de précisé
        if args and args[0] not in ("all",):
            ips = self._resolve(args[0])
        else:
            ips = [ip for ip, vm in self.vms.items()
                   if vm.state in ("armed", "configured")]

        if not ips:
            print("Aucune VM armed/configured. Lancez 'set' puis 'arm'."); return

        print(f"Pre-flight check ({len(ips)} VM(s))...")
        results  = self._run_preflight(ips)
        has_fail = self._display_preflight(results)

        if has_fail:
            print("\n[FAIL] Des problèmes bloquants ont été détectés.")
            print("       Corrigez-les ou utilisez 'launch --force' pour lancer quand même.")
        else:
            print("\n[OK] Toutes les VMs sont prêtes.")

    def cmd_launch(self, args):
        force = "--force" in args

        armed = [ip for ip, vm in self.vms.items() if vm.state == "armed"]
        if not armed:
            print("Aucune VM armed. Utilisez 'arm [all]' d'abord."); return

        # ---- Pre-flight (par défaut, sauf --force qui avertit seulement) ----
        print(f"Pre-flight check ({len(armed)} VM(s))...")
        pf_results = self._run_preflight(armed)
        has_fail   = self._display_preflight(pf_results)

        if has_fail and not force:
            print("\n[ABORT] Des problèmes bloquants empêchent le lancement.")
            print("        Corrigez-les ou relancez avec 'launch --force' pour ignorer.")
            return

        if has_fail:
            print("\n[WARN] Lancement forcé malgré des erreurs — les résultats peuvent être incomplets.")

        print(f"\nConnexion aux {len(armed)} VM(s) pour lancement synchronise...")
        results   = {}
        ready_n   = [0]
        rlock     = threading.Lock()
        all_ready = threading.Event()
        go        = threading.Event()

        def fire(ip):
            vm   = self.vms.get(ip)
            addr = vm.control_ip if (vm and vm.control_ip) else ip

            def _signal():
                with rlock:
                    ready_n[0] += 1
                    if ready_n[0] == len(armed):
                        all_ready.set()
            try:
                with socket.create_connection((addr, AGENT_PORT), timeout=10) as s:
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
        # Monitoring serveur et watcher de fin de test (en background)
        self._mon_result = {}
        self._mon.start(iface=self._server_state().get("iface", ""))
        threading.Thread(
            target=self._watch_until_done,
            args=(list(armed),),
            daemon=True,
            name="done-watcher",
        ).start()
        for t in threads:
            t.join(timeout=20)
        print(f"Signal envoye en {(time.perf_counter() - t0) * 1000:.0f} ms")

        for ip, r in sorted(results.items()):
            if r.get("ok"):
                self.vms[ip].state = "running"
                print(f"  {ip}: demarre (pid {r.get('pid')})")
            else:
                print(f"  {ip}: ERREUR — {r.get('error')}")

    def _watch_until_done(self, vms: list) -> None:
        """Thread background: poll les VMs toutes les 10s et notifie quand toutes terminent."""
        POLL_INTERVAL = 10      # secondes entre chaque poll
        MAX_WAIT      = 3600    # 1h max (pour les tests très longs ou configurés manuellement)

        deadline = time.time() + MAX_WAIT
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL)

            states = {}
            for ip in vms:
                r = self._send(ip, {"cmd": "STATUS"}, timeout=5)
                if r.get("ok"):
                    s = r.get("state", "unknown")
                    self.vms.setdefault(ip, VM(ip)).state = s
                    states[ip] = s
                else:
                    states[ip] = "?"

            if not any(s == "running" for s in states.values()):
                # Arrêter le monitoring exactement à la fin du test
                self._mon_result = self._mon.stop()

                done_n = sum(1 for s in states.values() if s == "done")
                other  = {ip: s for ip, s in states.items() if s != "done"}
                msg = f"\n[TEST TERMINÉ] {done_n}/{len(vms)} VM(s) done"
                if other:
                    msg += "  |  " + "  ".join(f"{ip}: {s}" for ip, s in other.items())
                msg += "\n>>> Tapez 'results' pour collecter les résultats."
                print(msg, flush=True)
                print("pqc> ", end="", flush=True)
                return

        # Timeout : arrêter quand même le monitoring
        self._mon_result = self._mon.stop()
        print(f"\n[WATCHER] Aucune notification après {MAX_WAIT // 60} min "
              f"— vérifiez l'état des VMs avec 'status'.", flush=True)
        print("pqc> ", end="", flush=True)

    def cmd_status(self, args):
        target = args[0] if args else "all"
        for ip in self._resolve(target):
            r  = self._send(ip, {"cmd": "STATUS"})
            vm = self.vms.setdefault(ip, VM(ip))
            if r.get("ok"):
                prev_state   = vm.state
                vm.state     = r["state"]
                vm.config    = r.get("config", vm.config)
                vm.last_seen = datetime.now().strftime("%H:%M:%S")
                rc           = r.get("returncode")
                rc_str       = f"  rc={rc}" if rc is not None else ""
                recovered    = "  [RECOVERED]" if prev_state == "unreachable" else ""
                print(f"  {ip}: {r['state']}{rc_str}{recovered}  {r.get('config', {})}")
                if r.get("last_log"):
                    for line in r["last_log"]:
                        print(f"    | {line}")
            elif vm.state == "unreachable":
                print(f"  {ip}: toujours injoignable")
            else:
                print(f"  {ip}: injoignable — {r.get('error')}")

    def cmd_logs(self, args):
        """logs [<ip>|all] [--lines N]"""
        n       = 50
        if "--lines" in args:
            idx = args.index("--lines")
            if idx + 1 < len(args):
                try:
                    n = int(args[idx + 1])
                except ValueError:
                    print(f"[WARN] --lines '{args[idx + 1]}' invalide — utilisation de 50")
            args = [a for i, a in enumerate(args) if i not in (idx, idx + 1)]

        target = args[0] if args else "all"
        for ip in self._resolve(target):
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
        target = args[0] if args else "all"
        for ip in self._resolve(target):
            r = self._send(ip, {"cmd": "RESET"})
            print(f"  {ip}: {'idle' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                self.vms.setdefault(ip, VM(ip)).state = "idle"

    # Colonnes numeriques des CSV bruts produits par pqc_bench.sh
    _NUM_COLS = (
        "Handshake_ms", "Debit_Mbps", "CPU_moy_pct",
        "RAM_moy_Mo", "Retransmissions_pct",
        "Duree_reelle_s", "Delai_planifie_s",
        # noms anciens (compat)
        "handshake_event_ms", "throughput_mbps", "cpu_avg_pct",
        "ram_avg_mb", "retransmit_pct",
    )
    _MASTER_FIELDS = [
        "Source", "Mode", "Type_test", "WAN",
        "Handshake_moy_ms", "Handshake_min_ms", "Handshake_max_ms",
        "Debit_moy_Mbps", "Debit_min_Mbps", "Debit_max_Mbps",
        "CPU_moy_pct", "RAM_moy_Mo", "Retransmissions_moy_pct",
        "Ping_moy_ms", "Ping_min_ms", "Ping_max_ms", "Ping_p99_moy_ms",
        "Jitter_moy_ms",
        "Packet_loss_moy_pct", "Packet_loss_UDP_moy_pct",
        "Fragmentation_moy_pct",
        "Handshake_paquets_moy", "Handshake_octets_moy",
        "TCP_connect_moy_ms", "TTFB_moy_ms",
        "Connexions_echec_total",
        "Nb_evenements",
    ]

    def _next_master_index(self, mode):
        """Retourne le prochain indice disponible pour master_<mode>_N.csv."""
        nums = []
        for p in RESULTS_DIR.glob(f"master_{mode}_*.csv"):
            try:
                nums.append(int(p.stem.rsplit("_", 1)[-1]))
            except ValueError:
                pass
        return max(nums, default=0) + 1

    def _summarise_vm_rows(self, rows):
        """Reduit les lignes par evenement d'une VM en stats aggregees."""
        def _col(name, alt=None):
            vals = []
            for r in rows:
                raw = r.get(name) or (r.get(alt) if alt else None)
                try:
                    v = float(raw)
                    if v >= 0:      # exclut -1 (mesure ratee)
                        vals.append(v)
                except (TypeError, ValueError):
                    pass
            return vals

        hs   = _col("Handshake_ms", "handshake_event_ms")
        dbt  = _col("Debit_Mbps",   "throughput_mbps")
        cpu  = _col("CPU_moy_pct",  "cpu_avg_pct")
        ram  = _col("RAM_moy_Mo",   "ram_avg_mb")
        rtr  = _col("Retransmissions_pct", "retransmit_pct")
        ping_moy  = _col("Ping_moy_ms")
        ping_min  = _col("Ping_min_ms")
        ping_max  = _col("Ping_max_ms")
        ping_p99  = _col("Ping_p99_ms")
        jitter    = _col("Jitter_ms")
        loss      = _col("Packet_loss_pct")
        loss_udp  = _col("Packet_loss_UDP_pct")
        frag      = _col("Fragmentation_pct")
        hs_pkts   = _col("Handshake_paquets")
        hs_bytes  = _col("Handshake_octets")
        tcp_conn  = _col("TCP_connect_ms")
        ttfb      = _col("TTFB_ms")
        conn_err  = _col("Connexions_echec")

        def avg(v): return round(statistics.mean(v), 3) if v else ""
        def mn(v):  return round(min(v), 3)             if v else ""
        def mx(v):  return round(max(v), 3)             if v else ""
        def sumv(v): return int(sum(v))                 if v else ""

        first = rows[0] if rows else {}
        mode  = first.get("Mode") or first.get("mode", "?")
        ttype = first.get("Type_test") or first.get("schedule", "?")

        return {
            "Mode": mode, "Type_test": ttype,
            "Handshake_moy_ms": avg(hs), "Handshake_min_ms": mn(hs), "Handshake_max_ms": mx(hs),
            "Debit_moy_Mbps":   avg(dbt), "Debit_min_Mbps": mn(dbt), "Debit_max_Mbps": mx(dbt),
            "CPU_moy_pct":   avg(cpu),
            "RAM_moy_Mo":    avg(ram),
            "Retransmissions_moy_pct": avg(rtr),
            "Ping_moy_ms":             avg(ping_moy),
            "Ping_min_ms":             mn(ping_min),
            "Ping_max_ms":             mx(ping_max),
            "Ping_p99_moy_ms":         avg(ping_p99),
            "Jitter_moy_ms":           avg(jitter),
            "Packet_loss_moy_pct":     avg(loss),
            "Packet_loss_UDP_moy_pct": avg(loss_udp),
            "Fragmentation_moy_pct":   avg(frag),
            "Handshake_paquets_moy":   avg(hs_pkts),
            "Handshake_octets_moy":    avg(hs_bytes),
            "TCP_connect_moy_ms":      avg(tcp_conn),
            "TTFB_moy_ms":             avg(ttfb),
            "Connexions_echec_total":  sumv(conn_err),
            "Nb_evenements": len(rows),
        }

    def _global_rows(self, vm_summaries, mode, wan, n_vms):
        """Produit les lignes GLOBAL_* a partir des resumes par VM."""
        num_keys = [
            "Handshake_moy_ms", "Handshake_min_ms", "Handshake_max_ms",
            "Debit_moy_Mbps", "Debit_min_Mbps", "Debit_max_Mbps",
            "CPU_moy_pct", "RAM_moy_Mo", "Retransmissions_moy_pct",
            "Ping_moy_ms", "Ping_min_ms", "Ping_max_ms", "Ping_p99_moy_ms",
            "Jitter_moy_ms",
            "Packet_loss_moy_pct", "Packet_loss_UDP_moy_pct",
            "Fragmentation_moy_pct",
            "Handshake_paquets_moy", "Handshake_octets_moy",
            "TCP_connect_moy_ms", "TTFB_moy_ms",
        ]
        def _vals(key):
            out = []
            for s in vm_summaries:
                try:
                    out.append(float(s[key]))
                except (TypeError, ValueError, KeyError):
                    pass
            return out

        def _conn_err_total():
            total = 0
            for s in vm_summaries:
                try: total += int(s.get("Connexions_echec_total", 0) or 0)
                except (TypeError, ValueError): pass
            return total

        rows = []
        for label, fn in [
            (f"GLOBAL_MOY (n={n_vms} VMs)", statistics.mean),
            (f"GLOBAL_MIN",                  min),
            (f"GLOBAL_MAX",                  max),
        ]:
            r = {"Source": label, "Mode": mode, "Type_test": "-", "WAN": wan, "Nb_evenements": "-"}
            for k in num_keys:
                v = _vals(k)
                r[k] = round(fn(v), 3) if v else ""
            r["Connexions_echec_total"] = _conn_err_total()
            rows.append(r)

        if n_vms > 1:
            r = {"Source": f"GLOBAL_ECART_TYPE (n={n_vms} VMs)", "Mode": mode, "Type_test": "-", "WAN": wan, "Nb_evenements": "-"}
            for k in num_keys:
                v = _vals(k)
                r[k] = round(statistics.stdev(v), 3) if len(v) > 1 else ""
            r["Connexions_echec_total"] = ""
            rows.append(r)
        return rows

    def _server_metrics_row(self, mode, wan):
        """Arrête le monitoring serveur et retourne une ligne master CSV avec les métriques
        collectées depuis le lancement du test (launch) jusqu'à maintenant (results)."""
        # Cas normal : le watcher a déjà arrêté le monitoring et stocké le résultat.
        # Fallback : results appelé avant la fin détectée → on arrête maintenant.
        metrics = self._mon_result or self._mon.stop()
        if not metrics:
            print("  [INFO] Aucune métrique serveur "
                  "(le monitoring démarre avec 'launch' — relancez un test complet)")
            return None

        srv_state = self._server_state()
        source    = srv_state.get("ip", "server")
        iface     = srv_state.get("iface", "")

        row = {k: "" for k in self._MASTER_FIELDS}
        row["Source"]         = source
        row["Mode"]           = mode
        row["Type_test"]      = "server"
        row["WAN"]            = wan
        row["CPU_moy_pct"]    = metrics["cpu_avg_pct"]
        row["RAM_moy_Mo"]     = metrics["ram_avg_mb"]
        row["Debit_moy_Mbps"] = metrics["rx_mbps"]
        print(f"  serveur ({source}): "
              f"CPU={metrics['cpu_avg_pct']}%  "
              f"RAM={metrics['ram_avg_mb']} Mo  "
              f"RX={metrics['rx_mbps']} Mbps  "
              f"({metrics['n_samples']} échantillons, {metrics['elapsed_s']}s"
              + (f", iface={iface}" if iface else "") + ")")
        return row

    def cmd_results(self, args):
        RESULTS_DIR.mkdir(exist_ok=True)

        vm_data = {}   # ip -> list of row dicts
        errors  = []
        mode    = "unknown"
        wan     = "?"

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

            # Sauvegarde individuelle avec timestamp pour ne pas ecraser
            ts_tag  = datetime.now().strftime("%Y%m%dT%H%M%S")
            indiv   = RESULTS_DIR / f"raw_{ip.replace('.', '_')}_{ts_tag}.csv"
            try:
                indiv.write_text(content)
            except OSError as exc:
                print(f"  {ip}: impossible d'ecrire {indiv} : {exc}")
                errors.append(ip)
                continue

            try:
                rows = list(csv.DictReader(io.StringIO(content)))
            except Exception as exc:
                print(f"  {ip}: CSV malformé ({exc})")
                errors.append(ip)
                continue
            if not rows:
                print(f"  {ip}: aucune donnee"); continue

            vm_data[ip] = rows
            # Recupere mode et wan depuis la config connue
            vm_mode = self.vms[ip].config.get("mode") or rows[0].get("Mode") or rows[0].get("mode", "unknown")
            vm_wan  = self.vms[ip].config.get("wan_profile", "?")
            if vm_mode != "unknown":
                mode = vm_mode
            if vm_wan != "?":
                wan = vm_wan
            print(f"  {ip}: {len(rows)} evenement(s) [{vm_mode}]")

        if not vm_data:
            print("Aucune donnee collectee."); return

        # Ligne resumee par VM
        master_rows = []
        vm_summaries = []
        for ip, rows in sorted(vm_data.items()):
            s = self._summarise_vm_rows(rows)
            s["Source"] = ip
            s["WAN"]    = self.vms[ip].config.get("wan_profile", "?")
            master_rows.append(s)
            vm_summaries.append(s)

        # Ligne serveur (métriques système collectées pendant le test)
        srv_row = self._server_metrics_row(mode, wan)
        if srv_row:
            master_rows.append(srv_row)

        # Lignes globales (VMs uniquement, serveur exclu)
        master_rows += self._global_rows(vm_summaries, mode, wan, len(vm_summaries))

        # Nommage avec auto-increment
        idx     = self._next_master_index(mode)
        outfile = RESULTS_DIR / f"master_{mode}_{idx}.csv"

        try:
            with open(outfile, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=self._MASTER_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(master_rows)
        except OSError as exc:
            print(f"[ERR] Impossible d'ecrire {outfile} : {exc}")
            return

        print(f"\nMaster CSV: {outfile}")
        srv_note = " + 1 ligne serveur" if srv_row else ""
        print(f"  {len(vm_data)} VM(s), {len(vm_summaries)} ligne(s) VM{srv_note} + lignes GLOBAL")
        if errors:
            print(f"  VMs sans resultats: {', '.join(errors)}")

    def cmd_compare(self, args):
        """compare [--output FILE]  Compile tous les master CSV en comparatif inter-modes."""
        RESULTS_DIR.mkdir(exist_ok=True)
        outfile = RESULTS_DIR / f"compare_{datetime.now().strftime('%Y%m%dT%H%M%S')}.csv"
        if "--output" in args:
            idx = args.index("--output")
            if idx + 1 < len(args):
                outfile = Path(args[idx + 1])

        masters = sorted(RESULTS_DIR.glob("master_*.csv"))
        if not masters:
            print("Aucun master CSV trouve dans results/."); return

        # Extrait les lignes GLOBAL_MOY de chaque master
        compare_rows = []
        for mpath in masters:
            try:
                rows = list(csv.DictReader(open(mpath)))
            except (OSError, Exception):
                print(f"[WARN] Lecture ignorée : {mpath.name}")
                continue
            for row in rows:
                src = row.get("Source", "")
                if src.startswith("GLOBAL_MOY"):
                    row["Fichier"] = mpath.name
                    compare_rows.append(row)

        if not compare_rows:
            print("Aucune ligne GLOBAL_MOY trouvee dans les master CSV."); return

        fields = ["Fichier"] + self._MASTER_FIELDS
        try:
            with open(outfile, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(compare_rows)
        except OSError as exc:
            print(f"[ERR] Impossible d'ecrire {outfile} : {exc}")
            return

        print(f"Comparatif: {outfile}  ({len(compare_rows)} ligne(s) sur {len(masters)} master(s))")

    def cmd_help(self, _args):
        print("""
  scan --test <subnet> [--control <subnet>]                  Découverte des agents
       [--force-remove | --force-keep]                         --test   : LAN de test (trafic + mesures)
                                                               --control: LAN de contrôle (orchestration)
                                                               --force-remove : supprime sans prompt les agents disparus
                                                               --force-keep   : conserve sans prompt (unreachable)
  list                                                       Tableau des VMs et leur etat (IP test + ctrl)
  set <ip|all> --mode MODE --target IP [--preset N] [...]   Configure une ou toutes les VMs
  arm [all|<ip>]                                             Met les VMs configurees en standby
  preflight [all|<ip>]                                       Verifie l'environnement de chaque VM
  launch [--force]                                           Lance toutes les VMs (preflight auto, --force ignore les FAIL)
  status [all|<ip>]                                          Poll l'etat + derniers logs
  logs [all|<ip>] [--lines N]                                Affiche les logs de pqc_bench.sh (defaut 50 lignes)
  reset [all|<ip>]                                           Remet en idle (kill si en cours)
  results                                                    Collecte les CSV, genere master_[mode]_N.csv
  compare [--output FILE]                                    Comparatif inter-modes depuis tous les master CSV
  help                                                       Cette aide
  exit / quit                                                Quitte le CLI
""")

    _CMDS = {
        "scan":      cmd_scan,
        "list":      cmd_list,
        "set":       cmd_set,
        "arm":       cmd_arm,
        "preflight": cmd_preflight,
        "launch":    cmd_launch,
        "status":    cmd_status,
        "logs":      cmd_logs,
        "reset":     cmd_reset,
        "results":   cmd_results,
        "compare":   cmd_compare,
        "help":      cmd_help,
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
