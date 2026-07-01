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
        self._idx   = {}   # {1: "192.168.x.y", ...} — assigne par cmd_scan

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

    def _send(self, ip, req, timeout=5.0):
        """Envoie req JSON a l'agent ip:AGENT_PORT, renvoie la reponse JSON."""
        try:
            with socket.create_connection((ip, AGENT_PORT), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall((json.dumps(req) + "\n").encode())
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 10 * 1024 * 1024:   # 10 Mo max
                        return {"ok": False, "error": "reponse trop grande (>10 Mo)"}
                return json.loads(buf.split(b"\n")[0])
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"JSON invalide dans la reponse : {e}"}
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
        found_pairs = []

        def probe(ip):
            r = self._send(str(ip), {"cmd": "STATUS"}, timeout=SCAN_TIMEOUT)
            return (str(ip), r) if r.get("ok") else None

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            futures = {ex.submit(probe, h): h for h in hosts}
            for future in as_completed(futures):
                pair = future.result()
                if pair:
                    found_pairs.append(pair)

        # Tri par IP pour des indices stables entre deux scans
        found_pairs.sort(key=lambda p: ipaddress.ip_address(p[0]))
        self._idx = {}
        for n, (ip, status) in enumerate(found_pairs, 1):
            vm = self.vms.setdefault(ip, VM(ip))
            vm.state     = status.get("state", "unknown")
            vm.config    = status.get("config", {})
            vm.last_seen = datetime.now().strftime("%H:%M:%S")
            self._idx[n] = ip
            print(f"  [{n}] {ip:17s}  [{vm.state}]")

        print(f"{len(found_pairs)} agent(s) detecte(s).")

    def cmd_list(self, args):
        if not self.vms:
            print("Aucune VM connue. Lancez 'scan <subnet>' d'abord."); return

        idx_rev = {v: k for k, v in self._idx.items()}   # ip -> n
        print(f"\n{'#':3s}  {'IP':17s}  {'ETAT':12s}  {'PRESET':7s}  {'MODE':16s}  {'WAN':5s}  VU A")
        print("-" * 76)
        for ip, vm in sorted(self.vms.items(),
                              key=lambda kv: ipaddress.ip_address(kv[0])):
            n = str(idx_rev.get(ip, "-"))
            print(f"{n:3s}  {ip:17s}  {vm.state:12s}  {str(vm.config.get('preset', '-')):7s}"
                  f"  {vm.config.get('mode', '-'):16s}  {vm.config.get('wan_profile', '-'):5s}"
                  f"  {vm.last_seen or '-'}")
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


        for ip in self._resolve(target):
            r = self._send(ip, {"cmd": "CONFIGURE", **cfg})
            print(f"  {ip}: {'OK' if r.get('ok') else r.get('error', '?')}")
            if r.get("ok"):
                vm = self.vms.setdefault(ip, VM(ip))
                vm.state  = "configured"
                vm.config = cfg

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
        target = args[0] if args else "all"
        for ip in self._resolve(target):
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

        # Lignes globales
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
        print(f"  {len(vm_data)} VM(s), {len(vm_summaries)} ligne(s) VM + lignes GLOBAL")
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
  scan [subnet]                                              Decouverte des agents (ex: 192.168.1.0/24)
  list                                                       Tableau des VMs et leur etat
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
