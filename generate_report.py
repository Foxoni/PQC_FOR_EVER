#!/usr/bin/env python3
"""
generate_report.py — Rapport HTML standalone depuis les CSV PQC Bench.

Usage:
    python3 generate_report.py results/master_hybrid-full_14.csv
    python3 generate_report.py results/master_*.csv        # comparaison multi-run
    python3 generate_report.py results/master_*.csv --output mon_rapport.html
"""

import csv, glob, json, sys
from datetime import datetime
from pathlib import Path

# Palette catégorielle (fixe, ordre stable entre charts)
_COLORS = [
    "#3B82F6", "#14B8A6", "#F97316",
    "#8B5CF6", "#EC4899", "#F59E0B",
    "#10B981", "#EF4444",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _f(v, fallback=None):
    """Convertit en float; retourne fallback si invalide ou négatif."""
    try:
        x = float(v)
        return x if x >= 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _fmt(v):
    """Formate un float : 1 décimale sauf si entier."""
    try:
        f = float(v)
        return f"{f:.1f}" if f != int(f) else str(int(f))
    except (TypeError, ValueError):
        return str(v) if v else "—"


# ── Chargement CSV ───────────────────────────────────────────────────────────

def load_master(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    if not rows:
        return {}, []
    return {
        "mode": rows[0].get("Mode", "?"),
        "wan":  rows[0].get("WAN", "?"),
        "name": Path(path).stem,
    }, rows


def find_raw_csvs(master_path):
    # master_hybrid-full_20.csv → run_id "hybrid-full_20"
    stem   = Path(master_path).stem          # "master_hybrid-full_20"
    run_id = stem[len("master_"):]           # "hybrid-full_20"
    matches = sorted(Path(master_path).parent.glob(f"raw_*_{run_id}_*.csv"))
    if not matches:
        # fallback pour anciens raw sans run_id dans le nom
        matches = sorted(Path(master_path).parent.glob("raw_*.csv"))
    return matches


def load_raw_rows(raw_paths):
    rows = []
    for p in raw_paths:
        try:
            with open(p, newline="", encoding="utf-8") as f:
                rows.extend(csv.DictReader(f))
        except Exception:
            pass
    return rows


# ── Données Chart.js ─────────────────────────────────────────────────────────

def _row_val(row, *fields):
    """Première valeur numérique valide parmi les colonnes données."""
    for f in fields:
        v = _f(row.get(f))
        if v is not None:
            return v
    return None


def event_chart(raw_rows, *fields, mode_filter=None):
    """
    Grouped bar chart : x = profil, séries = VMs.
    `fields` : noms de colonnes à tester dans l'ordre
    (ex: "Handshake_ms", "Handshake_moy_ms" pour couvrir preset + random).
    """
    if mode_filter:
        raw_rows = [r for r in raw_rows
                    if r.get("Mode", "").lower() == mode_filter.lower()]

    vms, event_order = {}, []
    for row in raw_rows:
        val = _row_val(row, *fields)
        if val is None:
            continue
        vm  = row.get("VM_IP", row.get("Source", "?"))
        lbl = row.get("Profil", "?")
        if lbl not in event_order:
            event_order.append(lbl)
        vms.setdefault(vm, {}).setdefault(lbl, []).append(val)

    if not vms:
        return None

    datasets = []
    for i, (vm, events) in enumerate(sorted(vms.items())):
        c = _COLORS[i % len(_COLORS)]
        datasets.append({
            "label": vm,
            "data": [
                round(sum(events[l]) / len(events[l]), 2) if l in events else None
                for l in event_order
            ],
            "backgroundColor": c + "BB",
            "borderColor":     c,
            "borderWidth": 1,
            "borderRadius": 4,
            "borderSkipped": False,
        })
    return {"labels": event_order, "datasets": datasets}


def timeseries_chart(raw_rows, *fields, mode_filter=None):
    """
    Line chart : x = Delai_planifie_s (preset uniquement), séries = VMs.
    `fields` : noms de colonnes à tester dans l'ordre.
    """
    if mode_filter:
        raw_rows = [r for r in raw_rows
                    if r.get("Mode", "").lower() == mode_filter.lower()]

    vms = {}
    for row in raw_rows:
        val = _row_val(row, *fields)
        t   = _f(row.get("Delai_planifie_s"))
        if val is None or t is None:
            continue
        vm = row.get("VM_IP", row.get("Source", "?"))
        vms.setdefault(vm, []).append({"x": t, "y": val})

    if not vms:
        return None

    datasets = []
    for i, (vm, pts) in enumerate(sorted(vms.items())):
        c = _COLORS[i % len(_COLORS)]
        datasets.append({
            "label": vm,
            "data":  sorted(pts, key=lambda p: p["x"]),
            "borderColor": c,
            "backgroundColor": c + "33",
            "borderWidth": 2,
            "pointRadius": 5,
            "pointHoverRadius": 7,
            "fill": False,
            "tension": 0.2,
        })
    return {"datasets": datasets}


# ── HTML ─────────────────────────────────────────────────────────────────────

_CSS = """
:root{--bg:#f8fafc;--sur:#fff;--bdr:#e2e8f0;--tx:#0f172a;--mu:#64748b;--ac:#3B82F6}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--sur:#1e293b;--bdr:#334155;--tx:#f1f5f9;--mu:#94a3b8;--ac:#60a5fa}}
[data-theme=dark]{--bg:#0f172a;--sur:#1e293b;--bdr:#334155;--tx:#f1f5f9;--mu:#94a3b8;--ac:#60a5fa}
[data-theme=light]{--bg:#f8fafc;--sur:#fff;--bdr:#e2e8f0;--tx:#0f172a;--mu:#64748b;--ac:#3B82F6}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:system-ui,sans-serif;font-size:14px;
     line-height:1.5;padding:24px 28px}
h1{font-size:1.4rem;font-weight:700;margin-bottom:4px}
h2{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
   color:var(--mu);margin:28px 0 10px}
.meta{color:var(--mu);font-size:.82rem;margin-bottom:24px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.tile{background:var(--sur);border:1px solid var(--bdr);border-radius:8px;padding:14px 18px;min-width:130px}
.tile-v{font-size:1.5rem;font-weight:700;color:var(--ac)}
.tile-l{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mu);margin-top:2px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(440px,1fr));gap:14px;margin-bottom:8px}
.box{background:var(--sur);border:1px solid var(--bdr);border-radius:8px;padding:16px}
.box-t{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;
       color:var(--mu);margin-bottom:12px}
.tbl-wrap{overflow-x:auto;border:1px solid var(--bdr);border-radius:8px}
table{width:max-content;min-width:100%;border-collapse:collapse;background:var(--sur);font-size:.8rem}
th{background:var(--bdr);padding:6px 8px;text-align:left;font-size:.68rem;
   text-transform:uppercase;letter-spacing:.04em;color:var(--mu);white-space:nowrap;
   position:sticky;top:0}
th.grp{border-left:2px solid var(--bg)}
td{padding:5px 8px;border-top:1px solid var(--bdr);font-variant-numeric:tabular-nums;white-space:nowrap}
td.grp{border-left:2px solid var(--bdr)}
tr.gl{color:var(--mu);font-style:italic}
tr.sv td:first-child{color:var(--ac);font-weight:600}
.btn{position:fixed;top:14px;right:14px;background:var(--sur);border:1px solid var(--bdr);
     border-radius:6px;padding:5px 10px;cursor:pointer;color:var(--tx);font-size:.78rem}
.note{color:var(--mu);font-size:.8rem;font-style:italic;padding:8px 0}
"""

_CHART_OPT = {
    "responsive": True,
    "plugins": {"legend": {"position": "bottom", "labels": {"boxWidth": 12, "padding": 14}}},
    "scales": {
        "x": {"ticks": {"maxRotation": 35}},
        "y": {"beginAtZero": True,
              "grid": {"color": "rgba(128,128,128,0.12)"},
              "title": {"display": True, "text": ""}},
    },
}


def _chart_block(cid, title, data, y_label, chart_type="bar"):
    if data is None:
        return ""
    opt = json.loads(json.dumps(_CHART_OPT))
    opt["scales"]["y"]["title"]["text"] = y_label
    if chart_type == "line":
        opt["scales"]["x"] = {
            "type": "linear",
            "title": {"display": True, "text": "Délai planifié (s)"},
            "grid": {"color": "rgba(128,128,128,0.12)"},
        }
    cfg = {"type": chart_type, "data": data, "options": opt}
    return (
        f'<div class="box">'
        f'<p class="box-t">{title}</p>'
        f'<canvas id="{cid}"></canvas>'
        f'</div>\n'
        f'<script>new Chart(document.getElementById("{cid}"),'
        f'{json.dumps(cfg, ensure_ascii=False)});</script>\n'
    )


def _tile(val, label):
    return f'<div class="tile"><div class="tile-v">{val}</div><div class="tile-l">{label}</div></div>'


# (key, label, group_start)  — group_start=True ajoute un séparateur visuel
_TABLE_COLS = [
    ("Source",                   "VM / Source",       False),
    ("Mode",                     "Mode",              False),
    ("Type_test",                "Test",              False),
    ("WAN",                      "WAN",               False),
    ("Nb_evenements",            "Évt",               False),
    # ── Handshake ──
    ("Handshake_moy_ms",         "HS moy ms",         True),
    ("Handshake_min_ms",         "min",               False),
    ("Handshake_max_ms",         "max",               False),
    ("TCP_connect_moy_ms",       "TCP ms",            False),
    ("TTFB_moy_ms",              "TTFB ms",           False),
    ("Connexions_echec_total",   "Erreurs",           False),
    # ── Débit ──
    ("Debit_moy_Mbps",           "Débit moy",         True),
    ("Debit_min_Mbps",           "min",               False),
    ("Debit_max_Mbps",           "max",               False),
    ("Retransmissions_moy_pct",  "Retrans %",         False),
    # ── RTT TCP ──
    ("RTT_moy_ms",               "RTT moy ms",        True),
    ("RTT_min_ms",               "min",               False),
    ("RTT_max_ms",               "max",               False),
    ("RTT_p99_moy_ms",           "P99",               False),
    # ── Qualité réseau ──
    ("Jitter_moy_ms",            "Jitter ms",         True),
    ("Packet_loss_UDP_moy_pct",  "Loss UDP %",        False),
    # ── Ressources ──
    ("CPU_moy_pct",              "CPU %",             True),
    ("RAM_moy_Mo",               "RAM Mo",            False),
    # ── Tshark ──
    ("Fragmentation_moy_pct",    "Frag %",            True),
    ("Handshake_paquets_moy",    "HS pkts",           False),
    ("Handshake_octets_moy",     "HS octets",         False),
]


def _table(rows):
    ths = "".join(
        f'<th{"  class=\"grp\"" if grp else ""}>{lbl}</th>'
        for _, lbl, grp in _TABLE_COLS
    )
    body = ""
    for row in rows:
        src = row.get("Source", "")
        cls = ""
        if "GLOBAL" in src:
            cls = ' class="gl"'
        elif row.get("Type_test", "") == "server":
            cls = ' class="sv"'
        tds = "".join(
            f'<td{"  class=\"grp\"" if grp else ""}>{_fmt(row.get(k, ""))}</td>'
            for k, _, grp in _TABLE_COLS
        )
        body += f"<tr{cls}>{tds}</tr>"
    return (
        f'<div class="tbl-wrap">'
        f"<table><thead><tr>{ths}</tr></thead><tbody>{body}</tbody></table>"
        f"</div>"
    )


# ── Génération principale ─────────────────────────────────────────────────────

def generate(master_paths, output=None):
    all_meta, all_master, all_raw = [], [], []

    for mp in master_paths:
        meta, rows = load_master(mp)
        if not rows:
            print(f"  SKIP {mp} (vide)")
            continue
        all_meta.append(meta)
        all_master.extend(rows)
        raws = find_raw_csvs(mp)
        raw_rows = load_raw_rows(raws)
        all_raw.extend(raw_rows)
        print(f"  {meta['name']} — {len(rows)} lignes master, {len(raw_rows)} lignes raw")

    if not all_meta:
        print("Aucune donnée."); sys.exit(1)

    mode  = all_meta[0]["mode"]
    wan   = all_meta[0]["wan"]
    title = " + ".join(m["name"] for m in all_meta)
    date  = datetime.now().strftime("%Y-%m-%d %H:%M")

    vm_rows = [r for r in all_master
               if r.get("Source","") and "GLOBAL" not in r["Source"]
               and r.get("Type_test","") != "server"]
    nb_vms  = len(vm_rows)

    hs_vals = [float(r["Handshake_moy_ms"]) for r in vm_rows
               if _f(r.get("Handshake_moy_ms")) is not None]
    db_vals = [float(r["Debit_moy_Mbps"]) for r in vm_rows
               if _f(r.get("Debit_moy_Mbps")) is not None]

    hs_avg = f"{sum(hs_vals)/len(hs_vals):.0f} ms" if hs_vals else "—"
    db_avg = f"{sum(db_vals)/len(db_vals):.1f} Mbps" if db_vals else "—"

    tiles_html = "\n".join([
        _tile(mode,    "Mode"),
        _tile(wan,     "Profil WAN"),
        _tile(nb_vms,  "VMs"),
        _tile(hs_avg,  "Handshake moyen"),
        _tile(db_avg,  "Débit moyen"),
    ])

    # Graphes handshake (preset → "Handshake_ms", random → "Handshake_moy_ms")
    hs_bar  = _chart_block("c_hs_bar",  "Latence handshake TLS par profil",
                            event_chart(all_raw, "Handshake_ms", "Handshake_moy_ms",
                                        mode_filter=mode), "ms")
    hs_line = _chart_block("c_hs_line", "Latence handshake TLS dans le temps",
                            timeseries_chart(all_raw, "Handshake_ms", "Handshake_moy_ms",
                                             mode_filter=mode), "ms", "line")

    # Graphes débit
    db_bar  = _chart_block("c_db_bar",  "Débit par profil",
                            event_chart(all_raw, "Debit_Mbps",
                                        mode_filter=mode), "Mbps")
    db_line = _chart_block("c_db_line", "Débit dans le temps",
                            timeseries_chart(all_raw, "Debit_Mbps",
                                             mode_filter=mode), "Mbps", "line")

    # Graphe jitter (voip/stream seulement)
    jitter_rows = [r for r in all_raw if r.get("Profil","") in ("voip","stream")]
    jt_bar = _chart_block("c_jt", "Jitter UDP (voip/stream)",
                           event_chart(jitter_rows, "Jitter_ms",
                                       mode_filter=mode), "ms")

    no_raw = '<p class="note">Aucun raw CSV trouvé — relancer <code>results</code> depuis server_cli.py pour collecter les données brutes.</p>'

    hs_block = (hs_bar + hs_line) or no_raw
    db_block = (db_bar + db_line) or no_raw
    jt_block = jt_bar or '<p class="note">Pas de données voip/stream dans ce run.</p>'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQC Bench — {title}</title>
<style>{_CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<button class="btn" onclick="var r=document.documentElement,t=r.getAttribute('data-theme')||'auto';r.setAttribute('data-theme',t==='dark'?'light':'dark')">☀ / 🌙</button>
<h1>PQC Bench — {title}</h1>
<p class="meta">Généré le {date} &nbsp;·&nbsp; Mode : {mode} &nbsp;·&nbsp; WAN : {wan} &nbsp;·&nbsp; {nb_vms} VM(s)</p>

<div class="tiles">
{tiles_html}
</div>

<h2>Handshake TLS</h2>
<div class="grid">
{hs_block}
</div>

<h2>Débit applicatif</h2>
<div class="grid">
{db_block}
</div>

<h2>Jitter UDP</h2>
<div class="grid">
{jt_block}
</div>

<h2>Résumé par VM</h2>
{_table(all_master)}

</body>
</html>"""

    if output is None:
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        output = Path("results") / f"report_{ts}.html"

    Path(output).write_text(html, encoding="utf-8")
    print(f"Rapport : {output}")


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0)

    output = None
    if "--output" in args:
        i = args.index("--output")
        output, args = args[i + 1], args[:i] + args[i + 2:]

    paths = []
    for a in args:
        expanded = glob.glob(a)
        paths.extend(expanded or [a])
    paths = [p for p in paths if Path(p).exists()]

    if not paths:
        print("Aucun fichier trouvé."); sys.exit(1)

    generate(paths, output)


if __name__ == "__main__":
    main()
