# PQC Benchmark - Cryptographie Post-Quantique sur reseau PME

Projet de recherche - Guardia Cybersecurity School  
Mesure de l'impact des algorithmes **post-quantiques standardises par le NIST** (ML-KEM / ML-DSA)
compares a la cryptographie classique (TLS 1.3 + ECDHE), sur un reseau de type PME simule.

---

## Contexte

Les algorithmes post-quantiques (PQC) standardises en 2024 par le NIST :

- **ML-KEM** (FIPS 203) - echange de cle, remplace ECDHE/X25519
- **ML-DSA** (FIPS 204) - signature numerique, remplace ECDSA/RSA
- **SLH-DSA** (FIPS 205) - signature hash-based (optionnel)

Ces algorithmes resistent aux attaques d'un ordinateur quantique (algorithme de Shor),
mais leur impact sur les performances reseau reelles est mal documente en contexte PME.
Ce projet le mesure.

---

## Architecture

### Topologie reseau

Le banc de test utilise **trois interfaces reseau** par machine pour isoler les flux :

```text
                    ┌─────────────────────────────────────┐
                    │         SERVEUR WAN (Linux)          │
                    │                                      │
                    │  pqc_bench.sh --server               │
                    │  traffic_server.py  (TCP:5300/UDP:5301)│
                    │  server_cli.py (CLI orchestration)   │
                    │  InfluxDB + Grafana (Docker)         │
                    └──────┬───────────────────┬───────────┘
                           │                   │
              LAN TEST      │   LAN CONTROLE    │
           192.168.141.x   │   192.168.142.x   │
         (trafic benchmark) │ (ordres CLI, 9998)│
                           │                   │
          ┌────────────────┴───┐  ┌────────────┴────────────┐
          │   VM 1 (cliente)   │  │   VM 2 (cliente)        │
          │ eth1: 141.10       │  │ eth1: 141.11            │
          │ eth2: 142.10       │  │ eth2: 142.11            │
          │ vm_agent.py :9998  │  │ vm_agent.py :9998       │
          │ telegraf            │  │ telegraf                │
          └────────────────────┘  └─────────────────────────┘

  NAT (internet uniquement - mises a jour, Docker pull, etc.)
```

**Principe de separation :**

| Interface | Reseau | Usage |
| --- | --- | --- |
| NAT | internet | Acces internet uniquement (apt, Docker pull, git) |
| Host-Only 192.168.141.x | LAN TEST | Trafic benchmark TLS + simulation WAN (tc-netem) |
| Host-Only 192.168.142.x | LAN CONTROLE | Ordres CLI server_cli.py → vm_agent.py (port 9998) |

Le trafic de controle (commandes, recup CSV) ne transite **jamais** par l'interface de test,
ce qui garantit que la simulation WAN (tc-netem) n'impacte pas les temps de reponse du CLI.

### Identification des VMs (double IP)

Chaque VM ayant deux IP, le serveur les associe via un mecanisme d'identifiant :

1. `scan --test 192.168.141.0/24` : decouvre les agents sur le LAN test, assigne un `ID` unique a chacun via `ASSIGN_ID`
2. `scan --control 192.168.142.0/24` : interroge les agents via `GET_ID`, fait correspondre l'IP controle a l'ID deja connu
3. Toutes les commandes suivantes passent par `control_ip` ; seul le trafic benchmark utilise `test_ip`

Les IDs persistent tant que le daemon `vm_agent.py` tourne. Un re-scan ne reaffecte pas un ID
deja attribue — il le recupere via `GET_ID` et verifie la coherence.

### Fichiers

```text
pqc_bench/
├── pqc_bench.sh          # Moteur de test - generation certificats, handshake, trafic, push InfluxDB
├── traffic_server.py     # Serveur de trafic (TCP :5300, UDP :5301) - lance par --server
├── traffic_gen.py        # Module utilitaire (stats, monitoring CPU/RAM, clients trafic, CSV)
├── traffic_presets.py    # Generateur de trafic - presets + mode continu aleatoire
├── vm_agent.py           # Daemon de controle sur chaque VM cliente (port 9998)
├── server_cli.py         # CLI central sur le serveur - orchestre toutes les VMs
├── docker-compose.yml    # InfluxDB v2 + Grafana pour la supervision
├── telegraf.conf         # Template Telegraf pour les VMs (CPU/RAM/reseau → InfluxDB)
├── grafana/
│   └── provisioning/
│       ├── datasources/influxdb.yml    # Datasource InfluxDB auto-configuree
│       └── dashboards/
│           ├── provider.yml            # Chargeur de dashboards
│           ├── pqc_live.json           # Dashboard temps reel (par run)
│           └── pqc_compare.json        # Comparaison multi-run
└── results/              # Fichiers CSV produits (cree automatiquement)
```

| Fichier | Role |
| --- | --- |
| `pqc_bench.sh` | Moteur d'execution : certificats, handshake TLS, orchestration trafic, ecriture CSV, push InfluxDB |
| `traffic_server.py` | Serveur de trafic multi-client (TCP :5300 + UDP :5301) — remplace le pool iperf3 |
| `traffic_gen.py` | Stats (min/avg/max/p99), monitoring CPU/RAM, clients trafic individuels, parsing JSON |
| `traffic_presets.py` | 5 presets PME predefinis + mode aleatoire continu, handshake TLS par connexion |
| `vm_agent.py` | Daemon TCP sur chaque VM cliente : recoit les ordres du serveur, lance pqc_bench.sh |
| `server_cli.py` | CLI interactif sur le serveur WAN : scan dual-interface, lancement synchronise, collecte |
| `docker-compose.yml` | Stack de supervision : InfluxDB 2.7 + Grafana 10.4, volumes persistants |
| `telegraf.conf` | Template de collecte systeme (CPU, RAM, reseau) pour les VMs |

---

## Prerequis

### Systeme (Debian / Ubuntu) — toutes les machines

Paquets obligatoires :

```bash
sudo apt install -y \
    nmap tcpdump \
    openssl python3 python3-pip curl \
    cmake gcc g++ libtool libssl-dev pkg-config \
    iproute2 net-tools bc netcat-openbsd git
```

Paquets optionnels (metriques reseau avancees) :

```bash
sudo apt install -y hping3 tshark fping
```

| Outil | Metriques activees | Droits requis |
| --- | --- | --- |
| `hping3` | `TCP_connect_ms` | aucun |
| `tshark` | `Fragmentation_pct`, `Handshake_paquets`, `Handshake_octets` | **root** (CAP_NET_RAW) |
| `fping` | fallback si hping3 absent | aucun |
| `curl` | `TTFB_ms`, push InfluxDB | aucun |

### OpenSSL 3.x + oqs-provider (support PQC)

Le script installe tout automatiquement :

```bash
sudo ./pqc_bench.sh --install
```

Ce que fait `--install` :

1. Installation des paquets systeme
2. Compilation de **liboqs** (bibliotheque Open Quantum Safe)
3. Compilation du **oqs-provider** pour OpenSSL 3
4. Enregistrement du provider dans `/etc/ssl/openssl.cnf`

Verification :

```bash
openssl list -providers | grep oqs
# oqsprovider doit apparaitre
```

### Docker (serveur uniquement — pour la supervision)

```bash
# Installation Docker Engine
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# Se reconnecter pour que le groupe soit pris en compte
```

---

## Deploiement

### 1. Sur toutes les machines (serveur et VMs clientes)

```bash
git clone https://github.com/Foxoni/PQC_FOR_EVER.git
cd PQC_FOR_EVER
sudo ./pqc_bench.sh --install
```

### 2. Sur le serveur WAN

#### Lancer la stack de supervision (optionnel mais recommande)

```bash
# 1. Creer le fichier de secrets a partir du template (jamais commite)
cp .env.example .env
nano .env   # definir les mots de passe et le token

# 2. Demarrer les conteneurs
docker compose up -d

# Grafana  : http://<IP_serveur>:3000  (identifiants definis dans .env)
# InfluxDB : http://<IP_serveur>:8086  (identifiants definis dans .env)
```

Exporter les variables pour activer la collecte automatique depuis le serveur et les VMs :

```bash
export INFLUX_URL=http://localhost:8086
export INFLUX_TOKEN=<valeur INFLUX_TOKEN du .env>
export INFLUX_ORG=pqc
export INFLUX_BUCKET=pqc_bench
```

> Ajouter ces exports dans `~/.bashrc` ou `/etc/environment` pour qu'ils persistent.
> Ne jamais mettre le token directement dans un script commite.

#### Lancer le serveur de benchmark

```bash
# Terminal 1 : serveur de trafic + TLS + simulation WAN
# --server-ip specifie l'IP du LAN TEST (obligatoire si plusieurs interfaces)
sudo ./pqc_bench.sh --server --mode hybrid-full --wan-profile eu --server-ip 192.168.141.1

# Terminal 2 : CLI de controle
python3 server_cli.py
```

### 3. Sur chaque VM cliente

#### Installer Telegraf (supervision systeme)

Telegraf n'est pas dans les depots Ubuntu — ajouter le depot InfluxData :

```bash
# 1. Importer la cle GPG InfluxData depuis le keyserver Ubuntu
sudo gpg --keyserver keyserver.ubuntu.com --recv-keys DA61C26A0585BD3B
sudo gpg --export DA61C26A0585BD3B | sudo tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null

# 2. Ajouter le depot
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | \
  sudo tee /etc/apt/sources.list.d/influxdata.list

# 3. Installer
sudo apt update && sudo apt install -y telegraf
```

Configurer et demarrer :

```bash
# Editer le template : remplacer INFLUX_URL et INFLUX_TOKEN
sudo cp telegraf.conf /etc/telegraf/telegraf.conf
sudo nano /etc/telegraf/telegraf.conf
# Modifier : urls = ["http://<IP_SERVEUR>:8086"]
#            token = "<valeur INFLUX_TOKEN du .env du serveur>"

sudo systemctl enable --now telegraf
```

#### Exporter les variables de supervision

Pour que `vm_agent.py` envoie les heartbeats a InfluxDB, exporter les variables suivantes
(**INFLUX_URL pointe vers le serveur**, pas localhost) :

```bash
export INFLUX_URL=http://192.168.142.1:8086   # IP controle du serveur (LAN 192.168.142.x)
export INFLUX_TOKEN=<valeur INFLUX_TOKEN du .env du serveur>
export INFLUX_ORG=pqc
export INFLUX_BUCKET=pqc_bench
```

Ajouter ces exports dans `~/.bashrc` pour qu'ils persistent apres reconnexion :

```bash
nano ~/.bashrc   # coller les 4 lignes export a la fin
source ~/.bashrc
```

> Sans ces variables, `vm_agent.py` demarre normalement mais n'envoie pas de heartbeat —
> les voyants restent rouges dans Grafana.

#### Lancer le daemon de controle

```bash
# Reste en arriere-plan (supervisor, tmux ou screen recommande)
python3 vm_agent.py
```

---

## Controle centralise depuis le serveur

`server_cli.py` est un CLI interactif qui orchestre toutes les VMs depuis le serveur.

```text
PQC Bench -- Controleur central  (tapez 'help' pour l'aide)

pqc>
```

### Commandes disponibles

| Commande | Description |
| --- | --- |
| `scan --test <subnet> [--control <subnet>]` | Scan du LAN test (assigne les IDs), puis du LAN controle (appaire les IPs) |
| `scan --test <subnet> --force-remove` | Supprime automatiquement les VMs disparues sans prompt |
| `scan --test <subnet> --force-keep` | Conserve les VMs disparues en etat `unreachable` sans prompt |
| `list` | Tableau : numero, IP TEST, IP CTRL, etat, preset, mode, WAN, derniere vue |
| `set <N\|ip\|all> [--preset N] [--wan-profile WAN] [--duration D]` | Configure une ou toutes les VMs — mode et cible auto-detectes depuis le serveur |
| `arm [N\|ip\|all]` | Met les VMs configurees en standby (pretes a demarrer) |
| `preflight [N\|ip\|all]` | Verifie l'environnement de chaque VM (outils, OQS provider, droits, connectivite) |
| `launch [--force]` | Envoie START a toutes les VMs armed **simultanement**, genere le `run_id`, demarre le monitoring |
| `status [N\|ip\|all]` | Poll l'etat + 5 dernieres lignes de log + code de retour |
| `logs [N\|ip\|all] [--lines N]` | Affiche le log complet de pqc_bench.sh sur la VM |
| `reset [N\|ip\|all]` | Remet en idle, kill le test si en cours |
| `results` | Collecte les CSV, inclut la ligne serveur, produit `master_[mode]_N.csv` |
| `compare [--output FILE]` | Lit tous les master CSV et produit un comparatif inter-modes |
| `help` | Liste des commandes |
| `exit` / `quit` | Quitte le CLI |

> **Mode et IP automatiques :** `pqc_bench.sh --server` ecrit `.server_mode` avec le mode et l'IP.
> `set` les detecte automatiquement. Specifier `--server-ip` au demarrage pour choisir l'interface test.

### Etats d'une VM

```text
idle --> configured --> armed --> running --> done
  ^                                            |
  |______________ reset ______________________|
```

En cas d'agent injoignable lors d'un re-scan : `unreachable` (conserve en memoire, ID intact).

### Workflow complet avec supervision

```bash
# === PREPARATION ===

# 1. Scanner le LAN test (detecte les agents, assigne les IDs)
pqc> scan --test 192.168.141.0/24
  [1] 192.168.141.10   [idle]
  [2] 192.168.141.11   [idle]
  [3] 192.168.141.12   [idle]
  3 agent(s) detecte(s).

# 2. Scanner le LAN controle (appaire les IPs controle aux IDs)
pqc> scan --control 192.168.142.0/24
  [1] 192.168.141.10  <->  ctrl: 192.168.142.10
  [2] 192.168.141.11  <->  ctrl: 192.168.142.11
  [3] 192.168.141.12  <->  ctrl: 192.168.142.12
  3 VM(s) appairees.

# (Variante : les deux en une commande)
pqc> scan --test 192.168.141.0/24 --control 192.168.142.0/24

# 3. Verifier le tableau (colonne IP CTRL renseignee)
pqc> list
  [1] 192.168.141.10  ctrl:192.168.142.10  idle   preset=1  hybrid-full
  [2] 192.168.141.11  ctrl:192.168.142.11  idle   preset=2  hybrid-full
  [3] 192.168.141.12  ctrl:192.168.142.12  idle   preset=3  hybrid-full

# === CONFIGURATION ===

# 4. Configurer toutes les VMs (mode et IP auto-detectes depuis .server_mode)
pqc> set all --preset 2
  [mode auto: hybrid-full]  [target auto: 192.168.141.1]
  192.168.141.10: OK  [vm_id=1]
  192.168.141.11: OK  [vm_id=2]
  192.168.141.12: OK  [vm_id=3]

# Ou configurer les VMs par preset different
pqc> set 1 --preset 1
pqc> set 2 --preset 3
pqc> set 3 --preset 5

# 5. Mettre en standby
pqc> arm all

# 6. (optionnel) Verifier l'environnement
pqc> preflight
  [192.168.141.10] 8/8 ok
  [192.168.141.11] 7/8 ok  1 WARN
      WARN: droits:tshark — ni root ni CAP_NET_RAW
  [192.168.141.12] 8/8 ok
[OK] Toutes les VMs sont pretes.

# === LANCEMENT ===

# 7. Lancer simultanement (pre-flight auto inclus)
pqc> launch
  Run ID: hybrid-full_14           ← identifiant unique du run (mode + index)
  Pre-flight check (3 VM(s))...
  [OK] Toutes les VMs sont pretes.

  Connexion aux 3 VM(s) pour lancement synchronise...
  Signal envoye en 4 ms
  192.168.141.10: demarre (pid 1234)
  192.168.141.11: demarre (pid 1235)
  192.168.141.12: demarre (pid 1236)

# Le monitoring serveur demarre automatiquement.
# Grafana (http://<serveur>:3000) affiche les metriques en direct.
# Pas besoin de 'status' en boucle — une notification arrive a la fin :

[TEST TERMINE] 3/3 VM(s) done
>>> Tapez 'results' pour collecter les resultats.
pqc>

# 8. Collecter les resultats
pqc> results
  192.168.141.10: 6 evenement(s) [hybrid-full]
  192.168.141.11: 6 evenement(s) [hybrid-full]
  192.168.141.12: 6 evenement(s) [hybrid-full]
  serveur (192.168.141.1): CPU=16.2%  RAM=1862 Mo  RX=643.7 Mbps  (72 echantillons, 360s)
  Master CSV: results/master_hybrid-full_14.csv

pqc> reset all

# 9. Relancer le serveur en mode classic, refaire le cycle
pqc> compare
  Comparatif: results/compare_20260703T180000.csv
```

> **Lancement `--force`** : ignore les echecs FAIL du pre-flight et lance quand meme.

---

## Supervision temps reel

### Stack technique

```text
VMs clientes          Serveur WAN
────────────          ───────────────────────────────────────────
telegraf   ──────────► InfluxDB v2 :8086  ◄─── server_cli.py (_SrvMonitor)
pqc_bench.sh ─────────►                   ◄─── pqc_bench.sh (VM)
                              │
                        Grafana :3000
                              │
                      Dashboard "Live"      → par run_id, rafraichi toutes les 10s
                      Dashboard "Compare"   → comparaison multi-run, bar charts
```

### Demarrage

```bash
# 1. Configurer les secrets (a faire une seule fois)
cp .env.example .env && nano .env

# 2. Demarrer la stack
docker compose up -d

# 3. Exporter le token pour le serveur (et les VMs)
export INFLUX_URL=http://192.168.141.1:8086
export INFLUX_TOKEN=<valeur INFLUX_TOKEN du .env>
export INFLUX_ORG=pqc
export INFLUX_BUCKET=pqc_bench
```

### Metriques collectees

| Measurement InfluxDB | Source | Tags principaux | Champs |
| --- | --- | --- | --- |
| `handshake` | `pqc_bench.sh` (VM) | `run_id`, `vm`, `mode`, `wan` | `hs_min`, `hs_avg`, `hs_max`, `hs_p99`, `tcp_connect_ms`, `ttfb_ms` |
| `traffic` | `pqc_bench.sh` (VM) | `run_id`, `vm`, `mode`, `profile` | `throughput_mbps`, `retransmit_pct` |
| `event` | `pqc_bench.sh` (preset, VM) | `run_id`, `vm`, `mode`, `profile` | `hs_ms`, `throughput_mbps`, `retransmit_pct` |
| `net_quality` | `pqc_bench.sh` (VM) | `run_id`, `vm`, `mode` | `jitter_ms`, `loss_pct`, `loss_udp_pct` |
| `server_metrics` | `server_cli.py` (_SrvMonitor) | `run_id` | `cpu_pct`, `ram_mb`, `rx_mbps` |
| `cpu`, `mem`, `net` | Telegraf (VMs) | `host` | metriques systeme standard |

### Identifiant de run (`run_id`)

A chaque `launch`, `server_cli.py` genere automatiquement un identifiant unique :

```text
run_id = <mode>_<index>     ex: hybrid-full_14, classic_3
```

L'index correspond au prochain `master_<mode>_N.csv` qui sera cree par `results`.
Toutes les metriques InfluxDB du run portent ce tag, permettant d'isoler un run
dans Grafana ou de comparer plusieurs runs cote a cote.

### Dashboards Grafana

Disponibles apres `docker compose up -d` sur `http://<serveur>:3000` (admin / pqcadmin) :

**PQC Bench — Statut Flotte** (`pqc-status-01`) — a ouvrir avant chaque test

- Rafraichissement automatique toutes les 10s
- Voyants par VM (un tile par hostname) colores par etat :

| Couleur | Etat | Signification |
| --- | --- | --- |
| Rouge `⚠ hors ligne` | aucun heartbeat recus | vm_agent.py ne tourne pas ou ne peut pas joindre InfluxDB |
| Gris `idle` | connecte, pas encore configure | `set` non encore lance |
| Jaune `configuree` | configure, pas encore arme | `arm` non encore lance |
| **Vert `✓ armee`** | **pret a lancer** | **tout est OK — `launch` peut etre execute** |
| Vert `⏳ en cours` | test en cours | — |
| Bleu `terminee` | test fini | — |

- Compteurs en haut : VMs connectees / armees / configurees / en cours
- Tableau de detail : hostname, ID, etat textuel, derniere vue

**PQC Bench — Live** (`pqc-live-01`)

- Filtre par `run_id` (liste deroulante auto-alimentee)
- Rafraichissement toutes les 10s
- Panneaux : handshake latence, debit par profil, jitter UDP, CPU/RAM VMs (Telegraf), CPU/RX serveur

**PQC Bench — Comparaison multi-run** (`pqc-compare-01`)

- Bar charts par `run_id` sur 7 jours glissants
- Handshake moyen/P99, TTFB, debit par profil, retransmissions, jitter, packet loss, CPU serveur

### Verification avant lancement

```text
1. Ouvrir "PQC Bench — Statut Flotte" dans Grafana
2. Verifier que toutes les VMs attendues apparaissent (rouge = pb de connexion InfluxDB)
3. Lancer : set all --preset N  →  arm all
4. Dans les 10s, les voyants doivent passer au VERT
5. Lancer : launch
```

Si une VM reste rouge apres le demarrage de vm_agent.py :

- Verifier que `INFLUX_URL` et `INFLUX_TOKEN` sont exports sur la VM
- Tester manuellement : `curl -sf $INFLUX_URL/health` doit repondre `{"status":"pass",...}`

### Configuration en production

Pour changer le token par defaut (recommande) :

1. Editer `docker-compose.yml` : `DOCKER_INFLUXDB_INIT_ADMIN_TOKEN`
2. Editer `grafana/provisioning/datasources/influxdb.yml` : `token`
3. Mettre a jour la variable `INFLUX_TOKEN` sur le serveur et les VMs

---

## Format des fichiers de resultats

**CSV bruts** (generes par `pqc_bench.sh` sur chaque VM) : une ligne par evenement de trafic.

**Master CSV** (`master_[mode]_N.csv`) : agrege par VM + ligne serveur + lignes globales.
Numerotation automatique — les anciens fichiers ne sont jamais ecrases.

```text
Source                  | Mode        | Type_test | WAN | Handshake_moy_ms | Debit_moy_Mbps | CPU_moy_pct | ...
192.168.141.10          | hybrid-full | preset_1  | eu  | 840.0            | 32.0           | 1.7         | ...
192.168.141.11          | hybrid-full | preset_2  | eu  | 164.3            | 151.7          | 3.6         | ...
192.168.141.12          | hybrid-full | preset_3  | eu  | 164.8            | 2.2            | 1.2         | ...
192.168.141.1           | hybrid-full | server    | eu  |                  | 643.7          | 16.2        | ...
GLOBAL_MOY (n=3 VMs)    | hybrid-full | -         | eu  | 295.0            | 84.2           | 2.1         | ...
GLOBAL_MIN              | hybrid-full | -         | eu  | 151.8            | 2.2            | 1.2         | ...
GLOBAL_MAX              | hybrid-full | -         | eu  | 840.0            | 180.8          | 3.6         | ...
GLOBAL_ECART_TYPE       | hybrid-full | -         | eu  | 304.7            | 77.9           | 1.1         | ...
```

> La ligne `server` (Type_test=server) contient les metriques du serveur WAN collectees par
> `_SrvMonitor` pendant la duree exacte du test : CPU moyen, RAM moyenne, debit RX entrant.
> Les lignes GLOBAL_* excluent le serveur (VMs uniquement).

**Comparatif inter-modes** (`compare_[timestamp].csv`, commande `compare`) :
extrait les lignes `GLOBAL_MOY` de tous les master CSV pour comparer les modes cote a cote.

---

## Rapport HTML standalone (generate_report.py)

Genere un rapport HTML interactif depuis les CSV, utilisable **sans Grafana** (connexion internet
requise uniquement pour Chart.js).

```bash
# Un seul run
python3 generate_report.py results/master_hybrid-full_14.csv

# Plusieurs runs (comparaison)
python3 generate_report.py results/master_*.csv

# Fichier de sortie personnalise
python3 generate_report.py results/master_hybrid-full_14.csv --output mon_rapport.html
```

Le rapport est genere dans `results/report_<timestamp>.html` par defaut et contient :

- **Tuiles de synthese** : mode, profil WAN, nombre de VMs, handshake moyen, debit moyen
- **Graphes handshake TLS** : bar chart par profil + courbe chronologique (si CSV bruts disponibles)
- **Graphes debit** : idem
- **Graphe jitter UDP** : filtré sur les profils voip/stream
- **Table de résumé** : toutes les lignes du master CSV
- **Thème clair/sombre** : bascule via le bouton en haut a droite, suit `prefers-color-scheme`

> Les graphes chronologiques et par profil necessitent les **CSV bruts** (`raw_<ip>_<ts>.csv`)
> produits par la commande `results` de `server_cli.py`. Sans eux, seule la table de synthese
> est affichee.

---

## Modes de chiffrement

Selection via `--mode <MODE>` (voir aussi `./pqc_bench.sh --list-modes`) :

| Priorite | Mode | KEM | Signature (certificat) | AES | Standard |
| --- | --- | --- | --- | --- | --- |
| ★★★ | `hybrid-full` | X25519 + ML-KEM-768 | ECDSA P-384 + ML-DSA-65 | 256-GCM | **Cible CNSA 2.0** |
| ★★☆ | `hybrid-kem` | X25519 + ML-KEM-768 | ECDSA P-256 | 256-GCM | Transition hybride KEM |
| ★★☆ | `classic` | X25519 (ECDHE) | ECDSA P-256 | 256-GCM | Baseline classique |
| ★☆☆ | `mlkem768` | ML-KEM-768 | ECDSA P-256 | 256-GCM | FIPS 203 Cat.3 |
| ★☆☆ | `mlkem1024` | ML-KEM-1024 | ECDSA P-256 | 256-GCM | FIPS 203 Cat.5 |
| ★☆☆ | `mlkem512` | ML-KEM-512 | ECDSA P-256 | 128-GCM | FIPS 203 Cat.1 |
| ★☆☆ | `mldsa65` | X25519 | ML-DSA-65 | 256-GCM | FIPS 204 Cat.3 |
| ★☆☆ | `mldsa44` | X25519 | ML-DSA-44 | 256-GCM | FIPS 204 Cat.2 |
| ★☆☆ | `mldsa87` | X25519 | ML-DSA-87 | 256-GCM | FIPS 204 Cat.5 |
| ☆☆☆ | `slhdsa128` | X25519 + ML-KEM-768 | SLH-DSA-128s | 256-GCM | FIPS 205 (lent) |
| ☆☆☆ | `slhdsa256` | X25519 + ML-KEM-768 | SLH-DSA-256s | 256-GCM | FIPS 205 (lent) |

> **Notes :**
>
> - `hybrid-full` utilise un certificat composite `p384_mldsa65` (oqs-provider 0.5+) :
>   double signature ECDSA + ML-DSA dans le meme certificat.
> - `slhdsa*` utilise les alias liboqs : `sphincssha2128ssimple` / `sphincssha2256ssimple`.
> - `mlkem512` reste en AES-128 car son niveau de securite declare est Cat.1 (iso-classique).
> - Tous les autres modes (y compris `classic`) utilisent AES-256 : Grover reduit AES-128
>   a ~64 bits effectifs face a un ordinateur quantique.

---

## Trafic aleatoire continu (`--random`)

Chaque connexion ouvre une nouvelle session TLS : le **handshake PQC est exerce tout au long
du test**, pas uniquement a T=0.

```bash
# 5 minutes de trafic, puis ecriture CSV
./pqc_bench.sh --target 10.0.1.1 --mode hybrid-full --random --duration 300

# Infini - Ctrl+C pour arreter
./pqc_bench.sh --target 10.0.1.1 --mode hybrid-kem --random
```

5 schedulers independants tournent en parallele :

| Type | Duree session | Pause entre sessions | Delai initial |
| --- | --- | --- | --- |
| `msg` (email/chat) | 5-15s | 8-30s | 0-5s |
| `web` (navigation) | 8-20s | 5-20s | 0-10s |
| `file` (transfert) | 15-35s | 30-120s | 0-20s |
| `voip` (visio) | 25-50s | 2-10 min | 0-40s |
| `stream` (video) | 20-40s | 40-180s | 0-25s |

---

## Presets predefinis (`--preset N`)

5 profils PME sur 60 secondes exactement, avec evenements staggeres.

```bash
# Voir le detail de tous les presets
python3 traffic_presets.py list

# Sequence comparative recommandee (meme preset = comparaison valide)
./pqc_bench.sh --target 10.0.1.1 --mode classic      --preset 3
./pqc_bench.sh --target 10.0.1.1 --mode hybrid-kem   --preset 3
./pqc_bench.sh --target 10.0.1.1 --mode hybrid-full  --preset 3
```

| Preset | Profil | Trafic |
| --- | --- | --- |
| **1 - Secretariat** | Bureautique leger | email x3, web x2, fichier x1 |
| **2 - Developpeur** | Transferts git, messagerie | file x2, web x2, msg x2 |
| **3 - Manager** | Email + reunion video | email x2, web x1, **voip a t=22s** |
| **4 - Commercial** | Email + meme reunion | email x2, web x1, **voip a t=23s**, fichier x1 |
| **5 - IT Technicien** | Gros volumes, streaming | file x2, stream x1, web x1, msg x1 |

> Les presets 3 et 4 rejoignent la meme reunion video avec 1s de decalage (t=22s vs t=23s),
> simulant un acces concurrent depuis deux postes differents.

---

## Serveur WAN simule (`--server`)

```bash
# Aide serveur (liste des modes, options)
sudo ./pqc_bench.sh --server --help

# Lancer le serveur (le mode est transmis automatiquement aux VMs via .server_mode)
# --server-ip = IP de l'interface LAN TEST (obligatoire si plusieurs interfaces)
sudo ./pqc_bench.sh --server --mode hybrid-full --wan-profile eu --server-ip 192.168.141.1
```

Le serveur lance :

- Un serveur de trafic custom `traffic_server.py` (TCP :5300, UDP :5301) — multi-client, zero contention
- Un serveur TLS en boucle (port 8443) avec le bon mode cryptographique
- La simulation de latence WAN via `tc-netem` sur l'interface de test uniquement

### Profils de latence WAN

| Profil | Delai | Jitter | Perte | Simule |
| --- | --- | --- | --- | --- |
| `fr` | 15ms +/-3ms | faible | 0.05% | Serveur heberge en France |
| `eu` | 35ms +/-8ms | modere | 0.1% | Serveur en Europe (defaut) |
| `us` | 80ms +/-15ms | eleve | 0.2% | Serveur aux Etats-Unis |

> Sans cette simulation, les handshakes PQC seraient mesures a <1ms au lieu des 30-80ms reels.

---

## Options completes (pqc_bench.sh)

```text
--target <IP>         IP du serveur WAN (obligatoire pour les modes test)
--mode <MODE>         Mode cryptographique (voir tableau des modes)
--list-modes          Affiche le tableau detaille des modes et quitte
--random              Trafic aleatoire continu staggere
--preset <N>          Preset predefini 1-5 (60s)
--profile <PROFILS>   Trafic libre en parallele : web,file,voip,stream,msg,all
--duration <sec>      Duree en secondes (--random: 0=infini | --profile: defaut 30)
--hs-count <N>        Iterations pour la mesure de handshake bulk (defaut: 100)
--output <DIR>        Repertoire de sortie CSV (defaut: ./results)
--wan-profile <p>     Profil latence WAN pour --server : fr | eu | us
--server-ip <IP>      IP de l'interface LAN TEST ecrite dans .server_mode
--vm-id <N>           Identifiant de la VM (assigne automatiquement par server_cli.py)
--run-id <ID>         Identifiant du run pour InfluxDB (assigne automatiquement par server_cli.py)
--scan [SUBNET]       Scan reseau (defaut: sous-reseau local /24)
--install             Installe les dependances (sudo requis)
--server --help       Affiche l'aide serveur avec la liste des modes valides
```

**Variables d'environnement** (surchargent les valeurs par defaut) :

```bash
INFLUX_URL=http://192.168.141.1:8086   # si vide, supervision desactivee (silencieux)
INFLUX_TOKEN=pqc-bench-token-changeme
INFLUX_ORG=pqc
INFLUX_BUCKET=pqc_bench
RUN_ID=hybrid-full_14                  # normalement assigne via --run-id par server_cli.py
```

---

## Colonnes CSV

### CSV brut (par evenement, produit par pqc_bench.sh)

| Colonne | Description | Outil requis |
| --- | --- | --- |
| `Horodatage` | Timestamp du test | — |
| `VM_IP` | IP de la VM cliente (interface test) | — |
| `Serveur_IP` | IP du serveur WAN cible | — |
| `Mode` | Mode cryptographique teste | — |
| `Type_test` | Type de test (preset_1, preset_2...) | — |
| `Profil` | Profil de trafic (msg, web, file, voip, stream) | — |
| `Libelle` | Description lisible de l'evenement | — |
| `Suite_chiffrement` | Suite TLS negociee | — |
| `AES_bits` | Taille de cle AES (128 ou 256) | — |
| `Delai_planifie_s` | Heure de declenchement dans le preset (secondes) | — |
| `Duree_reelle_s` | Duree effective de l'evenement | — |
| `Handshake_ms` | Duree du handshake TLS pour cet evenement (ms) | — |
| `Debit_Mbps` | Debit mesure par traffic_server.py (Mbps) | — |
| `CPU_moy_pct` | CPU moyen de la VM pendant le test | — |
| `RAM_moy_Mo` | RAM utilisee pendant le test (Mo) | — |
| `Retransmissions_pct` | Taux de retransmissions TCP | — |
| `Taille_cle_octets` | Taille de la cle privee (octets) | — |
| `Taille_cert_octets` | Taille du certificat (octets) | — |
| `RTT_moy_ms` / `min` / `max` / `p99` | RTT TCP mesuré par `ss` sur les connexions existantes | kernel (ss) |
| `Jitter_ms` | Variation de latence UDP — voip/stream uniquement, -1 sinon | traffic_server |
| `Packet_loss_UDP_pct` | Taux de perte UDP — voip/stream uniquement, -1 sinon | traffic_server |
| `Fragmentation_pct` | % de paquets fragmentes pendant le handshake TLS | tshark + sudo |
| `Handshake_paquets` | Nombre de paquets echanges pendant le handshake | tshark + sudo |
| `Handshake_octets` | Volume total en octets du handshake | tshark + sudo |
| `TCP_connect_ms` | Duree d'etablissement TCP seul, avant TLS | hping3 |
| `TTFB_ms` | Time To First Byte TLS (premier octet recu) | openssl |
| `Connexions_echec` | Nombre d'echecs de connexion sur l'ensemble du test | — |

### Master CSV (agrege par VM)

| Colonne | Description |
| --- | --- |
| `Source` | IP de la VM, IP du serveur (Type_test=server), ou libelle GLOBAL_* |
| `Mode` | Mode cryptographique |
| `Type_test` | preset_N pour les VMs, `server` pour la ligne serveur, `-` pour GLOBAL |
| `WAN` | Profil de latence WAN |
| `Handshake_moy_ms` / `min` / `max` | Statistiques handshake sur tous les evenements |
| `Debit_moy_Mbps` / `min` / `max` | Statistiques debit (valeurs -1 exclues) |
| `CPU_moy_pct` | CPU moyen (VM pendant le test, ou serveur via _SrvMonitor) |
| `RAM_moy_Mo` | RAM moyenne |
| `Retransmissions_moy_pct` | Taux de retransmissions moyen |
| `RTT_moy_ms` / `min` / `max` / `RTT_p99_moy_ms` | Statistiques RTT TCP (ss) agrégées |
| `Jitter_moy_ms` | Jitter UDP moyen (voip/stream uniquement) |
| `Packet_loss_UDP_moy_pct` | Perte paquets UDP moyenne (voip/stream uniquement) |
| `Fragmentation_moy_pct` | % de fragmentation moyen sur le handshake |
| `Handshake_paquets_moy` | Nombre moyen de paquets par handshake |
| `Handshake_octets_moy` | Volume moyen en octets par handshake |
| `TCP_connect_moy_ms` | Temps d'etablissement TCP moyen |
| `TTFB_moy_ms` | TTFB TLS moyen |
| `Connexions_echec_total` | Somme des echecs de connexion |
| `Nb_evenements` | Nombre d'evenements de trafic du test |

---

## Metriques cles a analyser

### Crypto et performances

| Metrique | Ce qu'elle revele |
| --- | --- |
| `Handshake_moy_ms` | Overhead direct de PQC vs classique a chaque connexion |
| `GLOBAL_ECART_TYPE Handshake_moy_ms` | Variabilite entre VMs (stabilite du test) |
| `Debit_moy_Mbps` | Degradation du debit sous charge crypto |
| `CPU_moy_pct` (VM) | Cout CPU client (ML-DSA bien plus lourd que ML-KEM) |
| `CPU_moy_pct` (server) | Cout CPU serveur (visible dans la ligne `server` du master) |

### Transport reseau

| Metrique | Ce qu'elle revele |
| --- | --- |
| `Handshake_paquets_moy` | Impact de la taille des cles PQC sur le nombre de paquets |
| `Handshake_octets_moy` | Volume reseau du handshake — cle ML-KEM-768 ≈ 1.1 KB vs 32 B pour X25519 |
| `Fragmentation_moy_pct` | % de fragmentation MTU — les grandes cles PQC peuvent depasser 1500 B |
| `TCP_connect_moy_ms` | Latence reseau brute (independante de la crypto) — baseline |
| `TTFB_moy_ms` | Latence percue par l'application — TCP + TLS, impact reel utilisateur |
| `Jitter_moy_ms` | Impact sur la voip/visio — un jitter > 30ms degrade la qualite audio |
| `Packet_loss_UDP_moy_pct` | Perte sur les flux temps-reel — critique pour voip et stream |

---

## Ports utilises

| Port | Protocole | Usage |
| --- | --- | --- |
| 5300 | TCP | traffic_server.py — trafic file/stream/web/msg/voip |
| 5301 | UDP | traffic_server.py — trafic voip et jitter |
| 8443 | TCP/TLS | Serveur TLS (handshake PQC) |
| 8086 | TCP | InfluxDB v2 (supervision) |
| 3000 | TCP | Grafana (dashboards) |
| 9998 | TCP | vm_agent — controle par server_cli.py (via LAN CONTROLE) |

> **Separation des flux :** le port 9998 (controle) transite par le LAN 192.168.142.x et n'est
> pas affecte par la simulation WAN (tc-netem appliquee uniquement sur l'interface 192.168.141.x).

---

## Depannage

### Installation et prerequis

| Probleme | Solution |
| --- | --- |
| `Permission denied` apres git clone | `chmod +x pqc_bench.sh` |
| `sudo: 'pqc_bench.sh': command not found` | Utiliser `sudo ./pqc_bench.sh` |
| `oqsprovider not found` apres `--install` | Relancer `sudo ./pqc_bench.sh --install` |
| `openssl list -providers` ne montre pas oqsprovider | `find /usr -name "oqsprovider.so"` puis `sudo ln -s <chemin> /usr/local/lib/ossl-modules/oqsprovider.so` |

### Serveur et trafic

| Probleme | Solution |
| --- | --- |
| Connexion refusee sur port 5300 | Verifier que `traffic_server.py` tourne (lance par `--server`) |
| `openssl s_client: handshake failure` | Mode client et serveur doivent correspondre |
| `tc: command not found` | `sudo apt install iproute2` |
| Instance traffic_server residuelle | `sudo pkill -f "traffic_server.py"` |
| Serveur boucle apres Ctrl+C | `sudo pkill -f "openssl s_server"; sudo pkill -f "traffic_server.py"` |

### server_cli.py et VMs

| Probleme | Solution |
| --- | --- |
| `scan` ne trouve aucun agent | Verifier que `vm_agent.py` tourne et que le port 9998 est ouvert |
| `scan --control` n'appaire pas de VM | Verifier que les agents ont deja un ID (faire `scan --test` d'abord) |
| VM en `unreachable` apres re-scan | La VM etait connue mais injoignable — `reset <ip>` ou attendre qu'elle revienne |
| `--force-remove` / `--force-keep` | Flags pour eviter le prompt interactif lors d'un re-scan avec VMs manquantes |
| `list` ne montre pas IP CTRL | Faire `scan --control <subnet>` apres le scan test |
| `launch` sans run_id affiche | Normal si aucune VM armed — faire `arm all` d'abord |
| `[TEST TERMINE]` n'arrive pas | Le watcher timeout apres 1h — utiliser `status` pour verifier |
| `results` retourne "aucun fichier" | Le test n'est pas termine (`status`) ou la VM a plante (`logs`) |
| `ERREUR: mode X != mode du serveur Y` | Relancer le serveur avec le bon mode ou omettre `--mode` dans `set` |
| Colonnes `Fragmentation_pct` toutes a `-1` | `tshark` absent ou script sans `sudo` |
| Colonne `TCP_connect_ms` a `-1` | `sudo apt install hping3` |
| `launch` abandonne avec `[ABORT]` | Pre-flight a echoue — lire les FAIL, ou `launch --force` |

### Supervision (InfluxDB / Grafana)

| Probleme | Solution |
| --- | --- |
| Grafana ne demarre pas | `docker compose logs grafana` ; verifier que le port 3000 est libre |
| InfluxDB inaccessible | `docker compose logs influxdb` ; verifier le port 8086 |
| Aucune donnee dans Grafana | Verifier que `INFLUX_URL` est defini sur le serveur et les VMs |
| Dashboard "Live" vide | Selectionner le bon `run_id` dans le menu deroulant en haut |
| `server_metrics` absent | La supervision ne demarre qu'a `launch` — les runs anterieurs n'ont pas de donnees serveur |
| Telegraf n'envoie pas de donnees | `sudo journalctl -u telegraf -f` ; verifier l'URL et le token dans `/etc/telegraf/telegraf.conf` |
| Token InfluxDB refuse | Regenerer via l'UI InfluxDB (:8086), mettre a jour `.env` + `telegraf.conf`, puis `docker compose restart grafana` |
| Pas de `run_id` dans les donnees VM | Verifier que `INFLUX_URL` est export sur les VMs ET que `--run-id` est passe par `vm_agent.py` |
| Redemarrer proprement la stack | `docker compose down && docker compose up -d` (les volumes sont persistants) |
| Purger toutes les donnees | `docker compose down -v` (supprime les volumes — irreversible) |

### Permissions apres git clone

```bash
chmod +x pqc_bench.sh
git config core.fileMode false   # evite les changements de permissions dans git diff
```

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe - liboqs](https://github.com/open-quantum-safe/liboqs)
- [OQS Provider for OpenSSL 3](https://github.com/open-quantum-safe/oqs-provider)
- [InfluxDB v2 line protocol](https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/)
- [Telegraf documentation](https://docs.influxdata.com/telegraf/v1/)
