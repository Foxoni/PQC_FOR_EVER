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

Le banc de test repose sur deux roles :

- **Serveur WAN** : simule un serveur internet distant avec latence artificielle (tc-netem).
  Lance `pqc_bench.sh --server` pour accepter les connexions TLS et iperf3,
  et `server_cli.py` pour orchestrer les VMs clientes depuis un CLI interactif.

- **VMs clientes** : chaque VM execute `vm_agent.py` (daemon TCP port 9998) qui attend les
  ordres du serveur. Sur signal, elle lance `pqc_bench.sh` et mesure les performances vers
  le serveur WAN.

### Fichiers

```text
pqc_bench/
├── pqc_bench.sh          # Moteur de test - generation certificats, handshake, trafic
├── traffic_gen.py        # Module utilitaire (stats, monitoring CPU/RAM, CSV)
├── traffic_presets.py    # Generateur de trafic - presets + mode continu aleatoire
├── vm_agent.py           # Daemon de controle sur chaque VM cliente (port 9998)
├── server_cli.py         # CLI central sur le serveur - orchestre toutes les VMs
└── results/              # Fichiers CSV produits (cree automatiquement)
```

| Fichier | Role |
| --- | --- |
| `pqc_bench.sh` | Moteur d'execution : certificats, handshake TLS, orchestration trafic, ecriture CSV |
| `traffic_gen.py` | Stats (min/avg/max/p99), monitoring CPU/RAM psutil, parsing JSON iperf3, fusion CSV |
| `traffic_presets.py` | 5 presets PME predefinis + mode aleatoire continu, handshake TLS par connexion |
| `vm_agent.py` | Daemon TCP sur chaque VM cliente : recoit les ordres du serveur, lance pqc_bench.sh |
| `server_cli.py` | CLI interactif sur le serveur WAN : scan, configuration, lancement synchronise, collecte |

---

## Prerequis

### Systeme (Debian / Ubuntu)

Paquets obligatoires :

```bash
sudo apt install -y \
    nmap iperf3 tcpdump \
    openssl python3 python3-pip curl \
    cmake gcc g++ libtool libssl-dev pkg-config \
    iproute2 net-tools bc netcat-openbsd git

pip3 install psutil
```

Paquets optionnels (metriques reseau avancees) :

```bash
sudo apt install -y hping3 tshark fping
```

| Outil | Metriques activees | Droits requis |
| --- | --- | --- |
| `hping3` | `TCP_connect_ms`, `Ping_p99_ms` | aucun |
| `tshark` | `Fragmentation_pct`, `Handshake_paquets`, `Handshake_octets` | **root** (CAP_NET_RAW) |
| `fping` | fallback si hping3 absent | aucun |
| `curl` | `TTFB_ms` | aucun |

> Si un outil est absent ou que les droits manquent, les colonnes correspondantes sont remplies
> avec `-1` (convention "non mesure") sans faire echouer le test.

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

---

## Deploiement

### Sur toutes les machines (serveur et clients)

```bash
git clone https://github.com/Foxoni/PQC_FOR_EVER.git
cd PQC_FOR_EVER
chmod +x pqc_bench.sh
sudo ./pqc_bench.sh --install
```

### Sur le serveur WAN

```bash
# Aide et liste des modes disponibles
sudo ./pqc_bench.sh --server --help

# Terminal 1 : lancer le serveur de trafic
# --server-ip : optionnel, utile si la machine a plusieurs interfaces reseau
sudo ./pqc_bench.sh --server --mode hybrid-full --wan-profile eu
sudo ./pqc_bench.sh --server --mode hybrid-full --wan-profile eu --server-ip 192.168.x.1

# Terminal 2 : lancer le CLI de controle
python3 server_cli.py --subnet 192.168.x.0/24
```

### Sur chaque VM cliente

```bash
# Lancer le daemon de controle (reste en arriere-plan)
python3 vm_agent.py
```

---

## Controle centralise depuis le serveur

`server_cli.py` est un CLI interactif qui orchestre toutes les VMs depuis le serveur.
Les VMs doivent avoir `vm_agent.py` en cours d'execution.

```text
PQC Bench -- Controleur central  (tapez 'help' pour l'aide)

pqc>
```

### Commandes disponibles

| Commande | Description |
| --- | --- |
| `scan [subnet]` | Scan parallele du sous-reseau, detecte les agents et leur assigne un numero `[1]`, `[2]`... |
| `list` | Tableau : numero, IP, etat, preset, mode, WAN, derniere vue |
| `set <N\|ip\|all> [--preset N] [--wan-profile WAN] [--duration D]` | Configure une ou toutes les VMs par numero, IP ou `all` — mode et cible auto-detectes |
| `arm [N\|ip\|all]` | Met les VMs configurees en standby (pretes a demarrer) |
| `launch` | Envoie START a toutes les VMs armed **simultanement** |
| `status [N\|ip\|all]` | Poll l'etat + 5 dernieres lignes de log + code de retour |
| `logs [N\|ip\|all] [--lines N]` | Affiche le log complet de pqc_bench.sh sur la VM (defaut 50 lignes) |
| `reset [N\|ip\|all]` | Remet en idle, kill le test si en cours |
| `results` | Collecte les CSV, produit `master_[mode]_N.csv` (numerotation auto) |
| `compare [--output FILE]` | Lit tous les master CSV et produit un comparatif inter-modes |
| `help` | Liste des commandes |
| `exit` / `quit` | Quitte le CLI |

> **Mode et IP automatiques :** au demarrage, `pqc_bench.sh --server` ecrit un fichier `.server_mode`
> contenant le mode et son IP. `server_cli.py` le lit pour remplir automatiquement `--mode` et
> `--target` dans la commande `set`. Si le serveur a plusieurs interfaces reseau, specifier
> `--server-ip <IP>` au lancement pour choisir la bonne adresse.
> Un `--mode` fourni manuellement different du serveur est refuse pour eviter des mesures invalides.

### Etats d'une VM

```text
idle --> configured --> armed --> running --> done
  ^                                            |
  |______________ reset ______________________|
```

### Workflow complet depuis le serveur

```bash
# 1. Decouvrir les VMs avec vm_agent actif
pqc> scan 192.168.1.0/24
  [1] 192.168.1.10   [idle]
  [2] 192.168.1.11   [idle]
  [3] 192.168.1.12   [idle]
3 agent(s) detecte(s).

# 2. Configurer toutes les VMs (mode et IP auto-detectes depuis le serveur)
pqc> set all --preset 2
  [mode auto: hybrid-full]
  [target auto: 192.168.1.1]
  192.168.1.10: OK
  192.168.1.11: OK
  192.168.1.12: OK

# 3. Ou configurer chaque VM par son numero de scan
pqc> set 1 --preset 1
pqc> set 2 --preset 3
pqc> set 3 --preset 5

# On peut aussi cibler plusieurs VMs a la fois
pqc> set 1,3 --preset 2

# 4. Mettre toutes les VMs en standby
pqc> arm all

# 5. Lancement simultane (toutes partent en meme temps)
pqc> launch
  Signal envoye en 3 ms
  192.168.1.10: demarre (pid 1234)
  192.168.1.11: demarre (pid 1235)
  192.168.1.12: demarre (pid 1236)

# 6. Surveiller l'avancement (affiche aussi les derniers logs)
pqc> status
  192.168.1.10: running  {'mode': 'hybrid-full', 'preset': 2, ...}
    | [INFO] Handshake #42/100...
  192.168.1.11: done  rc=0

# 7. En cas de probleme, consulter les logs complets
pqc> logs 192.168.1.10 --lines 30

# 8. Collecter les resultats du test (genere master_hybrid-full_1.csv)
pqc> results
  192.168.1.10: 6 evenement(s) [hybrid-full]
  192.168.1.11: 6 evenement(s) [hybrid-full]
  192.168.1.12: 6 evenement(s) [hybrid-full]
  Master CSV: results/master_hybrid-full_1.csv

pqc> reset all

# 9. Relancer le serveur en mode classic, refaire le cycle, puis comparer
pqc> compare
  Comparatif: results/compare_20260622T180000.csv  (2 ligne(s) sur 2 master(s))
```

### Format des fichiers de resultats

**CSV bruts** (generes par `pqc_bench.sh` sur chaque VM) : une ligne par evenement de trafic.

**Master CSV** (`master_[mode]_N.csv`) : une ligne aggregee par VM + lignes globales.
Numerotation automatique — les anciens fichiers ne sont jamais ecrases.

```text
Source               | Mode        | WAN | Handshake_moy_ms | Handshake_min_ms | Debit_moy_Mbps | CPU_moy_pct | ...
192.168.1.10         | hybrid-full | eu  | 22.4             | 18.1             | 9.8            | 5.1         | ...
192.168.1.11         | hybrid-full | eu  | 21.8             | 17.9             | 10.1           | 4.9         | ...
192.168.1.12         | hybrid-full | eu  | 23.1             | 18.5             | 9.5            | 5.3         | ...
GLOBAL_MOY (n=3 VMs) | hybrid-full | eu  | 22.4             | 18.2             | 9.8            | 5.1         | ...
GLOBAL_MIN           | hybrid-full | eu  | 21.8             | 17.9             | 9.5            | 4.9         | ...
GLOBAL_MAX           | hybrid-full | eu  | 23.1             | 18.5             | 10.1           | 5.3         | ...
GLOBAL_ECART_TYPE    | hybrid-full | eu  | 0.67             | 0.31             | 0.31           | 0.20        | ...
```

**Comparatif inter-modes** (`compare_[timestamp].csv`, commande `compare`) :
extrait les lignes `GLOBAL_MOY` de tous les master CSV pour comparer les modes cote a cote.

---

## Modes de chiffrement

Selection via `--mode <MODE>` (voir aussi `./pqc_bench.sh --list-modes`) :

| Priorite | Mode | KEM | Signature (certificat) | AES | Standard |
| --- | --- | --- | --- | --- | --- |
| ★★★ | `hybrid-full` | X25519 + ML-KEM-768 | ECDSA P-256 + ML-DSA-65 | 256-GCM | **Cible CNSA 2.0** |
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
> - `hybrid-full` utilise un certificat composite `p256_mldsa65` (oqs-provider 0.5+) :
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

# Lancer le serveur (le mode choisi ici est transmis automatiquement aux VMs)
sudo ./pqc_bench.sh --server --mode hybrid-full --wan-profile eu
```

Le serveur lance :

- Un pool de 10 instances iperf3 (ports 5201-5210, une instance dediee par port)
- Un serveur TLS en boucle (port 8443) avec le bon mode cryptographique
- La simulation de latence WAN via `tc-netem`

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
--server-ip <IP>      Force l'IP ecrite dans .server_mode (plusieurs interfaces)
--scan [SUBNET]       Scan reseau (defaut: sous-reseau local /24)
--install             Installe les dependances (sudo requis)
--server --help       Affiche l'aide serveur avec la liste des modes valides
```

> Les metriques de capture reseau (`Fragmentation_pct`, `Handshake_paquets`, `Handshake_octets`)
> necessitent `tshark` et l'execution en `sudo`. Sans ces droits, les colonnes affichent `-1`.

---

## Format de sortie CSV

Les fichiers sont ecrits dans `results/` :

```text
{vm_ip}_{mode}_{preset}_{ts}.csv    # CSV brut par VM (une ligne par evenement)
log_{mode}_{preset}.txt             # Log de pqc_bench.sh (commande logs)
raw_{ip}_{ts}.csv                   # Copie individuelle collectee par results
master_{mode}_N.csv                 # Master agrege du test N pour ce mode
compare_{ts}.csv                    # Comparatif inter-modes (commande compare)
```

### Colonnes du CSV brut (par evenement)

| Colonne | Description | Outil requis |
| --- | --- | --- |
| `Horodatage` | Timestamp du test | — |
| `VM_IP` | IP de la VM cliente | — |
| `Serveur_IP` | IP du serveur WAN cible | — |
| `Mode` | Mode cryptographique teste | — |
| `Type_test` | Type de test (preset_1, preset_2...) | — |
| `Profil` | Profil de trafic de l'evenement (msg, web, file, voip, stream) | — |
| `Libelle` | Description lisible de l'evenement | — |
| `Suite_chiffrement` | Suite TLS negociee | — |
| `AES_bits` | Taille de cle AES (128 ou 256) | — |
| `Delai_planifie_s` | Heure de declenchement dans le preset (secondes) | — |
| `Duree_reelle_s` | Duree effective de l'evenement | — |
| `Handshake_ms` | Duree du handshake TLS pour cet evenement (ms) | — |
| `Debit_Mbps` | Debit mesure par iperf3 (Mbps) | — |
| `CPU_moy_pct` | CPU moyen de la VM pendant le test | — |
| `RAM_moy_Mo` | RAM utilisee pendant le test (Mo) | — |
| `Retransmissions_pct` | Taux de retransmissions TCP | — |
| `Taille_cle_octets` | Taille de la cle privee (octets) | — |
| `Taille_cert_octets` | Taille du certificat (octets) | — |
| **Metriques reseau — mesures pendant l'evenement** | | |
| `Ping_moy_ms` | RTT moyen pendant le trafic (ping en parallele) | ping |
| `Ping_min_ms` | RTT minimum | ping |
| `Ping_max_ms` | RTT maximum | ping |
| `Ping_p99_ms` | RTT 99e percentile | hping3 / ping |
| `Jitter_ms` | Variation de latence UDP — voip et stream uniquement, -1 sinon | iperf3 |
| `Packet_loss_pct` | Taux de perte global (ICMP) | ping |
| `Packet_loss_UDP_pct` | Taux de perte UDP — voip et stream uniquement, -1 sinon | iperf3 |
| **Metriques handshake reseau — capture du premier handshake** | | |
| `Fragmentation_pct` | % de paquets fragmentes pendant le handshake TLS | tshark + sudo |
| `Handshake_paquets` | Nombre de paquets echanges pendant le handshake | tshark + sudo |
| `Handshake_octets` | Volume total en octets du handshake | tshark + sudo |
| **Latence applicative** | | |
| `TCP_connect_ms` | Duree d'etablissement TCP seul, avant TLS | hping3 |
| `TTFB_ms` | Time To First Byte TLS (time_appconnect via curl) | curl |
| `Connexions_echec` | Nombre d'echecs de connexion sur l'ensemble du test | — |

> Les colonnes marquees `-1` sont non disponibles soit parce que l'outil manque,
> soit parce que la metrique n'est pas pertinente pour ce profil.

### Colonnes du master CSV (agrege par VM)

| Colonne | Description |
| --- | --- |
| `Source` | IP de la VM ou libelle GLOBAL_* |
| `Mode` | Mode cryptographique |
| `WAN` | Profil de latence WAN |
| `Handshake_moy_ms` / `min` / `max` | Statistiques handshake sur tous les evenements |
| `Debit_moy_Mbps` / `min` / `max` | Statistiques debit (valeurs -1 exclues) |
| `CPU_moy_pct` | CPU moyen |
| `RAM_moy_Mo` | RAM moyenne |
| `Retransmissions_moy_pct` | Taux de retransmissions moyen |
| `Ping_moy_ms` / `Ping_min_ms` / `Ping_max_ms` | Statistiques RTT ICMP |
| `Ping_p99_moy_ms` | Moyenne des p99 de latence entre VMs |
| `Jitter_moy_ms` | Jitter UDP moyen (voip/stream uniquement) |
| `Packet_loss_moy_pct` | Perte paquets globale moyenne |
| `Packet_loss_UDP_moy_pct` | Perte paquets UDP moyenne (voip/stream uniquement) |
| `Fragmentation_moy_pct` | % de fragmentation moyen sur le handshake |
| `Handshake_paquets_moy` | Nombre moyen de paquets par handshake |
| `Handshake_octets_moy` | Volume moyen en octets par handshake |
| `TCP_connect_moy_ms` | Temps d'etablissement TCP moyen |
| `TTFB_moy_ms` | TTFB TLS moyen |
| `Connexions_echec_total` | Somme des echecs de connexion (pas une moyenne) |
| `Nb_evenements` | Nombre d'evenements de trafic du test |

---

## Workflow de comparaison PQC vs Classique

```text
SERVEUR WAN                                        VMs CLIENTES
-----------                                        ------------
1. pqc_bench.sh --server --mode classic --wan-profile eu

2. server_cli.py
   pqc> scan 192.168.x.0/24
   pqc> set all --preset 2
   #    [mode auto: classic]  [target auto: 192.168.x.1]
   pqc> arm all
   pqc> launch              ------>   [test lance simultanement sur toutes les VMs]
   pqc> status              (attente fin du test, logs visibles en cas d'erreur)
   pqc> results             <------   [genere master_classic_1.csv]
   pqc> reset all

3. Ctrl+C sur le serveur, relancer avec un autre mode, repeter :
   pqc_bench.sh --server --mode hybrid-kem  --wan-profile eu
   # [mode auto: hybrid-kem]  -> master_hybrid-kem_1.csv
   pqc_bench.sh --server --mode hybrid-full --wan-profile eu
   # [mode auto: hybrid-full] -> master_hybrid-full_1.csv

# Modes supplementaires selon les besoins :
# mlkem512, mlkem768, mlkem1024, mldsa44, mldsa65, mldsa87, slhdsa128, slhdsa256

4. Generer le comparatif final
   pqc> compare             <------   [compare_[ts].csv avec tous les modes cote a cote]
```

---

## Metriques cles a analyser

### Crypto et performances

| Metrique | Ce qu'elle revele |
| --- | --- |
| `Handshake_moy_ms` | Overhead direct de PQC vs classique a chaque connexion |
| `GLOBAL_ECART_TYPE Handshake_moy_ms` | Variabilite entre VMs (stabilite du test) |
| `Debit_moy_Mbps` | Degradation du debit sous charge crypto |
| `CPU_moy_pct` | Cout CPU (ML-DSA bien plus lourd que ML-KEM) |
| `Retransmissions_moy_pct` | Stabilite reseau sous charge |

### Transport reseau

| Metrique | Ce qu'elle revele |
| --- | --- |
| `Handshake_paquets_moy` | Impact de la taille des cles PQC sur le nombre de paquets — ML-KEM-768/1024 envoient plus de paquets que ECDHE |
| `Handshake_octets_moy` | Volume reseau du handshake — cle publique ML-KEM-768 ≈ 1.1 KB vs 32 B pour X25519 |
| `Fragmentation_moy_pct` | % de fragmentation MTU — les grandes cles PQC peuvent depasser 1500 B et fragmenter |
| `TCP_connect_moy_ms` | Latence reseau brute (independante de la crypto) — baseline du chemin reseau |
| `TTFB_moy_ms` | Latence percue par l'application — TCP + TLS, reflete l'impact reel utilisateur |
| `Ping_moy_ms` / `Ping_p99_moy_ms` | Stabilite de la latence sous charge de trafic |
| `Jitter_moy_ms` | Impact sur la voip/visio — un jitter > 30ms degrade la qualite audio |
| `Packet_loss_UDP_moy_pct` | Perte sur les flux temps-reel — critique pour voip et stream |
| `Connexions_echec_total` | Fiabilite globale — echecs TLS sur l'ensemble du test |

---

## Ports utilises

| Port | Protocole | Usage |
| --- | --- | --- |
| 5201 | TCP | iperf3 - transfert fichier |
| 5202 | UDP | iperf3 - visioconference (bidir) |
| 5203 | TCP | iperf3 - streaming video |
| 5204 | TCP | iperf3 - navigation web |
| 5205 | TCP | iperf3 - messagerie |
| 5206-5210 | TCP | iperf3 - pool reserve |
| 8443 | TCP/TLS | Serveur TLS (handshake PQC) |
| 9998 | TCP | vm_agent - controle par server_cli.py |
| 9999 | TCP | Port marqueur (detection deploiement par --scan) |

---

## Depannage

| Probleme | Solution |
| --- | --- |
| `Permission denied` apres `git clone` ou `git pull` | `chmod +x pqc_bench.sh` (voir ci-dessous) |
| `sudo: 'pqc_bench.sh': command not found` | Utiliser `sudo ./pqc_bench.sh` (le `./` est obligatoire) |
| `oqsprovider not found` | Relancer `sudo ./pqc_bench.sh --install` |
| `iperf3: connect failed` | Verifier que le serveur tourne et les ports 5201-5210 sont ouverts |
| `openssl s_client: handshake failure` | Le mode du client et du serveur doivent correspondre |
| `tc: command not found` | Installer `iproute2` ; sans tc la simulation WAN est desactivee |
| Resultats trop variables | Augmenter `--hs-count 200` et `--duration 120` |
| `date +%s%3N` ne fonctionne pas | Verifier GNU date (`apt install coreutils`) |
| Conflits de port iperf3 | Verifier qu'aucune autre instance ne tourne (`pkill iperf3`) |
| Le serveur boucle apres Ctrl+C + relance | `sudo pkill -f "openssl s_server"; sudo pkill -f "iperf3 -s"` |
| `scan` ne trouve aucun agent | Verifier que `python3 vm_agent.py` tourne sur les VMs et que le port 9998 est ouvert |
| VM bloquee en etat `armed` | Utiliser `reset <ip>` puis reconfigurer |
| `results` retourne "aucun fichier" | Le test n'est peut-etre pas termine (`status` pour verifier) |
| Lancement non simultane | Verifier la connectivite reseau ; un delai > 500ms indique un probleme |
| Test se termine immediatement (etat `done` en quelques secondes) | Utiliser `logs <ip>` pour voir l'erreur dans pqc_bench.sh |
| `--target manquant` lors du `set` | Ajouter `--target <IP_serveur_WAN>` a la commande set |
| `ERREUR: --mode requis (serveur non demarre)` | Lancer `sudo ./pqc_bench.sh --server --mode MODE` avant d'utiliser `set` |
| `ERREUR: mode X != mode du serveur Y` | Le serveur tourne avec un mode different — relancer le serveur avec le bon mode ou omettre `--mode` dans `set` |
| `[ERR] Mode inconnu : 'xxx'` au demarrage du serveur | Le mode n'existe pas — lancer `sudo ./pqc_bench.sh --server --help` pour voir la liste |
| `compare` ne trouve aucun master CSV | Lancer `results` au moins une fois pour generer un `master_*.csv` |
| Colonnes `Fragmentation_pct`, `Handshake_paquets`, `Handshake_octets` toutes a `-1` | `tshark` absent ou script lance sans `sudo` — ces metriques necessitent CAP_NET_RAW |
| Colonne `TCP_connect_ms` a `-1` | `hping3` absent — `sudo apt install hping3` |
| Colonne `TTFB_ms` a `-1` | `curl` absent — `sudo apt install curl` |
| `[WARN] tshark present mais non-root` | Relancer le test avec `sudo` pour activer la capture reseau |

### Permissions apres git clone / git pull

Sur Linux, les fichiers `.sh` clones depuis Windows n'ont pas le bit executable.
A lancer une seule fois apres chaque clone ou pull :

```bash
chmod +x pqc_bench.sh
```

Pour ne plus avoir a le refaire apres un `git pull`, il est possible de configurer git
pour ignorer le mode des fichiers localement :

```bash
git config core.fileMode false
```

> Note : cela desactive uniquement la detection locale des changements de permissions,
> les permissions sur la VM restent inchangees apres un pull suivant.
> Il faudra relancer `chmod +x pqc_bench.sh` si le fichier est remplace par un pull.

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe - liboqs](https://github.com/open-quantum-safe/liboqs)
- [OQS Provider for OpenSSL 3](https://github.com/open-quantum-safe/oqs-provider)
