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

```bash
sudo apt install -y \
    nmap iperf3 hping3 tcpdump tshark \
    openssl python3 python3-pip \
    cmake gcc g++ libtool libssl-dev pkg-config \
    iproute2 net-tools bc netcat-openbsd git

pip3 install psutil
```

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
# Terminal 1 : lancer le serveur de trafic
sudo ./pqc_bench.sh --server --mode mlkem768 --wan-profile eu

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
| `scan [subnet]` | Scan parallele du sous-reseau, detecte les agents actifs et leur etat |
| `list` | Tableau : IP, etat, preset, mode, WAN, derniere vue |
| `set <ip\|all> --target IP [--preset N] [--wan-profile WAN] [--duration D]` | Configure une ou toutes les VMs — le mode est lu automatiquement depuis le serveur |
| `arm [all\|<ip>]` | Met les VMs configurees en standby (pretes a demarrer) |
| `launch` | Envoie START a toutes les VMs armed **simultanement** |
| `status [all\|<ip>]` | Poll l'etat + 5 dernieres lignes de log + code de retour |
| `logs [all\|<ip>] [--lines N]` | Affiche le log complet de pqc_bench.sh sur la VM (defaut 50 lignes) |
| `reset [all\|<ip>]` | Remet en idle, kill le test si en cours |
| `results` | Collecte les CSV, produit `master_[mode]_N.csv` (numerotation auto) |
| `compare [--output FILE]` | Lit tous les master CSV et produit un comparatif inter-modes |
| `help` | Liste des commandes |
| `exit` / `quit` | Quitte le CLI |

> **Mode automatique :** `server_cli.py` lit le mode directement depuis le serveur (`pqc_bench.sh --server`
> ecrit `.server_mode` au demarrage). Il est inutile de specifier `--mode` dans `set`.
> Si le serveur n'est pas demarre, une erreur est affichee. Si un `--mode` est quand meme fourni
> et ne correspond pas au serveur, la commande est refusee.

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
  192.168.1.10   [idle]
  192.168.1.11   [idle]
  192.168.1.12   [idle]

# 2. Configurer toutes les VMs
#    Le mode est lu automatiquement depuis le serveur (pas besoin de --mode)
#    --target : IP du serveur WAN (vers lequel les clients vont se connecter)
pqc> set all --preset 2 --target 192.168.1.1
  [mode auto depuis serveur: mlkem768]
  192.168.1.10: OK
  192.168.1.11: OK
  192.168.1.12: OK

# 3. Ou configurer chaque VM individuellement avec un preset different
pqc> set 192.168.1.10 --preset 1 --target 192.168.1.1
pqc> set 192.168.1.11 --preset 3 --target 192.168.1.1
pqc> set 192.168.1.12 --preset 5 --target 192.168.1.1

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
  192.168.1.10: running  {'mode': 'mlkem768', 'preset': 2, ...}
    | [INFO] Handshake #42/100...
  192.168.1.11: done  rc=0

# 7. En cas de probleme, consulter les logs complets
pqc> logs 192.168.1.10 --lines 30

# 8. Collecter les resultats du test (genere master_mlkem768_1.csv)
pqc> results
  192.168.1.10: 6 evenement(s) [mlkem768]
  192.168.1.11: 6 evenement(s) [mlkem768]
  192.168.1.12: 6 evenement(s) [mlkem768]
  Master CSV: results/master_mlkem768_1.csv

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
Source               | Mode    | WAN | Handshake_moy_ms | Handshake_min_ms | Debit_moy_Mbps | CPU_moy_pct | ...
192.168.1.10         | mlkem768| eu  | 14.2             | 11.1             | 9.8            | 4.2         | ...
192.168.1.11         | mlkem768| eu  | 13.8             | 10.9             | 10.1           | 4.0         | ...
192.168.1.12         | mlkem768| eu  | 15.1             | 11.5             | 9.5            | 4.5         | ...
GLOBAL_MOY (n=3 VMs) | mlkem768| eu  | 14.4             | 11.2             | 9.8            | 4.2         | ...
GLOBAL_MIN           | mlkem768| eu  | 13.8             | 10.9             | 9.5            | 4.0         | ...
GLOBAL_MAX           | mlkem768| eu  | 15.1             | 11.5             | 10.1           | 4.5         | ...
GLOBAL_ECART_TYPE    | mlkem768| eu  | 0.67             | 0.31             | 0.31           | 0.25        | ...
```

**Comparatif inter-modes** (`compare_[timestamp].csv`, commande `compare`) :
extrait les lignes `GLOBAL_MOY` de tous les master CSV pour comparer les modes cote a cote.

---

## Modes de chiffrement

Selection via `--mode <MODE>` :

| Mode | Echange de cle | Signature | Chiffrement symetrique | Standard |
| --- | --- | --- | --- | --- |
| `classic` | X25519 (ECDHE) | ECDSA P-256 | AES-128-GCM | TLS 1.3 actuel |
| `mlkem512` | ML-KEM-512 | ECDSA P-256 | AES-128-GCM | FIPS 203 Cat.1 |
| `mlkem768` | ML-KEM-768 | ECDSA P-256 | AES-256-GCM | FIPS 203 Cat.3 |
| `mlkem1024` | ML-KEM-1024 | ECDSA P-256 | AES-256-GCM | FIPS 203 Cat.5 |
| `hybrid` | X25519 + ML-KEM-768 | ECDSA P-256 | AES-256-GCM | Recommande NIST (transition) |
| `mldsa44` | X25519 | ML-DSA-44 | AES-256-GCM | FIPS 204 Cat.2 |
| `mldsa65` | X25519 | ML-DSA-65 | AES-256-GCM | FIPS 204 Cat.3 |
| `mldsa87` | X25519 | ML-DSA-87 | AES-256-GCM | FIPS 204 Cat.5 |

> **Pourquoi AES-256 pour les modes PQC ?**  
> L'algorithme de Grover reduit la securite effective d'AES-128 a ~64 bits face a un ordinateur
> quantique. Le NIST recommande AES-256 minimum pour tout systeme post-quantum safe.
> ML-KEM-512 reste en AES-128 car c'est son niveau de securite declare (Cat.1), utile pour
> mesurer l'overhead a iso-niveau de securite classique.

---

## Trafic aleatoire continu (`--random`)

Chaque connexion ouvre une nouvelle session TLS : le **handshake PQC est exerce tout au long
du test**, pas uniquement a T=0.

```bash
# 5 minutes de trafic, puis ecriture CSV
./pqc_bench.sh --target 10.0.1.1 --mode mlkem768 --random --duration 300

# Infini - Ctrl+C pour arreter
./pqc_bench.sh --target 10.0.1.1 --mode hybrid --random
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

# Executer le preset 3 (identique sur les deux modes = comparaison valide)
./pqc_bench.sh --target 10.0.1.1 --mode classic  --preset 3
./pqc_bench.sh --target 10.0.1.1 --mode mlkem768 --preset 3
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
sudo ./pqc_bench.sh --server --mode mlkem768 --wan-profile eu
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
--mode <MODE>         Mode cryptographique (voir tableau ci-dessus)
--random              Trafic aleatoire continu staggere
--preset <N>          Preset predefini 1-5 (60s)
--profile <PROFILS>   Trafic libre en parallele : web,file,voip,stream,msg,all
--duration <sec>      Duree en secondes (--random: 0=infini | --profile: defaut 30)
--hs-count <N>        Iterations pour la mesure de handshake bulk (defaut: 100)
--output <FILE>       Fichier CSV de sortie
--wan-profile <p>     Profil latence WAN pour --server : fr | eu | us
--scan [SUBNET]       Scan reseau (defaut: sous-reseau local /24)
--install             Installe les dependances (sudo requis)
```

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

| Colonne | Description |
| --- | --- |
| `Horodatage` | Timestamp du test |
| `VM_IP` | IP de la VM cliente |
| `Serveur_IP` | IP du serveur WAN cible |
| `Mode` | Mode cryptographique teste |
| `Type_test` | Type de test (preset_1, preset_2...) |
| `Profil` | Profil de trafic de l'evenement (msg, web, file, voip, stream) |
| `Libelle` | Description lisible de l'evenement |
| `Suite_chiffrement` | Suite TLS negociee |
| `AES_bits` | Taille de cle AES (128 ou 256) |
| `Delai_planifie_s` | Heure de declenchement dans le preset (secondes) |
| `Duree_reelle_s` | Duree effective de l'evenement |
| `Handshake_ms` | Duree du handshake TLS pour cet evenement (ms) |
| `Debit_Mbps` | Debit mesure par iperf3 (Mbps) |
| `CPU_moy_pct` | CPU moyen de la VM pendant le test |
| `RAM_moy_Mo` | RAM utilisee pendant le test (Mo) |
| `Retransmissions_pct` | Taux de retransmissions TCP |
| `Taille_cle_octets` | Taille de la cle privee (octets) |
| `Taille_cert_octets` | Taille du certificat (octets) |

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
| `Nb_evenements` | Nombre d'evenements de trafic du test |

---

## Workflow de comparaison PQC vs Classique

```text
SERVEUR WAN                                        VMs CLIENTES
-----------                                        ------------
1. pqc_bench.sh --server --mode classic --wan-profile eu

2. server_cli.py
   pqc> scan 192.168.x.0/24
   pqc> set all --preset 2 --target 192.168.x.1
   #    [mode auto: classic]
   pqc> arm all
   pqc> launch              ------>   [test lance simultanement sur toutes les VMs]
   pqc> status              (attente fin du test, logs visibles en cas d'erreur)
   pqc> results             <------   [genere master_classic_1.csv]
   pqc> reset all

3. Ctrl+C sur le serveur, puis :
   pqc_bench.sh --server --mode mlkem768 --wan-profile eu
   pqc> set all --preset 2 --target 192.168.x.1
   #    [mode auto: mlkem768]
   pqc> arm all
   pqc> launch
   pqc> results             <------   [genere master_mlkem768_1.csv]
   pqc> reset all

# Repeter pour chaque mode : mlkem512, mlkem1024, hybrid, mldsa44, mldsa65, mldsa87

4. Generer le comparatif final
   pqc> compare             <------   [compare_[ts].csv avec tous les modes cote a cote]
```

---

## Metriques cles a analyser

| Metrique | Ce qu'elle revele |
| --- | --- |
| `Handshake_moy_ms` | Overhead direct de PQC vs classique a chaque connexion |
| `GLOBAL_ECART_TYPE Handshake_moy_ms` | Variabilite entre VMs (stabilite du test) |
| `Debit_moy_Mbps` | Degradation du debit sous charge crypto |
| `CPU_moy_pct` | Cout CPU (ML-DSA bien plus lourd que ML-KEM) |
| `Retransmissions_moy_pct` | Stabilite reseau sous charge |

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
| `compare` ne trouve aucun master CSV | Lancer `results` au moins une fois pour generer un `master_*.csv` |

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
