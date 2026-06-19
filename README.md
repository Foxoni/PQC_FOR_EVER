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

## Architecture des fichiers

```text
pqc_bench/
├── pqc_bench.sh          # Moteur de test - generation certificats, handshake, trafic
├── traffic_gen.py        # Module utilitaire (stats, monitoring CPU/RAM, CSV)
├── traffic_presets.py    # Generateur de trafic - presets + mode continu aleatoire
├── vm_agent.py           # Daemon de controle sur chaque VM de test (port 9998)
├── server_cli.py         # CLI central sur le serveur - orchestre toutes les VMs
└── results/              # Fichiers CSV produits (cree automatiquement)
```

### Role de chaque fichier

| Fichier | Role |
| --- | --- |
| `pqc_bench.sh` | Moteur d'execution : certificats, handshake TLS, orchestration trafic, ecriture CSV |
| `traffic_gen.py` | Stats (min/avg/max/p99), monitoring CPU/RAM psutil, parsing JSON iperf3, fusion CSV |
| `traffic_presets.py` | 5 presets PME predefinis + mode aleatoire continu, handshake TLS par connexion |
| `vm_agent.py` | Daemon TCP sur chaque VM cliente : recoit les ordres du serveur, lance pqc_bench.sh |
| `server_cli.py` | CLI interactif sur le serveur WAN : scan, configuration, lancement synchronise, collecte |

---

## Topologie reseau cible

```text
                    [ Internet / WAN ]
                           |
                        [ R2 ] <- Routeur
                           |
                      [ Pare-feu ]
                           |
             [ VM Serveur WAN ] <- --server + server_cli.py
                           |
                       [ ESW2 ] <- Switch central
                    /    |     \
              [ESW1]  [WiFi]  [ESW3]
             VLAN 10  VLAN 20  VLAN 30
          PC1 PC2 PC3  Laptop  Serveur
                        Mobile
         (vm_agent.py tourne sur chaque VM cliente)
```

- **VM Serveur WAN** : unique cible de toutes les VMs clientes, simule un serveur internet
  avec latence WAN artificielle via tc-netem. Heberge aussi `server_cli.py`.
- **VMs clientes** : PC1, PC2, PC3, Laptop, Mobile - executent `vm_agent.py` en attente
  d'ordres, puis lancent `pqc_bench.sh` sur commande du serveur.

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

## Deploiement sur la topologie

### 1. VM Serveur WAN

```bash
# Copier tous les scripts
scp pqc_bench.sh traffic_gen.py traffic_presets.py \
    vm_agent.py server_cli.py user@server_wan:/opt/pqc/

# Installer les dependances (une seule fois)
sudo /opt/pqc/pqc_bench.sh --install

# Lancer le serveur de trafic (doit tourner avant les clients)
sudo /opt/pqc/pqc_bench.sh --server --mode mlkem768 --wan-profile eu

# Dans un second terminal : lancer le CLI de controle
python3 /opt/pqc/server_cli.py --subnet 192.168.1.0/24
```

### 2. VMs clientes (repeter sur chaque VM)

```bash
scp pqc_bench.sh traffic_gen.py traffic_presets.py \
    vm_agent.py user@pc1:/opt/pqc/

sudo /opt/pqc/pqc_bench.sh --install

# Lancer le daemon de controle (reste en arriere-plan)
python3 /opt/pqc/vm_agent.py
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
| `set <ip\|all> --mode MODE [--preset N] [--wan-profile WAN] [--duration D]` | Configure une ou toutes les VMs (sans lancer) |
| `arm [all\|<ip>]` | Met les VMs configurees en standby (pretes a demarrer) |
| `launch` | Envoie START a toutes les VMs armed **simultanement** |
| `status [all\|<ip>]` | Poll l'etat actuel (idle / configured / armed / running / done) |
| `reset [all\|<ip>]` | Remet en idle, kill le test si en cours |
| `results [--output FILE]` | Collecte les CSV de toutes les VMs et compile un master CSV |
| `help` | Liste des commandes |
| `exit` / `quit` | Quitte le CLI |

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

# 2. Configurer toutes les VMs (pas de lancement immediat)
pqc> set all --mode mlkem768 --preset 2 --wan-profile eu

# 3. Ou configurer chaque VM individuellement avec un preset different
pqc> set 192.168.1.10 --mode mlkem768 --preset 1   # Secretariat
pqc> set 192.168.1.11 --mode mlkem768 --preset 3   # Manager
pqc> set 192.168.1.12 --mode mlkem768 --preset 5   # IT Technicien

# 4. Mettre toutes les VMs en standby
pqc> arm all

# 5. Lancement simultane (toutes partent en meme temps)
pqc> launch
  Signal envoye en 3 ms
  192.168.1.10: demarre (pid 1234)
  192.168.1.11: demarre (pid 1235)
  192.168.1.12: demarre (pid 1236)

# 6. Surveiller l'avancement
pqc> status
  192.168.1.10: running  ...
  192.168.1.11: done
  192.168.1.12: running  ...

# 7. Collecter et compiler les resultats
pqc> results --output resultats_mlkem768_eu.csv
  192.168.1.10: 1 ligne(s)
  192.168.1.11: 1 ligne(s)
  192.168.1.12: 1 ligne(s)
  Master CSV: resultats_mlkem768_eu.csv (3 lignes + 4 lignes de synthese)
```

### Format du master CSV (`results`)

La commande `results` collecte les CSV de toutes les VMs via la socket de controle,
sauvegarde un fichier individuel par VM dans `results/`, puis compile :

```text
vm_ip            mode      wan_profile  hs_avg_ms  throughput_mbps  ...
192.168.1.10     mlkem768  eu           14.2       312.5            ...
192.168.1.11     mlkem768  eu           13.8       298.1            ...
192.168.1.12     mlkem768  eu           15.1       321.4            ...
SUMMARY_AVG (n=3)  mlkem768  eu         14.4       310.7            ...
SUMMARY_MIN (n=3)  mlkem768  eu         13.8       298.1            ...
SUMMARY_MAX (n=3)  mlkem768  eu         15.1       321.4            ...
SUMMARY_STDDEV (n=3) mlkem768 eu        0.552      11.8             ...
```

Les lignes `SUMMARY_*` permettent de comparer directement les modes entre eux
(overhead moyen, variabilite inter-VM, meilleur/pire cas).

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

- Un pool de 10 instances iperf3 (ports 5201-5210, `--forking` pour multi-clients)
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

Les fichiers sont ecrits dans `results/` avec la convention de nommage :

```text
result_<mode>_p<preset>.csv     # mode preset (genere par vm_agent via pqc_bench.sh)
result_<mode>_r.csv             # mode aleatoire
results_<ip>.csv                # collecte individuelle par la commande results
results_master.csv              # master compile par la commande results (defaut)
```

| Colonne | Description |
| --- | --- |
| `vm_ip` | IP de la VM cliente (ajoute lors de la compilation master) |
| `mode` | Mode cryptographique teste |
| `wan_profile` | Profil de latence WAN utilise |
| `hs_min_ms` / `hs_avg_ms` / `hs_max_ms` / `hs_p99_ms` | Statistiques du handshake (ms) |
| `cpu_avg_pct` | Utilisation CPU moyenne pendant le test |
| `ram_avg_mb` | RAM utilisee pendant le test |
| `file_mbps` / `voip_mbps` / `stream_mbps` / `web_mbps` / `msg_mbps` | Debit par profil |
| `*_retrans_pct` | Taux de retransmissions TCP par profil |

---

## Workflow de comparaison PQC vs Classique

```text
SERVEUR WAN                              VMs CLIENTES
-----------                              ------------
1. pqc_bench.sh --server --mode classic
2. server_cli.py
   pqc> scan 192.168.x.0/24
   pqc> set all --mode classic --preset 2
   pqc> arm all
   pqc> launch              ------>      [test lance simultanement sur toutes les VMs]
   pqc> status              (attente fin du test)
   pqc> results             <------      [CSV collectes automatiquement]
   pqc> reset all

3. Relancer pqc_bench.sh --server --mode mlkem768
   pqc> set all --mode mlkem768 --preset 2
   pqc> arm all
   pqc> launch
   pqc> results --output results_mlkem768.csv

# Repeter pour chaque mode : mlkem512, mlkem1024, hybrid, mldsa44, mldsa65, mldsa87
# Les master CSV resultants contiennent SUMMARY_AVG/MIN/MAX/STDDEV pour comparaison directe
```

---

## Metriques cles a analyser

| Metrique | Ce qu'elle revele |
| --- | --- |
| `hs_avg_ms` | Overhead direct de PQC vs classique a chaque connexion |
| `SUMMARY_STDDEV hs_avg` | Variabilite entre VMs (stabilite du test) |
| `*_mbps` | Degradation du debit sous charge crypto par type de trafic |
| `cpu_avg_pct` | Cout CPU (ML-DSA bien plus lourd que ML-KEM) |
| `*_retrans_pct` | Stabilite reseau sous charge |

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
| `oqsprovider not found` | Relancer `sudo ./pqc_bench.sh --install` |
| `iperf3: connect failed` | Verifier que le serveur tourne et les ports 5201-5210 sont ouverts |
| `openssl s_client: handshake failure` | Le mode du client et du serveur doivent correspondre |
| `tc: command not found` | Installer `iproute2` ; sans tc la simulation WAN est desactivee |
| Resultats trop variables | Augmenter `--hs-count 200` et `--duration 120` |
| `date +%s%3N` ne fonctionne pas | Verifier GNU date (`apt install coreutils`) |
| Conflits de port iperf3 | Verifier qu'aucune autre instance ne tourne (`pkill iperf3`) |
| `scan` ne trouve aucun agent | Verifier que `python3 vm_agent.py` tourne sur les VMs et que le port 9998 est ouvert |
| VM bloquee en etat `armed` | Utiliser `reset <ip>` puis reconfigurer |
| `results` retourne "aucun fichier" | Le test n'est peut-etre pas termine (`status` pour verifier) |
| Lancement non simultane | Verifier la connectivite reseau ; un delai > 500ms indique un probleme |

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe - liboqs](https://github.com/open-quantum-safe/liboqs)
- [OQS Provider for OpenSSL 3](https://github.com/open-quantum-safe/oqs-provider)
