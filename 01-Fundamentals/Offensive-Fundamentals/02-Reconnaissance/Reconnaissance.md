# Chapitre : Reconnaissance

## Introduction

La reconnaissance, souvent appelée *recon* ou *footprinting*, est la première et l'une des phases les plus cruciales de tout test d'intrusion ou évaluation de sécurité offensive. Elle consiste à collecter un maximum d'informations sur une cible avant de lancer une attaque active. Une reconnaissance approfondie permet d'identifier les vulnérabilités potentielles, de comprendre l'infrastructure de la cible, de cartographier sa surface d'attaque et de planifier les étapes suivantes de manière plus efficace et furtive. Dans une perspective *Purple Team*, où les équipes offensives (Red Team) et défensives (Blue Team) collaborent, une reconnaissance bien documentée aide également la Blue Team à comprendre les vecteurs d'attaque potentiels et à améliorer ses capacités de détection et de réponse. Une bonne reconnaissance minimise le bruit généré lors des phases actives et maximise les chances de succès de l'engagement.

Ce chapitre explore les deux principales approches de la reconnaissance : passive et active. Nous détaillerons les méthodologies, les outils essentiels, les considérations opérationnelles (OPSEC) et la perspective de la Blue Team pour chaque approche, en fournissant des exemples concrets et des conseils pratiques pour les futurs professionnels de la sécurité offensive visant des certifications comme eJPT.



## Reconnaissance Passive

La reconnaissance passive consiste à collecter des informations sur une cible sans interagir directement avec ses systèmes. Cette approche ne laisse aucune trace détectable sur l'infrastructure de la cible, ce qui la rend particulièrement précieuse dans les premières phases d'un test d'intrusion ou d'une évaluation de sécurité. L'objectif est d'exploiter des sources d'information publiques et accessibles pour construire une image aussi complète que possible de la cible avant toute interaction directe.

### Méthodologie de la Reconnaissance Passive

Une méthodologie efficace de reconnaissance passive suit généralement ces étapes :

1. **Identification du périmètre** : Déterminer précisément ce qui constitue la cible (domaines, sous-domaines, plages d'adresses IP, etc.)
2. **Collecte d'informations organisationnelles** : Rechercher des informations sur l'organisation, sa structure, ses employés clés
3. **Découverte d'infrastructures techniques** : Identifier les serveurs, services, technologies utilisées
4. **Analyse des vulnérabilités potentielles** : Repérer les faiblesses possibles basées sur les informations recueillies
5. **Documentation et organisation des résultats** : Structurer les informations pour les phases suivantes

Cette approche méthodique permet d'optimiser la collecte d'informations tout en restant indétectable.

### Outils de Reconnaissance Passive par Catégorie

#### Analyse de Domaines et DNS

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **whois** | Interroger les bases de données d'enregistrement de domaines | `whois example.com` | Simple, rapide, informations de contact et dates | Données parfois masquées par la confidentialité | Première étape pour tout domaine |
| **RDAP** | Version moderne de whois avec format JSON | `curl https://rdap.org/domain/example.com` | Format structuré, plus complet que whois | Moins connu, nécessite parsing | Alternative moderne à whois |
| **dig** | Interrogation DNS avancée | `dig example.com ANY` | Très flexible, nombreuses options, sortie détaillée | Complexe pour débutants | Analyse DNS approfondie |
| **nslookup** | Interrogation DNS simple | `nslookup example.com` | Simple, disponible sur tous OS | Moins puissant que dig | Vérifications DNS rapides |
| **host** | Résolution DNS simplifiée | `host example.com` | Sortie concise et lisible | Fonctionnalités limitées | Vérifications DNS basiques |
| **dnsenum** | Énumération DNS complète | `dnsenum example.com` | Automatise plusieurs requêtes DNS | Peut être bruyant | Énumération DNS complète |
| **dnsrecon** | Reconnaissance DNS avancée | `dnsrecon -d example.com` | Nombreux modes, très complet | Complexe pour débutants | Tests DNS approfondis |

#### Certificats SSL/TLS et Transparence

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **crt.sh** | Recherche dans les logs de transparence des certificats | `curl "https://crt.sh/?q=example.com&output=json"` | Découverte de sous-domaines via certificats | Interface web parfois lente | Découverte de sous-domaines |
| **Censys** | Recherche de certificats et d'hôtes exposés | Interface web ou API | Base de données massive, recherche avancée | API limitée en version gratuite | Analyse d'exposition internet |
| **certspotter** | Surveillance des certificats | `curl -s "https://api.certspotter.com/v1/issuances?domain=example.com"` | API simple, alertes possibles | Limites d'API en version gratuite | Monitoring de certificats |

#### Moteurs de Recherche Spécialisés

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **Shodan** | Recherche d'appareils connectés à Internet | `shodan search hostname:example.com` | Base de données massive, filtres puissants | API payante pour usage avancé | Découverte d'équipements exposés |
| **Censys** | Recherche d'hôtes et services exposés | Interface web ou API | Données détaillées, recherche avancée | API limitée en version gratuite | Analyse d'exposition internet |
| **ZoomEye** | Moteur de recherche pour Internet des objets | Interface web ou API | Bonne couverture des appareils IoT | Moins connu, interface moins intuitive | Recherche d'appareils IoT |
| **BinaryEdge** | Intelligence sur l'exposition internet | Interface web ou API | Données historiques, scans réguliers | Majoritairement payant | Analyse d'exposition avancée |
| **FOFA** | Moteur de recherche de cybersécurité | Interface web ou API | Bonne couverture en Asie | Interface principalement en chinois | Recherche d'exposition globale |

#### Frameworks de Reconnaissance

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **SpiderFoot** | Framework d'OSINT automatisé | `spiderfoot -s example.com` | Interface web, nombreux modules, automatisation | Configuration complexe | Reconnaissance complète |
| **recon-ng** | Framework modulaire de reconnaissance | `recon-ng` puis `use recon/domains-hosts/google_site_web` | Structure modulaire, extensible | Courbe d'apprentissage | Reconnaissance méthodique |
| **theHarvester** | Collecte d'emails et sous-domaines | `theHarvester -d example.com -b all` | Simple, multiple sources | Résultats parfois limités | Collecte rapide d'informations |
| **OWASP Amass** | Cartographie d'attaque de surface | `amass enum -passive -d example.com` | Très complet, communauté active | Complexe, nombreuses options | Cartographie complète |
| **Maltego** | Visualisation de relations entre entités | Interface graphique | Visualisation puissante, nombreux transformers | Payant pour version complète | Analyse de relations complexes |

#### Recherche sur les Réseaux Sociaux et Employés

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **LinkedIn** | Recherche d'employés et structure | Recherche manuelle | Source primaire d'information RH | Nécessite compte, limites de recherche | Cartographie organisationnelle |
| **hunter.io** | Découverte d'emails professionnels | Interface web ou API | Patterns d'emails, vérification | Limites en version gratuite | Collecte d'emails ciblée |
| **phonebook.cz** | Recherche d'emails et numéros | Interface web | Simple, efficace | Couverture variable | Recherche rapide de contacts |
| **social-analyzer** | Analyse de présence sur réseaux sociaux | `social-analyzer --username "johndoe"` | Multi-plateformes, automatisé | Taux de faux positifs | Analyse de présence en ligne |

#### Recherche de Code et Fuites d'Information

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **GitHub Dorks** | Recherche de fuites dans le code | `"password" "example.com" filename:.env` | Très efficace pour trouver des secrets | Requiert connaissance des dorks | Découverte de secrets exposés |
| **GitLeaks** | Détection automatisée de secrets | `gitleaks detect --source=.` | Automatisé, règles personnalisables | Faux positifs possibles | Audit de code source |
| **TruffleHog** | Recherche de secrets dans repos | `trufflehog github --repo=https://github.com/org/repo` | Détection d'entropie, historique | Configuration complexe | Audit de dépôts Git |
| **Google Dorks** | Recherche avancée sur Google | `site:example.com filetype:pdf confidential` | Très puissant avec bons filtres | Limites de requêtes | Recherche de documents sensibles |

#### Géolocalisation et Réseaux Sans Fil

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **wigle.net** | Base de données de réseaux WiFi | Interface web | Cartographie mondiale, historique | Nécessite compte | Reconnaissance physique |
| **ShodanMaps** | Visualisation géographique des résultats Shodan | Interface web | Visualisation intuitive | Nécessite compte Shodan | Analyse géographique |
| **OpenCellID** | Base de données d'antennes cellulaires | API | Données mondiales, open source | Précision variable | Reconnaissance mobile |

### Exemples Réels de Reconnaissance Passive

Voici un exemple concret de reconnaissance passive sur une entreprise fictive "TechSecure Inc." :

```bash
# Étape 1: Analyse WHOIS pour obtenir des informations de base
whois techsecure.com

# Résultat (extrait)
# Domain Name: TECHSECURE.COM
# Registrar: GODADDY.COM, LLC
# Creation Date: 2010-05-15T18:33:25Z
# Admin Organization: TechSecure Inc.
# Admin Email: admin@techsecure.com
# Tech Email: it@techsecure.com

# Étape 2: Recherche de sous-domaines via certificats SSL
curl -s "https://crt.sh/?q=%.techsecure.com&output=json" | jq -r '.[].name_value' | sort -u

# Résultat
# admin.techsecure.com
# api.techsecure.com
# dev.techsecure.com
# mail.techsecure.com
# vpn.techsecure.com
# www.techsecure.com

# Étape 3: Analyse DNS pour chaque sous-domaine découvert
for subdomain in $(cat subdomains.txt); do
    dig $subdomain A +short
done

# Résultat
# admin.techsecure.com: 203.0.113.10
# api.techsecure.com: 203.0.113.11
# dev.techsecure.com: 198.51.100.25
# mail.techsecure.com: 203.0.113.15
# vpn.techsecure.com: 203.0.113.20
# www.techsecure.com: 203.0.113.5

# Étape 4: Recherche Shodan pour les services exposés
shodan search hostname:techsecure.com

# Résultat (extrait)
# IP: 203.0.113.5
# Hostnames: www.techsecure.com
# Services: HTTP/80, HTTPS/443
# Server: nginx/1.18.0
# IP: 203.0.113.20
# Hostnames: vpn.techsecure.com
# Services: HTTPS/443, OpenVPN/1194
# Product: Fortinet FortiGate
```

Cette séquence d'étapes permet de construire progressivement une image de l'infrastructure de la cible sans jamais interagir directement avec ses systèmes.

### Considérations OPSEC pour la Reconnaissance Passive

Bien que la reconnaissance passive soit par définition non intrusive, certaines précautions opérationnelles restent nécessaires :

La reconnaissance passive peut sembler totalement invisible, mais certaines plateformes comme Shodan ou les services d'API peuvent enregistrer vos requêtes et potentiellement les associer à votre identité ou adresse IP. Pour maintenir un niveau d'anonymat optimal lors d'engagements sensibles, il est recommandé d'utiliser des techniques de dissimulation comme l'utilisation de VPN, du réseau Tor, ou de proxies. La rotation régulière des adresses IP et l'utilisation de comptes différents pour les services nécessitant une authentification permettent également de réduire les risques d'association entre vos recherches et votre identité réelle.

Il est également important de considérer la cadence de vos requêtes. Même en reconnaissance passive, des requêtes trop nombreuses ou trop rapides vers certains services peuvent déclencher des alertes ou des limitations. Espacer vos requêtes et éviter les pics d'activité permet de rester sous les radars des systèmes de détection.

Enfin, la gestion des données collectées est un aspect crucial souvent négligé. Les informations obtenues lors de la reconnaissance peuvent être sensibles et doivent être stockées de manière sécurisée, idéalement chiffrées, et supprimées une fois l'engagement terminé, conformément aux accords contractuels et aux réglementations en vigueur.

### Perspective Blue Team sur la Reconnaissance Passive

Du point de vue défensif, comprendre comment les attaquants utilisent la reconnaissance passive est essentiel pour limiter l'exposition d'informations sensibles :

Les équipes de défense doivent régulièrement effectuer leur propre reconnaissance passive pour identifier les informations exposées publiquement sur leur organisation. Cette pratique, parfois appelée "Outside-In Testing", permet d'avoir une vision claire de ce qu'un attaquant potentiel pourrait découvrir sans interaction directe. Les résultats de ces analyses devraient alimenter une stratégie de réduction de la surface d'attaque informationnelle.

Plusieurs mesures peuvent être mises en place pour limiter l'exposition d'informations sensibles. L'utilisation de services de confidentialité WHOIS permet de masquer les coordonnées des contacts techniques et administratifs. La mise en œuvre d'une politique stricte de gestion des métadonnées des documents publiés en ligne évite la fuite d'informations via les propriétés des fichiers. La sensibilisation des employés aux risques liés au partage d'informations professionnelles sur les réseaux sociaux constitue également un axe de défense important.

La surveillance des logs de transparence des certificats (CT logs) permet de détecter rapidement l'émission de certificats non autorisés pour des sous-domaines de l'organisation, ce qui pourrait indiquer une tentative d'usurpation ou une fuite d'information. Des outils comme "cert-monitor" peuvent automatiser cette surveillance et alerter en cas d'anomalie.

Enfin, l'utilisation de services de surveillance du Dark Web peut aider à détecter précocement des fuites de données ou des discussions concernant l'organisation, permettant une réponse proactive avant qu'une attaque ne soit lancée.

## Reconnaissance Active

La reconnaissance active implique une interaction directe avec les systèmes de la cible pour obtenir des informations plus précises sur son infrastructure. Contrairement à la reconnaissance passive, cette approche peut être détectée par les systèmes de surveillance de la cible, mais elle fournit des données plus détaillées et actualisées sur les services, les versions logicielles et les vulnérabilités potentielles.

### Méthodologie de la Reconnaissance Active

Une approche méthodique de la reconnaissance active suit généralement ces étapes :

1. **Préparation et planification** : Définir les objectifs précis, les plages d'adresses IP autorisées et les contraintes temporelles
2. **Découverte d'hôtes** : Identifier les systèmes actifs dans les plages d'adresses IP ciblées
3. **Scan de ports** : Déterminer les ports ouverts et les services associés sur chaque hôte
4. **Identification de services** : Identifier précisément les services et leurs versions
5. **Énumération** : Collecter des informations détaillées sur chaque service identifié
6. **Découverte de vulnérabilités** : Analyser les versions des services pour identifier les vulnérabilités connues
7. **Documentation** : Organiser les résultats pour les phases suivantes du test d'intrusion

Cette approche progressive permet d'optimiser la collecte d'informations tout en minimisant le bruit généré sur le réseau cible.

### Outils de Reconnaissance Active par Catégorie

#### Découverte d'Hôtes et Scan de Ports

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **nmap** | Scanner de ports polyvalent | `nmap -sn 192.168.1.0/24` (découverte)<br>`nmap -sS -p- 192.168.1.10` (scan complet) | Très complet, nombreuses options, scripts NSE | Peut être lent pour de grandes plages | Outil de référence, polyvalent |
| **masscan** | Scanner de ports ultra-rapide | `masscan -p1-65535 192.168.1.0/24 --rate=10000` | Extrêmement rapide, peut scanner Internet entier | Moins précis que nmap, fonctionnalités limitées | Scan initial rapide de grandes plages |
| **rustscan** | Scanner de ports rapide | `rustscan -a 192.168.1.0/24 -- -sV` | Très rapide, intégration avec nmap | Moins mature que nmap | Scan rapide avec détection de version |
| **unicornscan** | Scanner asynchrone avancé | `unicornscan 192.168.1.10:1-65535` | Scan asynchrone efficace | Moins maintenu | Scan TCP/UDP efficace |
| **zmap** | Scanner réseau à grande échelle | `zmap -p 80 192.168.1.0/24` | Conçu pour scanner Internet entier | Limité en fonctionnalités | Scan à très grande échelle |
| **ping** | Vérification basique de disponibilité | `ping -c 1 192.168.1.10` | Disponible partout, simple | Souvent bloqué par les pare-feu | Test rapide de connectivité |
| **fping** | Ping multiple en parallèle | `fping -a -g 192.168.1.0/24` | Rapide pour de multiples hôtes | Moins d'options que nmap | Découverte rapide d'hôtes |
| **hping3** | Outil avancé de crafting de paquets | `hping3 -S -p 80 192.168.1.10` | Très flexible, permet des tests avancés | Complexe pour débutants | Tests de pare-feu, scan furtif |

#### Énumération DNS et Sous-domaines

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **amass** | Énumération de sous-domaines | `amass enum -d example.com` | Très complet, nombreuses sources | Complexe, peut être bruyant | Cartographie complète de domaine |
| **subfinder** | Découverte passive de sous-domaines | `subfinder -d example.com` | Rapide, nombreuses sources | Moins complet qu'amass | Découverte initiale de sous-domaines |
| **dnsenum** | Énumération DNS complète | `dnsenum example.com` | Automatise plusieurs requêtes DNS | Peut être bruyant | Énumération DNS complète |
| **fierce** | Scan DNS ciblé | `fierce --domain example.com` | Simple, efficace | Fonctionnalités limitées | Reconnaissance DNS rapide |
| **dnsrecon** | Reconnaissance DNS avancée | `dnsrecon -d example.com -t std` | Nombreux modes, très complet | Complexe pour débutants | Tests DNS approfondis |
| **sublist3r** | Énumération de sous-domaines | `sublist3r -d example.com` | Interface simple, multiples sources | Moins maintenu récemment | Découverte rapide de sous-domaines |

#### Vérification d'Hôtes Web et Virtual Hosts

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **httprobe** | Vérification de services HTTP/HTTPS | `cat domains.txt \| httprobe` | Rapide, simple | Fonctionnalités limitées | Validation rapide de domaines web |
| **httpx** | Sonde HTTP avancée | `httpx -l domains.txt -title -tech-detect` | Détection de technologies, rapide | Configuration complexe | Analyse détaillée de serveurs web |
| **EyeWitness** | Capture d'écran de sites web | `eyewitness --web -f urls.txt` | Captures d'écran, rapport HTML | Dépendances nombreuses | Reconnaissance visuelle de sites |
| **vhost-brute** | Découverte de virtual hosts | `vhost-brute -t example.com -w wordlist.txt` | Ciblé sur les vhosts | Moins maintenu | Découverte de virtual hosts |
| **virtual-host-discovery** | Découverte de virtual hosts | `ruby scan.rb --ip=192.168.1.10 --host=example.com` | Simple, efficace | Script basique | Test rapide de virtual hosts |
| **gobuster vhost** | Mode vhost de gobuster | `gobuster vhost -u example.com -w wordlist.txt` | Intégré à gobuster | Moins d'options spécifiques | Découverte de virtual hosts |

#### Fuzzing et Discovery de Contenu Web

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **gobuster** | Discovery de répertoires et fichiers | `gobuster dir -u http://example.com -w wordlist.txt` | Rapide, modes multiples | Moins d'options que ffuf | Discovery web rapide |
| **ffuf** | Fuzzer web polyvalent | `ffuf -u http://example.com/FUZZ -w wordlist.txt` | Très flexible, filtrage avancé | Complexe pour débutants | Fuzzing web avancé |
| **dirsearch** | Discovery de contenu web | `dirsearch -u http://example.com` | Simple, wordlists intégrées | Moins flexible que ffuf | Discovery web simple |
| **wfuzz** | Fuzzer web avancé | `wfuzz -c -z file,wordlist.txt http://example.com/FUZZ` | Très flexible, nombreux payloads | Syntaxe complexe | Fuzzing web avancé |
| **feroxbuster** | Scanner récursif de contenu web | `feroxbuster -u http://example.com` | Très rapide, récursif | Relativement nouveau | Discovery web rapide et récursif |
| **dirb** | Discovery de contenu web | `dirb http://example.com` | Simple, wordlists intégrées | Moins rapide que les alternatives | Discovery web basique |

#### Analyse de Services et Versions

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **nmap NSE** | Scripts d'énumération de services | `nmap -sV -sC 192.168.1.10` | Bibliothèque de scripts riche | Peut être détecté facilement | Énumération détaillée de services |
| **enum4linux** | Énumération Windows/Samba | `enum4linux -a 192.168.1.10` | Automatise plusieurs tests | Spécifique à SMB/Samba | Énumération de partages et utilisateurs |
| **smbclient** | Client SMB/CIFS | `smbclient -L //192.168.1.10` | Interaction directe avec SMB | Interface moins intuitive | Test de partages SMB |
| **snmpwalk** | Énumération SNMP | `snmpwalk -v 2c -c public 192.168.1.10` | Exploration complète de MIB | Nécessite connaissance SNMP | Énumération de systèmes via SNMP |
| **ldapsearch** | Interrogation LDAP | `ldapsearch -x -h 192.168.1.10 -b "dc=example,dc=com"` | Flexible, nombreuses options | Complexe pour débutants | Énumération d'annuaires LDAP |
| **smtp-user-enum** | Énumération d'utilisateurs SMTP | `smtp-user-enum -M VRFY -U users.txt -t 192.168.1.10` | Ciblé sur SMTP | Souvent bloqué sur serveurs modernes | Découverte d'utilisateurs via SMTP |

#### Scanners de Vulnérabilités

| Outil | But | Commande(s) Minimale(s) | Points Forts | Limites | Contexte d'Usage |
|-------|-----|-------------------------|-------------|---------|-----------------|
| **Nikto** | Scanner de vulnérabilités web | `nikto -h http://example.com` | Simple, détection de nombreuses vulnérabilités | Bruyant, facilement détectable | Scan initial de serveurs web |
| **OpenVAS** | Scanner de vulnérabilités complet | Interface web | Très complet, base de données à jour | Complexe à configurer | Scan complet d'infrastructure |
| **Nuclei** | Scanner basé sur templates | `nuclei -u http://example.com -t nuclei-templates/` | Rapide, extensible, communauté active | Nécessite des templates | Détection ciblée de vulnérabilités |
| **WPScan** | Scanner pour WordPress | `wpscan --url http://example.com` | Spécialisé WordPress, très complet | Limité à WordPress | Audit de sites WordPress |
| **sqlmap** | Scanner d'injections SQL | `sqlmap -u "http://example.com/?id=1"` | Détection et exploitation automatisées | Très bruyant, intrusif | Test d'injections SQL |
| **Nessus** | Scanner de vulnérabilités commercial | Interface web | Très complet, support professionnel | Payant pour usage commercial | Scan complet d'infrastructure |

### Exemples Annotés de Reconnaissance Active

Voici un workflow pas-à-pas pour une reconnaissance active méthodique sur un réseau cible fictif (192.168.1.0/24) :

```bash
# Étape 1: Découverte d'hôtes avec ping sweep (discret)
# Cette commande effectue un simple ping sur chaque adresse du réseau
# OPSEC: Utilise ICMP standard, généralement peu alertant mais visible
sudo nmap -sn 192.168.1.0/24 -oG sweep.txt
grep "Up" sweep.txt | cut -d " " -f 2 > live_hosts.txt

# Résultat: Liste d'hôtes actifs
# 192.168.1.1
# 192.168.1.10
# 192.168.1.20
# 192.168.1.50

# Étape 2: Scan de ports initial sur les hôtes découverts (top 1000 ports)
# OPSEC: Scan SYN (-sS) plus discret qu'un scan connect (-sT)
# Timing T2 (-T2) pour rester relativement discret
sudo nmap -sS -T2 -iL live_hosts.txt -oA initial_scan

# Résultat (extrait pour 192.168.1.10):
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 80/tcp   open  http
# 443/tcp  open  https
# 3306/tcp open  mysql

# Étape 3: Scan approfondi avec détection de version sur les ports ouverts
# OPSEC: Ciblé uniquement sur les ports déjà identifiés comme ouverts
# --script=banner pour limiter aux scripts de base d'identification
sudo nmap -sV --script=banner -p22,80,443,3306 192.168.1.10 -oA detailed_scan

# Résultat:
# PORT     STATE SERVICE  VERSION
# 22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
# 80/tcp   open  http     Apache httpd 2.4.41
# 443/tcp  open  ssl/http Apache httpd 2.4.41
# 3306/tcp open  mysql    MySQL 8.0.28-0ubuntu0.20.04.3

# Étape 4: Énumération DNS si un serveur web est détecté
# Recherche de sous-domaines et d'informations DNS
dnsrecon -d example.com -t std

# Résultat:
# [*] Performing General Enumeration of Domain: example.com
# [-] DNSSEC is not configured for example.com
# [*] 	 SOA ns1.example.com 192.168.1.10
# [*] 	 NS ns1.example.com 192.168.1.10
# [*] 	 NS ns2.example.com 192.168.1.11
# [*] 	 MX mail.example.com 192.168.1.20
# [*] 	 A example.com 192.168.1.10

# Étape 5: Discovery de contenu web sur le serveur HTTP découvert
# OPSEC: Utilisation de -t 50 pour limiter les threads et rester discret
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50 -o web_dirs.txt

# Résultat:
# /admin (Status: 301) [Size: 0] [--> /admin/]
# /css (Status: 301) [Size: 0] [--> /css/]
# /images (Status: 301) [Size: 0] [--> /images/]
# /js (Status: 301) [Size: 0] [--> /js/]
# /login.php (Status: 200) [Size: 1024]
# /logout.php (Status: 302) [Size: 0] [--> /login.php]

# Étape 6: Vérification de virtual hosts potentiels
# OPSEC: Utilisation d'un petit wordlist pour limiter le bruit
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1000-5000.txt -t 50 -o vhosts.txt

# Résultat:
# Found: admin.example.com (Status: 200) [Size: 1234]
# Found: dev.example.com (Status: 200) [Size: 5678]
# Found: api.example.com (Status: 403) [Size: 213]

# Étape 7: Scan de vulnérabilités ciblé avec Nuclei
# OPSEC: Utilisation de templates spécifiques plutôt qu'un scan complet
nuclei -u http://192.168.1.10 -t nuclei-templates/cves/ -o vulnerabilities.txt

# Résultat:
# [2023-05-28 10:15:26] [CVE-2021-41773] [critical] [http] [http://192.168.1.10/cgi-bin/]
# [2023-05-28 10:15:45] [CVE-2022-22965] [critical] [http] [http://192.168.1.10/login.php]
```

Ce workflow illustre une approche progressive, en commençant par des techniques moins intrusives et en augmentant progressivement la profondeur de l'analyse en fonction des résultats obtenus.

### Considérations OPSEC pour la Reconnaissance Active

La reconnaissance active présente des risques significatifs de détection, nécessitant une attention particulière aux aspects opérationnels de sécurité :

Le timing est l'un des facteurs les plus critiques en reconnaissance active. Des scans trop rapides ou trop agressifs déclenchent facilement les systèmes de détection d'intrusion (IDS/IPS). L'utilisation de paramètres de temporisation comme `-T2` dans nmap ou la limitation du nombre de threads dans les outils de fuzzing permet de réduire la signature de vos activités. Pour les cibles particulièrement sensibles, l'étalement des scans sur plusieurs heures ou jours peut être nécessaire pour rester sous les seuils de détection.

L'utilisation de techniques de dissimulation comme les "decoys" (leurres) peut aider à masquer l'origine réelle des scans. Nmap offre l'option `-D` qui permet de générer du trafic semblant provenir de multiples sources, rendant l'identification de la véritable source plus difficile. Par exemple : `nmap -sS -D 10.0.0.1,10.0.0.2,ME 192.168.1.10` génère du trafic semblant provenir de plusieurs adresses IP en plus de la vôtre.

```bash
# Exemple de scan avec decoys et timing lent
sudo nmap -sS -D 203.0.113.1,203.0.113.2,ME -T2 --data-length 24 192.168.1.10
```

La fragmentation des paquets (`-f` dans nmap) peut également aider à contourner certains systèmes de détection en divisant les paquets TCP en fragments plus petits, compliquant leur analyse par les systèmes de sécurité.

Pour les environnements hautement sécurisés, l'utilisation de proxies ou de rebonds peut être nécessaire pour masquer complètement l'origine des scans. Nmap supporte l'utilisation de proxies avec l'option `--proxies`, permettant de faire transiter les scans via un ou plusieurs serveurs intermédiaires.

Enfin, la limitation de la portée des scans est essentielle. Plutôt que de scanner tous les ports ou d'utiliser des scripts agressifs, ciblez uniquement ce qui est nécessaire pour votre évaluation. Cette approche minimise non seulement les risques de détection mais aussi les perturbations potentielles sur les systèmes cibles.

### Perspective Blue Team sur la Reconnaissance Active

Du point de vue défensif, la reconnaissance active laisse des traces qui peuvent être détectées et analysées :

Les équipes de défense peuvent détecter la reconnaissance active à travers plusieurs indicateurs. Les pics soudains de trafic ICMP, les tentatives de connexion TCP sur de multiples ports en séquence, ou les requêtes HTTP inhabituelles vers des ressources non existantes sont autant de signaux d'alerte. Les systèmes IDS comme Snort ou Suricata disposent de signatures spécifiques pour détecter les outils de scan courants comme nmap.

Voici quelques exemples de signatures IDS typiques qui détectent les activités de reconnaissance :

```
# Signature Snort pour détecter un scan nmap SYN
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN nmap SYN"; flow:stateless; flags:S,12; seq:0; ack:0; window:1024; threshold:type threshold, track by_src, count 20, seconds 60; reference:arachnids,28; classtype:attempted-recon; sid:1000001; rev:5;)

# Signature pour détecter un scan de ports séquentiel
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN sequential port scan"; flow:stateless; threshold:type threshold, track by_src, count 5, seconds 7; detection_filter:track by_src, count 30, seconds 60; classtype:attempted-recon; sid:1000002; rev:3;)

# Signature pour détecter gobuster/dirsearch
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB-ATTACK Directory Bruteforce Tool Activity"; flow:to_server,established; content:"User-Agent|3A| gobuster"; http_header; threshold:type threshold, track by_src, count 20, seconds 10; classtype:web-application-attack; sid:1000003; rev:1;)
```

Pour contrer efficacement la reconnaissance active, les équipes de défense peuvent mettre en place plusieurs mesures. La configuration de pare-feu pour limiter les réponses ICMP et filtrer les ports non utilisés réduit l'information disponible pour les scanners. L'implémentation de règles de rate-limiting sur les équipements réseau peut ralentir ou bloquer les tentatives de scan intensif.

Les honeypots et les systèmes de deception technology représentent une approche proactive. En déployant des systèmes leurres qui semblent vulnérables, les défenseurs peuvent détecter les activités de reconnaissance précocement tout en recueillant des informations sur les techniques utilisées par les attaquants.

La corrélation d'événements entre différentes sources de logs (pare-feu, IDS, serveurs web) permet d'identifier des patterns de reconnaissance qui pourraient passer inaperçus lorsqu'analysés isolément. Des outils comme Wazuh ou ELK Stack facilitent cette corrélation et peuvent générer des alertes basées sur des comportements suspects plutôt que sur des signatures statiques.

Enfin, la réalisation régulière d'exercices de Red Team permet aux équipes de défense de tester et d'améliorer leurs capacités de détection face à des techniques de reconnaissance réelles et évolutives.

## ⚡ Quick Ops (opérationnel < 1 h)

Cette section fournit des ressources opérationnelles pour une reconnaissance rapide et efficace, idéale pour les situations où le temps est limité ou pour les premières étapes d'un engagement.

### Tableau « Commandes Essentielles »

| Objectif | Commande | Description |
|----------|----------|-------------|
| Découverte d'hôtes | `sudo nmap -sn 192.168.1.0/24 -oG sweep.txt` | Ping sweep rapide pour identifier les hôtes actifs |
| Scan de ports rapide | `sudo nmap -sS -T4 --top-ports 1000 192.168.1.10 -oA quick_scan` | Scan des 1000 ports les plus courants |
| Détection de versions | `sudo nmap -sV -sC -p22,80,443 192.168.1.10` | Identification précise des services sur les ports spécifiés |
| Énumération DNS | `dig axfr @ns1.example.com example.com` | Tentative de transfert de zone DNS |
| Découverte de sous-domaines | `subfinder -d example.com -o subdomains.txt` | Découverte rapide de sous-domaines |
| Vérification de sites web | `httpx -l subdomains.txt -title -tech-detect -status-code` | Analyse rapide des serveurs web découverts |
| Discovery web | `ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -c` | Découverte de répertoires et fichiers courants |
| Scan de vulnérabilités web | `nuclei -l urls.txt -t nuclei-templates/cves/ -o vulns.txt` | Détection rapide de vulnérabilités connues |

### Check-list "Départ mission"

Avant de commencer toute opération de reconnaissance, assurez-vous de suivre ces étapes préliminaires essentielles :

1. **Préparation de l'environnement**
   - [ ] Vérifier la connexion VPN et confirmer l'adresse IP externe
   - [ ] Créer un répertoire dédié pour la mission avec sous-dossiers (passive, active, evidence)
   - [ ] Préparer les outils nécessaires et vérifier leurs versions
   - [ ] Configurer la journalisation locale pour toutes les actions (`script` ou `tee`)

2. **Cadrage initial**
   - [ ] Définir clairement le périmètre autorisé (domaines, IPs, exclusions)
   - [ ] Noter les contraintes temporelles et les plages horaires autorisées
   - [ ] Identifier les points de contact en cas d'incident
   - [ ] Vérifier les autorisations spécifiques (scan actif, fuzzing, etc.)

3. **Premières actions**
   - [ ] Effectuer un scan nmap initial des top 1000 ports sur les cibles
   - [ ] Lancer l'énumération DNS basique (sous-domaines, enregistrements)
   - [ ] Créer un log initial des services découverts
   - [ ] Établir une cartographie préliminaire de l'infrastructure

4. **Documentation en temps réel**
   - [ ] Maintenir un journal chronologique des actions effectuées
   - [ ] Capturer les preuves (screenshots, output de commandes)
   - [ ] Noter les observations inhabituelles pour investigation ultérieure
   - [ ] Mettre à jour la cartographie au fur et à mesure des découvertes

### Scénario Express 30 min : Cartographier 192.168.56.0/24 + Identifier Version Apache

Voici un plan d'action pas-à-pas pour accomplir rapidement cette mission :

**Minute 0-5 : Préparation et découverte d'hôtes**
```bash
# Créer le répertoire de travail et démarrer la journalisation
mkdir -p ~/mission_express/$(date +%F)
cd ~/mission_express/$(date +%F)
script -a reconnaissance.log

# Découverte rapide des hôtes actifs
sudo nmap -sn 192.168.56.0/24 -oG sweep.txt
grep "Up" sweep.txt | cut -d " " -f 2 > hosts_up.txt
echo "[+] Hôtes découverts : $(wc -l < hosts_up.txt)"
```

**Minute 5-15 : Scan de ports sur les hôtes découverts**
```bash
# Scan rapide des ports courants
sudo nmap -sS -T4 --top-ports 1000 -iL hosts_up.txt -oA nmap_top1000

# Identifier les serveurs web potentiels
grep -l "80/tcp" nmap_top1000.gnmap | cut -d " " -f 2 > web_servers.txt
echo "[+] Serveurs web potentiels : $(wc -l < web_servers.txt)"
```

**Minute 15-20 : Détection de version des serveurs web**
```bash
# Scan ciblé pour identifier les versions d'Apache
sudo nmap -sV -p80,443 -iL web_servers.txt --script=http-server-header -oA web_versions

# Extraire les versions Apache
grep -i apache web_versions.nmap > apache_servers.txt
echo "[+] Serveurs Apache identifiés :"
cat apache_servers.txt
```

**Minute 20-25 : Vérification et confirmation des versions**
```bash
# Vérification manuelle des en-têtes HTTP pour confirmation
for ip in $(cat web_servers.txt); do
    echo -e "\n[+] Vérification de $ip :"
    curl -s -I "http://$ip" | grep -i server
done > http_headers.txt

# Tentative d'identification plus précise via des pages spécifiques
for ip in $(cat web_servers.txt); do
    echo -e "\n[+] Pages d'erreur de $ip :"
    curl -s "http://$ip/nonexistentpage" | grep -i apache
done > error_pages.txt
```

**Minute 25-30 : Synthèse et documentation**
```bash
# Générer un rapport synthétique
echo -e "\n=== RAPPORT DE RECONNAISSANCE EXPRESS ===" > rapport.txt
echo -e "\nDate: $(date)" >> rapport.txt
echo -e "\nHôtes actifs découverts: $(wc -l < hosts_up.txt)" >> rapport.txt
echo -e "\nServeurs web identifiés: $(wc -l < web_servers.txt)" >> rapport.txt
echo -e "\nVersions Apache détectées:" >> rapport.txt
grep -i apache web_versions.nmap | sort -u >> rapport.txt

# Créer une visualisation simple de la topologie
echo "digraph network {" > network.dot
echo "  rankdir=LR;" >> network.dot
echo "  node [shape=box];" >> network.dot
for ip in $(cat hosts_up.txt); do
    if grep -q $ip web_servers.txt; then
        version=$(grep $ip apache_servers.txt | grep -o "Apache[^,]*" | head -1)
        if [ -z "$version" ]; then version="Web Server"; fi
        echo "  \"$ip\" [label=\"$ip\\n$version\"];" >> network.dot
    else
        echo "  \"$ip\" [label=\"$ip\"];" >> network.dot
    fi
done
echo "}" >> network.dot

# Terminer la session de journalisation
echo "[+] Mission terminée. Résultats dans rapport.txt"
exit
```

Ce scénario express permet de cartographier rapidement un réseau et d'identifier les versions d'Apache en 30 minutes, avec une approche méthodique et des résultats documentés.

## Mini-lab Guidé : Mapping Réseau + OSINT sur Juice Shop (45 min)

Ce mini-lab vous permettra de mettre en pratique les techniques de reconnaissance passive et active sur OWASP Juice Shop, une application web délibérément vulnérable conçue pour l'apprentissage de la sécurité.

### Objectifs du Lab

- Déployer l'environnement Juice Shop localement
- Effectuer une reconnaissance passive pour collecter des informations sur le projet
- Réaliser une cartographie réseau et une découverte de services
- Identifier les technologies utilisées et les vulnérabilités potentielles

### Prérequis

- Docker installé sur votre machine
- Outils de base : nmap, ffuf, whatweb, et un navigateur web
- Connexion internet pour la partie OSINT

### Étape 1 : Déploiement de l'environnement (5 min)

Commençons par déployer Juice Shop dans un conteneur Docker :

```bash
# Créer un répertoire pour le lab
mkdir -p ~/juiceshop_lab && cd ~/juiceshop_lab

# Démarrer Juice Shop dans un conteneur Docker
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Vérifier que le conteneur est en cours d'exécution
docker ps | grep juice-shop

# Noter l'adresse IP locale pour la suite
echo "Juice Shop est accessible à l'adresse : http://localhost:3000"
```

### Étape 2 : Reconnaissance Passive - OSINT (15 min)

Avant d'interagir avec l'application, effectuons une reconnaissance passive pour collecter des informations sur le projet :

```bash
# Créer un sous-répertoire pour les résultats OSINT
mkdir -p osint && cd osint

# Rechercher des informations sur le dépôt GitHub
echo "Analyse du dépôt GitHub de Juice Shop..." > github_info.txt
curl -s "https://api.github.com/repos/bkimminich/juice-shop" | jq '{name, description, language, forks_count, stargazers_count, open_issues_count, created_at, updated_at, homepage}' >> github_info.txt

# Extraire les contributeurs principaux
echo -e "\nContributeurs principaux :" >> github_info.txt
curl -s "https://api.github.com/repos/bkimminich/juice-shop/contributors?per_page=5" | jq -r '.[] | "- " + .login + " (contributions: " + (.contributions|tostring) + ")"' >> github_info.txt

# Rechercher les problèmes de sécurité récents
echo -e "\nProblèmes de sécurité récents :" >> github_info.txt
curl -s "https://api.github.com/repos/bkimminich/juice-shop/issues?state=all&labels=security" | jq -r '.[] | "- " + .title + " (#" + (.number|tostring) + ")"' | head -5 >> github_info.txt

# Extraire les dépendances du projet (potentielles vulnérabilités)
echo -e "\nAnalyse des dépendances..." > dependencies.txt
curl -s "https://raw.githubusercontent.com/bkimminich/juice-shop/master/package.json" | jq '.dependencies' >> dependencies.txt

# Rechercher des mentions dans les bases de vulnérabilités
echo "Recherche dans les bases de vulnérabilités..." > vulns_mentions.txt
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=juice%20shop&resultsPerPage=5" | jq -r '.vulnerabilities[] | .cve.id + " - " + .cve.descriptions[0].value' >> vulns_mentions.txt 2>/dev/null || echo "Aucune CVE spécifique trouvée" >> vulns_mentions.txt

echo "[+] Reconnaissance OSINT terminée. Résultats dans le dossier osint/"
cd ..
```

### Étape 3 : Cartographie Réseau et Découverte de Services (10 min)

Maintenant, passons à la reconnaissance active pour cartographier l'application :

```bash
# Créer un sous-répertoire pour les résultats de scan
mkdir -p scans && cd scans

# Scanner les ports ouverts sur l'hôte local où tourne Juice Shop
echo "Scan des ports sur localhost..." > nmap_scan.txt
sudo nmap -sS -p3000-3010 localhost -oN nmap_scan.txt

# Analyse détaillée du service sur le port 3000
echo -e "\nAnalyse détaillée du service Juice Shop..." >> nmap_scan.txt
sudo nmap -sV -p3000 --script=banner,http-headers,http-title localhost -oN nmap_service_details.txt

# Détecter les technologies web utilisées
echo "Détection des technologies web..." > tech_detection.txt
whatweb -a 3 http://localhost:3000 > tech_detection.txt 2>/dev/null

echo "[+] Cartographie réseau terminée. Résultats dans le dossier scans/"
cd ..
```

### Étape 4 : Découverte de Contenu Web (10 min)

Explorons la structure de l'application web pour identifier les points d'intérêt :

```bash
# Créer un sous-répertoire pour les résultats de discovery
mkdir -p web_discovery && cd web_discovery

# Créer une wordlist personnalisée basée sur le contexte (e-commerce, jus)
echo "Création d'une wordlist contextuelle..." > wordlist.txt
cat << EOF >> wordlist.txt
admin
login
register
products
basket
cart
checkout
profile
about
contact
faq
terms
api
rest
graphql
users
customer
juice
fruits
vegetables
organic
payment
order
tracking
EOF

# Découverte de répertoires et fichiers
echo "Discovery de contenu web..." > ffuf_results.txt
ffuf -u http://localhost:3000/FUZZ -w wordlist.txt -c -v >> ffuf_results.txt

# Découverte d'API endpoints
echo -e "\nDiscovery d'endpoints API..." >> ffuf_results.txt
ffuf -u http://localhost:3000/api/FUZZ -w wordlist.txt -c -v >> ffuf_results.txt

echo "[+] Discovery web terminée. Résultats dans le dossier web_discovery/"
cd ..
```

### Étape 5 : Analyse et Synthèse (5 min)

Finalisons le lab en analysant et synthétisant nos découvertes :

```bash
# Créer un rapport de synthèse
echo "=== RAPPORT DE RECONNAISSANCE SUR JUICE SHOP ===" > rapport_final.txt
echo "Date: $(date)" >> rapport_final.txt

# Synthèse OSINT
echo -e "\n== SYNTHÈSE OSINT ==" >> rapport_final.txt
echo "Projet: $(grep name osint/github_info.txt | cut -d'"' -f4)" >> rapport_final.txt
echo "Description: $(grep description osint/github_info.txt | cut -d'"' -f4)" >> rapport_final.txt
echo "Langage principal: $(grep language osint/github_info.txt | cut -d'"' -f4)" >> rapport_final.txt
echo "Frameworks principaux: $(grep -E '(angular|express|node)' osint/dependencies.txt | cut -d'"' -f2 | tr '\n' ', ')" >> rapport_final.txt

# Synthèse cartographie
echo -e "\n== SYNTHÈSE CARTOGRAPHIE ==" >> rapport_final.txt
echo "Service principal: Port 3000 - $(grep "3000/tcp" scans/nmap_scan.txt | awk '{print $3}')" >> rapport_final.txt
echo "Technologies détectées: $(grep -E '(JavaScript|Framework|jQuery|Bootstrap)' scans/tech_detection.txt | tr '\n' ', ')" >> rapport_final.txt

# Points d'intérêt découverts
echo -e "\n== POINTS D'INTÉRÊT DÉCOUVERTS ==" >> rapport_final.txt
grep -E "200|301|302" web_discovery/ffuf_results.txt | awk '{print "- " $1 " " $2}' >> rapport_final.txt

# Vulnérabilités potentielles
echo -e "\n== VULNÉRABILITÉS POTENTIELLES ==" >> rapport_final.txt
echo "- Basé sur l'OSINT, les vulnérabilités suivantes pourraient être présentes:" >> rapport_final.txt
grep -v "Aucune CVE" osint/vulns_mentions.txt >> rapport_final.txt 2>/dev/null || echo "  Aucune CVE spécifique identifiée" >> rapport_final.txt
echo "- Dépendances potentiellement vulnérables à vérifier:" >> rapport_final.txt
grep -E '(jquery|bootstrap|angular)' osint/dependencies.txt | cut -d'"' -f2,4 | tr '"' ' ' >> rapport_final.txt

echo "[+] Lab terminé! Rapport final disponible dans rapport_final.txt"
```

### Conclusion et Analyse

À la fin de ce mini-lab, vous devriez avoir :

1. **Une vision globale du projet** obtenue par OSINT (GitHub, dépendances, historique)
2. **Une cartographie technique** de l'application (port, service, technologies)
3. **Une structure de l'application** découverte par fuzzing et exploration
4. **Des pistes de vulnérabilités potentielles** basées sur les informations collectées

Ce processus illustre comment la combinaison de techniques de reconnaissance passive et active permet de construire une compréhension approfondie d'une cible avant de commencer les tests d'intrusion proprement dits. Les informations collectées orienteront les phases suivantes de l'évaluation de sécurité.

### Bonus (si temps restant)

Si vous avez terminé avant les 45 minutes, essayez ces activités supplémentaires :

- Explorez l'interface utilisateur de Juice Shop pour identifier manuellement des fonctionnalités intéressantes
- Utilisez Nuclei avec des templates basiques pour détecter automatiquement des vulnérabilités
- Analysez le code JavaScript côté client pour identifier des endpoints API supplémentaires

## Pièges Classiques

Même les professionnels expérimentés peuvent tomber dans certains pièges lors de la phase de reconnaissance. Voici cinq erreurs courantes et leurs contremesures pour améliorer l'efficacité et la discrétion de vos opérations.

### 1. Négliger la Reconnaissance Passive

**Erreur** : Se précipiter dans la reconnaissance active sans exploiter pleinement les sources d'information passives.

**Impact** : Exposition prématurée de vos intentions, déclenchement d'alertes, et perte d'opportunités d'obtenir des informations précieuses sans risque.

**Contremesures** :
- Établir une checklist exhaustive de sources passives à consulter avant toute action active
- Automatiser la collecte passive avec des frameworks comme SpiderFoot ou Recon-ng
- Documenter systématiquement les informations obtenues passivement pour identifier les lacunes
- Planifier une phase de reconnaissance passive d'au moins 30-40% du temps total alloué à la reconnaissance

**Exemple concret** : Un testeur d'intrusion lance immédiatement un scan nmap agressif sur une entreprise, déclenchant des alertes, alors qu'une simple recherche OSINT aurait révélé un document public détaillant l'infrastructure réseau et les technologies utilisées.

### 2. Scan Trop Agressif ou Mal Configuré

**Erreur** : Utiliser des paramètres de scan par défaut ou trop agressifs sans considération pour la cible.

**Impact** : Détection immédiate par les systèmes de sécurité, blocage potentiel de votre adresse IP, perturbation des services de la cible.

**Contremesures** :
- Adapter les paramètres de timing (`-T0` à `-T2` dans nmap pour les cibles sensibles)
- Utiliser des techniques d'évasion comme la fragmentation de paquets (`-f`) ou les leurres (`-D`)
- Répartir les scans sur une période plus longue pour éviter les pics de trafic
- Tester vos techniques de scan contre vos propres systèmes de détection pour évaluer leur discrétion

**Exemple concret** : Un scan masscan configuré avec `--rate=100000` sur un réseau d'entreprise provoque une surcharge du pare-feu et une interruption temporaire des services critiques, compromettant immédiatement l'engagement.

### 3. Sous-estimation de la Surface d'Attaque

**Erreur** : Se concentrer uniquement sur les domaines ou IPs principaux sans explorer les actifs périphériques.

**Impact** : Vision incomplète de l'infrastructure, oubli de systèmes potentiellement vulnérables, et opportunités manquées.

**Contremesures** :
- Utiliser des techniques de découverte de sous-domaines multiples (certificats SSL, brute force, sources passives)
- Rechercher les acquisitions, filiales et partenaires de l'organisation cible
- Explorer les ASN (Autonomous System Numbers) associés à l'organisation
- Vérifier les plages d'adresses IP historiquement associées à la cible via des bases WHOIS

**Exemple concret** : Un test d'intrusion limité au domaine principal `entreprise.com` manque complètement le sous-domaine legacy `ancien-systeme.entreprise-filiale.net` qui exécute une version non patchée et vulnérable d'un CMS.

### 4. Mauvaise Gestion des Données Collectées

**Erreur** : Collecter des informations sans système organisé de stockage, d'analyse et de corrélation.

**Impact** : Perte de temps à rechercher des informations déjà collectées, incapacité à identifier des patterns ou des vulnérabilités par corrélation.

**Contremesures** :
- Mettre en place une structure de répertoires cohérente dès le début de l'engagement
- Utiliser des outils de prise de notes structurées comme CherryTree, Obsidian ou Notion
- Automatiser l'extraction et la corrélation des données avec des scripts personnalisés
- Implémenter un système de tags ou de métadonnées pour faciliter la recherche ultérieure

**Exemple concret** : Un testeur découvre une vulnérabilité critique dans un service, mais ne peut pas l'exploiter efficacement car il a perdu les identifiants découverts trois jours plus tôt dans un fichier non documenté parmi des centaines d'autres.

### 5. Ignorer les Signaux de Détection

**Erreur** : Ne pas surveiller les réactions de la cible à vos activités de reconnaissance.

**Impact** : Perte de l'avantage de la surprise, adaptation des défenses de la cible, et potentiellement échec de la mission.

**Contremesures** :
- Mettre en place un système de surveillance des réponses anormales (blocages, timeouts, captchas)
- Alterner entre périodes d'activité et de silence pour évaluer les réactions
- Disposer de plusieurs vecteurs d'accès et méthodes de reconnaissance en cas de blocage
- Maintenir une infrastructure de scan distribuée pour pivoter en cas de détection

**Exemple concret** : Un testeur continue à scanner agressivement un réseau après que ses premières tentatives aient été bloquées, conduisant l'équipe de sécurité à renforcer les défenses et à surveiller spécifiquement ses activités, compromettant toutes les phases ultérieures du test.

### Bonus : Le Piège du 0-Day

**Erreur** : Rechercher ou tenter d'exploiter des vulnérabilités 0-day avant d'avoir épuisé les vecteurs d'attaque connus.

**Impact** : Gaspillage de ressources précieuses, complexité inutile, et risque de détection accru.

**Contremesures** :
- Suivre une méthodologie structurée qui commence par les vulnérabilités connues et courantes
- Maintenir une base de données à jour des CVE récentes et des exploits associés
- Utiliser des outils comme Nuclei ou Nessus pour détecter systématiquement les vulnérabilités connues
- Réserver la recherche de 0-day pour les cibles hautement sécurisées où les approches standard ont échoué

**Exemple concret** : Un testeur passe des jours à tenter de découvrir une vulnérabilité inédite dans une application personnalisée, alors qu'un simple scan aurait révélé plusieurs serveurs annexes exécutant des versions obsolètes avec des vulnérabilités connues et facilement exploitables.

## Points Clés à Retenir

La phase de reconnaissance est fondamentale pour le succès de tout test d'intrusion ou évaluation de sécurité. Voici les points essentiels à retenir de ce chapitre :

1. **La méthodologie prime sur les outils** : Une approche structurée et méthodique de la reconnaissance est plus importante que la maîtrise d'outils spécifiques. Commencez toujours par définir clairement vos objectifs et votre périmètre.

2. **Passive avant active** : La reconnaissance passive doit toujours précéder la reconnaissance active. Elle fournit une base solide d'informations sans risque de détection et oriente efficacement les phases actives ultérieures.

3. **L'OPSEC n'est jamais optionnelle** : Les considérations de sécurité opérationnelle doivent être intégrées à chaque étape du processus, même lors de la reconnaissance passive. Votre empreinte numérique peut révéler vos intentions.

4. **La documentation est cruciale** : Documentez systématiquement vos découvertes, commandes utilisées et résultats obtenus. Une bonne documentation fait souvent la différence entre un test d'intrusion réussi et un échec.

5. **Adaptez-vous à la cible** : Chaque cible est unique et nécessite une approche personnalisée. Adaptez vos techniques, outils et intensité en fonction du contexte, de la maturité de sécurité et des contraintes spécifiques.

6. **Pensez comme un défenseur** : Comprendre la perspective Blue Team vous permet d'anticiper les détections et d'adapter vos techniques pour rester sous le radar. Cette vision Purple Team améliore l'efficacité de vos opérations.

7. **La reconnaissance est continue** : La phase de reconnaissance ne s'arrête pas après le début des phases d'exploitation. Elle se poursuit tout au long de l'engagement pour découvrir de nouvelles cibles et opportunités.

8. **L'automatisation avec discernement** : Automatisez les tâches répétitives mais gardez un contrôle humain sur l'interprétation des résultats et les décisions stratégiques. L'automatisation aveugle peut conduire à des erreurs ou des détections.

9. **La corrélation crée la valeur** : La vraie valeur de la reconnaissance réside dans votre capacité à corréler des informations provenant de sources diverses pour identifier des patterns, des vulnérabilités ou des opportunités uniques.

10. **Respectez le cadre légal et éthique** : Assurez-vous toujours que vos activités de reconnaissance restent dans le cadre défini par votre autorisation de test et la législation applicable.

## Mini-Quiz

Testez vos connaissances sur la reconnaissance avec ces trois questions à choix multiples :

### Question 1 : Quelle affirmation concernant la reconnaissance passive est CORRECTE ?

A) Elle implique toujours une interaction directe avec les systèmes de la cible  
B) Elle ne peut pas être détectée par la cible car elle n'utilise que des sources publiques  
C) Elle est généralement moins efficace que la reconnaissance active et peut être ignorée  
D) Elle peut révéler des informations sensibles comme des sous-domaines via les logs de transparence des certificats  

### Question 2 : Lors d'un scan nmap, quelle option permet de réduire les risques de détection ?

A) `-T5` pour terminer le scan plus rapidement  
B) `-A` pour obtenir toutes les informations en une seule commande  
C) `-sS` combiné avec `-T2` pour un scan SYN discret avec timing lent  
D) `--script=vuln` pour identifier immédiatement les vulnérabilités  

### Question 3 : Dans une perspective Purple Team, quelle approche est la plus pertinente ?

A) Maximiser l'agressivité des scans pour tester les limites des défenses  
B) Documenter les techniques de détection possibles parallèlement aux méthodes de reconnaissance  
C) Éviter toute communication avec l'équipe Blue Team pour maintenir l'effet de surprise  
D) Se concentrer uniquement sur les vulnérabilités critiques pour optimiser le temps  

**Réponses :**
1. D) Elle peut révéler des informations sensibles comme des sous-domaines via les logs de transparence des certificats
2. C) `-sS` combiné avec `-T2` pour un scan SYN discret avec timing lent
3. B) Documenter les techniques de détection possibles parallèlement aux méthodes de reconnaissance
