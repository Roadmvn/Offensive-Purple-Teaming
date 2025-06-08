# 🌳 Structure du Projet - Offensive Purple Teaming

```
Offensive-Purple-Teaming/
│
├── .git/
├── README.md
│
├── 00-Orientation/
│   ├── README.md
│   ├── Roadmap.pdf
│   └── Méthodologie/
│       ├── eJPT-Ultimate-Guide.md
│       ├── guide_complet_ejpt_oscp.md
│       ├── manuel_complet_red_team.md
│       ├── methodologie_pentest.md
│       └── pentest_web_guide.md
│
├── 01-Fundamentals/
│   ├── Linux-Basics/
│   │   ├── README.md
│   │   └── labs/
│   ├── Windows-Basics/
│   │   ├── README.md
│   │   └── labs/
│   ├── Networking-Basics/
│   │   ├── README.md
│   │   └── labs/
│   ├── Programming-Basics/
│   │   ├── 01-Python/README.md
│   │   ├── 02-Bash/README.md
│   │   └── 03-PowerShell/README.md
│   └── Offensive-Fundamentals/
│       ├── 02-Reconnaissance/Reconnaissance.md
│       ├── 03-Enumeration/Énumération.md
│       ├── 04-Exploitation/Exploitation.md
│       ├── 05-Post-Exploitation/Post-Exploitation.md
│       ├── 06-Privilege-Escalation/Privilege_Escalation.md
│       └── 07-Base-Commands/test.md
│
├── 02-Web-Fundamentals/
│   ├── How-The-Web-Works/README.md
│   ├── DNS-Details/README.md
│   ├── HTTP-Deep-Dive/README.md
│   └── Putting-Together/README.md
│
├── 03-Web-Pentest/
│   ├── 01-Beginner/
│   │   ├── README.md
│   │   ├── 01-XSS-Reflected.md
│   │   ├── 02-SQLi-Basics.md
│   │   ├── 03-File-Inclusion-LFI.md
│   │   ├── 04-Command-Injection.md
│   │   └── labs/
│   │       ├── DVWA-low/
│   │       │   ├── scenario.md
│   │       │   └── solution.md
│   │       └── THM-Burp-Basics/
│   │           ├── scenario.md
│   │           └── solution.md
│   ├── 02-Intermediate/
│   │   ├── README.md
│   │   ├── 01-IDOR.md
│   │   ├── 02-Auth-Bypass.md
│   │   ├── 03-SSRF.md
│   │   ├── 04-File-Upload-RCE.md
│   │   ├── 05-XSS-Stored.md
│   │   └── labs/
│   │       ├── Juice-Shop-missions/
│   │       │   ├── scenario.md
│   │       │   └── solution.md
│   │       └── THM-Pickle-Rick/
│   │           ├── scenario.md
│   │           └── solution.md
│   ├── 03-Advanced/
│   │   ├── README.md
│   │   ├── 01-SSTI.md
│   │   ├── 02-Deserialisation.md
│   │   ├── 03-Prototype-Pollution.md
│   │   ├── 04-HTTP-Request-Smuggling.md
│   │   ├── 05-GraphQL-Abuse.md
│   │   └── labs/
│   │       ├── HTB-Cache/
│   │       │   ├── scenario.md
│   │       │   └── solution.md
│   │       ├── HTB-Bounty-Hunter/
│   │       │   ├── scenario.md
│   │       │   └── solution.md
│   │       └── THM-Inclusion/
│   │           ├── scenario.md
│   │           └── solution.md
│   └── 04-Burp-Suite/
│       ├── README.md
│       ├── 01-Repeater.md
│       ├── 02-Intruder.md
│       ├── 03-Extender-TurboIntruder.md
│       └── labs/
│           ├── Burp-Lab-01/
│           │   ├── scenario.md
│           │   └── solution.md
│           └── Burp-Lab-02/
│               ├── scenario.md
│               └── solution.md
│
├── 04-Network-Host-Pentest/
│   ├── 01-Recon-Scanning/
│   │   ├── Linux/
│   │   │   ├── Beginner/
│   │   │   │   ├── README.md
│   │   │   │   └── labs/
│   │   │   ├── Intermediate/
│   │   │   │   ├── README.md
│   │   │   │   └── labs/
│   │   │   └── Advanced/
│   │   │       ├── README.md
│   │   │       └── labs/
│   │   ├── Windows/
│   │   │   ├── Beginner/
│   │   │   │   ├── README.md
│   │   │   │   └── labs/
│   │   │   ├── Intermediate/
│   │   │   │   ├── README.md
│   │   │   │   └── labs/
│   │   │   └── Advanced/
│   │   │       ├── README.md
│   │   │       └── labs/
│   │   └── macOS/
│   │       ├── Beginner/
│   │       │   ├── README.md
│   │       │   └── labs/
│   │       ├── Intermediate/
│   │       │   ├── README.md
│   │       │   └── labs/
│   │       └── Advanced/
│   │           ├── README.md
│   │           └── labs/
│   ├── 02-Enumeration/
│   │   ├── Linux/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   ├── Windows/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   └── macOS/
│   │       ├── Beginner/
│   │       ├── Intermediate/
│   │       └── Advanced/
│   ├── 03-Exploitation/
│   │   ├── Linux/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   ├── Windows/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   └── macOS/
│   │       ├── Beginner/
│   │       ├── Intermediate/
│   │       └── Advanced/
│   ├── 04-Post-Exploitation/
│   │   ├── Linux/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   ├── Windows/
│   │   │   ├── Beginner/
│   │   │   ├── Intermediate/
│   │   │   └── Advanced/
│   │   └── macOS/
│   │       ├── Beginner/
│   │       ├── Intermediate/
│   │       └── Advanced/
│   └── 05-Reporting/
│       ├── Linux/
│       │   ├── Beginner/report-template.md
│       │   ├── Intermediate/report-template.md
│       │   └── Advanced/report-template.md
│       ├── Windows/
│       │   ├── Beginner/report-template.md
│       │   ├── Intermediate/report-template.md
│       │   └── Advanced/report-template.md
│       └── macOS/
│           ├── Beginner/report-template.md
│           ├── Intermediate/report-template.md
│           └── Advanced/report-template.md
│
├── 05-Privilege-Escalation/
│   ├── Linux-PE/
│   │   ├── README.md
│   │   ├── labs/
│   │   └── scripts/
│   ├── Windows-PE/
│   │   ├── README.md
│   │   ├── labs/
│   │   └── scripts/
│   └── macOS-PE/
│       ├── README.md
│       ├── labs/
│       └── scripts/
│
├── 06-Red-Team-Core/
│   ├── 01-Threat-Emulation-Plan/
│   ├── 02-Initial-Access/
│   ├── 03-Infrastructure-C2/
│   ├── 04-Active-Directory-Attacks/
│   ├── 05-Cloud-Targets/
│   ├── 06-Wireless-Security/
│   ├── 07-Password-Cracking-Credential-Theft/
│   ├── 08-Social-Engineering/
│   ├── 09-OPSEC-&-Evasion/
│   ├── 10-Exfiltration/
│   ├── 11-Specific-Attacks/
│   │   ├── README.md
│   │   ├── Phishing/
│   │   ├── Man-In-The-Middle/
│   │   ├── SQL-Injection/
│   │   ├── Cross-Site-Scripting/
│   │   ├── Distributed-DoS/
│   │   ├── Eavesdropping/
│   │   ├── Ransomware/
│   │   ├── AI-Powered-Attacks/
│   │   └── Drive-By-Attacks/
│   └── 12-Engagement-Reporting/
│
├── 07-Purple-Team-Detection/
│   ├── 01-Detection-Engineering/
│   │   ├── Logging-Monitoring/
│   │   ├── Sigma-Rules/
│   │   └── ATT&CK-Mapping/
│   ├── 02-SIEM-Setup/
│   │   ├── Wazuh/
│   │   └── ELK-Stack/
│   ├── 03-Attack-Simulation/
│   │   ├── Atomic-Red-Team/
│   │   └── Caldera-Framework/
│   └── 04-Playbooks-&-Metrics/
│       ├── Playbooks/
│       └── Reporting-Metrics/
│
├── 08-Tools/
│   ├── Metasploit_Framework.md
│   ├── Nmap.md
│   ├── Masscan.md
│   ├── BloodHound.md
│   ├── Chisel.md
│   ├── Socat.md
│   └── README.md                 ← index ou table des outils
│
├── 09-Automation-Tooling/
│   ├── Offensive-Scripts/
│   ├── Defensive-Scripts/
│   └── Automation-CI-CD/
│       ├── Ansible-Playbooks/
│       ├── GitHub-Actions/
│       └── CI-CD-Templates/
│
├── 10-Labs-Projects/
│   ├── TryHackMe-Rooms.txt
│   ├── HTB-Boxes.txt
│   ├── Custom-Docker-Labs/
│   ├── Purple-Team-Lab/
│   └── Write-Ups/
│
├── 11-Resources-Cheatsheets/
│   ├── Official-Documentation/
│   ├── Blogs-Articles/
│   ├── Cheatsheets/
│   └── Online-Tools-Resources/
│
├── 12-Tips-FAQ/
│   ├── Terminal-Tricks.md
│   ├── Common-Errors.md
│   ├── OPSEC-Best-Practices.md
│   ├── Study-Plans.md
│   └── Methodology-Checklist.md
│
└── 13-OSINT/                        ← NOUVELLE SECTION
    ├── 01-Beginner/
    │   ├── README.md                ← fondamentaux OSINT, cadre légal, OPSEC
    │   ├── 01-Passive-Footprinting.md
    │   ├── 02-Domain-Intel.md
    │   ├── 03-Username-Enum.md
    │   └── labs/
    │       ├── Lab-Personal-Footprint/
    │       │   ├── scenario.md
    │       │   └── solution.md
    │       └── Lab-Basic-Domain-Profile/
    │           ├── scenario.md
    │           └── solution.md
    │
    ├── 02-Intermediate/
    │   ├── README.md
    │   ├── 01-Social-Media-Intel.md
    │   ├── 02-Metadata-Extraction.md
    │   ├── 03-Geolocation-&-Image-Forensics.md
    │   ├── 04-Breach-Data-Search.md
    │   └── labs/
    │       ├── Lab-Twitter-Investigation/
    │       ├── Lab-EXIF-Geolocate/
    │       └── Lab-Leak-Lookup/
    │
    └── 03-Advanced/
        ├── README.md
        ├── 01-Advanced-Pivoting.md          ← graphing, Maltego, SpiderFoot
        ├── 02-Dark-Web-Intel.md
        ├── 03-Automation-Scripting.md       ← Python scraping, APIs
        ├── 04-Reporting-OSINT.md            ← créer un rapport décisionnel
        └── labs/
            ├── Lab-Full-Company-Profile/
            ├── Lab-DarkWeb-Marketplace/
            └── Lab-OSINT-CTI-Challenge/
```

## 📊 Statistiques du projet

- **Dossiers principaux :** 13 sections
- **Sous-dossiers :** ~160+ dossiers
- **Fichiers de documentation :** ~220+ fichiers
- **Laboratoires pratiques :** ~60+ labs
- **Templates de rapports :** 9 templates
- **Scripts d'automatisation :** Multiple collections
- **Section OSINT :** Complète du débutant à l'expert

## 🎯 Parcours recommandés

### 🔰 Débutant
```
00-Orientation → 01-Fundamentals → 02-Web-Fundamentals → 03-Web-Pentest/01-Beginner
```

### 🎓 Intermédiaire
```
Parcours Débutant → 04-Network-Host-Pentest → 05-Privilege-Escalation
```

### 🚀 Avancé
```
Parcours Intermédiaire → 06-Red-Team-Core → 07-Purple-Team-Detection
```

---

*Cette structure complète couvre tous les aspects de la sécurité offensive et défensive, du niveau débutant à expert.*
