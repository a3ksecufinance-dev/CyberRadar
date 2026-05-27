# Domaine 2 — Cyber Asset Intelligence (CAI)

> Priorité : HAUTE | Sprints : 8–12 | Dépendances : D0, D1

> "You cannot protect what you cannot see."

---

## Objectif

Remplacer une CMDB classique par un **inventaire cyber vivant, intelligent et dynamique**.

Moteur capable de :
- Découvrir automatiquement les actifs
- Classifier les actifs
- Comprendre leurs dépendances
- Calculer leur criticité
- Détecter le Shadow IT
- Cartographier les relations cyber
- Alimenter le Digital Twin

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| CAI-01 | Asset Discovery |
| CAI-02 | Asset Classification |
| CAI-03 | Asset Fingerprinting |
| CAI-04 | Unified Asset Inventory |
| CAI-05 | Asset Criticality Engine |
| CAI-06 | Dependency Mapping |
| CAI-07 | Shadow IT Detection |
| CAI-08 | Rogue Asset Detection |
| CAI-09 | Business Mapping |
| CAI-10 | Asset Lifecycle |
| CAI-11 | Exposure Profiling |
| CAI-12 | External Attack Surface (EASM) |
| CAI-13 | Asset Risk Scoring |
| CAI-14 | Digital Twin Feed |

---

## Types d'actifs supportés

| Catégorie | Types |
|---|---|
| Infrastructure | Serveur, VM, Container, Workstation, Mobile, Firewall, Switch, Router, Storage |
| Identity Assets | User, Admin, Service Account, API Account |
| Application Assets | Application, API, Microservice, CBS Module, SWIFT Component |
| Cloud Assets | EC2, VPC, Security Groups, IAM Roles, Kubernetes |
| Banking Assets | ATM/GAB, TPE/POS, Switch Monétique, CBS Nodes, Agence systems |
| Data Assets | Database, File Share, Sensitive Dataset |

---

## Epics & User Stories MVP

### EPIC CAI-01 — Asset Discovery

**Modes de découverte :**
```
Active Discovery  → scan réseau
Passive Discovery → analyse logs & trafic
Agent Discovery   → agents endpoint
API Discovery     → cloud/API
Identity Discovery → AD/IAM/PAM
```

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-DIS-001 | En tant qu'admin, la découverte d'actifs est automatique et continue | HAUTE |
| US-CAI-DIS-002 | En tant qu'admin, les actifs sont découverts en moins de 5 minutes | HAUTE |
| US-CAI-DIS-003 | En tant que pipeline, je découvre les actifs passivement depuis les logs | HAUTE |
| US-CAI-DIS-004 | En tant qu'admin, je découvre les resources cloud AWS/Azure/GCP | HAUTE |
| US-CAI-DIS-005 | En tant qu'admin, je découvre les workloads Kubernetes | HAUTE |
| US-CAI-DIS-006 | En tant qu'admin, je découvre les SaaS et APIs internes | HAUTE |
| US-CAI-DIS-007 | En tant qu'admin, je découvre les identités et comptes privilégiés | HAUTE |

**Protocoles :** SNMP, WMI, SSH, WinRM, ICMP, ARP, NetFlow

**Critères :** couverture > 95%, découverte < 5 min, duplication < 2%

---

### EPIC CAI-02 — Asset Classification

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-CLS-001 | En tant que pipeline, chaque actif est classifié automatiquement | HAUTE |
| US-CAI-CLS-002 | En tant qu'analyste, je vois le score de confiance de la classification | HAUTE |
| US-CAI-CLS-003 | En tant qu'admin, je crée des catégories custom | MOYENNE |
| US-CAI-CLS-004 | En tant qu'analyste, je valide/corrige une classification via workflow | MOYENNE |

**Catégories prédéfinies :** endpoint, server, domain controller, database, firewall, PAM, CBS, SWIFT, ATM, critical banking app

---

### EPIC CAI-03 — Asset Fingerprinting

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-FNG-001 | En tant que pipeline, chaque actif a un identifiant unique | HAUTE |
| US-CAI-FNG-002 | En tant de pipeline, les doublons sont détectés et fusionnés | HAUTE |
| US-CAI-FNG-003 | En tant de pipeline, un actif réapparu est correctement réidentifié | HAUTE |

**Sources fingerprint :** hostname, MAC, IP, BIOS, OS signature, certificates, installed software, cloud metadata

---

### EPIC CAI-04 — Unified Asset Inventory

**Asset Profile (vue unique obligatoire) :**

```
General   : asset_id, hostname, owner, BU, location
Technical : OS, software, versions
Security  : vulnerabilities, EDR, AV, patching
Identity  : admins, service accounts
Exposure  : internet_exposed, open_ports
Business  : CBS_dependency, SWIFT_dependency, criticality
```

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-INV-001 | En tant qu'analyste, je vois une fiche complète de chaque actif | HAUTE |
| US-CAI-INV-002 | En tant qu'analyste, je consulte l'historique et la timeline d'un actif | HAUTE |
| US-CAI-INV-003 | En tant d'analyste, je vois toutes les versions de configuration | MOYENNE |

---

### EPIC CAI-05 — Asset Criticality Engine

**Très critique**

**Inputs :**
```
Business service | Internet exposure | Privilege level
Vulnerabilities  | Financial impact  | Compliance impact | Data sensitivity
```

**Score : 0 → 100**

Exemples :
- CBS DB Server : 98/100
- Laptop interne : 22/100

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-CRT-001 | En tant que système, je calcule automatiquement la criticité de chaque actif | HAUTE |
| US-CAI-CRT-002 | En tant qu'analyste, je vois l'explication du score | HAUTE |
| US-CAI-CRT-003 | En tant d'admin, je peux override manuellement la criticité | HAUTE |
| US-CAI-CRT-004 | En tant de système, j'intègre l'impact financier dans le score | HAUTE |

---

### EPIC CAI-06 — Dependency Mapping

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-DPM-001 | En tant qu'analyste, je visualise les dépendances automatiquement découvertes | HAUTE |
| US-CAI-DPM-002 | En tant qu'analyste, je vois les flux applicatifs et réseau | HAUTE |
| US-CAI-DPM-003 | En tant qu'analyste, je calcule le blast radius d'un actif | HAUTE |

**Exemple mapping :**
```
Server A → API B → Database C → CBS D
```

---

### EPIC CAI-07 — Shadow IT Detection

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-SHD-001 | En tant qu'admin, je détecte les actifs inconnus (machines, SaaS, cloud, APIs) | HAUTE |
| US-CAI-SHD-002 | En tant qu'admin, chaque actif Shadow IT a un risk score | HAUTE |
| US-CAI-SHD-003 | En tant qu'admin, je reçois une alerte lors d'un nouveau Shadow IT | HAUTE |

---

### EPIC CAI-08 — Rogue Asset Detection

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-RGA-001 | En tant de système, je détecte les rogue devices (laptops non managés, fake AP, serveurs non autorisés) | HAUTE |
| US-CAI-RGA-002 | En tant de système, je recommande une mise en quarantaine automatique | HAUTE |

---

### EPIC CAI-09 — Business Mapping

**Très important pour la dimension bancaire**

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-BIZ-001 | En tant d'analyste, je vois la relation Actif → Service Métier → Processus → Criticité | HAUTE |
| US-CAI-BIZ-002 | En tant de système, j'estime l'impact financier d'un actif compromis | HAUTE |

**Exemples :**
- Server X → CBS → Paiement → Critique
- ATM Middleware → Monétique → Critique

---

### EPIC CAI-10 — Asset Lifecycle

**États :** discovered → active → inactive → orphaned → retired → compromised

| ID | User Story | Priorité |
|---|---|---|
| US-CAI-LFC-001 | En tant de système, je trace tout le cycle de vie d'un actif | HAUTE |
| US-CAI-LFC-002 | En tant d'admin, je détecte les actifs orphelins et dormants | HAUTE |

---

### EPIC CAI-11 — Exposure Profiling

| ID | Exigence | Priorité |
|---|---|---|
| FR-CAI-EXP-001 | Détection exposition internet | HAUTE |
| FR-CAI-EXP-002 | Scan ports ouverts | HAUTE |
| FR-CAI-EXP-003 | Détection misconfiguration | HAUTE |
| FR-CAI-EXP-004 | Détection credential exposure | HAUTE |

---

### EPIC CAI-12 — External Attack Surface (EASM)

| ID | Exigence | Priorité |
|---|---|---|
| FR-CAI-EASM-001 | Découverte domaines | HAUTE |
| FR-CAI-EASM-002 | Découverte sous-domaines | HAUTE |
| FR-CAI-EASM-003 | Monitoring SSL | HAUTE |
| FR-CAI-EASM-004 | Alerte expiration certificats | HAUTE |
| FR-CAI-EASM-005 | Détection exposition cloud | HAUTE |

---

### EPIC CAI-13 — Asset Risk Scoring

**Formule hybride :**
```
Risk Score = f(Exposure, Vulnerability, Identity Risk, Threat Exposure, Business Criticality)
```

| ID | Exigence | Priorité |
|---|---|---|
| FR-CAI-RSK-001 | Scoring dynamique | HAUTE |
| FR-CAI-RSK-002 | Mise à jour temps réel | HAUTE |
| FR-CAI-RSK-003 | Score explicable | HAUTE |

---

### EPIC CAI-14 — Digital Twin Feed

**Le CAI alimente le Graph DB :**

```
Nœuds   : asset, user, service, privilege
Relations: connects_to, owned_by, exposed_to
```

| ID | Exigence | Priorité |
|---|---|---|
| FR-CAI-DTW-001 | Sync temps réel vers Graph DB | HAUTE |
| FR-CAI-DTW-002 | Mise à jour topologie automatique | HAUTE |

---

## Exigences non fonctionnelles

| Code | Exigence |
|---|---|
| NFR-CAI-001 | Support 1M+ actifs |
| NFR-CAI-002 | Découverte < 5 minutes |
| NFR-CAI-003 | Précision > 95% |
| NFR-CAI-004 | Uptime 99.99% |

---

## APIs exposées

```
GET    /api/v1/assets                     # Liste des actifs
POST   /api/v1/assets                     # Ajout manuel
GET    /api/v1/assets/{id}                # Asset profile complet
PUT    /api/v1/assets/{id}/criticality    # Override criticité
GET    /api/v1/assets/{id}/dependencies   # Dépendances
GET    /api/v1/assets/{id}/risk           # Risk score
POST   /api/v1/discovery/scan             # Lancer un scan
GET    /api/v1/discovery/status           # Statut découverte
GET    /api/v1/assets/shadow-it           # Shadow IT détecté
GET    /api/v1/assets/rogue               # Rogue assets
GET    /api/v1/assets/{id}/business       # Business mapping
GET    /api/v1/dependencies               # Carte de dépendances
GET    /api/v1/exposure/external          # Attack surface
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Discovery Engine (Active + Passive) | Découverte automatique active |
| S02 | Asset Fingerprinting + Dedup | Identifiants uniques |
| S03 | Unified Asset Inventory + Profiling | Vue 360° actif |
| S04 | Asset Classification (ML) + Lifecycle | Classification intelligente |
| S05 | Criticality Engine + Business Mapping | Score métier |
| S06 | Dependency Mapping + Blast Radius | Relations cyber |
| S07 | Shadow IT + Rogue Asset Detection | Détection non-autorisé |
| S08 | Exposure Profiling + EASM | Surface d'attaque externe |
| S09 | Risk Scoring Engine | Score de risque hybride |
| S10 | Digital Twin Feed → Graph DB | Sync temps réel |
| S11-12 | (buffer) Couverture cloud, banking, OT | Sources spécialisées |

---

## Critères d'acceptation globaux

- [ ] Couverture actifs > 95%
- [ ] Découverte < 5 minutes
- [ ] Duplication < 2%
- [ ] Asset Profile complet pour tous les types d'actifs
- [ ] Criticality Engine avec score explicable
- [ ] Blast radius calculé automatiquement
- [ ] Shadow IT détecté et alerté
- [ ] Business Mapping CBS/Monétique/SWIFT opérationnel
- [ ] Digital Twin feed synchronisé en temps réel vers Graph DB
- [ ] 1M+ actifs supportés
