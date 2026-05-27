# Domaine 4 — Detection SIEM/XDR Core

> Priorité : HAUTE | Sprints : 8–10 | Dépendances : D0, D1

---

## Objectif

Moteur de détection unifié combinant les capacités SIEM (corrélation événements) et XDR (détection étendue cross-couche).
Première couche de génération d'alertes qualifiées et contextualisées.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| DET-01 | Correlation Engine (SIEM) |
| DET-02 | Detection Rules Management |
| DET-03 | Alert Management |
| DET-04 | XDR Cross-layer Detection |
| DET-05 | MITRE ATT&CK Mapping |
| DET-06 | Incident Management |
| DET-07 | Case Management |
| DET-08 | Threat Hunting Workbench |

---

## Epics & User Stories MVP

### EPIC DET-01 — Correlation Engine (SIEM)

| ID | User Story | Priorité |
|---|---|---|
| US-DET-COR-001 | En tant d'analyste, le moteur corrèle des événements de sources hétérogènes en temps réel | HAUTE |
| US-DET-COR-002 | En tant d'analyste, la corrélation est basée sur des fenêtres temporelles configurables | HAUTE |
| US-DET-COR-003 | En tant de système, les alertes dupliquées sont automatiquement groupées | HAUTE |
| US-DET-COR-004 | En tant de système, la corrélation contextualise selon Identity, Asset, Threat | HAUTE |
| US-DET-COR-005 | En tant d'analyste, je vois le score de risque global de chaque alerte | HAUTE |

---

### EPIC DET-02 — Detection Rules Management

| ID | User Story | Priorité |
|---|---|---|
| US-DET-RUL-001 | En tant d'analyste, je crée des règles de détection (SQL-like, YAML, GUI) | HAUTE |
| US-DET-RUL-002 | En tant d'admin, les règles MITRE ATT&CK sont pré-chargées | HAUTE |
| US-DET-RUL-003 | En tant d'analyste, je teste une règle en sandbox avant déploiement | HAUTE |
| US-DET-RUL-004 | En tant d'admin, les règles sont versionnées et rollbackables | HAUTE |
| US-DET-RUL-005 | En tant de système, les faux positifs ajustent automatiquement le scoring | HAUTE |

**Bibliothèque de règles MVP :**
```
- Brute force (AD, SSH, RDP, Web)
- Privilege escalation
- Lateral movement
- Data exfiltration
- Ransomware indicators
- CBS/SWIFT anomalies
- After-hours privileged access
- New admin account
- Pass-the-Hash / Kerberoasting
- DNS tunneling
- Beaconing
```

---

### EPIC DET-03 — Alert Management

| ID | User Story | Priorité |
|---|---|---|
| US-DET-ALT-001 | En tant d'analyste L1, je vois les alertes triées par priorité métier | HAUTE |
| US-DET-ALT-002 | En tant d'analyste, chaque alerte contient : contexte Identity, Asset, Threat, Impact Business | HAUTE |
| US-DET-ALT-003 | En tant d'analyste, je qualifie une alerte (True Positive / False Positive / Accepted Risk) | HAUTE |
| US-DET-ALT-004 | En tant de système, les alertes FP sont automatiquement apprises pour réduire le bruit | HAUTE |
| US-DET-ALT-005 | En tant d'analyste, les alertes corrélées forment automatiquement un incident | HAUTE |

**Objectif :** -70% faux positifs vs approche traditionnelle

---

### EPIC DET-04 — XDR Cross-layer Detection

| ID | User Story | Priorité |
|---|---|---|
| US-DET-XDR-001 | En tant de système, je détecte des attaques cross-couche (endpoint + réseau + identité + cloud) | HAUTE |
| US-DET-XDR-002 | En tant d'analyste, je vois le story graph d'une attaque cross-couche | HAUTE |
| US-DET-XDR-003 | En tant de système, je calcule la kill chain complète de l'attaque | HAUTE |

**Couches XDR :**
```
Endpoint | Network | Identity | Cloud | Email | Application | Banking
```

---

### EPIC DET-05 — MITRE ATT&CK Mapping

| ID | User Story | Priorité |
|---|---|---|
| US-DET-MIT-001 | En tant d'analyste, chaque alerte est mappée sur une technique ATT&CK | HAUTE |
| US-DET-MIT-002 | En tant de CISO, je vois ma couverture ATT&CK globale sous forme de heatmap | HAUTE |
| US-DET-MIT-003 | En tant d'analyste, je navigue dans les tactiques/techniques depuis une alerte | HAUTE |

---

### EPIC DET-06 — Incident Management

| ID | User Story | Priorité |
|---|---|---|
| US-DET-INC-001 | En tant d'analyste, je gère le cycle de vie complet d'un incident | HAUTE |
| US-DET-INC-002 | En tant d'analyste, un incident agrège automatiquement alertes + events + actifs + identités | HAUTE |
| US-DET-INC-003 | En tant de CISO, je suis l'avancement des incidents en cours | HAUTE |
| US-DET-INC-004 | En tant d'analyste, l'incident est scoré selon l'impact métier | HAUTE |

**États :** New → Investigating → Contained → Resolved → Closed

---

### EPIC DET-07 — Case Management

| ID | User Story | Priorité |
|---|---|---|
| US-DET-CAS-001 | En tant d'analyste, je crée un case à partir d'un incident | HAUTE |
| US-DET-CAS-002 | En tant d'analyste, je collabore sur un case avec d'autres analystes | HAUTE |
| US-DET-CAS-003 | En tant d'analyste, j'attache preuves, notes et timeline à un case | HAUTE |

---

### EPIC DET-08 — Threat Hunting Workbench

| ID | User Story | Priorité |
|---|---|---|
| US-DET-HNT-001 | En tant de threat hunter, je lance des hypothèses de chasse via le search engine | HAUTE |
| US-DET-HNT-002 | En tant de threat hunter, j'utilise le query language pour des requêtes avancées | HAUTE |
| US-DET-HNT-003 | En tant de threat hunter, je sauvegarde et partage mes playbooks de chasse | HAUTE |

---

## APIs exposées

```
GET    /api/v1/alerts                    # Liste alertes
GET    /api/v1/alerts/{id}               # Détail alerte
PUT    /api/v1/alerts/{id}/qualify       # Qualification alerte
GET    /api/v1/incidents                 # Liste incidents
POST   /api/v1/incidents                 # Création manuelle
GET    /api/v1/incidents/{id}            # Détail incident
PUT    /api/v1/incidents/{id}/status     # Update statut
GET    /api/v1/rules                     # Règles de détection
POST   /api/v1/rules                     # Création règle
PUT    /api/v1/rules/{id}
DELETE /api/v1/rules/{id}
POST   /api/v1/rules/{id}/test           # Test sandbox
GET    /api/v1/cases                     # Cases
POST   /api/v1/hunt/query               # Threat hunting
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Correlation Engine base + fenêtres temporelles | Corrélation temps réel |
| S02 | Rules Engine + bibliothèque règles MVP (20+ règles) | Détection opérationnelle |
| S03 | Alert Management + qualification + FP learning | Gestion alertes |
| S04 | XDR Cross-layer + Kill Chain | Détection cross-couche |
| S05 | MITRE ATT&CK Mapping + Heatmap | Couverture ATT&CK |
| S06 | Incident Management (cycle de vie complet) | Incidents qualifiés |
| S07 | Case Management + collaboration | Cases |
| S08 | Threat Hunting Workbench | Chasse active |
| S09-10 | (buffer) Tuning FP + règles banking | -70% FP validé |

---

## Critères d'acceptation

- [ ] Corrélation temps réel < 3 secondes
- [ ] -70% faux positifs vs baseline
- [ ] 20+ règles de détection pré-chargées (incluant banking)
- [ ] Chaque alerte contextualisée (Identity, Asset, Business Impact)
- [ ] MITRE ATT&CK mapping pour 100% des règles
- [ ] Incident lifecycle complet (New → Closed)
- [ ] Threat Hunting opérationnel
- [ ] MTTD < 5 minutes validé
