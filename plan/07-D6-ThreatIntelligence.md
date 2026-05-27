# Domaine 6 — Threat Intelligence (CTI)

> Priorité : MOYENNE | Sprints : 6–8 | Dépendances : D0, D1

---

## Objectif

Centraliser, normaliser et opérationnaliser toutes les sources de renseignement sur les menaces.
Enrichir automatiquement les détections avec le contexte threat en temps réel.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| CTI-01 | Threat Feeds Management |
| CTI-02 | IOC Management |
| CTI-03 | MITRE ATT&CK Intelligence |
| CTI-04 | Threat Actor Profiling |
| CTI-05 | Threat Intelligence Sharing |
| CTI-06 | CTI Enrichment Pipeline |
| CTI-07 | Predictive Threat Scoring |

---

## Sources supportées

```
STIX/TAXII 2.x | CERT national | AlienVault OTX | MISP
VirusTotal | Shodan | Commercial feeds | ISAC banking
IOC propriétaires | Dark web feeds (optionnel V2)
```

---

## Epics & User Stories MVP

### EPIC CTI-01 — Threat Feeds Management

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-FED-001 | En tant d'admin, je configure des feeds CTI (STIX/TAXII, CSV, API) | HAUTE |
| US-CTI-FED-002 | En tant de système, les feeds sont mis à jour automatiquement | HAUTE |
| US-CTI-FED-003 | En tant d'admin, je vois la qualité et la fraîcheur de chaque feed | HAUTE |
| US-CTI-FED-004 | En tant d'admin, je configure les feeds prioritaires pour le contexte bancaire | HAUTE |

---

### EPIC CTI-02 — IOC Management

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-IOC-001 | En tant d'analyste, je recherche un IOC (IP, hash, domaine, URL) | HAUTE |
| US-CTI-IOC-002 | En tant de système, les IOC sont matchés en temps réel sur les events entrants | HAUTE |
| US-CTI-IOC-003 | En tant d'analyste, je crée et partage des IOC internes | HAUTE |
| US-CTI-IOC-004 | En tant de système, les IOC expirés sont automatiquement archivés | MOYENNE |

**Types IOC :** IP, domaine, URL, hash (MD5/SHA1/SHA256), email, certificat, YARA rule

---

### EPIC CTI-03 — MITRE ATT&CK Intelligence

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-MIT-001 | En tant d'analyste, je navigue dans la base ATT&CK depuis la plateforme | HAUTE |
| US-CTI-MIT-002 | En tant de CISO, je vois ma couverture de détection par tactique/technique | HAUTE |
| US-CTI-MIT-003 | En tant d'analyste, les techniques ATT&CK sont liées aux alertes et incidents | HAUTE |

---

### EPIC CTI-04 — Threat Actor Profiling

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-ACT-001 | En tant d'analyste, je vois le profil des groupes APT actifs ciblant le secteur bancaire | HAUTE |
| US-CTI-ACT-002 | En tant d'analyste, je vois les TTP associés à un acteur | HAUTE |
| US-CTI-ACT-003 | En tant de système, je corrèle une alerte avec un acteur connu | HAUTE |

---

### EPIC CTI-05 — Threat Intelligence Sharing

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-SHR-001 | En tant d'admin, je partage du renseignement avec d'autres tenants (opt-in) | MOYENNE |
| US-CTI-SHR-002 | En tant d'admin, j'exporte des IOC en STIX | MOYENNE |

---

### EPIC CTI-06 — CTI Enrichment Pipeline

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-ENR-001 | En tant de pipeline, chaque event entrant est enrichi automatiquement avec les IOC correspondants | HAUTE |
| US-CTI-ENR-002 | En tant de pipeline, l'enrichissement a une latence < 500ms | HAUTE |
| US-CTI-ENR-003 | En tant de pipeline, un cache est utilisé pour les lookups fréquents | HAUTE |

---

### EPIC CTI-07 — Predictive Threat Scoring

| ID | User Story | Priorité |
|---|---|---|
| US-CTI-PRD-001 | En tant d'analyste, je vois le score de probabilité d'attaque sur mes actifs critiques | MOYENNE |
| US-CTI-PRD-002 | En tant de CISO, je vois quels actifs sont les plus susceptibles d'être ciblés prochainement | MOYENNE |

---

## APIs exposées

```
GET    /api/v1/cti/ioc/lookup?value=...     # Lookup IOC
POST   /api/v1/cti/ioc                      # Création IOC interne
GET    /api/v1/cti/feeds                    # Liste feeds
POST   /api/v1/cti/feeds                    # Ajout feed
GET    /api/v1/cti/actors                   # Threat actors
GET    /api/v1/cti/mitre/techniques         # Base ATT&CK
GET    /api/v1/cti/coverage                 # Coverage heatmap
POST   /api/v1/cti/export/stix              # Export STIX
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Feeds Management + STIX/TAXII | Feeds opérationnels |
| S02 | IOC Management + Real-time matching | Matching IOC temps réel |
| S03 | MITRE ATT&CK Integration | Navigation ATT&CK |
| S04 | Threat Actor Profiling | Profils APT |
| S05 | CTI Enrichment Pipeline (latence < 500ms) | Enrichissement auto |
| S06 | Predictive Threat Scoring | Score prédictif |
| S07-08 | (buffer) Banking-specific CTI + sharing | Contexte secteur |

---

## Critères d'acceptation

- [ ] Feeds STIX/TAXII opérationnels
- [ ] IOC matching en temps réel < 500ms
- [ ] MITRE ATT&CK navigateur intégré
- [ ] Enrichissement automatique de tous les events
- [ ] Coverage heatmap CISO opérationnelle
