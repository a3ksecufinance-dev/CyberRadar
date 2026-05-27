# Domaine 1 — Cyber Data Fabric (CDF)

> Priorité : CRITIQUE | Sprints : 10–14 | Dépendances : D0

---

## Objectif

Cœur réel de la plateforme. Couche centrale de collecte, transformation, enrichissement, stockage et diffusion de toutes les données cyber.
Transformer des données hétérogènes, bruitées et massives en **Cyber Intelligence exploitable en temps réel**.

> "Cyber Nervous System" — absorber, normaliser et contextualiser des milliards d'événements.

---

## Pipeline logique

```
Sources → Collecte → Streaming → Parsing → Normalization
       → Enrichment → Classification → Storage
       → Analytics / SIEM / UEBA / AI
```

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| CDF-01 | Data Ingestion |
| CDF-02 | Connectors Framework |
| CDF-03 | Event Streaming Layer |
| CDF-04 | Parsing & Normalization |
| CDF-05 | Data Enrichment |
| CDF-06 | Universal Cyber Schema |
| CDF-07 | Data Classification |
| CDF-08 | Correlation Context Layer |
| CDF-09 | Storage Layer |
| CDF-10 | Search & Query Engine |
| CDF-11 | Data Governance |
| CDF-12 | Retention & Archiving |
| CDF-13 | Data Quality |
| CDF-14 | Replay & Forensics |

---

## Sources supportées (MVP minimum)

| Catégorie | Sources |
|---|---|
| Infrastructure | Windows, Linux, VMware, Kubernetes |
| Réseau | Firewall, IDS/IPS, WAF, VPN, Proxy, DNS, DHCP, NetFlow/IPFIX |
| Endpoint | EDR, AV, XDR |
| Identity | Active Directory, Entra ID, LDAP, IAM, PAM |
| Cloud | AWS, Azure, GCP |
| SaaS | Microsoft 365, Google Workspace |
| Banking | CBS, Monétique, SWIFT, ATM/GAB, Payment Switch |
| Threat Intel | STIX/TAXII, CERT, IOC feeds |
| OT/IoT | SCADA, PLC, IoT gateways |

---

## Epics & User Stories MVP

### EPIC CDF-01 — Data Ingestion

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-ING-001 | En tant que connecteur, j'envoie des events en temps réel, near real-time ou batch | HAUTE |
| US-CDF-ING-002 | En tant que source, je peux envoyer en push ou pull | HAUTE |
| US-CDF-ING-003 | En tant que source Syslog, je supporte UDP/TCP/TLS | HAUTE |
| US-CDF-ING-004 | En tant que source API, je supporte REST, GraphQL | HAUTE |
| US-CDF-ING-005 | En tant que source streaming, je supporte Kafka, AMQP, MQTT | HAUTE |
| US-CDF-ING-006 | En tant que source réseau, je supporte NetFlow, IPFIX, sFlow | HAUTE |
| US-CDF-ING-007 | En tant que source fichier, je supporte CSV, JSON, XML, Parquet, Avro | MOYENNE |
| US-CDF-ING-008 | En tant que pipeline, je gère le backpressure et le retry automatique | HAUTE |

**Performance cible :** < 0.001% perte d'events

---

### EPIC CDF-02 — Connectors Framework

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-CON-001 | En tant que développeur, j'utilise le Connector SDK pour créer un connecteur | HAUTE |
| US-CDF-CON-002 | En tant qu'admin, je configure un connecteur low-code via l'interface | HAUTE |
| US-CDF-CON-003 | En tant qu'admin, je surveille la santé de chaque connecteur | HAUTE |
| US-CDF-CON-004 | En tant qu'admin, je mets à jour les connecteurs automatiquement | MOYENNE |

**Connecteurs MVP obligatoires :**
```
AD | Entra ID | Wallix PAM | Windows | Linux | Cisco
Fortinet | Check Point | Palo Alto | CrowdStrike | Defender
M365 | AWS | Azure | VMware | CBS | SWIFT
```

---

### EPIC CDF-03 — Event Streaming Layer

**Performance :** 100K EPS MVP → 1M+ EPS évolutif

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-STR-001 | En tant que pipeline, les events sont traités en temps réel avec garantie de livraison | HAUTE |
| US-CDF-STR-002 | En tant qu'admin, je rejoue un stream depuis un point donné | HAUTE |
| US-CDF-STR-003 | En tant que pipeline, les events ratés vont en dead-letter queue | HAUTE |
| US-CDF-STR-004 | En tant que pipeline, le partitionnement est horizontal | HAUTE |

---

### EPIC CDF-04 — Parsing & Normalization

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-PAR-001 | En tant que pipeline, je détecte automatiquement le format d'un event | HAUTE |
| US-CDF-PAR-002 | En tant qu'admin, je crée un parser custom via GUI | HAUTE |
| US-CDF-PAR-003 | En tant que pipeline, je normalise les timestamps en UTC | HAUTE |
| US-CDF-PAR-004 | En tant que pipeline, je déduplique les events | HAUTE |
| US-CDF-PAR-005 | En tant que pipeline, le parser apprend de nouveaux formats automatiquement | MOYENNE |

**Méthodes de parsing supportées :** regex, grok, JSON, XML, schema mapping

---

### EPIC CDF-05 — Data Enrichment

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-ENR-001 | En tant que pipeline, j'enrichis chaque event avec les données Identity | HAUTE |
| US-CDF-ENR-002 | En tant que pipeline, j'enrichis avec les données Asset (hostname, criticité, owner) | HAUTE |
| US-CDF-ENR-003 | En tant que pipeline, j'enrichis avec géolocalisation et réputation IP | HAUTE |
| US-CDF-ENR-004 | En tant que pipeline, j'enrichis avec Threat Intel (IOC, MITRE ATT&CK) | HAUTE |
| US-CDF-ENR-005 | En tant que pipeline, j'enrichis avec le contexte métier (CBS, service, impact) | HAUTE |
| US-CDF-ENR-006 | En tant que pipeline, j'utilise un cache pour minimiser la latence | HAUTE |

---

### EPIC CDF-06 — Universal Cyber Schema

**Critique — Schéma unifié pour tous les events**

```json
Event {
  EventID         : UUID
  Timestamp       : UTC
  Source          : string
  TenantID        : string
  User            : UserRef
  Asset           : AssetRef
  IPSource        : string
  IPDestination   : string
  Action          : string
  Severity        : enum [LOW, MEDIUM, HIGH, CRITICAL]
  ThreatScore     : float (0-100)
  MITRETechnique  : string
  RiskScore       : float (0-100)
  RawEvent        : string
}
```

| ID | Exigence | Priorité |
|---|---|---|
| FR-CDF-SCH-001 | Tous les events normalisés vers ce schéma | HAUTE |
| FR-CDF-SCH-002 | Schéma extensible | HAUTE |
| FR-CDF-SCH-003 | Backward compatibility | HAUTE |
| FR-CDF-SCH-004 | Versioning du schéma | MOYENNE |

---

### EPIC CDF-07 — Data Classification

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-CLS-001 | En tant que pipeline, chaque event est classifié (Security, Fraud, Network, IAM, Compliance, Transaction) | HAUTE |
| US-CDF-CLS-002 | En tant que pipeline, la sensibilité et la criticité métier sont taguées | HAUTE |

---

### EPIC CDF-08 — Correlation Context Layer

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-CTX-001 | En tant que SIEM, je reçois les events avec contexte Identity, Business, Threat et historique agrégés | HAUTE |

---

### EPIC CDF-09 — Storage Layer

**Architecture tiered :**

| Tier | Durée | Usage |
|---|---|---|
| Hot | 30 jours | Recherche temps réel |
| Warm | 1 an | Investigation forensic |
| Cold | 10 ans+ | Compliance |

| ID | Exigence | Priorité |
|---|---|---|
| FR-CDF-STG-001 | Compression obligatoire | HAUTE |
| FR-CDF-STG-002 | Encryption at rest mandatory | HAUTE |
| FR-CDF-STG-003 | Option immutable storage | HAUTE |
| FR-CDF-STG-004 | Souveraineté des données | HAUTE |

---

### EPIC CDF-10 — Search Engine

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-SRC-001 | En tant qu'analyste, je fais une recherche full-text en temps réel | HAUTE |
| US-CDF-SRC-002 | En tant que threat hunter, j'utilise un query language SQL-like | HAUTE |
| US-CDF-SRC-003 | En tant qu'analyste, je sauvegarde mes requêtes favorites | MOYENNE |

---

### EPIC CDF-11 — Data Governance

| ID | Exigence | Priorité |
|---|---|---|
| FR-CDF-DGV-001 | Data lineage obligatoire | HAUTE |
| FR-CDF-DGV-002 | Data ownership tracé | HAUTE |
| FR-CDF-DGV-003 | Data masking pour données sensibles | HAUTE |

---

### EPIC CDF-12 — Retention

| ID | Exigence | Priorité |
|---|---|---|
| FR-CDF-RET-001 | Politique de rétention configurable par tenant | HAUTE |
| FR-CDF-RET-002 | Legal hold | HAUTE |
| FR-CDF-RET-003 | Suppression sécurisée | HAUTE |

---

### EPIC CDF-13 — Data Quality

| ID | Exigence | Priorité |
|---|---|---|
| FR-CDF-DQ-001 | Détection champs manquants | HAUTE |
| FR-CDF-DQ-002 | Détection events malformés | HAUTE |
| FR-CDF-DQ-003 | Quality score par source | MOYENNE |

---

### EPIC CDF-14 — Replay & Forensics

| ID | User Story | Priorité |
|---|---|---|
| US-CDF-FOR-001 | En tant qu'analyste, je rejoue des events pour reconstituer une timeline | HAUTE |
| US-CDF-FOR-002 | En tant qu'analyste, j'exporte les preuves pour forensic | HAUTE |

---

## Exigences non fonctionnelles

| Code | Exigence |
|---|---|
| NFR-CDF-001 | 100K EPS MVP |
| NFR-CDF-002 | Latence pipeline < 3 secondes |
| NFR-CDF-003 | Uptime 99.99% |
| NFR-CDF-004 | Scaling horizontal |
| NFR-CDF-005 | Zéro perte de données |

---

## APIs exposées

```
POST   /api/v1/events                    # Ingestion manuelle
GET    /api/v1/events/{id}
POST   /api/v1/connectors                # Création connecteur
GET    /api/v1/connectors
PUT    /api/v1/connectors/{id}
DELETE /api/v1/connectors/{id}
GET    /api/v1/connectors/{id}/health
POST   /api/v1/search                    # Query events
GET    /api/v1/search/saved
POST   /api/v1/replay                    # Replay stream
GET    /api/v1/schema                    # Cyber schema
GET    /api/v1/data/quality              # Quality report
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Streaming Bus (Kafka) + Ingestion Engine base | Pipeline temps réel actif |
| S02 | Connector Framework + connecteurs MVP (AD, Windows, Linux) | 3 connecteurs fonctionnels |
| S03 | Parsing Engine + Normalization | Events normalisés |
| S04 | Universal Cyber Schema + Data Classification | Schéma unifié |
| S05 | Enrichment Engine (Identity + Asset + Geo) | Events enrichis |
| S06 | Enrichment (Threat Intel + Business context) | Enrichissement complet |
| S07 | Storage Tiering (Hot/Warm/Cold) | Stockage structuré |
| S08 | Search Engine + Saved Queries | Recherche opérationnelle |
| S09 | Connectors banking (CBS, SWIFT) + OT | Sources critiques |
| S10 | Replay Engine + Forensics | Investigation opérationnelle |
| S11 | Data Governance + Retention + Quality | Conformité data |
| S12 | Tests de charge 100K EPS + NFR validation | Performance validée |
| S13-14 | (buffer) Optimisation + connecteurs supplémentaires | Couverture étendue |

---

## Critères d'acceptation globaux

- [ ] 100K EPS soutenu sans dégradation
- [ ] Pipeline latence < 3 secondes end-to-end
- [ ] Perte d'events < 0.001%
- [ ] Tous les events normalisés selon Universal Cyber Schema
- [ ] Enrichissement automatique Identity, Asset, Geo, Threat
- [ ] Connecteurs MVP opérationnels (18 connecteurs minimum)
- [ ] Storage tiering Hot/Warm/Cold fonctionnel
- [ ] Recherche full-text < 2 secondes sur 30 jours
- [ ] Replay d'events opérationnel pour forensic
- [ ] Data lineage tracé
