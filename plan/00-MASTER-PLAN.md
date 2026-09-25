# Cyber Radar Platform (CRP) — Master Plan

> Version : 1.0 | Date : 2026-05-23 | Statut : Initial

---

## 1. Vue d'ensemble

| Attribut | Valeur |
|---|---|
| Produit | Cyber Radar Platform (CRP) |
| Type | Plateforme souveraine de cybersécurité next-gen |
| Cible | Banques, assurances, gouvernements, infrastructures critiques |
| Livraison MVP | Domaines 0 → 14 |
| Répertoire | `/Users/msp/CyberRadar` |

---

## 2. KPIs cibles

| Métrique | Objectif |
|---|---|
| MTTD | < 5 minutes |
| MTTR | < 15 minutes |
| Réduction faux positifs | -70% |
| Couverture actifs | 100% automatique |
| Disponibilité | 99.99% |
| Débit MVP | 100K EPS |
| Débit cible | 1M+ EPS |
| Latence API | < 200ms |

---

## 3. Architecture technique retenue

```
Pattern : Event-driven microservices + polyglot persistence
```

| Moteur | Technologie | Usage |
|---|---|---|
| Event Store | ClickHouse | SIEM, XDR, corrélation temps réel |
| Graph DB | Neo4j | Attack Path, Identity Graph, Digital Twin |
| SQL DB | PostgreSQL | RBAC, SOAR, config, incidents, tickets |
| Vector DB | pgvector / Qdrant | AI Copilot, RAG cyber, hunting |
| Streaming | Apache Kafka | Pipeline événements, streaming bus |
| API Gateway | Kong / custom | Rate limiting, JWT, REST/GraphQL |
| Observabilité | OpenTelemetry + Grafana | Métriques, traces, logs plateforme |
| Secrets | HashiCorp Vault | API keys, tokens, credentials |
| Identité | Keycloak | SSO, OIDC, SAML, MFA |

### Modèle Graph central (6 nœuds)
```
Identity → Asset → Privilege → Session → Context → Business Service
```

---

## 4. Roadmap globale MVP

```
Phase 1 — Socle (Domaines 0-1)         : ~20-22 sprints
Phase 2 — Visibilité (Domaines 2-3)    : ~16-18 sprints
Phase 3 — Détection (Domaines 4-7)     : ~20-24 sprints
Phase 4 — Intelligence (Domaines 8-10) : ~16-20 sprints
Phase 5 — Delivery (Domaines 11-14)    : ~12-16 sprints
```

---

## 5. Structure des domaines MVP

| # | Domaine | Sprints | Priorité | Dépendances |
|---|---|---|---|---|
| D0 | Foundation Platform | 6–8 | CRITIQUE | — |
| D1 | Cyber Data Fabric | 10–14 | CRITIQUE | D0 |
| D2 | Cyber Asset Intelligence | 8–12 | HAUTE | D0, D1 |
| D3 | Identity & PAM Intelligence | 6–8 | HAUTE | D0, D1, D2 |
| D4 | Detection SIEM/XDR Core | 8–10 | HAUTE | D0, D1 |
| D5 | UEBA++ | 6–8 | HAUTE | D1, D2, D3, D4 |
| D6 | Threat Intelligence | 6–8 | MOYENNE | D0, D1 |
| D7 | Vulnerability & Exposure Intelligence | 6–8 | MOYENNE | D2 |
| D8 | Attack Path Analytics | 6–8 | HAUTE | D2, D3 |
| D9 | Cyber Knowledge Graph | 6–8 | HAUTE | D2, D3, D4, D5 |
| D10 | SOAR Lite | 6–8 | MOYENNE | D4, D5, D6 |
| D11 | Dashboards & War Room | 4–6 | MOYENNE | D4, D5, D9 |
| D12 | AI Copilot Lite | 6–8 | BASSE | D9, D11 |
| D13 | API & Integration Framework | 4–6 | HAUTE | D0 |
| D14 | Security & Compliance | 4–6 | HAUTE | D0, D4 |

---

## 6. Hors MVP (V2/V3)

| Module | Phase |
|---|---|
| Fraud Fusion Intelligence | V2 |
| Predictive Attack AI | V2 |
| Autonomous Response | V2 |
| Digital Twin avancé | V3 |
| Cyber Risk Quantification | V3 |

---

## 7. Index des fichiers du plan

| Fichier | Contenu |
|---|---|
| `00-MASTER-PLAN.md` | Ce fichier — vue globale |
| `01-D0-Foundation.md` | Backlog Domaine 0 |
| `02-D1-CyberDataFabric.md` | Backlog Domaine 1 |
| `03-D2-AssetIntelligence.md` | Backlog Domaine 2 |
| `04-D3-IdentityPAM.md` | Backlog Domaine 3 |
| `05-D4-SIEM-XDR.md` | Backlog Domaine 4 |
| `06-D5-UEBA.md` | Backlog Domaine 5 |
| `07-D6-ThreatIntelligence.md` | Backlog Domaine 6 |
| `08-D7-VulnerabilityExposure.md` | Backlog Domaine 7 |
| `09-D8-AttackPath.md` | Backlog Domaine 8 |
| `10-D9-KnowledgeGraph.md` | Backlog Domaine 9 |
| `11-D10-SOAR.md` | Backlog Domaine 10 |
| `12-D11-Dashboards.md` | Backlog Domaine 11 |
| `13-D12-AICopilot.md` | Backlog Domaine 12 |
| `14-D13-APIFramework.md` | Backlog Domaine 13 |
| `15-D14-SecurityCompliance.md` | Backlog Domaine 14 |
| `16-TECH-STACK.md` | Stack technique détaillée |
| `17-DATA-MODEL.md` | Modèles de données |
| `18-API-CATALOG.md` | Catalogue APIs |
| `19-AUDIT-AND-ROADMAP.md` | Audit de code & roadmap production (Phase 0→4) |
