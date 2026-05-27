# Domaine 13 — API & Integration Framework

> Priorité : HAUTE | Sprints : 4–6 | Dépendances : D0

---

## Objectif

Exposer 100% des capacités de la plateforme via des APIs standardisées.
Fournir un framework d'intégration universel pour connecter CRP à l'écosystème bancaire existant.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| API-01 | API Gateway Central |
| API-02 | Developer Portal |
| API-03 | Webhook Framework |
| API-04 | SDK & Libraries |
| API-05 | Integration Templates |
| API-06 | API Security |

---

## Epics & User Stories MVP

### EPIC API-01 — API Gateway Central

| ID | User Story | Priorité |
|---|---|---|
| US-API-GW-001 | En tant de développeur, toutes les APIs sont accessibles depuis un point d'entrée unique | HAUTE |
| US-API-GW-002 | En tant de développeur, les APIs respectent REST (JSON) avec versioning /v1, /v2 | HAUTE |
| US-API-GW-003 | En tant d'admin, je configure le rate limiting par tenant et par endpoint | HAUTE |
| US-API-GW-004 | En tant de développeur, je m'authentifie via JWT ou API Key | HAUTE |
| US-API-GW-005 | En tant d'admin, je monitore l'usage des APIs en temps réel | HAUTE |

---

### EPIC API-02 — Developer Portal

| ID | User Story | Priorité |
|---|---|---|
| US-API-DEV-001 | En tant de développeur, j'accède à la documentation OpenAPI (Swagger) complète | HAUTE |
| US-API-DEV-002 | En tant de développeur, je teste les APIs depuis le portail (Try It) | HAUTE |
| US-API-DEV-003 | En tant de développeur, je génère des API Keys depuis le portail | HAUTE |

---

### EPIC API-03 — Webhook Framework

| ID | User Story | Priorité |
|---|---|---|
| US-API-WHK-001 | En tant d'admin, je configure des webhooks sortants sur événements (alerte créée, incident mis à jour) | HAUTE |
| US-API-WHK-002 | En tant de système, les webhooks ont un mécanisme de retry automatique | HAUTE |
| US-API-WHK-003 | En tant d'admin, je vois le statut de livraison de chaque webhook | HAUTE |

---

### EPIC API-04 — SDK & Libraries

| ID | User Story | Priorité |
|---|---|---|
| US-API-SDK-001 | En tant de développeur, j'utilise un SDK Python pour interagir avec CRP | MOYENNE |
| US-API-SDK-002 | En tant de développeur, j'utilise un SDK JavaScript/TypeScript | MOYENNE |
| US-API-SDK-003 | En tant de développeur, le SDK gère l'auth, le retry et la pagination | MOYENNE |

---

### EPIC API-05 — Integration Templates

| ID | User Story | Priorité |
|---|---|---|
| US-API-TPL-001 | En tant d'admin, je dispose de templates d'intégration pré-configurés pour les systèmes courants | HAUTE |

**Templates MVP :**
```
- ServiceNow (tickets incidents)
- Jira (issues)
- Slack (notifications)
- Microsoft Teams (notifications)
- PagerDuty (alerting)
- Splunk (export logs)
- QRadar (migration SIEM)
- CBS custom integration
```

---

### EPIC API-06 — API Security

| ID | Exigence | Priorité |
|---|---|---|
| FR-API-SEC-001 | JWT obligatoire sur toutes les APIs | HAUTE |
| FR-API-SEC-002 | HTTPS/TLS 1.3 obligatoire | HAUTE |
| FR-API-SEC-003 | Rate limiting pour prévenir les abus | HAUTE |
| FR-API-SEC-004 | Audit de tous les appels API | HAUTE |
| FR-API-SEC-005 | CORS configuré correctement | HAUTE |
| FR-API-SEC-006 | Pas de secrets dans les URLs | HAUTE |

---

## Catalogue APIs global (résumé)

```
Foundation      : /api/v1/tenants, /users, /roles, /audit
Data Fabric     : /api/v1/events, /connectors, /search, /replay
Asset Intel     : /api/v1/assets, /discovery, /dependencies
Identity        : /api/v1/identities, /pam/sessions
Detection       : /api/v1/alerts, /incidents, /rules, /cases
UEBA            : /api/v1/ueba/*
Threat Intel    : /api/v1/cti/*
Vulnerability   : /api/v1/vulnerabilities, /exposure
Attack Path     : /api/v1/attack-paths
Graph           : /api/v1/graph/*, /graphql
SOAR            : /api/v1/soar/*
Dashboards      : /api/v1/dashboards, /reports
AI Copilot      : /api/v1/copilot/*
Health          : /api/v1/health, /metrics
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | API Gateway central + Auth JWT | Authentification |
| S02 | Developer Portal + OpenAPI | Documentation |
| S03 | Webhook Framework | Webhooks sortants |
| S04 | Integration Templates (ServiceNow, Slack, Teams) | Intégrations |
| S05 | SDK Python + JS | SDKs |
| S06 | (buffer) Security audit APIs | APIs sécurisées |

---

## Critères d'acceptation

- [ ] 100% des fonctionnalités exposées via API
- [ ] Documentation OpenAPI complète (Swagger)
- [ ] JWT + TLS 1.3 sur tous les endpoints
- [ ] Rate limiting configuré
- [ ] Webhooks avec retry opérationnels
- [ ] Templates d'intégration ServiceNow, Slack, Teams
