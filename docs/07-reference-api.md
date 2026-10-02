<!-- GÉNÉRÉ — ne pas modifier à la main.
     Régénérer : cd backend && make docs-api
     Source : les enregistrements de routes des services eux-mêmes. -->

# Référence API

> 477 routes sur 30 services.
> Dérivé du code, pas tenu à la main — voir `backend/scripts/gen-api-reference.py`.
> Conventions, enveloppe de réponse et codes d'erreur : [`06-api.md`](06-api.md).

Toutes les routes ci-dessous sont préfixées par `/api/v1` et exigent un JWT.
La colonne **Permission** donne ce que le RBAC vérifie ; `—` signifie qu'aucune
permission n'est exigée au-delà d'un jeton valide.

Chaque service expose en plus `GET /health`, sans authentification.

## Index

| Service | Port | Routes |
|---|---|---|
| [`apifw`](#apifw) | 8017 | 17 |
| [`asset`](#asset) | 8006 | 11 |
| [`attackpath`](#attackpath) | 8012 | 14 |
| [`audit`](#audit) | 8003 | 4 |
| [`collector`](#collector) | 8005 | 2 |
| [`compliance`](#compliance) | 8018 | 22 |
| [`copilot`](#copilot) | 8016 | 13 |
| [`cspm`](#cspm) | 8025 | 17 |
| [`dashboard`](#dashboard) | 8015 | 17 |
| [`dlp`](#dlp) | 8021 | 18 |
| [`dspm`](#dspm) | 8030 | 23 |
| [`easm`](#easm) | 8019 | 21 |
| [`fraud`](#fraud) | 8020 | 16 |
| [`identity`](#identity) | 8002 | 9 |
| [`iga`](#iga) | 8024 | 20 |
| [`ir`](#ir) | 8026 | 17 |
| [`knowledgegraph`](#knowledgegraph) | 8013 | 14 |
| [`mobile`](#mobile) | 8029 | 27 |
| [`netsec`](#netsec) | 8022 | 18 |
| [`notification`](#notification) | 8004 | 4 |
| [`ot`](#ot) | 8028 | 22 |
| [`pam`](#pam) | 8007 | 16 |
| [`risk`](#risk) | 8023 | 21 |
| [`scs`](#scs) | 8027 | 21 |
| [`siem`](#siem) | 8008 | 22 |
| [`soar`](#soar) | 8014 | 14 |
| [`tenant`](#tenant) | 8001 | 22 |
| [`ti`](#ti) | 8010 | 13 |
| [`ueba`](#ueba) | 8009 | 8 |
| [`vuln`](#vuln) | 8011 | 14 |

Sans API HTTP : `syslog` — voir [`09-ingestion.md`](09-ingestion.md).

---

## apifw

`:8017` · 17 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/apifw/keys` | `api_keys:read` |
| `POST` | `/api/v1/apifw/keys` | `api_keys:write` |
| `DELETE` | `/api/v1/apifw/keys/{keyID}` | `api_keys:write` |
| `GET` | `/api/v1/apifw/keys/{keyID}` | `api_keys:read` |
| `PATCH` | `/api/v1/apifw/keys/{keyID}` | `api_keys:write` |
| `POST` | `/api/v1/apifw/keys/{keyID}/rotate` | `api_keys:write` |
| `GET` | `/api/v1/apifw/keys/{keyID}/usage` | `api_keys:read` |
| `GET` | `/api/v1/apifw/stats` | `api_keys:read` |
| `GET` | `/api/v1/apifw/webhooks` | `api_keys:read` |
| `POST` | `/api/v1/apifw/webhooks` | `api_keys:write` |
| `DELETE` | `/api/v1/apifw/webhooks/{webhookID}` | `api_keys:write` |
| `GET` | `/api/v1/apifw/webhooks/{webhookID}` | `api_keys:read` |
| `PATCH` | `/api/v1/apifw/webhooks/{webhookID}` | `api_keys:write` |
| `GET` | `/api/v1/apifw/webhooks/{webhookID}/deliveries` | `api_keys:read` |
| `POST` | `/api/v1/apifw/webhooks/{webhookID}/disable` | `api_keys:write` |
| `POST` | `/api/v1/apifw/webhooks/{webhookID}/enable` | `api_keys:write` |
| `POST` | `/api/v1/apifw/webhooks/{webhookID}/test` | `api_keys:write` |

## asset

`:8006` · 11 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/assets` | `assets:read` |
| `POST` | `/api/v1/assets` | `assets:write` |
| `GET` | `/api/v1/assets/discovery` | `assets:read` |
| `GET` | `/api/v1/assets/risk-profile` | `assets:read` |
| `GET` | `/api/v1/assets/stats` | `assets:read` |
| `DELETE` | `/api/v1/assets/{assetID}` | `assets:write` |
| `GET` | `/api/v1/assets/{assetID}` | `assets:read` |
| `PUT` | `/api/v1/assets/{assetID}` | `assets:write` |
| `GET` | `/api/v1/assets/{assetID}/relationships` | `assets:read` |
| `POST` | `/api/v1/assets/{assetID}/relationships` | `assets:write` |
| `GET` | `/api/v1/assets/{assetID}/risk` | `assets:read` |

## attackpath

`:8012` · 14 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/attack/choke-points` | `attack_paths:read` |
| `GET` | `/api/v1/attack/edges` | `attack_paths:read` |
| `POST` | `/api/v1/attack/edges` | `attack_paths:write` |
| `GET` | `/api/v1/attack/nodes` | `attack_paths:read` |
| `POST` | `/api/v1/attack/nodes` | `attack_paths:write` |
| `GET` | `/api/v1/attack/nodes/{nodeID}` | `attack_paths:read` |
| `PUT` | `/api/v1/attack/nodes/{nodeID}/compromise` | `attack_paths:write` |
| `GET` | `/api/v1/attack/paths` | `attack_paths:read` |
| `GET` | `/api/v1/attack/paths/graph` | `attack_paths:read` |
| `GET` | `/api/v1/attack/scenarios` | `attack_paths:read` |
| `POST` | `/api/v1/attack/scenarios` | `attack_paths:write` |
| `GET` | `/api/v1/attack/scenarios/{scenarioID}` | `attack_paths:read` |
| `POST` | `/api/v1/attack/scenarios/{scenarioID}/run` | `attack_paths:write` |
| `GET` | `/api/v1/attack/stats` | `attack_paths:read` |

## audit

`:8003` · 4 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/audit/events` | `audit:read` |
| `POST` | `/api/v1/audit/events` | `audit:write` |
| `GET` | `/api/v1/audit/events/{id}` | `audit:read` |
| `POST` | `/api/v1/audit/export` | `audit:export` |

## collector

`:8005` · 2 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `POST` | `/api/v1/events/heartbeat` | `events:ingest` |
| `POST` | `/api/v1/events/ingest` | `events:ingest` |

## compliance

`:8018` · 22 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/compliance/assessments` | `compliance:read` |
| `POST` | `/api/v1/compliance/assessments` | `compliance:write` |
| `POST` | `/api/v1/compliance/assessments/auto` | `compliance:write` |
| `POST` | `/api/v1/compliance/assessments/bulk` | `compliance:write` |
| `GET` | `/api/v1/compliance/assessments/{assessmentID}` | `compliance:read` |
| `PATCH` | `/api/v1/compliance/assessments/{assessmentID}` | `compliance:write` |
| `GET` | `/api/v1/compliance/controls` | `compliance:read` |
| `POST` | `/api/v1/compliance/controls` | `compliance:write` |
| `GET` | `/api/v1/compliance/controls/{controlID}` | `compliance:read` |
| `GET` | `/api/v1/compliance/evidence` | `compliance:read` |
| `POST` | `/api/v1/compliance/evidence` | `compliance:write` |
| `GET` | `/api/v1/compliance/frameworks` | `compliance:read` |
| `POST` | `/api/v1/compliance/frameworks` | `compliance:write` |
| `GET` | `/api/v1/compliance/frameworks/{frameworkID}` | `compliance:read` |
| `POST` | `/api/v1/compliance/frameworks/{frameworkID}/activate` | `compliance:write` |
| `POST` | `/api/v1/compliance/frameworks/{frameworkID}/deactivate` | `compliance:write` |
| `GET` | `/api/v1/compliance/frameworks/{frameworkID}/score` | `compliance:read` |
| `GET` | `/api/v1/compliance/risks` | `compliance:read` |
| `POST` | `/api/v1/compliance/risks` | `compliance:write` |
| `GET` | `/api/v1/compliance/risks/{riskID}` | `compliance:read` |
| `PATCH` | `/api/v1/compliance/risks/{riskID}` | `compliance:write` |
| `GET` | `/api/v1/compliance/stats` | `compliance:read` |

## copilot

`:8016` · 13 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/copilot/hunt-jobs` | `copilot:read` |
| `POST` | `/api/v1/copilot/hunt-jobs` | `copilot:write` |
| `GET` | `/api/v1/copilot/hunt-jobs/{jobID}` | `copilot:read` |
| `GET` | `/api/v1/copilot/knowledge` | `copilot:read` |
| `POST` | `/api/v1/copilot/knowledge` | `copilot:write` |
| `DELETE` | `/api/v1/copilot/knowledge/{sourceType}/{sourceRef}` | `copilot:delete` |
| `GET` | `/api/v1/copilot/sessions` | `copilot:read` |
| `POST` | `/api/v1/copilot/sessions` | `copilot:write` |
| `GET` | `/api/v1/copilot/sessions/{sessionID}` | `copilot:read` |
| `POST` | `/api/v1/copilot/sessions/{sessionID}/chat` | `copilot:write` |
| `POST` | `/api/v1/copilot/sessions/{sessionID}/close` | `copilot:write` |
| `GET` | `/api/v1/copilot/sessions/{sessionID}/history` | `copilot:read` |
| `GET` | `/api/v1/copilot/stats` | `copilot:read` |

## cspm

`:8025` · 17 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/cspm/accounts` | `cspm:read` |
| `POST` | `/api/v1/cspm/accounts` | `cspm:write` |
| `GET` | `/api/v1/cspm/accounts/{accountID}` | `cspm:read` |
| `PATCH` | `/api/v1/cspm/accounts/{accountID}` | `cspm:write` |
| `GET` | `/api/v1/cspm/findings` | `cspm:read` |
| `POST` | `/api/v1/cspm/findings` | `cspm:write` |
| `PATCH` | `/api/v1/cspm/findings/{findingID}` | `cspm:write` |
| `GET` | `/api/v1/cspm/resources` | `cspm:read` |
| `POST` | `/api/v1/cspm/resources` | `cspm:write` |
| `GET` | `/api/v1/cspm/resources/{resourceID}` | `cspm:read` |
| `GET` | `/api/v1/cspm/rules` | `cspm:read` |
| `POST` | `/api/v1/cspm/rules` | `cspm:write` |
| `POST` | `/api/v1/cspm/rules/seed` | `cspm:write` |
| `GET` | `/api/v1/cspm/scans` | `cspm:read` |
| `POST` | `/api/v1/cspm/scans` | `cspm:write` |
| `GET` | `/api/v1/cspm/scans/{scanID}` | `cspm:read` |
| `GET` | `/api/v1/cspm/stats` | `cspm:read` |

## dashboard

`:8015` · 17 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/dashboard/dashboards` | `reports:read` |
| `POST` | `/api/v1/dashboard/dashboards` | `reports:write` |
| `DELETE` | `/api/v1/dashboard/dashboards/{dashID}` | `reports:write` |
| `GET` | `/api/v1/dashboard/dashboards/{dashID}` | `reports:read` |
| `PATCH` | `/api/v1/dashboard/dashboards/{dashID}` | `reports:write` |
| `POST` | `/api/v1/dashboard/dashboards/{dashID}/widgets` | `reports:write` |
| `GET` | `/api/v1/dashboard/kpi/risk-timeline` | `reports:read` |
| `GET` | `/api/v1/dashboard/kpi/snapshot` | `reports:read` |
| `GET` | `/api/v1/dashboard/kpi/timeseries` | `reports:read` |
| `GET` | `/api/v1/dashboard/overview` | `reports:read` |
| `GET` | `/api/v1/dashboard/reports` | `reports:read` |
| `POST` | `/api/v1/dashboard/reports` | `reports:write` |
| `DELETE` | `/api/v1/dashboard/reports/{reportID}` | `reports:write` |
| `GET` | `/api/v1/dashboard/reports/{reportID}` | `reports:read` |
| `POST` | `/api/v1/dashboard/reports/{reportID}/run` | `reports:write` |
| `DELETE` | `/api/v1/dashboard/widgets/{widgetID}` | `reports:write` |
| `PATCH` | `/api/v1/dashboard/widgets/{widgetID}` | `reports:write` |

## dlp

`:8021` · 18 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/dlp/assets` | `dlp:read` |
| `POST` | `/api/v1/dlp/assets` | `dlp:write` |
| `GET` | `/api/v1/dlp/assets/{assetID}` | `dlp:read` |
| `PATCH` | `/api/v1/dlp/assets/{assetID}` | `dlp:write` |
| `GET` | `/api/v1/dlp/labels` | `dlp:read` |
| `POST` | `/api/v1/dlp/labels` | `dlp:write` |
| `GET` | `/api/v1/dlp/labels/{labelID}` | `dlp:read` |
| `PATCH` | `/api/v1/dlp/labels/{labelID}` | `dlp:write` |
| `GET` | `/api/v1/dlp/policies` | `dlp:read` |
| `POST` | `/api/v1/dlp/policies` | `dlp:write` |
| `GET` | `/api/v1/dlp/policies/{policyID}` | `dlp:read` |
| `PATCH` | `/api/v1/dlp/policies/{policyID}` | `dlp:write` |
| `GET` | `/api/v1/dlp/scans` | `dlp:read` |
| `POST` | `/api/v1/dlp/scans` | `dlp:write` |
| `GET` | `/api/v1/dlp/stats` | `dlp:read` |
| `GET` | `/api/v1/dlp/violations` | `dlp:read` |
| `POST` | `/api/v1/dlp/violations` | `dlp:write` |
| `PATCH` | `/api/v1/dlp/violations/{violationID}` | `dlp:write` |

## dspm

`:8030` · 23 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/dspm/data-stores` | `dspm:read` |
| `POST` | `/api/v1/dspm/data-stores` | `dspm:write` |
| `DELETE` | `/api/v1/dspm/data-stores/{storeID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/data-stores/{storeID}` | `dspm:read` |
| `PATCH` | `/api/v1/dspm/data-stores/{storeID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/data-stores/{storeID}/scans` | `dspm:read` |
| `POST` | `/api/v1/dspm/data-stores/{storeID}/scans` | `dspm:write` |
| `GET` | `/api/v1/dspm/findings` | `dspm:read` |
| `POST` | `/api/v1/dspm/findings` | `dspm:write` |
| `GET` | `/api/v1/dspm/findings/{findingID}` | `dspm:read` |
| `PATCH` | `/api/v1/dspm/findings/{findingID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/policies` | `dspm:read` |
| `POST` | `/api/v1/dspm/policies` | `dspm:write` |
| `DELETE` | `/api/v1/dspm/policies/{policyID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/policies/{policyID}` | `dspm:read` |
| `PATCH` | `/api/v1/dspm/policies/{policyID}` | `dspm:write` |
| `POST` | `/api/v1/dspm/remediation` | `dspm:write` |
| `GET` | `/api/v1/dspm/remediation/item/{itemID}` | `dspm:read` |
| `PATCH` | `/api/v1/dspm/remediation/item/{itemID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/remediation/{findingID}` | `dspm:read` |
| `GET` | `/api/v1/dspm/scans/{jobID}` | `dspm:read` |
| `PATCH` | `/api/v1/dspm/scans/{jobID}` | `dspm:write` |
| `GET` | `/api/v1/dspm/stats` | `dspm:read` |

## easm

`:8019` · 21 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/easm/assets` | `easm:read` |
| `POST` | `/api/v1/easm/assets` | `easm:write` |
| `DELETE` | `/api/v1/easm/assets/{assetID}` | `easm:write` |
| `GET` | `/api/v1/easm/assets/{assetID}` | `easm:read` |
| `PUT` | `/api/v1/easm/assets/{assetID}` | `easm:write` |
| `GET` | `/api/v1/easm/brand-alerts` | `easm:read` |
| `POST` | `/api/v1/easm/brand-alerts` | `easm:write` |
| `GET` | `/api/v1/easm/brand-alerts/{alertID}` | `easm:read` |
| `PUT` | `/api/v1/easm/brand-alerts/{alertID}/status` | `easm:write` |
| `GET` | `/api/v1/easm/exposures` | `easm:read` |
| `POST` | `/api/v1/easm/exposures` | `easm:write` |
| `GET` | `/api/v1/easm/exposures/{exposureID}` | `easm:read` |
| `POST` | `/api/v1/easm/exposures/{exposureID}/remediate` | `easm:write` |
| `GET` | `/api/v1/easm/leaks` | `easm:read` |
| `POST` | `/api/v1/easm/leaks` | `easm:write` |
| `POST` | `/api/v1/easm/leaks/{leakID}/acknowledge` | `easm:write` |
| `GET` | `/api/v1/easm/risk-score` | `easm:read` |
| `GET` | `/api/v1/easm/scans` | `easm:read` |
| `POST` | `/api/v1/easm/scans` | `easm:write` |
| `GET` | `/api/v1/easm/scans/{scanID}` | `easm:read` |
| `GET` | `/api/v1/easm/stats` | `easm:read` |

## fraud

`:8020` · 16 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/fraud/cases` | `fraud:read` |
| `POST` | `/api/v1/fraud/cases` | `fraud:write` |
| `GET` | `/api/v1/fraud/cases/{caseID}` | `fraud:read` |
| `PATCH` | `/api/v1/fraud/cases/{caseID}` | `fraud:write` |
| `GET` | `/api/v1/fraud/rules` | `fraud:read` |
| `POST` | `/api/v1/fraud/rules` | `fraud:write` |
| `GET` | `/api/v1/fraud/rules/{ruleID}` | `fraud:read` |
| `PATCH` | `/api/v1/fraud/rules/{ruleID}` | `fraud:write` |
| `GET` | `/api/v1/fraud/stats` | `fraud:read` |
| `GET` | `/api/v1/fraud/transactions` | `fraud:read` |
| `POST` | `/api/v1/fraud/transactions/ingest` | `fraud:write` |
| `GET` | `/api/v1/fraud/transactions/{txnID}` | `fraud:read` |
| `PATCH` | `/api/v1/fraud/transactions/{txnID}/status` | `fraud:write` |
| `GET` | `/api/v1/fraud/watchlist` | `fraud:read` |
| `POST` | `/api/v1/fraud/watchlist` | `fraud:write` |
| `DELETE` | `/api/v1/fraud/watchlist/{entryID}` | `fraud:write` |

## identity

`:8002` · 9 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/identities/dormant` | `users:read` |
| `GET` | `/api/v1/identities/orphans` | `users:read` |
| `GET` | `/api/v1/identities/privileged` | `users:read` |
| `GET` | `/api/v1/users` | `users:read` |
| `POST` | `/api/v1/users` | `users:write` |
| `DELETE` | `/api/v1/users/{userID}` | `users:write` |
| `GET` | `/api/v1/users/{userID}` | `users:read` |
| `PUT` | `/api/v1/users/{userID}` | `users:write` |
| `GET` | `/api/v1/users/{userID}/risk` | `users:read` |

## iga

`:8024` · 20 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/iga/assignments` | `iga:read` |
| `POST` | `/api/v1/iga/assignments` | `iga:write` |
| `GET` | `/api/v1/iga/assignments/{assignmentID}` | `iga:read` |
| `PATCH` | `/api/v1/iga/assignments/{assignmentID}` | `iga:write` |
| `GET` | `/api/v1/iga/campaigns` | `iga:read` |
| `POST` | `/api/v1/iga/campaigns` | `iga:write` |
| `GET` | `/api/v1/iga/campaigns/{campaignID}` | `iga:read` |
| `POST` | `/api/v1/iga/campaigns/{campaignID}/launch` | `iga:write` |
| `GET` | `/api/v1/iga/reviews` | `iga:read` |
| `POST` | `/api/v1/iga/reviews/{itemID}/decision` | `iga:write` |
| `GET` | `/api/v1/iga/roles` | `iga:read` |
| `POST` | `/api/v1/iga/roles` | `iga:write` |
| `GET` | `/api/v1/iga/roles/{roleID}` | `iga:read` |
| `PATCH` | `/api/v1/iga/roles/{roleID}` | `iga:write` |
| `GET` | `/api/v1/iga/sod/policies` | `iga:read` |
| `POST` | `/api/v1/iga/sod/policies` | `iga:write` |
| `POST` | `/api/v1/iga/sod/scan` | `iga:write` |
| `GET` | `/api/v1/iga/sod/violations` | `iga:read` |
| `PATCH` | `/api/v1/iga/sod/violations/{violationID}` | `iga:write` |
| `GET` | `/api/v1/iga/stats` | `iga:read` |

## ir

`:8026` · 17 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/ir/incidents` | `incidents:read` |
| `POST` | `/api/v1/ir/incidents` | `incidents:write` |
| `GET` | `/api/v1/ir/incidents/{incidentID}` | `incidents:read` |
| `PATCH` | `/api/v1/ir/incidents/{incidentID}` | `incidents:write` |
| `GET` | `/api/v1/ir/incidents/{incidentID}/evidence` | `incidents:read` |
| `POST` | `/api/v1/ir/incidents/{incidentID}/evidence` | `incidents:write` |
| `PATCH` | `/api/v1/ir/incidents/{incidentID}/evidence/{evidenceID}` | `incidents:write` |
| `GET` | `/api/v1/ir/incidents/{incidentID}/tasks` | `incidents:read` |
| `POST` | `/api/v1/ir/incidents/{incidentID}/tasks` | `incidents:write` |
| `PATCH` | `/api/v1/ir/incidents/{incidentID}/tasks/{taskID}` | `incidents:write` |
| `GET` | `/api/v1/ir/incidents/{incidentID}/timeline` | `incidents:read` |
| `POST` | `/api/v1/ir/incidents/{incidentID}/timeline` | `incidents:write` |
| `GET` | `/api/v1/ir/playbooks` | `playbooks:read` |
| `POST` | `/api/v1/ir/playbooks` | `playbooks:write` |
| `GET` | `/api/v1/ir/playbooks/{playbookID}` | `playbooks:read` |
| `PATCH` | `/api/v1/ir/playbooks/{playbookID}` | `playbooks:write` |
| `GET` | `/api/v1/ir/stats` | `incidents:read` |

## knowledgegraph

`:8013` · 14 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/kg/enrich` | `knowledge_graph:read` |
| `GET` | `/api/v1/kg/entities` | `knowledge_graph:read` |
| `POST` | `/api/v1/kg/entities` | `knowledge_graph:write` |
| `GET` | `/api/v1/kg/entities/{entityID}` | `knowledge_graph:read` |
| `PATCH` | `/api/v1/kg/entities/{entityID}` | `knowledge_graph:write` |
| `GET` | `/api/v1/kg/entities/{entityID}/neighbors` | `knowledge_graph:read` |
| `GET` | `/api/v1/kg/entities/{entityID}/relationships` | `knowledge_graph:read` |
| `GET` | `/api/v1/kg/entities/{entityID}/timeline` | `knowledge_graph:read` |
| `POST` | `/api/v1/kg/observations` | `knowledge_graph:write` |
| `POST` | `/api/v1/kg/relationships` | `knowledge_graph:write` |
| `DELETE` | `/api/v1/kg/relationships/{relID}` | `knowledge_graph:write` |
| `GET` | `/api/v1/kg/relationships/{relID}` | `knowledge_graph:read` |
| `GET` | `/api/v1/kg/stats` | `knowledge_graph:read` |
| `GET` | `/api/v1/kg/subgraph` | `knowledge_graph:read` |

## mobile

`:8029` · 27 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `POST` | `/api/v1/mobile/actions` | `mobile:write` |
| `GET` | `/api/v1/mobile/actions/detail/{actionID}` | `mobile:read` |
| `PATCH` | `/api/v1/mobile/actions/{actionID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/actions/{deviceID}` | `mobile:read` |
| `GET` | `/api/v1/mobile/apps` | `mobile:read` |
| `POST` | `/api/v1/mobile/apps` | `mobile:write` |
| `GET` | `/api/v1/mobile/apps/{appID}` | `mobile:read` |
| `PATCH` | `/api/v1/mobile/apps/{appID}` | `mobile:write` |
| `POST` | `/api/v1/mobile/compliance/check` | `mobile:write` |
| `GET` | `/api/v1/mobile/compliance/{deviceID}` | `mobile:read` |
| `GET` | `/api/v1/mobile/devices` | `mobile:read` |
| `POST` | `/api/v1/mobile/devices` | `mobile:write` |
| `DELETE` | `/api/v1/mobile/devices/{deviceID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/devices/{deviceID}` | `mobile:read` |
| `PATCH` | `/api/v1/mobile/devices/{deviceID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/devices/{deviceID}/apps` | `mobile:read` |
| `POST` | `/api/v1/mobile/devices/{deviceID}/apps/{appID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/policies` | `mobile:read` |
| `POST` | `/api/v1/mobile/policies` | `mobile:write` |
| `DELETE` | `/api/v1/mobile/policies/{policyID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/policies/{policyID}` | `mobile:read` |
| `PATCH` | `/api/v1/mobile/policies/{policyID}` | `mobile:write` |
| `GET` | `/api/v1/mobile/stats` | `mobile:read` |
| `GET` | `/api/v1/mobile/threats` | `mobile:read` |
| `POST` | `/api/v1/mobile/threats` | `mobile:write` |
| `GET` | `/api/v1/mobile/threats/{threatID}` | `mobile:read` |
| `PATCH` | `/api/v1/mobile/threats/{threatID}` | `mobile:write` |

## netsec

`:8022` · 18 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/netsec/anomalies` | `netsec:read` |
| `POST` | `/api/v1/netsec/anomalies` | `netsec:write` |
| `PATCH` | `/api/v1/netsec/anomalies/{anomalyID}` | `netsec:write` |
| `GET` | `/api/v1/netsec/devices` | `netsec:read` |
| `POST` | `/api/v1/netsec/devices` | `netsec:write` |
| `PATCH` | `/api/v1/netsec/devices/{deviceID}` | `netsec:write` |
| `GET` | `/api/v1/netsec/flows` | `netsec:read` |
| `POST` | `/api/v1/netsec/flows` | `netsec:write` |
| `GET` | `/api/v1/netsec/policies` | `netsec:read` |
| `POST` | `/api/v1/netsec/policies` | `netsec:write` |
| `GET` | `/api/v1/netsec/policies/{policyID}` | `netsec:read` |
| `PATCH` | `/api/v1/netsec/policies/{policyID}` | `netsec:write` |
| `GET` | `/api/v1/netsec/stats` | `netsec:read` |
| `GET` | `/api/v1/netsec/topology` | `netsec:read` |
| `GET` | `/api/v1/netsec/zones` | `netsec:read` |
| `POST` | `/api/v1/netsec/zones` | `netsec:write` |
| `GET` | `/api/v1/netsec/zones/{zoneID}` | `netsec:read` |
| `PATCH` | `/api/v1/netsec/zones/{zoneID}` | `netsec:write` |

## notification

`:8004` · 4 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/notifications/rules` | `notifications:read` |
| `POST` | `/api/v1/notifications/rules` | `notifications:write` |
| `POST` | `/api/v1/notifications/send` | `notifications:write` |
| `POST` | `/api/v1/notifications/test` | `notifications:write` |

## ot

`:8028` · 22 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/ot/assets` | `ot_assets:read` |
| `POST` | `/api/v1/ot/assets` | `ot_assets:write` |
| `GET` | `/api/v1/ot/assets/{assetID}` | `ot_assets:read` |
| `PATCH` | `/api/v1/ot/assets/{assetID}` | `ot_assets:write` |
| `GET` | `/api/v1/ot/communications` | `ot_assets:read` |
| `POST` | `/api/v1/ot/communications` | `ot_assets:write` |
| `GET` | `/api/v1/ot/events` | `ot_assets:read` |
| `POST` | `/api/v1/ot/events` | `ot_assets:write` |
| `PATCH` | `/api/v1/ot/events/{eventID}` | `ot_assets:write` |
| `GET` | `/api/v1/ot/patches` | `ot_assets:read` |
| `POST` | `/api/v1/ot/patches` | `ot_assets:write` |
| `PATCH` | `/api/v1/ot/patches/{patchID}` | `ot_assets:write` |
| `GET` | `/api/v1/ot/policies` | `ot_assets:read` |
| `POST` | `/api/v1/ot/policies` | `ot_assets:write` |
| `PATCH` | `/api/v1/ot/policies/{policyID}` | `ot_assets:write` |
| `GET` | `/api/v1/ot/stats` | `ot_assets:read` |
| `GET` | `/api/v1/ot/vulnerabilities` | `ot_assets:read` |
| `POST` | `/api/v1/ot/vulnerabilities` | `ot_assets:write` |
| `PATCH` | `/api/v1/ot/vulnerabilities/{vulnID}` | `ot_assets:write` |
| `GET` | `/api/v1/ot/zones` | `ot_assets:read` |
| `POST` | `/api/v1/ot/zones` | `ot_assets:write` |
| `PATCH` | `/api/v1/ot/zones/{zoneID}` | `ot_assets:write` |

## pam

`:8007` · 16 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/pam/accounts` | `pam:read` |
| `POST` | `/api/v1/pam/accounts` | `pam:write` |
| `GET` | `/api/v1/pam/accounts/{accountID}` | `pam:read` |
| `GET` | `/api/v1/pam/identities/high-risk` | `pam:read` |
| `GET` | `/api/v1/pam/identities/{identityID}/risk` | `pam:read` |
| `GET` | `/api/v1/pam/identities/{identityID}/risk/breakdown` | `pam:read` |
| `GET` | `/api/v1/pam/requests` | `pam:read` |
| `POST` | `/api/v1/pam/requests` | `pam:write` |
| `GET` | `/api/v1/pam/requests/{requestID}` | `pam:read` |
| `POST` | `/api/v1/pam/requests/{requestID}/approve` | `pam:write` |
| `GET` | `/api/v1/pam/sessions` | `pam:read` |
| `POST` | `/api/v1/pam/sessions` | `pam:write` |
| `DELETE` | `/api/v1/pam/sessions/{sessionID}` | `pam:write` |
| `GET` | `/api/v1/pam/sessions/{sessionID}` | `pam:read` |
| `GET` | `/api/v1/pam/sessions/{sessionID}/events` | `pam:read` |
| `POST` | `/api/v1/pam/sessions/{sessionID}/events` | `pam:write` |

## risk

`:8023` · 21 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/risk/assessments` | `risk:read` |
| `POST` | `/api/v1/risk/assessments` | `risk:write` |
| `GET` | `/api/v1/risk/assessments/{assessmentID}` | `risk:read` |
| `GET` | `/api/v1/risk/assets` | `risk:read` |
| `POST` | `/api/v1/risk/assets` | `risk:write` |
| `GET` | `/api/v1/risk/assets/{assetID}` | `risk:read` |
| `PATCH` | `/api/v1/risk/assets/{assetID}` | `risk:write` |
| `GET` | `/api/v1/risk/kris` | `risk:read` |
| `POST` | `/api/v1/risk/kris` | `risk:write` |
| `GET` | `/api/v1/risk/kris/{kriID}` | `risk:read` |
| `GET` | `/api/v1/risk/kris/{kriID}/history` | `risk:read` |
| `POST` | `/api/v1/risk/kris/{kriID}/value` | `risk:write` |
| `GET` | `/api/v1/risk/scenarios` | `risk:read` |
| `POST` | `/api/v1/risk/scenarios` | `risk:write` |
| `GET` | `/api/v1/risk/scenarios/{scenarioID}` | `risk:read` |
| `PATCH` | `/api/v1/risk/scenarios/{scenarioID}` | `risk:write` |
| `GET` | `/api/v1/risk/stats` | `risk:read` |
| `GET` | `/api/v1/risk/treatments` | `risk:read` |
| `POST` | `/api/v1/risk/treatments` | `risk:write` |
| `GET` | `/api/v1/risk/treatments/{treatmentID}` | `risk:read` |
| `PATCH` | `/api/v1/risk/treatments/{treatmentID}` | `risk:write` |

## scs

`:8027` · 21 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/scs/alerts` | `supply_chain:read` |
| `POST` | `/api/v1/scs/alerts` | `supply_chain:write` |
| `PATCH` | `/api/v1/scs/alerts/{alertID}` | `supply_chain:write` |
| `GET` | `/api/v1/scs/assessments` | `supply_chain:read` |
| `POST` | `/api/v1/scs/assessments` | `supply_chain:write` |
| `PATCH` | `/api/v1/scs/assessments/{assessmentID}` | `supply_chain:write` |
| `GET` | `/api/v1/scs/components` | `supply_chain:read` |
| `POST` | `/api/v1/scs/components` | `supply_chain:write` |
| `GET` | `/api/v1/scs/components/{componentID}` | `supply_chain:read` |
| `PATCH` | `/api/v1/scs/components/{componentID}` | `supply_chain:write` |
| `GET` | `/api/v1/scs/policies` | `supply_chain:read` |
| `POST` | `/api/v1/scs/policies` | `supply_chain:write` |
| `PATCH` | `/api/v1/scs/policies/{policyID}` | `supply_chain:write` |
| `GET` | `/api/v1/scs/sboms` | `supply_chain:read` |
| `POST` | `/api/v1/scs/sboms` | `supply_chain:write` |
| `GET` | `/api/v1/scs/sboms/{sbomID}` | `supply_chain:read` |
| `GET` | `/api/v1/scs/stats` | `supply_chain:read` |
| `GET` | `/api/v1/scs/vendors` | `supply_chain:read` |
| `POST` | `/api/v1/scs/vendors` | `supply_chain:write` |
| `GET` | `/api/v1/scs/vendors/{vendorID}` | `supply_chain:read` |
| `PATCH` | `/api/v1/scs/vendors/{vendorID}` | `supply_chain:write` |

## siem

`:8008` · 22 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/siem/alerts` | `alerts:read` |
| `GET` | `/api/v1/siem/alerts/stats` | `alerts:read` |
| `PUT` | `/api/v1/siem/alerts/{alertID}` | `alerts:write` |
| `POST` | `/api/v1/siem/alerts/{alertID}/case` | `alerts:write` |
| `GET` | `/api/v1/siem/cases` | `incidents:read` |
| `POST` | `/api/v1/siem/cases` | `incidents:write` |
| `GET` | `/api/v1/siem/cases/{caseID}` | `incidents:read` |
| `PUT` | `/api/v1/siem/cases/{caseID}` | `incidents:write` |
| `GET` | `/api/v1/siem/cases/{caseID}/comments` | `incidents:read` |
| `POST` | `/api/v1/siem/cases/{caseID}/comments` | `incidents:write` |
| `POST` | `/api/v1/siem/cases/{caseID}/observables` | `incidents:write` |
| `GET` | `/api/v1/siem/rule-library` | `rules:read` |
| `GET` | `/api/v1/siem/rule-library/coverage` | `rules:read` |
| `GET` | `/api/v1/siem/rule-library/{code}` | `rules:read` |
| `POST` | `/api/v1/siem/rule-library/{code}/adopt` | `rules:write` |
| `GET` | `/api/v1/siem/rule-library/{code}/upgrade` | `rules:read` |
| `POST` | `/api/v1/siem/rule-library/{code}/upgrade` | `rules:write` |
| `GET` | `/api/v1/siem/rules` | `rules:read` |
| `POST` | `/api/v1/siem/rules` | `rules:write` |
| `DELETE` | `/api/v1/siem/rules/{ruleID}` | `rules:write` |
| `GET` | `/api/v1/siem/rules/{ruleID}` | `rules:read` |
| `PUT` | `/api/v1/siem/rules/{ruleID}` | `rules:write` |

## soar

`:8014` · 14 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/soar/executions` | `soar:read` |
| `GET` | `/api/v1/soar/executions/{executionID}` | `soar:read` |
| `GET` | `/api/v1/soar/incidents` | `soar:read` |
| `POST` | `/api/v1/soar/incidents` | `soar:write` |
| `GET` | `/api/v1/soar/incidents/{incidentID}` | `soar:read` |
| `PATCH` | `/api/v1/soar/incidents/{incidentID}` | `soar:write` |
| `GET` | `/api/v1/soar/incidents/{incidentID}/timeline` | `soar:read` |
| `GET` | `/api/v1/soar/playbooks` | `soar:read` |
| `POST` | `/api/v1/soar/playbooks` | `soar:write` |
| `GET` | `/api/v1/soar/playbooks/{playbookID}` | `soar:read` |
| `POST` | `/api/v1/soar/playbooks/{playbookID}/disable` | `soar:write` |
| `POST` | `/api/v1/soar/playbooks/{playbookID}/enable` | `soar:write` |
| `POST` | `/api/v1/soar/playbooks/{playbookID}/run` | `soar:write` |
| `GET` | `/api/v1/soar/stats` | `soar:read` |

## tenant

`:8001` · 22 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/attack-policies/active` | `attack_paths:read` |
| `PUT` | `/api/v1/attack-policies/active` | `attack_paths:write` |
| `GET` | `/api/v1/attack-policies/history` | `attack_paths:read` |
| `GET` | `/api/v1/attack-policies/presets` | `attack_paths:read` |
| `GET` | `/api/v1/behaviour-policies/active` | `ueba:read` |
| `PUT` | `/api/v1/behaviour-policies/active` | `ueba:write` |
| `GET` | `/api/v1/behaviour-policies/history` | `ueba:read` |
| `GET` | `/api/v1/behaviour-policies/presets` | `ueba:read` |
| `GET` | `/api/v1/remediation-policies/active` | `vulnerabilities:read` |
| `PUT` | `/api/v1/remediation-policies/active` | `vulnerabilities:write` |
| `GET` | `/api/v1/remediation-policies/history` | `vulnerabilities:read` |
| `GET` | `/api/v1/remediation-policies/presets` | `vulnerabilities:read` |
| `GET` | `/api/v1/risk-profiles/active` | `risk:read` |
| `PUT` | `/api/v1/risk-profiles/active` | `risk:write` |
| `GET` | `/api/v1/risk-profiles/history` | `risk:read` |
| `GET` | `/api/v1/risk-profiles/presets` | `risk:read` |
| `GET` | `/api/v1/tenants` | `tenants:read` |
| `POST` | `/api/v1/tenants` | `tenants:write` |
| `DELETE` | `/api/v1/tenants/{tenantID}` | `tenants:write` |
| `GET` | `/api/v1/tenants/{tenantID}` | `tenants:read` |
| `PUT` | `/api/v1/tenants/{tenantID}` | `tenants:write` |
| `GET` | `/api/v1/tenants/{tenantID}/stats` | `tenants:read` |

## ti

`:8010` · 13 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/ti/actors` | `threat_intel:read` |
| `POST` | `/api/v1/ti/actors` | `threat_intel:write` |
| `GET` | `/api/v1/ti/feeds` | `threat_intel:read` |
| `POST` | `/api/v1/ti/feeds` | `threat_intel:write` |
| `DELETE` | `/api/v1/ti/feeds/{feedID}` | `threat_intel:write` |
| `GET` | `/api/v1/ti/feeds/{feedID}` | `threat_intel:read` |
| `PUT` | `/api/v1/ti/feeds/{feedID}` | `threat_intel:write` |
| `GET` | `/api/v1/ti/hits` | `threat_intel:read` |
| `GET` | `/api/v1/ti/iocs` | `threat_intel:read` |
| `POST` | `/api/v1/ti/iocs` | `threat_intel:write` |
| `POST` | `/api/v1/ti/iocs/bulk` | `threat_intel:write` |
| `POST` | `/api/v1/ti/iocs/lookup` | `threat_intel:write` |
| `GET` | `/api/v1/ti/stats` | `threat_intel:read` |

## ueba

`:8009` · 8 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/ueba/anomalies` | `ueba:read` |
| `GET` | `/api/v1/ueba/anomalies/stats` | `ueba:read` |
| `PUT` | `/api/v1/ueba/anomalies/{anomalyID}` | `ueba:write` |
| `GET` | `/api/v1/ueba/entities/{entityID}/timeline` | `ueba:read` |
| `GET` | `/api/v1/ueba/peer-groups` | `ueba:read` |
| `POST` | `/api/v1/ueba/peer-groups` | `ueba:write` |
| `GET` | `/api/v1/ueba/profiles` | `ueba:read` |
| `GET` | `/api/v1/ueba/profiles/{entityID}` | `ueba:read` |

## vuln

`:8011` · 14 routes

| Méthode | Chemin | Permission |
|---|---|---|
| `GET` | `/api/v1/vuln/assets/{assetID}/exposure` | `vulnerabilities:read` |
| `GET` | `/api/v1/vuln/findings` | `vulnerabilities:read` |
| `POST` | `/api/v1/vuln/findings` | `vulnerabilities:write` |
| `POST` | `/api/v1/vuln/findings/bulk` | `vulnerabilities:write` |
| `PUT` | `/api/v1/vuln/findings/{findingID}` | `vulnerabilities:write` |
| `GET` | `/api/v1/vuln/scans` | `vulnerabilities:read` |
| `POST` | `/api/v1/vuln/scans` | `vulnerabilities:write` |
| `GET` | `/api/v1/vuln/stats` | `vulnerabilities:read` |
| `GET` | `/api/v1/vuln/tickets` | `vulnerabilities:read` |
| `POST` | `/api/v1/vuln/tickets` | `vulnerabilities:write` |
| `PUT` | `/api/v1/vuln/tickets/{ticketID}` | `vulnerabilities:write` |
| `GET` | `/api/v1/vuln/vulnerabilities` | `vulnerabilities:read` |
| `POST` | `/api/v1/vuln/vulnerabilities` | `vulnerabilities:write` |
| `GET` | `/api/v1/vuln/vulnerabilities/{vulnID}` | `vulnerabilities:read` |

