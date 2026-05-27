# Domaine 0 — Foundation Platform

> Priorité : CRITIQUE | Sprints : 6–8 | Dépendances : aucune

---

## Objectif

Socle technique, fonctionnel et sécuritaire de toute la plateforme CRP.
Sans ce domaine, aucun module cyber ne peut fonctionner.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| FND-01 | Tenant Management |
| FND-02 | Identity & Access Management |
| FND-03 | RBAC / ABAC |
| FND-04 | Authentication & Federation |
| FND-05 | Secrets Management |
| FND-06 | Configuration Management |
| FND-07 | Audit & Traceability |
| FND-08 | Notifications |
| FND-09 | API Gateway |
| FND-10 | Service Registry |
| FND-11 | Observability |
| FND-12 | Feature Flags |
| FND-13 | Licensing & Subscription |
| FND-14 | Plugin Framework |

---

## Epics & User Stories MVP

### EPIC FND-01 — Tenant Management

**Objectif :** Isolation stricte multi-tenant (single / multi / MSSP)

| ID | User Story | Priorité | Critères d'acceptation |
|---|---|---|---|
| US-FND-TNT-001 | En tant qu'admin, je peux créer un tenant avec ses propres données, configs et politiques | HAUTE | Isolation validée, aucune fuite entre tenants |
| US-FND-TNT-002 | En tant qu'admin MSSP, je peux gérer des tenants parents/enfants | HAUTE | Hiérarchie parent-child fonctionnelle |
| US-FND-TNT-003 | En tant qu'admin, je peux segmenter les tenants par BU ou région | MOYENNE | Segmentation effective |
| US-FND-TNT-004 | En tant qu'admin, je peux activer cross-tenant analytics en opt-in | BASSE | Agrégation cross-tenant sans fuite |

**Exigences :**
- `FR-FND-TNT-001` : Support multi-tenant
- `FR-FND-TNT-002` : Isolation complète (users, configs, données, politiques, connecteurs)
- `FR-FND-TNT-003` : Modèle MSSP parent/child
- `FR-FND-TNT-004` : Tenant segmentation
- `FR-FND-TNT-005` : Cross-tenant analytics optionnel

---

### EPIC FND-02 — Identity Management

**Objectif :** Gestion centralisée des identités plateforme

| ID | User Story | Priorité | Critères d'acceptation |
|---|---|---|---|
| US-FND-IDM-001 | En tant qu'utilisateur, je peux me connecter via AD/LDAP/SAML/OIDC/OAuth2 | HAUTE | Fédération multi-protocole fonctionnelle |
| US-FND-IDM-002 | En tant qu'admin, je peux provisionner/déprovisionner des comptes automatiquement | HAUTE | SCIM ou équivalent opérationnel |
| US-FND-IDM-003 | En tant qu'admin, je peux gérer les groupes et service accounts | HAUTE | Groupes et comptes de service isolés par tenant |
| US-FND-IDM-004 | En tant que système, je peux scorer le risque d'une identité | HAUTE | RiskScore calculé en temps réel |

**Modèle de données User :**
```
User {
  UserID, Name, Email, Department,
  Role, Status, TenantID,
  MFAEnabled, RiskScore
}
```

---

### EPIC FND-03 — RBAC / ABAC

**Objectif :** Contrôle d'accès granulaire

**Rôles standards :**
```
Super Admin | Tenant Admin | SOC Analyst L1/L2
Threat Hunter | Incident Responder | Fraud Analyst
Compliance Officer | Auditor | CISO | Executive Viewer
```

| ID | User Story | Priorité |
|---|---|---|
| US-FND-RBAC-001 | En tant qu'admin, je configure des rôles avec permissions granulaires | HAUTE |
| US-FND-RBAC-002 | En tant que SOC L1, je vois les alertes mais ne peux pas modifier les connecteurs | HAUTE |
| US-FND-RBAC-003 | En tant que système, j'applique ABAC par BU/région/criticité/sensibilité | HAUTE |
| US-FND-RBAC-004 | En tant qu'admin, je peux élever des privilèges just-in-time | MOYENNE |

---

### EPIC FND-04 — Authentication & Federation

| ID | User Story | Priorité |
|---|---|---|
| US-FND-AUTH-001 | En tant qu'utilisateur, je m'authentifie avec MFA (TOTP/FIDO2/Push/Smart card) | HAUTE |
| US-FND-AUTH-002 | En tant qu'utilisateur, je bénéficie du SSO | HAUTE |
| US-FND-AUTH-003 | En tant que système, j'applique une auth adaptative selon le risque contexte | HAUTE |
| US-FND-AUTH-004 | En tant qu'utilisateur depuis un pays inhabituel, je reçois un step-up MFA | HAUTE |

---

### EPIC FND-05 — Secrets Management

| ID | User Story | Priorité |
|---|---|---|
| US-FND-SEC-001 | En tant que connecteur, j'accède aux credentials via vault (jamais en clair) | HAUTE |
| US-FND-SEC-002 | En tant qu'admin, je configure la rotation automatique des secrets | HAUTE |
| US-FND-SEC-003 | En tant qu'auditeur, j'audite tout accès aux secrets | HAUTE |

---

### EPIC FND-06 — Configuration Management

| ID | User Story | Priorité |
|---|---|---|
| US-FND-CFG-001 | En tant qu'admin, je gère toute la config depuis une interface centralisée | HAUTE |
| US-FND-CFG-002 | En tant qu'admin, je peux rollback une configuration | HAUTE |
| US-FND-CFG-003 | En tant que système, je détecte les drifts de configuration | MOYENNE |

---

### EPIC FND-07 — Audit & Traceability

**Critique — tout doit être tracé**

| ID | User Story | Priorité |
|---|---|---|
| US-FND-AUD-001 | En tant qu'auditeur, je vois toutes les actions avec horodatage UTC | HAUTE |
| US-FND-AUD-002 | En tant qu'auditeur, les logs sont immuables | HAUTE |
| US-FND-AUD-003 | En tant qu'auditeur, je recherche : "Qui a changé telle règle de corrélation ?" | HAUTE |
| US-FND-AUD-004 | En tant qu'auditeur, j'exporte les preuves forensic | MOYENNE |

**Événements audités :**
```
login | logout | privilege escalation | config change
connector change | alert suppression | policy update | secret access
```

---

### EPIC FND-08 — Notifications

| ID | User Story | Priorité |
|---|---|---|
| US-FND-NOT-001 | En tant qu'analyste, je reçois des alertes par Email/SMS/Teams/Slack/Webhook | HAUTE |
| US-FND-NOT-002 | En tant qu'admin, je configure des règles d'escalade automatique | HAUTE |
| US-FND-NOT-003 | En tant qu'admin, je personnalise les templates de notification | MOYENNE |

---

### EPIC FND-09 — API Gateway

| ID | User Story | Priorité |
|---|---|---|
| US-FND-API-001 | En tant que développeur, j'accède à 100% des fonctionnalités via API REST | HAUTE |
| US-FND-API-002 | En tant que développeur, je peux utiliser GraphQL pour les queries complexes | MOYENNE |
| US-FND-API-003 | En tant que système externe, je m'intègre via Webhooks | HAUTE |
| US-FND-API-004 | En tant qu'admin, je configure le rate limiting par tenant | HAUTE |

---

### EPIC FND-10 — Service Registry

| ID | User Story | Priorité |
|---|---|---|
| US-FND-SVC-001 | En tant que plateforme, les services se découvrent automatiquement | HAUTE |
| US-FND-SVC-002 | En tant qu'admin, je visualise la santé de chaque service | HAUTE |

---

### EPIC FND-11 — Observability

| ID | User Story | Priorité |
|---|---|---|
| US-FND-OBS-001 | En tant qu'ops, je surveille les métriques plateforme en temps réel | HAUTE |
| US-FND-OBS-002 | En tant qu'ops, je trace les requêtes distribuées | HAUTE |
| US-FND-OBS-003 | En tant qu'admin, je consulte un health dashboard centralisé | HAUTE |

---

### EPIC FND-12 — Feature Flags

| ID | User Story | Priorité |
|---|---|---|
| US-FND-FFT-001 | En tant qu'admin, j'active/désactive des features par tenant | MOYENNE |
| US-FND-FFT-002 | En tant qu'admin, je déploie en canary release | BASSE |

---

## Exigences non fonctionnelles

| Code | Exigence |
|---|---|
| NFR-FND-001 | Disponibilité 99.99% |
| NFR-FND-002 | Scalabilité horizontale |
| NFR-FND-003 | Zero downtime upgrade |
| NFR-FND-004 | Recovery < 15 min |
| NFR-FND-005 | Latence API < 200ms |

## Sécurité obligatoire

| Code | Exigence |
|---|---|
| SEC-FND-001 | TLS 1.3 obligatoire |
| SEC-FND-002 | Zero Trust mandatory |
| SEC-FND-003 | PAM obligatoire pour admins |
| SEC-FND-004 | Encryption AES-256 |
| SEC-FND-005 | SBOM mandatory |

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Tenant Management + Base IAM | Multi-tenant fonctionnel |
| S02 | RBAC/ABAC + Auth MFA/SSO | Contrôle d'accès complet |
| S03 | Secrets Vault + Config Management | Secrets sécurisés |
| S04 | Audit Logs (immuables) + Notifications | Traçabilité complète |
| S05 | API Gateway + Service Registry | API 100% exposée |
| S06 | Observability + Feature Flags | Health dashboard |
| S07 | Tests d'intégration + Security hardening | Foundation validée |
| S08 | (buffer) Performance + NFR validation | NFR atteints |

---

## APIs exposées

```
POST   /api/v1/tenants
GET    /api/v1/tenants/{id}
POST   /api/v1/users
GET    /api/v1/users/{id}
POST   /api/v1/roles
GET    /api/v1/permissions
POST   /api/v1/audit/events
GET    /api/v1/audit/events
POST   /api/v1/notifications
GET    /api/v1/health
GET    /api/v1/services
```

---

## Critères d'acceptation globaux

- [ ] Isolation tenant validée — aucune fuite de données
- [ ] MFA fonctionnel sur tous les canaux (TOTP, FIDO2, Push)
- [ ] SSO fonctionnel (SAML, OIDC, LDAP, AD)
- [ ] Tous les accès loggés et immuables
- [ ] API Gateway avec JWT, rate limiting, documentation OpenAPI
- [ ] Latence API < 200ms sous charge
- [ ] Disponibilité 99.99% validée en test
- [ ] TLS 1.3 activé sur tous les endpoints
- [ ] Secrets jamais en clair dans les logs ni configs
