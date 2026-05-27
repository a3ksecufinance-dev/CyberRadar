# Domaine 10 — SOAR Lite (Security Orchestration, Automation & Response)

> Priorité : MOYENNE | Sprints : 6–8 | Dépendances : D4, D5, D6

---

## Objectif

Orchestrer et automatiser la réponse aux incidents cyber.
Passer d'un modèle de playbooks statiques à une orchestration adaptative basée sur le contexte, la criticité et le risk score.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| SOR-01 | Playbook Engine |
| SOR-02 | Action Library |
| SOR-03 | Workflow Automation |
| SOR-04 | Response Orchestration |
| SOR-05 | Approval Workflow |
| SOR-06 | Integration Connectors (SOAR) |
| SOR-07 | Response Metrics |

---

## Epics & User Stories MVP

### EPIC SOR-01 — Playbook Engine

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-PLY-001 | En tant d'admin, je crée des playbooks visuellement (drag & drop) | HAUTE |
| US-SOR-PLY-002 | En tant de système, un playbook se déclenche automatiquement sur condition (alerte + score seuil) | HAUTE |
| US-SOR-PLY-003 | En tant d'admin, les playbooks sont versionnés et rollbackables | HAUTE |
| US-SOR-PLY-004 | En tant d'admin, je teste un playbook en mode simulation avant déploiement | HAUTE |

**Playbooks MVP pré-chargés :**
```
- Compte compromis → Désactiver + notifier + forcer reset
- Ransomware detected → Isoler endpoint + snapshot + alerter CISO
- Insider threat → Surveiller + notifier RH + step-up MFA
- CBS anomaly → Notifier équipe fraude + geler transaction
- Brute force → Bloquer IP + alerter SOC
- New admin account → Notifier + déclencher investigation
- Data exfiltration → Bloquer sortie + collecter preuves
```

---

### EPIC SOR-02 — Action Library

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-ACT-001 | En tant d'analyste, je dispose d'une bibliothèque d'actions pré-intégrées | HAUTE |

**Actions disponibles MVP :**
```
Identity   : disable_account, reset_password, revoke_token, enforce_mfa, elevate_risk
Network    : block_ip, quarantine_asset, update_firewall_rule
Endpoint   : isolate_endpoint, kill_process, collect_forensics, snapshot
Ticket     : create_ticket, assign_to_analyst, update_status
Notify     : email, sms, slack, teams, webhook
SOAR       : run_playbook, trigger_scan
```

---

### EPIC SOR-03 — Workflow Automation

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-WFL-001 | En tant de système, le workflow décide de l'action selon : criticité + business impact + confidence score | HAUTE |
| US-SOR-WFL-002 | En tant de système, les actions à faible risque s'exécutent automatiquement | HAUTE |
| US-SOR-WFL-003 | En tant de système, les actions à haut risque demandent une approbation humaine | HAUTE |

---

### EPIC SOR-04 — Response Orchestration

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-ORC-001 | En tant de système, la réponse est adaptative (pas seulement des règles statiques) | HAUTE |
| US-SOR-ORC-002 | En tant d'analyste, je vois toutes les actions exécutées et leur résultat | HAUTE |
| US-SOR-ORC-003 | En tant d'analyste, je peux annuler une action automatique (rollback) | HAUTE |

---

### EPIC SOR-05 — Approval Workflow

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-APR-001 | En tant d'analyste L2, je reçois une demande d'approbation pour les actions critiques | HAUTE |
| US-SOR-APR-002 | En tant d'admin, je configure les seuils d'approbation par type d'action | HAUTE |
| US-SOR-APR-003 | En tant d'analyste, si personne n'approuve en X minutes, l'escalade est automatique | HAUTE |

---

### EPIC SOR-06 — Integration Connectors (SOAR)

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-INT-001 | En tant d'admin, le SOAR est intégré avec Active Directory pour disable_account | HAUTE |
| US-SOR-INT-002 | En tant d'admin, le SOAR est intégré avec le firewall pour bloquer IP | HAUTE |
| US-SOR-INT-003 | En tant d'admin, le SOAR est intégré avec l'EDR pour isoler un endpoint | HAUTE |
| US-SOR-INT-004 | En tant d'admin, le SOAR crée des tickets dans ServiceNow/Jira | HAUTE |
| US-SOR-INT-005 | En tant d'admin, le SOAR est intégré avec le PAM pour révoquer sessions | HAUTE |

---

### EPIC SOR-07 — Response Metrics

| ID | User Story | Priorité |
|---|---|---|
| US-SOR-MTR-001 | En tant de CISO, je vois le MTTR en temps réel | HAUTE |
| US-SOR-MTR-002 | En tant d'admin, je vois le taux d'automatisation des réponses | HAUTE |
| US-SOR-MTR-003 | En tant d'admin, je vois les actions les plus fréquentes et leur efficacité | MOYENNE |

---

## APIs exposées

```
GET    /api/v1/soar/playbooks                  # Liste playbooks
POST   /api/v1/soar/playbooks                  # Création
PUT    /api/v1/soar/playbooks/{id}
POST   /api/v1/soar/playbooks/{id}/execute     # Exécution manuelle
POST   /api/v1/soar/playbooks/{id}/simulate    # Simulation
GET    /api/v1/soar/actions                    # Bibliothèque actions
POST   /api/v1/soar/actions/execute            # Action manuelle
GET    /api/v1/soar/executions                 # Historique exécutions
POST   /api/v1/soar/approvals/{id}/approve     # Approbation
POST   /api/v1/soar/approvals/{id}/reject
GET    /api/v1/soar/metrics                    # Métriques MTTR
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Playbook Engine (éditeur visuel) | Création playbooks |
| S02 | Action Library (Identity + Network + Notify) | Actions de base |
| S03 | Workflow Automation + Approval | Orchestration adaptative |
| S04 | Playbooks banking pré-chargés (CBS, compte compromis) | Playbooks MVP |
| S05 | Integration Connectors (AD, Firewall, EDR, Ticketing) | Intégrations |
| S06 | Response Metrics + MTTR Dashboard | Métriques |
| S07-08 | (buffer) Tests bout-en-bout + rollback | Sécurité actions |

---

## Critères d'acceptation

- [ ] Éditeur de playbooks visuels opérationnel
- [ ] 7 playbooks MVP pré-chargés (incluant banking)
- [ ] Actions automatiques < 30 secondes après déclenchement
- [ ] Approval workflow pour actions critiques
- [ ] MTTR < 15 minutes validé en test
- [ ] Rollback d'actions disponible
- [ ] Intégration AD, Firewall, EDR, PAM, Ticketing
