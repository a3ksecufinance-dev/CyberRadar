# Domaine 12 — AI Copilot Lite

> Priorité : BASSE (MVP) | Sprints : 6–8 | Dépendances : D9, D11

---

## Objectif

Assistant IA conversationnel spécialisé en cybersécurité bancaire.
Permettre aux analystes d'interagir en langage naturel avec la plateforme pour accélérer les investigations, la chasse aux menaces et la prise de décision.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| AIC-01 | Cyber RAG Engine |
| AIC-02 | Natural Language Query |
| AIC-03 | Investigation Assistant |
| AIC-04 | Threat Explanation |
| AIC-05 | Recommendation Engine |
| AIC-06 | Copilot Guardrails |

---

## Epics & User Stories MVP

### EPIC AIC-01 — Cyber RAG Engine

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-RAG-001 | En tant de système, le copilot utilise RAG sur les données cyber de la plateforme (events, alertes, actifs, identités) | HAUTE |
| US-AIC-RAG-002 | En tant de système, le RAG utilise le Vector DB pour la similarité sémantique | HAUTE |
| US-AIC-RAG-003 | En tant de système, les réponses sont fondées sur les données réelles du tenant | HAUTE |

---

### EPIC AIC-02 — Natural Language Query

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-NLQ-001 | En tant d'analyste, je pose des questions en français/anglais : "Quelles alertes critiques depuis 24h ?" | HAUTE |
| US-AIC-NLQ-002 | En tant d'analyste, je demande : "Montre-moi tous les comptes avec accès CBS sans MFA" | HAUTE |
| US-AIC-NLQ-003 | En tant d'analyste, la requête NL est automatiquement traduite en Cypher/SQL/DSL | HAUTE |

---

### EPIC AIC-03 — Investigation Assistant

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-INV-001 | En tant d'analyste, je demande : "Résume-moi l'incident #1234" | HAUTE |
| US-AIC-INV-002 | En tant d'analyste, je demande : "Quelles sont les prochaines étapes d'investigation ?" | HAUTE |
| US-AIC-INV-003 | En tant d'analyste, je demande : "Qui d'autre a accès à cet actif ?" | HAUTE |

---

### EPIC AIC-04 — Threat Explanation

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-EXP-001 | En tant d'analyste L1, je demande : "Explique-moi cette technique ATT&CK en termes simples" | HAUTE |
| US-AIC-EXP-002 | En tant d'analyste, je demande : "Pourquoi cette alerte est-elle critique ?" | HAUTE |
| US-AIC-EXP-003 | En tant d'analyste, je demande : "Quel est l'impact métier de cette vulnérabilité ?" | HAUTE |

---

### EPIC AIC-05 — Recommendation Engine

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-REC-001 | En tant d'analyste, le copilot propose des actions de remédiation contextualisées | HAUTE |
| US-AIC-REC-002 | En tant de CISO, le copilot propose les 3 actions prioritaires du jour | HAUTE |
| US-AIC-REC-003 | En tant de système, les recommandations sont expliquées (Explainable AI) | HAUTE |

---

### EPIC AIC-06 — Copilot Guardrails

| ID | User Story | Priorité |
|---|---|---|
| US-AIC-GRD-001 | En tant de système, le copilot ne peut pas exécuter d'actions sans validation humaine | HAUTE |
| US-AIC-GRD-002 | En tant de système, toutes les interactions sont loggées dans l'audit | HAUTE |
| US-AIC-GRD-003 | En tant de système, le copilot respecte les permissions RBAC de l'utilisateur | HAUTE |
| US-AIC-GRD-004 | En tant de système, le copilot ne fuit pas de données cross-tenant | HAUTE |

---

## APIs exposées

```
POST   /api/v1/copilot/chat              # Conversation
GET    /api/v1/copilot/history           # Historique conversations
POST   /api/v1/copilot/query/nl          # NL → Query
GET    /api/v1/copilot/recommendations   # Recommandations actives
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Cyber RAG Engine + Vector DB indexing | RAG opérationnel |
| S02 | Natural Language Query (NL → Cypher/SQL) | Requêtes NL |
| S03 | Investigation Assistant | Résumés incidents |
| S04 | Threat Explanation | Explications contextuelles |
| S05 | Recommendation Engine | Recommandations |
| S06 | Guardrails + Audit + RBAC | Sécurité copilot |
| S07-08 | (buffer) Fine-tuning domaine bancaire | Précision métier |

---

## Critères d'acceptation

- [ ] RAG sur données réelles du tenant opérationnel
- [ ] Requêtes NL en français et anglais fonctionnelles
- [ ] Toutes les réponses fondées sur les données réelles (pas d'hallucination)
- [ ] Guardrails : RBAC respecté, audit complet, pas de cross-tenant
- [ ] Explainable AI : toute décision IA expliquée
