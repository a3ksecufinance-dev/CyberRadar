# Domaine 3 — Identity & PAM Intelligence

> Priorité : HAUTE | Sprints : 6–8 | Dépendances : D0, D1, D2

---

## Objectif

Construire une vision unifiée et intelligente de toutes les identités (humaines et non-humaines) et de leurs accès privilégiés.
Détecter les abus, escalades et comportements anormaux sur les comptes critiques.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| IPM-01 | Identity Inventory |
| IPM-02 | Privileged Account Management (PAM) Intelligence |
| IPM-03 | Identity Risk Scoring |
| IPM-04 | Orphan & Dormant Account Detection |
| IPM-05 | Privilege Escalation Detection |
| IPM-06 | Identity Threat Detection (ITDR) |
| IPM-07 | Service Account Intelligence |
| IPM-08 | Identity Graph Feed |

---

## Modèle d'identité (6 nœuds du Graph)

```
Identity → Asset → Privilege → Session → Context → Business Service
```

**Types d'identités :**
```
user | admin | privileged account | service account
API identity | machine identity | bot | vendor access
```

**Attributs :**
```
privilege_level | risk_score | MFA_enabled
PAM_usage | behavior_score | last_seen | department
```

---

## Epics & User Stories MVP

### EPIC IPM-01 — Identity Inventory

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-INV-001 | En tant d'analyste, je visualise tous les comptes (humains et non-humains) | HAUTE |
| US-IPM-INV-002 | En tant d'admin, la découverte des comptes est automatique depuis AD/LDAP/IAM/PAM | HAUTE |
| US-IPM-INV-003 | En tant d'analyste, je vois le profil complet d'une identité : droits, sessions, assets, comportement | HAUTE |

---

### EPIC IPM-02 — PAM Intelligence

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-PAM-001 | En tant d'analyste, je vois toutes les sessions PAM ouvertes | HAUTE |
| US-IPM-PAM-002 | En tant de système, je corrèle session PAM → action → actif cible | HAUTE |
| US-IPM-PAM-003 | En tant d'analyste, j'audite les commandes exécutées via PAM | HAUTE |
| US-IPM-PAM-004 | En tant de système, je détecte une session PAM hors plage horaire | HAUTE |

---

### EPIC IPM-03 — Identity Risk Scoring

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-RSK-001 | En tant de système, chaque identité a un risk score dynamique | HAUTE |
| US-IPM-RSK-002 | En tant d'analyste, le score est expliqué (raisons détaillées) | HAUTE |
| US-IPM-RSK-003 | En tant de système, le score augmente lors d'une connexion depuis pays inhabituel | HAUTE |

---

### EPIC IPM-04 — Orphan & Dormant Detection

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-ORB-001 | En tant d'admin, je vois tous les comptes orphelins (sans propriétaire identifié) | HAUTE |
| US-IPM-ORB-002 | En tant d'admin, je vois tous les comptes dormants (inactifs > 90 jours) | HAUTE |
| US-IPM-ORB-003 | En tant de système, je génère une alerte pour tout compte orphelin avec privilèges | HAUTE |

---

### EPIC IPM-05 — Privilege Escalation Detection

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-ESC-001 | En tant de système, je détecte toute élévation de privilège non autorisée | HAUTE |
| US-IPM-ESC-002 | En tant de système, je corrèle escalade → action → impact métier | HAUTE |
| US-IPM-ESC-003 | En tant d'analyste, je vois le chemin complet de l'escalade | HAUTE |

---

### EPIC IPM-06 — Identity Threat Detection (ITDR)

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-TDR-001 | En tant de système, je détecte les attaques Pass-the-Hash, Pass-the-Ticket | HAUTE |
| US-IPM-TDR-002 | En tant de système, je détecte les attaques Kerberoasting, Golden Ticket | HAUTE |
| US-IPM-TDR-003 | En tant de système, je détecte les mouvements latéraux via identités | HAUTE |
| US-IPM-TDR-004 | En tant de système, je corrèle plusieurs événements suspects pour créer un incident ITDR | HAUTE |

---

### EPIC IPM-07 — Service Account Intelligence

| ID | User Story | Priorité |
|---|---|---|
| US-IPM-SVC-001 | En tant d'analyste, je vois tous les service accounts et leurs usages | HAUTE |
| US-IPM-SVC-002 | En tant de système, je détecte un service account utilisé de façon interactive | HAUTE |
| US-IPM-SVC-003 | En tant de système, je détecte un service account avec des droits excessifs | HAUTE |

---

### EPIC IPM-08 — Identity Graph Feed

| ID | Exigence | Priorité |
|---|---|---|
| FR-IPM-GRF-001 | Sync temps réel Identity → Graph DB | HAUTE |
| FR-IPM-GRF-002 | Relations : owns, authenticated_to, has_privilege, accesses, exposed_to | HAUTE |

---

## APIs exposées

```
GET    /api/v1/identities                    # Liste identités
GET    /api/v1/identities/{id}               # Profil complet
GET    /api/v1/identities/{id}/sessions      # Sessions actives/historiques
GET    /api/v1/identities/{id}/privileges    # Droits et rôles
GET    /api/v1/identities/{id}/risk          # Risk score
GET    /api/v1/identities/orphans            # Comptes orphelins
GET    /api/v1/identities/dormant            # Comptes dormants
GET    /api/v1/pam/sessions                  # Sessions PAM
GET    /api/v1/pam/sessions/{id}/commands    # Commandes PAM
GET    /api/v1/identities/threats            # ITDR incidents
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Identity Inventory + Discovery (AD, Entra, PAM) | Vue complète identités |
| S02 | PAM Intelligence + Session Correlation | Audit PAM opérationnel |
| S03 | Identity Risk Scoring + Orphan/Dormant | Scoring identité |
| S04 | Privilege Escalation Detection | Détection escalade |
| S05 | ITDR (Pass-the-Hash, Kerberoasting, Lateral) | Détection attaques identité |
| S06 | Service Account Intelligence + Graph Feed | Sync Graph DB |
| S07-08 | (buffer) Tests intégration + tuning | Précision validée |

---

## Critères d'acceptation

- [ ] Inventaire 100% des identités (humains + non-humains)
- [ ] PAM sessions corrélées avec actions et actifs cibles
- [ ] Risk score explicable et mis à jour en temps réel
- [ ] Détection Pass-the-Hash, Kerberoasting, Golden Ticket
- [ ] Comptes orphelins et dormants identifiés
- [ ] Identity Graph synchronisé en temps réel
