# Domaine 8 — Attack Path Analytics

> Priorité : HAUTE | Sprints : 6–8 | Dépendances : D2, D3

---

## Objectif

Calculer et visualiser les chemins d'attaque possibles à partir des vulnérabilités, identités, privileges et dépendances.
Anticiper les mouvements latéraux et les chemins de compromission avant qu'ils ne se produisent.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| APA-01 | Attack Graph Generation |
| APA-02 | Attack Path Simulation |
| APA-03 | Blast Radius Calculation |
| APA-04 | Critical Path Detection |
| APA-05 | Remediation Prioritization by Path |
| APA-06 | Attack Path Alerts |

---

## Modèle d'attaque (Cyber Graph)

```
Identity → Privilege → Asset → Dependency → Business Service
```

**Exemple bancaire (chemin critique) :**
```
Admin CBS (compromis)
    │
    ▼ PAM Session
Windows Jump Server
    │
    ▼ Mouvement latéral
CBS Middleware
    │
    ▼ Accès DB
Core Banking Database
    │
    ▼ Impact
Transactions SWIFT
```

---

## Epics & User Stories MVP

### EPIC APA-01 — Attack Graph Generation

| ID | User Story | Priorité |
|---|---|---|
| US-APA-GRF-001 | En tant d'analyste, le moteur génère automatiquement le graphe d'attaque depuis les données Identity, Asset, Privilege, Vulnerability | HAUTE |
| US-APA-GRF-002 | En tant d'analyste, le graphe est mis à jour en temps réel | HAUTE |
| US-APA-GRF-003 | En tant d'analyste, je visualise le graphe de façon interactive | HAUTE |

---

### EPIC APA-02 — Attack Path Simulation

| ID | User Story | Priorité |
|---|---|---|
| US-APA-SIM-001 | En tant d'analyste, je simule "Que se passe-t-il si ce compte est compromis ?" | HAUTE |
| US-APA-SIM-002 | En tant d'analyste, je vois tous les chemins possibles depuis un point de départ | HAUTE |
| US-APA-SIM-003 | En tant de CISO, je simule l'impact d'une non-remédiation d'une vulnérabilité | HAUTE |

---

### EPIC APA-03 — Blast Radius Calculation

| ID | User Story | Priorité |
|---|---|---|
| US-APA-BLR-001 | En tant d'analyste, je calcule le blast radius d'un actif ou compte compromis | HAUTE |
| US-APA-BLR-002 | En tant d'analyste, le blast radius est exprimé en termes métier (% services impactés, impact financier) | HAUTE |
| US-APA-BLR-003 | En tant de CISO, je vois les actifs avec le plus grand blast radius | HAUTE |

---

### EPIC APA-04 — Critical Path Detection

| ID | User Story | Priorité |
|---|---|---|
| US-APA-CRT-001 | En tant de système, je détecte les chemins menant aux actifs les plus critiques (CBS, SWIFT) | HAUTE |
| US-APA-CRT-002 | En tant de CISO, je vois en permanence les 5 chemins les plus dangereux | HAUTE |
| US-APA-CRT-003 | En tant de système, je génère une alerte si un nouveau chemin critique apparaît | HAUTE |

---

### EPIC APA-05 — Remediation Prioritization by Path

| ID | User Story | Priorité |
|---|---|---|
| US-APA-REM-001 | En tant d'analyste, je vois quelle correction casse le plus de chemins d'attaque | HAUTE |
| US-APA-REM-002 | En tant d'admin, je priorise les patchs selon leur impact sur la réduction des chemins | HAUTE |

---

### EPIC APA-06 — Attack Path Alerts

| ID | User Story | Priorité |
|---|---|---|
| US-APA-ALT-001 | En tant de système, je génère une alerte si un nouveau chemin vers CBS/SWIFT est découvert | HAUTE |
| US-APA-ALT-002 | En tant d'analyste, l'alerte inclut le chemin complet et les actions de remédiation | HAUTE |

---

## APIs exposées

```
GET    /api/v1/attack-paths                     # Chemins actifs
GET    /api/v1/attack-paths/critical            # Chemins critiques
POST   /api/v1/attack-paths/simulate            # Simulation
GET    /api/v1/attack-paths/{id}/blast-radius   # Blast radius
GET    /api/v1/attack-paths/remediation         # Remédiations prioritaires
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Attack Graph Generation (depuis Neo4j) | Graphe d'attaque |
| S02 | Attack Path Simulation | Simulation interactive |
| S03 | Blast Radius Calculation | Calcul impact |
| S04 | Critical Path Detection + Alerts | Chemins critiques |
| S05 | Remediation Prioritization | Priorisation corrective |
| S06-08 | (buffer) Scénarios banking + tuning | Scénarios CBS/SWIFT |

---

## Critères d'acceptation

- [ ] Graphe d'attaque généré automatiquement depuis Graph DB
- [ ] Simulation "si ce compte est compromis" opérationnelle
- [ ] Blast radius calculé en termes métier
- [ ] Chemins vers CBS/SWIFT détectés et alertés
- [ ] Recommandations de remédiation priorisées par impact
