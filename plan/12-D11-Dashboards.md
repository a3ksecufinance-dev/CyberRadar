# Domaine 11 — Dashboards & War Room

> Priorité : MOYENNE | Sprints : 4–6 | Dépendances : D4, D5, D9

---

## Objectif

Fournir des interfaces de visualisation adaptées à chaque profil (SOC Analyst, CISO, Executive) et une War Room collaborative pour la gestion de crise.

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| DSH-01 | SOC Dashboard |
| DSH-02 | CISO Dashboard |
| DSH-03 | Executive Dashboard |
| DSH-04 | War Room |
| DSH-05 | Custom Dashboard Builder |
| DSH-06 | Reporting Engine |

---

## Epics & User Stories MVP

### EPIC DSH-01 — SOC Dashboard

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-SOC-001 | En tant d'analyste SOC, je vois en temps réel : alertes actives, incidents ouverts, queue d'analyse | HAUTE |
| US-DSH-SOC-002 | En tant d'analyste SOC, je vois les alertes triées par priorité métier | HAUTE |
| US-DSH-SOC-003 | En tant d'analyste SOC, je vois les top 10 actifs/identités à risque | HAUTE |
| US-DSH-SOC-004 | En tant d'analyste SOC, je vois l'EPS (events per second) en temps réel | HAUTE |
| US-DSH-SOC-005 | En tant d'analyste SOC, je vois la heatmap MITRE ATT&CK de la journée | HAUTE |

---

### EPIC DSH-02 — CISO Dashboard

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-CIS-001 | En tant de CISO, je vois le risque cyber global de l'organisation (score 0-100) | HAUTE |
| US-DSH-CIS-002 | En tant de CISO, je vois le MTTD et MTTR en temps réel | HAUTE |
| US-DSH-CIS-003 | En tant de CISO, je vois la couverture ATT&CK et les gaps | HAUTE |
| US-DSH-CIS-004 | En tant de CISO, je vois les top actifs critiques, top vulnérabilités, top identités à risque | HAUTE |
| US-DSH-CIS-005 | En tant de CISO, je vois la posture compliance (PCI DSS, SWIFT CSP, ISO 27001) | HAUTE |

---

### EPIC DSH-03 — Executive Dashboard

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-EXC-001 | En tant de CEO/CFO, je vois le risque cyber traduit en langage business (impact financier, services à risque) | HAUTE |
| US-DSH-EXC-002 | En tant de CEO, je vois : "Service Paiement Monétique — Risque ÉLEVÉ" pas "Windows Server PROD-17 vulnérable" | HAUTE |
| US-DSH-EXC-003 | En tant de CEO, je vois l'évolution du risque dans le temps (trend) | HAUTE |

---

### EPIC DSH-04 — War Room

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-WAR-001 | En tant d'analyste, je rejoins une war room collaborative lors d'un incident majeur | HAUTE |
| US-DSH-WAR-002 | En tant d'analyste, la war room affiche en temps réel : timeline, actions, actifs impliqués | HAUTE |
| US-DSH-WAR-003 | En tant de CISO, je coordonne la réponse depuis la war room avec les équipes | HAUTE |
| US-DSH-WAR-004 | En tant d'analyste, je prends des notes et actions dans la war room | HAUTE |

---

### EPIC DSH-05 — Custom Dashboard Builder

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-BLD-001 | En tant d'admin, je crée des dashboards personnalisés avec drag & drop | MOYENNE |
| US-DSH-BLD-002 | En tant d'admin, je partage un dashboard avec mon équipe | MOYENNE |

---

### EPIC DSH-06 — Reporting Engine

| ID | User Story | Priorité |
|---|---|---|
| US-DSH-RPT-001 | En tant de CISO, je génère un rapport PDF hebdomadaire automatiquement | HAUTE |
| US-DSH-RPT-002 | En tant d'auditeur, je génère un rapport de conformité | HAUTE |
| US-DSH-RPT-003 | En tant d'admin, je programme des rapports récurrents | MOYENNE |

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | SOC Dashboard (alertes + incidents temps réel) | Dashboard SOC |
| S02 | CISO Dashboard (risk global + MTTD/MTTR) | Dashboard CISO |
| S03 | Executive Dashboard (langage business) | Dashboard Exec |
| S04 | War Room collaborative | War Room opérationnelle |
| S05 | Reporting Engine (PDF + export) | Rapports |
| S06 | (buffer) Custom Dashboard Builder | Personnalisation |

---

## Critères d'acceptation

- [ ] Dashboard SOC avec alertes temps réel < 5 secondes de latence
- [ ] CISO Dashboard avec risk score global et compliance posture
- [ ] Executive Dashboard en langage business (service, impact financier)
- [ ] War Room collaborative opérationnelle
- [ ] Rapports PDF générables à la demande et en automatique
