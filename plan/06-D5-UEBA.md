# Domaine 5 — UEBA++ (User & Entity Behavior Analytics)

> Priorité : HAUTE | Sprints : 6–8 | Dépendances : D1, D2, D3, D4

---

## Objectif

Analyse comportementale avancée des utilisateurs et entités pour détecter les menaces internes, les compromissions de comptes, les fraudes et les anomalies comportementales impossibles à détecter par règles statiques.

Le "++" indique une version augmentée intégrant :
- Behavioral baseline dynamique par identité, groupe, rôle, heure, localisation
- Corrélation comportementale avec contexte métier banking
- Détection insider threat + compromission externe + fraude

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| UBA-01 | Behavioral Baseline Engine |
| UBA-02 | Anomaly Detection |
| UBA-03 | Peer Group Analysis |
| UBA-04 | Risk Timeline |
| UBA-05 | Insider Threat Detection |
| UBA-06 | Account Compromise Detection |
| UBA-07 | Fraud Behavior Fusion |
| UBA-08 | Session Intelligence |

---

## Epics & User Stories MVP

### EPIC UBA-01 — Behavioral Baseline Engine

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-BAS-001 | En tant de système, je construis un profil comportemental normal pour chaque utilisateur | HAUTE |
| US-UBA-BAS-002 | En tant de système, la baseline intègre : horaires, localisations, actifs accédés, volume, commandes | HAUTE |
| US-UBA-BAS-003 | En tant de système, la baseline est recalibrée automatiquement selon l'évolution du comportement | HAUTE |
| US-UBA-BAS-004 | En tant de système, je crée des baselines par groupe de pairs (même rôle/département) | HAUTE |

---

### EPIC UBA-02 — Anomaly Detection

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-ANO-001 | En tant de système, je détecte toute déviation significative du comportement normal | HAUTE |
| US-UBA-ANO-002 | En tant d'analyste, chaque anomalie est scorée et expliquée | HAUTE |
| US-UBA-ANO-003 | En tant de système, je combine plusieurs anomalies faibles pour former une alerte haute | HAUTE |

**Anomalies détectées (exemples) :**
```
- Connexion heure inhabituelle (ex: 3h du matin)
- Connexion depuis pays/région inhabituel
- Volume de données exfiltré anormal
- Nombre de tentatives d'authentification anormal
- Accès à des ressources jamais consultées
- Commandes admin exécutées pour la première fois
- Escalade de privilèges hors contexte normal
- CBS : accès à des comptes clients hors portefeuille habituel
```

---

### EPIC UBA-03 — Peer Group Analysis

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-PGP-001 | En tant de système, je compare le comportement d'un user vs ses pairs (même rôle/équipe) | HAUTE |
| US-UBA-PGP-002 | En tant d'analyste, je vois si un user se comporte différemment de son groupe | HAUTE |

---

### EPIC UBA-04 — Risk Timeline

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-RTL-001 | En tant d'analyste, je vois l'évolution du risk score d'une identité dans le temps | HAUTE |
| US-UBA-RTL-002 | En tant d'analyste, la timeline montre les événements ayant fait monter le score | HAUTE |
| US-UBA-RTL-003 | En tant d'analyste, je navigue dans la timeline pour investiguer | HAUTE |

---

### EPIC UBA-05 — Insider Threat Detection

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-INS-001 | En tant de système, je détecte les patterns insider threat (sabotage, exfiltration, préparation départ) | HAUTE |
| US-UBA-INS-002 | En tant de système, je corrèle les signaux RH (départ prévu) avec les comportements cyber | HAUTE |
| US-UBA-INS-003 | En tant de système, je génère un score insider threat par identité | HAUTE |

---

### EPIC UBA-06 — Account Compromise Detection

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-COM-001 | En tant de système, je détecte une connexion depuis un nouveau device (premier usage) | HAUTE |
| US-UBA-COM-002 | En tant de système, je détecte une connexion impossible (pays A → pays B en < 30 min) | HAUTE |
| US-UBA-COM-003 | En tant de système, je détecte un comportement post-compromission (discovery, exfil) | HAUTE |

---

### EPIC UBA-07 — Fraud Behavior Fusion (Banking)

**Spécifique secteur bancaire**

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-FRD-001 | En tant de système, je corrèle comportement cyber + transaction bancaire anormale | HAUTE |
| US-UBA-FRD-002 | En tant de système, je détecte : CBS Admin + escalade privilège + transaction atypique + hors horaire | HAUTE |
| US-UBA-FRD-003 | En tant d'analyste fraude, je vois les alertes cyber-fraud fusionnées | HAUTE |

**Exemple :**
```
CBS Admin
+ privilege escalation
+ transaction atypique
+ hors horaire
→ Cyber Fraud Alert CRITIQUE
```

---

### EPIC UBA-08 — Session Intelligence

| ID | User Story | Priorité |
|---|---|---|
| US-UBA-SES-001 | En tant de système, j'analyse le comportement dans chaque session (commandes, durée, actifs) | HAUTE |
| US-UBA-SES-002 | En tant de système, je détecte un session hijacking | HAUTE |
| US-UBA-SES-003 | En tant de système, je détecte un PAM abuse (commandes anormales pendant session PAM) | HAUTE |

---

## APIs exposées

```
GET    /api/v1/ueba/users/{id}/risk          # Risk score utilisateur
GET    /api/v1/ueba/users/{id}/timeline      # Risk timeline
GET    /api/v1/ueba/users/{id}/anomalies     # Anomalies détectées
GET    /api/v1/ueba/alerts                   # Alertes UEBA
GET    /api/v1/ueba/insider-threats          # Insider threat scores
GET    /api/v1/ueba/compromised-accounts     # Comptes suspectés compromis
GET    /api/v1/ueba/fraud-alerts             # Alertes cyber-fraud
GET    /api/v1/ueba/sessions/{id}/analysis   # Analyse session
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Behavioral Baseline Engine | Profils comportementaux |
| S02 | Anomaly Detection (ML) + Scoring | Détection anomalies |
| S03 | Peer Group Analysis | Comparaison groupes |
| S04 | Account Compromise Detection | Détection compromission |
| S05 | Insider Threat Detection | Détection insider |
| S06 | Fraud Behavior Fusion (CBS/SWIFT) | Corrélation fraud banking |
| S07 | Session Intelligence + Risk Timeline | Analyse sessions |
| S08 | (buffer) Tuning ML + calibration | Précision validée |

---

## Critères d'acceptation

- [ ] Baselines construites automatiquement (J+14 cold start)
- [ ] Anomalies détectées avec score explicable
- [ ] Détection impossible travel < 2 minutes
- [ ] Fraud Behavior Fusion opérationnel (CBS + cyber)
- [ ] Insider threat score calculé pour tous les utilisateurs
- [ ] -70% faux positifs vs règles statiques
