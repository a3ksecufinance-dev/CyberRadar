# Domaine 14 — Security & Compliance

> Priorité : HAUTE | Sprints : 4–6 | Dépendances : D0, D4

---

## Objectif

Garantir la sécurité intrinsèque de la plateforme et assurer la conformité continue aux réglementations applicables au secteur bancaire.

---

## Référentiels de conformité cibles

| Référentiel | Applicabilité |
|---|---|
| PCI DSS v4 | Données de paiement |
| SWIFT CSP | Transactions SWIFT |
| ISO 27001 | Sécurité information |
| NIST CSF 2.0 | Cyber framework |
| DORA | Résilience opérationnelle numérique (EU) |
| Exigences Banque Centrale | Selon pays de déploiement |

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| SEC-01 | Platform Security Hardening |
| SEC-02 | Compliance Monitoring |
| SEC-03 | Compliance Reporting |
| SEC-04 | Security Testing |
| SEC-05 | SBOM & Supply Chain |
| SEC-06 | Data Sovereignty |

---

## Epics & User Stories MVP

### EPIC SEC-01 — Platform Security Hardening

| ID | Exigence | Priorité |
|---|---|---|
| SEC-FND-001 | TLS 1.3 obligatoire sur tous les composants | HAUTE |
| SEC-FND-002 | Zero Trust — aucun composant implicitement trusted | HAUTE |
| SEC-FND-003 | PAM obligatoire pour tous les accès administrateurs | HAUTE |
| SEC-FND-004 | Encryption AES-256 at rest | HAUTE |
| SEC-FND-005 | SBOM mandatory pour tous les composants | HAUTE |
| SEC-FND-006 | Pas de secrets dans les variables d'environnement ni les logs | HAUTE |
| SEC-FND-007 | Scan de vulnérabilités hebdomadaire automatique | HAUTE |
| SEC-FND-008 | Penetration testing avant chaque release majeure | HAUTE |

---

### EPIC SEC-02 — Compliance Monitoring

| ID | User Story | Priorité |
|---|---|---|
| US-SEC-COM-001 | En tant de CISO, je vois l'état de conformité PCI DSS en temps réel (contrôles satisfaits/échoués) | HAUTE |
| US-SEC-COM-002 | En tant de CISO, je vois l'état de conformité SWIFT CSP | HAUTE |
| US-SEC-COM-003 | En tant de CISO, je vois l'état de conformité DORA | HAUTE |
| US-SEC-COM-004 | En tant de système, je génère une alerte dès qu'un contrôle de conformité échoue | HAUTE |

---

### EPIC SEC-03 — Compliance Reporting

| ID | User Story | Priorité |
|---|---|---|
| US-SEC-RPT-001 | En tant d'auditeur, je génère un rapport PCI DSS complet (SAQ/ROC) | HAUTE |
| US-SEC-RPT-002 | En tant d'auditeur, je génère un rapport SWIFT CSP | HAUTE |
| US-SEC-RPT-003 | En tant d'auditeur, je génère un rapport ISO 27001 | HAUTE |
| US-SEC-RPT-004 | En tant d'auditeur, je programme des rapports récurrents automatiques | HAUTE |

---

### EPIC SEC-04 — Security Testing

| ID | Exigence | Priorité |
|---|---|---|
| FR-SEC-TST-001 | DAST automatisé sur toutes les APIs | HAUTE |
| FR-SEC-TST-002 | SAST sur le code plateforme en CI/CD | HAUTE |
| FR-SEC-TST-003 | Tests de pénétration semestriels | HAUTE |
| FR-SEC-TST-004 | Bug bounty program (optionnel V2) | BASSE |

---

### EPIC SEC-05 — SBOM & Supply Chain

| ID | Exigence | Priorité |
|---|---|---|
| FR-SEC-SBOM-001 | SBOM généré automatiquement pour chaque release | HAUTE |
| FR-SEC-SBOM-002 | Scan des dépendances (CVE) en CI/CD | HAUTE |
| FR-SEC-SBOM-003 | Alerte dès qu'une dépendance critique est vulnérable | HAUTE |

---

### EPIC SEC-06 — Data Sovereignty

| ID | Exigence | Priorité |
|---|---|---|
| FR-SEC-SOV-001 | Les données d'un tenant restent dans sa région géographique | HAUTE |
| FR-SEC-SOV-002 | Support déploiement on-premise et air-gapped | HAUTE |
| FR-SEC-SOV-003 | Aucune télémétrie vers des serveurs externes sans consentement | HAUTE |
| FR-SEC-SOV-004 | Chiffrement de bout en bout des données en transit | HAUTE |

---

## APIs exposées

```
GET    /api/v1/compliance/pci-dss            # État PCI DSS
GET    /api/v1/compliance/swift-csp          # État SWIFT CSP
GET    /api/v1/compliance/dora               # État DORA
GET    /api/v1/compliance/iso27001           # État ISO 27001
POST   /api/v1/compliance/reports/generate  # Génération rapport
GET    /api/v1/security/sbom                 # SBOM actuel
GET    /api/v1/security/scan/results         # Résultats scans
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Platform hardening (TLS, Zero Trust, Vault) | Sécurité socle |
| S02 | Compliance Monitoring (PCI DSS, SWIFT CSP) | Tableau de bord conformité |
| S03 | Compliance Reporting (PDF, export) | Rapports |
| S04 | SBOM + Supply Chain Security (CI/CD) | SBOM automatisé |
| S05 | DAST/SAST intégration | Tests sécurité |
| S06 | (buffer) Data Sovereignty + air-gapped support | Déploiement souverain |

---

## Critères d'acceptation

- [ ] TLS 1.3 activé sur 100% des composants
- [ ] Compliance PCI DSS visible en temps réel
- [ ] Compliance SWIFT CSP visible en temps réel
- [ ] Rapports conformité générables (PCI DSS, SWIFT, ISO 27001)
- [ ] SBOM généré automatiquement à chaque release
- [ ] Zéro secret en clair dans les logs
- [ ] Data sovereignty : données localisées par région
