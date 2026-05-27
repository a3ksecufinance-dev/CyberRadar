# Catalogue API — Cyber Radar Platform

> Standard : REST JSON | Auth : JWT Bearer | Version : /api/v1/

---

## Conventions

```
Base URL   : https://crp.{tenant}.domain.com/api/v1/
Auth       : Authorization: Bearer <JWT>
Format     : application/json
Pagination : ?page=1&limit=50&sort=created_at:desc
Tenant     : extrait automatiquement du JWT
```

---

## D0 — Foundation Platform

### Tenants
```
POST   /tenants                  Créer un tenant
GET    /tenants                  Lister les tenants
GET    /tenants/{id}             Détail tenant
PUT    /tenants/{id}             Modifier tenant
DELETE /tenants/{id}             Désactiver tenant
GET    /tenants/{id}/stats       Statistiques tenant
```

### Users & Identity
```
POST   /users                    Créer utilisateur
GET    /users                    Lister utilisateurs
GET    /users/{id}               Profil utilisateur
PUT    /users/{id}               Modifier utilisateur
DELETE /users/{id}               Désactiver
POST   /users/{id}/mfa/enroll    Enrôlement MFA
GET    /users/me                 Profil connecté
```

### RBAC
```
GET    /roles                    Lister rôles
POST   /roles                    Créer rôle
GET    /roles/{id}/permissions   Permissions d'un rôle
PUT    /users/{id}/roles         Assigner rôles
```

### Audit
```
GET    /audit/events             Recherche événements audit
GET    /audit/events/{id}        Détail événement
POST   /audit/export             Export audit (PDF, JSON)
```

### Config
```
GET    /config                   Configuration plateforme
PUT    /config/{key}             Modifier config
GET    /config/history           Historique config
POST   /config/rollback/{version} Rollback
```

### Notifications
```
POST   /notifications/rules      Créer règle notification
GET    /notifications/rules      Lister règles
PUT    /notifications/rules/{id}
POST   /notifications/test       Tester canal
```

### Health
```
GET    /health                   Santé plateforme
GET    /health/services          Santé par service
GET    /metrics                  Métriques Prometheus
```

---

## D1 — Cyber Data Fabric

### Events (Ingestion)
```
POST   /events                   Ingestion event(s)
POST   /events/batch             Ingestion batch
GET    /events/{id}              Détail event
```

### Search
```
POST   /search                   Recherche events (DSL/SQL-like)
GET    /search/saved             Requêtes sauvegardées
POST   /search/saved             Sauvegarder requête
DELETE /search/saved/{id}
```

### Connectors
```
GET    /connectors               Lister connecteurs
POST   /connectors               Créer connecteur
GET    /connectors/{id}          Détail connecteur
PUT    /connectors/{id}          Modifier
DELETE /connectors/{id}          Supprimer
GET    /connectors/{id}/health   Santé connecteur
GET    /connectors/{id}/stats    Statistiques
POST   /connectors/{id}/test     Tester connecteur
```

### Schema
```
GET    /schema                   Cyber schema actuel
GET    /schema/versions          Versions du schema
```

### Replay
```
POST   /replay                   Lancer un replay
GET    /replay/{id}/status       Statut replay
DELETE /replay/{id}              Annuler
```

### Data Quality
```
GET    /data/quality             Rapport qualité
GET    /data/quality/{source_id} Qualité par source
```

---

## D2 — Cyber Asset Intelligence

### Assets
```
GET    /assets                   Lister actifs (filtrables)
POST   /assets                   Créer actif manuellement
GET    /assets/{id}              Asset profile complet
PUT    /assets/{id}              Modifier
DELETE /assets/{id}
GET    /assets/{id}/history      Timeline actif
GET    /assets/{id}/vulnerabilities Vulnérabilités
GET    /assets/{id}/dependencies Dépendances
GET    /assets/{id}/risk         Risk score
PUT    /assets/{id}/criticality  Override criticité
GET    /assets/{id}/sessions     Sessions sur l'actif
```

### Discovery
```
POST   /discovery/scan           Lancer un scan
GET    /discovery/scan/{id}      Statut scan
GET    /discovery/schedule       Calendrier scans
PUT    /discovery/schedule       Configurer schedule
```

### Shadow IT & Rogue
```
GET    /assets/shadow-it         Shadow IT détecté
GET    /assets/rogue             Rogue assets
PUT    /assets/{id}/authorize    Autoriser un actif
```

### External Exposure
```
GET    /exposure/external        Surface d'attaque externe
GET    /exposure/misconfigs      Misconfigurations
GET    /exposure/certificates    Certificats SSL (expiration)
```

### Dependencies
```
GET    /dependencies             Carte de dépendances
GET    /dependencies/blast-radius/{asset_id} Blast radius
```

---

## D3 — Identity & PAM Intelligence

```
GET    /identities               Lister identités
GET    /identities/{id}          Profil complet
GET    /identities/{id}/sessions Sessions
GET    /identities/{id}/privileges Droits
GET    /identities/{id}/risk     Risk score + timeline
GET    /identities/{id}/anomalies Anomalies détectées
GET    /identities/orphans       Comptes orphelins
GET    /identities/dormant       Comptes dormants
GET    /identities/privileged    Comptes privilégiés
GET    /pam/sessions             Sessions PAM actives/historiques
GET    /pam/sessions/{id}        Détail session PAM
GET    /pam/sessions/{id}/commands Commandes exécutées
GET    /identities/threats       Alertes ITDR
```

---

## D4 — Detection SIEM/XDR

```
GET    /alerts                   Lister alertes
GET    /alerts/{id}              Détail alerte + contexte complet
PUT    /alerts/{id}/qualify      Qualifier (TP/FP/AR)
PUT    /alerts/{id}/assign       Assigner analyste
GET    /alerts/stats             Statistiques alertes

GET    /incidents                Lister incidents
POST   /incidents                Créer incident manuellement
GET    /incidents/{id}           Détail incident
PUT    /incidents/{id}/status    Changer statut
POST   /incidents/{id}/close     Clôturer

GET    /rules                    Règles de détection
POST   /rules                    Créer règle
GET    /rules/{id}
PUT    /rules/{id}               Modifier
DELETE /rules/{id}
POST   /rules/{id}/test          Test sandbox
POST   /rules/{id}/enable        Activer/désactiver

GET    /cases                    Cases
POST   /cases                    Créer case
GET    /cases/{id}
PUT    /cases/{id}
POST   /cases/{id}/notes         Ajouter note
POST   /cases/{id}/evidence      Attacher preuve

POST   /hunt/query               Threat hunting query
GET    /hunt/playbooks           Playbooks de chasse sauvegardés
```

---

## D5 — UEBA

```
GET    /ueba/users/{id}/risk         Risk score + explication
GET    /ueba/users/{id}/timeline     Risk timeline
GET    /ueba/users/{id}/anomalies    Anomalies
GET    /ueba/users/{id}/baseline     Profil baseline
GET    /ueba/alerts                  Alertes UEBA
GET    /ueba/insider-threats         Scores insider threat
GET    /ueba/compromised-accounts    Comptes suspectés compromis
GET    /ueba/fraud-alerts            Alertes cyber-fraud (banking)
GET    /ueba/sessions/{id}/analysis  Analyse comportementale session
```

---

## D6 — Threat Intelligence

```
GET    /cti/ioc/lookup           Lookup IOC (IP, hash, domain, URL)
POST   /cti/ioc                  Créer IOC interne
GET    /cti/ioc                  Lister IOC
DELETE /cti/ioc/{id}

GET    /cti/feeds                Lister feeds
POST   /cti/feeds                Ajouter feed
PUT    /cti/feeds/{id}
DELETE /cti/feeds/{id}
GET    /cti/feeds/{id}/stats     Statistiques feed

GET    /cti/actors               Threat actors
GET    /cti/actors/{id}/ttp      TTP d'un acteur

GET    /cti/mitre/tactics        Tactiques ATT&CK
GET    /cti/mitre/techniques     Techniques ATT&CK
GET    /cti/coverage             Coverage heatmap

POST   /cti/export/stix          Export STIX
```

---

## D7 — Vulnerability & Exposure

```
GET    /vulnerabilities          Lister CVE
GET    /vulnerabilities/{id}     Détail CVE
GET    /vulnerabilities/priority Top priorités (score contextualisé)
GET    /assets/{id}/vulnerabilities Vulns d'un actif

GET    /exposure/misconfigurations Misconfigurations
GET    /exposure/credentials-leaked Credentials exposés

GET    /patches                  Patches disponibles
POST   /patches/plan             Planifier patches

GET    /sla/breaches             SLA dépassés
GET    /compliance/posture       Posture compliance (PCI DSS, SWIFT CSP, ISO 27001)
POST   /compliance/reports/generate Générer rapport
```

---

## D8 — Attack Path

```
GET    /attack-paths             Chemins d'attaque actifs
GET    /attack-paths/critical    Chemins critiques (CBS/SWIFT)
POST   /attack-paths/simulate    Simuler "si X compromis"
GET    /attack-paths/{id}/detail Chemin détaillé
GET    /attack-paths/blast-radius/{asset_id} Blast radius
GET    /attack-paths/remediation Remédiations prioritaires
```

---

## D9 — Knowledge Graph

```
POST   /graph/query              Requête Cypher
GET    /graph/nodes/{id}         Nœud + relations directes
GET    /graph/nodes/{id}/paths   Tous les chemins
GET    /graph/nodes/{id}/neighbors Voisins (depth configurable)
GET    /graph/analytics/centrality Nœuds les plus centraux
GET    /graph/analytics/clusters  Clusters
POST   /graphql                  GraphQL endpoint
```

---

## D10 — SOAR

```
GET    /soar/playbooks           Lister playbooks
POST   /soar/playbooks           Créer
PUT    /soar/playbooks/{id}      Modifier
DELETE /soar/playbooks/{id}
POST   /soar/playbooks/{id}/execute Exécution manuelle
POST   /soar/playbooks/{id}/simulate Simulation
GET    /soar/playbooks/{id}/history Historique exécutions

GET    /soar/actions             Bibliothèque actions
POST   /soar/actions/execute     Exécuter action manuelle

GET    /soar/executions          Historique exécutions
GET    /soar/executions/{id}     Détail exécution
POST   /soar/executions/{id}/rollback Rollback action

POST   /soar/approvals/{id}/approve Approuver action
POST   /soar/approvals/{id}/reject  Rejeter

GET    /soar/metrics             MTTR, taux automatisation
```

---

## D12 — AI Copilot

```
POST   /copilot/chat             Conversation (streaming SSE)
GET    /copilot/history          Historique conversations
DELETE /copilot/history/{id}

POST   /copilot/query/nl         NL → Query (Cypher/SQL)
GET    /copilot/recommendations  Recommandations actives
POST   /copilot/explain/alert    Expliquer une alerte
POST   /copilot/explain/risk     Expliquer un risk score
```

---

## Codes de réponse standards

```
200 OK               Succès
201 Created          Ressource créée
204 No Content       Suppression réussie
400 Bad Request      Requête invalide
401 Unauthorized     JWT manquant ou invalide
403 Forbidden        Permission insuffisante
404 Not Found        Ressource introuvable
409 Conflict         Conflit (ex: doublon)
422 Unprocessable    Validation échouée
429 Too Many Requests Rate limit atteint
500 Internal Error   Erreur serveur
503 Unavailable      Service indisponible
```

---

## Format de réponse standard

```json
{
  "data": { ... },
  "meta": {
    "page": 1,
    "limit": 50,
    "total": 1247,
    "tenant_id": "uuid"
  },
  "error": null
}
```

## Format d'erreur

```json
{
  "data": null,
  "error": {
    "code": "ALERT_NOT_FOUND",
    "message": "Alert not found",
    "details": {}
  }
}
```
