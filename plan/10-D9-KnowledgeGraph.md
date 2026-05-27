# Domaine 9 — Cyber Knowledge Graph

> Priorité : HAUTE | Sprints : 6–8 | Dépendances : D2, D3, D4, D5

---

## Objectif

Construire le moteur relationnel cyber de la plateforme.
Le Knowledge Graph connecte toutes les entités cyber et permet des requêtes relationnelles complexes impossibles en SQL ou Event Store seul.

---

## Modèle de graphe central

```
6 nœuds centraux :
  Identity | Asset | Privilege | Session | Context | Business Service

Relations clés :
  User ─owns→ Device
  User ─authenticated_to→ Session
  User ─has_privilege→ PAM Role
  User ─accesses→ CBS
  User ─exposed_to→ Threat
  Asset ─connects_to→ Asset
  Asset ─owned_by→ BU
  Privilege ─grants_access_to→ Asset
  Session ─interacts_with→ Asset
  Asset ─part_of→ Business Service
  Business Service ─has_revenue_impact→ Financial Amount
```

---

## Sous-domaines

| Code | Sous-domaine |
|---|---|
| KGR-01 | Graph Data Model |
| KGR-02 | Graph Ingestion & Sync |
| KGR-03 | Graph Query Engine |
| KGR-04 | Graph Analytics |
| KGR-05 | Graph Visualization |
| KGR-06 | Graph API |

---

## Epics & User Stories MVP

### EPIC KGR-01 — Graph Data Model

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-MDL-001 | En tant de système, le graphe supporte les 6 nœuds centraux avec leurs attributs | HAUTE |
| US-KGR-MDL-002 | En tant de système, le schéma de graphe est extensible sans migration | HAUTE |
| US-KGR-MDL-003 | En tant de système, chaque nœud et relation a un TenantID pour l'isolation | HAUTE |

---

### EPIC KGR-02 — Graph Ingestion & Sync

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-SYN-001 | En tant de système, le graphe est alimenté en temps réel depuis D2 (Assets) | HAUTE |
| US-KGR-SYN-002 | En tant de système, le graphe est alimenté en temps réel depuis D3 (Identity) | HAUTE |
| US-KGR-SYN-003 | En tant de système, les modifications sont propagées en < 5 secondes | HAUTE |
| US-KGR-SYN-004 | En tant de système, les nœuds supprimés (actif retiré) sont archivés avec historique | HAUTE |

---

### EPIC KGR-03 — Graph Query Engine

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-QRY-001 | En tant d'analyste, je fais des requêtes Cypher sur le graphe | HAUTE |
| US-KGR-QRY-002 | En tant d'analyste, j'utilise des templates de requêtes pré-définis | HAUTE |
| US-KGR-QRY-003 | En tant de système, les requêtes "Find all paths from User X to CBS" s'exécutent en < 3s | HAUTE |

**Exemples de requêtes types :**
```cypher
// Chemins depuis un compte compromis vers CBS
MATCH path = (u:Identity {id:'user_123'})-[*1..5]->(s:Asset {type:'CBS'})
RETURN path

// Tous les admins avec accès direct à SWIFT sans MFA
MATCH (u:Identity)-[:has_privilege]->(p:Privilege {level:'admin'})
      -[:grants_access_to]->(a:Asset {type:'SWIFT'})
WHERE u.MFAEnabled = false
RETURN u, p, a

// Blast radius d'un asset
MATCH (a:Asset {id:'cbs_prod'})<-[*1..3]-(n)
RETURN n, count(n)
```

---

### EPIC KGR-04 — Graph Analytics

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-ANL-001 | En tant d'analyste, je détecte les nœuds centraux (high centrality = high risk) | HAUTE |
| US-KGR-ANL-002 | En tant d'analyste, je détecte les clusters d'assets/identités à haut risque | HAUTE |
| US-KGR-ANL-003 | En tant de système, je calcule le PageRank cyber (actifs les plus critiques structurellement) | HAUTE |

---

### EPIC KGR-05 — Graph Visualization

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-VIZ-001 | En tant d'analyste, je visualise le graphe de façon interactive (zoom, filtre, expand) | HAUTE |
| US-KGR-VIZ-002 | En tant d'analyste, je visualise le graphe centré sur une identité ou un actif | HAUTE |
| US-KGR-VIZ-003 | En tant d'analyste, les nœuds sont colorés selon leur niveau de risque | HAUTE |

---

### EPIC KGR-06 — Graph API

| ID | User Story | Priorité |
|---|---|---|
| US-KGR-API-001 | En tant de développeur, j'accède au graphe via REST et GraphQL | HAUTE |
| US-KGR-API-002 | En tant de système (SOAR, AI Copilot, Attack Path), je consomme le graphe programmatiquement | HAUTE |

---

## APIs exposées

```
POST   /api/v1/graph/query               # Requête Cypher
GET    /api/v1/graph/nodes/{id}          # Nœud et ses relations
GET    /api/v1/graph/nodes/{id}/paths    # Tous les chemins
GET    /api/v1/graph/analytics/central   # Centralité
GET    /api/v1/graph/analytics/clusters  # Clusters
POST   /graphql                          # GraphQL endpoint
```

---

## Plan de sprints

| Sprint | Contenu | Livrable |
|---|---|---|
| S01 | Schema Neo4j + modèle 6 nœuds | Graphe structuré |
| S02 | Ingestion sync depuis D2 (Assets) | Assets dans le graphe |
| S03 | Ingestion sync depuis D3 (Identity) | Identités dans le graphe |
| S04 | Query Engine + templates Cypher | Requêtes opérationnelles |
| S05 | Graph Analytics (centralité, PageRank) | Analytics graphe |
| S06 | Graph Visualization interactive | UI graphe |
| S07-08 | (buffer) GraphQL API + performance | API graphe |

---

## Critères d'acceptation

- [ ] Graphe avec 6 nœuds centraux opérationnel
- [ ] Sync temps réel depuis D2 et D3 (< 5 secondes)
- [ ] Requêtes de chemin exécutées en < 3 secondes
- [ ] Visualisation interactive avec filtres
- [ ] API REST + GraphQL exposée
- [ ] Business Service comme nœud (impact financier visible)
