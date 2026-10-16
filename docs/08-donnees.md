# 08 — Données

## Où vit quoi

| Dépôt | Contenu | Volume attendu |
|---|---|---|
| **PostgreSQL 16 + pgvector** | La source de vérité : 142 tables. Tenants, identités, actifs, règles, alertes, constats, politiques, plongements. | Modéré, transactionnel |
| **ClickHouse** | 18 tables : événements bruts, alertes, séries UEBA, agrégats. | Élevé, analytique |
| **Neo4j** *(facultatif)* | Graphe d'attaque, graphe de connaissance. | Miroir de PostgreSQL |
| **Redis** | Compteurs de seuil, caches courts. | Éphémère |
| **Kafka** | Les événements en transit. | Flux |

---

## PostgreSQL

### Les migrations

`backend/migrations/postgres/`, numérotées, appliquées dans l'ordre par `psql`.

| Plage | Contenu |
|---|---|
| `000001`–`000028` | Un fichier par domaine : tenants, identités, actifs, PAM, SIEM, UEBA, renseignement, vulnérabilités, chemins d'attaque, graphe, SOAR, tableaux de bord, Copilot, et les douze domaines suivants |
| `000029`–`000032` | Le catalogue de permissions, les comptes de service, le rôle `soar_executor` |
| `000033`–`000038` | Activité quotidienne des identités, base de connaissance du Copilot, unification de l'administrateur, preuves du graphe, coût des arêtes, risque par actif |
| `000039`, `000042`, `000043`, `000045` | **Les quatre politiques paramétrables** |
| `000040`, `000041` | La bibliothèque de détection et sa remise à niveau |
| `000044` | L'identité d'entité UEBA |
| `000046`, `000047` | Les paquets de contenu et leur provenance |

> **Elles ne sont pas rejouables.** Il n'y a pas de table d'état ; le script
> détecte un schéma déjà présent et refuse plutôt que d'échouer à mi-chemin.
> `./scripts/dev-local.sh reset` repart d'une base vide. Adopter un outil à
> état reste à faire.

### Le cloisonnement

Chaque table porte `tenant_id`, et chaque lecture le filtre. Le tenant vient du
jeton, pas de la requête — voir [05 — Sécurité](05-securite.md).

### Les politiques versionnées et datées

Le même motif, quatre fois (risque, remédiation, comportement, chemins
d'attaque) :

```sql
CREATE TABLE <x>_policies (
    tenant_id      UUID,          -- NULL pour un préréglage de la plateforme
    code           VARCHAR,
    version        INT,
    effective_from TIMESTAMPTZ,
    effective_to   TIMESTAMPTZ,   -- NULL = active
    …les champs nommés, pas un blob JSON…
);

CREATE UNIQUE INDEX … ON <x>_policies (tenant_id)
    WHERE effective_to IS NULL;   -- une seule version active par tenant
```

Trois conséquences voulues :

- **Une seule active par tenant**, garantie par l'index partiel et non par du
  code applicatif.
- **L'historique est conservé.** Un auditeur demande « quelle était la formule
  ce jour-là » ; `effective_from`/`effective_to` répondent.
- **Des colonnes nommées, pas un JSON.** Une contrainte `CHECK` peut alors
  dire qu'un seuil est hors bornes, et le refus porte le nom du champ.

Une vue publie la politique active à l'usage des autres domaines, qui partagent
la même base :

```sql
CREATE VIEW tenant_remediation_policy AS
SELECT …
  CASE WHEN own.id IS NOT NULL THEN own.cbs_days ELSE std.cbs_days END …
```

`CASE WHEN` et non `COALESCE` : un plafond délibérément *non* posé par le
tenant ne doit pas hériter de celui du préréglage. `COALESCE` ne sait pas
distinguer « absent » de « volontairement vide ».

### Les plongements

`pgvector` porte la base de connaissance du Copilot (migration 34). La
dimension suit `EMBEDDINGS_MODEL`, `BAAI/bge-large-en-v1.5` par défaut.

---

## ClickHouse

18 tables réparties en sept bases :

| Base | Tables |
|---|---|
| `crp_audit` | `audit_logs`, `cyber_events` |
| `crp_fabric` | `raw_events`, `connectors`, `pipeline_metrics` |
| `crp_siem` | `alerts`, `alert_dedup`, `correlation_metrics` |
| `crp_ueba` | `behavior_events`, `anomaly_events`, `entity_risk_daily` |
| `crp_ti` | `ioc_hits`, `ioc_stats_daily` |
| `crp_vuln` | `exposure_snapshots`, `scan_metrics` |
| `crp_dash` | `kpi_snapshots`, `kpi_hourly`, `risk_timeline` |

### La rétention

| Table | TTL |
|---|---|
| `crp_fabric.raw_events` | 7 jours |
| `crp_siem.alert_dedup` | 1 jour |
| `crp_ueba.behavior_events` | 90 jours |
| `crp_ueba.anomaly_events` | 180 jours |
| `crp_ueba.entity_risk_daily` | 365 jours |
| `crp_siem.alerts` | 365 jours |
| `crp_vuln.scan_metrics` | 1 an |
| `crp_vuln.exposure_snapshots` | 2 ans |
| `crp_dash.kpi_hourly` | 90 jours |
| `crp_dash.risk_timeline` | 180 jours |
| `crp_dash.kpi_snapshots` | 1 an |
| `crp_*.​*_metrics` | 90 jours |
| **`crp_audit.audit_logs`** | **aucun, délibérément** |

**Pourquoi la piste d'audit n'a pas de TTL.** Un enregistrement d'audit qui
s'efface tout seul sur une minuterie est le contraire de ce à quoi sert la
table. La rétention est fixée par l'exploitant contre sa propre obligation, pas
par un défaut.

Cette table portait auparavant une politique d'étagement vers des disques
`warm` et `cold`. Un schéma ne peut pas supposer que ces disques existent : sur
tout déploiement mono-disque la commande échouait avec « No such disk », et
cette migration — la piste d'audit, la table qu'un régulateur réclame — n'était
jamais créée. L'étagement est une décision de déploiement :

```sql
ALTER TABLE crp_audit.audit_logs MODIFY TTL
    toDateTime(timestamp) + INTERVAL 30 DAY  TO DISK 'warm',
    toDateTime(timestamp) + INTERVAL 365 DAY TO DISK 'cold';
```

> **La rétention PostgreSQL n'est pas automatisée.** Aucune purge planifiée.
> Les alertes, les constats et les incidents s'accumulent.

---

## Neo4j

Deux schémas, `migrations/neo4j/000001_attack_graph.cypher` et
`000002_knowledge_graph.cypher`. Facultatif : sans `NEO4J_URI`, les deux
graphes sont lus depuis PostgreSQL, ce qui est le réglage par défaut même quand
Neo4j est présent.

PostgreSQL reste la vérité. Les écritures vont dans les deux ; une écriture
miroir a le droit d'échouer sans faire échouer la requête.

```bash
make graph-reconcile   # compare les deux, dit où ils divergent
make graph-backfill    # recopie depuis PostgreSQL, puis vérifie
make kg-reconcile
make kg-backfill
```

Les lectures ne basculent (`ATTACKPATH_GRAPH_READS=neo4j`) qu'une fois la
réconciliation à l'égalité.

---

## Redis

| Base | Service | Usage |
|---|---|---|
| 0 | `tenant` | Cache |
| 1 | `identity` | Sessions, limitation de tentatives |
| 8 | `ueba` | Compteurs comportementaux |
| 9 | `siem` | Compteurs de seuil et déduplication |

Les compteurs y vivent et non en mémoire : deux instances d'un même service
doivent compter ensemble, sinon un seuil de 5 ne se déclenche qu'à 10.

---

## Kafka

| Sujet | Produit par | Consommé par |
|---|---|---|
| `crp.events.raw` | `syslog`, `collector` | `pipeline` |
| `crp.events.normalized` | `pipeline` | `siem`, `ueba` |
| `crp.events.enriched` | `pipeline` | les domaines |
| `crp.events.alerts` | `siem` | `soar`, `dashboard` |
| `crp.events.dlq` | tous | inspection manuelle |
| `crp.events.kpi` | les domaines | `dashboard` |
| `crp.events.<domaine>` | chaque domaine | — |
| `crp.notification` | les domaines | `notification` |

Détail dans [09 — Ingestion](09-ingestion.md).

---

## Sauvegarde

Ce qu'il faut sauvegarder, et ce qui se reconstruit :

| | Sauvegarde | Remarque |
|---|---|---|
| PostgreSQL | **Indispensable** | La source de vérité |
| ClickHouse | Selon l'obligation | `audit_logs` au minimum |
| Neo4j | Inutile | Se reconstruit par `make graph-backfill` |
| Redis | Inutile | Compteurs éphémères |
| Kafka | Inutile | Transit |
| Clés JWT | **Indispensable** | Les perdre invalide tous les jetons |
| Clé de signature du contenu | **Indispensable** | La perdre impose une rotation — voir [`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md) |

> Aucune procédure de sauvegarde n'est fournie ni automatisée. Cette table dit
> quoi sauvegarder, pas comment.
