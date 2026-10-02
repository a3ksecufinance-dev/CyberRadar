# Écart entre ce qui est prévu et ce qui est mesuré

> Date : 2026-10-02 · Compare la **spécification** (`00` à `18`) à ce qui est
> **mesurable dans le dépôt**.
>
> L'audit [`19`](19-AUDIT-AND-ROADMAP.md) comparait le code à son intention —
> « ce service fait-il ce que son code prétend faire ». Ce document pose la
> question d'avant : **ce que le plan a promis existe-t-il ?**

---

## Méthode, et ses limites

Quatre comparaisons, de la plus objective à la plus interprétative :

| Comparaison | Objectivité |
|---|---|
| Les 8 KPI du master plan contre ce qui est mesuré | **Exacte** — un chiffre existe ou non |
| Les 14 NFR contre ce qui est vérifié | **Exacte** |
| Les 142 tables du schéma contre ce que le code lit | **Exacte** — script de comparaison |
| Les 183 routes du catalogue d'API contre les 477 servies | **Exacte**, après neutralisation des renommages |
| Les 346 user stories contre le code | **Interprétative** — c'est mon jugement |

Pour les user stories, chaque ligne est classée en **Fait**, **Partiel** ou
**Absent**, avec une preuve pointable (une route, une table, un paquet). Le
classement est le mien ; une équipe qui le relit déplacera des lignes, mais
l'ordre de grandeur ne bougera pas.

**« Partiel » a un sens précis** : le mécanisme existe et la fonction demandée
n'est pas atteinte. Le champ `trigger_conditions` existe sur un playbook et
rien ne l'évalue — c'est partiel, pas fait.

---

## 1. Les KPI du master plan : 8 annoncés, 0 mesuré

| KPI | Objectif | Mesuré |
|---|---|---|
| MTTD | < 5 min | **jamais** |
| MTTR | < 15 min | calculé dans `soar` et sur les cas SIEM, **jamais mesuré en charge** |
| Réduction des faux positifs | −70 % | **jamais** — et rien n'apprend des faux positifs |
| Couverture des actifs | 100 % automatique | **0 %** — aucune découverte automatique n'existe |
| Disponibilité | 99,99 % | **jamais** — pas de haute disponibilité |
| Débit MVP | 100 K EPS | **jamais** |
| Débit cible | 1 M+ EPS | **jamais** |
| Latence API | < 200 ms | **jamais** — l'histogramme est borné pour la lire, rien ne l'a chargé |

**Zéro sur huit.** Ce n'est pas que les chiffres soient mauvais : **personne
n'a jamais regardé**. C'est l'écart le plus lourd du document, parce que ces
huit chiffres sont ceux qui figureront dans une réponse à appel d'offres.

## 2. Les exigences non fonctionnelles : 14 annoncées, 0 vérifiée

| NFR | Annoncé | Réalité mesurable |
|---|---|---|
| `NFR-FND-001` | Disponibilité 99,99 % | Mono-instance, aucune réplication |
| `NFR-FND-002` | Scalabilité horizontale | Les services sont sans état et les compteurs sont dans Redis — **structurellement possible, jamais exercé** |
| `NFR-FND-003` | Mise à jour sans interruption | Aucun orchestrateur |
| `NFR-FND-004` | Reprise < 15 min | Aucune restauration jamais exécutée |
| `NFR-FND-005` | Latence API < 200 ms | Non mesurée |
| `NFR-CDF-001` | 100 K EPS | Non mesuré |
| `NFR-CDF-002` | Latence pipeline < 3 s | Non mesurée |
| `NFR-CDF-003` | Uptime 99,99 % | — |
| `NFR-CDF-004` | Scaling horizontal | Comme `FND-002` |
| `NFR-CDF-005` | Zéro perte de données | **La DLQ existe et rien ne la consomme** : un événement perdu est tracé, pas récupéré |
| `NFR-CAI-001` | Support 1M+ actifs | Non mesuré |
| `NFR-CAI-002` | Découverte < 5 min | **Sans objet** : aucune découverte |
| `NFR-CAI-003` | Précision > 95 % | **Sans objet** : aucune classification automatique |
| `NFR-CAI-004` | Uptime 99,99 % | — |

Deux d'entre elles sont **sans objet** parce que la fonction qu'elles
qualifient n'existe pas. C'est pire qu'un objectif non tenu : c'est un objectif
qui n'a rien à qualifier.

---

## 3. Le schéma : 142 tables, 5 mortes

**C'est le bon chiffre du document.** Le schéma n'est pas une déclaration
d'intention : **97 % des tables sont réellement lues ou écrites par du code.**

Les cinq que rien ne nomme dans le code Go :

| Table | Ce qu'elle devait porter | Conséquence |
|---|---|---|
| `config_entries` | La configuration centralisée (`US-FND-CFG-001`) | L'épique entière est absente |
| `config_history` | Le rollback de configuration (`US-FND-CFG-002`) | Idem |
| `notification_rules` | L'escalade automatique (`US-FND-NOT-002`) | Absente |
| `identity_privileges` | L'inventaire des privilèges | Absent |
| `asset_scans` | L'historique de scan d'un actif | Absent |

> **Une table sans code est pire qu'une table absente** : elle fait croire à
> une revue de schéma que la fonction existe. Les cinq doivent être soit
> implémentées, soit supprimées par une migration qui dit pourquoi.

---

## 4. Le catalogue d'API : 183 annoncées, 8 familles entièrement absentes

Le catalogue [`18-API-CATALOG.md`](18-API-CATALOG.md) annonçait 183 routes. Il
en existe 477 — mais ce ne sont pas les mêmes : la plateforme a beaucoup
construit **à côté** du catalogue, pas dedans.

Après neutralisation des renommages (`/cti/ioc` est servi comme `/ti/iocs`,
`/attack-paths` comme `/attackpath`), **huit familles n'existent sous aucun
nom** :

| Famille absente | Routes annoncées | Ce que ça retire |
|---|---|---|
| `connectors` | 5 | Toute la gestion des connecteurs : santé, configuration, statistiques |
| `config` | 4 | La configuration centralisée et son historique |
| `search` | 3 | La recherche et le langage de requête |
| `replay` | 3 | Le rejeu de flux |
| `dependencies` | 2 | La cartographie de dépendances |
| `schema` | 2 | Le registre de schéma |
| `graphql` | 1 | GraphQL, annoncé dans la pile technique |
| `sla` | 1 | L'endpoint SLA (les délais existent, l'endpoint non) |

Le catalogue est lui-même périmé : la référence d'aujourd'hui est
[`../docs/07-reference-api.md`](../docs/07-reference-api.md), générée depuis le
code et vérifiée en CI. **`18-API-CATALOG.md` devrait être marqué comme
historique** pour qu'il ne soit plus lu comme un engagement.

---

## 5. La pile technique annoncée

| Composant annoncé | État |
|---|---|
| ClickHouse | ✅ 18 tables, 7 bases |
| Neo4j | ✅ derrière une abstraction, **lectures en PostgreSQL par défaut** |
| PostgreSQL | ✅ 142 tables |
| pgvector | ✅ RAG du Copilot |
| Kafka | ✅ 4 états d'événement, DLQ, reprise exponentielle |
| **API Gateway (Kong ou maison)** | ❌ **aucune** — 30 ports exposés |
| OpenTelemetry + Grafana | 🟡 instrumenté ; aucun tableau de bord livré, aucune alerte |
| Vault | 🟡 `identity` seul y puise ; les 29 autres lisent l'environnement |
| Keycloak | ✅ OIDC ; **SAML annoncé et absent** |

L'absence de passerelle n'est pas un détail d'infrastructure : trois user
stories en dépendent (`US-API-GW-001`, `GW-003`, `US-FND-API-004`), et c'est
aussi là que vivraient la limitation de débit et la terminaison TLS.

---

## 6. Les 346 user stories

| Domaine | US | Fait | Partiel | Absent | Taux |
|---|---:|---:|---:|---:|---:|
| D0 Foundation | 40 | 11 | 8 | 21 | 28 % |
| D1 Cyber Data Fabric | 35 | 16 | 7 | 12 | **46 %** |
| D2 Asset Intelligence | 33 | 4 | 4 | 25 | **12 %** |
| D3 Identity & PAM | 23 | 5 | 4 | 14 | 22 % |
| D4 SIEM / XDR | 31 | 14 | 7 | 10 | **45 %** |
| D5 UEBA | 24 | 5 | 3 | 16 | 21 % |
| D6 Threat Intelligence | 21 | 8 | 3 | 10 | 38 % |
| D7 Vulnerability & Exposure | 19 | 7 | 3 | 9 | 37 % |
| D8 Attack Path | 16 | 2 | 2 | 12 | **13 %** |
| D9 Knowledge Graph | 18 | 5 | 3 | 10 | 28 % |
| D10 SOAR | 22 | 4 | 5 | 13 | 18 % |
| D11 Dashboards | 22 | 7 | 4 | 11 | 32 % |
| D12 AI Copilot | 19 | 10 | 7 | 2 | **53 %** |
| D13 API Framework | 15 | 3 | 2 | 10 | 20 % |
| D14 Security & Compliance | 8 | 0 | 3 | 5 | **0 %** |
| **Total** | **346** | **101** | **65** | **180** | **29 %** |

**29 % faits, 19 % partiels, 52 % absents.**

### Ce que la répartition dit, et qui surprend

**Le Copilot est le domaine le plus complet (53 %)** alors qu'il était classé
priorité **BASSE** au master plan. L'inverse est vrai de D2 Asset Intelligence
(12 %, priorité HAUTE) et D14 Security & Compliance (0 %, priorité HAUTE).

Ce n'est pas un hasard : **ce qui a été construit est ce qui est construisible
sans connecteur.** Le Copilot lit les données déjà là. L'inventaire d'actifs
suppose de découvrir un parc, et la conformité suppose d'évaluer des contrôles
contre un parc découvert. Les deux attendent la même chose, qui n'existe pas.

### Le trou structurant : zéro découverte

| Domaine | Ce qui manque |
|---|---|
| D2 | Les 7 US de découverte (`US-CAI-DIS-001` à `007`) : réseau, cloud, Kubernetes, SaaS, passif depuis les logs — **toutes absentes** |
| D3 | `US-IPM-INV-002` découverte des comptes depuis AD/LDAP/IAM/PAM — absente |
| D7 | `US-VEI-DIS-001/002/003` : scanners, NVD, Qualys/Tenable — **toutes absentes** |
| D6 | `US-CTI-FED-002` mise à jour automatique des feeds — absente |

**Rien n'entre tout seul dans la plateforme.** Les données arrivent par syslog,
par l'API, ou par le jeu de démonstration. C'est le même trou vu de quatre
domaines, et il explique à lui seul une grande part des 180 absences : un
inventaire qu'on ne découvre pas ne peut pas être classifié, ni corrélé, ni
évalué pour sa conformité.

### Les familles d'absence, par taille

| Famille | US perdues | Exemples |
|---|---:|---|
| **Découverte et connecteurs** | ~34 | Découverte d'actifs, AD/LDAP, scanners, feeds, SDK connecteur |
| **Analyse avancée** | ~28 | Blast radius, centralité, PageRank, kill chain, story graph, pairs UEBA, insider threat |
| **Interfaces riches** | ~22 | Visualisation de graphe, war room, constructeur de tableaux de bord, drag & drop, heatmap |
| **Gouvernance de la réponse** | ~14 | Approbation humaine, simulation de playbook, rollback d'action, escalade |
| **Intégrations tierces** | ~12 | ServiceNow, Jira, EDR, AD, STIX/TAXII, SDK Python et JS |
| **Recherche et forensic** | ~11 | Full-text, langage de requête, rejeu, timeline d'investigation |
| **Rapports** | ~10 | PDF, conformité PCI/SWIFT/ISO, rapports récurrents |
| Divers | ~49 | ABAC, JIT, feature flags, canary, GraphQL, OpenAPI… |

---

## 7. Les cinq écarts qui comptent

Sur 180 absences, cinq décident de la suite. Les 175 autres sont du produit à
construire ; ces cinq sont des promesses à tenir ou à retirer.

### 1. Les huit KPI annoncés, zéro mesuré

C'est le seul écart qui peut coûter une affaire **sans correctif possible**.
Un chiffre démenti en réunion ne se rattrape pas. Mesurer, puis tenir le
chiffre ou le changer — [`21-PRODUCTION-PLAN.md`](21-PRODUCTION-PLAN.md) J1.7.

### 2. Zéro découverte automatique

La promesse « couverture des actifs : 100 % automatique » est à **0 %**, et
c'est la racine de D2 (12 %), D7 partiel, D3 partiel et D14 (0 %). Un
connecteur — un seul, l'annuaire ou un scanner — déplace quatre domaines.

### 3. D14 Conformité à 0 % alors que la cible est bancaire

Huit US, zéro faite. Les référentiels sont en base, les contrôles aussi, **et
rien ne les évalue ni ne génère de rapport**. Pour un produit qui s'adresse à
des banques, c'est le domaine dont l'absence se remarque le plus vite — et
`compliance:read` figure déjà dans la matrice de permissions, ce qui donne
l'impression du contraire.

### 4. Pas d'approbation humaine dans un playbook

`US-SOR-WFL-003` et les trois `US-SOR-APR-*` sont absentes. Les quinze actions
SOAR sont **réelles** : elles bloquent une adresse, désactivent un compte,
isolent une machine. Sans palier d'approbation, un client prudent n'activera
aucune. C'est une fonctionnalité qui rend utilisable ce qui est déjà construit.

### 5. Cinq tables sans code

Petit en volume, mauvais en signal : une revue de schéma conclut que la
configuration centralisée existe. Implémenter ou supprimer, pas laisser.

---

## 8. Ce que l'écart ne dit pas

Un taux de 29 % se lit mal sans trois précisions.

**Ce qui est fait est solide, pas esquissé.** Les 101 US faites le sont avec
des décisions tenues : RS256 à clé unique, autorisation vérifiée sur les 477
routes, compteurs partagés dans Redis, contenu de détection signé et vérifié
avant analyse, quatre politiques versionnées et datées. Ce n'est pas 29 % d'un
prototype, c'est 29 % d'un produit.

**Le master plan décrivait un concurrent de Splunk plus CrowdStrike plus
Tenable.** 346 US sur 15 domaines, c'est le périmètre de trois éditeurs. Un
taux de 29 % sur ce périmètre n'est pas le même objet qu'un taux de 29 % sur un
périmètre de MVP. L'audit [`19`](19-AUDIT-AND-ROADMAP.md) §6.2 recommandait
déjà de choisir un angle d'attaque plutôt que d'affronter Splunk de face : **ce
tableau est la justification chiffrée de cette recommandation.**

**Six domaines se tiennent, neuf non.** D1, D4, D12 sont au-dessus de 45 % et
ce sont les trois qui tiennent une démonstration. D2, D8, D10, D13, D14 sont
sous 20 %. Le produit vendable aujourd'hui est l'intersection — pas la réunion.

---

## 9. Ce qu'il faut en faire

Trois actions, par ordre d'urgence.

1. **Mesurer les huit KPI** avant qu'un prospect les challenge. Trois jours,
   et c'est le seul écart irréversible.
2. **Trancher le périmètre annoncé.** Soit le master plan est révisé pour
   décrire ce qui sera livré, soit il reste une cible à long terme et **cesse
   d'être le document qu'on montre**. Aujourd'hui il annonce 346 US et un
   produit en livre 101 : un prospect qui lit les deux voit l'écart.
3. **Marquer [`18-API-CATALOG.md`](18-API-CATALOG.md) comme historique.** La
   référence est [`../docs/07-reference-api.md`](../docs/07-reference-api.md),
   générée et vérifiée en CI. Deux catalogues dont un faux est pire qu'un seul.

Le reste est du produit, et il est séquencé dans
[`21-PRODUCTION-PLAN.md`](21-PRODUCTION-PLAN.md).
