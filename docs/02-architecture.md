# 02 — Architecture

## La forme générale

32 services Go, chacun un module de l'espace de travail `backend/go.work`
(33 modules avec le socle partagé `internal`). Une interface Next.js.
PostgreSQL comme source de vérité, ClickHouse pour les séries temporelles,
Kafka entre les étages d'ingestion, Redis pour les compteurs partagés, Neo4j
facultatif pour les deux graphes.

Les 32 ne sont pas de la même espèce :

| | Combien | Ce que c'est |
|---|---|---|
| Services d'API | **30** | Ports 8001–8030, chacun avec `/health` et un sous-arbre `/api/v1` |
| Connecteur syslog | 1 | Écoute, parse, publie. Pas d'API : seulement `/health` sur :8031 |
| Travailleur de pipeline | 1 | `cmd/worker`, pas de serveur HTTP du tout |

`make build` produit 36 binaires : les 32, plus `contentctl`, `demo-seed`,
`attackpath-reconcile` et `kg-reconcile`.

```
                      ┌──────────────────────────────┐
                      │   Interface Next.js (:3000)  │
                      └───────────────┬──────────────┘
                                      │  JWT RS256
      ┌───────────────────────────────┼───────────────────────────────┐
      ▼                               ▼                               ▼
┌───────────┐                   ┌───────────┐                   ┌───────────┐
│  identity │                   │   siem    │                   │   …28     │
│   :8002   │                   │   :8008   │                   │  autres   │
└─────┬─────┘                   └─────┬─────┘                   └─────┬─────┘
      │                               │                               │
      └───────────────┬───────────────┴───────────────┬───────────────┘
                      ▼                               ▼
              ┌───────────────┐               ┌───────────────┐
              │  PostgreSQL   │               │     Kafka     │
              │   (vérité)    │               │  (ingestion)  │
              └───────────────┘               └───────────────┘
                      │                               │
         ┌────────────┴──────────┐                    │
         ▼                       ▼                    ▼
   ┌───────────┐           ┌──────────┐        ┌─────────────┐
   │ClickHouse │           │  Neo4j   │        │   Redis     │
   │ (séries)  │           │(optionnel)│       │ (compteurs) │
   └───────────┘           └──────────┘        └─────────────┘
```

**Pas de passerelle d'API.** L'interface appelle chaque service sur son port.
C'est un choix assumé en développement et un sujet ouvert pour la production :
voir « Ce qui n'est pas résolu » plus bas.

---

## Un service, de l'extérieur

Tous les services suivent la même forme. Ouvrir n'importe quel
`services/<nom>/cmd/server/main.go` donne la même lecture :

```go
r := chi.NewRouter()
r.Use(corsmw.Middleware(...))          // origines depuis CORS_ALLOWED_ORIGINS
r.Use(observe.Middleware("x-service")) // traces OTel + métriques Prometheus
r.Use(chimiddleware.RequestID, RealIP, Recoverer, Timeout(30s))

r.Get("/health", ...)                  // sans authentification

r.Route("/api/v1", func(r chi.Router) {
    r.Use(authmw.RequireJWT(verifier, logger, providerOpt))
    r.Use(authmw.RequirePermissionByMethod("vulnerabilities"))
    handler.RegisterRoutes(r)
})
```

Ce qui en découle, et qui vaut pour les 30 services d'API :

- `/health` répond sans jeton — c'est ce que la sonde de disponibilité appelle.
- Tout `/api/v1` exige un JWT valide, vérifié avec la **clé publique** RS256 ;
  aucun service ne détient la clé privée sauf `identity`.
- L'autorisation est un middleware, pas une vérification dispersée dans les
  handlers. `RequirePermissionByMethod("x")` se résout en `x:read` pour GET et
  `x:write` sinon ; `RequirePermission("x:y")` est posé route par route quand le
  verbe ne suffit pas.
- Le délai maximal d'une requête est de 30 s, imposé par le routeur.

---

## Les couches dans un service

```
cmd/server/main.go        câblage : env, pools, routeur, arrêt propre
internal/handler/         HTTP : décoder, appeler, encoder, traduire l'erreur
internal/service/         la logique du domaine, sans SQL ni HTTP
internal/repository/      SQL, et rien d'autre
internal/model/           les types du domaine, et les règles qui ne dépendent
                          de rien (calculs, seuils, validations)
```

La règle qui tient l'ensemble : **une erreur traverse les couches comme une
valeur typée, pas comme un code HTTP**. `internal/pkg/errors` définit six
genres ; `internal/pkg/httperr` les traduit, et traduit aussi les codes SQLSTATE
de PostgreSQL. Voir [06 — API](06-api.md).

---

## Le socle partagé

`backend/internal/pkg/` est le module commun. Ce qu'il contient, et pourquoi
chacun existe :

| Paquet | Rôle |
|---|---|
| `authmw` | Le middleware d'authentification et d'autorisation, **un seul**. Il a remplacé 30 copies divergentes. |
| `authctx` | Le porteur d'identité dans le contexte : tenant, utilisateur, permissions. |
| `jwt` | Signature et vérification RS256. `Signer` n'existe que chez `identity`. |
| `rbac` | Résolution des permissions d'une identité, rôles compris. |
| `svcauth` | L'identité de service : un service qui appelle un autre porte son propre jeton, pas celui de l'appelant. |
| `oidc` | Vérification des jetons émis par Keycloak. |
| `response` | L'enveloppe de réponse unique (`data` / `meta` / `error`). |
| `errors`, `httperr` | Les genres d'erreur et leur traduction HTTP, SQLSTATE compris. |
| `db` | Les pools PostgreSQL, avec leurs réglages par défaut. |
| `kafka` | Producteur et consommateur, avec reprise exponentielle et file d'échec. |
| `event` | Le type `NormalizedEvent` : le contrat entre les étages d'ingestion. |
| `iocindex` | L'index d'indicateurs, assez rapide pour être interrogé sur chaque événement. |
| `cache` | Redis : les compteurs que plusieurs instances d'un même service partagent. |
| `graphdb` | L'abstraction derrière laquelle Neo4j est facultatif. |
| `observe` | Traces OpenTelemetry et métriques Prometheus. |
| `vault` | Lecture des secrets. |
| `kpi` | Publication des instantanés de KPI vers `crp.events.kpi`. |
| `corsmw` | CORS, origines depuis l'environnement. |
| `apicheck` | Le relevé de toutes les lectures de tous les services, exercé contre une plateforme qui tourne. |
| `deploycheck` | Vérifie que la table des services du script de développement et `docker-compose.yml` disent la même chose. |
| `devtoken` | Frappe un jeton pour un utilisateur donné — outillage de test, jamais en production. |

---

## Les dépôts de données

| Dépôt | Ce qu'il porte | Pourquoi lui |
|---|---|---|
| **PostgreSQL 16 + pgvector** | La source de vérité : tenants, identités, actifs, règles, alertes, constats, politiques. Et les plongements du Copilot. | Transactions, contraintes, index partiels. Les politiques versionnées en dépendent. |
| **ClickHouse** | Événements bruts, alertes, séries UEBA, agrégats de tableau de bord. | Volume et lectures analytiques ; TTL pour la rétention. |
| **Kafka** | Les quatre états d'un événement en transit, plus les sujets par domaine. | Découple l'ingestion du traitement, et absorbe les pics. |
| **Redis** | Compteurs de seuil SIEM et UEBA, cache court. | Deux instances d'un même service doivent compter ensemble, pas chacune pour soi. |
| **Neo4j** *(facultatif)* | Graphe d'attaque, graphe de connaissance. | Les parcours à profondeur variable. Sans lui, PostgreSQL fait le travail — et c'est le défaut (`ATTACKPATH_GRAPH_READS=postgres`). |
| **Vault** | Secrets. | Un secret dans une variable d'environnement est un secret dans la liste des processus. |
| **Keycloak** | Fournisseur d'identité OIDC. | L'authentification des personnes ; la plateforme émet ensuite ses propres jetons. |

Détail des schémas : [08 — Données](08-donnees.md).

---

## Trois décisions structurantes

### Un middleware d'authentification, pas trente

Chaque service avait sa copie, et elles avaient divergé : certaines vérifiaient
la signature, d'autres décodaient le jeton sans la vérifier. `authmw` est
désormais la seule implémentation. Une faille d'authentification corrigée à un
endroit l'est partout, ce qui n'était pas vrai avant.

### Une identité de service distincte de celle de l'appelant

Quand `soar` appelle `netsec` pour bloquer une adresse, il porte **son** jeton,
pas celui de l'analyste. Deux raisons : l'analyste n'a pas forcément la
permission `netsec:write`, et le journal d'audit doit montrer que c'est le
playbook qui a agi, pas la personne qui l'a lancé. `svcauth` porte cette
identité ; les comptes de service sont en base (migration 31).

### Le graphe derrière une abstraction

`graphdb` expose `GraphStore`. PostgreSQL et Neo4j l'implémentent tous les
deux. Le choix est une variable d'environnement, par domaine
(`ATTACKPATH_GRAPH_READS`, `KG_GRAPH_READS`), et les écritures vont dans les
deux quand Neo4j est présent — une écriture miroir a le droit d'échouer sans
faire échouer la requête, parce que PostgreSQL reste la vérité.

`make graph-reconcile` et `make kg-reconcile` comparent les deux et disent où
ils divergent ; `make graph-backfill` recopie depuis PostgreSQL puis vérifie.

---

## Ce qui n'est pas résolu

Dit ici parce que c'est de l'architecture, pas du détail :

- **Pas de passerelle d'API.** L'interface connaît 30 adresses. En production,
  il faudrait un point d'entrée unique qui porte TLS, la limitation de débit et
  le routage — et c'est aussi là que devrait vivre la vérification du jeton,
  qui est aujourd'hui répétée 31 fois (par le même code, mais répétée).
- **31 unités déployables pour un produit.** L'audit recommande de consolider
  vers 8 à 10 : voir [`../plan/19-AUDIT-AND-ROADMAP.md`](../plan/19-AUDIT-AND-ROADMAP.md) §6.1.
- **Pas de corrélation inter-domaines.** Chaque service décide seul ; rien ne
  relie une anomalie comportementale à un chemin d'attaque.
- **La migration PostgreSQL n'est pas rejouable.** Le script d'installation le
  dit et propose `reset`. Un outil de migration avec état (golang-migrate ou
  équivalent) reste à adopter.
