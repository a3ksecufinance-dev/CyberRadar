# CyberRadar Platform (CRP)

Plateforme de cybersécurité multi-tenant : ingestion d'événements, détection
SIEM/XDR, analyse comportementale, gestion des vulnérabilités et réponse à
incident. Backend Go en microservices, frontend Next.js.

- **Architecture et roadmap** : [`plan/00-MASTER-PLAN.md`](plan/00-MASTER-PLAN.md)
- **Audit de code et état réel** : [`plan/19-AUDIT-AND-ROADMAP.md`](plan/19-AUDIT-AND-ROADMAP.md)
  — à lire avant de contribuer : il liste ce qui fonctionne, ce qui est encore
  simulé, et les décisions en attente.

---

## Démarrage local

### Prérequis

Go 1.22+, Node 20+, Docker et Docker Compose, `psql`, `openssl`.

### Backend

```bash
cd backend

make jwt-keys      # génère la paire RSA de signature des jetons (obligatoire)
make infra-up      # postgres, clickhouse, redis, kafka, vault, jaeger, prometheus, grafana
make migrate       # applique les 30 migrations PostgreSQL + ClickHouse
make dev           # démarre les 32 services
```

`make dev` dépend déjà de `jwt-keys` : sans la paire de clés, **aucun service ne
démarre** — ils refusent de se lancer plutôt que de tourner sans vérification de
jeton.

Optionnel, pour exercer le chemin Vault plutôt que les variables d'environnement :

```bash
make vault-seed    # écrit les secrets de dev dans Vault
```

### Frontend

```bash
cd frontend
cp .env.example .env.local   # puis renseigner NEXTAUTH_SECRET et les valeurs Keycloak
npm ci
npm run dev                  # http://localhost:3000
```

### Vérifier que tout tourne

```bash
curl localhost:8002/health     # identity
curl localhost:8002/metrics    # métriques exposées par le service
```

| Interface | URL |
|---|---|
| Frontend | <http://localhost:3000> |
| Grafana | <http://localhost:3001> |
| Prometheus | <http://localhost:9090> |
| Jaeger | <http://localhost:16686> |
| Keycloak | <http://localhost:8080> |
| Vault | <http://localhost:8200> |

---

## Structure

```
backend/
  internal/pkg/        module Go partagé par tous les services
    authctx/           identité de l'appelant dans le contexte de requête
    authmw/            middleware d'authentification et d'autorisation
    jwt/               émission et vérification des jetons (RS256)
    observe/           métriques Prometheus et traces OpenTelemetry
    vault/             lecture de secrets, avec repli sur l'environnement
    db/ cache/ kafka/  accès PostgreSQL, ClickHouse, Redis, Kafka
    errors/ response/  erreurs de domaine et réponses HTTP normalisées
  services/<domaine>/  un module Go par service
    cmd/server/        point d'entrée
    internal/handler/  routes HTTP
    internal/service/  logique métier
    internal/repository/ accès aux données
    internal/model/    types du domaine
  migrations/          SQL PostgreSQL et ClickHouse, appliquées dans l'ordre
  deployments/         docker-compose, prometheus, keycloak
  policies/            policies OPA (spécification ; pas encore exécutées)
  scripts/             génération de clés et de certificats, amorçage Vault

frontend/src/
  app/[locale]/        routes Next.js (App Router, i18n fr/en)
  components/          composants UI
  hooks/               accès API via SWR
  lib/                 client HTTP, configuration NextAuth
```

Chaque service est **son propre module Go**, liés par `go.work`. Conséquence
pratique : `go build ./...` depuis `backend/` ne matche rien. Les cibles du
Makefile parcourent les modules — utilisez-les.

```bash
make build      # compile les 32 binaires
make test       # tests de tous les modules
make vet        # go vet sur tous les modules
make fmt-check  # échoue si un fichier n'est pas gofmt
```

---

## Conventions

### Authentification

`identity-service` est le **seul émetteur de jetons** : il détient la clé privée
RSA. Les 30 autres services montent la clé publique en lecture seule et peuvent
vérifier sans jamais signer. Un service compromis ne peut donc pas forger de
jeton pour les autres.

Protéger une route :

```go
r.Route("/api/v1", func(r chi.Router) {
    r.Use(authmw.RequireJWT(jwtVerifier, logger))        // 401 si le jeton est invalide
    r.Use(authmw.RequirePermissionByMethod("assets"))     // 403 sans assets:read|write|delete
    handler.RegisterRoutes(r)
})
```

Lire l'appelant depuis un handler :

```go
tenantID := authctx.TenantID(r.Context())   // jamais depuis le corps de la requête
userID   := authctx.UserID(r.Context())
```

> **Ne jamais lire le contexte directement** (`r.Context().Value("tenant_id")`).
> C'est ainsi que cinq services ont silencieusement perdu leur isolation tenant :
> les clés étaient écrites et relues avec des types différents, ce que ni le
> compilateur ni `go vet` ne signalent. Le package `authctx` rend l'erreur
> impossible à exprimer.

### Autorisation

Les permissions sont nommées `ressource:action` (`alerts:read`, `pam:write`),
résolues à la connexion depuis `role_permissions` et portées par le jeton.
Ajouter une ressource se fait par migration — voir `000030` pour le format.

`RequirePermissionByMethod` dérive l'action : `GET` → `read`, `DELETE` →
`delete`, le reste → `write`. Quand les routes d'un service ne relèvent pas de
la même autorité, protégez par groupe plutôt qu'en bloc (voir `siem`, `ir`,
`audit`).

### Observabilité

Le middleware `observe.Middleware` est monté **avant** l'authentification, afin
que les requêtes rejetées soient comptées : un pic de 401 est précisément ce
qu'un opérateur doit voir. Le label `route` est toujours le motif chi, jamais le
chemin brut — sinon un identifiant par requête ferait exploser la cardinalité.

### Secrets

`internal/pkg/vault` lit Vault quand il est configuré, l'environnement sinon.
Un échec de lecture Vault est signalé **même quand le repli réussit** : un
service qui tourne discrètement sur l'environnement alors qu'on le croit sur
Vault est exactement la mauvaise configuration à rendre visible.

### Tests

```bash
cd backend/services/<service> && go test ./...
```

Les tests de `internal/pkg/jwt`, `authmw` et `observe` couvrent des propriétés
de sécurité (confusion d'algorithme, isolation des permissions, cardinalité des
labels). Ne les affaiblissez pas pour faire passer un changement.

---

## Pièges connus

| Piège | Détail |
|---|---|
| `go build ./...` depuis `backend/` | Ne matche rien : workspace multi-modules. Utiliser `make`. |
| Migrations non idempotentes | Les rejouer sur une base existante échoue partiellement. Repartir d'une base vierge. |
| Pas d'outil de migration versionné | `make migrate` boucle sur les fichiers avec `psql`. Aucune table de suivi. |
| Le frontend a besoin de Keycloak | Sans lui, `/login` renvoie une erreur de configuration NextAuth. |
| `next.config` doit rester `.mjs` | Next 14 ne supporte pas une configuration TypeScript. |
| Les clés et certificats ne sont pas versionnés | `.gitignore` exclut `*.pem` et `*.key`. Les générer localement. |

---

## Points encore ouverts

À connaître avant de bâtir dessus — le détail et les raisons sont dans
[`plan/19-AUDIT-AND-ROADMAP.md`](plan/19-AUDIT-AND-ROADMAP.md) :

- **Les actions SOAR sont simulées.** L'orchestration est réelle, mais
  `block_ip`, `isolate_host` et consorts renvoient des valeurs figées.
- **Neo4j est absent.** Attack Path et Knowledge Graph tournent sur PostgreSQL.
- **Pas de magasin vectoriel.** Le Copilot n'a pas de RAG.
- **Kafka sans DLQ ni backoff.** Une erreur de traitement rejoue indéfiniment ou
  disparaît. Inacceptable en l'état pour un SIEM.
- **Les compteurs SIEM/UEBA/PAM sont en mémoire.** Ils ne survivent ni au
  redémarrage ni à la mise à l'échelle horizontale.
- **Sept pages frontend affichent des données figées** : `ot`, `risk`, `ir`,
  `scs`, `attackpath`, `compliance`, `settings`.
- **Les appels machine ne sont pas authentifiés individuellement.**
  `collector` et `POST /audit/events` attendent une identité de service.
- **La matrice de permissions est un point de départ**, pas une politique
  arrêtée. À revoir avant production.

---

## Contribuer

La CI (`.github/workflows/ci.yml`) exécute, sur chaque PR : format, build, vet
et tests du backend ; application des migrations sur une base vierge ; typecheck,
lint et build du frontend ; scan de vulnérabilités des dépendances.

Faites tourner l'équivalent localement avant de pousser :

```bash
cd backend && make fmt-check && make build && make vet && make test
cd ../frontend && npm run type-check && npm run lint && npm run build
```
