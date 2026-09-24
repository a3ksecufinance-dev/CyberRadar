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

### Identité de service

Les appels machine ne sont plus « un jeton valide quelconque ». Un compte de
service est une identité de type `service_account` : rôles et permissions
viennent de `identity_roles`, donc le catalogue RBAC s'applique aux machines
sans modèle parallèle.

```bash
# 1. l'administrateur crée le compte — le secret n'est affiché qu'ici
curl -X POST localhost:8002/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"client_id":"collector-agent-bankA","scope":"tenant",
       "role_ids":["10000000-0000-0000-0000-000000000012"],"expires_in_days":90}'

# 2. la machine échange son credential contre un jeton de 15 minutes
curl -X POST localhost:8002/api/v1/auth/service-token \
  -d '{"client_id":"collector-agent-bankA","client_secret":"..."}'
```

Côté service Go, `internal/pkg/svcauth` s'en charge : il récupère le jeton, le
met en cache et le renouvelle avant expiration.

Protéger une route réservée aux machines :

```go
r.Use(authmw.RequireServiceAccount())          // 403 pour un humain
r.Use(authmw.RequirePermission("events:ingest"))
```

> Les deux sont nécessaires. La permission seule ne suffit pas : elle s'accorde
> à un rôle, et un rôle donné par erreur à une personne ouvrirait la route en
> silence. Exiger que le jeton nomme un compte de service rend cette erreur
> inexprimable par simple attribution.

**Deux portées.** `tenant` (par défaut) : le jeton est toujours pour le tenant
du compte — un agent d'ingestion chez une banque ne peut pas écrire pour une
autre. `platform` : le compte nomme explicitement le tenant pour lequel il agit,
ce qui permet à un seul SOAR de traiter l'alerte de n'importe quel client. C'est
un droit large, donc réservé au super admin à la création et journalisé à chaque
émission (`cross_tenant: true`). **Il n'existe aucun jeton « tous tenants »** :
tout jeton nomme exactement un tenant.

### Remédiation automatisée

Les actions de playbook appellent réellement les services de la plateforme,
avec le jeton du compte de service du SOAR et rien d'autre. Un échec du
service cible **fait échouer l'étape** : c'est ce qui rend `on_failure: abort`
opérant.

```bash
# créer le compte du SOAR, une fois (super admin requis : portée platform)
curl -X POST localhost:8002/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"client_id":"soar-executor","scope":"platform",
       "role_ids":["10000000-0000-0000-0000-000000000014"]}'
```

Le rôle `soar_executor` (migration `000032`) porte exactement les onze droits
que les actions utilisent, et rien de plus : un credential SOAR capturé ne doit
pas être un moyen de lire à loisir les alertes ou les actifs d'un client.

Ajouter une action : une méthode dans `dispatcher.go` qui construit un `call`
(service, méthode, chemin, corps) et le passe à `send`. Un service sans URL
configurée désactive les actions qui en dépendent, et elles échouent en le
disant — plutôt que de rapporter un confinement qui n'a pas eu lieu.

### Activité par fenêtre (PAM)

`identity_activity_daily` tient une ligne par identité et par jour UTC. Les
chiffres du profil de risque — `events_today`, `events_7d`, `anomaly_count_7d`,
`anomaly_count_30d`, `priv_sessions_30d` — en sont la somme sur leur fenêtre,
et non des compteurs incrémentés à vie.

L'incrément se fait **dans la base**, pas en Go :

```sql
ON CONFLICT (tenant_id, identity_id, day) DO UPDATE SET
    events = identity_activity_daily.events + EXCLUDED.events
```

Le profil était auparavant lu, incrémenté en mémoire puis réécrit en entier.
Mesuré sur cette base : 8 écrivains concurrents × 25 incréments en lecture-
modification-écriture n'enregistrent que **39 des 200**. L'upsert atomique les
enregistre tous.

La rétention est de 30 jours — la plus large fenêtre utilisée. Le service PAM
purge au démarrage puis toutes les 6 heures.

### Compteurs de détection

Les seuils SIEM et les compteurs UEBA (vélocité, brute-force) passent par
`cache.Window`, adossé à Redis, et non par une map de processus : un seuil doit
valoir pour le service, pas pour la réplica qui a reçu l'événement.

```go
count, _ := window.Count(ctx, tenantID+"|"+entityID, 5*time.Minute)
```

`Count` ne renvoie jamais d'erreur : sans Redis il compte en mémoire plutôt que
de rendre une erreur qu'un appelant lirait comme « aucun événement ». La
dégradation se lit dans `crp_sliding_window_fallback_total` — à surveiller, car
elle signifie que les seuils sont redevenus locaux à chaque réplica.

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

- **Le SOAR a besoin de son compte de service.** Sans `SOAR_CLIENT_ID` /
  `SOAR_CLIENT_SECRET` valides, chaque étape de playbook échoue — bruyamment,
  ce qui est le comportement voulu, mais aucune remédiation ne part.
- **`unblock_ip` et `unisolate_host` attendent le `policy_id`** renvoyé par
  l'étape qui a posé la règle. netsec n'expose pas de suppression : la règle
  passe en `log` plutôt que d'être retirée, ce qui laisse la trace.
- **Neo4j est absent.** Attack Path et Knowledge Graph tournent sur PostgreSQL.
- **Pas de magasin vectoriel.** Le Copilot n'a pas de RAG.
- **Les compteurs de détection ont besoin d'un Redis en `noeviction`.** Le Redis
  de développement est en `allkeys-lru`, qui peut évincer une clé de comptage
  sous pression mémoire — donc perdre un seuil sans bruit.
- **Sept pages frontend affichent des données figées** : `ot`, `risk`, `ir`,
  `scs`, `attackpath`, `compliance`, `settings`.
- **Les agents d'ingestion déployés doivent être re-provisionnés.**
  `POST /events/ingest`, `/events/heartbeat` et `POST /audit/events` exigent
  désormais un compte de service ; un jeton utilisateur y reçoit un 403.
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
