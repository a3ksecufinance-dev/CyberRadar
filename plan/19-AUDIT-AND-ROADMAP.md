# Audit de code & Roadmap Production

> Version : 1.0 | Date : 2026-09-22 | Statut : Initial | Périmètre : `backend/` + `frontend/` au commit `ad162b0`

---

## 1. Verdict global

**Ce n'est pas du scaffolding.** Les 32 services contiennent de la logique métier réelle et non triviale :
authentification bcrypt + TOTP, moteur de détection piloté par Kafka avec seuils et déduplication,
parsers syslog RFC3164/5424/CEF avec framing octet-counting, boucle agentique Anthropic avec tool-use,
scoring comportemental pondéré. Les marqueurs TODO sont rares (~10 dans tout le dépôt) et bien localisés.

**Le risque principal n'est pas du code manquant — c'est du câblage cassé entre des pièces réelles,
et des dépendances déclarées sans aucun code correspondant.**

| Axe | État |
|---|---|
| Logique métier | Réelle, early-stage, qualité correcte |
| Sécurité applicative (SQL, validation) | Bonne |
| Câblage inter-composants | **Cassé sur plusieurs points critiques** |
| Autorisation (RBAC) | **Inexistante à l'exécution** |
| Tests | **Zéro** |
| CI/CD | **Inexistante** |
| Observabilité | **Déployée mais non instrumentée** |

---

## 2. Défauts bloquants

### 2.1 Le service `identity` est silencieusement non fonctionnel

`services/identity/cmd/server/main.go:156-159` écrit le contexte avec des clés `string` non typées :

```go
ctx := context.WithValue(r.Context(), "tenant_id", claims.TenantID)
```

`services/identity/internal/handler/auth.go:186,192,209` les relit via un type distinct :

```go
type contextKey string
v, _ := r.Context().Value(contextKey("tenant_id")).(string)
```

Go compare les clés de contexte par **(type, valeur)**. Une clé `string` ne correspondra jamais à une clé
`contextKey`. **Tout appel tenant-scopé du service identity reçoit `uuid.Nil`.**

Le défaut n'est pas isolé. Cinq services perdent silencieusement l'identité de l'appelant :

| Service | Écriture (middleware) | Lecture (handler) | Effet |
|---|---|---|---|
| `identity` | clé `string` | `contextKey` | tenant et user = `uuid.Nil` |
| `audit` | clé `string` | `contextKey` | tenant et `is_super_admin` perdus |
| `notification` | clé `string` | `contextKey` | tenant perdu |
| `tenant` | littéral `string` via helper `any` | constante typée `ctxTenantID` | tenant et `is_super_admin` perdus |
| `mobile` | valeur `string` | assertion `.(uuid.UUID)` | assertion toujours fausse |

Les 27 autres services utilisent `string` des deux côtés, de façon cohérente : ils fonctionnent, mais
par accident. La convention reste fragile et expose la plateforme aux collisions de clés entre packages.

> Invisible pour `go build` et `go vet` en configuration par défaut : le défaut a été livré sans être détecté.

### 2.2 Aucune autorisation à l'exécution — le RBAC n'est jamais évalué

Les trois policies (`policies/abac.rego`, `rbac.rego`, `tenant_isolation.rego`) sont correctement écrites
(bypass super-admin, MFA obligatoire pour l'export, geo-blocking, restriction horaire).
`github.com/open-policy-agent/opa v0.64.1` figure dans `internal/go.mod:13`.

**Aucun fichier Go du dépôt n'importe OPA.**

Conséquences :
- **Aucun service ne vérifie `claims.Roles` contre une permission requise** avant d'exécuter un handler.
  Tout utilisateur authentifié peut appeler toute route.
- L'isolation tenant est réimplémentée à la main, service par service, en comparaisons
  `if user.TenantID != tenantID` dupliquées. Cela fonctionne là où c'est présent, mais sans garantie centrale.

La donnée de politique manquait également : `000002` seede 26 permissions et 11 rôles system, mais
**jamais le lien entre les deux** — `role_permissions` était vide, donc aucun rôle ne portait la
moindre permission.

> Corrigé en Phase 1 : migration `000029` seedant la matrice rôles→permissions, permissions
> effectives portées par le jeton, et `authmw.RequirePermission` appliqué par groupe de routes.
> Voir §5 Phase 1.

### 2.3 Dépendances déclarées sans aucun code

Déclarées dans `internal/go.mod`, **zéro import dans le code Go** :

| Dépendance | Conséquence de l'absence de code |
|---|---|
| `open-policy-agent/opa` | Pas de moteur de politiques (cf. 2.2) |
| `hashicorp/vault/api` | Aucun client Vault — le conteneur tourne, personne ne s'y connecte |
| `go.opentelemetry.io/otel` (+ sdk, trace, exporter) | Aucun span, aucune trace émise |
| `prometheus/client_golang` | Aucun endpoint `/metrics` |
| `IBM/sarama` | Client Kafka redondant (`segmentio` est utilisé) |

Prometheus, Grafana et Jaeger sont déployés dans `deployments/docker-compose.yml` mais ne reçoivent
aucune donnée applicative. **Aucun SLO (99.99 %, MTTD < 5 min) n'est mesurable aujourd'hui.**

### 2.4 Secret JWT unique partagé par toute la plateforme

`deployments/docker-compose.yml` fixe le même `JWT_SECRET` sur les ~25 services.
La valeur est explicitement de développement, mais le modèle est la faille : **tout service compromis
peut forger des jetons valides pour tous les autres.** Sur une plateforme dont un composant est
exposé à Internet (collecteur syslog), c'est un chemin de latéralisation direct.

S'y ajoutait une faiblesse de vérification : **un seul service sur trente (`tenant`) contrôlait
l'algorithme de signature du jeton reçu.** Chaque service embarquait sa propre copie du middleware,
et les copies avaient divergé.

> Corrigé en 0.3 : signature RS256, clé privée détenue par `identity` seul, contrôle obligatoire de
> la famille d'algorithme dans un middleware unique.

### 2.5 Aucune authentification service-à-service

`services/copilot/internal/service/tools.go:203-210` émet uniquement l'en-tête `X-Internal-Tenant-ID`,
sans `Authorization: Bearer`. Or tous les services aval protègent `/api/v1/*` par `jwtMiddleware`.
`X-Internal-Tenant-ID` n'est lu nulle part ailleurs dans le dépôt.

**Il n'existe aucun mécanisme de confiance inter-services.** Tous les tool calls du Copilot
(`query_alerts`, `lookup_ioc`, `get_incident`) échoueront en 401 en déploiement réel.
Ce manque bloque aussi la Phase 2 : le SOAR ne peut pas appeler les services de remédiation sans lui.

### 2.6 Le connecteur syslog est mono-tenant

`services/syslog/cmd/server/main.go:49` lit un unique `DEFAULT_TENANT_ID` et l'estampille sur **tout**
événement ingéré (`publisher/kafka.go:41`), quelle que soit la source. Pour un SIEM multi-tenant
destiné aux banques et administrations, une instance de connecteur = un client, sans mapping
source → tenant.

### 2.7 Le middleware frontend n'était pas exécuté, et ne validait pas le jeton

Deux défauts superposés :

1. **Le middleware n'a jamais tourné.** `middleware.ts` était placé à la racine du projet alors que
   l'application utilise un répertoire `src/`. Next.js attend alors `src/middleware.ts`. Le
   `middleware-manifest.json` produit par le build était vide : **aucune protection de route n'était
   active**, pas même la vérification de cookie.
2. **La vérification elle-même était insuffisante.** Le code testait uniquement la **présence** du
   cookie de session, sans décoder ni valider le JWT : aveugle à l'expiration, à l'altération et à
   l'état `RefreshAccessTokenError`.

L'activation du middleware a révélé un troisième défaut latent, jusque-là masqué : `next-intl`
préfixait les routes `/api/*` avec la locale, transformant `/api/auth/*` en `/en/api/auth/*` et
cassant tous les endpoints NextAuth.

### 2.8 Le frontend ne compilait pas

`next.config.ts` n'est pas supporté par Next.js 14 (la configuration TypeScript arrive en Next 15) :
`next build` échouait avant même de compiler. S'y ajoutaient 11 erreurs de typage (`tsc --noEmit`),
dont une augmentation de module `next-auth/jwt` non résolue qui dégradait tous les champs du token
en `unknown`. **L'application n'avait donc jamais été compilée ni typée avec succès.**

### 2.9 Next.js 14.2.3 porte une vulnérabilité connue

`npm install` signale que la version épinglée fait l'objet d'un avis de sécurité
(<https://nextjs.org/blog/security-update-2025-12-11>). À corriger en Phase 1 avec la mise en place
de `govulncheck` / `npm audit` en CI.

---

## 3. Fonctionnalités manquantes

| Gap | Localisation | Impact |
|---|---|---|
| ~~**Le SOAR ne remédie rien**~~ — *corrigé* | `soar/internal/service/dispatcher.go` | Les quinze actions appellent réellement les services de la plateforme. Voir §3.3. |
| ~~**Compteurs en mémoire intra-processus**~~ — *corrigé* | `internal/pkg/cache/window.go` | Seuils SIEM, vélocité et brute-force UEBA comptent désormais dans un sorted set Redis partagé par toutes les réplicas. Voir §3.1. |
| ~~**Kafka sans DLQ ni backoff**~~ — *corrigé* | `internal/pkg/kafka/consumer.go` | `DLQTopic` est obligatoire : un consumer sans DLQ refuse de se construire. Retry avec backoff exponentiel, puis parking dans `crp.events.dlq`. |
| ~~**Les compteurs « 7 jours » et « 30 jours » du PAM ne décroissent jamais**~~ — *corrigé* | `migrations/000033`, `pam/internal/repository/pam_postgres.go` | `Events7d`, `EventsToday`, `AnomalyCount7d`, `AnomalyCount30d` sont incrémentés et **jamais remis à zéro ni décrus** : aucune tâche, aucun `UPDATE`, aucun calcul par fenêtre nulle part dans le dépôt. Ce sont des compteurs à vie affichés à l'analyste comme « sur les 7 derniers jours ». Conséquence directe : `AnomalyCount30d > 3` déclenche la mention « risque persistant », que toute identité finit par porter à vie. S'y ajoute une perte de mise à jour : le profil est lu, incrémenté en mémoire puis réécrit en entier, donc deux réplicas qui traitent le même événement en écrasent une. |
| Neo4j absent — **le constat d'origine était inexact** | `attackpath/internal/service/analyzer.go` | L'audit affirmait que « les traversées multi-sauts sont impraticables en SQL relationnel ». C'est faux : le SQL ne sert qu'à charger nœuds et arêtes, la traversée est écrite en Go. Le vrai problème n'était pas le langage de requête mais le parcours lui-même — sept défauts, détaillés en §3.5, tous corrigés et aucun que Neo4j n'aurait réglé de lui-même. |
| pgvector / Qdrant absent | — | Copilot sans RAG sémantique |
| Enrichissement pipeline | `pipeline/enricher/threat.go:38,104`, `geo.go:37` | GeoIP et matching IOC : stubs TODO |
| Envoi d'e-mail | `notification/internal/service/notification.go:138-145` | Stub, aucun SMTP |
| Agrégation stats tenant | `tenant/internal/handler/tenant.go:179` | TODO |
| **7 pages frontend en données figées** | `ot`, `risk`, `ir`, `scs`, `attackpath`, `compliance`, `settings` | Tableaux `mockRisks`, `mockIncidents`… définis dans le fichier de page, sans état loading/error. `useOT.ts` existe intégralement mais `ot/page.tsx` ne l'importe jamais. |
| **Messages d'erreur incohérents** — *corrigé* | `internal/pkg/response` | `response.NotFound` ajoutait « not found » à ce qu'on lui passait alors que la plupart des 25 appelants passaient déjà un message complet : les réponses sortaient en « X not found not found », préfixées du tag interne `[NOT_FOUND]`. Le helper prend désormais un message, comme `Forbidden` et `Conflict`. |
| **Aucun graphique** | `recharts` déclaré, jamais importé | `useKPITimeseries` existe, aucune page ne l'utilise. Produit de dashboards sans visualisation. |
| **Zéro test, zéro CI/CD** | — | Aucun filet de sécurité sur 32 services. Une CI exécutant `go build`, `tsc --noEmit` et `next build` aurait intercepté les défauts 2.7 et 2.8 au premier commit. |

### 3.1 Compteurs de détection partagés — ce qui a été fait

`internal/pkg/cache.Window` compte les occurrences dans une fenêtre glissante, avec un sorted set
Redis : un membre par occurrence, scoré par horodatage. Purger la fenêtre est un `ZREMRANGEBYSCORE`,
compter un `ZCARD`, le tout dans une transaction pour que deux réplicas ne se perdent pas
d'incrément.

Ce que cela corrige concrètement : une règle « cinq échecs d'authentification en cinq minutes » ne
se déclenchait pas face à un attaquant réparti par le load balancer à quatre tentatives sur chacune
de deux réplicas. Un test le démontre — il échoue sur l'ancien compteur intra-processus.

Trois décisions qui méritent d'être connues :

- **Scores en millisecondes, pas en nanosecondes.** Les scores d'un sorted set sont des `float64`,
  qui cessent de représenter les entiers consécutifs au-delà de 2^53 — seuil qu'un epoch en
  nanosecondes a franchi en 1970. L'unicité vient du membre (un UUID), pas du score : deux
  événements dans la même milliseconde comptent bien pour deux.
- **`Count` ne renvoie jamais d'erreur.** Une panne Redis dégrade vers un comptage intra-processus
  au lieu de remonter une erreur qu'un appelant pourrait traiter comme « aucun événement ». Un
  moteur de détection qui cesse de compter quand son cache cligne des yeux est un moteur qui rate
  l'attaque. La dégradation est en revanche bruyante : log d'erreur limité à un par 30 s (l'échec
  est par événement — une panne Redis ne doit pas devenir une panne de logs) et compteur
  `crp_sliding_window_fallback_total`, qui couvre aussi le cas d'un service démarré sans `REDIS_URL`.
  Une seule alerte suffit donc pour les deux situations.
- **Le repli en mémoire balaie ses clés.** Les maps remplacées ne supprimaient jamais rien : un seul
  événement d'une entité y immobilisait sa slice pour la durée du processus.

**Point d'exploitation à trancher avant la production.** Le Redis de développement tourne en
`--maxmemory-policy allkeys-lru` (`docker-compose.yml`). Sous pression mémoire, cette politique peut
évincer une clé de comptage — donc faire disparaître silencieusement des seuils de détection. En
production, les compteurs de détection doivent viser une instance en `noeviction`, distincte du
cache applicatif. Un numéro de base Redis ne suffit pas : la politique d'éviction est réglée par
instance, pas par base.

### 3.2 Identité de service — ce qui a été fait

Jusqu'ici tout appelant était une personne. Les endpoints écrits pour des
machines — l'ingestion du `collector`, l'API d'écriture de l'`audit` — ne
pouvaient donc être protégés que par « un jeton valide quelconque » : le jeton
d'un analyste y passait, et aucune machine ne pouvait être révoquée sans
désactiver un humain.

Un compte de service est une identité de type `service_account` — le type
existait déjà dans `identities` sans jamais servir. Rôles et permissions
viennent de `identity_roles`, donc le catalogue RBAC gouverne les machines sans
modèle parallèle. La table `service_accounts` (migration `000031`) n'ajoute que
ce qu'une machine a de particulier : un credential client, une échéance de
rotation, une portée.

Le credential s'échange contre un jeton de 15 minutes sur
`POST /api/v1/auth/service-token`, qui porte une revendication `svc`. Pas de
refresh token : une machine détient un credential et peut redemander un jeton
quand elle veut, un refresh ne serait qu'un second secret à protéger.

Décisions à connaître :

- **Deux gardes, pas une.** `RequireServiceAccount` **et** la permission. La
  permission seule ne suffit pas : elle s'accorde à un rôle, et un rôle donné
  par erreur à une personne ouvrirait la route sans bruit. Vérifié en vrai :
  un jeton de **super admin** reçoit 403 sur `/events/ingest`.
- **Tout jeton nomme exactement un tenant.** Un compte `tenant` n'obtient que
  le sien ; un compte `platform` doit nommer celui pour lequel il agit. Il
  n'existe pas de jeton « tous tenants », parce qu'un handler qui lit
  `tenant_id` devrait alors en inventer un — c'est ainsi que l'isolation se
  perd.
- **La portée `platform` est un droit large**, donc réservée au super admin à
  la création et journalisée à chaque émission avec `cross_tenant: true`.
  C'est elle qui débloquera le SOAR autonome.
- **Un `client_id` inconnu est comparé à un hash leurre**, pour que « compte
  inexistant » et « mauvais secret » prennent le même temps : sinon
  l'endpoint révèle quels `client_id` existent.

**Défaut trouvé en exécutant, pas en relisant.** La validation du `tenant_id`
était `uuid4`. Or les identifiants de tenant de la plateforme ne sont pas des
UUID v4 (`00000000-0000-0000-0000-000000000001`), donc toute demande
légitime d'un compte `platform` échouait en 422 — le mécanisme entier aurait
été inutilisable, avec un message d'erreur trompeur. Corrigé en `uuid`.

**Reste ouvert.** Les credentials des comptes de service devraient être
distribués par Vault, pas par variable d'environnement : `internal/pkg/vault`
existe, le raccordement reste à faire. `internal/pkg/svcauth` est en revanche
utilisé : le SOAR s'en sert pour tenir un jeton par tenant (§3.3).

### 3.3 Remédiation SOAR — ce qui a été fait

L'orchestration était réelle — séquençage, abort-on-failure, timeouts,
persistance — mais `executeAction` était un `switch` qui renvoyait des maps
figées (`{"action":"block_ip","status":"blocked"}`) sans contacter quoi que ce
soit. Deux conséquences que la lecture seule ne rend pas évidentes :

1. **Aucune étape ne pouvait échouer**, donc `on_failure: abort` n'était
   jamais atteint. Le code du garde-fou existait et n'a jamais pu s'exécuter.
2. **L'enregistrement d'exécution était une fiction.** Un playbook de
   confinement rapportait « IP bloquée, hôte isolé, SOC notifié » en n'ayant
   rien fait. C'est pire que l'absence de SOAR : un analyste qui lit ce
   rapport croit l'incident traité.

`dispatcher.go` appelle maintenant les services réels, authentifié par le
compte de service du SOAR (§3.2), avec un jeton par tenant. Un non-2xx fait
échouer l'étape, et la sortie enregistrée porte le service appelé, le statut
et la réponse — pas une étiquette figée.

Décisions à connaître :

- **`isolate_host` est une règle réseau, pas un statut.** Les vocabulaires
  `assets` et `netsec.devices` n'ont pas d'état « isolé » ; marquer un hôte
  `inactive` aurait enregistré un confinement qui n'a pas eu lieu. L'action
  pose une règle `deny` sur l'adresse de l'hôte, en résolvant l'actif vers son
  adresse au besoin — et échoue si l'actif n'a aucune adresse connue.
- **`tag_entity` relit avant d'écrire.** La mise à jour d'actif remplace la
  liste de tags : n'écrire que le nouveau aurait effacé tous les autres. Un
  tag déjà présent n'est pas une erreur, pour qu'un playbook rejoué reste
  idempotent.
- **`send_notification` exige un canal.** Il n'y a pas de destinataire par
  défaut raisonnable pour une alerte de sécurité automatisée.
- **Un service sans URL configurée désactive ses actions**, qui échouent en le
  nommant. Le demi-déploiement est le cas dangereux : le playbook ne doit pas
  rapporter un succès pour un service qu'on ne lui a jamais dit comment
  joindre.
- **`unblock_ip` / `unisolate_host` prennent le `policy_id`** renvoyé par
  l'étape qui a posé la règle. netsec n'a pas de route de suppression : la
  règle passe en `log`, ce qui laisse la trace.

Le rôle `soar_executor` (`000032`) porte exactement les onze droits utilisés
par les actions. Il est distinct de `platform_service` volontairement : ce
sont des droits de **modifier l'environnement d'un client** — désactiver un
compte, refuser du trafic — et ils doivent se relire seuls.

**Vérifié de bout en bout** contre des services qui tournent : un compte
`platform` avec le rôle `soar_executor` obtient un jeton pour un tenant,
appelle `DELETE /api/v1/users/{id}` sur `identity`, et l'utilisateur passe
réellement de `active` à `disabled` en base. Un compte sans `users:delete`
reçoit 403 ; un jeton émis pour le tenant B ne voit pas l'utilisateur du
tenant A.

**Reste ouvert.** Le secret du compte SOAR vient de l'environnement, pas de
Vault. Et `create_ticket` crée un ticket de vulnérabilité faute de service de
ticketing générique — c'est le magasin le plus proche, pas le bon à terme.

### 3.4 Fenêtres d'activité du PAM — ce qui a été fait

`events_today`, `events_7d`, `anomaly_count_7d`, `anomaly_count_30d` et
`priv_sessions_30d` étaient incrémentés à chaque événement et jamais remis à
zéro ni décrus — aucune tâche, aucun `UPDATE`, aucun calcul par fenêtre nulle
part dans le dépôt. Des totaux à vie portant le nom d'une fenêtre glissante.

La conséquence pratique est dans `ComputeBreakdown` : au-delà de trois
anomalies sur `anomaly_count_30d`, une identité est étiquetée « risque
persistant ». Comme le compteur ne redescend jamais, **toute** identité finit
par porter l'étiquette et ne peut plus s'en défaire. Le signal se dégrade en
bruit, et un analyste apprend à l'ignorer — ce qui est plus nuisible que de
n'avoir aucun signal.

`identity_activity_daily` (`000033`) tient une ligne par identité et par jour
UTC. Les chiffres du profil en sont la somme sur leur fenêtre. Le profil reste
la surface de lecture de l'API : seules les valeurs qu'il porte deviennent
vraies.

**Le second défaut a été corrigé dans le même geste.** Le profil était lu,
incrémenté en mémoire, puis réécrit en entier : deux réplicas traitant la même
identité s'écrasaient mutuellement. L'incrément se fait maintenant dans la
base (`ON CONFLICT … SET events = events + EXCLUDED.events`). Mesuré sur une
base réelle, le motif lecture-modification-écriture n'enregistre que **39 des
200** incréments concurrents ; l'upsert atomique les enregistre tous les 200.
Un test l'assure, et la CI monte désormais un PostgreSQL pour que ces tests ne
puissent pas passer au vert en étant simplement sautés.

**Choix à connaître.** La granularité est le jour UTC, pas l'heure locale du
tenant : « aujourd'hui » veut dire la même chose pour tout le monde, plutôt que
de dépendre du fuseau de la réplica qui traite l'événement. La rétention est de
30 jours — la fenêtre la plus large utilisée — purgée au démarrage puis toutes
les 6 heures, sans quoi la table croît d'une ligne par identité et par jour
indéfiniment.

**Coût assumé.** Le chemin chaud passe d'une requête par événement à trois
(l'upsert du jour, la lecture des fenêtres, l'upsert du profil). La lecture est
une agrégation indexée sur trente lignes au plus. C'est le prix de chiffres
exacts, et il est mesurable si jamais il devient gênant.

### 3.5 Chemins d'attaque — ce qui a été fait, et la question Neo4j

**Correction d'un constat de cet audit.** J'avais écrit que les traversées
multi-sauts étaient « impraticables en SQL relationnel ». En lisant le code
plutôt que le schéma : `buildGraph` charge les arêtes depuis PostgreSQL, puis
**tout le parcours est en Go**. Le SQL ne traverse rien. Le diagnostic portait
sur le mauvais composant.

Le parcours lui-même, en revanche, avait sept défauts — dont aucun n'aurait été
réglé par un changement de base, et dont tous auraient été **transcrits tels
quels en Cypher** si la migration avait été faite d'abord :

1. **`path_score` récompensait les chemins longs.** La formule multipliait par
   le nombre de sauts : à coût égal, un chemin de cinq sauts scorait au-dessus
   d'un chemin d'un saut. La liste que l'analyste dépile par le haut classait
   donc les attaques les plus difficiles comme les plus dangereuses.
2. **`impact` valait 7.0 pour tout chemin**, quelle que soit la cible. Le champ
   ne portait aucune information ; il vient maintenant de la criticité de la
   cible.
3. **`has_internet_entry`, `has_exploit_step`, `has_priv_esc` n'étaient jamais
   calculés.** Déclarés, persistés, relus par l'API — et `false` pour chaque
   chemin en base. Ce sont précisément les filtres qu'un analyste utilise.
4. **`include_types` était ignoré.** Stocké, renvoyé par l'API, jamais lu par
   la traversée : restreindre un scénario à un type de nœud ne changeait rien.
5. **`path_type` valait `lateral_movement` pour tout chemin.**
6. **Le plafond de 200 chemins tronquait en silence.** Un scénario enregistrait
   « 200 chemins » sans qu'on puisse le distinguer d'un graphe qui en a 200.
7. **`max_hops` était dépassé d'un saut** : la condition d'arrêt testait
   `> max_hops+1`, donc des chemins d'un saut de trop remontaient.

S'y ajoutait le coût mémoire : le BFS copiait l'ensemble `visited` **et** les
deux séquences à chaque arête explorée, soit une croissance en nœuds × arêtes.
Le parcours est maintenant en profondeur avec retour arrière — un seul ensemble
et deux tranches, déroulés au retour — donc l'empreinte est la profondeur du
parcours, bornée par `max_hops`.

`ListNodes` plafonne par ailleurs à 500 résultats : une traversée qui s'en
serait servie aurait parcouru une partie du graphe en rapportant les chemins
qu'elle aurait trouvés. `LoadGraph` charge le graphe entier ou échoue.

**Le préalable à Neo4j est posé.** L'analyseur dépend désormais de
`service.GraphStore` — `LoadGraph`, `SetScenarioStatus`, `SavePaths`,
`UpdateScenarioResult` — et non du dépôt PostgreSQL. Une implémentation Neo4j
satisfait la même interface sans que la traversée change. Seize tests couvrent
le parcours sur des graphes construits dans le test, sans base du tout.

**Ce que Neo4j apporterait vraiment**, une fois les défauts ci-dessus corrigés :

- la traversée s'exécute **là où sont les données** au lieu de charger le
  graphe entier du tenant dans le processus à chaque scénario ;
- le plus court chemin **pondéré** (Dijkstra, A\*) que le parcours actuel ne
  fait pas : `weight` est accumulé mais l'ordre reste le nombre de sauts ;
- des algorithmes de graphe prêts à l'emploi — centralité d'intermédiarité pour
  les points d'étranglement, au lieu du comptage d'occurrences actuel.

**Pourquoi l'implémentation n'est pas livrée ici.** Neo4j ne peut pas être
exécuté dans cet environnement : le proxy refuse (403) aussi bien les images
conteneur que l'archive de distribution. Écrire le pilote, le schéma, les
requêtes Cypher et la double écriture sans pouvoir les exécuter **une seule
fois** produirait du code qui compile et dont personne ne sait s'il fonctionne
— sur le différenciateur produit de la plateforme. C'est exactement le genre de
livraison « qui a l'air finie » que cet audit reproche au reste du dépôt.

**Plan de migration, à exécuter dans un environnement où Neo4j tourne :**

1. Service `neo4j` dans `docker-compose`, contraintes d'unicité sur
   `(tenant_id, id)` pour `:AttackNode`, index sur `tenant_id`.
2. `repository/graph_neo4j.go` implémentant `service.GraphStore`. `LoadGraph`
   devient d'abord un `MATCH` équivalent, à iso-comportement.
3. **Double écriture** sur les upserts de nœuds et d'arêtes, PostgreSQL restant
   la source de vérité, avec une commande de réconciliation qui compare les
   deux et compte les écarts.
4. Bascule de la lecture vers Neo4j derrière une variable d'environnement, par
   tenant, avec les tests de traversée rejoués contre les deux implémentations
   — ils sont écrits pour ça.
5. Une fois la parité établie, pousser la traversée dans Cypher
   (`shortestPath`, `apoc.path.expandConfig`) et retirer `LoadGraph` du chemin
   chaud.

L'isolation tenant est le point de vigilance : en PostgreSQL elle est une
colonne présente dans chaque `WHERE`. En Cypher elle devient une propriété
qu'il faut filtrer explicitement à chaque `MATCH`, sans le filet du schéma.
Une base par tenant l'élimine, au prix de la densité — arbitrage à trancher
avant l'étape 2.

---

## 4. Points forts à préserver

- **`services/syslog` est de qualité production**, pas MVP : RFC3164/5424, CEF, framing octet-counting
  *et* newline-delimited, TLS 1.2 minimum avec allowlist de cipher suites AEAD, support mTLS
  (`listener/tls.go`). Meilleure hygiène que le reste de la plateforme.
- **SQL intégralement paramétré** sur tous les services relus — aucune injection. La concaténation
  n'est utilisée que pour des listes de colonnes issues de whitelists fixes.
- **Validation d'entrée systématique** : `go-playground/validator` sur tous les DTO d'écriture,
  mapping 400/422 correct.
- **Gestion d'erreurs centralisée** : `DomainError` → statut HTTP, cohérente sur tous les services.
- **`context.Context` correctement propagé** (repositories, consumers Kafka, clients HTTP)
  + `chimiddleware.Timeout(30s)`.
- **`internal/pkg/db`** : pooling réel (pgxpool avec MaxConns/MinConns/lifetimes), option TLS 1.3,
  wrapping d'erreurs `%w`.
- **`identity`** : bcrypt, TOTP, rotation de refresh token — la logique d'authentification elle-même
  est excellente ; c'est son câblage contextuel qui est cassé (2.1).
- **`compliance` et `cspm` ne sont pas des stubs** : ~1 400 lignes de CRUD réel malgré leurs 5 fichiers Go.
- **Frontend** : NextAuth v5 sur Keycloak OIDC avec rotation de refresh token, SWR partout avec polling
  différencié (15 s alertes SIEM, 60 s+ données lentes), ~25 interfaces TypeScript strictes avec
  unions littérales.

---

## 5. Roadmap vers la production

### Phase 0 — Correctifs bloquants · 1 à 2 semaines

Coût faible, impact sécurité maximal. Prérequis à tout le reste.

| # | Action | Réf. audit | État |
|---|---|---|---|
| 0.1 | Package `internal/pkg/authctx` avec clés typées + accesseurs ; correction des 5 services cassés ; migration des 32 services | 2.1 | **Fait** |
| 0.2 | Propagation du token appelant dans les appels du Copilot | 2.5 | **Fait** |
| 0.3 | Migration RS256 : identity signe, les 30 services vérifient avec la clé publique seule | 2.4 | **Fait** |
| 0.4 | Activation du middleware frontend + validation réelle de la session | 2.7, 2.8 | **Fait** |
| 0.5 | Trancher sur OPA : retrait des dépendances non importées, policies conservées pour la Phase 1 | 2.2, 2.3 | **Fait** |

**Phase 0 terminée.** Deux décisions de conception méritent d'être notées :

- **0.2 — propagation plutôt que jeton de service.** Les appels du Copilot sont faits *pour le compte
  d'un utilisateur* : transmettre son propre jeton authentifie l'appel **et** le confine à ce que cet
  utilisateur peut déjà voir. Un jeton de service aurait élargi le périmètre sans nécessité. Les
  appelants autonomes — les actions SOAR, sans utilisateur derrière — avaient besoin d'une identité
  de service propre. Elle a été introduite en Phase 2 (§3.2), au moment où un consommateur existait,
  et le SOAR est ce consommateur (§3.3).
- **0.3 — RS256 plutôt qu'un secret par service.** Un secret distinct par service aurait résolu la
  latéralisation mais imposé la distribution de N secrets. Avec RS256, il n'existe qu'une clé privée,
  détenue par le seul émetteur. Effet de bord important : la clé publique n'étant pas secrète, un
  vérificateur acceptant HMAC accepterait un jeton que n'importe qui peut forger avec elle — d'où le
  contrôle obligatoire de la famille d'algorithme dans le middleware partagé.

Un effet collatéral notable : le middleware unique remplace 30 copies et retire environ 1 150 lignes.

### Phase 1 — Socle de confiance · 4 à 6 semaines

Aucun déploiement production sans cette phase.

- **Tests** : viser 60 % sur les services critiques (`identity`, `siem`, `pam`, `syslog`).
  Testcontainers pour PostgreSQL/ClickHouse/Kafka. Prioriser les parsers syslog et le rule engine SIEM
  (logique pure, test facile, valeur élevée).
- **CI/CD** : GitHub Actions — `golangci-lint`, build, test, `govulncheck`, scan d'images (Trivy),
  build/push des images. Ajouter un analyzer de clés de contexte pour attraper la classe de défaut 2.1.
- **RBAC réel** — *fait, 29 services sur 30 protégés.*

  **Mécanisme.** Les permissions effectives sont résolues à la connexion et portées par le jeton
  (claim `perms`) ; `authmw.RequirePermission` refuse en 403 en nommant la permission attendue, et
  `RequirePermissionByMethod` dérive l'action de la méthode HTTP (GET → `read`, DELETE → `delete`,
  le reste → `write`).

  **Catalogue.** `000002` déclarait 26 permissions sur 11 ressources sans jamais les relier aux
  rôles. `000029` seede la matrice manquante ; `000030` étend le catalogue aux domaines restants —
  une ressource par domaine de service. Total : **82 permissions sur 34 ressources, 219 associations**
  réparties sur 10 rôles (`super_admin` en est absent : il contourne le contrôle).

  `:delete` n'est déclaré que pour les 9 domaines exposant réellement une route `DELETE`, afin de
  ne jamais accorder un droit sans objet.

  **Granularité.** Trois services sont protégés par groupe de routes plutôt qu'en bloc, parce que
  leurs routes ne relèvent pas de la même autorité :
  - `siem` → `rules:*` (écrire une règle de détection), `alerts:*` (trier), `incidents:*` (les cas) ;
  - `ir` → `playbooks:*` (rédiger une procédure) distinct de `incidents:*` (traiter un incident) ;
  - `audit` → `audit:read` en lecture, `audit:export` à l'export — l'export d'une piste d'audit
    n'est pas sa consultation.

  **`collector` et `POST /audit/events` faisaient exception** — appels machine sans utilisateur
  derrière, donc protégés par `RequireJWT` seul. Ce n'est plus le cas : ils exigent maintenant un
  compte de service **et** la permission (`events:ingest`, `audit:write`). Voir §3.2.

  **À revoir avant production.** La matrice de `000030` suit les descriptions de rôles seedées en
  `000002` et constitue un point de départ défendable, pas une politique de sécurité arrêtée :
  qui peut lire les actifs OT ou approuver un accès privilégié est une décision d'organisation.

  **Compromis assumé** : porter les permissions dans le jeton rend l'autorisation locale et sans
  appel réseau, mais un changement de droits ne prend effet qu'au jeton suivant. La durée de vie du
  jeton d'accès (60 min par défaut) borne donc la révocation ; la réduire si le besoin l'exige.

- **Observabilité** — *fait.* `internal/pkg/observe` fournit un middleware HTTP unique qui produit à la
  fois un compteur de requêtes, un histogramme de latence dont les seuils encadrent la cible de
  200 ms, et un span OTLP qui prolonge une trace entrante. Câblé dans les 31 services, monté **avant**
  l'authentification pour que les requêtes rejetées soient comptées. Le label `route` est le motif
  chi, jamais le chemin brut ; une requête non routée est étiquetée `unmatched`, de sorte qu'un
  scanner ne peut pas créer une série temporelle par sonde. `prometheus.yml` listait déjà une cible
  par service : elles n'avaient simplement rien à scruter.

  Reste : `pipeline-worker` est scruté sur `:9100` mais n'expose aucun serveur HTTP ; et le
  connecteur syslog n'expose que les métriques Go/process, pas encore ses compteurs d'ingestion
  (messages traités, échecs de parsing par format) — les plus utiles sur le chemin le plus volumineux.

- **Vault** — *fait.* `internal/pkg/vault` lit un mount KV v2 et résout une valeur depuis Vault quand
  il est configuré, depuis l'environnement sinon. Un échec de lecture Vault est signalé **même quand
  le repli réussit**. `identity` y puise son URL de base et sa clé de signature, et journalise la
  source de chacune.

  Reste : les autres services lisent encore leurs secrets depuis l'environnement, et le jeton racine
  de dev doit céder la place à AppRole ou à l'authentification Kubernetes, avec une policy par
  service limitée à son propre chemin `crp/<service>/*`.

- **README** — *fait* (`README.md` à la racine) : démarrage local, structure, conventions
  d'authentification/autorisation/observabilité, pièges connus et points encore ouverts.

### Phase 2 — Combler les écarts fonctionnels · 8 à 12 semaines

- **Identité de service** — *fait*, voir §3.2. Débloque `collector`, l'écriture
  d'audit, et le SOAR autonome (portée `platform`).
- **SOAR réel** — *fait*, voir §3.3. Les quinze actions appellent les services
  de remédiation ; un échec fait échouer l'étape.
- **Neo4j** — préalable posé (§3.5) : l'analyseur dépend d'une interface `GraphStore`, et les sept
  défauts du parcours qui auraient été transcrits en Cypher sont corrigés. L'implémentation attend un
  environnement où Neo4j peut tourner. Migration des modèles `attackpath` et `knowledgegraph` : plus elle est tardive,
  plus la réécriture des couches repository/service coûte cher.
- **État partagé Redis** pour les compteurs SIEM et UEBA — *fait*, voir §3.1. Le PAM n'en faisait pas
  partie : ses compteurs étaient déjà en base, avec un autre défaut (tableau §3).
- **DLQ + backoff exponentiel** sur Kafka — *fait*.
- **Corriger les compteurs du PAM** — *fait*, voir §3.4. Recalculés par fenêtre depuis une table
  d'agrégats quotidiens en PostgreSQL plutôt que depuis ClickHouse : le PAM n'a pas de connexion
  ClickHouse, et une ligne par identité et par jour suffit pour des fenêtres à la journée. Le même
  passage supprime la perte de mise à jour entre réplicas.
- **pgvector** (plus simple que Qdrant, déjà sur PostgreSQL) + RAG Copilot.
- Enrichissement pipeline : GeoIP (MaxMind) + matching IOC contre le service TI.
- **Multi-tenancy syslog** : mapping IP source / certificat client → tenant.

### Phase 3 — Complétude produit · 6 à 8 semaines

- Câbler les 7 pages en données figées sur leurs hooks (`useOT` existe déjà : travail de raccordement).
- **Intégrer recharts** : séries temporelles, heatmap MITRE ATT&CK, courbes de tendance.
- Visualisation du graphe d'attaque (Cytoscape.js ou react-force-graph).
- Tests end-to-end Playwright sur les parcours critiques.

### Phase 4 — Production readiness · 6 à 8 semaines

- **Kubernetes + Helm** — le `docker-compose` actuel est strictement destiné au développement.
- Haute disponibilité : réplication PostgreSQL/ClickHouse, cluster Kafka 3 brokers, PDB, HPA.
- **Tests de charge** : valider les 100 K EPS annoncés. C'est le chiffre qui sera challengé en appel d'offres.
- Sauvegarde/restauration et plan de reprise, testés.
- Pentest externe et audit de code tiers (exigés pour vendre à une banque).
- Durcissement : images distroless, exécution non-root, network policies.

> **Chemin critique réaliste : 6 à 9 mois** à équipe constante avant un premier déploiement client en production.

---

## 6. Recommandations stratégiques

### 6.1 Consolider les 32 services vers 8-10 unités déployables

Avec zéro test et une petite équipe, 32 services signifient 32 pipelines, 32 images et 32 surfaces de panne.
Regrouper par domaine — par exemple `detection` (siem + ueba + ti), `posture` (cspm + dspm + vuln + easm),
`identity` (identity + pam + iga) — préserve les frontières de modules Go tout en divisant la charge
d'exploitation par trois. **C'est la décision au meilleur retour sur investissement de cette roadmap.**

### 6.2 Choisir un angle d'attaque plutôt qu'affronter Splunk de face

Le marché all-in-one est saturé (Splunk, Sentinel, CrowdStrike, Wiz, Palo Alto XSIAM).
Trois angles crédibles :

- **Souveraineté** — positionnement déclaré du produit, et marché réellement non adressé par les
  acteurs américains (contrainte Cloud Act). À pousser fortement.
- **DORA / NIS2 natif** — contrainte réglementaire datée pour les banques européennes.
  Un produit sortant les rapports DORA clé en main bénéficie d'un cycle de vente court.
- **Le graphe central** `Identity → Asset → Privilege → Session → Context → Business Service`
  est le vrai différenciateur technique — *à condition* qu'il tourne sur un moteur de graphe réel.
  C'est l'argument « chemin d'attaque contextualisé au métier », que peu d'acteurs exécutent bien.

### 6.3 Prouver les KPIs avant de les commercialiser

MTTD < 5 min, −70 % de faux positifs, 100 K EPS : promesses invérifiables aujourd'hui (zéro test,
zéro métrique). En POC bancaire, elles seront mesurées. Instrumenter avant d'annoncer.

### 6.4 Le SOAR simulé est le principal risque commercial

Un prospect découvrant en POC que `isolate_host` ne fait rien perd confiance sur l'ensemble du produit.
Deux options : le finir, ou le retirer de la démonstration jusqu'à ce qu'il soit réel.

### 6.5 Engager une certification tôt

ISO 27001 ou SecNumCloud (cible France/UE) conditionne l'accès aux appels d'offres publics et bancaires.
Le délai d'obtention (12 à 18 mois) impose un démarrage en parallèle du développement, pas après.

---

## 7. Méthodologie

Audit conduit par lecture intégrale du code de 9 services représentatifs (`identity`, `siem`, `syslog`,
`soar`, `pam`, `ueba`, `copilot`, `asset`, `compliance`) couvrant l'éventail de taille et de criticité,
du socle partagé `internal/pkg`, des policies OPA, des migrations SQL et de l'intégralité du frontend.

Défauts reproduits et confirmés directement sur le dépôt, non déduits de la lecture :

- 2.1 — comparaison des sites d'écriture et de lecture sur les 32 services
- 2.3 — `grep` des chemins d'import sur l'ensemble des fichiers `.go`
- 2.7 — `middleware-manifest.json` vide après `next build`, puis vérification du comportement
  (requête sans session, requête avec cookie forgé, routes publiques, préfixe de locale) contre
  un build de production servi localement
- 2.8 — échec de `next build` et 11 erreurs de `tsc --noEmit` sur le commit initial

Baseline de compilation établie avant toute modification : les 33 modules Go compilaient, le frontend
non.
