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
| ~~pgvector / Qdrant absent~~ — *corrigé* | `migrations/000034`, `copilot/internal/repository/knowledge_postgres.go` | pgvector plutôt que Qdrant : le PostgreSQL est déjà là, déjà sauvegardé, déjà isolé par tenant. Voir §3.6. |
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

**Ce qui était bloqué ne l'est plus.** L'audit précédent notait que Neo4j ne
pouvait pas tourner dans cet environnement — le proxy refusait (403) les images
conteneur comme l'archive de distribution — et refusait de livrer un pilote que
personne n'aurait jamais exécuté. Le constat portait sur deux chemins de
téléchargement ; un troisième passe. Neo4j est un logiciel Java publié sur Maven
Central, que le proxy autorise : `org.neo4j.test:neo4j-harness` **est** le
serveur, embarqué, connecteur Bolt compris. Un serveur 5.26.31 a donc tourné en
local, et tout ce qui suit a été exécuté contre lui, pas seulement compilé.

**Étapes 1 à 4 du plan de migration : faites.**

1. **Service `neo4j`** dans `docker-compose` (Community 5.26) et
   `migrations/neo4j/000001_attack_graph.cypher` : unicité sur
   `(tenant_id, id)` et sur `(tenant_id, ref_id, node_type)` — les deux clés de
   PostgreSQL retranscrites —, index sur `tenant_id` pour les nœuds et les
   arêtes. Le service applique les mêmes instructions au démarrage
   (`EnsureSchema`) ; **un test compare le fichier et le code**, parce que deux
   copies d'un schéma autorisées à diverger finissent par diverger.
2. **`repository/graph_neo4j.go`.** `Neo4jGraphStore` encapsule le dépôt
   PostgreSQL et ne redéfinit que `LoadGraph` : le graphe déménage, les
   scénarios et les chemins découverts restent relationnels — ce sont des
   enregistrements, pas de la topologie.
3. **Double écriture** sur les upserts de nœuds et d'arêtes et sur le marquage
   de compromission. Un échec du miroir **ne fait pas échouer l'écriture** :
   PostgreSQL est la source de vérité, et faire dépendre l'écriture primaire
   d'un magasin secondaire reviendrait à ne plus pouvoir enregistrer un graphe
   parce qu'une base de reporting est tombée. L'échec est journalisé en `error`
   et compté (`attackpath_graph_mirror_failures_total`).
   `attackpath-reconcile` (`make graph-reconcile`) compare les deux magasins,
   liste ce qui diverge et **sort en code non nul** : une réconciliation
   planifiée qui réussit toujours n'apprend rien à personne.
4. **Bascule de lecture** derrière `ATTACKPATH_GRAPH_READS=neo4j`, la valeur par
   défaut restant `postgres`. Le test de parité rejoue le **même scénario sur le
   même graphe** depuis chaque magasin et compare les chemins trouvés — route,
   longueur, score, drapeaux. Il a été falsifié pour vérifier qu'il échoue
   quand les deux divergent.

**Mesuré plutôt que supposé.** Avec Neo4j arrêté, une écriture de nœud prenait
**30 secondes** : les valeurs par défaut du pilote réessaient une transaction
pendant une demi-minute, et le miroir est sur le chemin de la requête. Le miroir
a le droit d'échouer, pas de rendre le magasin primaire lent : délai propre de
5 s, détaché de l'annulation de la requête (un client qui raccroche ne doit pas
laisser les deux magasins dans des états différents). Vérifié à nouveau :
5,0 s miroir arrêté, ~25 ms miroir démarré.

**Deux défauts trouvés en exécutant, pas en lisant :**

- **Toute lecture de scénario renvoyait 500.** `last_run_ms` est `NULL` tant que
  le scénario n'a pas tourné, et il était lu dans un `int`. Autrement dit : un
  scénario défini par un analyste était illisible jusqu'à sa première
  exécution — et son exécution passe par sa lecture. La fonctionnalité entière
  était inutilisable. Même classe que les défauts IR et OT du §3.8.
- **`ip_address` était accepté, jamais stocké, jamais relu.** L'API prenait
  l'adresse, l'`INSERT` ne la portait pas, le `SELECT` non plus. Un champ qui
  fait semblant.

**Étape 5 — faite, et pas comme prévu.** L'intitulé disait « pousser la
traversée dans Cypher ». La mesure a montré que la formulation visait le mauvais
levier.

`LoadGraph` charge tous les nœuds et toutes les arêtes actives du tenant dans le
processus **avant** que la marche ne commence, à chaque exécution de scénario,
quoi que le scénario demande. Sur un tenant de 20 000 nœuds et 137 000 arêtes :
**462 ms depuis PostgreSQL, 5,8 s depuis Neo4j**. Le coût n'est pas le langage
de requête, c'est le transfert.

Le parcours est donc désormais **énuméré par le magasin**, par un CTE récursif
côté PostgreSQL et un motif de longueur variable côté Neo4j, tous deux bornés
par le budget de 200 chemins — le `LIMIT` arrête l'énumération au lieu de
rogner son résultat. Plus rien ne traverse le réseau que les routes elles-mêmes.

| | temps par scénario | routes trouvées |
|---|---|---|
| `LoadGraph` + marche en mémoire (avant) | 481 ms | 16 |
| `FindPaths` PostgreSQL | **14,6 ms** | 16 |
| `FindPaths` Neo4j | **18,1 ms** | 16 |

**33× plus rapide**, et les deux magasins se tiennent désormais à 25 % l'un de
l'autre — parce que ni l'un ni l'autre ne transfère le graphe.

**Trois implémentations, un seul comportement.** La marche en mémoire reste, non
plus comme chemin de production mais comme **implémentation de référence** :
c'est elle que fixent les seize tests de traversée, et un test compare les trois
sur cinq scénarios — cycles, `include_types`, cibles multiples, limites de
sauts. Le piège rencontré : les motifs de longueur variable de Neo4j excluent
une *arête* répétée, pas un *nœud* répété, donc sans test d'unicité explicite
une route repassant par le même hôte aurait été comptée comme une seconde
attaque. Aucun plugin n'est requis : APOC élaguerait pendant l'expansion plutôt
qu'après, mais un déploiement en environnement fermé ne télécharge pas de
plugin au démarrage d'un conteneur, et la mesure ne justifie pas la dépendance.

**Le plus court chemin pondéré, enfin enregistré.** `weight` était accumulé à
chaque marche et jeté. `shortest_path` valait le nombre de sauts minimal — donc
un saut unique exigeant un identifiant administrateur et un exploit distant
passait devant trois sauts sur des partages ouverts. Les sauts ne sont pas de
l'effort. `attack_paths.total_cost` porte maintenant le poids accumulé de chaque
route et `attack_scenarios.cheapest_path_cost` le plus faible du scénario
(migration `000037`).

**Et `critical_path` enregistrait le chemin le plus LONG** en l'appelant « le
plus critique » — à peu près l'inverse : l'attaquant prend la route qui score le
plus haut, et la longueur joue contre une route, pas pour elle. Corrigé ; les
valeurs existantes sont remises à `NULL` par la migration plutôt que laissées à
être mal lues.

**Le miroir écrivait une instruction par ligne.** Backfiller ce même tenant
prenait **5 min 03**. Par lots de mille : **1 min 49**. Ce n'est pas une
optimisation, c'est ce qui rend un backfill exécutable sur un vrai tenant.

**Ce qui reste, et pourquoi c'est laissé.** La centralité d'intermédiarité pour
les points d'étranglement — aujourd'hui un comptage d'occurrences sur les routes
découvertes — demande le plugin GDS. Il est téléchargeable, mais c'est un
plugin d'analytique lourd, et les mesures ci-dessus disent que le chemin Neo4j
n'est pas le plus rapide ici : ajouter cette dépendance pour une meilleure
métrique de point d'étranglement ne se justifie pas avant que la bascule des
lectures ait été faite en production et tenue.

**L'isolation tenant, arbitrage tranché.** En PostgreSQL c'est une colonne
présente dans chaque `WHERE` ; en Cypher, une propriété sans filet. Une base par
tenant l'éliminerait, mais le multi-base est une fonction **Enterprise** : sur
Community, visée par ce déploiement, il n'y a qu'une base et le filtre par
propriété est la seule option. Deux choses en tiennent lieu : chaque lecture
filtre `tenant_id` sur la relation **et** sur ses deux extrémités — une arête
écrite entre deux tenants est alors intraversable depuis l'un comme depuis
l'autre — et aucun Cypher n'est construit par concaténation. Un test dédié
tient lieu de ce que le schéma relationnel garantissait.

### 3.6 Mémoire du Copilot — ce qui a été fait

Les outils du Copilot répondent à des questions exactes. Ils ne répondent pas à
« est-ce qu'on a déjà vu ça ? », qui est une question de similarité — et c'est
celle que pose un analyste devant une alerte à 3h du matin.

`copilot_knowledge` (`000034`) indexe ce que le tenant a déjà écrit, avec
pgvector : HNSW sur distance cosinus, une ligne par document source, clé
`(tenant, type, référence)` pour qu'une réindexation **remplace** au lieu
d'accumuler des quasi-doublons qui matchent tous la même requête.

**pgvector plutôt que Qdrant.** Le PostgreSQL est déjà déployé, déjà sauvegardé,
déjà soumis à l'isolation tenant qui existe partout ailleurs. Ajouter Qdrant
aurait introduit un second magasin avec sa propre sauvegarde, sa propre
isolation à réimplémenter et sa propre surface d'attaque, pour un corpus qui se
compte en milliers de documents par tenant, pas en milliards.

**Les embeddings ne viennent pas d'Anthropic** : il n'existe pas d'endpoint
d'embeddings. C'est une décision, et elle compte pour une plateforme dite
souveraine — envoyer le texte d'un incident bancaire à une API tierce est
exactement ce que les règles de résidence des données interdisent. `Embedder`
est donc une interface, et l'implémentation livrée parle l'API compatible
OpenAI (`/v1/embeddings`) : c'est ce que parlent les serveurs auto-hébergés
(text-embeddings-inference, vLLM, Ollama, LocalAI) **et** les fournisseurs
hébergés. Une banque pointe `EMBEDDINGS_URL` sur son propre serveur et rien ne
sort du périmètre ; un opérateur qui accepte un service hébergé le pointe
ailleurs. **La plateforme n'impose ni l'un ni l'autre**, et sans variable le
Copilot fonctionne simplement sans mémoire.

Défauts trouvés en exécutant contre un vrai pgvector, pas en lisant la doc :

- **Un vecteur nul rend la similarité NaN.** La distance cosinus divise par la
  norme. Plusieurs serveurs d'embeddings renvoient un vecteur nul pour une
  entrée vide ; stocké, il empoisonne silencieusement l'index — un NaN passe à
  travers une comparaison `> seuil`. Refusé à l'écriture, et filtré à la
  lecture par sécurité. Vérifié en base : `similarity` vaut bien `NaN`.
- **Le filtre tenant doit être dans le `WHERE`**, pas appliqué après le tri :
  un `ORDER BY` sur l'index suivi d'un filtre renverrait les documents d'un
  autre client dès qu'ils sont les plus proches. Un test le vérifie.
- **Les résultats d'embeddings ne reviennent pas forcément dans l'ordre.** La
  spécification porte un `index` par résultat ; associer silencieusement un
  vecteur au mauvais document ne se verrait qu'au contexte récupéré incohérent,
  longtemps après l'indexation.
- **La largeur du modèle est vérifiée au démarrage** contre la colonne, lue
  depuis le catalogue. Sinon l'erreur n'apparaît qu'à l'indexation, document par
  document, sur un déploiement qui paraissait sain.

**Seuil et présentation.** En dessous de 0,35 de similarité cosinus rien n'est
récupéré : une question sans rapport doit laisser le modèle dire qu'il n'a rien,
plutôt que recevoir le document le moins hors-sujet du corpus et le traiter
comme une preuve. Ce qui est récupéré est annoncé comme un **précédent à citer**,
explicitement pas comme un fait sur la question posée.

**Au passage.** La route `DELETE` nouvelle aurait répondu 403 à tout le monde :
`copilot:delete` n'existait pas. `000030` ne déclarait `:delete` que pour les
domaines ayant réellement une route DELETE — le Copilot en a une maintenant,
donc la permission est créée et accordée à qui peut déjà indexer.

**Reste ouvert.** Rien n'alimente le corpus automatiquement : l'API d'indexation
existe, mais aucun service ne pousse ses incidents résolus dedans. Le découpage
en chunks est laissé à l'appelant — un runbook de trente pages indexé d'un bloc
se récupère d'un bloc.

### 3.7 Le frontend — ce qui a été fait

Les sept pages sur données codées en dur étaient le symptôme visible. Le
diagnostic est plus large : **la couche de données du frontend décrivait une API
imaginaire**. Les interfaces de `src/types` ne correspondaient à aucune struct Go,
quatre chemins pointaient vers des routes inexistantes, et le lecteur de listes
supposait une forme de réponse que la majorité des services n'émet pas. Une page
« branchée » affichait donc des cellules vides sans la moindre erreur.

**Trois formes de réponse coexistent.** Le contrat documenté est
`{"data": …, "meta": …, "error": null}`. Dans les faits :

| Forme | Exemple | Services |
|---|---|---|
| Enveloppe, tableau nu | `{"data":[…],"meta":{…}}` | identity (seul à utiliser `OKWithMeta`) |
| Enveloppe, tableau nommé | `{"data":{"alerts":[…],"total":12}}` | siem, ti, vuln, attackpath, compliance, apifw, dashboard, copilot |
| Aucune enveloppe | `{"incidents":[…],"total":12}` | **dspm, ir, mobile, ot, scs** |

Cinq services écrivent leur JSON eux-mêmes au lieu de passer par
`internal/pkg/response` ; quatre autres (cspm, iga, netsec, risk) mélangent les
deux. Aucun client ne peut écrire un seul analyseur. La réconciliation est faite
une fois, dans `lib/api.ts` (`payloadOf` / `itemsOf`), plutôt que dans chaque
hook. **La vraie correction est de normaliser les services sur `OKWithMeta`** —
c'est du travail backend, listé en Phase 3 ci-dessous ; l'adaptateur tient
jusque-là.

**Quatre chemins n'existaient pas.** `/api/v1/incidents` (réel :
`/api/v1/ir/incidents`), `/api/v1/stats` (réel : `/api/v1/ir/stats`),
`/api/v1/vulnerabilities` (réel : `/api/v1/vuln/vulnerabilities`) et
`/api/v1/mobile/devices/stats` (réel : `/api/v1/mobile/stats`). Le Copilot
postait vers `/api/v1/copilot/chat`, qui n'existe pas : le service adresse une
session (`POST /copilot/sessions/{id}/chat`) et attend `{content}`, pas
`{message, session_id}`. Le `catch` de la page présentait chaque échec comme
« service indisponible » — c'est ainsi qu'un 404 permanent a pu passer pour une
panne. Les chemins vivent désormais dans une table `ROUTES` unique, et le
Copilot ouvre une vraie session avant son premier message.

**Les types décrivaient autre chose.** `Vulnerability` déclarait `severity`,
`affected_component`, `remediation_status`, `asset_count`, `exploit_in_wild`,
`first_seen_at` : aucun de ces champs n'existe. Le vrai modèle porte
`cvss_severity`, `affected_products`, `is_exploited`, `epss_score`,
`published_at` — et le statut de remédiation appartient à un *finding* (une
vulnérabilité sur un actif), pas au CVE. `AssetStats` annonçait `critical`,
`online`, `avg_risk_score` ; le service renvoie `by_criticality`, `by_status`,
`cbs_connected`, `swift_connected`. Chaque interface est maintenant transcrite
des tags `json:` de sa struct, ce qui transforme une cellule vide en erreur de
compilation.

Deux pièges de sérialisation que seuls des appels réels ont révélés :

- **`asset.criticality` est un entier 1–4**, pas un mot — `Criticality` est un
  `int` sans `MarshalJSON`. La page appelait `.toUpperCase()` dessus : plantage
  à la première ligne de données.
- **Les sévérités du SIEM sont en majuscules** (`Enum8('LOW','MEDIUM','HIGH',
  'CRITICAL')` côté ClickHouse), celles des domaines Postgres en minuscules.
  `countOf` lit donc les répartitions sans tenir compte de la casse, et le
  filtre de sévérité de la page SIEM envoie la valeur en majuscules — en
  minuscules il ne correspondait à rien et vidait le tableau sans erreur.
- **`assets_by_purdue` est clé `level_1`, pas `1`** (idem `vendors_by_tier` →
  `tier_1`). La distribution Purdue affichait zéro partout.

**Des filtres qui ne filtraient rien.** La page actifs envoyait
`criticality=critical` là où le service lit un entier, et `search=` là où il lit
`q=`. La page menaces envoyait `search=` pour un `q=`. La page SIEM offrait une
recherche plein texte qu'aucun paramètre ne porte : elle restreint maintenant la
page déjà chargée et le dit.

**Deux bugs backend découverts en exécutant.** `POST /ir/incidents` renvoyait
500 sur *tout* incident : `estimated_impact`, `lead_name`, `description`,
`source`, `source_ref` et `attack_vector` sont des colonnes nullables sans
défaut, lues dans des `string` Go qui ne peuvent pas porter NULL
(`cannot scan NULL into *string`). Aucun incident ne pouvait être créé — le
domaine IR était mort. Même classe dans `POST /ot/events`
(`acknowledged_by`, `resolved_by`). C'est la famille du bug de login corrigé en
Phase 0. Les colonnes sont `COALESCE`-ées dans chaque requête qui lit la ligne,
et `services/ir/.../incident_null_test.go` crée un incident sans aucun champ
texte optionnel — le cas exact qui échouait. La CI le rend obligatoire via
`IR_TEST_DSN`.

**Les graphiques.** `recharts` était déclaré depuis le début et jamais importé.
Il sert maintenant les répartitions que les API calculent déjà (sévérité,
statut, niveau de risque, tier fournisseur) sur le dashboard, IR, OT, SCS,
risque et vulnérabilités. La palette de sévérité du projet échoue le contrôle
*catégoriel* (critical contre high mesurent ΔE 10,6 en vision normale) : c'est
une échelle de **statut**, pas d'identité, les couleurs sont celles des badges
pour ne pas afficher deux rouges différents côte à côte, et chaque barre porte
son nom en étiquette directe — la couleur ne porte jamais seule l'information.

**Pas de graphique de série temporelle.** `/dashboard/kpi/timeseries` lit
ClickHouse, alimenté par un consommateur Kafka — mais **aucun service ne publie
de `KPISnapshot`**. L'endpoint renverra toujours vide. Un widget condamné au
vide n'a pas été livré ; le producteur manquant est le travail à faire.

**Ce qui a été retiré plutôt que branché.** La page réglages listait six
intégrations (« Keycloak SSO 24.0.1 », « MISP 2.4.188 », toutes « connected »)
et des bascules « Imposer le MFA », « Liste d'IP autorisées ». Aucun endpoint ne
sert ni n'accepte quoi que ce soit de tout cela : les versions étaient des
littéraux et les bascules n'écrivaient nulle part. Une console qui affiche des
contrôles non appliqués est pire qu'une console qui dit ne pas savoir. Les
utilisateurs viennent d'`/api/v1/users` ; le reste est remplacé par ce qui est
réellement configurable, et où.

**Le rôle `super_admin` n'accorde rien.** `is_admin` — le contournement de
vérification — vient de `identities.privilege_level`, tandis que le rôle nommé
`super_admin` est délibérément absent de la matrice `000029`. Attribuer ce rôle
à quelqu'un lui donne donc zéro permission. C'est fail-closed, donc pas
dangereux, mais un administrateur qui accorde « super_admin » n'obtient pas ce
qu'il croit. Les deux notions d'administrateur devraient être une seule.

**Une valeur d'énumération invalide renvoie 500.** `incident_type`,
`event_type`, `vendor_type` sont protégés par des contraintes CHECK ; une valeur
hors liste remonte en erreur 500 au lieu d'un 422. L'utilisateur voit « erreur
interne » pour une saisie invalide.

### 3.8 Le contrat d'API, les erreurs, l'administrateur et les KPI

Quatre chantiers issus de §3.7. Trois étaient des dettes connues ; le quatrième
a mis au jour trois défauts qui, ensemble, rendaient le tableau de bord
inexistant.

**Une seule forme de réponse.** Les 30 services passent désormais par
`internal/pkg/response`. Neuf écrivaient leur JSON eux-mêmes — ~780 sites
d'appel — et la plupart emballaient les listes sous une clé de leur choix. Les
erreurs de ces neuf-là sortaient en `{"error": "texte"}` là où le contrat dit
`{"error": {"code", "message"}}` : un client lisant `error.message` recevait
`undefined`, donc « HTTP 500 » au lieu du motif. Une liste est maintenant un
tableau sous `data`, avec `meta.total` **toujours présent** — il portait
`omitempty`, si bien qu'une page sans résultat répondait sans total et qu'on ne
pouvait pas distinguer « zéro correspondance » de « cet endpoint ne compte
pas ». `page` et `limit` gardent `omitempty` : leur absence dit que l'endpoint
ne pagine pas. Côté frontend, l'adaptateur à trois formes a disparu ; il reste
un garde qui *signale* une réponse non conforme au lieu de l'absorber.

**Les erreurs disent ce qui s'est passé.** `internal/pkg/httperr` remplace
vingt copies de `mapError` qui divergeaient : certaines renvoyaient `err.Error()`
au client — avec le préfixe `[KIND]` et parfois le message du driver —, d'autres
répondaient 500 à tout ce que la couche domaine n'avait pas classé, ce qui
incluait **toutes** les violations de contrainte. Désormais une valeur hors
d'une liste CHECK donne 422 en nommant le champ :

```json
{"error": {"code": "VALIDATION_ERROR", "details":
  {"field": "incident_type", "constraint": "ir_incidents_incident_type_check",
   "reason": "value is not accepted for this field"}}}
```

Une clé dupliquée donne 409, une référence absente 422, un littéral UUID
malformé 400. Tout le reste reste 500 avec un texte générique : le message du
driver, qui nomme la relation et parfois le SQL, ne quitte plus le serveur.

**Un seul administrateur.** Le rôle `super_admin` n'accordait rien : 000029
l'omettait délibérément de la matrice au motif que le code le court-circuitait,
et le court-circuit lisait en réalité `identities.privilege_level`. Les deux
notions sont séparées selon l'axe qui les distingue vraiment :

> les permissions disent **quoi** ; `is_admin` dit **sur les données de qui**.

`super_admin` détient maintenant les 82 permissions par la matrice, comme
n'importe quel rôle — donc son autorité est énumérable — et c'est lui, non la
colonne, qui accorde la portée inter-tenant. Le court-circuit de
`HasPermission` a disparu : il rendait la matrice décorative pour précisément le
compte le plus puissant. Migration 000035, avec réconciliation des données
existantes ; `TestSuperAdminHoldsEveryPermission` échoue si une migration future
ajoute une permission sans l'accorder.

**Les KPI : trois défauts superposés.** Le constat de §3.7 (« rien ne publie de
`KPISnapshot` ») était exact mais en cachait deux autres, et les trois se
conjuguaient pour rendre le tableau de bord vide :

1. **`PlatformOverview` lit lui aussi le magasin KPI.** Il ne calcule rien : il
   assemble le dernier relevé publié par chaque domaine. Sans producteur, ce
   n'était pas « un graphique manquant » — c'était *toute* la page, score de
   sécurité compris, à zéro pour chaque tenant.
2. **Six des sept migrations ClickHouse ne s'appliquaient pas.** Cinq portaient
   un `TTL` sur une colonne `DateTime64`, que ClickHouse refuse (il exige `Date`
   ou `DateTime`) ; une déclarait `ORDER BY (..., severity DESC, ...)`, or une
   clé de tri MergeTree n'a pas de direction — erreur de syntaxe. Les schémas
   SIEM, UEBA, TI, vuln et audit **n'avaient donc jamais existé**. La septième
   exigeait des disques `warm`/`cold` qu'aucun schéma ne peut présumer : la
   table d'audit, celle qu'un régulateur demande, échouait sur toute
   installation mono-disque. Le TTL de tiering y est remplacé par la commande
   `ALTER TABLE` documentée ; ce qui ne doit jamais y figurer est une expiration
   sèche — un enregistrement d'audit qui s'efface tout seul est le contraire de
   ce à quoi sert la table.
3. **Toutes les lectures ClickHouse échouaient.** `clickhouse.Named` lie ses
   paramètres sous forme textuelle : un `uuid.UUID` ([16]byte) et un `time.Time`
   sont rejetés par `expected string value in NamedValue for query parameter`.
   Les écritures, en liaison positionnelle, passaient ; les lectures — les
   `LatestSnapshots` du dashboard, son `QueryTimeSeries`, la déduplication
   d'alertes du SIEM et son filtre de dates — non. `db.CHTime` / `db.CHTime64`
   règlent le cas au même endroit.

Faire tourner la chaîne en a révélé trois de plus, qu'aucun test unitaire
n'aurait pu voir :

4. **`GetAlertStats` du SIEM échouait toujours.** `COUNT()` revient en `UInt64`
   et le driver refuse de le réduire : `converting UInt64 to *int is
   unsupported`. Les agrégats groupés lisaient déjà dans un `uint64`, la
   première ligne non. L'endpoint `/siem/alerts/stats` n'a donc jamais répondu.
5. **`AlertStats.Open` n'était jamais renseigné.** ClickHouse détient les
   alertes, PostgreSQL détient leur statut dans `alert_metadata`, et la requête
   n'interrogeait que ClickHouse : le compte d'alertes ouvertes valait zéro quel
   qu'en soit le nombre — sur la page du SIEM comme sur le tableau de bord.
   `CountOpenAlerts` fait la jointure ; une alerte sans ligne de métadonnées n'a
   jamais été triée, et la colonne comme son absence valent `open`.
6. **Un consommateur démarré avant son topic ne le voyait jamais apparaître.**
   Sans partition assignée, il reste bloqué sur `ReadMessage` sans une seule
   erreur à montrer. C'est arrivé pour de bon ici : l'ingesteur du dashboard a
   précédé le premier producteur et n'a rien consommé jusqu'à son redémarrage.
   `WatchPartitionChanges: true` sur les cinq lecteurs du dépôt.

Le producteur lui-même est `internal/pkg/kpi` : un service le démarre en un
appel dans son `main`, fournit `KPISamples(ctx, tenantID)` au-dessus de ce qu'il
calcule déjà pour son propre `/stats`, et le sampler publie pour chaque tenant
actif sur `crp.events.kpi`. L'échec d'un tenant n'interrompt pas les autres :
un tableau de bord vidé pour tout le monde parce qu'un tenant est en erreur est
exactement ce qu'on cherche à supprimer. Les sept domaines que lit l'aperçu
(siem, ueba, ti, vuln, attackpath, soar, kg) publient.

**Vérifié de bout en bout.** Avec PostgreSQL, ClickHouse 24.3 et un broker
Kafka KRaft : quatre alertes insérées dans ClickHouse (2 critiques) et quatre
statuts dans PostgreSQL (3 non closes) ; le SIEM publie
`critical_alerts=2`, `open_alerts=3`, `risk_score=25` (10×2 + 4×1 + 1) ; le
consommateur les stocke ; `GET /dashboard/overview` les rend. Le même essai
répété avec le consommateur démarré *avant* la création du topic passe
désormais aussi.

**À faire valider avant de lire les scores comme des mesures.** Chaque domaine
dérive un `risk_score` 0–100 d'une formule pondérée écrite en clair dans son
fichier `kpi.go` — dix alertes critiques ouvertes saturent le score du SIEM, une
entité à risque pèse plus qu'une anomalie isolée, un finding hors SLA pèse plus
qu'un finding de même gravité encore dans les temps. Ces pondérations sont un
point de départ, au même titre que la matrice de permissions : arbitrer une
gravité contre une autre est une décision d'appétit au risque qui appartient à
l'établissement, pas au code.

### 3.9 Le knowledge graph — un parcours qui n'a jamais fonctionné, puis Neo4j

Le knowledge graph a exactement un endpoint de parcours,
`GET /kg/entities/{id}/neighbors`, et c'est le seul moyen de répondre à la
question qu'un analyste pose réellement : *à quoi cette adresse IP est-elle
reliée ?* Il n'a jamais fonctionné.

**`direction=both` — la valeur par défaut — était du SQL invalide.** Le CTE
récursif comportait trois branches `UNION ALL` ; la deuxième référençait
`g.path` et `g.depth` sans jointure sur `graph`. PostgreSQL refuse :
`missing FROM-clause entry for table "g"`. Le handler met `both` par défaut, et
`Enrich` — la vue enrichie d'une entité — ne connaît pas d'autre direction.
Vérifié en exécutant la requête telle qu'elle était écrite, pas en la lisant.

**Et `Enrich` transformait l'échec en silence.** L'erreur du parcours était
journalisée en `warn`, puis l'entité était renvoyée avec une liste de voisins
vide. L'enrichissement d'une IP a donc toujours répondu « aucune relation
connue », sans que rien ne distingue cela d'un graphe réellement vide. C'est la
réponse la plus coûteuse qu'un outil de sécurité puisse donner.

**Trois autres défauts dans le même parcours :**

1. **`rel_types` était analysé et ignoré.** Le handler le découpait, le service
   le portait, la traversée ne le lisait jamais : restreindre une requête à
   `CONNECTS_TO` renvoyait la même chose que ne rien restreindre. Même classe
   que `include_types` du §3.5.
2. **`valid_from` n'était jamais filtré.** Seul `valid_until` l'était. Une
   relation déclarée effective le mois prochain était déjà parcourue — et
   `ListRelationships` la listait aussi, donc la vue graphe et la liste de
   relations pouvaient se contredire.
3. **Le CTE énumérait les chemins simples**, pas les entités. L'exclusion
   (`NOT (id = ANY(path))`) était par chemin, pas globale : sur un nœud de
   concentration — un rebond partagé, une IP de sortie d'entreprise — cinq sauts
   avec un facteur de branchement de cent, c'est dix milliards de lignes. Un
   danger de production, pas une lenteur.

**Le parcours est réécrit en expansion saut par saut**, avec un ensemble de
visités global : chaque entité revient à la profondeur la plus courte qui
l'atteint, le travail est linéaire en arêtes, et au-delà de 2000 entités
atteintes la traversée **refuse** au lieu de renvoyer un sous-ensemble
arbitraire — une réponse partielle silencieuse à « à quoi est-ce relié » est la
seule qu'on ne puisse pas vérifier.

**L'algorithme vit hors des magasins** (`internal/repository/traversal.go`).
Les deux magasins exécutent la même marche et ne diffèrent que sur une question :
« quelles relations en vigueur touchent ces entités ? ». Une différence entre
eux ne peut donc venir que des données ou de cette requête, jamais de deux
implémentations de BFS qui divergent.

**Neo4j, selon le même schéma qu'au §3.5** : `:KGEntity`, contrainte d'unicité
sur `(tenant_id, id)`, double écriture sur les entités, les relations **et les
suppressions** — une suppression qui n'atteint pas le miroir y laisse une
relation que la traversée continue de parcourir, ce qui est pire qu'une relation
manquante puisqu'elle affirme quelque chose de faux. `kg-reconcile`
(`make kg-reconcile`) compare et sort en code non nul ; la bascule est
`KG_GRAPH_READS=neo4j`. Les relations portent leur **vrai type Cypher**
(`USES`, `RESOLVES_TO`…) plutôt qu'un type générique : Cypher ne paramètre pas
un type de relation, donc la table des douze types est fixe et indexée par les
constantes du modèle — aucune chaîne venue d'une requête n'atteint le texte
Cypher, et un type inconnu est refusé avant toute construction.

**Deux défauts trouvés en passant :**

- **`evidence_source = 'collector'` était valide partout sauf en base.** Le
  validateur de l'API l'accepte, le modèle le déclare, `kg_observations`
  l'accepte — et la contrainte CHECK de `kg_relationships` le refusait. Le
  collector est justement le service qui découvre le plus de relations
  (`BELONGS_TO` entre un actif et son propriétaire). Migration `000036`.
- **`Stats` jetait l'erreur de chacune de ses cinq requêtes.** Un échec se
  lisait zéro : la carte « total entities » du tableau de bord montrait un parc
  vide plutôt que de dire qu'elle ne savait pas.

**Étape 5 — mesurée, puis refusée, et voici pourquoi.**

J'avais écrit qu'il fallait pousser la marche dans Cypher avec
`apoc.path.expandConfig`. En l'essayant, deux obstacles, dans cet ordre.

**Le premier est une question de justesse.** `apoc.path.expandConfig` est la
seule primitive Neo4j qui fasse un parcours en largeur avec un ensemble de
visités **global** — exactement l'algorithme d'ici. Elle ne sait filtrer que sur
le *type* d'une relation, jamais sur ses propriétés. Or une relation n'est
parcourable que si l'instant présent tombe dans `[valid_from, valid_until)`.
Filtrer après coup ne marche pas : le parcours marque une entité visitée dès
qu'il l'atteint, donc s'il l'a atteinte par une relation périmée, elle est
écartée et jamais réatteinte par une relation valide. Le résultat manquerait des
entités réellement joignables. `ANY SHORTEST` de Cypher 5.26 accepte bien un
prédicat de relation, mais avec une cible non liée le planificateur produit un
`StatefulShortestPath(Into)` précédé d'un produit cartésien : une recherche par
entité candidate, soit N parcours au lieu d'un.

Une autre voie existait — ne mettre dans Neo4j que les relations *en vigueur*, et
laisser un balayage périodique les faire entrer et sortir. Elle rend toutes les
primitives disponibles, au prix d'une réponse qui dépend de la date du dernier
balayage. Pour un graphe de sécurité, « cette relation a expiré il y a une
heure » est une réponse fausse dans le sens qui compte. Refusée.

**Le second est une question de gain.** Contrairement aux chemins d'attaque, ce
parcours-ci **n'a jamais chargé le graphe dans le processus** : il interroge le
magasin à chaque saut, cinq fois au maximum. Il n'y avait donc pas de
`LoadGraph` à retirer. Mesuré sur un tenant de 20 000 entités et 137 000
relations, en grappes :

| sauts | PostgreSQL | Neo4j |
|---|---|---|
| 1 | 0,8–1,1 ms | 3,4–4,7 ms |
| 2 | 3,2–3,8 ms | 13,0 ms |
| 3 | 9,1–9,2 ms | 74–83 ms |
| 4 | 24–35 ms | 198–205 ms |

Deux exécutions concordantes après `VACUUM ANALYZE` — une troisième, sur des
tables gonflées par un jeu d'essai laissé en place, avait donné des chiffres
vingt-cinq fois différents, ce qui a coûté une itération et vaut d'être dit.
**PostgreSQL est 4 à 8× plus rapide, à toutes les profondeurs.** Réserve
honnête : le PostgreSQL de cet environnement est un paquet système réglé, le
Neo4j un serveur embarqué aux réglages par défaut, sur la même VM à quatre
cœurs. Le rapport est indicatif, pas un verdict général sur les deux produits.

**Ce qui a été fait à la place**, sur la foi de ces mesures :

- **La requête d'adjacence Neo4j partait d'un balayage.** Écrite
  `MATCH (a:KGEntity {tenant_id: $t}) WHERE a.id IN $frontier`, elle parcourait
  les vingt mille entités du tenant pour en filtrer cent trente. Un `UNWIND` sur
  le front utilise l'index de la contrainte `(tenant_id, id)` — le plan passe à
  `NodeUniqueIndexSeek`.
- **Le motif non orienté comptait deux fois** toute relation interne au front :
  1809 lignes projetées et triées pour 1185 relations. `WITH DISTINCT r`
  supprime le doublon avant que ses douze propriétés ne soient lues.
- **Le miroir écrivait une instruction par ligne** : backfiller ce tenant
  prenait **5 min 21**, contre **18 s** par lots de mille.

Un banc (`BenchmarkNeighbors`, `BenchmarkAdjacency`) est livré avec, et c'est
lui qui a séparé le coût de la requête de celui du décodage : 70 ms des 72 sont
dans la requête, 2,5 ms dans la reconstruction des UUID. Sans cette séparation
j'aurais optimisé le mauvais côté.

### 3.10 L'installation — ce que faire tourner la plateforme a montré

La plateforme n'avait jamais été installée. Tout avait été vérifié par `curl`,
par des tests, par des builds — jamais en ouvrant l'interface sur les services.
L'installer a pris une matinée et révélé quatre défauts qu'aucune de ces
vérifications ne pouvait atteindre.

**1. Aucun CORS n'existait, nulle part.** L'interface est servie depuis une
origine et chaque service répond sur son port : chaque appel est donc
inter-origine. Le navigateur les bloquait tous. L'interface affichait sa
coquille, chaque panneau disait « Failed to fetch », et **aucun journal de
service ne contenait quoi que ce soit** — la requête n'arrivait jamais. `curl`
n'en avait jamais eu besoin. Le préflight doit par ailleurs être traité avant
l'authentification : un `OPTIONS`, que le navigateur envoie sans identifiants,
repart sinon en 401 et le navigateur bloque la requête réelle.

**2. L'interface et les services n'avaient pas le même émetteur de jetons.**
Le frontend s'authentifie auprès de Keycloak et envoyait le jeton Keycloak ; les
trente services ne vérifiaient que des RS256 signés par `identity-service`. Deux
systèmes d'authentification, aucun pont : on pouvait se connecter et ne rien
lire. `identity-service` a en outre son propre `/auth/login` email + mot de
passe avec MFA — deux chemins d'authentification utilisateur dans le même
produit.

*Décision prise avec l'utilisateur* : les services valident Keycloak directement
(`internal/pkg/oidc`, JWKS, algorithme épinglé). Mais le jeton n'est cru que sur
**qui** est l'appelant. Le tenant, les rôles et les permissions viennent des
tables de la plateforme (`internal/pkg/rbac`), parce que les deux vocabulaires
de rôles diffèrent — `dpo`, `risk_manager`, `platform_admin` côté realm ;
`tenant_admin`, `threat_hunter`, `super_admin` côté plateforme — et les faire
correspondre reviendrait à en maintenir deux pour toujours. Une personne que
l'annuaire connaît et que la plateforme ignore reçoit **403**, pas 401 : elle a
prouvé qui elle est, et recommencer la connexion ne changerait rien.

**3. PostgreSQL par défaut ne peut pas faire tourner la plateforme.** Trente
services avec un pool de 25 maximum et 5 minimum, c'est 150 connexions
immobilisées avant que rien ne se passe et 750 demandées en pointe, contre un
serveur à `max_connections = 100`. En Docker Compose exactement pareil : l'image
`pgvector/pgvector:pg16` garde le défaut. Les services perdants du départ
mouraient sur « sorry, too many clients already ». Minimum ramené à 2, bornes
réglables (`DB_MAX_CONNS`, `DB_MIN_CONNS`), `max_connections=400` inscrit dans
le compose — et il faudra un pooler en production.

**4. La connexion échouait pour tout le monde hors Vercel.** Auth.js refuse de
faire confiance à l'en-tête `Host` sans opt-in explicite, et le contrôle a lieu
dans le middleware Edge de Next — où une valeur de `.env.local` ne parvient pas.
Il faut `AUTH_TRUST_HOST` dans l'environnement du processus. Le symptôme est un
500 disant seulement « a problem with the server configuration ».

Et un cinquième, côté interface : **SWR partait avant la session**. La clé ne
dépendait pas du jeton, donc le premier rendu appelait sans en-tête, le service
répondait 401, et SWR gardait cet échec sous une clé qui ne changeait plus
quand le jeton arrivait. Le panneau restait cassé toute la session pendant que
le même appel depuis une console renvoyait 200.

**Ce qui est livré avec.** `backend/scripts/dev-local.sh` monte la plateforme
entière en natif — infrastructure, migrations, identités, trente services,
interface — pour les machines où Docker ne peut pas tirer d'image. Un test
(`internal/pkg/deploycheck`) compare sa liste de services à celle du
`docker-compose` **et** à la table de ports du frontend : un service ajouté d'un
seul côté ne casse aucune compilation, il ne démarre simplement pas. Le script
dit aussi ce qu'il ne fait pas : les migrations ne sont pas rejouables et il
renvoie vers `reset` plutôt que d'échouer à mi-chemin ; le Copilot exige une clé
de modèle et il le saute en le disant.

**Vérifié en interface**, connecté en `admin@cyberradar.io` par Keycloak : le
tableau de bord et cinq autres pages — SIEM, actifs, vulnérabilités, chemins
d'attaque, conformité, incidents — chargent sans une seule erreur d'API.

---

### 3.11 Le renseignement ne pilotait aucune détection

L'enrichisseur du pipeline renvoyait `[]` pour les IOC, avec un commentaire le
disant. Le seul composant qui matchait réellement des indicateurs était un
second consommateur du **même topic** que le moteur de règles — donc à côté de
lui, pas avant. Conséquence : aucune règle ne pouvait être écrite sur une
correspondance, et les indicateurs du tenant n'avaient **aucun effet sur la
détection**. Onze indicateurs chargés, zéro détection possible.

**Où la question doit être posée.** Dans l'enrichissement, avant que le moteur
de règles voie l'événement. C'est la détection la plus précieuse qu'une
plateforme de ce type puisse faire : « quelque chose ici a parlé à une adresse
que le flux connaît ».

**Pourquoi un index en mémoire** (`internal/pkg/iocindex`) et non un appel au
service TI. Un événement porte jusqu'à une demi-douzaine de valeurs candidates ;
aux débits annoncés cela fait des centaines de milliers de recherches par
seconde, qu'aucune base et aucun cache réseau ne servira. Le coût est que
l'index est un instantané : un indicateur ajouté maintenant met jusqu'au
rafraîchissement suivant (60 s par défaut) à peser sur la détection. La fenêtre
est bornée et l'âge de l'instantané est journalisé — c'est le compromis honnête.
Un plafond (`IOC_MAX_ENTRIES`, un million par défaut) borne la mémoire du chemin
d'ingestion ; un flux plus gros est matché partiellement **et le dit**.

**Trois décisions dans la notation.**

- Une correspondance **relève le score à un plancher** plutôt que de s'y
  ajouter : additionner laisserait deux correspondances faibles peser plus
  qu'une certaine, et rendrait le seuil qu'une règle doit comparer dépendant du
  nombre de champs qui ont matché. Plancher : CRITICAL 9, HIGH 8, MEDIUM 6,
  LOW 4.
- **L'attribution du flux bat la devinette par mot-clé.** Un événement
  `file_transfer` était étiqueté T1041 par heuristique ; s'il a touché une
  adresse que le flux attribue à T1071.001, c'est celle du flux qui est portée.
- Le champ `ioc_matched` est **vide, jamais nul** : un consommateur ne doit pas
  avoir à distinguer « aucune correspondance » de « champ non renseigné ».

**Une seule extraction de candidats.** Il y en avait deux, et elles étaient en
désaccord — l'une lisait `user_name`, l'autre aurait lu `user_email` — donc
quels indicateurs pouvaient matcher dépendait du composant interrogé. De même,
la normalisation (`Normalize`) est désormais partagée entre l'index et le dépôt
TI : une recherche normalisée autrement que la valeur stockée manque à chaque
fois, et manque **silencieusement**.

**Le champ est devenu interrogeable.** `ioc_matched` est ajouté à `getField` du
moteur de règles : une règle dit `exists` pour « le flux connaît quelque chose
ici », ou `contains "ip:"` pour nommer un genre. Le jeu de démonstration porte
les deux.

**Mesuré sur la plateforme installée** : 39 événements injectés, index de 11
indicateurs, **14 alertes** contre 5 auparavant — dont 5 levées par les deux
nouvelles règles sur 4 entités distinctes. Dans ClickHouse, les événements
concernés portent `ioc_matched`, un `threat_score` à 9 (plancher CRITICAL) ou 8
(HIGH), et la technique du flux.

**Ce qui reste.** Le service TI continue de faire sa propre recherche pour
enregistrer les hits, et c'est voulu : un hit enregistré doit reposer sur la
réponse de la base, pas sur un champ posé en amont. Les deux ne partagent que
l'extraction des candidats.

### 3.12 Les lectures que personne n'avait jamais exécutées

Deux défauts du même genre avaient été trouvés en exerçant six services à la
main — une colonne nullable lue dans une `string` Go, qui compile, passe la
revue, et répond 500 la première fois que la colonne est vide. Vingt-quatre
services n'avaient jamais été exercés du tout.

`internal/pkg/apicheck` lit maintenant **toutes** les routes de liste de tous
les services contre une plateforme qui tourne, et échoue sur le moindre 5xx.
Les chemins viennent de deux sources : la table `ROUTES` de l'interface, **lue
depuis `frontend/src/lib/api.ts`** plutôt que recopiée — une route que
l'interface gagne est couverte sans que personne y pense, et une route renommée
ne laisse pas une sonde périmée passer contre un endpoint que plus rien
n'appelle — et une table explicite pour les quatorze services que l'interface
n'appelle pas encore. Un test de couverture échoue si un service déployé n'a
aucune sonde ; `collector` y est nommé comme exception, avec sa raison (il
n'expose que de l'écriture machine).

**Ce que la première exécution a trouvé.** 118 routes, un seul 500 :
`GET /api/v1/audit/events`. La recherche dans la piste d'audit passait au
pilote ClickHouse une `map[string]any` contenant un `time.Time` là où un
paramètre de requête nommé doit être une chaîne — `clickhouse.Named`, comme le
reste du dépôt le fait déjà. Le pilote refusait la requête entière. **Toute
lecture de la piste d'audit répondait 500 depuis que le code existe**, et rien
ne le disait : un 500 issu d'une erreur domaine enveloppée en `Internal` ne
laissait aucune ligne de journal jusqu'à ce que ce soit corrigé (§3.10). Les
deux corrections se sont trouvées le même jour, et la seconde a nommé la
première en une ligne.

**Une limite à connaître avant de se fier à un succès** : la lecture d'une
table vide ne peut pas rencontrer de NULL. Le contrôle ne vaut que sur ce que
le jeu de démonstration remplit — d'où `dev-local.sh demo` puis
`dev-local.sh smoke`, dans cet ordre. La CI n'exécute que la moitié qui ne
demande pas de plateforme : faire tourner trente services dans un job reste à
faire.

### 3.13 Ce qu'un navigateur piloté a trouvé que rien d'autre ne voyait

`frontend/e2e` couvre dix-sept parcours : la connexion via Keycloak, les huit
pages alimentées par le jeu de démonstration, les sept encore vides, la
déconnexion. Chaque page est jugée sur l'absence d'appel d'API en 5xx, l'absence
de requête que le navigateur n'a pas pu terminer, l'absence d'exception non
rattrapée — puis sur une donnée du jeu réellement affichée. Les assertions
portent sur les données et non sur les libellés : un libellé est traduit, et
l'affirmer teste le dictionnaire.

Deux défauts à la première exécution :

- **Le bouton de déconnexion n'avait aucun gestionnaire.** Sur un poste
  d'analyste partagé, c'est tout le défaut. Corrigé via `signOut`, qui termine
  aussi la session côté Keycloak.
- **`output: 'standalone'` cassait le build servi** alors que rien ne le
  consommait. `next start` ne le supporte pas ; le HTML réclamait des empreintes
  de chunks absentes de `.next/static`, et chaque page mourait vide sur
  `ChunkLoadError`.

Et deux dans le lanceur local, trouvés en faisant tourner tout cela :

- **Un pid seul n'est pas une identité.** Le fichier de pid de Redis contenait
  482, qui après redémarrage appartenait à un worker noyau : le script a annoncé
  Redis « déjà démarré » alors que rien n'écoutait. La même erreur dans l'autre
  sens aurait tué ce worker. Le fichier porte désormais le pid **et l'heure de
  démarrage** que le noyau enregistre — le couple est unique, et il survit à
  `exec`, ce qu'un marqueur pris dans la ligne de commande ne fait pas.
- **`stop` ne tuait que le pid enregistré.** `npm run start` lance le vrai
  serveur en enfant ; l'enfant gardait le port et le démarrage suivant échouait
  en `EADDRINUSE`. Les processus sont maintenant lancés dans leur propre groupe,
  et c'est le groupe qui est arrêté.

### 3.14 Paramétrable — et la ligne où cela s'arrête

Le score de risque portait ses pondérations en dur. Le problème n'était pas la
propreté : **les pondérations ne sont pas des faits sur le parc, ce sont
l'appétence au risque d'une institution**. CVSS 9,8 vaut 9,8 partout ; qu'une
vulnérabilité critique sur un actif exposé et dans le périmètre carte vaille 7
ou 9 est une décision que la fonction risque d'une banque prend, défend devant
son régulateur, et révise. Un éditeur qui tranche à sa place a tort, ou se fera
contester à chaque appel d'offres.

Le modèle retenu, et qui vaut comme **patron pour le reste de la plateforme** :

**La question à se poser sur chaque valeur : est-ce un fait ou un jugement ?**
Un fait ne se paramètre pas — le score CVSS, l'appartenance au catalogue KEV,
l'horodatage d'un événement. Un jugement se paramètre toujours : une
pondération, un seuil, un délai de correction contractuel, ce qui compte comme
« risque élevé », quelles détections sont actives, quels référentiels
s'appliquent. Rendre un fait configurable est une porte ouverte à la
falsification ; laisser un jugement en dur, c'est imposer le nôtre.

**Des valeurs standards livrées, pas un formulaire vide.** Quatre profils —
équilibré, orienté vulnérabilités, orienté PCI DSS, orienté SWIFT CSCF — parce
qu'une banque n'a pas une appétence unique : ce qu'un évaluateur carte demande
et ce qu'une attestation CSCF demande ne sont pas la même question. Le client en
adopte un puis l'ajuste, et **l'écart au profil standard est ce qu'il défend
devant son auditeur** — beaucoup plus solide qu'un ensemble de nombres sans
généalogie. Un tenant qui n'a rien choisi est noté sous le profil standard, et
l'API le **dit** (`chosen: false`) : présenter un défaut comme une décision du
client, c'est finir par défendre l'appétence de quelqu'un d'autre en audit.

**Versionné et daté, jamais modifié en place.** Sous DORA et ISO 27001, un score
qui a fondé une décision doit s'expliquer des mois plus tard, et la première
question est « quelle était la formule ce jour-là ». Une ligne éditée sur place
ne peut pas y répondre. Chaque changement ouvre une version et ferme la
précédente, avec l'auteur et une note libre — la note est ce que l'auditeur lit
d'abord : *pourquoi* ce choix.

**Des colonnes nommées, pas un blob JSON.** Une pondération porte alors une
contrainte qui la borne, la vue SQL la joint sans rien extraire, et un facteur
ajouté au modèle est une migration que quelqu'un a relue — pas une clé qui
apparaît en production.

**Un ensemble de facteurs fixe, pondérable — pas un langage d'expressions.** Et
c'est le point sur lequel je serais le plus ferme : un client capable d'écrire
des formules arbitraires obtient un nombre que plus personne n'explique, sans
répartition par facteur, incomparable d'un tenant à l'autre, et impossible à
défendre. Le contrat qui tient est **toute liberté sur le jugement, aucune sur
le vocabulaire**. Un facteur qui manque vraiment est une conversation produit,
pas un champ de configuration.

**L'autorité n'est pas administrative.** Les routes sont derrière `risk:read` /
`risk:write`, pas `tenants:*`. Dans la matrice seedée, le CISO peut changer
l'appétence et un administrateur de tenant ne peut pas : c'est le bon sens de la
séparation.

**Ce que cela coûte.** La formule existe désormais deux fois — en SQL dans la vue
`asset_risk`, pour trier et compter cent mille actifs dans la base, et en Go pour
la répartition qui l'explique. Le test d'intégration fait tourner les deux sur
les mêmes lignes **sous chacun des quatre profils standards**, et un second test
vérifie que les valeurs seedées par la migration et celles codées dans
`DefaultRiskProfile` coïncident : deux jeux de défauts qui divergent
signifieraient qu'une installation neuve note autrement qu'une installation
documentée.

**Mesuré.** Le profil `balanced` reproduit exactement l'ancienne formule : rendre
la chose paramétrable n'a changé aucun chiffre. En adoptant `swift_cscf` avec le
poids SWIFT porté à 2,5 et le seuil à 6, `swift-gw-01` passe de 5,40 à 7,15,
`hsm-pay-01` de 6,00 à 7,75, et le compteur « risque élevé » de 3 à 7 — et la
répartition nomme le profil et sa version.

**Ce qui reste.** La page Réglages ne sait pas encore écrire ce profil ; l'API
est là, l'écran non. Et le même patron reste à appliquer aux autres jugements en
dur : les seuils de détection UEBA, les délais SLA de correction, les
pondérations du score de chemin d'attaque.

### 3.15 La bibliothèque de détection, et sa généalogie

Un moteur de détection avec une table de règles vide ne détecte rien. Chaque
client réécrit alors les mêmes quinze règles que tous les autres, de mémoire, et
personne ne peut dire ce que la plateforme couvre.

`detection_content` porte les quinze détections que la plateforme livre —
bourrage d'identifiants, force brute sur un compte, session administrateur,
élévation de privilèges, interpréteur sur actif critique, trois règles de
renseignement, deux d'exfiltration, balayage réseau, déplacement latéral,
transaction à risque, et deux entrées géographiques et comportementales. Le
tenant adopte ce qui lui convient, l'ajuste, et écrit les siennes dans la même
grammaire.

**La généalogie est le cœur.** Une règle de tenant enregistre de quelle entrée
elle vient **et à quelle version**, ce qui rend trois questions répondables :

- *Que faisons-nous tourner qui vient de CyberRadar, et qu'avons-nous changé ?*
  L'écart est **calculé à la lecture**, champ par champ, donc il ne peut pas se
  périmer — et une modification faite directement sur la règle y apparaît au
  lieu d'être invisible.
- *La plateforme a-t-elle amélioré une règle que nous avons adoptée ?* La version
  courante de l'entrée est supérieure à celle adoptée.
- *Que couvrons-nous, et contre quel référentiel ?* Le catalogue porte la
  cartographie ATT&CK et les références de contrôle, donc la couverture est une
  requête, pas un tableur.

**La comparaison se fait contre la version adoptée, jamais contre celle du jour.**
Comparer un tenant resté en v1 à la v2 rapporterait les améliorations de
l'éditeur comme des modifications du client — exactement la mauvaise réponse à
« qu'avez-vous changé ». Un test le vérifie en publiant une v2 et en exigeant
zéro écart.

**Deux choses qu'une simple liste de règles ne ferait pas.**

Le catalogue **déclare ses prérequis**. Une détection qui s'appuie sur un champ
que rien ne remplit charge, ne matche rien, et se présente comme une couverture
— ce qui est pire que pas de règle. Ces entrées sont livrées **désactivées**,
avec la raison, et le service refuse de les activer par défaut même si une future
entrée oubliait de le faire. Deux le sont : la règle géographique (il faut une
base MaxMind sous licence) et la règle horaire (il faut la notion de plage
attendue par compte).

Et il porte **le raisonnement** : pourquoi la détection existe, ce qui la
déclenche légitimement, quoi faire quand elle part. C'est la troisième qu'un
analyste lit à trois heures du matin, et une règle sans elle est un bipeur qui ne
dit rien. Un test refuse une entrée sans justification.

**Un défaut trouvé en écrivant le catalogue.** `cbs_impact` et `swift_impact`
sont dans le schéma d'événement et dans le vocabulaire du moteur de règles, et
**rien dans la plateforme ne les renseigne** : ils valent toujours zéro. Une
règle livrée sur l'un des deux aurait été une détection incapable de déclencher.
Le vocabulaire du moteur est désormais déclaré (`KnownFields`), et deux tests
ferment la boucle : aucune entrée du catalogue ne nomme un champ inconnu, et
chaque champ déclaré résout réellement sur un événement complet.

**Le jeu de démonstration adopte au lieu d'écrire.** Huit entrées, dont deux
ajustées — une fenêtre de déduplication resserrée, une sévérité relevée — pour
que la généalogie ait quelque chose à montrer. Il écrivait ses règles à la main ;
il démontrait le mauvais geste, et laissait la bibliothèque ressembler à de la
documentation que personne n'utilise. Mesuré : 8 adoptées sur 15, 8 actives, 0
règle propre, et **32 alertes** levées par le moteur sur les 39 événements
injectés.

### 3.16 La remise à niveau : une fusion à trois, pas un écrasement

Signaler qu'une version plus récente existe sans pouvoir la prendre, c'est une
demi-réponse. La prendre en écrasant la règle aurait été la mauvaise autre
moitié : la généalogie existait pour conserver les décisions du client, et une
remise à niveau qui les jette détruit exactement ce qu'elle protégeait.

La plateforme compare donc **à trois** — la version adoptée, celle qui est
publiée, la règle telle qu'elle est — avec cinq issues par champ :

| issue | situation | résultat |
|---|---|---|
| `unchanged` | personne ne l'a déplacé | — |
| `take_incoming` | nous l'avons déplacé, pas eux | l'amélioration arrive |
| `keep_tenant` | ils l'ont déplacé, pas nous | leur décision survit |
| `converged` | les deux, à la même valeur | rien à décider |
| `conflict` | les deux, différemment | **eux seuls peuvent trancher** |

Un conflit non tranché **refuse** la remise à niveau et nomme les champs.
Désigner un côté en silence, ce serait un éditeur qui fixe le seuil de détection
d'une banque à sa place.

Deux routes, parce qu'un plan doit être lisible sans être pris :
`GET .../{code}/upgrade` calcule, `POST` applique. Le `POST` porte la version
contre laquelle le plan a été calculé, et l'`UPDATE` vérifie cette version dans
son `WHERE` : une décision prise sur un écart ne peut pas atterrir sur un autre
après que le catalogue a bougé, et deux appels simultanés ne peuvent pas tous
deux croire avoir fusionné.

Vérifié sur la plateforme en marche. Une v2 de la détection d'exfiltration a été
publiée — élargissant la fenêtre de déduplication, abaissant la sévérité que le
tenant avait déjà relevée :

```
severity        conflict       adoptée HIGH   nous MEDIUM   eux CRITICAL
dedup_window_s  take_incoming  adoptée 900    nous 1020     eux 900
```

Un `POST` vide a été refusé en nommant le champ. Trancher en faveur du tenant a
laissé la règle en CRITICAL, pris la fenêtre élargie, déplacé la généalogie en
v2 et enregistré le motif — l'écart d'après est donc **un seul champ, toujours
le leur**.

Migration 000041 : `content_upgraded_at`, tenu à part de `updated_at` (une règle
dont on a corrigé le nom hier n'a pas été portée sur une détection plus récente,
et une seule colonne ne peut pas dire les deux), et `lineage_notes`, parce
qu'une décision ne survit à la personne qui l'a prise que si elle est écrite à
côté de ce qu'elle décide.

Six tests, deux mutations pour prouver qu'ils mordent : forcer la fusion à
toujours prendre la valeur entrante, et laisser passer un conflit non tranché,
échouent l'un comme l'autre.

### 3.17 Les écrans : ce que la plateforme savait et que le client ne pouvait pas faire

Le catalogue, l'écart au standard, la couverture ATT&CK et les pondérations du
score de risque n'existaient que comme routes d'API. La plateforme savait ; le
client n'y pouvait rien.

**La page SIEM** répond maintenant à trois questions plutôt qu'à une. L'onglet
*Bibliothèque* : les quinze détections, avec pour chacune si ce tenant la fait
tourner, combien d'écarts sa copie porte, si une version plus récente existe, et
combien d'alertes elle a levées ; en déplier une montre le raisonnement que le
catalogue porte et qu'une liste de règles ne porte jamais. L'onglet *Couverture* :
par technique, lacunes d'abord et en ambre, chacune nommant les entrées qui la
combleraient. Les règles écrites par le tenant sont comptées **à part** : elles
détectent peut-être exactement ce qu'il faut, mais ce n'est pas une couverture
dont le catalogue peut répondre.

**La page Réglages** ouvre sur l'appétit au risque : ce qui est en vigueur, sa
version et sa date d'effet — et, quand le tenant n'a pas choisi, le fait qu'il
est noté avec *nos* valeurs et non avec une décision qu'il a prise. Puis les
quatre profils standards, les dix-sept facteurs groupés comme le score se
construit, la valeur standard à côté de la sienne, le motif, et chaque version
avec la fenêtre pendant laquelle elle était en vigueur.

Mesuré ensuite sur le parc : sous l'appétit que ce tenant a enregistré, **quatre
actifs sont à risque élevé ; sous le seuil standard, deux**. Le paramétrage
atteint le reporting.

**Trois défauts trouvés en pilotant les écrans, pas en les relisant.**

Cinq en-têtes de colonne affichaient leur propre clé de traduction —
`siem.severity`, `dspm.riskScore`, `mobile.lastSeen`. next-intl rend la clé
qu'il ne sait pas résoudre : la page a l'air construite plutôt que cassée et
rien n'échoue. `frontend/scripts/check-messages.mjs` prouve désormais que toute
clé littérale résout dans chaque locale et que les deux dictionnaires portent
les mêmes clés ; la CI l'exécute.

Choisir un autre profil standard gardait les chiffres déjà à l'écran et ne
changeait que ce à quoi ils étaient comparés — adopter PCI DSS aurait enregistré
onze valeurs du profil précédent comme des surcharges délibérées d'un standard
que personne n'avait choisi pour elles. Et l'enregistrement vidait le formulaire
en attendant la relecture pour le ré-amorcer : l'effet passait d'abord, depuis le
profil encore en cache, si bien qu'une version enregistrée contre PCI DSS était
aussitôt affichée contre SWIFT CSCF — cinq écarts montrés là où le client en
avait fait un. La base avait raison les deux fois, ce qui est précisément ce qui
rend ce genre de défaut livrable.

**`dev-local.sh restart [nom…]`.** `services` ne démarre que ce qui ne tourne
pas, donc il laisse silencieusement un service sur le binaire avec lequel il a
été lancé. Une route ajoutée et compilée répondait 404 depuis un processus
démarré dix minutes plus tôt, et le frontend servait un HTML nommant des
fragments que le nouveau build avait remplacés — toutes les pages vides, aucune
erreur nulle part.

**Ce qui reste sur ce sujet.** Le catalogue arrive par migration : à terme il
doit se livrer indépendamment du code, avec sa propre cadence, sinon améliorer
une détection impose un déploiement. Et la même configurabilité est due aux
seuils UEBA, aux délais de remédiation et aux pondérations des chemins
d'attaque, qui restent des constantes de la plateforme.

### 3.18 Les délais de remédiation : un engagement, pas une constante

Quatre nombres dans une map Go sous un commentaire les qualifiant de
« banking-grade ». Ce n'est pas un fait sur une vulnérabilité.

Migration 000042 leur donne la forme du profil de risque : colonnes nommées,
versionnées, effectives-datées — « ce constat a dépassé son SLA » est une
affirmation sur la politique en vigueur **quand il a été levé**, pas sur celle
d'aujourd'hui.

La base est la sévérité ; les plafonds ne peuvent que resserrer. Pas de plafond
« exposé sur Internet » : l'inventaire n'a pas la colonne, et une condition sur
un champ que rien ne renseigne ferait lire la politique plus stricte que la
plateforme ne se comporte. `banking_default` ne porte aucun plafond, donc
l'adopter ne déplace rien ; ce que nous conseillerions est une politique à part.

**Deux défauts trouvés en exécutant.** `computeExposure(cvss, severity, false)` —
le bonus KEV n'avait jamais joué. Puis le drapeau atteignait l'exposition et pas
l'échéance : les propriétés de l'actif et l'exploitabilité ne viennent pas du
même endroit, la première version demandait de le poser à deux endroits, et celui
qui alimentait l'échéance était celui qu'on oubliait. L'échéance est maintenant
calculée en SQL depuis `first_seen_at` sur les deux chemins : un rescan ne
repousse plus rien, et une vulnérabilité re-notée en critique ne garde plus le
mois qu'on lui avait donné quand personne n'y voyait d'enjeu.

```
banking_default   0 / 15      exploit_aware   12 / 15
pci_dss          12 / 15      swift_cscf      12 / 15      dora_critical  12 / 15
```

### 3.19 Les seuils comportementaux — et un moteur qui n'avait jamais tourné

Migration 000043 : huit types d'anomalie, chacun avec activation, sévérité et
score, plus les six compteurs. Le moteur les lit depuis un instantané par tenant ;
le premier chargement est fatal, parce qu'un moteur détectant silencieusement sur
les valeurs par défaut pendant qu'une console affiche celles du client est une
divergence que personne ne trouve avant des mois.

**Puis la vérification a montré que le moteur n'avait jamais rien produit.**
`ueba_profiles` : 0 ligne. `ueba_anomalies` : 0 ligne. Sur une plateforme ayant
ingéré des milliers d'événements. `entityFrom` ne lisait que `user_id` et
`asset_id` ; une ligne de log porte un nom. Chaque événement était écarté une
étape après son arrivée, et aucune ligne de base n'avait jamais existé.

L'identifiant est dérivé du nom quand la source n'en donne pas — stable, scopé
par tenant, en minuscules, sans lecture sur le chemin chaud. Migration 000044
stocke le nom à côté : une console affichant un UUID dérivé et aucun moyen de le
résoudre ne vaut pas mieux que rien.

```
avant              0 profil,   0 anomalie
après             12 profils,  4 anomalies   (balanced, 5 échecs)
privileged_watch  12 profils,  8 anomalies   (3 échecs)
```

Désactiver tous les signaux est refusé avec la raison. Un test échouait ou
passait selon l'heure à laquelle la suite tournait — un skip se lit comme un
succès dans une sortie de CI — donc la fixture est construite contre l'horloge.

### 3.20 Trois écrans, une seule forme

Réglages porte les trois jugements. Écrire trois fois la même chose était la
façon dont le troisième aurait cessé de dire « vous n'avez pas choisi », qui est
la phrase qui compte le plus — donc ce qui se répète est écrit une fois : ce qui
est en vigueur, le sélecteur de profils, l'historique, et la barre motif +
boutons. Les éditeurs de champs restent séparés : pondérations, délais et seuils
ne sont pas la même chose.

Les deux nouveaux écrans ont repris les deux corrections que l'écran du risque
avait coûté à trouver : choisir un profil adopte ses valeurs au lieu de
réétiqueter celles déjà à l'écran, et le formulaire est réamorcé depuis ce que le
service a renvoyé plutôt que depuis une relecture qui court.

### 3.21 Les chemins d'attaque : une posture, pas des constantes

Migration 000045. Dix valeurs : ce qu'un pas coûte (base, complexité, privilège),
ce que vaut la distance (décroissance par saut), ce que vaut une cible (plafond,
cible inconnue, bonus système critique) et ce qu'ajoutent plusieurs voies
d'entrée. Quatre postures, `balanced` reproduisant les constantes.

Ce qui le prouve n'est pas un test écrit pour l'occasion : c'est la suite
existante, écrite contre ces constantes. Aucun de ces tests n'a été modifié, et
ils passent tous.

**Les pondérations s'appliquent à l'analyse**, pas à l'écriture de l'arête. La
colonne `weight` est écrite une fois ; une posture qui ne vaudrait que pour les
arêtes suivantes reclasserait la moitié d'un graphe. Une arête dont le
vocabulaire ne dit rien garde son poids — un import qui savait quelque chose que
ce vocabulaire ne sait pas dire n'est pas aplati.

**Un scénario enregistre la version qui l'a noté** (`policy_code`,
`policy_version`). Sans cela, le chiffre d'un rapport devient irreproductible dès
que la posture bouge.

**Un second défaut, trouvé en mesurant.** `SavePaths` insérait sans supprimer, et
sortait tôt sur un résultat vide : un scénario annonçant deux chemins en portait
trente-huit, issus de dix-neuf exécutions, mélangées. Il prend désormais
l'identifiant du scénario et remplace, en une transaction, y compris à vide.

```
balanced             coût min 3,00   meilleur score 3,40
assume_breach        coût min 2,40   meilleur score 4,55
exploitability_led   coût min 4,00   meilleur score 2,50
crown_jewels         coût min 3,00   meilleur score 3,40
```

Un `git checkout` sur un fichier aux modifications non commitées les a effacées
au milieu de ce travail ; elles ont été réappliquées. À ne plus faire : pour
défaire une mutation de test, restaurer depuis une copie, jamais depuis l'index.

### 3.22 Les quatre jugements, et ce que le patron a donné

Les quatre suivent la même forme : colonnes nommées, versionnées, effectives-datées,
un profil standard qui reproduit l'existant à l'identique, un `chosen` qui dit au
client que ce ne sont pas encore ses valeurs, et un motif à côté de ce qu'il
décide.

| | migration | ce qui était en dur | ce que la mesure a montré |
|---|---|---|---|
| Appétit au risque | 000039 | 17 pondérations | 4 actifs à risque élevé contre 2 |
| Délais de remédiation | 000042 | 4 nombres | 12 retards sur 15 que les délais masquaient |
| Seuils comportementaux | 000043 | 6 seuils, 8 signaux | 0 → 12 profils, 0 → 8 anomalies |
| Chemins d'attaque | 000045 | 10 pondérations | 3,40 → 4,55 selon la posture |

Trois des quatre ont révélé un terme mort en les câblant : le bonus KEV jamais
appliqué, le drapeau d'exploitabilité qui n'atteignait pas l'échéance, le moteur
UEBA qui n'avait jamais traité un événement, et les chemins qui s'accumulaient
sur dix-neuf exécutions. Aucun n'était visible en lisant le code ; tous l'étaient
en l'exécutant et en regardant les nombres.

### 3.23 Le catalogue se livre sans le code

Les quinze détections étaient des `INSERT` dans la migration 000040 : améliorer
l'une d'elles était un changement de schéma. Elles sont maintenant des fichiers,
réconciliés par `contentctl`.

**Pas de numéro de version dans les fichiers.** Il est dérivé d'une empreinte du
contenu. Un numéro qu'on oublie de changer dit à un tenant qu'il est à jour alors
qu'il fait tourner autre chose ; une empreinte ne s'oublie pas. Réordonner une
liste n'est pas une version ; changer un seuil l'est, et l'exécution à blanc
nomme le champ.

**La convergence est la partie délicate.** Une ligne seedée avant les empreintes
n'en a pas. La traiter comme « différente » aurait republié les quinze entrées au
premier chargement et annoncé quinze mises à jour à chaque tenant. Elle est donc
reconstruite en `Entry` et hachée comme un fichier : la première exécution à
blanc a répondu *nothing to do*, ce qui était la seule réponse acceptable.

**Le retrait n'est pas une suppression.** Des règles de tenant pointent sur le
code, et l'écart se calcule en relisant la version adoptée.

**La validation ne demande pas de base.** C'est le point : le contenu se livre
sans le code, donc le contrôle du contenu doit tourner sans la plateforme. Le
test qui vérifiait depuis la base que chaque condition nomme un champ connu a
donc déménagé dans le paquet `content`, où il lit les fichiers.

**Un défaut de mon fait, attrapé avant le commit.** Le paquet a été généré depuis
le catalogue vivant, qui portait trois lignes v2 expérimentales de mes essais
précédents — une fenêtre de déduplication élargie et une sévérité abaissée qui
n'ont jamais été des décisions de contenu. Régénérées depuis la v1.

### 3.24 La livraison signée

Un paquet livré séparément est un paquet que le déploiement n'a pas construit.
Une livraison est donc un `.crpack` signé en Ed25519, et `contentctl` sait le
construire, le vérifier et le charger.

Trois décisions valaient d'être prises explicitement :

- **Clé de contenu ≠ clé de jetons.** Réutiliser la paire RSA des JWT ferait
  d'une compromission de clé de contenu une forgerie de jetons.
- **La confiance vient du déploiement, pas du paquet.** Un paquet portant sa
  propre clé publique ne prouve rien.
- **La signature couvre un manifeste d'empreintes**, pas les octets de
  l'archive : un échec doit nommer le fichier fautif, sinon il est ignoré.

**L'ordre.** Signature, puis empreintes par fichier, puis analyse. Un test
affirme qu'un paquet altéré *et* illisible échoue sur l'empreinte : atteindre
l'analyseur signifierait avoir décodé des octets dont personne ne répond.

**Un défaut attrapé en testant.** Le lecteur d'archive refusait les entrées de
répertoire, donc un paquet construit avec `tar` était rejeté avant même que sa
signature soit vérifiée — et mes trois premiers tests d'altération passaient
pour cette raison-là, pas pour la bonne. Les répertoires sont ignorés ; tout ce
qui n'est pas un fichier ordinaire, un lien symbolique en premier, reste refusé.

Migration 000047 : `signed_by` et `pack_digest` sur l'enregistrement de
chargement. Un chargement depuis un répertoire n'en porte aucun, ce qui est la
distinction à garder.

La CI passe par le chemin publié et vérifie qu'une clé non fiable est refusée.

Reste sur ce sujet, traité en §3.25 : la publication elle-même, la rotation de
clé documentée comme procédure, et la révocation.

### 3.25 Le canal, et le retrait d'une clé

**Une signature ne dit pas « à jour ».** Elle prouve que personne n'a altéré la
livraison ; elle ne prouve pas que c'est celle qu'il faut faire tourner. Qui
peut vous servir un fichier peut vous servir une livraison *authentique mais
ancienne*, publiée avant la détection qui le concerne — et le paquet est
exactement aussi vrai qu'au jour de sa signature. C'est le trou que §3.24
laissait ouvert, et aucune amélioration de la signature du paquet ne le ferme.

Le canal est donc signé lui aussi : `index.json` nomme chaque version publiée
avec l'empreinte de son manifeste et dit laquelle est courante, `index.sig` le
couvre. Trois questions deviennent vérifiables au lieu d'être supposées : ce qui
existe, ce qui est courant, et si le paquet servi est bien celui-là.

**Le troisième contrôle est ce que l'index achète.** Sans comparer l'empreinte
du paquet ouvert à celle que l'index promettait, un index signé dirait quelle
version est courante et on pourrait toujours servir un autre paquet,
correctement signé, à cette adresse. Prouvé par mutation : supprimer ce contrôle
seul laisse passer un paquet republié en place.

Décisions prises, chacune avec une mauvaise réponse tentante :

- **`current` est une valeur de l'index, pas « le plus grand numéro publié ».**
  Sinon retirer une livraison fautive exigerait de la supprimer, ce qui casse
  toute épingle écrite dessus.
- **Rétropublier ne déplace pas `current`.** Combler un trou ou re-signer une
  archive ne doit pas faire reculer en silence chaque déploiement qui suit.
- **Un numéro republié avec un contenu différent est refusé.** Laisser 2026.11.0
  vouloir dire deux choses rendrait sans valeur toutes les épingles existantes,
  et l'échec se manifesterait comme une détection se comportant différemment sur
  deux déploiements « à la même version ».
- **Republier le même paquet est un no-op**, date de publication comprise :
  rejouer un job de publication ne doit pas horodater à neuf un vieil artefact.
- **Le comparateur de versions est numérique par segment.** `2026.10.1` suit
  `2026.9.4`, ce qu'une comparaison de chaînes inverse — et c'est exactement la
  comparaison dont dépend le refus de retour arrière.

**Le retour arrière est refusé pour une livraison publiée, pas pour un
répertoire.** Pointer le chargeur sur un répertoire est quelqu'un qui dit « fais
correspondre le catalogue à ces fichiers » : il n'y a rien à rejouer. J'avais
d'abord appliqué le refus aux deux, et la première exécution de
`dev-local.sh content` après avoir testé un canal a échoué — le cas ordinaire,
bloqué pour se garder de rien. Avertissement pour un répertoire, refus pour une
livraison.

**La révocation est additive.** Retirer une clé en effaçant son `.pub` signifie
que l'hôte qui a raté le changement continue de lui faire confiance et ne dit
rien. Un `*.revoked` qu'il faut de toute façon distribuer échoue dans l'autre
sens : celui qui l'a reçu refuse bruyamment, celui qui ne l'a pas reçu n'est pas
plus mal loti qu'avant. Trois conséquences tenues :

- la révocation tient **sans** le fichier de clé — sinon la supprimer la
  désarmerait ;
- un refus pour révocation est distinct d'un refus pour clé inconnue : les deux
  envoient un exploitant chercher ailleurs ;
- un identifiant mal tapé **fait échouer** le chargement. Une révocation dont
  personne n'a vu qu'elle avait échoué est le pire cas : on croit la clé
  retirée et elle ne l'est pas.

`-affected <clé>` répond à ce que la révocation ne dit pas : ce que cette clé a
signé et que ce déploiement a installé. Retirer une clé arrête la prochaine
mauvaise livraison, pas celles déjà dans le catalogue, et c'est la question de
la première heure.

**Un défaut attrapé en exerçant.** `dev-local.sh` ne reconstruisait `contentctl`
que s'il était absent. Un binaire en cache antérieur au drapeau `-channel`
échouait en imprimant l'usage de l'outil qu'il avait été — ce qui se lit comme
une erreur de l'appelant, pas comme une construction périmée. Reconstruit dès
qu'une source est plus récente.

**Mesures.** Quatre mutations, chacune rattrapée : supprimer la comparaison
d'empreinte entre l'index et le paquet, comparer les versions comme des chaînes,
ne plus consulter la liste de révocation, et — la première tentative — supprimer
l'empreinte en laissant la vérification de numéro, qui a montré que mon test ne
prouvait pas le bon contrôle. Un test a été ajouté pour le cas que seul
l'empreinte attrape : le même numéro réécrit en place.

La CI passe par la chaîne complète — construire, signer, publier, installer ce
que le canal dit courant — et affirme quatre refus **avec leur motif**, pas
seulement leur code de sortie. Un refus pour le mauvais motif est la façon dont
un contrôle qui ne s'exécute jamais passe : c'est précisément ce qui était
arrivé en §3.24.

Procédure écrite : [`plan/20-CONTENT-RELEASE.md`](20-CONTENT-RELEASE.md) —
publier, rotation planifiée, clé compromise, clé perdue, et ce que chaque refus
veut dire.

**Reste sur ce sujet, et c'est de l'infrastructure, pas du code** : où le canal
est hébergé et avec quelle authentification ; la garde de la clé privée, qu'un
fichier en 0600 ne résout pas (un HSM ou un coffre signataire est la suite, et
`contentctl` ne sait aujourd'hui lire qu'un PEM) ; et la fraîcheur — un
déploiement qui n'interroge jamais son canal reste sur une version ancienne sans
que rien ne l'affirme, l'index ne portant pas de date d'expiration.

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
- **Neo4j** — *fait*, voir §3.5 (`attackpath`) et §3.9 (`knowledgegraph`) : schéma, double
  écriture, réconciliation et bascule de lecture pour les deux, exécutés contre un serveur 5.26
  réel. L'étape 5 a été faite pour les chemins d'attaque — l'énumération se fait dans le magasin,
  33× plus vite — et **refusée** pour le knowledge graph, dont le parcours ne chargeait rien et dont
  la fenêtre de validité ne s'exprime dans aucune primitive de parcours Neo4j. Les mesures sont
  en §3.9. Reste la centralité d'intermédiarité (plugin GDS), laissée tant que les lectures n'ont
  pas basculé en production.
- **État partagé Redis** pour les compteurs SIEM et UEBA — *fait*, voir §3.1. Le PAM n'en faisait pas
  partie : ses compteurs étaient déjà en base, avec un autre défaut (tableau §3).
- **DLQ + backoff exponentiel** sur Kafka — *fait*.
- **Corriger les compteurs du PAM** — *fait*, voir §3.4. Recalculés par fenêtre depuis une table
  d'agrégats quotidiens en PostgreSQL plutôt que depuis ClickHouse : le PAM n'a pas de connexion
  ClickHouse, et une ligne par identité et par jour suffit pour des fenêtres à la journée. Le même
  passage supprime la perte de mise à jour entre réplicas.
- **pgvector** + RAG Copilot — *fait*, voir §3.6. Reste : alimenter le corpus
  automatiquement depuis les incidents résolus, et découper les longs documents.
- **Matching IOC dans l'enrichissement** — *fait*, voir §3.11. GeoIP reste : la
  résolution pays/ASN exige une base MaxMind sous licence, que ce dépôt ne peut
  pas embarquer ; l'enrichisseur détecte les plages privées et laisse le reste
  vide, ce qui est visible plutôt que faux.
- **Multi-tenancy syslog** : mapping IP source / certificat client → tenant.

### Phase 3 — Complétude produit · 6 à 8 semaines

Fait (§3.7) : les 7 pages figées sont branchées, les types alignés sur les
structs Go, les chemins et filtres corrigés, recharts introduit sur les
répartitions que les API calculent.

Fait (§3.8) : réponses normalisées sur `response.OKWithMeta`, erreurs Postgres
mappées sur leur vrai statut, `super_admin` unifié, producteur de KPI écrit et
les trois défauts qui vidaient le tableau de bord corrigés.

Reste :

- **Auditer les services non exercés** — *fait*, voir §3.12. Les 118 routes de
  lecture des 29 services qui tournent répondent ; la seule qui échouait était
  la recherche dans la piste d'audit, cassée depuis toujours.
- **Pondérations de `risk_score`** — *fait autrement*, voir §3.14 : elles ne sont
  plus à valider, elles sont **paramétrables par client**, versionnées et datées.
  Ce qui reste du point d'origine : chaque client doit trancher son propre
  profil ; la plateforme ne peut pas le faire à sa place.
- Endpoint de réglages du tenant, pour que la page Réglages puisse écrire.
- Visualisation du graphe d'attaque (Cytoscape.js ou react-force-graph).
- Heatmap MITRE ATT&CK.
- **Tests end-to-end Playwright** — *fait*, voir §3.13. Dix-sept parcours ; deux
  défauts trouvés à la première exécution, dont un bouton de déconnexion sans
  gestionnaire.

### Phase 4 — Production readiness · 6 à 8 semaines

> **Remplacée par [`21-PRODUCTION-PLAN.md`](21-PRODUCTION-PLAN.md)**, écrit après
> que les phases 0 à 3 ont été faites et sur des chiffres mesurés. Ce qui suit
> reste le périmètre ; le plan en donne la séquence, les critères de sortie et
> les décisions à trancher.

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
