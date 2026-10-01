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

### La bibliothèque de détection, et sa généalogie

Un moteur de détection avec une table de règles vide ne détecte rien. Chaque
client réécrit alors les mêmes quinze règles que tous les autres, de mémoire, et
personne ne peut dire ce que la plateforme couvre.

```bash
GET  /api/v1/siem/rule-library              # le catalogue, vu par ce tenant
GET  /api/v1/siem/rule-library/coverage     # la couverture ATT&CK, lacunes d'abord
GET  /api/v1/siem/rule-library/{code}       # une détection, avec son raisonnement
POST /api/v1/siem/rule-library/{code}/adopt # l'adopter  (rules:write)
```

Quinze détections livrées, du bourrage d'identifiants au déplacement latéral. Le
tenant adopte ce qui lui convient — corps vide pour la prendre telle qu'elle est
— l'ajuste, et écrit les siennes dans la même grammaire.

**La généalogie est le cœur.** Une règle de tenant enregistre de quelle entrée
elle vient **et à quelle version** :

```json
"adopted": { "at_version": 1, "update_available": false,
             "changes": [ {"field":"severity","standard":"HIGH","tenant":"CRITICAL"} ] }
```

Trois questions deviennent répondables : *qu'avons-nous changé au standard* —
l'écart est **calculé à la lecture**, donc il ne peut pas se périmer et une
modification faite directement sur la règle y apparaît ; *la plateforme a-t-elle
amélioré ce que nous faisons tourner* ; *que couvrons-nous, et contre quel
référentiel* — le catalogue porte la cartographie ATT&CK et les références de
contrôle.

La comparaison se fait **contre la version adoptée, jamais celle du jour** :
comparer un tenant resté en v1 à la v2 rapporterait les améliorations de
l'éditeur comme des modifications du client.

Deux choses qu'une simple liste de règles ne ferait pas :

- **Le catalogue déclare ses prérequis.** Une détection appuyée sur un champ que
  rien ne remplit charge, ne matche rien, et se présente comme une couverture —
  pire que pas de règle. Ces entrées sont livrées **désactivées**, avec la raison
  (ici : une base MaxMind sous licence, et la notion de plage horaire attendue
  par compte).
- **Il porte le raisonnement** : pourquoi la détection existe, ce qui la
  déclenche légitimement, quoi faire quand elle part. C'est la troisième qu'un
  analyste lit à trois heures du matin, et une règle sans elle est un bipeur qui
  ne dit rien.

**Un défaut trouvé en écrivant le catalogue** : `cbs_impact` et `swift_impact`
sont dans le vocabulaire du moteur de règles et **rien ne les renseigne** — ils
valent toujours zéro. Une règle livrée sur l'un des deux n'aurait jamais pu
déclencher. Le vocabulaire est désormais déclaré (`KnownFields`) et deux tests
ferment la boucle : aucune entrée ne nomme un champ inconnu, et chaque champ
déclaré résout réellement.

Le jeu de démonstration **adopte** huit entrées au lieu d'écrire ses règles, dont
deux ajustées, pour que la généalogie ait quelque chose à montrer.

**La remise à niveau est une décision, pas une migration.** Quand le catalogue
avance, un tenant peut reprendre la nouvelle version sans perdre ses propres
réglages : la plateforme compare à trois — la version adoptée, celle qui est
publiée, la règle telle qu'elle est — et en tire cinq issues par champ.

```
GET  /api/v1/siem/rule-library/{code}/upgrade   ce que ça ferait
POST /api/v1/siem/rule-library/{code}/upgrade   le faire, conflits tranchés

unchanged      personne ne l'a touché
take_incoming  nous l'avons changé, pas eux      → l'amélioration arrive
keep_tenant    ils l'ont changé, pas nous        → leur décision survit
converged      les deux, au même endroit
conflict       les deux, différemment            → eux seuls peuvent trancher
```

Un conflit est **refusé** tant que personne n'a tranché : désigner un côté en
silence, ce serait un éditeur qui fixe le seuil de détection d'une banque à sa
place, et le client l'apprendrait par une alerte qui ne part plus. La requête
porte la version sur laquelle le plan a été calculé, et l'`UPDATE` vérifie la
version dans son `WHERE` — une décision prise sur un écart ne peut pas atterrir
sur un autre.

**L'écran.** La page SIEM répond désormais à trois questions plutôt qu'à une :
ce qui a déclenché, ce qu'on fait tourner et en quoi cela diffère du standard,
et ce qu'on ne voit pas. L'onglet *Bibliothèque* liste les quinze détections
avec leur adoption, leurs écarts, les versions disponibles et le nombre
d'alertes levées ; en déplier une montre le raisonnement du catalogue. L'onglet
*Couverture* classe par technique, lacunes d'abord, chacune nommant les entrées
qui la combleraient.

**Adopter n'envoie aucune surcharge**, volontairement : un écran qui
pré-remplirait un formulaire avec les valeurs standards produirait un tenant qui
a l'air d'avoir tout modifié dès le premier jour, et l'écart ne voudrait plus
rien dire.

**Reste** : le catalogue arrive par migration. À terme il doit se livrer
indépendamment du code, avec sa propre cadence — sinon améliorer une détection
impose un déploiement.

### Le renseignement pilote la détection

L'enrichisseur du pipeline renvoyait une liste d'IOC vide, avec un commentaire
le disant. Le seul composant qui matchait des indicateurs était un second
consommateur du **même topic** que le moteur de règles — à côté de lui, pas
avant — donc aucune règle ne pouvait porter sur une correspondance. Onze
indicateurs chargés, zéro détection possible.

`internal/pkg/iocindex` répond maintenant « cette valeur est-elle un indicateur
connu ? » assez vite pour la poser sur chaque événement, dans
l'enrichissement, avant le moteur de règles.

```
{"field": "ioc_matched", "op": "exists"}                  le flux connaît quelque chose ici
{"field": "ioc_matched", "op": "contains", "value": "ip:"} une adresse, précisément
```

**Un index en mémoire, pas un appel au service TI.** Un événement porte jusqu'à
six valeurs candidates ; aux débits visés cela fait des centaines de milliers de
recherches par seconde, qu'aucune base et aucun cache réseau ne servira. Le coût
assumé : l'index est un instantané, rafraîchi toutes les 60 s
(`IOC_REFRESH_SECONDS`), et son âge est journalisé. Un plafond
(`IOC_MAX_ENTRIES`) borne la mémoire du chemin d'ingestion, et un flux plus gros
est matché partiellement **en le disant** — se taire serait rapporter zéro
menace et être cru.

Trois décisions qui se lisent dans le code :

- Une correspondance **relève le score à un plancher**, elle ne s'y ajoute pas
  (CRITICAL 9, HIGH 8, MEDIUM 6, LOW 4). Additionner laisserait deux
  correspondances faibles peser plus qu'une certaine, et rendrait le seuil d'une
  règle dépendant du nombre de champs qui ont matché.
- **L'attribution du flux bat la devinette par mot-clé** : un `file_transfer`
  était étiqueté T1041 par heuristique ; s'il a touché une adresse que le flux
  attribue à T1071.001, c'est celle-là qui est portée.
- L'extraction des champs candidats et la normalisation sont **partagées** avec
  le service TI. Il y avait deux extractions en désaccord (`user_name` d'un
  côté, `user_email` de l'autre) : quels indicateurs pouvaient matcher dépendait
  du composant interrogé. Et une recherche normalisée autrement que la valeur
  stockée manque à chaque fois, **silencieusement** — « pas un indicateur connu »
  se lit exactement comme un événement propre.

Mesuré sur l'installation : 39 événements, 11 indicateurs, et des alertes levées
par les trois règles de renseignement de la bibliothèque là où aucune règle ne
pouvait porter sur une correspondance auparavant.

**GeoIP reste ouvert** : la résolution pays/ASN demande une base MaxMind sous
licence que ce dépôt ne peut pas embarquer. L'enrichisseur reconnaît les plages
privées et laisse le reste vide — visible, plutôt que faux.

### Copilot : modèle et outils

Le service appelle l'API Messages en direct, sans SDK. Rien n'y est figé :
`ANTHROPIC_MODEL` (`claude-opus-5-5` par défaut), `ANTHROPIC_BASE_URL` pour une
passerelle interne, `COPILOT_MAX_TOKENS`, `COPILOT_EFFORT`. Le modèle servi est
annoncé sur `/health` : « quel modèle répond » est la première question posée
d'un déploiement, et la lire dans un fichier de configuration ailleurs est la
façon de s'y tromper.

Trois points que la mise en service a tranchés :

- **La profondeur de réflexion ne se demande plus par un budget de jetons.**
  Les modèles courants refusent `budget_tokens` ; elle se règle par
  `output_config.effort`, et n'est envoyée que si un exploitant en a demandé
  une.
- **Les blocs de réflexion doivent revenir intacts.** La boucle d'outils
  renvoie le tour de l'assistant tel quel ; un bloc rendu sans sa signature est
  rejeté. Un type qui les laissait tomber au passage aurait transformé chaque
  appel d'outil en 400 — et seulement au deuxième échange, là où le premier
  paraît parfait.
- **Un refus n'est pas un résultat vide.** Une route absente renvoyait une page
  404 que le dispatcher passait au modèle comme une donnée ; le modèle
  concluait « aucune alerte » sur un service qu'il n'avait jamais interrogé.
  L'erreur est désormais explicite dans le résultat d'outil.

Les dix outils sont couverts par un test qui compare la route appelée à celle
que le service monte réellement : trois d'entre eux se trompaient de préfixe,
et rien ne le montrait — la réponse revenait fluide, assurée, et sur rien.

### Mémoire du Copilot (pgvector)

Les outils du Copilot répondent à des questions exactes — « quelles alertes sont
critiques », « recherche cet IOC ». Ils ne répondent pas à celle que l'analyste
pose vraiment à 3h du matin : **« est-ce qu'on a déjà vu ça ? »**. C'est une
question de similarité, et `copilot_knowledge` l'indexe avec pgvector (HNSW,
distance cosinus) sur ce que le tenant a déjà écrit : incidents résolus, notes
de playbook, runbooks.

```bash
curl -X POST localhost:8016/api/v1/copilot/knowledge \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"source_type":"incident","source_ref":"INC-2024-118",
       "title":"Credential stuffing sur le portail client",
       "content":"..."}'
```

**Les embeddings ne viennent pas d'Anthropic** — il n'y a pas d'endpoint
d'embeddings. `EMBEDDINGS_URL` attend une API compatible OpenAI
(`/v1/embeddings`), ce que parlent aussi bien les serveurs auto-hébergés
(text-embeddings-inference, vLLM, Ollama, LocalAI) que les fournisseurs hébergés.
**Pour une banque, pointez-le sur votre propre serveur** : le texte d'incident
ne quitte pas votre périmètre. La plateforme n'impose aucun fournisseur.

Sans `EMBEDDINGS_URL`, le Copilot fonctionne — il n'a simplement aucune mémoire
de l'historique du tenant. Avec, le service vérifie au démarrage que la largeur
du modèle correspond à la colonne (1024) et **refuse de démarrer** sinon :
autrement l'erreur n'apparaîtrait qu'à l'indexation, document par document.

Un chunk récupéré est présenté au modèle comme un **précédent à citer**, pas
comme un fait sur la question posée. En dessous de 0,35 de similarité cosinus,
rien n'est récupéré : une question sans rapport ne doit pas se voir servir le
document le moins hors-sujet du corpus.

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

### Lire l'API depuis le frontend

Tout chemin vit dans la table `ROUTES` de `frontend/src/lib/api.ts` — jamais en
dur dans un hook ou une page. Les hooks de domaine la lisent :

```ts
export function useIncidents(params?: Record<string, string>) {
  return useApiList<Incident>('ir', ROUTES.ir.incidents, params)
}
```

Deux règles qui coûtent cher à ignorer :

**Les interfaces de `src/types` sont transcrites des tags `json:` des structs
Go.** Un champ absent de la struct est absent du type. Inventer un champ pour
arranger un écran donne une cellule vide en production plutôt qu'une erreur de
compilation — c'est exactement ce qui a produit sept pages muettes. Les modèles
sont dans `backend/services/<svc>/internal/model/`.

**La forme des réponses est uniforme**, et doit le rester : tout service passe
par `internal/pkg/response`. Une liste est un tableau sous `data`, avec
`meta.total` toujours présent. `lib/api.ts` ne contient plus d'adaptateur mais
un garde : une réponse non conforme est signalée en console plutôt qu'absorbée,
parce qu'une table vide sans erreur est précisément le défaut que la
normalisation a supprimé.

Vérifier qu'un paramètre de filtre est bien lu par le handler avant de
l'envoyer : un paramètre inconnu est ignoré en silence, et la page semble ne
rien filtrer sans afficher d'erreur.

### Graphiques

`recharts`, avec les composants de `src/components/charts/`. La sévérité est une
échelle de **statut** : elle reprend les couleurs de `SeverityBadge` pour qu'un
graphique et un badge côte à côte ne montrent jamais deux rouges différents, et
chaque barre porte son nom en étiquette directe — la couleur ne porte jamais
seule l'information.

Les répartitions viennent des `map[string]int` que les services calculent déjà
(`by_severity`, `by_status`, `assets_by_purdue`…). Les lire avec `countOf`, qui
ignore la casse : le SIEM renvoie `CRITICAL`, les domaines Postgres `critical`.
Attention aux clés préfixées — `assets_by_purdue` est clé `level_1`, pas `1`.

### Répondre depuis un service

Tout handler passe par `internal/pkg/response`. Jamais de `json.NewEncoder(w)`
direct : neuf services le faisaient, aucun client ne pouvait écrire un seul
analyseur, et leurs erreurs sortaient sous une forme que le frontend lisait
comme `undefined`.

```go
response.OK(w, asset)                                     // une ressource
response.OKWithMeta(w, assets, &response.Meta{Total: n})  // une liste
response.Created(w, asset)
httperr.WriteLogged(w, err, h.logger)                     // toute erreur
```

**Ne jamais construire une réponse d'erreur à la main.** `internal/pkg/httperr`
classe l'erreur : une erreur de domaine (`apierrors`) prend le statut de son
`Kind`, une violation de contrainte Postgres prend le sien — CHECK et clé
étrangère en 422 avec le champ nommé, clé dupliquée en 409, littéral malformé
en 400 — et tout le reste en 500 avec un texte générique. Le message du driver
nomme la relation et parfois le SQL : il ne doit pas sortir du serveur.

### Publier ses KPI

Le tableau de bord ne calcule rien : `PlatformOverview` assemble le dernier
relevé publié par chaque domaine. Un service qui ne publie pas compte pour zéro
dans le score de sécurité, sans que rien ne le signale.

```go
kpi.Start(ctx, kpi.Config{
    Brokers: brokers,
    Domain:  "siem",
    Tenants: kpi.TenantsFromPostgres(pool),
    Source:  siemSvc.KPISamples,
}, logger)
```

`kpi.MetricKeys` dit ce que chaque domaine doit publier — c'est le contrat avec
l'aperçu, et un test échoue si un domaine cesse de l'honorer. Les formules de
`risk_score` vivent dans le `kpi.go` de chaque service, en clair : ce sont des
pondérations à faire valider, pas des mesures.

### Interroger ClickHouse

Les paramètres nommés sont liés **sous forme textuelle**. Passer un `uuid.UUID`
ou un `time.Time` échoue avec `expected string value in NamedValue` — c'est ce
qui cassait toutes les lectures du dashboard et du SIEM. Utiliser
`tenantID.String()` et `db.CHTime` / `db.CHTime64`.

### Écrire dans le graphe d'attaque

Le graphe vit à deux endroits : PostgreSQL, qui fait foi, et Neo4j, qui en
reçoit une copie. Rien à faire côté appelant — `AttackPathService` s'en charge —
mais trois règles valent pour quiconque y touche :

- **Une écriture au miroir ne doit jamais faire échouer l'écriture primaire.**
  Elle est journalisée et comptée
  (`attackpath_graph_mirror_failures_total`), sous un délai de 5 s. Faire
  dépendre PostgreSQL d'un magasin secondaire, c'est ne plus pouvoir enregistrer
  un graphe parce qu'une base de reporting est tombée.
- **Toute lecture Cypher filtre `tenant_id` sur la relation et sur ses deux
  extrémités.** Ici l'isolation est une propriété, pas une colonne : il n'y a
  pas de schéma derrière. Neo4j Community n'a qu'une base, donc pas de base par
  tenant.
- **Une arête dont un nœud manque dans Neo4j est refusée.** Sans ce contrôle, le
  `MERGE` ne rattache rien et rapporte un succès : PostgreSQL porterait un chemin
  que la traversée Neo4j ne verrait pas, et rien ne le dirait.

Après une écriture manuelle, un incident ou une reprise, `make graph-reconcile`
liste ce qui diverge ; `make graph-backfill` recopie PostgreSQL dans Neo4j puis
vérifie. Le knowledge graph a les mêmes : `make kg-reconcile`, `make kg-backfill`.

Les bancs (`go test -run XXX -bench . -benchtime 5x` dans
`services/attackpath/internal/service` et
`services/knowledgegraph/internal/repository`) construisent un tenant de
20 000 entités et comparent les deux magasins. Ils sont là pour trancher une
question de conception, pas pour décorer : faites-les tourner après un
`VACUUM ANALYZE` et sur une base sans jeu d'essai résiduel, sinon les chiffres
PostgreSQL varient d'un facteur vingt-cinq.

### Parcourir un graphe

Les deux graphes ne se parcourent pas de la même façon, et la différence est
mesurée, pas supposée.

**Chemins d'attaque : le magasin énumère les routes.** `FindPaths` — un CTE
récursif en PostgreSQL, un motif de longueur variable en Cypher — rend les
routes et rien d'autre. Auparavant chaque exécution de scénario chargeait tous
les nœuds et arêtes du tenant dans le processus : 462 ms depuis PostgreSQL,
5,8 s depuis Neo4j, avant que la marche ne commence. La marche en mémoire reste
comme **implémentation de référence**, et un test tient les trois au même
résultat. 481 ms → 15 ms sur un tenant de 20 000 nœuds.

**Knowledge graph : le parcours reste piloté depuis Go**, un saut à la fois.
Il n'a jamais chargé le graphe, donc il n'y avait rien à retirer du chemin
chaud ; et la fenêtre `[valid_from, valid_until)` ne s'exprime dans aucune
primitive de parcours Neo4j — `apoc.path.expandConfig` ne filtre que sur le type
d'une relation, et filtrer après coup perd des entités réellement joignables.
Voir §3.9 de l'audit pour les chiffres.

Ce qui vaut pour les deux : **l'algorithme vit hors des magasins**, et chaque
magasin ne répond qu'à une question — « quelles relations touchent ces
entités ? ». Une différence entre PostgreSQL et Neo4j ne peut alors venir que
des données ou de cette requête, jamais de deux parcours qui divergent.

Trois pièges, tous rencontrés :

- **Déduplication globale, pas par chemin.** Exclure les répétitions chemin par
  chemin énumère les chemins simples : sur un nœud de concentration, cinq sauts
  font des milliards de lignes. L'ensemble des visités est global, et chaque
  entité revient à la profondeur la plus courte qui l'atteint.
- **Une réponse partielle silencieuse est pire qu'une erreur.** Au-delà de
  `maxNeighbors`, la traversée refuse en nommant la limite, plutôt que de
  renvoyer un sous-ensemble que personne ne peut distinguer du tout.
- **Une relation « en vigueur », c'est `[valid_from, valid_until)`.** Les deux
  bornes, des deux côtés, à la lecture comme à la liste — sinon la vue graphe et
  la liste de relations se contredisent.

### Tester la solution de bout en bout

Deux chemins. Le premier ne demande que Docker ; le second ne demande pas
Docker du tout. Les deux aboutissent à la même chose : trente services sur les
mêmes ports, l'interface sur `http://localhost:3000`, et un jeu de
démonstration à regarder.

**Avec Docker** — il construit les images des services depuis le dépôt :

```bash
git clone -b claude/elegant-gauss-twfdeb \
  https://github.com/a3ksecufinance-dev/CyberRadar.git
cd CyberRadar/backend

make dev            # infrastructure + Keycloak, migrations, identités, services
make demo           # le jeu de démonstration, via l'API

cd ../frontend && cp .env.example .env.local && npm install && npm run dev
```

`make migrate`, `make seed` et `make demo` ont besoin de `psql` et de Go sur la
machine ; tout le reste tourne en conteneur.

**Sans Docker** — voir la section suivante : `./scripts/dev-local.sh up` puis
`./scripts/dev-local.sh demo`.

**Puis** : `http://localhost:3000`, connexion `admin@cyberradar.io` /
`Admin@CyberRadar2025!`. La console Keycloak est sur `http://localhost:8080`
(`admin` / même mot de passe).

Ce qu'il faut regarder en premier, une fois connecté :

| Page | Ce que le jeu de démonstration y met |
|---|---|
| Tableau de bord | 32 alertes ouvertes, 5 incidents, 11 indicateurs actifs, 21 chemins d'attaque |
| Actifs | 14 actifs, score de risque de 3,5 à 7,5, 3 au-dessus du seuil |
| Vulnérabilités | 10 CVE réelles, 15 constats, CVSS moyen 8,8 |
| SIEM | 32 alertes **levées par le moteur** à partir de 39 événements injectés, par 8 règles adoptées depuis la bibliothèque |
| Chemins d'attaque | 3 scénarios analysés, 21 chemins, 2 points de passage obligé |
| Conformité | DORA, PCI DSS, SWIFT CSP, ISO 27001 et leurs écarts |

Le Copilot demande une clé de modèle : `ANTHROPIC_API_KEY=sk-ant-… make dev`
(ou la même variable devant `dev-local.sh`). Sans elle il est sauté, et le
reste fonctionne.

### Installer la plateforme sur une machine

`deployments/docker-compose.yml` reste la référence du déploiement. Quand Docker
n'est pas disponible ou ne peut pas tirer d'images — réseau verrouillé, poste
hors ligne, runner sans démon — `backend/scripts/dev-local.sh` monte la même
chose en natif, sur les mêmes ports :

```bash
cd backend
CRP_KAFKA_HOME=/opt/kafka_2.13-3.7.1 \
CRP_KEYCLOAK_HOME=/opt/keycloak-24.0.4 \
./scripts/dev-local.sh up
```

`up` enchaîne infrastructure, migrations, identités, services et interface, puis
affiche un état. Les étapes s'exécutent aussi séparément (`infra`, `migrate`,
`seed`, `demo`, `smoke`, `e2e`, `services`, `frontend`), `status` dit ce qui répond, `logs <service>`
suit un journal, `down` n'arrête que ce que le script a démarré. Un test
(`internal/pkg/deploycheck`) compare sa liste de services à celle du
`docker-compose` et à la table de ports du frontend : un service ajouté d'un
seul côté ne planterait aucune compilation, il ne démarrerait simplement pas.

Trois choses qu'une installation révèle et qu'aucun test ne montrait :

- **PostgreSQL par défaut ne suffit pas.** Trente services contre un serveur à
  100 connexions : la plateforme ne démarre pas, et les perdants du départ
  meurent sur « sorry, too many clients already ». Le compose fixe désormais
  `max_connections=400` et les pools se règlent par `DB_MAX_CONNS` /
  `DB_MIN_CONNS`. Une vraie production met un pooler devant.
- **Les migrations PostgreSQL ne sont pas rejouables.** Il n'y a pas d'outil
  versionné : `migrate` laisse une base déjà migrée tranquille et renvoie vers
  `reset`. Celles de ClickHouse et de Neo4j le sont, et tournent à chaque
  `migrate` — le garde-fou couvrait la fonction entière, si bien qu'une
  installation d'abord montée sans ClickHouse ne pouvait plus jamais recevoir
  son schéma : le seul magasin qui manquait était celui que le garde-fou
  rendait inatteignable.
- **Le Copilot exige une clé de modèle** et refuse de démarrer sans. Le script
  le saute en le disant, plutôt que de le laisser mort dans la liste.

### Les tests end-to-end, dans un navigateur

```bash
cd backend
./scripts/dev-local.sh up && ./scripts/dev-local.sh demo
./scripts/dev-local.sh e2e        # ou : cd ../frontend && npm run e2e
```

Dix-sept parcours : la connexion via Keycloak, les huit pages que le jeu de
démonstration alimente, les sept encore vides, et la déconnexion. Chaque page
est jugée sur trois choses — **aucun appel d'API en 5xx, aucune requête que le
navigateur n'a pas pu terminer** (c'est la trace qu'un préflight CORS bloqué
laisse : rien, dans aucun journal de service, parce que la requête n'est jamais
arrivée) **et aucune exception non rattrapée** — puis sur une donnée du jeu de
démonstration réellement affichée.

Les assertions portent sur les **données**, pas sur les libellés. Un libellé est
traduit : l'affirmer teste le dictionnaire. Un nom d'actif à l'écran prouve
toute la chaîne — PostgreSQL, le service, CORS, le jeton, le composant.

Deux défauts trouvés par la première exécution, tous deux invisibles autrement :

- **Le bouton « Log out » n'avait aucun gestionnaire.** Il se surlignait au
  survol, il disait « Log out », et la session restait valide. Sur un poste
  d'analyste partagé, c'est tout le défaut. La déconnexion passe maintenant par
  `signOut`, qui termine aussi la session côté Keycloak — vider le cookie
  pendant que le fournisseur garde sa session signifie que la reconnexion
  suivante ne redemande pas de mot de passe.
- **`output: 'standalone'` cassait le build servi.** Rien ne le consommait — il
  n'y a pas de Dockerfile pour l'interface — et `next start`, ce que tout le
  monde utilise, ne le supporte pas : Next le dit au démarrage, et le symptôme
  est pire que l'avertissement. Le HTML servi réclamait des empreintes de chunks
  différentes de celles présentes dans `.next/static`, donc chaque page chargeait
  son cadre puis mourait sur `ChunkLoadError`, vide. Cliquer dans un build tiède
  ne le montrait pas ; un navigateur piloté, si.

La CI n'exécute pas ces tests : ils demandent une plateforme debout. Monter
trente services dans un job reste à faire.

### Vérifier que toutes les lectures répondent

```bash
./scripts/dev-local.sh demo && ./scripts/dev-local.sh smoke   # ou : make smoke
```

`internal/pkg/apicheck` lit **toutes** les routes de liste de tous les services
et échoue sur le moindre 5xx. C'est le contrôle d'une classe de défaut
qu'aucune compilation ne voit : une colonne nullable lue dans une `string` Go
compile, passe la revue, et répond 500 la première fois que la colonne est
vide. Deux avaient été trouvées en exerçant six services à la main ;
vingt-quatre n'avaient jamais été exercés.

Les chemins viennent de la table `ROUTES` de l'interface, **lue** depuis
`frontend/src/lib/api.ts` plutôt que recopiée, plus une table explicite pour
les quatorze services que l'interface n'appelle pas encore. Un test de
couverture échoue si un service déployé n'a aucune sonde.

Première exécution : 118 routes, un seul 500 — la recherche dans la piste
d'audit, qui passait au pilote ClickHouse une `map[string]any` contenant un
`time.Time` là où un paramètre nommé doit être une chaîne. Toute lecture de la
piste d'audit répondait 500 depuis que le code existe.

**Une limite** : la lecture d'une table vide ne peut pas rencontrer de NULL. Le
contrôle ne vaut que sur ce que le jeu de démonstration remplit — d'où l'ordre
`demo` puis `smoke`.

### L'appétence au risque est celle du client

Les pondérations du score d'actif ne sont pas des faits sur le parc, ce sont
l'appétence au risque d'une institution. CVSS 9,8 vaut 9,8 partout ; qu'une
vulnérabilité critique sur un actif exposé et dans le périmètre carte vaille 7 ou
9 est une décision que la fonction risque prend et défend devant son régulateur.

```bash
GET  /api/v1/risk-profiles/presets    # les quatre profils livrés
GET  /api/v1/risk-profiles/active     # celui en vigueur, et si le client l'a choisi
GET  /api/v1/risk-profiles/history    # toutes les versions, avec auteur et note
PUT  /api/v1/risk-profiles/active     # une nouvelle version  (risk:write)
```

```bash
curl -X PUT localhost:8001/api/v1/risk-profiles/active -H "Authorization: Bearer $TOKEN"   -d '{"based_on":"swift_cscf","name":"Appétence BNF 2026",
       "notes":"Validé par le comité des risques du 30/09.",
       "weights":{"swift_connected":2.5,"high_risk_threshold":6.0}}'
```

Quatre profils standards — équilibré, orienté vulnérabilités, orienté PCI DSS,
orienté SWIFT CSCF — parce qu'une banque n'a pas une appétence unique : ce qu'un
évaluateur carte demande et ce qu'une attestation CSCF demande ne sont pas la
même question. Le client en adopte un puis l'ajuste, et **l'écart au profil
standard est ce qu'il défend devant son auditeur**.

Six décisions de conception, qui valent comme patron pour le reste de la
plateforme :

- **Fait ou jugement.** Un fait ne se paramètre pas — score CVSS, appartenance
  au KEV, horodatage. Un jugement se paramètre toujours — pondération, seuil,
  délai contractuel, ce qui compte comme « risque élevé ». Rendre un fait
  configurable ouvre la porte à la falsification ; laisser un jugement en dur,
  c'est imposer le nôtre.
- **Des valeurs standards, pas un formulaire vide.** Un tenant qui n'a rien
  choisi est noté sous le profil standard, et l'API le dit (`chosen: false`) :
  présenter un défaut comme une décision du client, c'est finir par défendre
  l'appétence de quelqu'un d'autre en audit.
- **Versionné et daté, jamais modifié en place.** Un score qui a fondé une
  décision doit s'expliquer des mois plus tard, et la première question est
  « quelle était la formule ce jour-là ». Chaque changement ouvre une version et
  ferme la précédente, avec l'auteur et une note — la note est ce que l'auditeur
  lit d'abord.
- **Des colonnes nommées, pas un blob JSON.** Une pondération porte alors une
  contrainte qui la borne, la vue SQL la joint sans rien extraire, et un facteur
  ajouté est une migration relue plutôt qu'une clé qui apparaît en production.
- **Un ensemble de facteurs fixe, pondérable — pas un langage d'expressions.**
  Un client qui peut écrire des formules arbitraires obtient un nombre que plus
  personne n'explique, sans répartition, incomparable d'un tenant à l'autre.
  Toute liberté sur le jugement, aucune sur le vocabulaire.
- **L'autorité n'est pas administrative.** `risk:read` / `risk:write`, pas
  `tenants:*` : le CISO change l'appétence, un administrateur de tenant non.

Le profil `balanced` reproduit exactement l'ancienne formule — rendre la chose
paramétrable n'a changé aucun chiffre. En adoptant `swift_cscf` avec le poids
SWIFT à 2,5 et le seuil à 6 : `swift-gw-01` passe de 5,40 à 7,15, `hsm-pay-01`
de 6,00 à 7,75, le compteur « risque élevé » de 3 à 7, et
`GET /assets/{id}/risk` nomme le profil et sa version.

**La page Réglages ouvre maintenant dessus.** Ce qui est en vigueur, sa version
et sa date d'effet — et, quand le tenant n'a pas tranché, le fait qu'il est noté
avec *nos* valeurs plutôt qu'avec une décision qu'il a prise : présenter un
défaut comme un choix du client, c'est finir par défendre l'appétence de
quelqu'un d'autre devant un auditeur. Puis les quatre profils standards, les
dix-sept facteurs groupés comme le score se construit, la valeur standard à côté
de la sienne, le motif — qu'un auditeur lit avant les pondérations — et chaque
version avec la fenêtre pendant laquelle elle s'appliquait.

Mesuré sur le parc après enregistrement : sous l'appétence que ce tenant a
retenue, **quatre actifs sont à risque élevé ; sous le seuil standard, deux**.

### Les délais de remédiation

Quatre nombres dans une map Go — 3, 7, 30, 90 jours par sévérité — sous un
commentaire les qualifiant de « banking-grade ». Ce n'est pas un fait sur une
vulnérabilité : c'est un engagement, devant un régulateur, un schéma de carte ou
son propre conseil, et il diffère entre une banque de détail et un processeur de
paiement.

La base reste la sévérité. Par-dessus viennent des **plafonds** — exploitée,
DMZ, core banking, SWIFT, périmètre carte — qui ne peuvent que **resserrer** une
échéance, jamais la repousser : un établissement qui s'accorderait plus de temps
sur les actifs dont il répond le plus est le seul résultat que la forme doit
interdire.

Il n'y a volontairement **pas de plafond « exposé sur Internet »** : l'inventaire
n'a pas cette colonne, et une condition appuyée sur un champ que rien ne
renseigne ferait lire la politique plus stricte que la plateforme ne se comporte.

`banking_default` ne porte aucun plafond : l'adopter ne déplace pas une seule
échéance. Ce que nous conseillerions est une politique **à part**, que le client
choisit — le catalogue informe, il n'impose pas.

**Deux défauts trouvés en l'exécutant.** `computeExposure` prenait un argument
`isExploited` et l'unique appelant passait le littéral `false` : le bonus KEV, le
signal le plus fort de la priorisation, n'avait jamais joué, alors que l'appelant
tenait la vulnérabilité depuis le début. Puis le même drapeau atteignait le score
d'exposition et pas l'échéance, parce que les propriétés de l'actif et
l'exploitabilité ne viennent pas du même endroit — la première version demandait
aux appelants de poser le drapeau à deux endroits, et celui qui alimentait
l'échéance était celui qu'ils oubliaient.

Mesuré sur le parc, constats ouverts au-delà de leur échéance :

```
banking_default   0 / 15      exploit_aware   12 / 15
pci_dss          12 / 15      swift_cscf      12 / 15
dora_critical    12 / 15
```

Douze retards que les anciens délais masquaient, parce qu'ils traitaient un
Log4Shell armé exactement comme une criticité théorique.

### Les seuils comportementaux — et un moteur qui n'avait jamais tourné

Quatre-vingts événements par minute, cinq échecs en cinq, trois heures distinctes
avant de se fier à une ligne de base. Aucun n'est un fait sur le comportement
humain. Un seuil fixe n'est pas seulement parfois faux, il est faux
**invisiblement** : une détection qui part toutes les nuits chez le même client
cesse d'être une détection et devient une règle de filtrage écrite dans une
messagerie. Pouvoir la désactiver ici est ce qui garde cette décision visible.

Huit types d'anomalie, chacun avec son activation, sa sévérité et son score.
Quatre politiques standards ; `balanced` reproduit les constantes à l'identique.
Le moteur les lit depuis un instantané par tenant rafraîchi sur minuterie — même
réponse que l'index d'indicateurs, et pour la même raison : un seul consommateur
traite les événements de tous les tenants.

**En le vérifiant, il s'est avéré que le moteur n'avait jamais tourné.**
`ueba_profiles` et `ueba_anomalies` étaient vides sur une plateforme qui avait
ingéré des milliers d'événements. `entityFrom` ne résolvait une entité que depuis
`user_id` et `asset_id`, et une ligne de log porte un nom d'utilisateur — les
parseurs remplissent `user_name` et laissent `user_id` vide. Chaque événement
était écarté une étape après son arrivée. Aucune ligne de base n'avait jamais été
construite, et des seuils paramétrables auraient été un bouton relié à rien.

L'identifiant est désormais **dérivé du nom** quand la source n'en donne pas :
même nom, même tenant, même UUID, sur toutes les répliques et après chaque
redémarrage, sans aucune lecture sur le chemin chaud. Scopé par tenant — l'« admin »
d'un client n'est jamais celui d'un autre — et en minuscules, parce qu'une source
qui écrit M.Durand le lundi et m.durand le mardi décrit une personne.

```
avant              0 profil,   0 anomalie
après             12 profils,  4 anomalies   (balanced, 5 échecs)
privileged_watch  12 profils,  8 anomalies   (3 échecs)
```

Désactiver **tous** les signaux est refusé avec la raison : c'est légitime une
après-midi et alarmant à demeure, donc cela doit être une décision qu'on défend,
pas une qu'on atteint en décochant huit cases.

**Les trois écrans.** Réglages porte maintenant l'appétit au risque, les délais
et les seuils, dans une seule forme : ce qui est en vigueur, si le client l'a
choisi, le standard d'origine, ce qu'il a déplacé, pourquoi, et ce que c'était
tel jour.

**Reste** : les pondérations des chemins d'attaque sont le dernier de ces
jugements encore tenu en constante.

### Le score de risque d'un actif

`assets.vuln_critical`, `vuln_high`, `vuln_medium` et `vuln_low` étaient lues
par le calcul de score et **écrites par personne** — aucun des trente-trois
modules ne les affectait. Tout un terme de la formule était donc mort : un parc
de neuf actifs critiques portant dix CVE activement exploitées répondait
`high_risk: 0`, et le score de chaque actif ne reflétait que sa criticité
déclarée et ses drapeaux. Le nombre avait l'air réfléchi. C'était de
l'arithmétique sur des zéros.

Un cache que personne ne rafraîchit est pire que pas de cache : il est faux
d'une manière qui se lit comme une autorité. Les colonnes ont donc disparu, et
deux vues les remplacent, en deux couches pour que la couture suive la
propriété :

- `asset_vulnerability_summary` **appartient au domaine vulnérabilité** : c'est
  ce qu'il publie d'un actif, les constats ouverts par sévérité. Un constat
  résolu ne compte plus — sinon un actif ne pourrait jamais s'améliorer en se
  faisant corriger.
- `asset_risk` **appartient au domaine actif** : la table plus ces compteurs
  plus le score. Le service d'actifs lit cette vue et ne touche jamais aux
  tables de vulnérabilité.

La formule existe donc deux fois — en Go, où elle s'explique (`/assets/{id}/risk`
détaille chaque terme), et en SQL, pour qu'on puisse trier et compter cent
mille actifs dans la base plutôt qu'en mémoire. C'est un coût, payé contre un
test d'intégration qui fait tourner les deux sur les mêmes lignes et échoue à
la première divergence : quatorze cas, dont chaque plafond atteint puis
dépassé, parce qu'un plafond appliqué d'un seul côté est d'accord sur tous les
actifs ordinaires et diverge exactement sur ceux qui comptent.

### Remplir la plateforme pour une démonstration

Une plateforme vide ne s'évalue pas : chaque page affiche zéro et rien ne dit
si le produit fonctionne ou s'il se contente de démarrer.

```bash
cd backend
./scripts/dev-local.sh demo          # ou : make demo
./scripts/dev-local.sh demo -summary # ne crée rien, compte ce qui est là
```

`internal/cmd/demoseed` écrit une banque de taille moyenne — quatorze actifs
(canal en ligne, cœur bancaire, passerelle SWIFT, réseau monétique), dix CVE
réelles et leurs constats, onze indicateurs rattachés à trois acteurs, huit
règles adoptées depuis la bibliothèque de détection, cinq incidents, un graphe d'attaque de seize nœuds avec
trois scénarios analysés, quatre référentiels de conformité et leurs contrôles,
un graphe de connaissance.

**Tout passe par l'API de la plateforme**, sous une identité réelle et avec les
permissions que ses rôles accordent vraiment. Des `INSERT` directs auraient
sauté la validation, l'autorisation, le cloisonnement par tenant, les instantanés
que le tableau de bord lit et le graphe que l'analyse de chemins parcourt — la
démonstration aurait montré des lignes, pas un produit. Écrire à travers les
mêmes portes a d'ailleurs révélé trois défauts qu'aucun test ne voyait : un actif
créé sans champ facultatif partait en 500, la moitié des erreurs 500 ne
laissaient aucune trace, et trois des dix outils du Copilot appelaient une route
qui n'existait pas.

Deux choses ne se créent pas par API, et c'est voulu :

- **Les alertes SIEM.** Une alerte est ce que le moteur a conclu, pas ce qu'un
  client affirme. Le jeu envoie donc les **événements** qu'un connecteur
  enverrait, et les alertes à l'écran sont celles que cette plateforme a
  décidé de lever.
- **L'ingestion**, réservée aux comptes de service : le jeton d'un analyste ne
  doit pas pouvoir injecter dans la chaîne de détection. Le connecteur de
  démonstration est donc enrôlé comme un vrai — compte de service, secret
  montré une fois, échange de justificatifs — et garde son secret dans
  `.dev-local/demo-connector.json`.

Relancer la commande ne duplique rien : chaque étape liste ce qu'elle s'apprête
à créer et laisse en place ce qui existe.

### Se connecter à l'interface

L'interface s'authentifie auprès de Keycloak ; les services **valident
eux-mêmes** ce jeton contre les clés publiées du realm (`internal/pkg/oidc`),
puis résolvent le tenant, les rôles et les permissions dans les tables de la
plateforme (`internal/pkg/rbac`). Autrement dit : **Keycloak dit qui vous êtes,
la matrice RBAC dit ce que vous pouvez.**

Les deux vocabulaires de rôles ne sont pas les mêmes — le realm livre `dpo`,
`risk_manager`, `platform_admin`, la plateforme a `tenant_admin`,
`threat_hunter`, `super_admin` — et les faire correspondre reviendrait à en
maintenir deux. Conséquence directe : **une personne que l'annuaire connaît et
que la plateforme ignore reçoit un 403 explicite**, pas un 401 ni une interface
vide. C'est la bonne réponse : un compte ajouté à un annuaire d'entreprise n'est
pas un compte sur la plateforme de sécurité d'une banque. `dev-local.sh seed`
crée les identités correspondant aux utilisateurs du realm.

Trois pièges rencontrés en la faisant tourner pour la première fois :

- **Aucun CORS n'existait.** L'interface est sur une origine, chaque service sur
  son port : le navigateur bloquait tout, chaque panneau affichait « Failed to
  fetch », et aucun journal ne disait rien — la requête n'arrivait jamais. Le
  préflight doit en plus être traité **avant** l'authentification, sinon le
  `OPTIONS`, que le navigateur envoie sans identifiants, repart en 401.
- **`AUTH_TRUST_HOST` doit être dans l'environnement du processus**, pas
  seulement dans `.env.local` : Auth.js fait le contrôle dans le middleware Edge
  de Next, où une valeur de `.env.local` ne parvient pas. Sans lui, la connexion
  échoue en 500 disant seulement « a problem with the server configuration ».
- **SWR ne doit pas partir sans jeton.** La clé vaut `null` tant que la session
  n'a pas résolu ; sinon le premier rendu part sans en-tête, le service répond
  401, et SWR garde cet échec sous une clé qui ne change pas quand le jeton
  arrive — le panneau reste cassé toute la session pendant que le même appel
  depuis une console renvoie 200.

### Secrets

`internal/pkg/vault` lit Vault quand il est configuré, l'environnement sinon.
Un échec de lecture Vault est signalé **même quand le repli réussit** : un
service qui tourne discrètement sur l'environnement alors qu'on le croit sur
Vault est exactement la mauvaise configuration à rendre visible.

### Tests

```bash
cd backend/services/<service> && go test ./...
```

Les tests qui ont besoin d'une vraie dépendance **sautent** quand elle est
injoignable, ce qui garde la suite utilisable sur un portable. Mais un saut est
indiscernable d'un succès dans la sortie de CI : chacun lit une variable
d'environnement qui transforme le saut en échec, et la CI les pose toutes —
`REDIS_TEST_URL`, `PAM_TEST_DSN`, `COPILOT_TEST_DSN`, `IR_TEST_DSN`,
`IDENTITY_TEST_DSN`, `DASHBOARD_TEST_CH`, `ATTACKPATH_TEST_DSN`,
`ATTACKPATH_TEST_NEO4J`, `KG_TEST_DSN`, `KG_TEST_NEO4J`, `RBAC_TEST_DSN`. Si vous ajoutez un test qui parle à une base, suivez ce
motif plutôt que de le faire sauter en silence.

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
| `COUNT()` ClickHouse est un `UInt64` | Le driver ne le réduit pas en `int` : scanner dans un `uint64` puis convertir. |
| Un consommateur Kafka doit surveiller son topic | Démarré avant que le topic existe, il reste bloqué sans erreur. `WatchPartitionChanges: true`. |
| Le statut d'une alerte est dans PostgreSQL | ClickHouse détient les alertes, `alert_metadata` leur statut. Compter les ouvertes exige les deux. |
| Paramètres nommés ClickHouse | Liés sous forme textuelle : un `uuid.UUID` ou un `time.Time` est rejeté. Utiliser `.String()` et `db.CHTime`. |
| Migrations ClickHouse | `TTL` exige `Date`/`DateTime`, pas `DateTime64` ; une clé de tri MergeTree n'accepte pas `DESC`. Six des sept migrations échouaient pour ces deux raisons. |
| `asset.criticality` est un entier | 1 faible … 4 critique. `Criticality` est un `int` Go sans `MarshalJSON`. |
| Les sévérités du SIEM sont en majuscules | `Enum8('LOW'…'CRITICAL')` côté ClickHouse ; les domaines Postgres écrivent en minuscules. |
| `super_admin` accorde tout par la matrice | Plus de court-circuit : le rôle détient les 82 permissions et la portée inter-tenant. Une permission ajoutée doit lui être accordée — un test le vérifie. |
| Neo4j n'est pas le maître du graphe | PostgreSQL l'est ; Neo4j en reçoit une copie. Basculer `ATTACKPATH_GRAPH_READS` seulement après `make graph-reconcile` en parité. |
| Les contraintes de relation sont Enterprise | Sur Community, l'unicité d'une arête tient par `MERGE` sur sa clé naturelle — donc aucune autre écriture ne doit créer de relation. |
| Le pilote Neo4j réessaie 30 s par défaut | Sur le chemin d'une requête, cela fait 30 s par écriture quand le miroir est tombé. `MaxTransactionRetryTime` et un contexte borné. |
| Une colonne annulable ne se lit pas dans un `int` | `last_run_ms` rendait 500 toute lecture de scénario avant sa première exécution. `COALESCE(col, 0)` à la lecture. |
| Trente services ne tiennent pas dans 100 connexions | `max_connections=400` côté serveur, `DB_MAX_CONNS` / `DB_MIN_CONNS` côté service. Sinon la plateforme ne démarre pas. |
| Le préflight CORS passe avant l'authentification | Un `OPTIONS` est envoyé sans identifiants : s'il atteint le middleware JWT, il repart en 401 et le navigateur bloque la vraie requête. |
| Keycloak authentifie, la plateforme autorise | Les rôles du realm ne sont pas ceux de la matrice. Une personne sans identité ici reçoit 403, pas 401. |
| `AUTH_TRUST_HOST` doit être exporté | Le contrôle a lieu dans le middleware Edge, que `.env.local` n'atteint pas. |
| Une clé SWR ne doit pas exister sans jeton | Sinon le premier rendu met un 401 en cache sous une clé qui ne changera plus. |
| Cypher ne paramètre pas un type de relation | Table fixe indexée par les constantes du modèle, type inconnu refusé avant toute construction de requête. |
| Une suppression doit atteindre le miroir | Une relation supprimée mais laissée dans Neo4j est parcourue : elle affirme quelque chose de faux, ce qui est pire qu'une absence. |
| `direction=both` du knowledge graph était du SQL invalide | Le CTE récursif référençait le terme récursif depuis une branche d'amorce. C'était la valeur par défaut du handler et la seule direction d'`Enrich`. |
| Un miroir Neo4j s'écrit par lots | Une instruction par ligne : 5 min pour backfiller 20 000 nœuds et 137 000 arêtes, contre 18 s par lots de mille. |
| Un `MATCH` Cypher part d'un index, pas d'un `WHERE id IN` | `MATCH (a:X {tenant_id:$t}) WHERE a.id IN $ids` balaie le tenant entier. `UNWIND $ids` puis `MATCH (a:X {tenant_id:$t, id:id})` utilise la contrainte. |
| Les motifs de longueur variable excluent une arête répétée, pas un nœud | Sans test d'unicité explicite, une route repassant par le même hôte est comptée comme une seconde attaque. |
| Les sauts ne sont pas de l'effort | `shortest_path` est le nombre de sauts ; `cheapest_path_cost` est le poids accumulé — c'est lui qui dit ce que l'attaque la plus facile coûte réellement. |

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
- **Neo4j est un miroir, pas la source de vérité.** Attack Path et Knowledge
  Graph y écrivent en double ; PostgreSQL reste la référence et les lectures n'y
  passent que si `ATTACKPATH_GRAPH_READS` / `KG_GRAPH_READS` valent `neo4j`. Un
  échec du miroir ne fait pas échouer l'écriture — il est compté — donc les deux
  magasins peuvent diverger : `make graph-reconcile` et `make kg-reconcile`
  disent en quoi, et sortent en code non nul si c'est le cas. Ne basculez les
  lectures qu'après un rapport en parité. Voir §3.5 et §3.9 de l'audit.
- **Les compteurs de détection ont besoin d'un Redis en `noeviction`.** Le Redis
  de développement est en `allkeys-lru`, qui peut évincer une clé de comptage
  sous pression mémoire — donc perdre un seuil sans bruit.
- **Les pondérations de `risk_score` ne sont pas calibrées.** Chaque domaine en
  dérive une de ce qu'il compte, formule écrite en clair dans son `kpi.go`. À
  faire valider par la fonction risque avant de présenter le score de sécurité
  comme une mesure.
- **La page Réglages ne peut rien écrire.** Aucun endpoint de réglages du tenant
  n'existe ; elle liste les utilisateurs réels et dit ce qui se configure
  ailleurs.
- **Le rôle `super_admin` n'accorde aucune permission.** Seul
  `identities.privilege_level = 'super_admin'` ouvre le contournement. Les deux
  notions devraient être unifiées.
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
