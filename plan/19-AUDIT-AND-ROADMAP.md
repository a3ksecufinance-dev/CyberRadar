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
| **Le SOAR ne remédie rien** | `soar/internal/service/executor.go:108-196` | L'orchestration (séquençage, abort-on-failure, timeouts, persistance) est réelle et bien construite, mais `block_ip`, `disable_user`, `isolate_host`, `add_to_blocklist` retournent des maps figées. Commentaire ligne 106 l'admet. |
| **Compteurs en mémoire intra-processus** | `siem/engine.go:194-221`, `pam/risk.go`, `ueba/engine.go:44-49` | Seuils, vélocité et brute-force perdus au redémarrage et non partagés entre réplicas. `internal/pkg/cache` (Redis) existe et n'est pas utilisé ici. Bloque la scalabilité horizontale. |
| **Kafka sans DLQ ni backoff** | `internal/pkg/kafka/consumer.go` | `event.TopicDLQ` et `DLQMessage` sont définis dans `schema.go`, **rien ne publie dedans**. Une erreur de handler provoque soit un retry infini, soit un drop silencieux. Perte de données inacceptable pour un SIEM (valeur probatoire). |
| Neo4j absent | — | Attack Path (D8) et Knowledge Graph (D9) tournent sur PostgreSQL. Les traversées multi-sauts et le plus court chemin d'attaque sont impraticables en SQL relationnel. |
| pgvector / Qdrant absent | — | Copilot sans RAG sémantique |
| Enrichissement pipeline | `pipeline/enricher/threat.go:38,104`, `geo.go:37` | GeoIP et matching IOC : stubs TODO |
| Envoi d'e-mail | `notification/internal/service/notification.go:138-145` | Stub, aucun SMTP |
| Agrégation stats tenant | `tenant/internal/handler/tenant.go:179` | TODO |
| **7 pages frontend en données figées** | `ot`, `risk`, `ir`, `scs`, `attackpath`, `compliance`, `settings` | Tableaux `mockRisks`, `mockIncidents`… définis dans le fichier de page, sans état loading/error. `useOT.ts` existe intégralement mais `ot/page.tsx` ne l'importe jamais. |
| **Aucun graphique** | `recharts` déclaré, jamais importé | `useKPITimeseries` existe, aucune page ne l'utilise. Produit de dashboards sans visualisation. |
| **Zéro test, zéro CI/CD** | — | Aucun filet de sécurité sur 32 services. Une CI exécutant `go build`, `tsc --noEmit` et `next build` aurait intercepté les défauts 2.7 et 2.8 au premier commit. |

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
  appelants autonomes — les actions SOAR réelles, sans utilisateur derrière — auront besoin d'une
  identité de service propre ; elle sera introduite avec ces actions en Phase 2, pas avant d'avoir un
  consommateur.
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

  **Seule exception : `collector`.** Ses deux routes (`POST /events/ingest`, `/events/heartbeat`)
  sont des appels machine sans utilisateur derrière. Idem pour `POST /audit/events`, laissée
  ouverte au sein d'un `audit` par ailleurs protégé. Les deux attendent l'identité de service
  prévue en Phase 2 ; elles restent couvertes par `RequireJWT`.

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

- **SOAR réel** : les actions appellent les services de remédiation (possible grâce à 0.2).
  C'est le différenciateur produit le plus important qui manque.
- **Neo4j** + migration des modèles `attackpath` et `knowledgegraph`. Plus la migration est tardive,
  plus la réécriture des couches repository/service coûte cher.
- **État partagé Redis** pour les compteurs SIEM/UEBA/PAM — prérequis à la scalabilité horizontale.
- **DLQ + backoff exponentiel** sur Kafka. Non négociable pour un SIEM.
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
