# 03 — Installation

Deux chemins, qui mènent au même état : les mêmes binaires, les mêmes schémas,
les mêmes ports.

| Chemin | Quand |
|---|---|
| **Docker Compose** | Le cas normal. Un `make dev` et tout tourne. |
| **`scripts/dev-local.sh`** | Quand Docker n'est pas disponible ou que les images ne peuvent pas être téléchargées : réseau fermé, poste isolé, exécuteur de CI sans démon. |

---

## Prérequis

| | Version | Pourquoi |
|---|---|---|
| Go | 1.26+ | L'espace de travail `go.work` l'exige. La version est un minimum de sécurité et non de confort : les correctifs de `net/url`, `crypto/tls` et `crypto/x509` que `govulncheck` exige n'existent qu'à partir de 1.25, et `golang.org/x/crypto` 0.56 — la version qui corrige GO-2026-6355 et GO-2026-6354 — déclare `go 1.26` |
| Node | 20+ | Next.js 14 |
| `psql` | 14+ | L’amorçage des identités et l’inspection de la base ; le schéma PostgreSQL passe par `internal/cmd/migrate` |
| `openssl` | — | Génère la paire RSA des jetons |
| Docker + Compose | 24+ | Chemin Compose uniquement |

Pour le chemin local, il faut en plus PostgreSQL 16 avec `pgvector`, Redis,
ClickHouse, Kafka et Keycloak installés sur la machine. Le script les démarre
mais ne les installe pas, et dit lequel manque.

---

## Chemin 1 — Docker Compose

```bash
cd backend
make dev
```

`make dev` enchaîne : génération de la paire de clés JWT, démarrage de
l'infrastructure, migrations, amorçage des identités, puis les services.

Ensuite, séparément :

```bash
make content   # charge le catalogue de détection — voir plus bas
make demo      # remplit le tenant d'un parc de démonstration
make smoke     # lit toutes les listes de tous les services, échoue sur tout 5xx
```

Arrêt : `make down`.

---

## Chemin 2 — Installation locale, sans Docker

```bash
cd backend
./scripts/dev-local.sh up
```

Le script ne détruit jamais ce qu'il n'a pas démarré : il écrit les
identifiants de processus dans `backend/.dev-local/pids` et ne tue que
ceux-là. Un PostgreSQL déjà présent sur la machine n'est pas emporté par un
`down`.

### Les étapes, séparément

```bash
./scripts/dev-local.sh infra      # PostgreSQL, Redis, ClickHouse, Kafka, Keycloak
./scripts/dev-local.sh migrate    # PostgreSQL + ClickHouse ; rejouable
./scripts/dev-local.sh content    # le catalogue de détection
./scripts/dev-local.sh seed       # les identités, sans quoi personne ne peut se connecter
./scripts/dev-local.sh build      # 36 binaires
./scripts/dev-local.sh services   # les 30 services
./scripts/dev-local.sh frontend   # l'interface sur :3000
```

### Les migrations

PostgreSQL passe par une table de version (`schema_migrations`) : chaque
fichier s'applique une fois, et une nouvelle migration s'applique par-dessus
une installation en service. C'est ce qui rend l'étape rejouable.

```bash
make migrate          # applique ce qui ne l'est pas encore
make migrate-status   # la version où la base se trouve
```

Un deuxième `make migrate` n'applique rien :

```
applied 0 → 49
already at 49, nothing to apply
```

Il n'y a pas de migration descendante, par décision : la plupart de ces
fichiers créent une table et l'essentiel du reste élargit une colonne.
L'inverse de « la colonne contient désormais les données du client » n'est pas
un `DROP`, c'est une restauration. `migrate down` est donc refusé, avec cette
raison, plutôt que de faire quelque chose de destructeur sans le dire.

#### Une installation antérieure à la table de version

Les installations mises en place avant cette table ont le schéma et rien qui
l'enregistre : `migrate` échouerait sur le premier `CREATE TABLE`. La version
s'adopte une fois pour toutes :

```bash
make migrate-baseline               # adopted the existing schema at version 49
make migrate                        # already at 49, nothing to apply
./scripts/dev-local.sh migrate-baseline   # le même, par le lanceur local
```

`migrate up` ne touche à rien dans cet état : il refuse d'emblée, en nommant
`baseline`. C'est voulu, et c'est le défaut que l'exécution a trouvé — une
tentative d'application sur un schéma déjà posé échoue sur le premier index
existant *et* inscrit une version 1 « sale », après quoi `up` refuse (sale) et
`baseline` refuse (il y a une version) : l'installation est bloquée par la
première commande qu'un exploitant aurait tapée. Le contrôle est donc fait
avant d'appliquer quoi que ce soit.

`migrate baseline` refuse une base vide (c'est `up` qu'il faut) et une base qui
porte déjà une version (il n'y a rien à adopter).

ClickHouse et Neo4j restent appliqués par une boucle : chaque instruction de
ces fichiers est un `CREATE … IF NOT EXISTS`, ils sont rejouables tels quels.

### Et pour l'exploiter

```bash
./scripts/dev-local.sh status            # qui écoute, qui est en bonne santé
./scripts/dev-local.sh logs siem-service # suivre un journal
./scripts/dev-local.sh restart siem-service
./scripts/dev-local.sh demo              # le parc de démonstration
./scripts/dev-local.sh smoke             # toutes les lectures
./scripts/dev-local.sh e2e               # pilote l'interface dans un navigateur
./scripts/dev-local.sh reset             # repart d'une base vide
./scripts/dev-local.sh down
```

**`services` ne démarre que ce qui ne tourne pas.** Pour reprendre en compte un
binaire reconstruit, c'est `restart` qu'il faut, pas `services` — sinon le
processus d'avant continue de répondre et les contrôles de santé passent
contre lui.

### Où le script met ses affaires

```
backend/.dev-local/
  logs/     un fichier par service
  pids/     un identifiant de processus par service
  data/     les répertoires de données de l'infrastructure
```

`CRP_STATE_DIR` déplace l'ensemble.

### Neo4j

Facultatif, et désactivé par défaut. Sans `CRP_NEO4J_HOME`, le script le passe
en le disant, et les deux graphes sont lus depuis PostgreSQL — ce qui est de
toute façon le réglage par défaut.

---

## Après l'installation

| | Adresse | Identifiants |
|---|---|---|
| Interface | http://localhost:3000 | `admin@cyberradar.io` / `Admin@CyberRadar2025!` |
| Keycloak | http://localhost:8080 | `admin` / `Admin@CyberRadar2025!` |
| Jaeger | http://localhost:16686 | — |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3001 | — |

Le royaume `cyberradar` est importé avec sept comptes, un par rôle, pour
pouvoir vérifier ce que chacun voit :

| Compte | Rôle |
|---|---|
| `admin@cyberradar.io` | `platform_admin`, `ciso` |
| `ciso@bnf.fr` | `ciso` |
| `soc-l1@bnf.fr` | `soc_analyst_l1` |
| `soc-l2@bnf.fr` | `soc_analyst_l2` |
| `risk@bnf.fr` | `risk_manager` |
| `dpo@bnf.fr` | `dpo` |
| `auditor@bnf.fr` | `auditor` |

Tous avec le même mot de passe de développement, `Admin@CyberRadar2025!`.

> **`seed` n'est pas optionnel.** Keycloak authentifie une personne ; la
> plateforme doit ensuite savoir *qui* elle est et *ce qu'elle peut*. Sans
> l'amorçage, une connexion réussit auprès de Keycloak et chaque appel d'API
> répond 403.

---

## Le catalogue de détection

Il n'est **pas** dans les migrations : il se livre à sa propre cadence. Une
base fraîchement migrée n'a aucune détection tant que le chargeur n'a pas
tourné.

```bash
make content          # charge depuis backend/content/detections
make content-check    # valide sans toucher à une base de données
```

Pour une installation réelle, le catalogue vient d'une livraison signée et non
d'un répertoire — voir
[`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md).

---

## Le jeu de démonstration

```bash
make demo      # ou ./scripts/dev-local.sh demo
```

Il remplit le tenant à travers **les API réelles de la plateforme**, pas par
des `INSERT`. Ce qui veut dire qu'il exerce la validation, les permissions et
les enchaînements au passage : un parc qui s'injecte est un parc dont les
chemins d'écriture fonctionnent.

> **Une limite connue.** Les événements sont injectés en rafale. Les lignes de
> base UEBA ont besoin d'activité **étalée dans le temps** pour se former, donc
> les détections qui en dépendent ne se déclenchent pas sur le jeu de
> démonstration. Ce n'est pas un défaut du moteur : c'est ce que le jeu de
> données ne contient pas.

---

## Vérifier que l'installation est bonne

```bash
make api-health    # les 30 /health
make smoke         # toutes les listes, échec sur tout 5xx
make test          # la suite complète
```

`smoke` est celui qui compte : il lit **toutes** les listes de **tous** les
services contre la plateforme qui tourne. C'est ce qui attrape la classe de
défaut qu'aucune compilation ne voit — une colonne nullable lue dans une chaîne
Go, qui compile, passe la revue, et répond 500 la première fois que la colonne
est vide.

---

## Problèmes courants

| Symptôme | Cause | Remède |
|---|---|---|
| `already carries the schema but has no migration version` | Installation antérieure à la table de version | `make migrate-baseline`, puis `make migrate` |
| Connexion acceptée, puis 403 partout | L'amorçage des identités n'a pas tourné | `make seed` |
| Un service répond l'ancien comportement après rebuild | `services` ne démarre que ce qui ne tourne pas | `./scripts/dev-local.sh restart <service>` |
| `copilot-service skipped` | Pas de clé API | `export ANTHROPIC_API_KEY=…` |
| `address already in use` mais `/health` répond | Un processus d'avant détient le port | `readlink /proc/<pid>/exe` montre `(deleted)` ; `kill -9` |
| Le catalogue est vide | Le contenu n'est plus dans les migrations | `make content` |
