# 19 — Développement

## L'espace de travail

33 modules Go dans `backend/go.work` : `internal` (le socle partagé) et un par
service.

> **`go build ./...` ne construit pas la plateforme.** Il ne voit qu'un module.
> Les cibles du `Makefile` traversent l'espace de travail ; ce sont elles qu'il
> faut.

```bash
cd backend
make build       # 36 binaires → bin/
make vet
make test
make lint        # golangci-lint
make fmt         # gofmt sur tout
make fmt-check   # échoue si un fichier n'est pas formaté
make tidy
```

---

## Les couches d'un service

```
cmd/server/main.go        câblage : env, pools, routeur, arrêt propre
internal/handler/         HTTP : décoder, appeler, encoder, traduire l'erreur
internal/service/         la logique du domaine, sans SQL ni HTTP
internal/repository/      SQL, et rien d'autre
internal/model/           les types, et les règles qui ne dépendent de rien
```

### Les règles qui tiennent l'ensemble

**Une erreur traverse les couches comme une valeur typée, pas comme un code
HTTP.** Le code métier renvoie `apierrors.NotFound(...)` ; `httperr` traduit,
une seule fois, au bord. Voir [06 — API](06-api.md).

**`KindInternal` est l'absence de jugement.** Si le service ne sait pas
classer, il laisse passer : le pilote PostgreSQL en dessous sait souvent, et sa
réponse est plus honnête qu'un 500.

**Le tenant vient du contexte, jamais de la requête.**

```go
tenantID := authctx.TenantID(r.Context())
```

**Toute liste répond avec `OKWithMeta`**, pour que `total` soit toujours là.

---

## Ajouter une route

1. L'écrire dans `internal/handler/`, avec sa permission :
   ```go
   r.With(authmw.RequirePermission("x:write")).Post("/x/{id}/do", h.Do)
   ```
2. Si la permission est nouvelle, l'ajouter au catalogue (une migration).
3. Si l'interface l'appelle, l'ajouter à `frontend/src/lib/api.ts` — c'est de
   là que les sondes du back-end tirent leur liste.
4. Régénérer la référence :
   ```bash
   make docs-api
   ```
   **La CI échoue si vous l'oubliez.**

---

## Ajouter un service

1. Le module dans `backend/go.work`.
2. L'arborescence `cmd/server` + `internal/{handler,service,repository,model}`.
3. Le câblage de `main.go`, copié sur un service voisin : CORS, `observe`,
   RequestID, RealIP, Recoverer, Timeout 30 s, `/health`, puis `/api/v1` avec
   `RequireJWT` et `RequirePermissionByMethod`.
4. Le port, **aux trois endroits** : `scripts/dev-local.sh`,
   `deployments/docker-compose.yml`, `frontend/src/lib/api.ts`.
   `internal/pkg/deploycheck` vérifie que les deux premiers s'accordent.
5. La migration du schéma.
6. Une sonde dans `internal/pkg/apicheck` — **le test de couverture échoue
   sans elle**.

---

## Les tests

```bash
make test                               # tout
go test ./services/siem/... -v          # un service
go test ./internal/pkg/content/ -run TestASignedPackRoundTrips
```

### Les trois sortes

| | Ce que ça couvre |
|---|---|
| **Unitaires** | Les parsers syslog, le moteur SIEM, les calculs de politique, le contenu signé |
| **`internal/pkg/apicheck`** | **Toutes** les lectures de **tous** les services, contre une plateforme qui tourne |
| **Playwright** | Les parcours d'interface |

`apicheck` exige une plateforme démarrée ; il échoue autrement en nommant les
services qui n'écoutent pas. C'est voulu : il attrape une classe de défaut
qu'aucune compilation ne voit.

### Ce qui est le plus couvert

Les parsers syslog et le moteur SIEM. C'est délibéré : ce sont les chemins où
une erreur est silencieuse — un message mal analysé n'échoue pas, il produit un
événement faux.

### Prouver qu'un test a des dents

La discipline suivie dans tout ce dépôt : après avoir écrit un test, **casser
le code exprès** et vérifier qu'il échoue — et qu'il échoue **pour la bonne
raison**.

> Un test de contenu altéré affirmait la présence de `"yaml"` dans l'erreur.
> Il passait… parce que le *nom de fichier* contenait `.yaml`, pas parce qu'un
> analyseur avait protesté. Un test vert qui ne teste rien est pire qu'aucun.

> Et plus tard : supprimer la comparaison d'empreinte entre l'index et le
> paquet laissait la vérification de *numéro* attraper le cas. Le test
> échouait, donc la mutation était « rattrapée » — mais pas par le garde-fou
> qu'elle visait. Un test a été ajouté pour le cas que seule l'empreinte
> attrape.

> **Ne jamais restaurer un fichier avec `git checkout` pour défaire une
> mutation.** Cela emporte tout le travail non commité. Travailler sur une
> copie.

---

## La CI

| Job | Ce qu'il fait |
|---|---|
| **Backend** | Format, build, vet, migrations PostgreSQL + ClickHouse, **publication et installation d'une livraison de contenu signée**, quatre refus asservis à leur motif, tests |
| **Migrations** | Applique toutes les migrations à une base vierge et rapporte le schéma |
| **Frontend** | `type-check`, `lint`, **`check:messages`**, `build` |
| **Vulnérabilités** | `govulncheck`, `npm audit` |

Le job backend passe par **la chaîne publiée complète** — construire, signer,
publier dans un canal, installer ce que le canal dit courant — et non par le
répertoire de travail. Une chaîne qui ne chargerait jamais que le répertoire
n'exercerait jamais ce que fait un déploiement.

Les quatre refus sont affirmés **avec leur motif**, pas seulement leur code de
sortie : un refus pour la mauvaise raison est la façon dont un contrôle qui ne
s'exécute jamais passe.

---

## La documentation générée

```bash
make docs-api            # régénère docs/07-reference-api.md
```

La CI échoue si le fichier commité diffère de ce que dit le code. Une liste de
routes tenue à la main est une liste fausse, et fausse en silence : le lecteur
l'apprend quand son appel répond 404.

---

## Conventions de code

### Les commentaires disent pourquoi, pas quoi

```go
// Ordered by path and marshalled with Go's encoder, so the same pack produces
// the same bytes and therefore the same signature on any machine. A manifest
// whose serialisation varied would make two builds of one pack unverifiable
// against each other.
```

Et quand un défaut a motivé le code, il est écrit :

```go
// It exists as one implementation rather than a copy per service because the
// copies drifted: only one of the thirty verified the token's signing
// algorithm, and each repeated the claims struct it parsed into.
```

### Les messages d'erreur nomment ce qui ne va pas

```
permission required: rules:write
2026.11.0 is already published with digest 3878… and this pack is 1c81…
"6956066-oops" is not a key identifier (32 hex characters)
```

Pas « invalid input ». Ce que l'exploitant doit faire doit se lire dans le
message.

### Les messages de commit

Objet à l'impératif, qui dit le changement et non le fichier. Corps qui dit le
**pourquoi**, les décisions prises et les mauvaises réponses écartées.

```
feat(siem): a channel says which release is current, and a key can be withdrawn
```

### Le frontend

- Les types de `src/types` suivent les modèles Go, pas ce que l'interface
  espère.
- Toute clé de traduction littérale doit se résoudre dans les deux locales :
  `npm run check:messages`, en CI.
- Trois états de page partagés : `LoadingState`, `EmptyState`, `ErrorState`.
  Zéro résultat et une erreur ne se ressemblent pas.

---

## Le flux de travail

```bash
git checkout -b <branche>
# …
cd backend && make fmt && make vet && make test
make docs-api                       # si une route a bougé
cd ../frontend && npm run type-check && npm run lint && npm run check:messages
git commit
```

Pour exercer réellement un changement :

```bash
./scripts/dev-local.sh up
./scripts/dev-local.sh demo
./scripts/dev-local.sh smoke
```

**Exécuter trouve ce que lire ne trouve pas.** Dans ce dépôt : une majoration
KEV qui n'avait jamais été appliquée, un moteur UEBA qui n'avait jamais traité
un événement, des chemins d'attaque accumulés sur 19 exécutions, cinq en-têtes
affichant leur clé de traduction, et deux défauts dans un écran fraîchement
écrit — trouvés en le pilotant, pas en le relisant.
