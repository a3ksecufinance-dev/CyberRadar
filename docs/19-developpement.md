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
5. La migration du schéma : `migrations/postgres/0000NN_ce_qu_elle_fait.up.sql`,
   le numéro suivant celui du dernier fichier. Le suffixe `.up.sql` n'est pas
   décoratif — c'est ce que `golang-migrate` lit, un fichier nommé autrement
   ne s'applique pas. Il n'y a pas de `.down.sql` : voir plus bas.
6. Une sonde dans `internal/pkg/apicheck` — **le test de couverture échoue
   sans elle**.

---

## Les tests

```bash
make test                               # tout
go test ./services/siem/... -v          # un service
go test ./internal/pkg/content/ -run TestASignedPackRoundTrips
```

### Les quatre sortes

| | Ce que ça couvre |
|---|---|
| **Unitaires** | Les parsers syslog, le moteur SIEM, les calculs de politique, le contenu signé |
| **De dépôt** | Le SQL, contre une vraie base — via `internal/pkg/testinfra` |
| **`internal/pkg/apicheck`** | **Toutes** les lectures de **tous** les services, contre une plateforme qui tourne |
| **Playwright** | Les parcours d'interface |

### Tester le SQL : `internal/pkg/testinfra`

Dans un service construit en handler → service → dépôt, le code facile à rater
est le SQL. Il n'y avait aucun moyen d'en exécuter dans un test, donc personne
n'en écrivait, et la classe de défaut que seul le SQL produit — une colonne
nullable lue dans une chaîne Go — est passée deux fois.

```go
func TestSomething(t *testing.T) {
    pool := testinfra.Postgres(t)      // base migrée, à ce test seul
    conn := testinfra.ClickHouse(t)    // schéma migré
    k    := testinfra.Kafka(t)         // courtiers + un sujet à ce test seul
}
```

**Chaque appel à `Postgres` rend une base à lui.** Elle est taillée dans un
gabarit migré une seule fois, par `CREATE DATABASE … TEMPLATE`, que PostgreSQL
fait en copie de fichiers : le schéma complet arrive en moins de temps qu'une
migration n'en met à être analysée. Deux tests ne se voient donc jamais, et
aucun n'a à nettoyer derrière lui.

**Le gabarit porte l'empreinte des migrations qui l'ont produit.** Si un
fichier de `migrations/postgres/` bouge, l'empreinte change et le gabarit est
reconstruit. Sans ça, un gabarit d'avant la migration 000048 servirait à chaque
test un schéma avec cinq tables qui n'existent plus.

#### D'où vient l'infrastructure

Dans cet ordre :

1. **Une instance déjà là**, nommée par `CRP_TEST_POSTGRES_DSN`,
   `CRP_TEST_CLICKHOUSE_DSN`, `CRP_TEST_KAFKA_BROKERS`. C'est ce qu'utilise la
   CI (ses conteneurs de service) et ce qu'a tout développeur ayant lancé
   `scripts/dev-local.sh infra`.
2. **Un conteneur démarré à la demande**, si un démon Docker répond.
3. **Ni l'un ni l'autre** : le test est **ignoré**, avec un message nommant les
   trois sorties.

> **Pourquoi la réutilisation passe avant les conteneurs.** `go test ./...`
> lance un processus par paquet. Un assistant qui démarrerait toujours des
> conteneurs en démarrerait un jeu par paquet — une trentaine dans cet espace
> de travail — et la suite durerait plus longtemps que personne n'attend.

#### Un test ignoré ne doit pas passer pour un test vert

```
CRP_TEST_REQUIRE_INFRA=postgres,clickhouse   # échoue au lieu d'ignorer
CRP_TEST_REQUIRE_INFRA=all
```

La liste est par dépendance parce qu'une chaîne exige exactement ce qu'elle
fournit. La nôtre déclare les trois — `postgres,clickhouse,kafka` — parce que
le travail `backend` démarre les trois. Un drapeau global ferait échouer un
test pour une omission de la chaîne et non pour un défaut ; une dépendance
omise de la liste alors qu'elle est fournie laisserait au contraire ses tests
passer au vert en étant ignorés.

Le travail `testinfra — the container path` ne déclare aucun service et exige
`all` : il démarre les trois lui-même, pour que la moitié conteneur du code ne
pourrisse pas sans que personne le voie.

`apicheck` exige une plateforme démarrée ; il échoue autrement en nommant les
services qui n'écoutent pas. C'est voulu : il attrape une classe de défaut
qu'aucune compilation ne voit.

### Ce qui est le plus couvert

| Module | Couverture | Ce qui est tenu |
|---|---|---|
| `services/collector` | **83 %** | Les six analyseurs de format, et le sujet sur lequel chaque message atterrit |
| `services/tenant` | **73 %** | La fusion partielle des politiques, les règles d'autorisation, la surface HTTP |
| `services/cspm` | **83 %** | Dépôt : la posture par compte, et le compte auquel on peut rattacher quelque chose |
| `services/iga` | **78 %** | Dépôt : la campagne de revue d'accès, les conflits de séparation des tâches |
| `services/dlp` | **77 %** | Dépôt : la violation, l'étiquette d'un actif, le scan qui note un actif |
| `services/netsec` | **75 %** | Dépôt : la politique entre deux zones, les flux, les adresses INET |
| `services/scs` | **73 %** | Dépôt : le SBOM, le dossier fournisseur, l'évaluation |
| `services/ot` | **71 %** | Dépôt : le score de risque d'un automate, les correctifs, les événements |
| Les neuf autres de B3 | 60 à 80 % | Dépôt : la même paire de questions pour chacun (voir plus bas) |
| `services/syslog` | — | Les analyseurs RFC 3164 / 5424 de l'écouteur TCP/UDP |
| `services/siem` | — | Le moteur de corrélation |

C'est délibéré : ce sont les chemins où une erreur est silencieuse. Un message
mal analysé n'échoue pas, il produit un événement faux ; une politique mal
fusionnée ne lève rien, elle déplace un chiffre ; une règle d'autorisation qui
ne s'applique pas n'a aucun effet visible tant que personne ne lit le tenant du
voisin.

Trois défauts ont été trouvés par ce travail de couverture, dans du code qui
compilait, passait `vet` et tournait :

1. **Les lettres mortes du collecteur partaient sur le sujet des événements.**
   `cmd/server` construisait un producteur dédié au sujet de rebut et ne le
   passait jamais au service, qui publiait donc ses `DLQMessage` sur
   `crp.events.normalized` — là où la chaîne de traitement lit des
   `NormalizedEvent`. `json.Unmarshal` accepte les champs inconnus, donc chaque
   ligne malformée devenait un événement sans identifiant, sans tenant et sans
   catégorie. Aucun test à producteur factice n'aurait pu le voir : ce qui est
   en cause est le sujet, pas l'appel.

2. **Tout événement syslog RFC 3164 était horodaté en l'an 0000.** Le format ne
   porte pas d'année et `time.Parse` en rend zéro ; l'année vient maintenant de
   l'heure de réception, avec le recul d'un an au passage du 31 décembre, comme
   le fait déjà l'écouteur du service `syslog`. Les deux analyseurs du même
   format s'accordent désormais.

3. **Les extensions CEF étaient découpées sur les espaces.** Une valeur CEF peut
   en contenir — `rt=Mar 14 2026 08:00:00` et `msg=…` sont du CEF ordinaire — et
   seul le premier mot de chaque valeur était conservé. L'horodatage propre de
   l'événement et son message étaient donc perdus en silence. Le découpage se
   fait maintenant devant la clé suivante, et `rt` est accepté sous ses deux
   formes (textuelle et millisecondes depuis l'époque).

### Les deux questions que pose un test de dépôt

Les 15 services qui n'avaient aucun test en ont un, et c'est le même test à
chaque fois : un fichier `internal/repository/<service>_postgres_test.go` qui
tourne contre une vraie base. Il ne cherche pas la couverture, il pose deux
questions qu'une doublure de base ne peut pas entendre.

**1. Une colonne nullable lue dans un `string` Go.** Une colonne sans valeur par
défaut, remplie seulement plus tard — `resolved_by` quand l'alerte est fermée,
`decision` quand la revue est tranchée, `applied_by` quand le correctif est
posé — rend `NULL` à la création. `pgx` refuse de l'écrire dans un `string` :
`cannot scan NULL into *string`. Le code compile, `vet` est muet, et **chaque**
appel répond 500. Six services étaient dans cet état sur leur écriture
principale, et `dspm` sur la totalité de ses lectures. La correction est un
`COALESCE(colonne,'')` dans la projection ; la détection, un test qui crée
l'objet **sans rien d'optionnel** — ce que fait un vrai agent, et ce que ne
fait jamais un test écrit depuis la structure Go.

Variante de la même classe : une colonne qui porte un `CHECK (col IN (…))` et
reçoit `''` d'un champ Go optionnel. `NULL` passe un `CHECK`, `''` non. Dans
`scs`, `assessment_type` avait un `DEFAULT` *et* un `CHECK`, mais l'`INSERT`
nommait la colonne : le défaut ne s'appliquait donc jamais et toute évaluation
ouverte sans type était refusée par la base.

**2. Un identifiant venu de la requête, dont on ne vérifie pas le propriétaire.**
Le filtre de tenant sur une écriture ne prouve rien quand c'est la *cible* qui
vient du client : la ligne écrite porte le tenant de l'appelant, donc elle est
« la sienne » quel que soit l'appareil, le compte, la zone ou le fournisseur
qu'elle désigne. Les clés étrangères ne portent pas de tenant ; PostgreSQL
accepte l'identifiant de n'importe quel client. Onze écritures étaient dans ce
cas, et ce qu'elles permettaient n'est pas théorique :

- déclencher un effacement à distance sur le téléphone d'un autre client, ou y
  installer une application (`mobile`) ;
- révoquer l'accès d'un collaborateur d'un autre client, en lisant au passage
  son nom, son courriel et son rôle (`iga`) ;
- pousser l'automate d'une autre usine en « violations_found » et son score de
  risque à 100 (`dlp`, `ot`) ;
- écrire une règle de pare-feu entre deux zones d'un autre réseau, et lire le
  nom de ces zones dans la réponse (`netsec`) ;
- faire monter le compteur d'infractions d'une politique voisine, c'est-à-dire
  le classement de son tableau de bord (`dlp`, `netsec`) ;
- déposer une alerte « vendor_breach » dans le dossier fournisseur d'un autre
  client, où elle s'affiche comme son propre constat (`scs`).

La forme de la correction est la même partout : une fonction
`<objet>BelongsTo(ctx, tenantID, id)` appelée **avant** l'écriture, et un
prédicat de tenant sur les jointures qui remplissent un nom ou comptent des
lignes à côté d'un objet.

Deux classes de moindre portée reviennent aussi : un compteur ou un score
recalculé dans un seul sens (le risque d'un actif qui ne pouvait que monter,
dans `ot` et `scs`), et une écriture qui ne trouve rien et le rapporte comme un
succès — un `RowsAffected()` jeté. Le test les attrape de la même façon : il
affirme des **nombres**, jamais l'absence d'erreur.

### Tester une chaîne d'ingestion : `testinfra.Kafka`

```go
f := testinfra.Kafka(t)              // courtiers + un sujet à ce test seul
dlqTopic := f.NewTopic("dlq")        // un second sujet, dérivé du même préfixe
```

Un test d'ingestion a besoin de **deux** sujets, parce que ce qu'il prouve est
qu'un message est parti sur le bon. Les deux assertions se valent :

```go
i.read(t, i.dead, 1, "le sujet de rebut")      // la lettre morte est arrivée
i.empty(t, i.events, "le sujet des événements") // et n'est pas allée ailleurs
```

La seconde est celle qui a trouvé le défaut 1 ci-dessus. Elle attend trois
secondes puis conclut que rien n'arrive : c'est le seul moyen d'affirmer une
absence sur un courtier, et c'est pour cela que la suite du collecteur dure une
vingtaine de secondes.

### La chaîne de bout en bout : `make e2e-chain`

```
./scripts/dev-local.sh up        # ou infra + migrate + seed + services
./scripts/dev-local.sh accounts  # le compte de service du SOAR
make e2e-chain
```

Une attaque, d'un bout à l'autre, chronométrée :

```
  step                                     took     budget
  1. a detection rule is authored          208ms         —
  2. a connector is onboarded              170ms         —
  3. the attack begins: six failed logins   50ms       20s
  4. the rule engine raises an alert      1m2.7s     2m30s
  5. an analyst promotes it to a case        9ms       15s
  6. a containment playbook is written       9ms         —
  7. the playbook runs to completion          2s      1m0s
  8. the address is blocked at the network    5ms      1m0s
  9. the audit trail names the playbook      15ms       30s
  total                                   1m5.1s
```

Ce que cette table apporte et qu'aucun test unitaire n'apporte : **le passage
d'une étape à la suivante**. Chacune des neuf avait un test ; aucune n'avait de
test que la suivante arrive. Les quatre défauts trouvés à la première exécution
complète étaient tous là :

1. le compte de service du SOAR n'était créé nulle part, donc toute action
   atteignant un autre service répondait 401 — la moitié « réponse » du produit
   ne pouvait pas agir, dans **toute** installation ;
2. aucune action de playbook n'était journalisée : un pare-feu changé par
   automate ne laissait aucune trace d'audit ;
3. le moteur de règles s'arrêtait définitivement sur une coupure du courtier
   Kafka, avec une ligne de journal et aucune alerte ;
4. `POST /playbooks/{id}/run` ne rend pas l'identifiant de l'exécution qu'il
   démarre, donc suivre un travail asynchrone demande de lister et de trier.

Le budget de l'étape 4 est large (2 min 30) pour une raison qui se lit dans la
table : le moteur rafraîchit son cache de règles toutes les 60 secondes, donc
une règle écrite à l'instant ne s'applique pas aux événements qui arrivent
ensuite. La chaîne rejoue la rafale toutes les 20 secondes jusqu'à l'alerte —
ce que fait un attaquant de toute façon — ce qui rend le chiffre honnête :
c'est le temps entre la première tentative et l'alerte, latence de cache
comprise.

En CI, le travail `e2e-chain` démarre la plateforme **sans Keycloak** :
`CRP_OIDC_ISSUER` est explicitement vide, donc les services n'acceptent que les
jetons signés par la plateforme, ce que la chaîne émet avec
`internal/pkg/devtoken`. C'est aussi la configuration à utiliser pour déboguer
localement sans fournisseur d'identité.

#### Et trois défauts de plus, que seule la CI pouvait montrer

La chaîne passait en local en 4 s et échouait en CI. Trois exécutions, deux
symptômes différents, et aucune des deux ne disait quoi : le journal d'un
travail fait plusieurs mégaoctets et l'API ne le rend pas page par page. Les
quatorze sorties du test écrivent donc aussi leur phrase en **annotation** de
l'exécution, que l'API rend en un appel, et l'étape de vidage des journaux fait
de même pour les lignes d'erreur de chaque service. La première exécution ainsi
instrumentée a donné la réponse immédiatement :

```
[failure] soar: {"level":"fatal","service":"soar-service",
  "error":"oidc discovery http://localhost:8080/realms/cyberradar/…:
    dial tcp [::1]:8080: connect: connection refused"}
```

5. **la configuration était implicite dans le shell appelant.** `restart`
   repasse par `services`, qui relit le shell — un autre shell. Le job posait
   `CRP_OIDC_ISSUER` vide sur la seule étape qui démarre la plateforme ;
   l'étape suivante provisionne le compte du SOAR et le redémarre, sans la
   variable. Le service redémarré a sondé un Keycloak absent et s'est arrêté.
   Les choix sont désormais écrits dans `$STATE_DIR/config.env` au premier
   démarrage et relus ensuite, par `declare -p` pour que « défini mais vide »
   survive — c'est la valeur qui porte le sens. Le même piège attendait un
   développeur qui redémarre un service depuis un second terminal ;
6. **`services` annonçait un démarrage réussi avec des services morts**, par
   un avertissement et un code de retour nul. Trois exécutions de la chaîne ont
   piloté une plateforme sans SOAR. Le code de retour est maintenant non nul, et
   le redémarrage du SOAR, qui était muet et dont le résultat était ignoré, est
   vérifié ;
7. **le moteur de détection repartait de la fin du journal Kafka.** Le
   travailleur du pipeline lisait depuis le début (`FirstOffset`), le moteur de
   règles depuis la fin (`LastOffset`) : le service qui ne fait que stocker les
   événements en prenait soin, celui qui décide s'il faut lever une alerte non.
   Conséquence : redémarrer le SIEM pendant une attaque rend cette attaque
   invisible, sans une ligne de journal pour le dire. (Ce défaut a d'abord été
   pris pour la cause de l'instabilité de l'étape 4 en CI ; quatre
   ré-exécutions du même commit l'ont démenti — deux vertes, deux rouges. Il est
   réel et corrigé pour ce qu'il est, pas pour ce qu'on lui a attribué.)
   L'UEBA portait le même défaut : des lignes de
   base construites sur un trou sous-estiment l'activité. Les deux lisent
   désormais depuis le début, ce qui ne change que le cas d'un groupe sans
   position validée ; en régime établi le moteur reprend où il s'était arrêté,
   et la clé de déduplication (règle, entité, client) est ce qui empêche un
   rejeu de lever deux fois la même alerte. Le SOAR reste délibérément sur
   « seulement les nouveaux » : rejouer une alerte, c'est rejouer son playbook,
   donc rebloquer des adresses sur la foi de l'histoire. Les deux constantes
   portent maintenant un nom — `kafka.FromTheBeginning` et
   `kafka.OnlyNewEvents` — et un test de source vérifie le choix de chaque
   service, parce qu'un `-1` à un appel ne dit rien et qu'un service copié sur
   son voisin hérite du choix de ce voisin ;
8. **et la rupture, elle, est entre le collecteur et le moteur.** Le courtier
   a tranché ce que les deux journaux ne pouvaient pas dire :
   `crp.events.normalized` écrit jusqu'à 48, `crp.events.enriched` à 0. Le
   collecteur publie, le travailleur du pipeline ne republie rien, et le moteur
   de règles attend correctement sur un sujet vide. Ni l'un ni l'autre n'écrit
   une ligne par événement, donc une reprise réussie et une reprise perdue sont
   indiscernables dans leurs journaux — c'est pourquoi la chaîne interroge
   maintenant le courtier elle-même (`BrokerState`) et le dit en une phrase
   dans son échec. Diagnostic en cours ;
9. **`${VAR:-default}` là où le vide a un sens.** Le deux-points fait prendre le
   défaut à une valeur explicitement vide. Pour un mot de passe, « ce serveur
   n'en a pas » est une configuration réelle — celle des conteneurs de la CI — et
   la seule façon de le dire est le vide. Avec le deux-points, chaque `AUTH`
   échouait et chaque service basculait sur son chemin de repli : la fenêtre
   glissante du SIEM compte alors en mémoire, par conception, donc rien ne
   paraissait cassé pendant que le compteur partagé n'était jamais exercé.

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

## Les migrations

PostgreSQL passe par `golang-migrate` et une table `schema_migrations` :
chaque fichier s'applique une fois, et une nouvelle migration s'applique
par-dessus une installation en service.

```bash
make migrate          # applique ce qui ne l'est pas encore
make migrate-status   # la version où la base se trouve
make migrate-baseline # adopter un schéma posé avant la table de version
```

Ce que ça remplace : une boucle sur `migrations/postgres/*.sql` à travers
`psql`. Elle marche exactement une fois. Au deuxième passage elle rejoue tous
les fichiers, et un fichier qui n'est pas idempotent — un `ALTER TABLE`, un
`INSERT` de données d'amorçage, un `CREATE INDEX` sans `IF NOT EXISTS` —
échoue ou duplique. Le lanceur local portait donc un garde-fou qui refusait de
migrer une base ayant déjà le schéma, ce qui voulait dire qu'une nouvelle
migration ne pouvait pas être appliquée à une installation en service : la
seule voie documentée était de détruire la base et de repartir de zéro. Pour
une plateforme destinée à une banque, ce n'est pas une histoire de migration.

Et le garde-fou couvrait toute la fonction : une installation montée sans
ClickHouse ne pouvait plus jamais recevoir son schéma ClickHouse non plus — le
seul magasin qui manquait était celui que le garde-fou rendait inatteignable.

**Pas de migration descendante, par décision.** La plupart de ces fichiers
créent une table et l'essentiel du reste élargit une colonne ; l'inverse de
« la colonne contient désormais les données du client » n'est pas un `DROP`,
c'est une restauration. `migrate down` est refusé avec cette raison plutôt que
de faire discrètement quelque chose de destructeur.

ClickHouse et Neo4j restent une boucle : chaque instruction de ces fichiers est
un `CREATE … IF NOT EXISTS`, ils sont rejouables tels quels, et leur donner une
table de version dont ils n'ont pas besoin ne ferait qu'ajouter une deuxième
chose à adopter.

---

## La CI

| Job | Ce qu'il fait |
|---|---|
| **Backend** | Format, build, vet, migrations PostgreSQL + ClickHouse, **publication et installation d'une livraison de contenu signée**, quatre refus asservis à leur motif, tests |
| **Migrations** | Applique toutes les migrations à une base vierge, **les applique une seconde fois et exige que rien ne s'applique**, puis supprime la table de version, adopte le schéma et exige encore un `up` vide |
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
