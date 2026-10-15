# Les trois chiffres

> Mesurés le 14 octobre 2026 avec `make bench`, sur la machine décrite plus
> bas. **Ce sont des mesures, pas des spécifications.** La commande est dans le
> dépôt pour être relancée sur le matériel d'un client ; c'est elle qui engage,
> pas le nombre ci-dessous.

| | Mesuré | Comment |
|---|---|---|
| **Débit d'ingestion** | **376 ev/s tenus** · plafond à 600 ev/s | Échelle de paliers, verdict pris sur ce que le pipeline a **consommé** |
| **Coût d'un événement** | **3,6 ms**, une instance | Retard créé puis drainé, relevé chaque seconde (`-only lag`) |
| **Latence API p95** | **10 ms** seule · **51 ms** à 8 requêtes en vol | 500 requêtes après échauffement, mesure côté client |
| **Temps de détection** | **p50 443 ms** · p95 624 ms | De l'événement remis au collecteur à l'alerte lisible par l'API |

## La machine

```
processeur   Intel(R) Xeon(R) @ 2.10GHz × 4
mémoire      15,7 Gio
noyau        6.18.44
Go           1.26.0
disposition  les 29 services, Kafka, PostgreSQL, ClickHouse, Redis et Neo4j
             tournent sur cette même machine, et le banc aussi
```

Quatre cœurs partagés entre toute la plateforme et l'outil qui la mesure. Les
trois chiffres sont donc un **plancher**. Ce qu'ils disent de vrai au-delà de
cette machine, c'est le rapport entre eux et la raison du plafond.

## Ce que la mesure a trouvé, et qui ne dépend pas de la machine

### Le collecteur accepte vingt fois plus vite que le pipeline ne traite

Une première échelle a conclu à **5 716 ev/s tenus**. C'était faux, et la façon
dont c'était faux vaut d'être écrite : le verdict vérifiait que le sujet
`crp.events.normalized` avançait du nombre d'événements envoyés. Or c'est le
**collecteur** qui écrit dans ce sujet. La mesure prouvait que le collecteur
avait répondu, pas que la plateforme avait traité.

Le verdict lit maintenant l'**offset validé par le groupe de consommateurs**
du pipeline. Avec cette correction, le même matériel donne **276 ev/s**.

L'écart n'est pas une erreur de mesure, c'est la plateforme : le collecteur
encaisse à 5 700 ev/s, le pipeline d'enrichissement traite à ~280, et Kafka
absorbe la différence. C'est une architecture légitime — c'est à cela que sert
un journal distribué — mais elle a une conséquence qu'il faut dire : **sous une
rafale, la plateforme accepte tout et détecte en retard.** Une rafale de
160 000 événements a mis le pipeline à **525 586 événements de retard**, soit
plus d'une heure de rattrapage, pendant laquelle aucune détection nouvelle
n'est sortie.

### Le plafond était structurel — il ne l'est plus

À la première mesure, tous les sujets avaient **une seule partition**. Dans un
groupe de consommateurs Kafka, une partition n'est lue que par un seul
consommateur : déployer dix instances du pipeline n'en aurait fait travailler
qu'une, les neuf autres restant inactives. Le débit ne s'augmentait qu'en
rendant un seul processus plus rapide.

C'est corrigé (US-CDF-STR-004). Les sujets naissent avec six partitions,
`KAFKA_PARTITIONS` le règle, et `EnsureTopic` **élève** le compte d'un sujet
déjà créé — sans quoi une plateforme ayant tourné une fois aurait gardé sa
partition unique pour toujours, sans autre symptôme qu'un débit refusant de
s'améliorer quel qu'ait été le nombre d'instances ajoutées.

**Mesuré, sur la même machine :**

| Instances du pipeline | Débit tenu | Plafond |
|---|---|---|
| 1 | 189 ev/s | 400 ev/s |
| 2 | **349 ev/s** | 600 ev/s |

**×1,85 en doublant les instances.** Avant le changement, le facteur aurait été
de 1,0. Les journaux des deux instances confirment le partage : la seconde a
traité 12 216 des 24 000 événements du palier.

Le reste de l'écart au facteur 2 est la machine — quatre cœurs déjà partagés
entre vingt-neuf services, l'infrastructure et le banc.

> **Ce qui reste séquentiel.** Chaque instance traite **un message à la fois** :
> `FetchMessage` → traitement → `commit`. Le débit s'obtient donc en ajoutant
> des instances, jusqu'à six — au-delà, il faudra soit plus de partitions, soit
> un traitement concurrent dans le processus, qui est un changement de
> sémantique de commit et non un réglage.

### Les 5 ms par événement étaient une fenêtre d'attente

Le point précédent laissait une question ouverte : à ~5 ms par événement,
atteindre 100 K EPS demanderait des centaines d'instances. La question était
donc *où passent ces 5 ms* — et la réponse n'était dans aucun des endroits
attendus. Ni l'enrichissement, ni le rapprochement d'indicateurs, ni
l'écriture ClickHouse, qui est tamponnée par lots de mille.

Elles passaient dans le **producteur Kafka**. `kafka-go` garde un lot ouvert
pendant `BatchTimeout` — 5 ms — en espérant qu'un autre message le rejoigne,
pour amortir l'aller-retour sur plusieurs messages à la fois. C'est le bon
réglage pour un producteur appelé par beaucoup de goroutines : une poignée de
requêtes HTTP concurrentes remplit le lot bien avant l'échéance.

C'est le mauvais réglage pour la boucle du pipeline, qui est séquentielle.
Aucun second message ne peut rejoindre le lot : la seule goroutine qui
pourrait en envoyer un est précisément celle qui attend. La fenêtre entière
est donc payée **sur chaque événement**.

Mesuré isolément, un `Publish` séquentiel coûte **6,35 ms** avec la fenêtre à
5 ms et **1,75 ms** avec la fenêtre à 1 ms — neuf exécutions, écart maximal de
0,05 ms. `ProducerConfig.BatchTimeout` rend la fenêtre réglable ; le pipeline
la met à 1 ms, le défaut ne bouge pas pour les autres producteurs, qui eux ont
de la concurrence à amortir.

**Mesuré de bout en bout, une instance, retard créé puis drainé :**

| Fenêtre de lot | Débit drainé | Coût d'un événement |
|---|---|---|
| 5 ms | 124 ev/s | 8,1 ms |
| **1 ms** | **298 ev/s** | **3,4 ms** |
| 5 ms, repassé en dernier | 126 ev/s | 8,0 ms |

Les trois paliers ci-dessus lisent l'offset validé du **pipeline** seul.
`-only lag` suit le plus en retard des deux étages, pipeline et moteur de
règles, et rend donc un peu moins — 278 ev/s, 3,6 ms — pour la même machine
dans le même état. L'écart est la définition, pas la mesure.

**×2,4.** Le gain de bout en bout (4,7 ms par événement) correspond à
l'économie mesurée isolément sur le `Publish` (4,6 ms) à 0,1 ms près : les deux
instruments, indépendants, donnent la même réponse. Le troisième palier reprend
le premier réglage en dernier, pour que l'ordre des essais n'explique pas
l'écart.

Sur l'échelle de paliers, le même changement porte le débit tenu de **276 à
376 ev/s** et le plafond de 400 à 600.

### Comment cette mesure a failli être fausse trois fois

Elle mérite d'être écrite, parce que chacune des trois erreurs produisait un
résultat crédible.

**Deux instances au lieu d'une.** Le script d'échange d'instance tuait le shell
qui enveloppait le processus, pas le processus. Les deux versions tournaient
donc ensemble et se partageaient les partitions. L'échelle a rendu 294 contre
311 ev/s : « le changement ne sert à rien », conclusion qui aurait été publiée.
Le même changement vaut ×2,4 une fois une seule instance en marche.

**Une compilation en parallèle.** Un `go test -race` lancé pendant un relevé :
sur quatre cœurs partagés, il déplace le chiffre plus que la plupart des
changements qu'on cherche à mesurer.

**L'échelle elle-même.** Elle ne pouvait pas répondre à la question. Elle
mesure ce que la plateforme *accepte*, à travers le générateur, le collecteur
et les cœurs partagés. Pour le coût d'un événement *dans le pipeline*, il faut
un retard créé directement sur le sujet normalisé et drainé sans personne en
face — c'est ce que fait `-only lag -lag-backlog N`, relevé chaque seconde
plutôt qu'en un seul écart sur une minute, parce qu'un écart unique moyenne
les changements de régime qu'il contient.

## Le banc écrit dans le locataire de la démonstration

À dire avant de lancer `make bench` sur une plateforme qui sert aussi à
montrer quelque chose. Le banc s'authentifie avec une identité réelle, donc
ses événements atterrissent dans le locataire de cette identité — le même que
celui du domaine de démonstration. Ils sont *distinguables* (`source =
'crp-bench'`), ce qui n'est pas la même chose que *séparés*.

Quelques exécutions suffisent à ensevelir le jeu de démonstration. Mesuré
ici : **151 403 événements de banc contre 1 357 réels**, tous ceux du banc en
`LOW`. Un graphique de répartition des sévérités montrait alors 99 % de `LOW`
— c'est-à-dire la signature d'un générateur de charge, pas celle d'une banque.

`make bench-clean` affiche ce qui porte la marque du banc et ne supprime rien ;
`make bench-clean ARGS=--yes` supprime ces lignes-là et aucune autre. Après
nettoyage, le locataire de démonstration retrouve sa répartition : 736 `MEDIUM`,
599 `LOW`, 20 `HIGH`, 2 `CRITICAL` sur 1 357 événements.

## Deux pertes silencieuses, trouvées en lisant le chemin chaud

Chercher où passaient les millisecondes voulait dire lire `Handle` ligne à
ligne. Deux défauts s'y trouvaient, sans rapport avec la performance, et tous
deux de la même espèce : un événement disparaissait et rien ne le disait.

**Le tampon ClickHouse était partagé sans verrou.** La boucle de consommation
appelle `Write`, qui ajoute au tampon ; une goroutine distincte appelle `Flush`
toutes les cinq secondes, qui le vide. Les deux touchaient la même tranche sans
synchronisation. Un ajout et une troncature qui s'entrelacent perdent des
événements que le consommateur a **déjà validés comme traités** : ils ne
reviendront pas. Le détecteur de courses de Go le confirme sur l'ancien code,
et reste muet sur le nouveau.

**Un échec de publication était journalisé puis oublié.** Le sujet enrichi est
ce que lit le moteur de règles. Si la publication échouait, le code écrivait
une ligne de journal et retournait `nil` — l'offset était validé, et
l'événement sortait définitivement du chemin de détection. C'est la panne la
plus discrète possible pour une plateforme dont le métier est de ne rien
manquer.

Il part maintenant en file de rebut, et n'est pas rejoué : ClickHouse détient
déjà la ligne et `cyber_events` est un `MergeTree` simple, donc un rejeu la
dupliquerait. Et si la file de rebut échoue à son tour, l'erreur remonte et
l'offset n'est pas validé — c'est le seul cas où une ligne en double vaut mieux
que l'alternative, qui est de perdre l'événement sans trace nulle part.

Quatre tests couvrent ces chemins, chacun vérifié par mutation : remis dans
leur état d'avant, ils échouent.

## La réponse à la question des 100 K EPS

Le plan d'exécution demandait une décision explicite : tenir le chiffre de
100 000 événements par seconde, ou le changer.

Les deux premières étapes sont faites : les sujets sont partitionnés, et la
mise à l'échelle est mesurée à ×1,85 pour deux instances. **Le chiffre ne peut
toujours pas être annoncé**, mais pour une raison différente et plus saine : il
reste à l'extrapoler sur du matériel de production, ce qu'aucune mesure prise
sur quatre cœurs partagés ne permet.

Ce qu'on peut dire aujourd'hui, et qui est vrai :

- le débit **s'additionne** avec les instances, jusqu'au nombre de partitions ;
- une instance traite ~300 ev/s sur quatre cœurs partagés avec toute la
  plateforme, soit 3,4 ms par événement ;
- ce coût a déjà été divisé par 2,4 en retirant une attente qui ne servait à
  rien ; ce qui reste est du travail réel, pas de l'attente.

À 3,4 ms par événement, 100 000 ev/s demanderait encore de l'ordre de
340 instances. Le coût unitaire doit donc continuer de baisser, et la prochaine
étape connue n'est plus un réglage : c'est le traitement concurrent dans le
processus, qui change la sémantique du commit. Tant qu'elle n'est pas
instruite, le chiffre à citer reste celui qu'on a mesuré, avec sa machine.

## La méthode, et pourquoi elle est ainsi

**Le débit** procède par paliers. Chaque palier propose un débit pendant une
fenêtre, puis pose quatre questions à la plateforme — pas aux compteurs du
banc : le collecteur a-t-il refusé des événements ; les a-t-il acceptés sans
rien publier ; la file de rebut a-t-elle grossi ; le pipeline a-t-il consommé
ce qui a été envoyé. Un palier ne « tient » que si les quatre réponses sont
bonnes. Le banc propose un débit plutôt que de taper aussi vite qu'il peut :
un client qui sature mesure le client.

**La latence** est mesurée deux fois, seule et sous charge. Un seul chiffre
cacherait lequel des deux il décrit : seule, c'est le coût du traitement ;
sous charge, c'est ce que ressent un utilisateur quand ses collègues
travaillent aussi. Sur peu de cœurs, l'écart entre les deux est de la mise en
file, pas du travail. Un échauffement précède la mesure — sans lui, la
première exécution d'une session lit cinq fois pire que la seconde.

**La détection** envoie une rafale d'échecs d'authentification depuis une
adresse propre à ce tour, puis attend que l'alerte soit lisible par l'API.
L'adresse est salée par l'heure de démarrage : sans cela, deux exécutions
espacées de moins de cinq minutes se heurtent à la fenêtre de déduplication du
moteur, et la seconde conclut à tort que rien n'a été détecté.

**Avant de mesurer la détection, le banc refuse de commencer si le pipeline a
du retard.** Une mesure prise avec un arriéré mesure l'arriéré. C'est ce qui
est arrivé à la première exécution complète : les dix tours ont expiré à
quatre-vingt-dix secondes et le rapport allait conclure que le moteur ne levait
plus d'alertes, alors qu'il lisait encore, des minutes en arrière.

## Relancer

```bash
cd backend
./scripts/dev-local.sh up      # la plateforme
./bin/demo-seed                # les données, et la clé du connecteur
make bench                     # les trois chiffres

./bin/bench -only lag          # le pipeline a-t-il du retard, et à quel rythme draine-t-il
./bin/bench -only detection    # un seul des trois
./bin/bench -ladder 100,200,400 -window 20s -settle 30s
```

Sur un matériel neuf, commencer par `-only lag` après une rafale : le rythme
de drainage est le débit du pipeline sans personne pour lui disputer la
machine, et c'est la mesure la plus directe des trois.
