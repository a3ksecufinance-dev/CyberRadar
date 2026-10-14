# Les trois chiffres

> Mesurés le 13 octobre 2026 avec `make bench`, sur la machine décrite plus
> bas. **Ce sont des mesures, pas des spécifications.** La commande est dans le
> dépôt pour être relancée sur le matériel d'un client ; c'est elle qui engage,
> pas le nombre ci-dessous.

| | Mesuré | Comment |
|---|---|---|
| **Débit d'ingestion** | **276 ev/s tenus** · plafond à 400 ev/s | Échelle de paliers, verdict pris sur ce que le pipeline a **consommé** |
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
> `FetchMessage` → traitement → `commit`. À 190 ev/s par instance, le traitement
> d'un événement coûte environ 5 ms. Le débit s'obtient donc aujourd'hui en
> ajoutant des instances, jusqu'à six — au-delà, il faudra soit plus de
> partitions, soit un traitement concurrent dans le processus, qui est un
> changement de sémantique de commit et non un réglage.

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
- une instance traite ~190 ev/s sur quatre cœurs partagés avec toute la
  plateforme ;
- atteindre 100 000 ev/s demanderait, à ce coût unitaire, de l'ordre de
  500 instances — autrement dit le coût par événement doit baisser, pas
  seulement le nombre de machines augmenter.

Ce dernier point est l'arbitrage à instruire, et il se traite dans le
traitement d'un événement, pas dans la topologie. Tant qu'il ne l'est pas, le
chiffre à citer est celui qu'on a mesuré, avec sa machine.

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
