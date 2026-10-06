# Démontrer la plateforme

> Pour présenter CyberRadar à un client, à un intégrateur ou devant une salle de
> décideurs. Écrit après une démonstration préparée dans l'urgence, donc chaque
> section répond à une chose qui a réellement manqué.
>
> Deux principes. **Le portable est le support, la machine distante est le
> secours** : le réseau d'un salon tombe, et il n'y a pas de seconde chance
> devant une salle. **Rien ne se montre qui n'a pas été vérifié le jour même** :
> une seule commande donne le verdict.

---

## 1. Le contrôle avant-vol

```bash
cd backend
./scripts/demo-ready.sh --chain
```

Sept contrôles, un verdict, aucune réparation — il lit, il ne répare pas. Avec
`--chain` il conduit en plus l'attaque complète, ce qui prend une quinzaine de
secondes et vérifie la seule chose qu'aucun autre contrôle ne vérifie : que
chaque service passe bien la main au suivant.

Ce qu'il regarde, dans l'ordre où ça mord :

| Contrôle | Ce qu'il évite |
|---|---|
| Les quatre magasins écoutent | Une page qui répond 500 au pire moment |
| Le schéma est à la dernière version | Une migration de retard, visible sur un seul écran |
| Les 29 services répondent **deux fois** | Un service qui répond puis meurt — c'est ce qui a mis un SOAR mort derrière un démarrage réussi |
| Le patrimoine est peuplé | Chaque graphique à zéro, et un évaluateur incapable de distinguer un produit qui marche d'un produit qui démarre |
| Le compte de service du SOAR existe | Tout confinement répond 401 |
| L'interface répond | — |
| L'attaque de bout en bout | La chaîne rompue sans qu'aucun journal le dise : ça a coûté quatre exécutions de CI avant que les offsets du courtier ne le révèlent |

**Si le verdict est bloquant, ne présentez pas en l'état** : chaque ligne porte
la commande qui corrige.

---

## 2. Démarrage à froid, depuis rien

Compter **15 à 20 minutes** la première fois (la construction des 36 binaires et
celle de l'interface dominent), 3 à 4 minutes ensuite.

```bash
cd backend
./scripts/dev-local.sh infra       # PostgreSQL, Redis, ClickHouse, Kafka, Keycloak
./scripts/dev-local.sh migrate     # le schéma, rejouable
./scripts/dev-local.sh content     # le catalogue de détection
./scripts/dev-local.sh seed        # les identités, sans quoi personne n'entre
./scripts/dev-local.sh services    # les 30 services
./scripts/dev-local.sh accounts    # le compte de service du SOAR
make demo                          # le patrimoine de démonstration
./scripts/dev-local.sh frontend    # l'interface sur :3000
./scripts/demo-ready.sh --chain    # le verdict
```

`./scripts/dev-local.sh up` enchaîne tout cela, mais les étapes séparées sont
préférables la veille d'une présentation : on voit laquelle échoue.

**Ce qui doit tourner et qu'on oublie :** `accounts`. Sans lui le SOAR n'a pas
de justificatif et toute action de confinement répond 401 — l'étape la plus
spectaculaire de la démonstration, en panne, sans message explicite.

---

## 3. Le déroulé, et ce qu'il faut dire

Vingt minutes, cinq temps. Les chiffres cités sont ceux que `make demo` produit
et que l'écran affichera : **vérifiez-les avant**, ils dépendent du jeu de
données.

### Temps 1 — Le tableau de bord (2 min)

L'estate : **125 actifs**, 25 vulnérabilités, **412 constats**, 72 alertes,
42 contrôles sur **5 référentiels**, 4 risques — Banque Al Massira, banque de
détail marocaine fictive : siège à Casa Finance City, 24 agences de Tanger à
Laâyoune, son réseau de distributeurs, son back-office et ses systèmes
centraux.

> **La banque est inventée**, le nom comme le domaine `almassira.ma`. Les
> villes sont réelles. À dire une fois, au début : un DSI qui se demande de
> quelle banque viennent ces chiffres n'écoute plus le reste.

> « Tout ce que vous voyez a été écrit à travers l'API de la plateforme, sous
> une identité réelle avec de vraies permissions. Rien n'est injecté en base. »

C'est vrai et c'est vérifiable, et c'est ce qui distingue cette démonstration
d'une maquette.

Deux détails qui tiennent à l'examen, et qu'il vaut la peine de montrer si on
vous pousse : chaque agence porte sa propre ville dans le champ *localisation*,
et les vulnérabilités sont rattachées aux actifs **par le produit qu'elles
nomment**. Un distributeur porte SMBGhost et PrintNightmare ; il ne porte pas la
faille Outlook. C'est exactement ce qu'un RSSI vérifie en premier.

**Et le point qui porte devant cette salle** : les cinq référentiels sont ceux
qui obligent réellement un établissement marocain — **DNSSI** de la DGSSI,
**loi 09-08** et CNDP, **PCI DSS 4.0**, **SWIFT CSP** et **ISO 27001:2022**.
DORA n'y est pas : c'est un règlement européen, et le citer à Casablanca
décrédibilise au lieu de rassurer. Les intitulés de contrôle sont la
correspondance de la plateforme, pas une citation des textes — ce qui se
démontre est le mécanisme, et il vaut pour le référentiel que le client apporte.

### Temps 2 — La détection, et sa généalogie (4 min)

L'écran SIEM, puis la bibliothèque de détection. 36 règles actives.

> « Le catalogue se livre indépendamment du code, signé. Une règle adoptée garde
> son lien vers la version du catalogue dont elle vient, donc on sait répondre à
> "qu'est-ce que votre plateforme couvre" autrement que par une capture
> d'écran. »

C'est l'argument qui intéresse un intégrateur : la couverture est un objet
versionné, pas une promesse.

### Temps 3 — L'attaque, en direct (5 min) — **le moment fort**

Dans un terminal, à l'écran :

```bash
make e2e-chain
```

Neuf étapes chronométrées : règle écrite, connecteur raccordé, six
authentifications en échec depuis une adresse, alerte levée, cas ouvert,
playbook écrit, playbook exécuté, adresse bloquée au niveau réseau, journal
d'audit nommant le playbook.

**Entre 4 et 65 secondes de bout en bout**, et la variation a une raison qu'il
vaut mieux énoncer que subir : le moteur rafraîchit son cache de règles toutes
les 60 secondes, donc une règle écrite à l'instant s'applique quelque part dans
ce cycle. Mesures réelles : 4,3 s et 44,9 s sur la même installation. Si vous
voulez le chiffre bas, lancez la chaîne une fois cinq minutes avant — et si
elle met 40 secondes devant la salle, dites pourquoi : « le temps affiché
inclut la latence du cache, c'est le délai qu'un client constate, pas celui
qu'un commercial choisit ».

> « L'ingestion, la détection, la réponse et la trace d'audit sont quatre
> produits séparés chez la plupart des éditeurs. Ici c'est une seule chaîne, et
> voilà son chronomètre. »

Puis revenir dans l'interface montrer l'alerte, le cas et la politique réseau
qui viennent d'apparaître — au milieu des 72 alertes de la semaine, ce qui
montre au passage qu'on ne travaille pas sur une base vide.

**Si la chaîne échoue en direct** : elle affiche la table des étapes et dit
*lequel* des passages a rompu, avec les offsets du courtier. Lisez-la à voix
haute — un outil qui dit précisément où il casse est plus convaincant qu'un
outil qui ne casse jamais devant personne. Puis enchaînez sur les 423 alertes
déjà en base, qui, elles, ne dépendent de rien.

### Temps 4 — La conformité et le risque (4 min)

41 contrôles, les écarts, le profil de risque paramétrable (seuils UEBA, délais
de remédiation, pondérations des chemins d'attaque).

> « Les seuils ne sont pas dans le code. Un client qui juge qu'un verrouillage
> de compte doit se déclencher à trois tentatives et non cinq le change sans
> livraison. »

### Temps 5 — La franchise (5 min)

C'est le temps qui fait la différence devant un DSI, et celui qu'on supprime
quand on manque de temps. Ne le supprimez pas.

| | |
|---|---|
| User stories faites | **101 / 346** |
| Services sans test | **0 / 32** |
| KPI du master plan mesurés | **0 / 8** — MTTD et MTTR jamais mesurés en charge |
| NFR vérifiées | **0 / 14** |
| Unités déployables | 32, cible 8–10 |
| Connecteurs cloud réels | lot L3, pas commencé |

> « La plateforme est réelle et tourne devant vous. Elle couvre environ 30 % de
> son périmètre spécifié, et je peux vous dire lesquels. Les chiffres de
> performance ne sont pas mesurés : je ne vous citerai pas un MTTD que je n'ai
> pas mesuré. »

Un décideur qui entend ça fait confiance au reste. Un décideur qui entend
« tout est prêt » vérifie, et trouve.

---

## 4. Ce qu'il ne faut pas ouvrir

| | Pourquoi |
|---|---|
| L'écran Copilot sans `ANTHROPIC_API_KEY` | Le service refuse de démarrer, et c'est le bon comportement : un assistant qui répond silencieusement rien est pire qu'un assistant absent. L'écran, lui, sera vide |
| Les graphes d'attaque sans Neo4j | La lecture retombe sur PostgreSQL, ce qui marche, mais le rendu est moins parlant |
| Les écrans à faible volume | DSPM et mobile portent peu de données de démonstration |
| La couverture de détection à 100 % | 13 des 15 règles du catalogue sont adoptées, deux ne le sont pas **volontairement** : l'écran de couverture n'a d'intérêt que s'il a un écart à montrer, et « pourquoi celle-là n'est pas active » est la question qu'un auditeur pose |
| Le détail d'une CVE devant un RSSI | Le score CVSS est celui publié, mais l'EPSS est une valeur **datée** : c'est une probabilité qui change chaque jour. Elle est là pour que le tri ait un sens, pas pour être citée comme un chiffre courant |

---

## 5. La machine de secours

À faire **la veille**, pas le matin.

```bash
# Sur une machine neuve : 8 vCPU, 32 Go, Docker et Compose
git clone <dépôt> && cd CyberRadar/backend
./scripts/harden-demo.sh --rotate --host demo.example.com
docker compose -f deployments/docker-compose.yml up -d
# puis, depuis la machine :
./scripts/demo-ready.sh --chain
```

`harden-demo.sh` écrit `deployments/.env` avec des valeurs générées et une
nouvelle paire RSA. Il est nécessaire : le fichier Compose porte des
identifiants de développement — `crp_password_dev` — et la clé de signature
livrée avec le dépôt signe le jeton de n'importe quelle identité.

**Ce que le script ne fait pas, et qui reste obligatoire :**

1. **HTTPS devant.** Rien ne doit répondre en clair.
2. **Le pare-feu.** Seuls 3000 et 8080 ont une raison d'être joignables. Les
   30 ports de service, PostgreSQL, ClickHouse, Kafka, Neo4j, Redis, Vault,
   Prometheus, Grafana et Jaeger n'en ont aucune.
3. **Le mot de passe de l'administrateur de démonstration**, qui est dans
   `migrations/seed/001_identities.sql`, donc dans le dépôt.

**Le piège qui fait perdre une heure** : PostgreSQL, ClickHouse et Neo4j ne
lisent leur mot de passe qu'à la création de leur volume. Durcir une
installation déjà démarrée ne change rien côté serveur, et l'erreur sera une
authentification refusée sans rapport apparent avec le `.env`. Durcissez
**avant** le premier `up`, ou `docker compose … down -v` d'abord.

> **Non vérifié à l'écrit de ces lignes** : le chemin Compose n'a pas été
> exécuté depuis que les identifiants y sont paramétrés — l'environnement où ce
> fichier a été modifié n'a pas de démon Docker. Déroulez-le une fois en entier
> la veille, et gardez le chemin local comme support principal.

---

## 6. Si quelque chose casse sur scène

| Symptôme | En direct |
|---|---|
| Une page répond 500 | Passez à l'écran suivant, revenez-y après. `./scripts/dev-local.sh logs <service>` dira pourquoi, plus tard |
| La chaîne échoue | Lisez sa table d'étapes à voix haute, puis montrez les 423 alertes déjà en base |
| L'interface ne répond plus | `./scripts/dev-local.sh restart frontend`, 40 s |
| Un service est mort | `./scripts/dev-local.sh restart <service>` |
| Le réseau du salon tombe | Tout est local, rien ne sort — c'est la raison du choix |

**La règle** : ne déboguez jamais devant la salle. Notez, enchaînez, revenez
dessus après.
