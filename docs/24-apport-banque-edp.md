# 24 — L'apport réel pour une banque de 300+ agences avec filiale EDP

Ce document répond à une question précise : **qu'est-ce que cette plateforme
apporte vraiment** à un établissement bancaire marocain de plus de 300 agences,
soumis à la DNSSI, à la loi sur les données personnelles, à la CNDP et à
l'ISO 27001, qui prend DORA comme référence volontaire, et dont une filiale
établissement de paiement (EDP) exploite des wallets **dans le même core
banking**.

Il reprend le périmètre du [document 23](23-prerequis-deploiement.md) — écrit
pour une microfinance — et dit ce que le changement d'échelle et de statut
réglementaire change. Il sépare partout **ce qui est démontrable aujourd'hui**
de **ce qui ne l'est pas**. Les deux listes comptent ; la seconde est celle qui
détermine le plan.

---

## 0. Trois points de cadrage, avant tout le reste

**« loi 08/20 » n'existe pas au Maroc sous cette référence.** Deux textes
portent des numéros proches et des obligations très différentes :

| Texte | Objet | Autorité |
|---|---|---|
| **Loi 09-08** | Protection des personnes physiques à l'égard des traitements de données à caractère personnel | **CNDP** |
| **Loi 05-20** | Cybersécurité — obligations des infrastructures d'importance vitale | **DGSSI** (directive DNSSI) |

Comme la CNDP est citée dans la même phrase, ce document traite **les deux**,
et signale pour chacun ce que la plateforme couvre. Si une troisième référence
était visée, ce document est à corriger sur ce point avant diffusion.

**DORA ne s'applique pas à un établissement marocain.** C'est un règlement de
l'Union européenne (2022/2554), opposable aux entités financières agréées dans
l'UE. Le prendre comme référence est un choix défendable — c'est le cadre le
plus complet sur la résilience opérationnelle, et il structure correctement le
sujet. Mais c'est un **référentiel volontaire** ici, pas une obligation :
aucune autorité marocaine ne contrôlera une conformité DORA, et aucun écart
DORA ne constitue un manquement. Le mentionner comme obligation dans un dossier
destiné à Bank Al-Maghrib serait une erreur de fond.

**Ce n'est plus une microfinance.** Une banque de 300+ agences avec une filiale
EDP partageant le CBS n'est pas la même commande : le volume est multiplié par
un facteur 3 à 5, la séparation entre deux entités régulées devient une
exigence technique et non une préférence, et les délais de notification
d'incident deviennent opposables. Le dimensionnement du document 23 **ne tient
plus** ; la section 3 ci-dessous le refait.

---

## 1. L'apport, obligation par obligation

Le tableau ci-dessous est la réponse directe à la question posée. Chaque ligne
indique **ce que la plateforme fait réellement aujourd'hui** — vérifié dans le
code, pas dans la plaquette — et **ce qui reste à votre charge**.

### 1.1 Loi 05-20 / DNSSI — détection et notification d'incident

| | |
|---|---|
| **Ce qui existe** | Chaîne d'ingestion mesurée de bout en bout : collecte → normalisation → enrichissement → détection → alerte → cas. **16 détections signées** livrées, dont 5 sur l'authentification, 3 sur le commande-et-contrôle, 2 sur l'exfiltration. Moteur de corrélation à fenêtre temporelle : `threshold: {count, group_by, window_seconds}` — par exemple 5 échecs d'authentification depuis une même IP en 300 s. Latence de traversée mesurée **p95 11 ms**. Service de réponse à incident avec cycle de vie, cas, observables, horodatage de chaque transition. |
| **L'apport** | La DNSSI demande une capacité de détection et un délai de notification. La plateforme fournit la **matière chronométrée** de cette notification : quand l'événement est entré, quand la règle a déclenché, quand un humain a pris le cas. C'est ce qu'un contrôle demande et que la plupart des SI ne peuvent pas produire. |
| **Ce qui manque** | Aucune **notification automatique vers le maCERT/DGSSI** n'est implémentée — ni formulaire, ni format, ni canal. Le délai est mesurable, la déclaration reste manuelle. Les 16 détections sont un socle, pas une couverture : un SOC bancaire en exploite typiquement 150 à 400. |

### 1.2 Loi 09-08 / CNDP — données personnelles

| | |
|---|---|
| **Ce qui existe** | Le journal d'audit (`crp_audit.audit_logs`) enregistre acteur, action, ressource, résultat, IP, session, requête — et un **checksum SHA-256** par ligne. La table est en MergeTree sans déduplication, explicitement conçue en écriture seule. Isolation par `tenant_id` dans chaque requête. Durées de rétention déclarées par table (événements bruts 7 j, UEBA 90 j, alertes 365 j). |
| **L'apport** | La traçabilité des accès aux données personnelles est l'exigence 09-08 la plus difficile à produire a posteriori. Elle est native ici, et l'intégrité de chaque ligne est vérifiable. |
| **Ce qui manque** | **Rien n'est prévu pour l'exercice des droits** (accès, rectification, opposition) : pas de recherche par personne concernée, pas d'export, pas d'effacement ciblé. **Aucun registre de traitement.** Et un point à trancher avec votre DPO : la plateforme ingère par construction des identifiants de personnes (comptes, IP, terminaux) — elle est elle-même un traitement à déclarer, pas seulement un outil de conformité. |

### 1.3 ISO 27001 — système de management

| | |
|---|---|
| **Ce qui existe** | Module de conformité avec référentiels, contrôles, évaluations et preuves. **ISO27001 est l'un des cinq référentiels livrés** (avec DORA, PCIDSS, SWIFTCSP, GDPR). Les détections portent leur rattachement : 12 des 16 citent ISO27001, avec les contrôles A.5.7, A.8.2, A.8.16, A.8.22. |
| **L'apport** | Le lien automatique entre un contrôle de l'Annexe A et la détection qui en fournit la preuve d'efficacité. En audit, c'est la différence entre affirmer qu'un contrôle fonctionne et le montrer. |
| **Ce qui manque** | **Les contrôles ne sont pas pré-chargés** : les référentiels existent comme codes, le catalogue des 93 contrôles de l'Annexe A est à saisir. Compter 5 à 10 jours de paramétrage initial. Aucune automatisation de la revue de direction, de l'analyse de risque ni du plan de traitement — le SMSI reste chez vous. |

### 1.4 DNSSI et loi 09-08 comme référentiels dans l'outil

C'est un point où le code a été corrigé récemment et où il faut être précis.
Le référentiel de conformité n'acceptait que **sept codes en dur** (ISO27001,
SOC2, PCIDSS, SWIFTCSP, NIS2, DORA, GDPR) : l'API répondait **422 sur
« DNSSI »**. La migration `000050` a remplacé cette énumération par une
contrainte de forme.

Conséquence exacte, sans arrondi : **DNSSI et la loi 09-08 sont désormais
enregistrables comme référentiels, mais leurs contrôles ne sont pas livrés.**
Vous obtenez un conteneur vide et correct, pas une cartographie prête.

### 1.5 DORA, en référentiel volontaire

| | |
|---|---|
| **Ce qui existe** | **15 des 16 détections** citent DORA, 14 pointent le contrôle DORA-10.3 (détection d'activité anormale), 2 le DORA-17.1 (gestion des incidents). |
| **Honnêtement** | Cette densité reflète la manière dont le pack a été écrit, pas une couverture des cinq piliers de DORA. Les piliers *gestion du risque TIC tiers* et *tests de résilience opérationnelle numérique* (TLPT) ne sont **pas couverts du tout** — ce ne sont pas des sujets de SIEM. Présenter la plateforme comme « conforme DORA » serait faux ; comme « produisant des preuves pour le pilier détection et incidents » est exact. |

---

## 2. Le cas particulier : la filiale EDP et les wallets dans le même CBS

C'est le point le plus intéressant de la question, et celui où je dois être le
plus direct.

### 2.1 Ce qui est demandé, réellement

Une filiale EDP (loi 103-12) partageant le core banking de sa maison mère pose
trois problèmes distincts :

1. **Ségrégation** — deux entités régulées séparément, deux agréments, deux
   périmètres de contrôle, dans une base de données commune.
2. **Détection de fraude wallet** — cash-in/cash-out en boucle, structuration,
   collusion d'agent, siphonnage après SIM-swap. Ce ne sont pas les mêmes
   schémas que la fraude sur virement.
3. **Pistes d'audit séparées** pour deux autorités qui peuvent contrôler
   indépendamment.

### 2.2 Point 1 — Ségrégation : partiellement répondu

Le modèle multi-tenant permet de déclarer banque et EDP comme deux tenants
distincts, et **chaque requête porte un filtre `tenant_id`** — y compris les
requêtes ClickHouse, qui partitionnent par `tenant_id` avant la date.

Mais : **l'isolation est appliquée par le code applicatif, pas par la base.**
Il n'y a **aucune politique PostgreSQL de sécurité au niveau ligne** (`ROW
LEVEL SECURITY`) dans les 51 migrations. Autrement dit, la séparation entre les
données de la banque et celles de l'EDP tient à la discipline d'écriture de
chaque requête, et une requête oubliée traverse la frontière sans alarme.

Pour un déploiement où la ségrégation est une **exigence d'agrément**, c'est
insuffisant en l'état. La correction est connue et bornée : activer RLS sur les
tables porteuses de `tenant_id` et poser une politique par tenant, de sorte que
l'isolation soit garantie par le moteur et non par la relecture. Estimation :
**15 à 25 jours**, dont la moitié en tests de non-régression.

### 2.3 Point 2 — Fraude wallet : non répondu

Il faut le dire sans détour. Le module de fraude est un **squelette de
scoring**, pas un moteur de fraude wallet. Dans `evaluateRule`, trois types de
règles seulement :

- `threshold` — un seuil sur un montant, et le champ est **codé en dur sur
  `amount`** ;
- `watchlist` — appartenance à une liste ;
- `pattern` — égalité exacte sur canal, pays d'origine, pays de destination.

**Il n'y a ni vélocité, ni agrégation temporelle, ni comportement de référence
par compte.** Or aucun des quatre schémas de fraude wallet cités plus haut ne
se détecte sans compter des événements dans une fenêtre, par compte ou par
agent. La structuration, c'est exactement « N opérations sous le seuil en
24 h » — ce que ce moteur ne sait pas exprimer.

Deuxième constat, trouvé en suivant le chemin du message : les transactions
notées ≥ 50 sont publiées sur le topic **`crp.events.fraud`**, et **aucun
consommateur ne lit ce topic**. Le service de fraude consomme bien
`crp.events.enriched`, mais son consommateur est un journal — le commentaire du
code dit « hook for future parsing ». **Une transaction signalée frauduleuse
n'atteint donc aujourd'hui aucun moteur de détection et ne crée aucune alerte
SIEM.** Elle change de statut en base, et c'est tout.

Ce qui existe par ailleurs et qu'il faut mettre à son crédit : **le moteur de
détection du SIEM, lui, sait compter dans une fenêtre et grouper par champ
arbitraire** (`threshold: {count, group_by, window_seconds}`). La capacité
technique nécessaire aux règles de fraude wallet est donc déjà écrite — elle
est simplement dans l'autre moteur, et les transactions n'y arrivent pas.

C'est une bonne nouvelle pour le chiffrage : il ne s'agit pas de construire un
moteur, mais de **raccorder les transactions au moteur qui existe** et d'écrire
les règles. Estimation : **40 à 60 jours** pour le raccordement, un jeu de 15 à
20 règles wallet, et leur calibrage sur vos données réelles — le calibrage
étant la moitié du travail et celle qu'on ne peut pas faire sans vous.

### 2.4 Point 3 — Pistes d'audit séparées : répondu

Le partitionnement `(tenant_id, toYYYYMM(timestamp))` permet d'extraire,
d'exporter ou de conserver le périmètre d'une seule entité sans toucher à
l'autre. Le journal d'audit **n'a volontairement aucune expiration** : la
rétention est une décision d'exploitant, pas un défaut du schéma. Pour deux
autorités aux exigences de durée différentes, c'est la bonne conception.

---

## 3. Ce que 300 agences changent au dimensionnement

Le document 23 dimensionnait pour 50 à 150 agences. Les mesures de référence
restent celles-ci, inchangées et toujours vérifiables par `make bench` :

| | Mesuré |
|---|---|
| Débit tenu, une instance | **376 ev/s** |
| Coût d'un événement | **3,4 ms** |
| Mise à l'échelle, deux instances | **×1,72** |
| Latence de traversée | **p95 11 ms** |
| Reprise | **313 200 événements en 15 min** par instance |
| Compression ClickHouse | **4,7×** |

**Volume attendu.** En extrapolant le ratio du document 23 (50–150 agences →
100–400 ev/s), 300+ agences donnent **600 à 1 500 ev/s en moyenne**, avec des
pointes de **3 000 à 6 000** à l'ouverture et pendant les traitements de fin de
journée. Le trafic wallet de l'EDP s'y ajoute et n'est pas dans ce ratio.
**Cette estimation est le chiffre le plus fragile de ce document** : elle doit
être remplacée par un comptage réel sur votre SI avant tout engagement.

**Et c'est là que la mesure devient gênante.** À ×1,72 pour deux instances, la
mise à l'échelle est nettement sous-linéaire : deux instances tiennent
**647 ev/s**, et rien au-delà de deux n'a été mesuré. Pour 1 000 ev/s soutenus,
je ne peux donc pas produire de preuve — seulement une extrapolation qui, au
rythme marginal observé, demanderait plus de quatre instances.

Conséquence pratique, et c'est une décision à prendre avant un engagement :
**le traitement concurrent dans le pipeline n'est plus une optimisation, c'est
un prérequis.** Chaque instance traite aujourd'hui ses messages séquentiellement
— les 3,4 ms sont dominés par des attentes, pas par du calcul. Le passage au
traitement concurrent change la sémantique de validation des offsets Kafka et
doit être tranché explicitement.

**Stockage, recalculé** à 150 octets par événement sur disque (`débit × 86 400 ×
jours × octets`) :

| Débit moyen | Par jour | 90 jours | 365 jours | 5 ans |
|---|---|---|---|---|
| 600 ev/s | ~7,8 Go | ~700 Go | ~2,8 To | ~14 To |
| 1 000 ev/s | ~13 Go | ~1,2 To | ~4,7 To | ~24 To |
| 1 500 ev/s | ~19 Go | ~1,8 To | ~7,1 To | ~35 To |

Ajouter **50 % de marge** : une base ClickHouse pleine est une panne pendant
laquelle plus rien n'est détecté. Et noter la colonne « 5 ans » : si votre
obligation de conservation du journal d'audit est pluriannuelle, c'est elle qui
dimensionne le stockage, pas la fenêtre d'exploitation.

**Matériel révisé** par rapport au document 23 :

| Rôle | Nœuds | Par nœud | Disque |
|---|---|---|---|
| Données — ClickHouse | 3 | 16 vCPU · 64 Go | NVMe, §3 ci-dessus |
| Données — PostgreSQL + Redis | 2 (primaire + réplique) | 16 vCPU · 64 Go | 1 To NVMe |
| Bus — Kafka | 3 | 8 vCPU · 32 Go | 1 To NVMe |
| Services + interface | 3 | 16 vCPU · 64 Go | 200 Go |

> **NVMe, pas de SAN partagé** pour ClickHouse et Kafka. C'est la seule
> exigence matérielle sur laquelle je ne transigerais pas, et elle compte
> davantage à 1 000 ev/s qu'à 200.

---

## 4. Le CBS : ce que « connecteur core banking » veut dire exactement

Point à clarifier avant qu'il ne devienne un malentendu en phase projet.

La plateforme accepte quatre formats : **JSON, CEF, syslog, LEEF**. Un événement
déclaré avec un `source_type` valant `cbs`, `banking`, `payment`, `atm`,
`swift` ou `monetique` est classé en catégorie `Transaction` et suit le reste de
la chaîne normalement.

Ce qui n'existe pas : **aucun analyseur ISO 8583, aucun analyseur de message
SWIFT MT ou MX, aucun connecteur vers un progiciel bancaire nommé.** Le
raccordement du CBS suppose donc que votre core banking sache émettre du syslog
ou du JSON sur HTTP — ce que la plupart font pour leurs journaux applicatifs,
et aucun pour ses flux transactionnels natifs.

Pour alimenter la détection de fraude en transactions, il faut **écrire un
connecteur**. C'est une tâche identifiée, pas un obstacle : le registre de
connecteurs et le suivi de santé des sources existent depuis peu. Mais le
connecteur CBS lui-même est à produire, et son coût dépend entièrement du
progiciel que vous exploitez — ce que ce document ne connaît pas.

---

## 5. En résumé : ce que vous achetez, ce que vous ne devez pas croire acheter

**Vous achetez, et c'est démontrable :**

- une chaîne de collecte et de détection mesurée de bout en bout, avec des
  chiffres reproductibles par une commande ;
- un journal d'audit immuable et vérifiable ligne à ligne, sans expiration par
  défaut — la pièce la plus demandée en contrôle et la plus difficile à
  reconstituer après coup ;
- un moteur de corrélation à fenêtre temporelle avec 16 détections signées et
  un canal de publication de contenu indépendant du code ;
- un module de conformité qui relie contrôle et preuve, avec ISO 27001 livré et
  DNSSI/09-08 désormais enregistrables ;
- une séparation par tenant utilisable pour banque et EDP, jusqu'aux
  partitions de stockage.

**Vous n'achetez pas, et il ne faut pas le laisser croire :**

- **un moteur de fraude wallet** — le module est un squelette de scoring sans
  vélocité, et ses alertes n'atteignent aujourd'hui aucun consommateur ;
- **une conformité DORA** — ni applicable au Maroc, ni couverte sur deux de ses
  cinq piliers ;
- **une cartographie DNSSI ou 09-08 prête à l'emploi** — les référentiels sont
  enregistrables, les contrôles sont à saisir ;
- **une ségrégation garantie par la base** — elle est garantie par le code, ce
  qui n'est pas le même niveau de preuve devant un régulateur ;
- **un connecteur core banking** — il est à écrire, et son coût dépend de votre
  progiciel ;
- **une notification automatique au maCERT** — le délai est mesurable, la
  déclaration est manuelle ;
- **1 000 ev/s** — 647 ev/s sont mesurés sur deux instances, le reste est une
  extrapolation.

---

## 6. L'ordre dans lequel je traiterais les écarts

Classement par ce qui bloque un agrément ou une mise en production, pas par
facilité.

| | Chantier | Pourquoi d'abord | Estimation |
|---|---|---|---|
| 1 | **Comptage réel du volume** sur votre SI | Tout le dimensionnement, et donc le coût d'infrastructure, repose sur une extrapolation | 5 j |
| 2 | **RLS PostgreSQL** pour la ségrégation banque/EDP | Exigence d'agrément ; aujourd'hui garantie par le code seul | 15–25 j |
| 3 | **Traitement concurrent du pipeline** | Prérequis de débit à 300 agences, pas une optimisation | 20–30 j |
| 4 | **Raccordement fraude → moteur de détection** + règles wallet | Le besoin métier de la filiale EDP ; le moteur existe déjà | 40–60 j |
| 5 | **Connecteur CBS** | Sans lui, pas de transaction à analyser | à chiffrer |
| 6 | **Contrôles ISO 27001, DNSSI, 09-08** pré-chargés | Paramétrage, pas développement | 15–25 j |
| 7 | **Droits des personnes (09-08)** et registre de traitement | Exigence CNDP non couverte | 20–30 j |

Les points 1 à 3 sont à traiter avant tout engagement contractuel sur des
volumes ou sur la séparation des périmètres. Les points 4 à 7 peuvent se
contractualiser par lots.
