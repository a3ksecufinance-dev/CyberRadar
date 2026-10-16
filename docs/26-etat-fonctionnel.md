# 26 — État fonctionnel : ce qui est assuré, ce qui manque

Inventaire des fonctions réellement tenues, établi en lisant le code et la CI,
pas la spécification. Il sert à deux décisions : ce qu'on peut vendre au Maroc
aujourd'hui, et ce qui sépare la plateforme d'un produit défendable à
l'international.

La thèse qui le gouverne est au [document 25](25-positionnement.md) : une
plateforme de **sécurité** pour institution financière, dont la conformité est
une sortie.

---

## 1. Méthode : quatre niveaux de preuve

Une fonction n'est pas « faite » ou « pas faite ». Elle est à un niveau de
preuve, et le niveau est ce qui décide si on peut l'annoncer.

| Niveau | Ce que ça veut dire | Ce qu'on peut en dire |
|---|---|---|
| **N1 — Démontré** | Exercé de bout en bout, en CI, à chaque commit | On le montre en démonstration |
| **N2 — Mesuré** | Un chiffre reproductible par une commande | On donne le chiffre |
| **N3 — Testé** | Testé unitairement, jamais exercé en chaîne | On l'annonce avec prudence |
| **N4 — Présent** | Du code et des routes, aucune preuve de fonctionnement | On ne l'annonce pas |

---

## 2. N1 — Ce qui est démontré de bout en bout

Le job CI `e2e-chain` déroule neuf étapes à chaque commit, sur une
infrastructure réelle. C'est la colonne vertébrale du produit, et la seule
partie dont je dirais sans réserve qu'elle fonctionne :

| # | Étape | Service exercé |
|---|---|---|
| 1 | une règle de détection est écrite | `siem` |
| 2 | un connecteur est raccordé | `collector` |
| 3 | l'attaque commence : six échecs d'authentification | `collector` → `pipeline` |
| 4 | le moteur de règles lève une alerte | `siem` |
| 5 | un analyste la promeut en cas | `siem` |
| 6 | un playbook de confinement est écrit | `soar` |
| 7 | le playbook s'exécute jusqu'au bout | `soar` |
| 8 | l'adresse est bloquée au niveau réseau | `netsec` |
| 9 | la piste d'audit nomme le playbook | `audit` |

Sept services sur trente-deux. C'est peu, et c'est exactement le parcours
qu'un acheteur veut voir : de l'événement brut à l'action de confinement
tracée.

S'y ajoutent, démontrés par la CI sans être dans cette chaîne : les
**51 migrations PostgreSQL** appliquées à une base vierge puis réappliquées
sans effet (ce qui prouve qu'une nouvelle version est déployable sur une
installation existante), les **migrations ClickHouse**, et le **typecheck,
lint et build du frontend**.

## 3. N2 — Ce qui est mesuré

Chiffres reproductibles par `make bench` et `bench -only nfr|kpi`, obtenus sur
cette infrastructure et avec cet outil de mesure — un plancher, pas une
spécification :

| | Mesuré |
|---|---|
| Débit tenu, une instance | **376 ev/s** |
| Coût unitaire d'un événement | **3,4 ms** |
| Mise à l'échelle, deux instances | **×1,72** (647 ev/s) |
| Latence de traversée | **p95 11 ms** |
| Reprise après interruption | **313 200 événements en 15 min** par instance |
| Compression ClickHouse | **4,7×** sur la table réelle |

Indicateurs de suivi : **KPI 7/8**, **NFR 5/14**. Les neuf NFR restants ne sont
pas en échec — ils ne sont pas encore vérifiables, ce qui n'est pas la même
chose et ne doit pas être présenté comme tel.

## 4. N3 — Implémenté et testé, jamais démontré en chaîne

- **Enrichissement** : géolocalisation, score de menace, rapprochement
  d'indicateurs dans le pipeline avant le moteur de règles.
- **Drapeaux bancaires** `cbs_impact` / `swift_impact`, renseignés depuis le
  type de source.
- **Transaction signalée → moteur de détection** : publication sur
  `crp.events.enriched` en événement canonique.
- **Pack de détection signé** : 16 détections, généalogie, adoption et remise à
  niveau par tenant, publication indépendante du code, rotation et révocation
  des clés.
- **Multi-tenant** : filtre `tenant_id` sur chaque requête, partitions
  ClickHouse par tenant.
- **Journal d'audit immuable** : checksum SHA-256 par ligne, écriture seule,
  sans expiration par défaut.
- **Registre et santé des connecteurs** : vivant / en retard / silencieux.
- **UEBA**, **chemins d'attaque** (Neo4j), **graphe de connaissance**,
  **Copilot** (RAG sur pgvector) : testés unitairement, non exercés en chaîne.

## 5. N4 — Présent, non exercé

Douze domaines — `cspm`, `dspm`, `dlp`, `ot`, `scs`, `easm`, `apifw`, `iga`,
`mobile`, `pam`, `netsec`, `risk` — pour environ 2 000 lignes chacun, soit des
routes CRUD et un test de passage unique écrit par lot pour qu'aucun service ne
soit à zéro.

Vingt-cinq des trente-deux services ont **un ou deux fichiers de test**, le
plus souvent un aller-retour en base. Sept seulement ont une couverture de
comportement : `tenant`, `siem`, `attackpath`, `collector`, `knowledgegraph`,
`copilot`, `fraud`.

Le sort de ces douze est tranché au document 25 : drapeau de fonctionnalité,
désactivés par défaut.

---

## 6. Le trou au milieu : on ne peut pas chercher un événement

Constat trouvé en établissant cet inventaire, et le plus important de tous.

La table `crp_audit.cyber_events` reçoit chaque événement normalisé et
enrichi. **Aucune API et aucun écran ne permet de la lire.** Les seules
requêtes dans tout le dépôt sont l'écriture du pipeline et le calcul de santé
des connecteurs.

Concrètement : un analyste reçoit une alerte et **ne peut pas voir les
événements autour**. Il ne peut pas pivoter sur l'adresse IP, dérouler
l'activité du compte dans l'heure précédente, ni vérifier si le schéma s'est
déjà produit. C'est la boucle de travail numéro un d'un analyste SOC, et elle
n'existe pas.

Ce n'est pas une lacune de confort. Un SIEM sans recherche d'événements est un
produit qu'un analyste refuse à la première démonstration où on lui demande
« et maintenant, montrez-moi ce qui s'est passé avant ». Je le place en tête
des manques pour les deux marchés.

**Depuis, c'est fait.** `GET /api/v1/siem/events` cherche sur une fenêtre
bornée avec seize filtres, et l'onglet **Recherche** du SIEM porte la boucle :
fenêtre glissante, texte libre dans la charge brute, filtres, panneau de
détail avec la charge brute, et le **pivot** — cliquer une adresse ou un
compte dans un résultat relance la recherche dessus, qui est le geste que
l'analyste répète.

Ce qui reste sur ce point : l'écran n'a pas encore été exercé contre une pile
réelle (le parcours Playwright est écrit, pas joué), et la pagination est en
`offset`, ce qui se dégrade en profondeur sur une grande fenêtre.

---

## 7. Ce qui manque pour le Maroc

| Manque | Pourquoi ça bloque | Estimation |
|---|---|---|
| **Connecteur core banking** | Aucun analyseur ISO 8583 ni SWIFT MT/MX. Sans transactions en entrée, la thèse ne s'exerce pas | à chiffrer |
| **Règles de fraude wallet** | Le moteur sait compter dans une fenêtre ; personne ne lui a dit quoi compter | 40–60 j |
| **RLS PostgreSQL** | La ségrégation banque / filiale EDP tient au code applicatif, pas à la base. Relève de l'agrément | 15–25 j |
| **Contrôles DNSSI, 09-08, ISO 27001 pré-chargés** | Les référentiels sont enregistrables depuis la migration 000050, les contrôles sont à saisir | 15–25 j |
| **Droits des personnes (09-08)** et registre de traitement | Exigence CNDP non couverte. À noter : la plateforme est elle-même un traitement à déclarer | 20–30 j |
| **Notification maCERT / DGSSI** | Le délai est mesurable, la déclaration reste manuelle | 10–15 j |
| **Interface en arabe** | Deux langues livrées, `en` et `fr`. Exigé par une partie du secteur public et par certaines banques | 10–15 j |
| **Traitement concurrent du pipeline** | 647 ev/s mesurés ; une banque de 300 agences en demande 600 à 1 500 | 20–30 j |

À quoi s'ajoute un prérequis qui n'est pas du code : **la certification
ISO 27001 de l'éditeur**. Une direction des achats bancaire la demandera avant
de confier sa télémétrie de sécurité à un tiers, et aucune ligne de Go ne la
remplace.

## 8. Ce qui manque pour l'international

Les manques marocains restent valables. S'y ajoutent ceux qui séparent la
plateforme d'un produit comparable à Splunk ES, QRadar, Sentinel ou Wazuh.

**Le premier, maintenant que la recherche existe : la couverture des
sources.** Quatre formats
(JSON, CEF, syslog, LEEF) et six analyseurs, contre plusieurs centaines de
connecteurs chez un concurrent établi. C'est le critère numéro un d'un appel
d'offres SIEM, et l'écart est d'un ordre de grandeur. C'est aussi le chantier
dont le coût croît linéairement : il n'y a pas d'astuce, il faut les écrire.

| Manque | Conséquence | Remarque |
|---|---|---|
| **Couverture des sources** | Disqualifiant en appel d'offres | Le seul vrai levier : un SDK de connecteur, pour que le client et les partenaires en écrivent |
| **Compatibilité Sigma** | Coupe la plateforme de l'écosystème ouvert de détection | **Le meilleur rapport valeur / effort du document** : un traducteur Sigma → notre format donne accès à des milliers de règles publiques. Notre moteur a déjà `field_matches` et `threshold` |
| **Alignement OCSF ou ECS** | Frottement à chaque intégration | Notre schéma canonique est propriétaire |
| **Volume de détections** | 16 règles, 9 tactiques MITRE sur 14, très peu par tactique | Partiellement résolu par Sigma |
| **Échelle** | 647 ev/s mesurés ; une grande entreprise part de 10 000 EPS | Traitement concurrent, puis mesure au-delà de deux instances |
| **Haute disponibilité** | Jamais démontrée | Un acheteur grand compte l'exige avant le prix |
| **Agent / collecteur déporté** | La source doit savoir pousser du syslog ou du HTTP | Beaucoup de sources ne savent pas |
| **SOC 2 Type II** | Barrière à l'entrée sur le marché nord-américain | Organisationnel, pas technique |
| **Mode SaaS et multi-région** | Le produit est conçu pour l'installation sur site | Choix assumé ; il ferme un segment |
| **Facturation et cloisonnement MSSP** | Le multi-tenant existe, le modèle infogérance non | Le canal le plus rapide pour un éditeur de cette taille |
| **Langues** | `en` et `fr` | L'arabe et l'espagnol ouvrent deux marchés |

---

## 9. Dans quel ordre

Classé par ce qui débloque une vente, pas par facilité.

| | Chantier | Sert | Estimation |
|---|---|---|---|
| ~~1~~ | ~~**Recherche d'événements**~~ | — | **livrée** (§ 6) |
| 1 | **Comptage réel du volume** chez un client | Les deux | 5 j |
| 2 | **Traducteur Sigma** | International d'abord, Maroc aussi | 20–30 j |
| 4 | **Connecteur CBS + règles wallet** | Maroc, cœur de la thèse | 40–60 j + à chiffrer |
| 5 | **RLS PostgreSQL** | Maroc, exigence d'agrément | 15–25 j |
| 6 | **Traitement concurrent** | Les deux | 20–30 j |
| 7 | **SDK de connecteur** | International | 30–45 j |
| 8 | **Contrôles pré-chargés + droits 09-08** | Maroc | 35–55 j |

Le premier est à faire avant tout engagement : tout le dimensionnement repose
aujourd'hui sur une extrapolation.

Le troisième mérite son rang : c'est le seul chantier de cette liste qui
multiplie la valeur sans multiplier l'effort, parce qu'il fait travailler
l'écosystème à notre place.
