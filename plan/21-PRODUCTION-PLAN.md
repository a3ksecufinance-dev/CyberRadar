# Plan de passage en production

> **Repris par [`23-PLAN-EXECUTION.md`](23-PLAN-EXECUTION.md)**, qui couvre le
> périmètre complet retenu (les 346 user stories) et dont ce document forme
> les lots L0, L1, L2 et L13. Le détail tâche par tâche ci-dessous reste la
> référence pour ces lots ; la séquence d'ensemble est dans `23`.

> Date : 2026-10-02 · Périmètre : `backend/` + `frontend/` + déploiement
> Remplace la Phase 4 de [`19-AUDIT-AND-ROADMAP.md`](19-AUDIT-AND-ROADMAP.md) §5
> et consolide les « Reste ouvert » dispersés dans ce document.
>
> **Chemin critique : 7 mois** à trois ingénieurs. Les chiffres d'effort sont les
> miens, pas ceux de l'équipe qui les tiendra : à relire avant de s'engager.

---

## 0. Où nous en sommes, mesuré

Tout ce qui suit a été compté dans le dépôt, pas estimé.

| | Valeur |
|---|---|
| Services | **32** — 30 servent une API, 1 connecteur syslog, 1 travailleur |
| Routes d'API | 477, chacune avec sa permission vérifiée à l'exécution |
| Lignes de Go (hors tests) | 77 521 |
| Lignes de test | 12 369 — **ratio 1:6,3** |
| Tests | 383, dans 51 fichiers |
| **Services sans aucun test** | **17 sur 32** |
| Tables PostgreSQL | 142, sur 47 migrations |
| Tables ClickHouse | 18, dans 7 bases |
| Permissions | 69, sur 10 rôles |
| Détections livrées | 15, signées, livrables hors du code |
| Politiques paramétrables | 4, versionnées et datées, 17 préréglages |
| Dockerfiles | 32, multi-étages vers `scratch` |
| Infrastructure as code | **aucune** — ni Helm, ni Terraform, ni manifeste |
| Débit mesuré | **aucun** |
| Latence p95 mesurée | **aucune** |

**Ce que les phases 0 à 3 de l'audit ont réellement livré** : l'authentification
RS256 avec une clé privée unique, un middleware d'autorisation partagé qui a
remplacé 30 copies divergentes, le RBAC à l'exécution, l'identité de service,
l'observabilité instrumentée, la DLQ Kafka, les quinze actions SOAR réelles,
Neo4j derrière une abstraction, le RAG du Copilot, les quatre politiques
paramétrables, et le catalogue de détection signé publié hors du code.

**Ce qui n'a pas commencé** : tout le déploiement.

---

## 1. Les cinq verrous

Il y a beaucoup à faire. Mais cinq choses seulement **empêchent** la production,
au sens où aucune quantité de travail sur le reste ne les contourne.

### V1 — Rien n'est déployable

Pas de Helm, pas de Terraform, pas de manifeste. `docker-compose.yml` expose
41 ports, ne pose **aucune limite mémoire sur 42 services**, et 34 d'entre eux
n'ont pas de `healthcheck`. Les images ne sont poussées dans aucun registre : la
CI construit et jette.

### V2 — Rien n'est chiffré en transit

HTTP en clair sur l'API et entre services. `sslmode=disable` sur PostgreSQL.
Aucune banque ne mettra ses journaux de sécurité dans un système qui les
transporte en clair, et aucun audit ne le laissera passer.

### V3 — Les secrets sont ceux du dépôt

`crp_password_dev`, `crp-vault-dev-token`, et **la paire de clés JWT est
versionnée dans git**. Le secret du compte SOAR vaut littéralement
`change-me-create-the-account-first` — et le compte n'existe pas, donc toutes
les actions de playbook échouent sur une installation fraîche.

### V4 — 17 services sur 32 n'ont aucun test

Dont **`tenant`**, qui porte les quatre politiques paramétrables : une erreur
là déplace silencieusement les échéances de remédiation de tous les clients.
Et **`collector`**, le point d'entrée des événements.

### V5 — Le chiffre annoncé n'est pas mesuré

`plan/00-MASTER-PLAN.md` annonce **100 K EPS**. Rien ne l'a jamais mesuré. Si
un appel d'offres le challenge et que la réalité est 5 K, l'affaire est perdue
sur place — et c'est le genre de chiffre qu'un concurrent fait vérifier.

> **C'est le risque commercial le plus élevé du projet**, plus que n'importe
> quel trou fonctionnel. Un trou fonctionnel se comble ; un chiffre démenti en
> réunion ne se rattrape pas.

---

## 2. Les cinq jalons

Chaque jalon a un **critère de sortie testable**. Pas « la phase est finie » mais
« cette commande rend ce résultat ».

```
J1 ─────────▶ J2 ─────────▶ J3 ─────────▶ J4 ─────────▶ J5
Sandbox      Socle de      Consolidation  Haute dispo   Validation
cloud        confiance     + Kubernetes   + reprise     externe
3 sem.       6 sem.        8 sem.         6 sem.        6 sem.
                                                         │
                                            ┌────────────┘
                                            ▼
                                     Premier client
                                     en production
```

| Jalon | Durée | Ce qu'il permet |
|---|---|---|
| **J1** — Sandbox cloud défendable | 3 sem. | Un POC client sur un VPC, sans rougir |
| **J2** — Socle de confiance mesurable | 6 sem. | Des chiffres à opposer à un appel d'offres |
| **J3** — Consolidation et Kubernetes | 8 sem. | Un déploiement reproductible et exploitable |
| **J4** — Haute disponibilité et reprise | 6 sem. | Un engagement de service tenable |
| **J5** — Validation externe | 6 sem. | Ce qu'une banque exige pour signer |

**J1 est parallélisable avec le travail produit. J3 ne l'est pas** : consolider
32 services puis écrire les charts est la moitié du travail d'écrire 32 charts
puis consolider.

---

## 3. Les décisions qui ne sont pas les miennes

Cinq choix bloquent le plan et appartiennent au client, pas à l'ingénierie. Les
trancher avant J1 économise un mois.

| Décision | Pourquoi elle bloque | Avant quand |
|---|---|---|
| **Quel cloud** | Détermine la forme de J3 et J4 : Terraform AWS, Azure ou OVH ne sont pas interchangeables, et une banque française a souvent une contrainte de souveraineté | **avant J1** |
| **Les 12 domaines superficiels : livrer, masquer, ou couper** | Douze domaines « CRUD + lectures » livrés à une banque invitent la question qui détruit la confiance dans les six vrais | **avant J1** |
| **Le chiffre de débit qu'on défend** | 100 K EPS est annoncé et non mesuré. Soit on le tient après mesure, soit on le change avant qu'un prospect le challenge | **avant J2** |
| **La matrice RBAC** | Qui peut lire les actifs OT, qui approuve un accès privilégié : c'est une décision d'organisation, pas de code. La matrice actuelle est « un point de départ défendable, pas une politique arrêtée » | **avant J5** |
| **La rétention** | `crp_audit.audit_logs` n'a volontairement aucun TTL. L'obligation réglementaire du client la fixe | **avant J4** |

Ma recommandation sur la deuxième, parce que c'est la plus coûteuse à
repousser : **masquer les douze**, derrière un drapeau de fonctionnalité par
domaine. Les six domaines réels tiennent une démonstration de 45 minutes et une
question de suivi. Les douze autres ne tiennent pas la question de suivi, et le
prospect qui en gratte un se demande ensuite ce que valent les six autres.

---

## 4. J1 — Sandbox cloud défendable · 3 semaines

**But** : un POC client sur un VPC, avec du TLS, des secrets qui ne sont pas
dans git, et des chiffres de performance.

### J1.1 — Terminaison TLS et point d'entrée unique · 4 j

Un reverse proxy devant les 30 services, routage par préfixe de chemin, TLS
terminé là. Les 41 ports ne sont plus exposés : un seul l'est.

C'est aussi là que devra vivre la vérification du jeton, aujourd'hui répétée
31 fois — par le même code, mais répétée. **Ne pas la déplacer maintenant** :
elle marche, et la déplacer sous pression de POC est la façon de créer un trou
d'authentification.

- [ ] Reverse proxy (Caddy ou nginx) avec routage `/<service>/api/v1/*`
- [ ] TLS, certificat de l'autorité du client ou Let's Encrypt
- [ ] `CORS_ALLOWED_ORIGINS` et `NEXT_PUBLIC_API_URL` recâblés sur un seul hôte
- [ ] PostgreSQL en `sslmode=require`

**Sortie** : `curl https://<hôte>/siem/api/v1/siem/alerts` répond, et aucun port
de service n'est joignable depuis l'extérieur du VPC.

### J1.2 — Les secrets sortent du dépôt · 2 j

- [ ] Paire JWT générée à l'installation, jamais versionnée ; retirer la paire
      de développement de l'historique si elle y est
- [ ] Tous les mots de passe générés, dans le gestionnaire de secrets du cloud
- [ ] Vault en AppRole plutôt qu'en jeton racine, une policy par service limitée
      à `crp/<service>/*`
- [ ] **Les 29 services autres qu'`identity` lisent encore leurs secrets depuis
      l'environnement** — les basculer sur Vault

**Sortie** : `git ls-files | grep -E '\.pem$|\.key$'` ne rend rien, et un
`grep -r password_dev` sur la configuration déployée ne rend rien.

### J1.3 — Le compte de service SOAR · 1 j

Le *rôle* `soar_executor` est amorcé par la migration 32. Le *compte* ne l'est
pas. Toutes les actions de playbook échouent donc sur une installation fraîche —
et c'est l'une des six démonstrations qui valent quelque chose.

- [ ] Commande d'amorçage du compte, avec secret généré
- [ ] Le secret va dans Vault, pas dans l'environnement
- [ ] Un test de bout en bout qui exécute un playbook et vérifie l'effet chez
      `netsec`

**Sortie** : un playbook `block_ip` lancé depuis l'interface produit une
politique de refus visible dans `netsec`.

### J1.4 — Limites, sondes, images · 3 j

- [ ] Limite mémoire et CPU sur les 42 services du compose
- [ ] Les 34 `healthcheck` manquants
- [ ] Job de CI qui construit et **pousse** les 32 images vers un registre, avec
      un scan Trivy bloquant sur les vulnérabilités critiques
- [ ] `USER` non-root dans les Dockerfiles (ils sont déjà sur `scratch`, donc
      c'est une ligne)

**Sortie** : les images sont dans le registre avec un tag d'un commit, et le
scan passe.

### J1.5 — Migrations à état · 3 j

Un POC qui dure trois mois recevra des changements de schéma. Aujourd'hui le
seul chemin est `reset`.

- [ ] Adopter `golang-migrate` (ou équivalent) sur les 47 migrations existantes
- [ ] Écrire les `down` manquantes, ou décider explicitement de ne pas en avoir
- [ ] Un job de migration qui tourne avant les services, pas à côté

**Sortie** : appliquer les migrations deux fois de suite n'échoue pas, et une
48ᵉ migration s'applique sur une base déjà migrée.

### J1.6 — Le jeu de démonstration étalé dans le temps · 2 j

**Le meilleur rapport effort/valeur du plan.** Les lignes de base UEBA ne se
forment pas aujourd'hui parce que `demoseed` injecte en rafale. Résultat : les
détections comportementales — la meilleure différenciation du produit — ne sont
pas démontrables.

- [ ] Horodater les événements injectés sur une fenêtre de plusieurs jours
- [ ] Vérifier que `ueba_profiles` se peuple et que `geo_anomaly` et
      `anomalous_hours` se déclenchent
- [ ] Les deux détections SIEM qui en dépendent lèvent une alerte

**Sortie** : après `make demo`, `ueba_anomalies` est non vide et au moins une
détection à base comportementale a levé une alerte.

### J1.7 — Les trois chiffres · 3 j

Aucun n'existe. Ce sont les trois premières questions d'une DSI.

- [ ] **Débit d'ingestion** : événements/s avant que la DLQ se remplisse, mesuré
      sur le connecteur syslog et sur `/events/ingest`
- [ ] **Latence API p95** : l'histogramme est déjà borné autour de 200 ms, il
      suffit de charger
- [ ] **Temps de détection** : horodatage d'entrée → horodatage de l'alerte
- [ ] Les trois publiés dans un tableau de bord Grafana, pas dans un tableur

**Sortie** : trois nombres, avec la configuration matérielle qui les a produits.

### J1.8 — Sauvegarde · 1 j

- [ ] `pg_dump` planifié vers un stockage objet, chiffré
- [ ] **Une restauration exécutée**, pas une procédure écrite

**Sortie** : une base restaurée depuis une sauvegarde répond à `make smoke`.

> **Critère de sortie de J1** : un POC client tourne sur un VPC, en HTTPS, avec
> des secrets gérés, les six domaines réels démontrables, une sauvegarde
> restaurée, et trois chiffres de performance mesurés.

---

## 5. J2 — Socle de confiance mesurable · 6 semaines

**But** : des chiffres à opposer à un appel d'offres, et un filet de sécurité
sous les changements.

### J2.1 — Les 17 services sans test · 3 sem.

Par ordre de dégât si ça casse, pas par ordre alphabétique :

| Priorité | Service | Pourquoi d'abord |
|---|---|---|
| 1 | **`tenant`** | Porte les quatre politiques. Une erreur déplace silencieusement les échéances de **tous** les clients |
| 2 | **`collector`** | Le point d'entrée. Une erreur perd des événements sans bruit |
| 3 | `notification` | Une alerte non envoyée est une alerte qui n'existe pas |
| 4 | `ti` | Pilote la correspondance d'indicateurs du pipeline |
| 5 | `compliance`, `risk` | Produisent des chiffres qu'un régulateur lit |
| 6 | les 11 autres | Au moins les lectures, par Testcontainers |

- [ ] Testcontainers pour PostgreSQL, ClickHouse et Kafka, une fois pour toutes
- [ ] Cible : **60 % de couverture sur les six domaines réels plus `tenant` et
      `collector`**, et pas zéro sur les onze autres
- [ ] Un test par politique qui vérifie que le préréglage neutre **ne déplace
      aucun chiffre** — c'est la promesse qui protège les clients existants

**Sortie** : `go test -cover` rend ≥ 60 % sur les huit services nommés, et aucun
service n'est à 0.

### J2.2 — Le parcours de bout en bout, scripté · 1 sem.

`make smoke` prouve les lectures. Rien ne prouve la chaîne.

- [ ] Script : injecter un événement → l'alerte apparaît → créer un cas →
      lancer un playbook → **vérifier l'effet chez `netsec`** → l'audit porte
      l'identité du playbook et non celle de l'analyste
- [ ] Chronométré, pour que « temps de détection » soit une mesure et non un
      espoir
- [ ] Dans la CI, contre une plateforme éphémère

**Sortie** : un seul `make e2e-chain` qui passe ou échoue, avec son chronomètre.

### J2.3 — Retirer les bêtas des dépendances d'authentification · 3 j

`next-auth@5.0.0-beta.19` est une **bêta sur le chemin d'authentification**.
Aucun audit bancaire ne laissera passer ça.

- [ ] Figer sur la dernière version stable de la v4, ou attendre la v5 stable
- [ ] `govulncheck` et `npm audit` bloquants en CI, pas informatifs

**Sortie** : aucune dépendance en `beta`, `rc` ou `alpha` dans
`frontend/package.json`.

### J2.4 — Fermer les trous d'observabilité · 1 sem.

- [ ] `pipeline-worker` est scruté sur `:9100` et **n'expose aucun serveur
      HTTP** — la cible Prometheus pointe dans le vide
- [ ] Le connecteur syslog n'expose que les métriques Go : il lui manque
      messages traités et échecs de parsing **par format** — sur le chemin le
      plus volumineux de la plateforme
- [ ] Alertes Prometheus : la configuration les prévoit en commentaire. Au
      minimum : `crp_sliding_window_fallback_total > 0`, profondeur de la DLQ,
      latence p95 au-delà de la cible, un service qui ne répond plus
- [ ] Alertmanager, et un tableau de bord Grafana versionné

**Sortie** : une alerte se déclenche quand on coupe Redis, et une autre quand on
remplit la DLQ.

### J2.5 — Durcissement de sécurité applicative · 1,5 sem.

- [ ] **Limitation de débit** par tenant et par adresse, au point d'entrée
- [ ] **Révocation de jeton** : aujourd'hui un jeton reste valide jusqu'à
      expiration même compte désactivé. Une liste de révocation dans Redis, ou
      réduire la durée de vie et l'assumer
- [ ] Les refus d'autorisation dans un flux exploitable, pour qu'un 403 répété
      devienne une détection
- [ ] Limitation par tenant **à l'ingestion** : un tenant bavard sature
      aujourd'hui le pipeline des autres

**Sortie** : un client qui dépasse son quota reçoit 429, et un compte désactivé
perd l'accès en moins d'une minute.

> **Critère de sortie de J2** : la couverture est mesurée et suffisante là où ça
> compte, la chaîne complète est testée en CI, et le débit annoncé
> commercialement est celui qui a été mesuré.

---

## 6. J3 — Consolidation et Kubernetes · 8 semaines

**But** : un déploiement reproductible, et un nombre d'unités qu'une équipe
d'exploitation peut tenir.

### J3.1 — Consolider 32 services vers 8 à 10 · 4 sem.

**À faire avant les charts, pas après.** Écrire 32 charts Helm puis en fusionner
24 est la moitié du travail refait.

Le découpage que je recommande, par cohésion de données et non par domaine
fonctionnel :

| Unité | Services absorbés | Pourquoi ensemble |
|---|---|---|
| `crp-core` | tenant, identity, audit, notification | Le socle. Partagent les identités et la configuration |
| `crp-ingest` | collector, syslog, pipeline | La chaîne d'ingestion. Se dimensionnent ensemble |
| `crp-detect` | siem, ueba, ti | Lisent le même flux normalisé, partagent Redis |
| `crp-expose` | vuln, asset, attackpath, easm, cspm, dspm, scs | Toutes parlent du parc et de ce qui est exposé |
| `crp-respond` | soar, ir | L'automatisation et le dossier |
| `crp-govern` | compliance, risk, iga, dlp, pam | Ce qu'un auditeur lit |
| `crp-insight` | dashboard, knowledgegraph, copilot | Les lectures transverses |
| `crp-edge` | apifw, netsec, mobile, ot, fraud | Les périmètres |

- [ ] Un module Go par unité, les paquets de domaine conservés tels quels
- [ ] **Les routes ne changent pas** : le contrat d'API est préservé, donc
      l'interface et les 477 routes documentées restent valides
- [ ] `internal/pkg/apicheck` et la référence API générée doivent continuer à
      passer sans modification — c'est le test que la consolidation n'a rien
      cassé

**Sortie** : 8 à 10 binaires, `make smoke` vert, et
`make docs-api-check` toujours vert.

### J3.2 — Helm et Terraform · 3 sem.

- [ ] Un chart par unité, un chart parapluie
- [ ] `ConfigMap` pour la configuration, `Secret` externes (External Secrets ou
      l'équivalent du cloud) pour les secrets
- [ ] Sondes `liveness` et `readiness` distinctes : **`/health` répond « ok » dès
      que le processus écoute** et ne vérifie ni PostgreSQL ni Kafka. Il faut une
      sonde de disponibilité réelle, qui soit différente
- [ ] `NetworkPolicy` : chaque unité ne joint que ce dont elle a besoin
- [ ] Terraform pour le VPC, les bases gérées, le registre, les secrets
- [ ] Déploiement en un `helm upgrade --install`, pas en douze étapes

**Sortie** : un environnement complet créé depuis zéro par Terraform + Helm, en
une commande chacun, deux fois de suite, avec le même résultat.

### J3.3 — Faire du contenu signé le chemin normal · 1 sem.

Le mécanisme existe et il est exercé en CI. Ce qui manque est l'infrastructure.

- [ ] Héberger le canal : un bucket derrière un CDN, en lecture publique ou
      authentifiée — c'est la décision laissée ouverte en
      [`20-CONTENT-RELEASE.md`](20-CONTENT-RELEASE.md) §8
- [ ] La clé privée dans un HSM ou un coffre signataire, plus un fichier en 0600
- [ ] Le magasin de confiance distribué comme une ressource de déploiement
- [ ] Un job qui publie à chaque étiquette de version

**Sortie** : un déploiement installe une version de contenu depuis le canal
public, et `-affected` répond sur la clé qui l'a signée.

> **Critère de sortie de J3** : un environnement se crée et se détruit par
> commande, avec 8 à 10 unités, et le contenu de détection arrive par le canal
> publié.

---

## 7. J4 — Haute disponibilité et reprise · 6 semaines

**But** : un engagement de service qu'on peut tenir, et une panne dont on
revient.

### J4.1 — Haute disponibilité · 3 sem.

- [ ] PostgreSQL : réplication, bascule testée. Une base gérée par le cloud est
      le choix par défaut, et le bon
- [ ] Kafka : trois courtiers, facteur de réplication 3, `min.insync.replicas=2`
- [ ] ClickHouse : réplication ou acceptation explicite de la perte
- [ ] Redis : sentinelle ou mode géré. **Attention** : la perte de Redis dégrade
      les seuils en comptage par réplique, ce qui est signalé par
      `crp_sliding_window_fallback_total` — c'est une dégradation silencieuse si
      personne ne regarde la métrique
- [ ] `PodDisruptionBudget` et `HorizontalPodAutoscaler` par unité
- [ ] Deux instances minimum des unités sans état

**Sortie** : tuer le primaire PostgreSQL, un courtier Kafka et une réplique de
chaque unité, l'un après l'autre, sans perdre une requête ni un événement.

### J4.2 — Reprise après sinistre · 2 sem.

- [ ] Objectifs écrits : **RPO** et **RTO**, chiffrés et signés par le client
- [ ] Sauvegarde de PostgreSQL, de ClickHouse, des clés JWT et de la clé de
      signature du contenu
- [ ] **Un exercice de restauration complète, chronométré**, sur un
      environnement vierge
- [ ] La procédure de rotation et de révocation des clés de contenu existe déjà
      ([`20-CONTENT-RELEASE.md`](20-CONTENT-RELEASE.md)) ; celle de la paire JWT
      **n'existe pas** et doit être écrite et répétée

**Sortie** : une plateforme reconstruite depuis les sauvegardes dans le RTO
annoncé, vérifiée par `make smoke` et le parcours de bout en bout.

### J4.3 — Rétention et purge · 1 sem.

- [ ] Les TTL ClickHouse alignés sur l'obligation du client
- [ ] L'étagement `warm`/`cold` de `crp_audit.audit_logs` **déclaré par le
      déploiement**, jamais par le schéma — la raison est écrite dans la
      migration : un schéma qui suppose des disques qui n'existent pas échoue à
      créer la table que le régulateur réclame
- [ ] **La purge PostgreSQL, qui n'existe pas.** Alertes, constats et incidents
      s'accumulent sans limite
- [ ] Un test qui vérifie qu'une purge ne supprime pas une ligne encore
      référencée

**Sortie** : une base vieillie artificiellement de deux ans conserve ce qu'elle
doit et a purgé le reste.

> **Critère de sortie de J4** : une panne de chaque composant est survivable, et
> une reconstruction complète a été chronométrée.

---

## 8. J5 — Validation externe · 6 semaines

**But** : ce qu'une banque exige pour signer. Rien ici n'est du développement,
et rien ici ne peut être fait par nous.

| | Durée | Remarque |
|---|---|---|
| **Test d'intrusion externe** | 3 sem. | Boîte grise, avec le code. Prévoir deux semaines de correction après |
| **Audit de code tiers** | 3 sem. | En parallèle. Le ratio de test 1:6,3 sera relevé |
| **Test de charge contradictoire** | 1 sem. | Par le client ou un tiers, sur le chiffre de J1.7 |
| **Revue de la matrice RBAC** | 1 sem. | Par la sécurité du client. Décision d'organisation, pas de code |
| **Revue de conformité** | 2 sem. | DORA, et PCI DSS ou SWIFT CSCF selon le client |

- [ ] Prévoir **deux semaines de correction** après le pentest. Un pentest sans
      fenêtre de correction derrière est un rapport, pas une validation
- [ ] Le rapport d'audit de code mentionnera la couverture. J2.1 est ce qui
      permet d'y répondre autrement que par une promesse

> **Critère de sortie de J5** : les constats de criticité haute et moyenne sont
> corrigés et revérifiés, et les rapports sont signés.

---

## 9. Ce qui est délibérément hors périmètre

Dit ici pour qu'on ne le découvre pas en cours de route.

| | Pourquoi dehors |
|---|---|
| **Les connecteurs vers des outils tiers** | Aucun n'est livré : ni EDR, ni cloud, ni annuaire. C'est un produit en soi, à vendre et à chiffrer séparément. **Le premier client en voudra un** : le prévoir au contrat, pas au plan |
| **La corrélation inter-domaines** | Rien ne lie une anomalie comportementale à un chemin d'attaque. C'est une vraie fonctionnalité, pas une finition |
| **Les 12 domaines superficiels** | Décision §3. Les approfondir est un trimestre par domaine |
| **Le rejeu depuis la DLQ** | Utile, pas bloquant. Inspection manuelle en attendant |
| **L'approbation humaine dans un playbook** | Bloquant pour une action destructrice en production chez un client prudent. À ajouter quand un client le demande, et il le demandera |
| **L'idempotence de l'API** | Aucun endpoint ne lit `Idempotency-Key`. À ajouter avant qu'un intégrateur en ait besoin |
| **Un schéma OpenAPI** | La référence générée en tient lieu. Un intégrateur tiers en voudra un |

---

## 10. Les risques

Classés par ce qu'ils coûtent, pas par probabilité.

| Risque | Conséquence | Atténuation |
|---|---|---|
| **Les 100 K EPS démentis en réunion** | Perte de crédibilité irrécupérable sur un appel d'offres | **Mesurer en J1.7, puis décider de tenir le chiffre ou de le changer.** Avant qu'un prospect le fasse |
| **Un prospect gratte un des 12 domaines superficiels** | Doute reporté sur les six vrais | Décision §3 : masquer |
| **Un défaut dans `tenant`** | Les échéances de remédiation de tous les clients bougent en silence | J2.1 priorité 1 |
| **La consolidation casse le contrat d'API** | Reprise de l'interface et de l'intégration client | Les routes ne changent pas, et `apicheck` plus `docs-api-check` le prouvent à chaque commit |
| **Le pentest trouve une faille d'authentification** | Report de plusieurs mois | Le chemin est unique (`authmw`) et testé : la surface est petite. La bêta `next-auth` est le point faible, traité en J2.3 |
| **Perte de la clé privée de contenu** | Rotation forcée de toutes les livraisons | Procédure écrite ([`20-CONTENT-RELEASE.md`](20-CONTENT-RELEASE.md) §6), HSM en J3.3 |
| **Perte de la paire JWT** | Tous les jetons invalidés, reconnexion de tous les utilisateurs | Sauvegarde en J4.2. **La procédure n'existe pas** et doit être écrite |

---

## 11. Suivre le plan

Six indicateurs. S'ils n'avancent pas, le plan n'avance pas, quoi qu'en dise le
tableau d'avancement.

| Indicateur | Aujourd'hui | Cible | Mesuré par |
|---|---|---|---|
| Services sans test | **17 / 32** | 0 | `find … -name '*_test.go'` par service |
| Couverture, domaines critiques | non mesurée | ≥ 60 % | `go test -cover` |
| Débit d'ingestion | **non mesuré** | le chiffre défendu | J1.7 |
| Latence API p95 | **non mesurée** | < 200 ms | `crp_http_request_duration_seconds` |
| Unités déployables | **32** | 8–10 | `ls bin` |
| Secrets dans le dépôt | **oui** (paire JWT) | 0 | `git ls-files \| grep -E '\.pem$\|\.key$'` |

---

## 12. Récapitulatif

```
J1  Sandbox cloud défendable         3 sem.   ├── parallélisable
J2  Socle de confiance mesurable     6 sem.   ├── parallélisable
J3  Consolidation et Kubernetes      8 sem.   └── séquentiel après J1
J4  Haute disponibilité et reprise   6 sem.       séquentiel après J3
J5  Validation externe               6 sem.       séquentiel après J4
                                   ─────────
                            chemin critique : 7 mois
```

**7 mois** à trois ingénieurs, en comptant J1 et J2 en parallèle et les deux
semaines de correction après le pentest.

**Trois mois** suffisent à un POC client défendable : J1 seul, avec la décision
§3 sur les douze domaines.

> Le chiffre de 6 à 9 mois donné en [`19-AUDIT-AND-ROADMAP.md`](19-AUDIT-AND-ROADMAP.md) §5
> tenait avant que les phases 0 à 3 soient faites. Il reste juste, pour une
> raison différente : ce qui restait était du code, ce qui reste est du
> déploiement et de la validation — et la validation externe ne s'accélère pas
> en ajoutant des ingénieurs.
