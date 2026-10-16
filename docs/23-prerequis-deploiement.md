# Prérequis de déploiement — institution de microfinance

> Établi le 15 octobre 2026. Les chiffres de dimensionnement viennent de
> mesures prises sur la plateforme (`make bench`, `bench -only nfr`), pas
> d'estimations. Chacun est reproductible par la commande indiquée.
>
> **Cas visé** : CBS hébergé en cloud, le reste du système d'information sur
> site, CyberRadar installé **sur site**.

---

## 1. Ce qu'une microfinance y gagne

Une institution de microfinance n'a pas le profil d'une banque de détail. Elle
a beaucoup d'agences, peu d'informaticiens, et souvent **une à trois personnes**
pour la sécurité — parfois zéro à plein temps. Les bénéfices qui comptent ne
sont donc pas les mêmes.

### 1.1 Voir ce qui ne parle plus

C'est le bénéfice le moins spectaculaire et le plus utile. Avec cent agences,
personne ne remarque à la main que le pare-feu d'une agence a cessé d'envoyer
ses journaux il y a trois jours. Cette agence n'est pas « sans incident » :
elle est **sans surveillance**, et rien ne le dit.

La plateforme répond à cette question (`GET /api/v1/sources/health`) et compte
dans sa couverture d'actifs les équipements inventoriés qui n'émettent rien.
Un actif muet est au dénominateur, jamais au numérateur.

### 1.2 Un seul endroit pour le cloud et le site

Le CBS est chez un hébergeur, les postes et le réseau sont dans les agences.
Sans consolidation, un détournement qui commence par un vol d'identifiant sur
un poste d'agence et se termine par une opération dans le CBS se lit comme
deux événements sans rapport, dans deux outils, par deux personnes.

### 1.3 Une charge de travail qui tient dans une petite équipe

La valeur pour une équipe de deux personnes n'est pas un tableau de quatre
cents alertes : c'est une liste courte, ordonnée, où ce qui est en haut mérite
réellement la matinée. Ce que la plateforme apporte sur ce point :

- **UEBA** avec des seuils paramétrables par l'institution, pas par l'éditeur ;
- **déduplication** des alertes par entité sur une fenêtre réglable ;
- **playbooks SOAR** pour les gestes répétitifs ;
- **MTTD et MTTR calculés** sur les incidents réels, pour savoir si l'équipe
  s'améliore ou si elle se noie.

### 1.4 Les obligations réglementaires

| Cadre | Ce que la plateforme apporte |
|---|---|
| **Bank Al-Maghrib** — dispositif de sécurité | journal d'audit inaltérable, traçabilité des accès, rapports |
| **Loi 09-08 / CNDP** — données personnelles | les données des clients **ne quittent pas le site** ; DLP et DSPM pour les localiser |
| **PCI DSS** (si cartes) | périmètre identifié par l'inventaire, contrôles suivis |
| **ISO 27001** | le module conformité suit les contrôles et leur preuve |

**L'installation sur site est ici un argument réglementaire**, pas seulement
technique : les journaux contiennent des données personnelles de clients, et
les garder sur le territoire simplifie la conversation avec la CNDP.

### 1.5 Ce que je ne compte pas comme bénéfice

Par honnêteté, trois choses qu'on pourrait attendre et que la plateforme ne
donne pas aujourd'hui :

- **la réduction des faux positifs ne peut pas être chiffrée** avant une
  période de double exploitation sur votre site — elle compare un taux au taux
  de l'outil remplacé, et aucun des deux n'existe ici ;
- **le catalogue de connecteurs est en cours** : quinze détections signées sont
  livrées, mais l'inventaire des connecteurs prêts à l'emploi est au début de
  son chantier ;
- **la haute disponibilité n'est pas démontrée**. Voir §5.

---

## 2. L'architecture dans votre cas

```
        CLOUD                                SITE (on-premise)
   ┌─────────────┐                  ┌──────────────────────────────────┐
   │     CBS     │ ──── TLS ──────► │  Collecteur  :8005               │
   └─────────────┘   (sortant du    │       │                          │
                      cloud vers    │       ▼                          │
                      votre site)   │  Kafka ──► Pipeline ──► Détection│
   ┌─────────────┐                  │       │                          │
   │ Pare-feu    │ ─── syslog ────► │       ▼                          │
   │ AD / postes │                  │  ClickHouse   PostgreSQL   Redis │
   │ Réseau      │                  │       │                          │
   └─────────────┘                  │       ▼                          │
                                    │  Interface web  :3000            │
                                    └──────────────────────────────────┘
```

**La décision d'architecture à prendre tôt** : comment le CBS en cloud alimente
le collecteur sur site. Deux options, et elles n'ont pas le même coût :

| | Comment | Ce que ça demande |
|---|---|---|
| **A — le CBS pousse** | le CBS appelle `/api/v1/events/ingest` du collecteur | une entrée depuis Internet vers votre site : VPN site-à-site, ou publication du seul collecteur derrière un reverse proxy avec mTLS |
| **B — un relais dans le cloud** | un petit collecteur dans le cloud agrège et pousse vers le site | une machine de plus à exploiter, mais **aucune entrée** ouverte sur votre site |

**Recommandation : B**, par VPN site-à-site. Ouvrir une porte entrante vers le
cœur du SI d'une institution financière pour y faire entrer des journaux est un
risque qui dépasse le confort qu'il procure.

---

## 3. Prérequis d'infrastructure

### 3.1 Les briques nécessaires

| Brique | Rôle | Version |
|---|---|---|
| **PostgreSQL** | configuration, inventaire, incidents, vulnérabilités | 16+, extension `pgvector` |
| **ClickHouse** | événements, audit, séries temporelles | 24+ |
| **Kafka** | tampon entre collecte et traitement | 3.7+, mode KRaft |
| **Redis** | compteurs de détection et de comportement | 7+ |
| **Keycloak** | authentification des personnes | 24+ |
| **Neo4j** | graphes d'attaque *(facultatif — sinon PostgreSQL)* | 5+ |

### 3.2 Dimensionnement, dérivé des mesures

**Ce qui a été mesuré** (quatre cœurs partagés entre la plateforme entière,
l'infrastructure et l'outil de mesure — c'est un plancher, pas une
spécification) :

| | Mesuré | Commande |
|---|---|---|
| Débit tenu | **376 ev/s** | `make bench` |
| Coût d'un événement | **3,4 ms**, une instance | `bench -only nfr` |
| Mise à l'échelle | **×1,72** pour deux instances | idem |
| Latence de traversée | **p95 11 ms** | idem |
| Reprise | **313 200 événements rattrapés en 15 min** par instance | idem |
| Compression ClickHouse | **4,7×** mesuré sur la table réelle | — |

**Volumétrie attendue pour une microfinance.** Une institution de 50 à 150
agences produit typiquement **100 à 400 événements/seconde en moyenne**, avec
des pointes à 1 000–2 000 pendant les heures d'ouverture et les traitements de
fin de journée. À valider chez vous : c'est l'inconnue qui change tout le
reste.

**Stockage**, calculé et non estimé. Un événement réaliste mesuré ici porte
**~300 octets de charge utile brute** ; avec les colonnes structurées et une
compression mesurée à 4,7×, cela donne **~120 à 270 octets sur disque** selon
la verbosité de vos sources.

Les lignes ci-dessous prennent **150 octets par événement sur disque**, le
milieu de cette fourchette. Pour recalculer avec vos propres sources :
`débit × 86 400 × jours × octets_par_événement`.

| Débit moyen | Par jour | 90 jours | 365 jours |
|---|---|---|---|
| 100 ev/s | ~1,3 Go | ~115 Go | ~470 Go |
| 200 ev/s | ~2,6 Go | ~235 Go | ~950 Go |
| 400 ev/s | ~5,2 Go | ~465 Go | ~1,9 To |

Ajouter : **PostgreSQL** quelques dizaines de Go, **Kafka** la rétention que
vous choisissez (7 jours à 200 ev/s ≈ 120 Go), et **50 % de marge** — une base
pleine est une panne, et une base ClickHouse pleine est une panne pendant
laquelle plus rien n'est détecté.

### 3.3 Matériel proposé

**Pilote — un seul serveur.** Pour valider la chaîne, pas pour produire.

```
16 vCPU · 64 Go RAM · 1 To NVMe · Linux x86-64
```

**Production — cinq nœuds.** La séparation n'est pas cosmétique : ClickHouse et
Kafka se disputent le disque, et l'un des deux perd toujours.

| Rôle | Nœuds | Par nœud | Disque |
|---|---|---|---|
| Données — ClickHouse | 2 | 8 vCPU · 32 Go | NVMe, dimensionné §3.2 |
| Données — PostgreSQL + Redis | 1 | 8 vCPU · 32 Go | 500 Go NVMe |
| Bus — Kafka | 1 | 4 vCPU · 16 Go | 500 Go NVMe |
| Services + interface | 2 | 8 vCPU · 32 Go | 100 Go |

> **NVMe, pas de disque mécanique ni de SAN partagé** pour ClickHouse et Kafka.
> C'est la seule exigence matérielle sur laquelle je ne transigerais pas : les
> deux sont limités par les entrées-sorties, et un SAN partagé avec le reste du
> SI transforme un pic d'ingestion en incident de production ailleurs.

### 3.4 Réseau

| Flux | Port | Sens |
|---|---|---|
| Sources → collecteur | 8005 (HTTPS) | entrant depuis le SI |
| Syslog → collecteur syslog | 514/6514 (TLS) | entrant depuis le SI |
| Postes → interface web | 443 | entrant depuis le SI |
| CBS cloud → site | selon §2 | **VPN site-à-site recommandé** |
| Plateforme → Internet | 443 sortant | flux CTI, CVE *(peut être relayé)* |

Une **autorité de certification interne** est nécessaire : la plateforme parle
TLS entre ses composants, et des certificats auto-signés non gérés deviennent
une panne six mois plus tard, le jour de leur expiration.

---

## 4. Prérequis de mise en production

### 4.1 Du côté de l'institution

- [ ] **Un propriétaire nommé.** Une plateforme de détection sans personne qui
      regarde produit des journaux, pas de la sécurité.
- [ ] **Les sources identifiées et leur verbosité décidée.** Quels équipements,
      quel niveau de journalisation. C'est ce qui fixe la volumétrie.
- [ ] **Une politique de rétention écrite**, cohérente avec vos obligations.
- [ ] **Les seuils décidés** : délais de remédiation, seuils comportementaux,
      pondérations de risque. La plateforme les rend paramétrables parce
      qu'aucun défaut d'éditeur n'engage l'institution à votre place.
- [ ] **Une astreinte définie**, même informelle. Savoir à 2 h du matin ne sert
      que si quelqu'un est joignable.
- [ ] **Un plan de sauvegarde et un test de restauration.** Pas un plan : un
      test.

### 4.2 Du côté technique

- [ ] Les six briques du §3.1 installées, sauvegardées et supervisées
- [ ] L'autorité de certification interne, et la rotation des certificats
- [ ] Keycloak raccordé à votre annuaire (AD / LDAP)
- [ ] Les comptes de service créés, les secrets dans un coffre
- [ ] Le dimensionnement **validé chez vous** par `make bench` — la commande
      est dans le dépôt pour cela
- [ ] Une bascule par étapes : une source, puis cinq, puis tout

---

## 5. Ce que je ne peux pas promettre aujourd'hui

Cette section existe parce qu'un prérequis omis coûte plus cher qu'un
prérequis désagréable.

| | État |
|---|---|
| **Infrastructure as code** | **absente**. Ni Helm, ni Terraform, ni manifeste Kubernetes. Il y a un `docker-compose.yml` et 32 images. L'intégrateur écrit le déploiement. |
| **Haute disponibilité** | **non démontrée**. Les composants la permettent ; la plateforme n'a jamais été exploitée en HA et aucune bascule n'a été mesurée. |
| **Terminaison TLS en bordure** | **à fournir**. Aucun reverse proxy n'est livré. |
| **Catalogue de connecteurs** | **au début**. Le contrat d'ingestion fonctionne, le registre et la santé existent ; les connecteurs prêts à l'emploi par éditeur restent à écrire. |
| **100 000 ev/s** | **non tenu et non promis.** 376 ev/s mesurés sur quatre cœurs partagés. Pour une microfinance à 400 ev/s, la marge est confortable — mais le chiffre de 100 K est une cible d'architecture, pas une caractéristique. |

**Ce que cela implique pour un projet réel** : la part intégration est
substantielle. Compter l'écriture du déploiement, la terminaison TLS, le
raccordement des sources et la reprise de l'existant — ce n'est pas une
installation, c'est un projet.

---

## 6. Pour aller plus loin

- [`03-installation.md`](03-installation.md) — installer la plateforme
- [`18-exploitation.md`](18-exploitation.md) — l'exploiter au quotidien
- [`22-mesures.md`](22-mesures.md) — les mesures citées ici, et leur méthode
- [`plan/21-PRODUCTION-PLAN.md`](../plan/21-PRODUCTION-PLAN.md) — le chemin
  vers la production, jalon par jalon
