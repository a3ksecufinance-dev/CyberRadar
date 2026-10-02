# 10 — Détection

## Le moteur

`services/siem` consomme `crp.events.normalized`, évalue chaque événement
contre les règles actives du tenant, et produit une alerte quand une règle est
satisfaite.

```
événement ─▶ règles actives du tenant (cache, rafraîchi périodiquement)
                 │
                 ├─ field_matches  toutes doivent être vraies
                 └─ threshold      N occurrences dans une fenêtre, groupées
                                   │
                                   ▼
                            déduplication (dedup_window_s)
                                   │
                                   ▼
                                alerte ──▶ crp.events.alerts
```

### Les champs qu'une règle peut nommer

```
category   severity   outcome   action   source_type
mitre_tactic   mitre_technique
user_id   user_name   ip_source   ip_destination   geo_country
risk_score   threat_score   cbs_impact   swift_impact
ioc_matched   geo_anomaly   anomalous_hours
```

Cette liste est **déclarée**, pas déduite du code qui la résout. C'est
délibéré : une règle livrée qui nomme un champ inconnu se charge, ne
correspond à rien, et se présente comme une couverture qui fonctionne — ce qui
est pire que pas de règle du tout. Un test affirme les deux sens : toute entrée
du catalogue ne nomme que ces champs, et chacun de ces champs se résout
réellement.

### Les opérateurs

| `op` | Sens |
|---|---|
| `eq`, `neq` | Égalité, insensible à la casse |
| `contains` | Sous-chaîne, insensible à la casse |
| `gt`, `gte`, `lt`, `lte` | Comparaison numérique |
| `in` | Appartenance à une liste séparée par des virgules |
| `exists` | Le champ est non vide |

### Les seuils

```yaml
threshold:
  count: 5
  window_seconds: 300
  group_by: [ip_source]
```

**Les compteurs sont dans Redis, pas en mémoire.** Deux instances du service
doivent compter ensemble : chacune pour soi, un seuil de 5 ne se déclenche
qu'à 10.

### Les actions

`notify`, `create_case`, `block_ip`, `disable_user`. Une détection sans action
est légitime : elle lève l'alerte et rien de plus.

---

## Le catalogue livré

Quinze détections, dans `backend/content/detections/`, un fichier par
détection plus `pack.yaml` qui porte l'identité de la livraison.

**Elles ne sont pas dans une migration.** Elles l'étaient — des `INSERT` dans
la migration 000040 — et améliorer l'une d'elles était donc un changement de
schéma : une migration, une recompilation, une fenêtre de déploiement, pour une
phrase de raisonnement ou un seuil que quelqu'un voulait resserrer. Un contenu
qui ne peut se livrer qu'avec le code se livre à la cadence du code, et ce
n'est pas la bonne cadence pour du contenu de détection.

### Le format

```yaml
code: CRP-IAM-0001
title: Bourrage d'identifiants depuis une même adresse
description: Cinq échecs d'authentification ou plus depuis une même adresse
  source en cinq minutes.
category: IAM
severity: HIGH
mitre:
  tactic: TA0006
  technique: T1110.004
conditions:
  threshold: { count: 5, window_seconds: 300, group_by: [ip_source] }
  field_matches:
    - { field: category, op: eq, value: IAM }
    - { field: outcome,  op: eq, value: failure }
actions:
  - type: notify
dedup_window_s: 300
rationale: >-
  Un attaquant qui essaie une liste d'identifiants volés produit beaucoup
  d'échecs depuis peu d'adresses…
false_positives: >-
  Un portail dont la session expire mal, un client mobile qui réessaie…
  Regarder si les noms d'utilisateur varient : un seul compte qui échoue
  vingt fois est un utilisateur en difficulté, vingt comptes depuis une
  adresse ne l'est pas.
response: >-
  Limiter le débit sur l'adresse au niveau du pare-feu applicatif…
frameworks: [DORA, PCIDSS, ISO27001]
controls:   [DORA-10.3, PCI-10.4.1, A.8.16]
requires:   []
enabled_by_default: true
tags: [authentification, standard]
```

`rationale`, `false_positives` et `response` ne sont pas de la décoration : ce
sont ce qu'un analyste de nuit lit quand l'alerte tombe. Une détection sans
raisonnement est refusée par la validation.

### Il n'y a pas de numéro de version dans un fichier

Il est **dérivé d'une empreinte** de tout ce qui est substantiel. Un numéro
dans un fichier est un numéro que quelqu'un oublie de changer — et un oubli dit
à un tenant resté en v1 qu'il est à jour alors qu'il fait tourner autre chose.

Réordonner une liste de référentiels ou réindenter un fichier n'est pas une
nouvelle version ; resserrer un seuil l'est. L'exécution à blanc dit quel champ
a bougé :

```
^ CRP-IAM-0001   v1 -> v2     [conditions]
- CRP-FRD-0001   v1 retired   no longer in the pack
would apply: 1 published, 1 retired, 13 unchanged   (re-run with -apply)
```

### Charger le catalogue

```bash
make content-check       # valide, sans base de données
make content             # charge depuis le répertoire (mode auteur)
```

Pour un déploiement, le catalogue vient d'une **livraison signée** et d'un
canal publié, jamais d'un répertoire :
[`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md).

### Ce que la validation refuse

Elle s'exécute **là où le contenu est écrit, sans base de données** — c'est le
point : le contenu se livre sans le code, donc la vérification que le contenu
tient debout doit tourner sans la plateforme.

| Refus | Pourquoi |
|---|---|
| Un champ que le moteur ne lit pas | La règle chargerait, ne matcherait rien, et passerait pour une couverture |
| Une détection sans raisonnement | L'analyste de nuit n'aurait rien à lire |
| Une entrée à prérequis livrée active | Elle ne peut pas fonctionner tant que le prérequis manque |
| Une clé mal orthographiée | Elle laisserait un champ à sa valeur nulle en silence (`KnownFields(true)` sur le décodeur YAML) |
| Un répertoire vide | Quelqu'un peut vouloir dire « catalogue de rien », personne par accident |

### Trois cas de réconciliation

| Cas | Décision |
|---|---|
| Une ligne antérieure aux empreintes | Reconstruite et hachée comme un fichier, donc un contenu identique converge en silence. La traiter comme « différente » aurait republié tout le catalogue au premier chargement et annoncé quinze mises à jour à chaque tenant |
| Un code que le paquet ne porte plus | **Retiré, jamais supprimé.** Des tenants l'ont adopté, et l'écart avec la version qu'ils ont prise se calcule en relisant cette version |
| Une empreinte identique | Rien ne bouge, numéro de version compris |

---

## La bibliothèque et la généalogie

Le catalogue est **le standard** ; ce qu'un tenant fait tourner est **ce qu'il
en a adopté**. Les deux sont distincts, et l'écart est visible.

```
GET  /api/v1/siem/rule-library                 le catalogue, avec l'état d'adoption
GET  /api/v1/siem/rule-library/coverage        la couverture MITRE et par référentiel
GET  /api/v1/siem/rule-library/{code}          une entrée, et la version adoptée
POST /api/v1/siem/rule-library/{code}/adopt    adopter
GET  /api/v1/siem/rule-library/{code}/upgrade  ce qu'une remise à niveau ferait
POST /api/v1/siem/rule-library/{code}/upgrade  la faire
```

### La remise à niveau est une fusion à trois, pas un écrasement

Un tenant qui a adopté la v1 et l'a ajustée ne doit pas perdre ses ajustements
parce qu'une v2 est sortie. Trois versions sont comparées champ par champ :
**ce qui a été adopté**, **ce qui arrive**, **ce que le tenant fait tourner**.

| Les trois | Résultat |
|---|---|
| Identiques | Inchangé |
| Adopté = tenant, l'entrant diffère | **Prendre l'entrant** — le tenant n'avait rien changé |
| Adopté = entrant, le tenant diffère | **Garder le tenant** — le standard n'a pas bougé sur ce champ |
| Entrant = tenant, l'adopté diffère | **Convergé** — ils sont arrivés au même endroit |
| Les trois diffèrent | **Conflit** |

**Un conflit non résolu fait refuser l'opération entière.** Fusionner ce qui se
fusionne et laisser le reste donnerait une règle à moitié à jour que personne
ne peut décrire.

La migration 000041 garde `content_upgraded_at` **à part de** `updated_at` :
« la dernière fois que le standard a bougé sous cette règle » et « la dernière
fois que quelqu'un l'a touchée » sont deux questions différentes.

---

## La couverture

```
GET /api/v1/siem/rule-library/coverage
```

Rend ce que le catalogue couvre, par tactique MITRE et par référentiel (DORA,
PCI DSS, ISO 27001), et ce que le tenant en a réellement adopté. L'écran de la
bibliothèque l'affiche côte à côte : **ce que le standard propose** et **ce qui
tourne vraiment**.

---

## Ce qui n'est pas fait

- **Pas de corrélation multi-événements** au-delà des seuils. Pas de séquence
  (« A puis B dans les 10 minutes »).
- **Pas de recherche libre** sur les événements : le moteur évalue, il n'offre
  pas de langage d'interrogation.
- **Pas de simulation.** On ne peut pas passer une règle sur l'historique pour
  voir ce qu'elle aurait levé.
- **Pas de réglage automatique des seuils.** Un seuil est une valeur, pas une
  statistique apprise.
- **Les détections dépendant d'une ligne de base UEBA** (`geo_anomaly`,
  `anomalous_hours`) ne se déclenchent pas sur le jeu de démonstration : il
  injecte en rafale, et une ligne de base a besoin d'activité étalée dans le
  temps.
