# 11 — UEBA

`services/ueba` consomme `crp.events.enriched`, tient un profil par entité, et
lève une anomalie quand le comportement s'écarte de ce profil.

---

## L'entité

Une entité est un utilisateur ou un actif. Son identifiant est **dérivé**, pas
pris tel quel dans l'événement :

```go
var entityNamespace = uuid.MustParse("6f6a2c1e-9b4e-5d3a-8c17-0d2f4b9a7e31")

key := tenantID + "|" + kind + "|" + strings.ToLower(strings.TrimSpace(raw))
id  := uuid.NewSHA1(entityNamespace, []byte(key))
```

Trois propriétés tenues, et chacune résout un défaut concret :

- **Stable entre les redémarrages et entre les répliques.** Une entité dont
  l'identifiant changerait repartirait d'une ligne de base vierge à chaque fois
  et ne serait jamais anormale.
- **Portée au tenant.** `jdupont` chez deux clients sont deux entités.
- **Insensible à la casse et aux espaces.** `JDupont ` et `jdupont` sont la
  même personne.

> **Le défaut que cela a corrigé.** Le moteur lisait uniquement `user_id` et
> `asset_id`. Les lignes de journal portent `user_name`. Résultat : zéro profil,
> zéro anomalie — le moteur n'avait jamais traité un seul événement, et rien ne
> le disait.

---

## Les huit signaux

| Type | Sévérité par défaut | Score |
|---|---|---|
| `OFF_HOURS_ACCESS` | MEDIUM | 3,5 |
| `NEW_COUNTRY` | HIGH | 6,5 |
| `NEW_IP_PREFIX` | LOW | 2,0 |
| `VELOCITY_SPIKE` | HIGH | 5,0 |
| `BRUTE_FORCE` | HIGH | 6,0 |
| `PRIVILEGE_ESCALATION` | HIGH | 7,0 |
| `LATERAL_MOVEMENT` | CRITICAL | 8,5 |
| `DATA_EXFILTRATION` | CRITICAL | 9,0 |

Chacun peut être **éteint** par le tenant, et sa sévérité comme son score sont
les siens.

> Éteindre un signal est une décision légitime : une institution qui tourne en
> trois équipes n'a aucun usage d'une alerte « hors heures » qui se déclenche
> toutes les nuits. L'honorer ici est ce qui les empêche de le faire en aval
> dans une règle de messagerie, où personne ne peut voir qu'ils l'ont fait.

---

## Les seuils

| | Défaut | Ce que c'est |
|---|---|---|
| `min_hours_for_baseline` | 3 | Combien d'heures distinctes avant de faire confiance à la ligne de base horaire |
| `min_countries_for_baseline` | 1 | Idem pour les pays |
| `velocity_threshold` | 80 | Événements avant de crier à la pointe |
| `velocity_window_s` | 60 | Sur quelle fenêtre |
| `brute_force_threshold` | 5 | Échecs avant de crier à la force brute |
| `brute_force_window_s` | 300 | Sur quelle fenêtre |

Ils étaient des constantes dans le code. Ils sont désormais ceux du tenant,
lus à travers un cache ; ce qu'ils valaient est conservé comme
`DefaultBehaviourPolicy()`, qui est **à la fois** le profil standard livré
**et** ce sur quoi le moteur se rabat quand aucune politique ne peut être lue.

> **Détecter avec des seuils légèrement faux vaut mieux que ne pas détecter.**
> Un moteur comportemental qui s'arrête parce qu'une base de données a été
> brièvement injoignable serait pire.

### Les préréglages

| Code | Pour qui |
|---|---|
| `balanced` | **Exactement le comportement antérieur.** L'adopter ne déplace aucun chiffre |
| `round_the_clock` | Activité continue : « hors heures » n'a pas de sens |
| `privileged_watch` | Surveillance renforcée des comptes à privilèges |
| `low_noise` | Bruit réduit |

Paramétrage : [16 — Paramétrage](16-parametrage.md).

---

## Le profil et le score

Un profil porte les ensembles de ce qui est normal pour l'entité — heures,
pays, préfixes d'adresse — et six dimensions de score :

```
LoginScore   AccessScore   DataScore   TemporalScore   PeerScore
                      │
                      ▼
                  RiskScore
```

À chaque événement : la ligne de base est complétée, les scores sont
recalculés, et une décroissance est appliquée pour qu'une anomalie ancienne
pèse moins qu'une récente.

### Le cache de politique

La politique est lue à travers un `atomic.Pointer` rafraîchi chaque minute : le
chemin chaud ne peut pas interroger PostgreSQL par événement. Le premier
chargement est fatal — démarrer sans savoir sur quels seuils on détecte serait
démarrer en prétendant détecter.

### Les compteurs glissants

Dans Redis, comme ceux du SIEM, pour que deux répliques comptent ensemble. Un
comptage **dégradé** — qui ne couvre que cette réplique — est signalé par la
fenêtre elle-même, en journal limité et en métrique
`crp_sliding_window_fallback_total`.

---

## L'API

```
GET  /api/v1/ueba/profiles
GET  /api/v1/ueba/profiles/{entityID}
GET  /api/v1/ueba/anomalies
PATCH /api/v1/ueba/anomalies/{anomalyID}     open → acknowledged → …
GET  /api/v1/ueba/stats
```

La liste complète est dans [07 — Référence API](07-reference-api.md).

---

## Ce qui n'est pas fait

- **Pas d'analyse de pairs réelle.** `PeerScore` existe comme dimension ; rien
  ne constitue les groupes de pairs ni ne compare une entité aux siens.
- **Pas de modèle appris.** Les lignes de base sont des ensembles observés et
  des compteurs, pas un modèle statistique.
- **Les lignes de base ne se forment pas sur le jeu de démonstration.** Il
  injecte en rafale ; une ligne de base a besoin d'activité étalée dans le
  temps. Les détections SIEM qui en dépendent (`geo_anomaly`,
  `anomalous_hours`) ne peuvent donc pas être exercées en démonstration.
- **Pas de rétroaction analyste.** Marquer une anomalie comme faux positif ne
  change rien au profil.
