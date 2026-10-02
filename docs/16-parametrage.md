# 16 — Paramétrage

## La ligne, et où elle passe

Quatre jugements sont ceux du client. Le reste ne l'est pas.

Le test appliqué, chaque fois : **est-ce un fait ou un jugement ?**

- Qu'un CVSS de 9,8 soit plus grave qu'un 4,3 est un **fait**. Ce n'est pas
  paramétrable.
- Que « critique » veuille dire trois jours plutôt que sept est un
  **jugement**, et il appartient à l'institution qui en répondra devant son
  régulateur.
- Que `maxPathsPerScenario` vaille 200 est une **borne de calcul**. La rendre
  paramétrable laisserait un tenant faire tomber l'analyseur ; elle reste une
  constante, délibérément.

Un éditeur qui impose ses seuils demande à ses clients de défendre le jugement
de quelqu'un d'autre devant leur régulateur. Un éditeur qui ne livre aucun
seuil laisse chaque client en inventer un. Le compromis tenu ici : **livrer un
avis, l'étiqueter comme tel, et laisser le changer**.

---

## Les quatre politiques

| Politique | Service | Ce qu'elle décide | Préréglages |
|---|---|---|---|
| **Profil de risque** | `risk` | Comment la criticité, les vulnérabilités et le contexte métier composent un score d'actif | 4 |
| **Délais de remédiation** | `vuln` | Combien de jours pour corriger, et quels contextes resserrent | 5 |
| **Seuils comportementaux** | `ueba` | Quels signaux sont actifs, à quelle sévérité, à partir de quel seuil | 4 |
| **Pondérations des chemins d'attaque** | `attackpath` | Ce que coûte une arête, comment la distance atténue, ce que vaut une cible inconnue | 4 |

---

## La forme commune

Les quatre suivent exactement le même motif, en base comme à l'API.

### En base

```sql
CREATE TABLE <x>_policies (
    tenant_id      UUID,          -- NULL = préréglage de la plateforme
    code           VARCHAR,
    name           VARCHAR,
    description    TEXT,
    version        INT,
    effective_from TIMESTAMPTZ,
    effective_to   TIMESTAMPTZ,   -- NULL = active
    …les paramètres, en colonnes nommées…
);

CREATE UNIQUE INDEX … ON <x>_policies (tenant_id) WHERE effective_to IS NULL;
```

Quatre décisions, chacune avec une mauvaise réponse tentante :

- **Des colonnes nommées, pas un blob JSON.** Une contrainte `CHECK` peut
  alors refuser un seuil hors bornes, et le refus porte le nom du champ. Un
  JSON accepte tout et échoue plus tard, ailleurs.
- **Versionnée et datée.** Un auditeur demande « quelle était la formule ce
  jour-là ». `effective_from`/`effective_to` répondent ; un `UPDATE` sur place
  ne le pourrait pas.
- **Une seule active par tenant, garantie par un index partiel.** Pas par du
  code applicatif qu'on peut contourner.
- **Une vue publie la politique en vigueur.** Les domaines partagent la même
  base ; une vue est un contrat publié, une table partagée est un couplage.

### Le repli vers le standard

```sql
CASE WHEN own.id IS NOT NULL THEN own.cbs_days ELSE std.cbs_days END
```

`CASE WHEN` et non `COALESCE`. Un plafond que le tenant a **délibérément**
laissé vide ne doit pas hériter de celui du préréglage ; `COALESCE` ne sait pas
distinguer « absent » de « volontairement non posé ».

### À l'API

Quatre routes par politique, sur `tenant-service` (:8001) :

```
GET /api/v1/<x>-policies/presets     les préréglages livrés
GET /api/v1/<x>-policies/active      ce qui est en vigueur, et d'où vient chaque valeur
PUT /api/v1/<x>-policies/active      en adopter une
GET /api/v1/<x>-policies/history     ce qui a été en vigueur, et quand
```

avec `<x>` ∈ `risk-profiles`, `remediation-policies`, `behaviour-policies`,
`attack-policies`.

| Politique | Permission |
|---|---|
| `risk-profiles` | `risk:read` / `risk:write` |
| `remediation-policies` | `vulnerabilities:read` / `:write` |
| `behaviour-policies` | `ueba:read` / `ueba:write` |
| `attack-policies` | `attack_paths:read` / `:write` |

**Concurrence optimiste** : la version est dans la clause `WHERE`. Deux
écritures simultanées ne s'écrasent pas en silence ; la seconde est refusée et
l'écran recharge.

---

## Le préréglage par défaut ne déplace rien

Chaque politique a un préréglage qui **reproduit exactement** ce que la
plateforme faisait avant que le paramètre existe :

| Politique | Préréglage neutre |
|---|---|
| Risque | `balanced` |
| Remédiation | `banking_default` |
| Comportement | `balanced` |
| Chemins d'attaque | `balanced` |

> **Rendre quelque chose paramétrable ne doit déplacer aucun chiffre le jour
> où c'est livré.** Un client qui découvre lundi que ses échéances ont bougé
> pendant le week-end n'a pas reçu une fonctionnalité, il a reçu un incident.

Les autres préréglages sont étiquetés pour ce qu'ils sont : *ce que nous
conseillerions, et que nous n'imposons pas*.

---

## Les détails par politique

### Profil de risque — `risk`

| Préréglage | Pour qui |
|---|---|
| `balanced` | **Neutre** |
| `vulnerability_led` | Quand la dette technique est le sujet |
| `pci_dss` | Quand l'évaluateur PCI est le lecteur |
| `swift_cscf` | Quand l'attestation CSCF l'est |

Paramètres : pas de criticité et plafond, poids par sévérité de vulnérabilité
et plafond, majorations CBS / SWIFT / PCI, plafond d'exposition.

### Délais de remédiation — `vuln`

Détaillé dans [12 — Vulnérabilités](12-vulnerabilites.md).

Base par sévérité, plafonds par contexte (exploité, DMZ, CBS, SWIFT, PCI), et
un plancher. **Un plafond resserre, jamais ne relâche.**

### Seuils comportementaux — `ueba`

Détaillé dans [11 — UEBA](11-ueba.md).

Huit signaux, chacun avec son interrupteur, sa sévérité et son score ; plus six
seuils (lignes de base, vélocité, force brute).

### Pondérations des chemins d'attaque — `attackpath`

Détaillé dans [13 — Chemins d'attaque](13-chemins-attaque.md).

Dix paramètres de coût, de décroissance et d'impact.

---

## Ce que l'écran montre

Quatre écrans, une seule forme (`frontend/src/components/settings/`) :

1. **En vigueur** — chaque valeur, et d'où elle vient : *héritée du standard*
   ou *propre au tenant*.
2. **Préréglages** — ce qu'ils valent, pour qui, et combien de valeurs
   changeraient.
3. **Historique** — ce qui a été en vigueur, et quand.
4. **Barre d'enregistrement** — ce qui va changer, avant de le faire.

> **Deux défauts trouvés en pilotant mon propre écran**, pas en le relisant :
> choisir un préréglage le *réétiquetait* au lieu de l'adopter — ce qui aurait
> enregistré onze valeurs héritées comme des surcharges ; et enregistrer vidait
> le formulaire en course avec la relecture — ce qui affichait cinq
> différences là où une seule avait été faite. Les deux corrigés, et les
> corrections portées dans les trois écrans suivants.

---

## Ce qui n'est pas paramétrable, et pourquoi

| | Raison |
|---|---|
| L'échelle CVSS | Un fait, pas un jugement |
| `maxPathsPerScenario = 200` | Une borne de calcul. Paramétrable, elle laisserait un tenant faire tomber l'analyseur |
| Les champs qu'une règle peut nommer | Le vocabulaire du moteur |
| Les fenêtres de rétention ClickHouse | Une décision de déploiement, pas de tenant |
| Les actions SOAR disponibles | Du code, pas de la configuration |
