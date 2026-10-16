# 13 — Chemins d'attaque

`services/attackpath` tient un graphe du parc et calcule, pour un scénario
donné, les routes qu'un attaquant pourrait emprunter d'un point d'entrée à une
cible.

---

## Le graphe

| | |
|---|---|
| **Nœud** | Un actif, un compte, un service. Porte sa criticité (1–4), son score de risque, et s'il est un système critique |
| **Arête** | Une transition possible. Porte sa complexité d'attaque (`LOW`/`MEDIUM`/`HIGH`), les privilèges requis (`NONE`/`LOW`/`HIGH`), et un poids |

Stocké dans PostgreSQL, **et** dans Neo4j quand il est configuré. Les lectures
restent sur PostgreSQL par défaut (`ATTACKPATH_GRAPH_READS`) jusqu'à ce qu'une
réconciliation rapporte l'égalité.

```bash
make graph-reconcile   # compare les deux
make graph-backfill    # recopie depuis PostgreSQL, puis vérifie
```

---

## Le coût d'une arête

```go
func (p *AttackPolicy) EdgeCost(e *AttackEdge) float64 {
    // Une arête dont le vocabulaire ne dit rien garde le poids qu'on lui a donné.
    if e.AttackComplexity == "" && e.PrivilegesRequired == "" && e.Weight > 0 {
        return e.Weight
    }
    cost := p.BaseCost
    switch e.AttackComplexity {
    case "MEDIUM": cost += p.ComplexityMedium
    case "HIGH":   cost += p.ComplexityHigh
    }
    switch e.PrivilegesRequired {
    case "LOW":  cost += p.PrivilegeLow
    case "HIGH": cost += p.PrivilegeHigh
    }
    return cost
}
```

Le repli n'est pas une commodité : toute arête que la plateforme crée porte les
deux champs, donc il n'est atteint que par une arête **importée** avec un coût
et sans récit de sa provenance. L'aplatir sur le coût de base effacerait en
silence ce que l'import savait et que ce vocabulaire ne sait pas dire.

---

## Le score d'un chemin

```go
avgCost := totalCost / hopCount
score   := 10.0 / (1.0 + avgCost) * pow(HopDecay, hopCount-1)
```

Plus de sauts **et** des arêtes plus lourdes rendent l'attaque plus difficile,
donc les deux **baissent** le score.

> **Une formule antérieure multipliait par le nombre de sauts.** Un chemin de
> cinq sauts marquait donc plus qu'un chemin d'un saut au même coût : elle
> classait les attaques les plus difficiles comme les plus dangereuses, ce qui
> est l'inverse de ce qu'il faut pour une liste qu'on travaille par le haut.

---

## L'impact

```go
switch {
case target.Criticality > 0:
    impact = min(ImpactCeiling, Criticality/4.0 * ImpactCeiling)
case target.RiskScore > 0:
    impact = min(ImpactCeiling, target.RiskScore)
default:
    impact = UnknownTargetImpact      // une posture, pas une constante
}
if target.IsCriticalSystem { impact += CriticalSystemBonus }
```

> **Chaque chemin enregistrait auparavant un impact fixe de 7,0**, quelle que
> soit la cible. L'impact ne portait donc aucune information, et tout
> classement qui s'en servait était arbitraire.

**Ce qu'on suppose d'une cible inconnue est une posture, pas un défaut.** La
poser haut traite l'inconnu comme dangereux : plus sûr, et plus bruyant. La
poser bas concentre l'attention, et c'est aussi par là qu'on passe à côté de
quelque chose.

---

## Les préréglages

| Code | Pour qui | Ce qui change |
|---|---|---|
| `balanced` | **Exactement les constantes antérieures.** L'adopter ne reclasse aucun chemin | base 1,0 · décroissance 0,85 · plafond 9,0 · inconnu 4,5 |
| `assume_breach` | Après un exercice d'équipe rouge qui a traversé le parc | La complexité et les privilèges freinent peu, la distance ne protège pas (décroissance 1,0). Beaucoup plus de chemins ressortent — **c'est le but, et c'est bruyant** |
| `exploitability_led` | Une équipe qui doit prioriser peu de corrections | Complexité élevée et privilèges administrateur coûtent cher, chaque saut retire un quart de la menace. Moins de chemins, plus tranchés |
| `crown_jewels` | Quand le conseil demande les joyaux de la couronne | L'impact domine : système critique +2, plafond à 10, cible inconnue supposée peu importante (3,0). **À n'utiliser qu'avec un inventaire tenu** |

Les dix paramètres : `base_cost`, `complexity_medium`, `complexity_high`,
`privilege_low`, `privilege_high`, `hop_decay`, `impact_ceiling`,
`unknown_target_impact`, `critical_system_bonus`, `many_paths_boost`.

Paramétrage : [16 — Paramétrage](16-parametrage.md).

---

## Les scénarios

Un scénario nomme un point d'entrée, une cible, et conserve les chemins
trouvés. Chaque exécution enregistre le code et la version de la politique
appliquée (`policy_code`, `policy_version` sur `attack_scenarios`) : un
classement qu'on relit six mois plus tard doit pouvoir dire sous quelles
pondérations il a été produit.

> **Un défaut trouvé en regardant les données.** `SavePaths` ajoutait
> indéfiniment : un `ON CONFLICT DO NOTHING` ne déduplique jamais face à un
> identifiant neuf. Un scénario qui rapportait 2 chemins en détenait 38, issus
> de 19 exécutions. Corrigé : la sauvegarde prend l'identifiant du scénario et
> remplace en une transaction — **y compris quand le résultat est vide**, sans
> quoi un scénario qui ne trouve plus rien garderait les chemins d'hier.

La politique est lue **par requête**, pas mise en cache : l'analyse d'un
scénario est une opération lourde et peu fréquente, le coût d'une lecture y est
négligeable — l'inverse du moteur UEBA.

---

## L'API

```
GET  /api/v1/attackpath/nodes
GET  /api/v1/attackpath/edges
GET  /api/v1/attackpath/scenarios
POST /api/v1/attackpath/scenarios/{id}/analyze
GET  /api/v1/attackpath/paths
```

Liste complète : [07 — Référence API](07-reference-api.md).

---

## Ce qui n'est pas fait

- **Le graphe n'est pas alimenté automatiquement.** Nœuds et arêtes entrent
  par l'API ; rien ne les déduit de l'inventaire ni du trafic.
- **`maxPathsPerScenario = 200` reste une constante**, délibérément : c'est une
  borne de calcul, pas un jugement métier. La rendre paramétrable laisserait
  un tenant faire tomber l'analyseur.
- **Pas de simulation de correction.** On ne peut pas demander « que devient
  ce classement si je corrige cet actif ».
