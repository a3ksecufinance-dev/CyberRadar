# 12 — Vulnérabilités

`services/vuln` tient la bibliothèque des vulnérabilités, les constats sur les
actifs, les campagnes de scan et les tickets de remédiation.

---

## Les objets

| | Ce que c'est |
|---|---|
| **Vulnérabilité** | Une CVE : identifiant, CVSS, sévérité, exploitation connue |
| **Constat** (*finding*) | Le lien actif ↔ vulnérabilité, avec son échéance |
| **Scan** | Une campagne |
| **Ticket** | Le suivi de remédiation |

```
GET  /api/v1/vuln/vulnerabilities           la bibliothèque CVE
GET  /api/v1/vuln/findings                  les constats
POST /api/v1/vuln/findings/bulk             import en masse
GET  /api/v1/vuln/assets/{assetID}/exposure l'exposition d'un actif
GET  /api/v1/vuln/scans
GET  /api/v1/vuln/tickets
GET  /api/v1/vuln/stats
```

---

## L'exposition

```go
func computeExposure(cvss float64, severity string, isExploited bool) float64 {
    base := cvss                          // 0–10
    if isExploited {
        base = min10(base + 1.5)          // majoration KEV
    }
    switch severity {
    case SeverityCritical: base = min10(base * 1.1)
    case SeverityHigh:     base = min10(base * 1.05)
    }
    return base
}
```

> **Un défaut trouvé en exécutant, pas en lisant.** L'unique appelant passait
> `false` en dur pour `isExploited`. La majoration KEV n'avait **jamais** été
> appliquée. Corrigé : deux vulnérabilités HIGH réellement exploitées sont
> passées de 7,8 à 9,77.

---

## Les délais de remédiation

Un délai de remédiation est un **engagement**, pas une constante. Trois
institutions n'ont pas les mêmes, et celles qui ont signé quelque chose n'ont
pas le choix.

### Le calcul

```go
func (p *RemediationPolicy) DueDays(severity string, c FindingContext) int {
    days := p.BaseDays(severity)

    tighten := func(ceiling *int, applies bool) {
        if applies && ceiling != nil && *ceiling < days { days = *ceiling }
    }
    tighten(p.ExploitedDays, c.Exploited)
    tighten(p.DMZDays,       c.DMZ)
    tighten(p.CBSDays,       c.CBS)
    tighten(p.SWIFTDays,     c.SWIFT)
    tighten(p.PCIDays,       c.PCI)

    if days < p.MinimumDays { days = p.MinimumDays }
    if days < 1             { days = 1 }
    return days
}
```

Un plafond **resserre, jamais ne relâche** : un contexte aggravant ne peut pas
allonger une échéance. Et un plancher (`minimum_days`) empêche une
accumulation de plafonds de produire un délai que personne ne peut tenir.

### Les préréglages

| Code | Base C/H/M/L | Plafonds | Pour qui |
|---|---|---|---|
| `banking_default` | 3 / 7 / 30 / 90 | aucun | **Exactement ce que la plateforme faisait avant.** L'adopter ne déplace aucune échéance |
| `exploit_aware` | 3 / 7 / 30 / 90 | exploité 1 j, DMZ 7 j | Ce qui est attaqué aujourd'hui ne se traite pas au rythme de ce qui pourrait l'être un jour |
| `pci_dss` | 3 / 7 / 30 / 90 | + PCI 14 j | Quand l'évaluateur PCI est le lecteur principal |
| `swift_cscf` | 3 / 7 / 30 / 90 | + CBS 7 j, SWIFT 7 j | Quand l'attestation CSCF pilote le reporting |
| `dora_critical` | 2 / 5 / 21 / 60 | exploité 1 j, DMZ 5 j, CBS 5 j, SWIFT 5 j, PCI 14 j | Quand le registre DORA pilote la priorisation |

Le premier est le seul qui soit neutre. Les quatre autres sont **ce que nous
conseillerions, et que nous n'imposons pas**.

### Le calcul est en SQL

L'échéance est posée à l'insertion :

```sql
NOW() + make_interval(days => $11)                                  -- nouveau
asset_vulnerabilities.first_seen_at + make_interval(days => $11)    -- existant
```

Sur un constat déjà connu, l'échéance part de **la première observation**, pas
de la dernière : un scan qui repasse tous les jours ne doit pas repousser
l'échéance tous les jours.

> **Un second défaut, jumeau du premier.** Le drapeau d'exploitation arrivait
> bien à l'exposition mais pas à l'échéance : `FindingContexts` lit
> l'inventaire des actifs, alors que l'exploitation appartient à la
> vulnérabilité. Corrigé en posant `fctx.Exploited` dans `UpsertFinding`
> plutôt qu'en demandant aux appelants de le renseigner deux fois.

---

## Le contexte d'un constat

| Champ | D'où il vient |
|---|---|
| `Exploited` | La vulnérabilité (KEV) |
| `DMZ`, `CBS`, `SWIFT`, `PCI` | L'inventaire des actifs |

---

## Ce qui n'est pas fait

- **Aucun connecteur de scanner.** Ni Qualys, ni Tenable, ni rien. Les
  constats entrent par l'API (`/findings/bulk`).
- **Pas d'alimentation CVE automatique.** La bibliothèque est remplie par
  l'API.
- **Pas d'enrichissement KEV automatique.** Le drapeau d'exploitation est une
  donnée portée par la vulnérabilité, qu'il faut poser.
- **Pas d'alerte sur dépassement d'échéance.** L'échéance est calculée et
  stockée ; rien ne surveille son dépassement.
