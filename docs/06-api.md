# 06 — API : conventions

La liste des 477 routes est dans [07 — Référence API](07-reference-api.md), et
elle est générée depuis le code. Cette page-ci dit ce qui est vrai de toutes.

---

## Base

```
http://<service>:<port>/api/v1/…
Authorization: Bearer <JWT>
Content-Type: application/json
```

Il n'y a **pas de passerelle** : l'interface appelle chaque service sur son
port. La table des ports est dans [04 — Configuration](04-configuration.md).

**Le tenant n'est jamais dans l'URL.** Il vient du jeton. Un appelant ne peut
pas lire les données d'un autre tenant en changeant une adresse, parce qu'il
n'y a pas d'adresse à changer.

---

## L'enveloppe

Toutes les réponses, succès comme échec, ont la même forme :

```json
{
  "data":  …,
  "meta":  { "page": 1, "limit": 50, "total": 128, "tenant_id": "…" },
  "error": { "code": "…", "message": "…", "details": … }
}
```

`meta` n'apparaît que sur les listes. `error` est `null` en cas de succès.

### `total` est toujours émis

Il portait `omitempty`, donc une page sans résultat répondait sans total, et un
client ne pouvait pas distinguer « aucune correspondance » de « cet endpoint ne
rapporte pas de total ». **Zéro correspondance est une réponse.**

`page` et `limit` gardent `omitempty` : ils ne s'appliquent vraiment pas à un
endpoint qui renvoie tout ce qu'il a, et leur absence le dit.

---

## Exemples réels

### Une liste

```
GET /api/v1/siem/rule-library
```
```json
{
  "data": [
    { "content": { "code": "CRP-C2-0001", "version": 3,
                   "severity": "CRITICAL", "…": "…" } }
  ],
  "meta": { "total": 15 },
  "error": null
}
```

### Une pagination

```
GET /api/v1/vuln/findings?page=1&limit=2
```
```json
{ "data": [ … 2 éléments … ], "meta": { "total": 15 } }
```

### Une ressource absente

```
GET /api/v1/siem/rule-library/CRP-XXX-9999
```
```json
{ "data": null,
  "error": { "code": "NOT_FOUND",
             "message": "no detection named \"CRP-XXX-9999\" in the library" } }
```

### Sans jeton

```json
{ "error": { "code": "UNAUTHORIZED", "message": "Missing Authorization header" } }
```

### Avec un jeton, sans la permission

```
POST /api/v1/siem/rules      (compte dpo@bnf.fr)
```
```json
{ "error": { "code": "FORBIDDEN", "message": "permission required: rules:write" } }
```

Le message **nomme la permission manquante**. Un 403 qui ne dit pas laquelle
oblige à deviner.

### Une validation

```json
{ "data": null,
  "error": { "code": "VALIDATION_ERROR",
             "message": "Request validation failed",
             "details": "Key: 'CreateVulnRequest.Title' Error:Field validation for 'Title' failed on the 'min' tag" } }
```

### La santé

```
GET /health          (sans authentification)
```
```json
{ "status": "ok", "service": "siem-service" }
```

---

## Pagination

```
?page=1&limit=50
```

`page` commence à 1. Les endpoints qui renvoient un ensemble borné par nature
— les préréglages d'une politique, la couverture d'un catalogue — ne paginent
pas et n'émettent ni `page` ni `limit`.

---

## Les erreurs

### Les genres du domaine

Le code métier ne renvoie jamais un code HTTP : il renvoie une erreur typée,
qu'une seule couche traduit.

| Genre | HTTP | Sens |
|---|---|---|
| `KindNotFound` | 404 | La ressource n'existe pas pour ce tenant |
| `KindConflict` | 409 | L'état actuel interdit l'opération |
| `KindForbidden` | 403 | Identifié, pas autorisé |
| `KindUnauth` | 401 | Pas identifié |
| `KindBadInput` | 400 | La requête est malformée |
| `KindInternal` | — | **L'absence de jugement**, pas un jugement |

**`KindInternal` ne devient pas un 500 tout de suite.** C'est le service qui
dit « j'ai rencontré une erreur que je n'arrive pas à classer ». Le pilote en
dessous, lui, sait souvent : la traduction laisse donc passer au niveau
suivant. Une violation de contrainte `NOT NULL` emballée ainsi arrivait chez
l'appelant comme « an internal error occurred » alors que la réponse honnête —
quel champ, et qu'il est obligatoire — était une couche plus bas.

### Les codes PostgreSQL

Une contrainte de schéma est une validation. La refuser en 500 serait dire que
la plateforme est en panne alors que c'est la requête qui est fausse.

| SQLSTATE | HTTP | Détails renvoyés |
|---|---|---|
| `23514` CHECK | 422 | `field`, `constraint`, `value is not accepted for this field` |
| `23502` NOT NULL | 422 | `field`, `field is required` |
| `23503` FOREIGN KEY | 422 | `field`, `constraint`, `referenced record does not exist` |
| `23505` UNIQUE | 409 | `a record with these values already exists` |
| `22P02` texte invalide | 400 | `a value is not in the expected format` |
| `22001` trop long | 422 | `field`, `value is too long` |
| `22003` hors bornes | 422 | `field`, `value is out of range` |
| `40P01` interblocage | 500 | C'est la nôtre |
| `pgx.ErrNoRows` | 404 | `resource not found` |

**Le champ est récupéré du nom de la contrainte.** PostgreSQL nomme une
contrainte en ligne `<table>_<colonne>_check` (ou `_fkey`) ; retirer le préfixe
et le suffixe rend la colonne. Un `CHECK` est la façon dont le schéma énonce
une énumération, donc la réponse peut dire quel champ et pourquoi.

### Les codes applicatifs

| `code` | HTTP |
|---|---|
| `UNAUTHORIZED` | 401 |
| `FORBIDDEN` | 403 |
| `NOT_FOUND` | 404 |
| `CONFLICT` | 409 |
| `VALIDATION_ERROR` | 400 / 422 |
| `BAD_INPUT` | 400 |
| `INVALID_VALUE` | 400 |
| `INTERNAL_ERROR` | 500 |

---

## Authentification

```
Authorization: Bearer <JWT>
```

Deux émetteurs sont acceptés : `identity` (RS256, clé publique locale) et
Keycloak (clés publiées du royaume). Le détail est dans
[05 — Sécurité](05-securite.md).

Pour obtenir un jeton par l'API :

```bash
curl -s -X POST http://localhost:8002/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cyberradar.io","password":"Admin@CyberRadar2025!"}'
```

Les autres routes d'authentification : `/auth/refresh`, `/auth/logout`,
`/auth/me`.

---

## Autorisation

Chaque route exige une permission `resource:action`. La colonne **Permission**
de [07 — Référence API](07-reference-api.md) donne celle de chacune des 477.

Deux formes dans le code :

- `RequirePermissionByMethod("x")` — `x:read` pour GET et HEAD, `x:write`
  sinon ;
- `RequirePermission("x:y")` — posée route par route quand le verbe ne suffit
  pas. Adopter une règle de détection est une écriture, pas un POST
  quelconque.

---

## Ce que l'API ne fait pas

- **Pas de versionnement au-delà de `/api/v1`.** Il n'y a pas eu de v2 ; la
  politique de rupture n'est pas écrite.
- **Pas d'idempotence.** Aucun endpoint ne lit d'en-tête `Idempotency-Key` ;
  rejouer un POST crée un second enregistrement.
- **Pas de limitation de débit.**
- **Pas de pagination par curseur.** `page`/`limit` dérive si des lignes sont
  insérées entre deux pages.
- **Pas d'OpenAPI.** La référence générée en tient lieu ; un schéma formel
  reste à produire.
- **Pas d'ETag ni de requête conditionnelle.**

Les politiques paramétrables font exception sur un point : elles utilisent une
concurrence optimiste (le numéro de version dans la clause `WHERE`), donc deux
écritures simultanées ne s'écrasent pas en silence. Voir
[16 — Paramétrage](16-parametrage.md).
