# 05 — Sécurité

## Le modèle, en une page

```
   Personne                                    Service
      │                                           │
      │ 1. mot de passe + TOTP                    │ 1. client_id + secret
      ▼                                           ▼
 ┌──────────┐      ┌──────────┐             ┌──────────┐
 │ Keycloak │  ou  │ identity │             │ identity │
 │  (OIDC)  │      │  (RS256) │             │  (RS256) │
 └────┬─────┘      └────┬─────┘             └────┬─────┘
      │                 │                        │
      └────── jeton ────┴────────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ authmw.RequireJWT │  signature vérifiée (clé publique)
              └─────────┬─────────┘
                        ▼
              ┌───────────────────┐
              │ rbac : qui, quel  │  tenant, rôles, permissions —
              │ tenant, quoi      │  depuis les tables de LA plateforme
              └─────────┬─────────┘
                        ▼
              ┌───────────────────┐
              │ RequirePermission │  403 si la permission manque
              └───────────────────┘
```

**Un jeton d'un fournisseur externe fait foi sur l'identité et rien d'autre.**
Le tenant, les rôles et les permissions viennent des tables de la plateforme :
les rôles de royaume de Keycloak sont un autre vocabulaire, et l'autorisation
reste là où elle peut être auditée.

---

## Authentification

### Les jetons

RS256, asymétrique. **Une seule clé privée, chez `identity`** ; tous les autres
services ne portent que la publique. Un service compromis ne peut donc pas
émettre de jeton.

C'est un changement de nature par rapport à HS256 : un secret partagé fait de
chaque porteur un émetteur.

| | Durée |
|---|---|
| Jeton d'accès | 60 min en développement (`JWT_EXPIRY_MINUTES`) |
| Jeton de rafraîchissement | 24 h (`JWT_REFRESH_EXPIRY_HOURS`) |

### Deux émetteurs acceptés

| Émetteur | Qui s'en sert | Vérifié par |
|---|---|---|
| `identity` | L'API directe, les comptes de service | La clé publique RS256 locale |
| Keycloak | L'interface web | Les clés publiées du royaume (JWKS) |

L'interface authentifie contre Keycloak et envoie **le jeton de Keycloak** aux
services. Avant que ce soit géré, chaque appel depuis un navigateur était
refusé : l'interface pouvait connecter quelqu'un et ne rien lire ensuite.

### MFA

TOTP, avec `MFA_ISSUER` comme émetteur affiché dans l'application
d'authentification. Enrôlement et vérification :
`POST /api/v1/users/{userID}/mfa/enroll` et `/verify`.

---

## Autorisation

### Un middleware, pas trente

`authmw` est la seule implémentation. Les trente copies qu'il a remplacées
avaient divergé : **une seule vérifiait l'algorithme de signature du jeton**,
les autres décodaient et faisaient confiance.

### Deux formes

```go
// Le verbe suffit : GET → vulnerabilities:read, le reste → vulnerabilities:write
r.Use(authmw.RequirePermissionByMethod("vulnerabilities"))

// Le verbe ne suffit pas : adopter une règle est une écriture, pas un POST
// quelconque
r.With(authmw.RequirePermission("rules:write")).Post("/{code}/adopt", h.Adopt)
```

La permission exigée par chacune des 477 routes est dans
[07 — Référence API](07-reference-api.md).

### Le catalogue de permissions

Les ressources, en `resource:action` :

```
alerts:read  alerts:write  alerts:suppress
api_keys:read  api_keys:write  api_keys:delete
assets:read  assets:write
attack_paths:read  attack_paths:write
audit:read  audit:export
compliance:read  compliance:write
config:read  config:write
connectors:read  connectors:write  connectors:delete
copilot:read  copilot:write
cspm:read   dlp:read   dspm:read   easm:read
fraud:read  fraud:write  fraud:delete
iga:read  iga:write
incidents:read  incidents:write
knowledge_graph:read  knowledge_graph:write
mobile:read  mobile:write
netsec:read  netsec:write
notifications:read  notifications:write
ot_assets:read
pam:read  pam:write  pam:delete
playbooks:read  playbooks:write
reports:read  reports:write  reports:generate
risk:read  risk:write
roles:read  roles:write
rules:read  rules:write
soar:read  soar:write
supply_chain:read
tenants:read
threat_intel:read  threat_intel:write  threat_intel:delete
ueba:read  ueba:write
users:read  users:write  users:delete
vulnerabilities:read  vulnerabilities:write
```

Trois actions méritent d'exister à part de `read` :

- **`audit:export`** — lire la piste d'audit et l'emporter sont deux autorités
  différentes ;
- **`alerts:suppress`** — faire taire une alerte n'est pas la modifier ;
- **`reports:generate`** — produire un rapport consomme des ressources.

### Les rôles

Les rôles de royaume Keycloak (`platform_admin`, `ciso`, `soc_analyst_l1`,
`soc_analyst_l2`, `risk_manager`, `dpo`, `auditor`) servent à **l'amorçage** :
ils disent quelles permissions une personne reçoit dans les tables de la
plateforme. Ce sont ces tables qui font autorité à l'exécution.

**Une seule notion d'administrateur.** Il y en avait deux — un drapeau dans la
table des utilisateurs et un rôle — et elles ne se recouvraient pas. La
migration 35 les a unifiées sur `super_admin`.

---

## L'identité de service

Quand `soar` exécute un playbook qui bloque une adresse, il appelle `netsec`
avec **son propre jeton**, pas celui de l'analyste.

Deux raisons, et chacune suffit :

1. L'analyste n'a pas forcément `netsec:write`. Lui faire porter l'action
   l'obligerait à détenir toutes les permissions qu'un playbook peut exercer.
2. Le journal d'audit doit dire que **le playbook** a agi. « L'analyste a bloqué
   10.0.0.5 » est faux si l'analyste a seulement cliqué sur « exécuter ».

```
SOAR_CLIENT_ID=soar-executor
SOAR_CLIENT_SECRET=…
```

Le compte vit en base (migration 31), avec le rôle `soar_executor`
(migration 32). `svcauth` renouvelle le jeton avant expiration, pour qu'un
appel n'échoue pas parce que le jeton est mort entre la vérification et
l'arrivée de la requête.

**Le Copilot fait l'inverse, et c'est voulu** : il *propage* le jeton de
l'appelant. Un assistant ne doit jamais lire ce que la personne qui l'interroge
ne pourrait pas lire elle-même ; agir sous une identité de service élargirait
sa portée au lieu de la refléter.

---

## Le cloisonnement multi-tenant

Le tenant vient **du jeton**, jamais d'un paramètre de requête. Un appelant ne
peut pas demander les données d'un autre tenant en changeant une URL : il n'y
a pas d'URL à changer.

```go
tenantID := authctx.TenantID(r.Context())   // du jeton, résolu par authmw
```

Chaque table porte `tenant_id`, et chaque lecture le filtre. Les politiques
paramétrables s'appuient sur un index unique partiel
(`WHERE effective_to IS NULL`) qui garantit **une seule version active par
tenant**.

---

## Le contenu signé

Le catalogue de détection se livre séparément du code, dans un artefact signé
en Ed25519, publié dans un canal lui aussi signé. Trois décisions :

- **La clé de contenu n'est pas celle des jetons.**
- **La confiance est configurée par le déploiement**, jamais portée par la
  livraison.
- **La signature couvre un manifeste d'empreintes**, pour qu'un échec nomme le
  fichier fautif.

Et un ordre : signature → empreintes par fichier → analyse. Analyser d'abord
serait passer un décodeur YAML sur des octets dont personne ne répond.

Procédure, rotation et révocation :
[`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md).

---

## Le transport

| | État |
|---|---|
| Syslog | TLS disponible (`SYSLOG_TLS_ADDR`), certificats auto-signés en développement |
| API | **HTTP en clair en développement.** Un déploiement réel met un terminateur TLS devant |
| Inter-services | HTTP en clair sur le réseau Docker |
| PostgreSQL | `sslmode=disable` en développement |

**C'est le principal écart avec un déploiement réel.** Rien dans le code ne s'y
oppose : les adresses sont des variables d'environnement.

---

## Ce qui n'est pas fait

- **Pas de limitation de débit.** Ni par tenant, ni par adresse.
- **Pas de rotation automatique des clés de jetons.** La paire est générée une
  fois ; une rotation est une opération manuelle non documentée (celle de la
  clé de *contenu* l'est, elle).
- **Pas de révocation de jeton.** Un jeton d'accès reste valide jusqu'à
  expiration, même si le compte est désactivé.
- **Pas de chiffrement au repos** piloté par l'application. C'est laissé au
  stockage sous-jacent.
- **Pas de journalisation des refus d'autorisation** sous forme exploitable :
  un 403 est journalisé, il n'alimente pas de détection.

Ces points sont dans la roadmap, en Phase 1 :
[`../plan/19-AUDIT-AND-ROADMAP.md`](../plan/19-AUDIT-AND-ROADMAP.md).
