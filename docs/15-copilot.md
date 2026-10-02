# 15 — Copilot

Un assistant qui répond sur **les données de la plateforme**, en appelant ses
services comme outils.

> **Il exige une clé API.** Sans `ANTHROPIC_API_KEY`, le service ne démarre pas
> et le script d'installation le signale en le passant. Son onglet dans
> l'interface est alors inopérant.

---

## La boucle

```
question ──▶ modèle ──▶ appel d'outil ──▶ service de la plateforme
                 ▲                              │
                 └──────── résultat ◀───────────┘
                 │
                 ▼
             réponse
```

Une boucle agentique : le modèle choisit ses outils, lit les résultats, et
recommence jusqu'à pouvoir répondre.

---

## Sous quelle identité

**Celle de l'appelant.** Chaque appel d'outil porte le jeton de la personne qui
pose la question.

```go
// Each Dispatch call reaches the target microservice over HTTP carrying the
// asking user's own bearer token, so a tool can never read more than that
// user could read directly.
```

C'est l'inverse du SOAR, et c'est voulu : un assistant ne doit jamais lire ce
que la personne qui l'interroge ne pourrait pas lire elle-même. Agir sous une
identité de service élargirait sa portée au lieu de la refléter — et un
assistant qui en sait plus que son utilisateur est une fuite avec une interface
conversationnelle.

---

## Les dix outils

| Outil | Service appelé |
|---|---|
| `query_alerts` | `siem` |
| `lookup_ioc` | `ti` |
| `get_incident` | `ir` |
| `query_anomalies` | `ueba` |
| `query_vulnerabilities` | `vuln` |
| `analyze_attack_path` | `attackpath` |
| `search_entities` | `knowledgegraph` |
| `get_asset` | `asset` |
| `query_platform_stats` | `dashboard` |
| `hunt_threats` | plusieurs |

Les adresses viennent de l'environnement (`SIEM_SERVICE_URL`,
`UEBA_SERVICE_URL`, …) — voir [04 — Configuration](04-configuration.md).

---

## Le RAG

Une base de connaissance dans `pgvector` (migration 34), interrogée par
similarité pour donner du contexte au modèle.

**L'embarquement est une interface**, pas une dépendance :

```go
// It is an interface because where embeddings come from is a deployment
// decision, not a code one. Anthropic has no embeddings endpoint, so the
// model behind this is never the one answering the question.
```

L'implémentation fournie parle le dialecte `/v1/embeddings` compatible OpenAI.
C'est délibéré : c'est ce que parle un serveur auto-hébergé —
text-embeddings-inference, vLLM, Ollama, LocalAI — aussi bien que les
fournisseurs hébergés. **Une banque qui ne peut pas envoyer le texte de ses
incidents hors de ses murs** branche le sien et ne change pas une ligne.

| Variable | Défaut |
|---|---|
| `EMBEDDINGS_URL` | — |
| `EMBEDDINGS_API_KEY` | — |
| `EMBEDDINGS_MODEL` | `BAAI/bge-large-en-v1.5` |

---

## Les réglages

| Variable | Rôle |
|---|---|
| `ANTHROPIC_API_KEY` | **Obligatoire** |
| `ANTHROPIC_BASE_URL` | Pour une passerelle d'entreprise |
| `ANTHROPIC_MODEL` | Surcharge du modèle |
| `COPILOT_EFFORT` | L'effort de raisonnement |
| `COPILOT_MAX_TOKENS` | Le plafond de sortie |

---

## L'API

```
POST /api/v1/copilot/conversations
POST /api/v1/copilot/conversations/{id}/messages
GET  /api/v1/copilot/conversations/{id}
GET  /api/v1/copilot/knowledge
POST /api/v1/copilot/knowledge
```

Liste complète : [07 — Référence API](07-reference-api.md).

---

## Ce qui n'est pas fait

- **Pas d'action.** Les dix outils lisent. Le Copilot ne peut rien bloquer, ni
  désactiver, ni modifier. C'est un choix : donner à un assistant la capacité
  d'agir demande un modèle d'approbation qui n'existe pas encore.
- **Pas d'indexation automatique.** La base de connaissance se remplit par
  l'API.
- **Pas de limite de dépense.** Rien ne borne le nombre d'appels au modèle par
  tenant ou par jour.
- **Le texte des incidents part chez le fournisseur du modèle**, sauf passerelle
  configurée. Les embarquements, eux, peuvent rester sur place.
