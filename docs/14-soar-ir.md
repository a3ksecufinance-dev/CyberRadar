# 14 — SOAR et réponse à incident

Deux services, deux rôles distincts :

| | |
|---|---|
| **`soar`** | Les playbooks : une suite d'actions exécutées automatiquement à partir d'une alerte |
| **`ir`** | Le dossier d'incident : preuves, tâches, chronologie, playbooks de réponse humains |

---

## SOAR

### Le modèle

```
alerte ──▶ playbook ──▶ étape 1 ──▶ étape 2 ──▶ …
                           │
                      Dispatcher : exécute UNE action
                      Executor   : séquence, reprises, persistance
```

La séparation est ce qui rend l'abandon sur échec testable sans base de
données : l'exécuteur ne connaît que quatre méthodes du dépôt.

### Les quinze actions

Elles appellent les **vraies API** des autres services. Ce ne sont pas des
simulations.

| Action | Ce qu'elle fait |
|---|---|
| `block_ip` | Installe une politique de refus dans `netsec`, dans les deux sens |
| `unblock_ip` | Retire la politique par son nom (`netsec` n'a pas de route de suppression) |
| `disable_user` / `enable_user` | `identity` |
| `isolate_host` / `unisolate_host` | `asset` |
| `enrich_ioc` | `ti` |
| `add_to_blocklist` | `ti` |
| `create_ticket` / `close_ticket` | `vuln` |
| `send_notification` | `notification` |
| `run_siem_query` | `siem` |
| `tag_entity` | `asset` |
| `mark_compromised` | `asset` |
| `create_incident` | `ir` |
| `wait` | Géré par l'exécuteur, qui possède l'horloge entre les étapes |

### Sous quelle identité

**Celle du playbook, pas celle de l'analyste.**

```
SOAR_CLIENT_ID=soar-executor
SOAR_CLIENT_SECRET=…
```

Deux raisons, et chacune suffit : l'analyste n'a pas forcément `netsec:write`,
et le journal d'audit doit dire que c'est le playbook qui a agi. « L'analyste a
bloqué 10.0.0.5 » est faux s'il a seulement cliqué sur « exécuter ».

Voir [05 — Sécurité](05-securite.md).

### Les bornes

| | Valeur |
|---|---|
| Délai par défaut d'une action | 15 s (`defaultActionTimeout`) |
| Corps d'erreur conservé | 512 octets (`maxErrorBody`) |

Une étape qui pend retient toutes celles qui suivent, d'où le délai. Le corps
d'erreur est tronqué parce qu'il est lu par des analystes et stocké par étape :
une réponse HTML de 200 Ko dans un enregistrement d'exécution n'aide personne.

### Les paramètres d'une étape

Un paramètre non fourni est **résolu depuis l'événement** (`resolveParam`) :
un playbook écrit une fois sert pour toute alerte qui porte le champ attendu.

### L'API

```
GET  /api/v1/soar/incidents
GET  /api/v1/soar/incidents/{id}/timeline
GET  /api/v1/soar/playbooks
POST /api/v1/soar/playbooks/{id}/execute
GET  /api/v1/soar/executions
```

---

## Réponse à incident

`ir` tient le dossier, là où `soar` tient l'automatisation.

| Objet | Routes |
|---|---|
| Incidents | `GET|POST /api/v1/ir/incidents`, `PATCH /{id}` |
| Preuves | `/{id}/evidence`, `PATCH /{id}/evidence/{evidenceID}` |
| Tâches | `/{id}/tasks`, `PATCH /{id}/tasks/{taskID}` |
| Chronologie | `/{id}/timeline` |
| Playbooks de réponse | `/api/v1/ir/playbooks` |
| Statistiques | `/api/v1/ir/stats` |

Permissions : `incidents:read|write` pour les incidents, `playbooks:read|write`
pour les playbooks.

### Et les cas SIEM ?

Trois objets voisins, qu'il vaut mieux ne pas confondre :

| | Service | Ce que c'est |
|---|---|---|
| **Cas** | `siem` | Le regroupement d'alertes qu'un analyste N1 constitue |
| **Incident SOAR** | `soar` | Ce sur quoi un playbook s'est déclenché |
| **Incident IR** | `ir` | Le dossier formel : preuves, tâches, chronologie |

`POST /api/v1/siem/alerts/{alertID}/case` crée le premier.
L'action `create_incident` d'un playbook crée le troisième.

> Rien ne relie automatiquement les trois. C'est un écart connu : un analyste
> qui escalade un cas SIEM en incident IR le fait à la main.

---

## Ce qui n'est pas fait

- **Pas de déclenchement automatique de playbook sur alerte.** `soar` consomme
  `crp.events.alerts`, mais l'association alerte → playbook se fait par appel
  explicite.
- **Pas d'approbation humaine dans un playbook.** Une étape s'exécute ou
  échoue ; il n'y a pas d'étape « attendre qu'un humain valide ».
- **Pas d'annulation d'une exécution en cours.**
- **Pas de lien entre cas SIEM, incident SOAR et dossier IR.**
