# Documentation CyberRadar Platform

Plateforme de cybersécurité multi-tenant : ingestion d'événements, détection
SIEM/XDR, analyse comportementale, gestion des vulnérabilités, chemins
d'attaque, réponse à incident. 32 services Go, une interface Next.js.

Cette documentation décrit **la plateforme telle qu'elle est**, pas telle
qu'elle est prévue. Ce qui est simulé, partiel ou absent est dit comme tel, à
l'endroit où le lecteur se poserait la question. Pour l'écart entre le produit
visé et le produit existant, et la route entre les deux, voir
[`../plan/19-AUDIT-AND-ROADMAP.md`](../plan/19-AUDIT-AND-ROADMAP.md).

---

## Par où commencer

| Vous êtes | Lisez d'abord |
|---|---|
| Nouveau sur le projet | [01 — Vue d'ensemble](01-vue-densemble.md) puis [03 — Installation](03-installation.md) |
| Développeur back-end | [02 — Architecture](02-architecture.md), [06 — API](06-api.md), [19 — Développement](19-developpement.md) |
| Développeur front-end | [17 — Interface](17-interface.md), [06 — API](06-api.md) |
| Exploitant / SRE | [03 — Installation](03-installation.md), [04 — Configuration](04-configuration.md), [18 — Exploitation](18-exploitation.md) |
| Analyste SOC | [10 — Détection](10-detection.md), [11 — UEBA](11-ueba.md), [14 — SOAR et réponse](14-soar-ir.md) |
| RSSI / conformité | [05 — Sécurité](05-securite.md), [16 — Paramétrage](16-parametrage.md), [08 — Données](08-donnees.md) |
| Auditeur | [05 — Sécurité](05-securite.md), [08 — Données](08-donnees.md), [`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md) |

---

## Les guides

### Comprendre

- **[01 — Vue d'ensemble](01-vue-densemble.md)** — ce que fait la plateforme, les domaines couverts, l'état réel de chacun.
- **[02 — Architecture](02-architecture.md)** — les 32 services, le flux d'un événement, les dépôts de données, les décisions structurantes.
- **[20 — Glossaire](20-glossaire.md)** — le vocabulaire du produit et celui du code.

### Installer et exploiter

- **[03 — Installation](03-installation.md)** — poste de développement, Docker Compose, jeu de démonstration.
- **[04 — Configuration](04-configuration.md)** — variables d'environnement, ports, secrets, Vault.
- **[18 — Exploitation](18-exploitation.md)** — santé, observabilité, incidents courants, sauvegarde.

### Intégrer

- **[06 — API : conventions](06-api.md)** — enveloppe, pagination, erreurs, authentification, idempotence.
- **[07 — Référence API](07-reference-api.md)** — les 477 routes, par service, avec leur permission. *Généré depuis le code.*
- **[09 — Ingestion](09-ingestion.md)** — syslog, collecteur HTTP, pipeline, Kafka, file d'attente d'échec.

### Les domaines

- **[10 — Détection](10-detection.md)** — moteur SIEM, catalogue de détections, bibliothèque et généalogie.
- **[11 — UEBA](11-ueba.md)** — profils comportementaux, anomalies, seuils.
- **[12 — Vulnérabilités](12-vulnerabilites.md)** — exposition, délais de remédiation, tickets.
- **[13 — Chemins d'attaque](13-chemins-attaque.md)** — graphe, scénarios, pondérations.
- **[14 — SOAR et réponse](14-soar-ir.md)** — playbooks, actions réelles, incidents.
- **[15 — Copilot](15-copilot.md)** — assistant, outils, RAG, mémoire.

### Gouverner

- **[05 — Sécurité](05-securite.md)** — authentification, RBAC, identité de service, cloisonnement.
- **[08 — Données](08-donnees.md)** — modèle, migrations, rétention, multi-tenant.
- **[16 — Paramétrage](16-parametrage.md)** — les quatre politiques configurables par tenant.
- **[`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md)** — livrer le contenu de détection, faire tourner et révoquer une clé de signature.

### Mettre en production

- **[`../plan/22-ECART-PREVU-MESURE.md`](../plan/22-ECART-PREVU-MESURE.md)** — ce que la spécification promettait, confronté à ce qui est mesurable : 346 user stories classées, 8 KPI, 14 exigences non fonctionnelles.
- **[`../plan/23-PLAN-EXECUTION.md`](../plan/23-PLAN-EXECUTION.md)** — la route vers le périmètre complet : 14 lots, 2 235 jours-homme, le graphe de dépendances, les portes de qualité, les huit indicateurs.
- **[`../plan/21-PRODUCTION-PLAN.md`](../plan/21-PRODUCTION-PLAN.md)** — le détail du déploiement et de la validation, repris comme lots L0 à L2 et L13 du plan d'exécution.

### Contribuer

- **[17 — Interface](17-interface.md)** — Next.js, internationalisation, conventions.
- **[19 — Développement](19-developpement.md)** — espace de travail Go, tests, CI, conventions de code.

---

## Ce qui est généré

| Fichier | Régénérer | Vérifié par |
|---|---|---|
| [`07-reference-api.md`](07-reference-api.md) | `cd backend && make docs-api` | CI échoue si le fichier dérive du code |

Une liste de routes tenue à la main est une liste fausse, et fausse en silence :
le lecteur l'apprend quand son appel répond 404. Celle-ci est dérivée des
enregistrements de routes des services, et la CI refuse une route ajoutée sans
régénération.
