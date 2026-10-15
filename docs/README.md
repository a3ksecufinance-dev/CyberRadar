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
| Vous présentez la plateforme | [21 — Démonstration](21-demonstration.md) — contrôle avant-vol, déroulé, et les chiffres à ne pas embellir |
| On vous demande des chiffres de performance | [22 — Mesures](22-mesures.md) — les trois chiffres, la machine qui les a produits, et pourquoi le plafond est topologique |
| On se demande à quoi sert le produit | [25 — Positionnement](25-positionnement.md) — la thèse, le tri des 32 services, et ce qu'on peut dire à un client |
| Un client veut l'installer chez lui | [23 — Prérequis de déploiement](23-prerequis-deploiement.md) — bénéfices, dimensionnement chiffré, et ce qui n'est pas prêt |
| Le client est une banque, avec une filiale EDP | [24 — Apport pour une banque de 300+ agences](24-apport-banque-edp.md) — l'apport obligation par obligation, et les six écarts à combler |

---

## Les guides

### Comprendre

- **[01 — Vue d'ensemble](01-vue-densemble.md)** — ce que fait la plateforme, les domaines couverts, l'état réel de chacun.
- **[02 — Architecture](02-architecture.md)** — les 32 services, le flux d'un événement, les dépôts de données, les décisions structurantes.
- **[20 — Glossaire](20-glossaire.md)** — le vocabulaire du produit et celui du code.

### Installer et exploiter

- **[03 — Installation](03-installation.md)** — poste de développement, Docker Compose, jeu de démonstration.
- **[04 — Configuration](04-configuration.md)** — variables d'environnement, ports, secrets, Vault.
- **[21 — Démonstration](21-demonstration.md)** — présenter à un client ou à un intégrateur : une commande pour le verdict, le déroulé minuté, ce qu'il ne faut pas ouvrir, et le durcissement d'une machine joignable.
- **[22 — Mesures](22-mesures.md)** — débit d'ingestion, latence API p95, temps de détection : ce que `make bench` mesure, sur quelle machine, et la réponse mesurée à la question des 100 K EPS.
- **[25 — Positionnement](25-positionnement.md)** — à quoi sert ce produit : une plateforme de sécurité dont la conformité est une sortie, le tri des 32 services en cœur / soutien / hors thèse, et la règle qui sépare ce qu'on peut dire d'un client de ce qu'on ne peut pas.
- **[23 — Prérequis de déploiement](23-prerequis-deploiement.md)** — ce qu'une microfinance gagne à l'installer, le dimensionnement dérivé des mesures, les prérequis d'infrastructure sur site, et la liste de ce qui n'est pas encore prêt.
- **[24 — Apport pour une banque de 300+ agences](24-apport-banque-edp.md)** — l'apport confronté à la DNSSI, à la loi 09-08, à la CNDP, à l'ISO 27001 et à DORA pris en référentiel volontaire ; le cas de la filiale EDP partageant le core banking ; le dimensionnement refait ; les six écarts classés.
- **[La présentation](presentation/)** — le document PDF pour un intégrateur, un DSI ou une direction générale, sa source et son contrôle de mise en page.
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
