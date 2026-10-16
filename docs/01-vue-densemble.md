# 01 — Vue d'ensemble

## Ce que fait la plateforme

CyberRadar reçoit des événements de sécurité, les normalise, les enrichit, leur
applique des règles de détection, en déduit des alertes, et donne à un analyste
de quoi décider : un profil comportemental par entité, une exposition par actif,
des chemins d'attaque, des playbooks de réponse.

Elle est **multi-tenant** : un déploiement sert plusieurs organisations, dont
les données, les règles et les seuils sont cloisonnés. Le cloisonnement est
porté par le jeton, pas par un paramètre d'URL — voir
[05 — Sécurité](05-securite.md).

Le domaine visé est le secteur financier régulé : les référentiels cités dans
le contenu livré sont DORA, PCI DSS et SWIFT CSCF, et les quatre politiques
paramétrables ([16 — Paramétrage](16-parametrage.md)) ont des préréglages pour
chacun.

---

## Le chemin d'un événement

```
   source                 collecte            traitement              décision
┌───────────┐  syslog  ┌───────────┐       ┌───────────┐          ┌───────────┐
│ pare-feu  │─────────▶│  syslog   │       │ pipeline  │          │   SIEM    │
│ AD / IAM  │          │ connector │──┐    │  worker   │──┐       │  engine   │
│ EDR, apps │  HTTPS   ├───────────┤  │    └───────────┘  │       └───────────┘
│           │─────────▶│ collector │──┤                   │             │
└───────────┘          └───────────┘  │                   │             ▼
                                      ▼                   ▼         alertes
                               crp.events.raw     crp.events.normalized
                                                          │             │
                                                          ▼             ▼
                                                  crp.events.enriched  UEBA,
                                                   (IOC, actif, géo)   SOAR,
                                                                        KG…
```

Quatre sujets Kafka portent les quatre états d'un événement : brut, normalisé,
enrichi, et — pour ce qui ne passe pas — la file d'échec `crp.events.dlq`. Le
détail est dans [09 — Ingestion](09-ingestion.md).

---

## Les domaines, et leur état réel

Chaque ligne dit ce que le service fait **aujourd'hui**, pas ce qu'il
ambitionne. « CRUD + lectures » signifie que le service stocke, expose et
agrège, mais qu'aucun moteur d'analyse ne tourne derrière.

| Domaine | Service | État |
|---|---|---|
| Socle multi-tenant | `tenant` | Tenants, configuration, **les 4 politiques paramétrables** |
| Identité, MFA, RBAC | `identity` | Connexion, TOTP, jetons RS256, rôles et permissions |
| Journal d'audit | `audit` | Écriture, recherche, export |
| Notifications | `notification` | Canaux, envoi |
| Ingestion | `collector`, `syslog`, `pipeline` | **Réel** : parsers RFC3164/5424/CEF, normalisation, enrichissement IOC |
| Inventaire d'actifs | `asset` | Actifs, criticité, exposition, risque par actif |
| PAM | `pam` | Comptes à privilèges, sessions, fenêtres d'activité |
| SIEM / XDR | `siem` | **Réel** : moteur de règles, seuils, déduplication, alertes, cas, bibliothèque |
| UEBA | `ueba` | **Réel** : profils, scoring pondéré, anomalies, seuils paramétrables |
| Renseignement | `ti` | Indicateurs, flux, index de correspondance en ligne |
| Vulnérabilités | `vuln` | **Réel** : exposition calculée, délais de remédiation paramétrables |
| Chemins d'attaque | `attackpath` | **Réel** : graphe, scénarios, pondérations paramétrables |
| Graphe de connaissance | `knowledgegraph` | Nœuds, arêtes, parcours (PostgreSQL ou Neo4j) |
| SOAR | `soar` | **Réel** : 15 types d'action exécutées contre les vraies API |
| Réponse à incident | `ir` | Incidents, preuves, tâches, chronologie |
| Tableaux de bord | `dashboard` | Widgets, KPI agrégés |
| Copilot | `copilot` | **Réel** : boucle agentique, outils, RAG pgvector. Exige une clé API |
| Pare-feu d'API | `apifw` | CRUD + lectures |
| Conformité | `compliance` | Référentiels, contrôles, constats |
| EASM | `easm` | CRUD + lectures |
| Fraude | `fraud` | CRUD + lectures |
| DLP | `dlp` | CRUD + lectures |
| Sécurité réseau | `netsec` | CRUD + lectures |
| Risque | `risk` | CRUD + lectures |
| IGA | `iga` | CRUD + lectures |
| CSPM | `cspm` | CRUD + lectures |
| Chaîne logicielle | `scs` | CRUD + lectures |
| OT / ICS | `ot` | CRUD + lectures |
| Mobile | `mobile` | CRUD + lectures |
| DSPM | `dspm` | CRUD + lectures |

**Ce que « CRUD + lectures » veut dire concrètement.** Le service a un schéma,
des endpoints qui écrivent et lisent, des agrégats, et une page dans
l'interface. Il n'a pas de moteur qui produit les données tout seul : elles
viennent d'un appel d'API, d'un import, ou du jeu de démonstration. Un
connecteur vers l'outil réel du domaine reste à écrire pour chacun.

---

## Ce qui est livré avec la plateforme

**Quinze détections**, dans `backend/content/detections`, un fichier par
détection. Elles ne sont **pas** dans une migration : le catalogue se livre à
sa propre cadence, signé, et un déploiement peut dire de quelle clé il le tient.
Voir [10 — Détection](10-detection.md) et
[`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md).

| Code | Sévérité | Catégorie |
|---|---|---|
| `CRP-C2-0001` | CRITICAL | Contact avec un indicateur de compromission connu |
| `CRP-C2-0002` | CRITICAL | Balise vers une adresse de commande et de contrôle |
| `CRP-C2-0003` | HIGH | Résolution d'un domaine malveillant connu |
| `CRP-DIS-0001` | MEDIUM | Balayage réseau depuis une adresse interne |
| `CRP-EXE-0001` | CRITICAL | Interpréteur lancé sur un actif critique |
| `CRP-EXF-0001` | HIGH | Transfert sortant de volume anormal |
| `CRP-EXF-0002` | CRITICAL | Transfert vers une destination au renseignement |
| `CRP-FRD-0001` | HIGH | Transaction à risque élevé |
| `CRP-GEO-0001` | CRITICAL | Accès depuis un pays sous sanctions |
| `CRP-IAM-0001` | HIGH | Bourrage d'identifiants depuis une même adresse |
| `CRP-IAM-0002` | HIGH | Attaque en force sur un compte unique |
| `CRP-IAM-0003` | CRITICAL | Session administrateur ouverte avec succès |
| `CRP-IAM-0004` | HIGH | Élévation de privilèges |
| `CRP-IAM-0005` | MEDIUM | Activité en dehors des heures ouvrées |
| `CRP-LAT-0001` | HIGH | Déplacement latéral par service distant |

**Dix-sept préréglages de politique**, répartis sur les quatre jugements que la
plateforme laisse au client : profil de risque, délais de remédiation, seuils
comportementaux, pondérations des chemins d'attaque. Chacun a un préréglage
« par défaut » qui **reproduit exactement** le comportement antérieur, pour
qu'une valeur devenue paramétrable ne déplace aucun chiffre le jour où elle est
livrée. Voir [16 — Paramétrage](16-parametrage.md).

---

## Ce que la plateforme ne fait pas

Dit ici une fois, pour ne pas avoir à le chercher :

- **Aucun connecteur vers un outil tiers réel** n'est livré. Les données entrent
  par syslog, par l'API, ou par le jeu de démonstration.
- **Aucune corrélation inter-domaines** : chaque domaine décide seul. Il n'y a
  pas de moteur qui lie une anomalie UEBA à un chemin d'attaque à un constat
  CSPM.
- **Le Copilot exige une clé API Anthropic.** Sans elle, le service ne démarre
  pas et son onglet est inopérant.
- **Neo4j est facultatif.** Sans lui, le graphe d'attaque et le graphe de
  connaissance sont lus depuis PostgreSQL, ce qui est le défaut.
- **La rétention n'est pas automatisée.** Les tables ClickHouse ont des TTL ;
  PostgreSQL n'a pas de purge planifiée.
