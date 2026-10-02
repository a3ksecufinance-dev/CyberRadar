# 09 — Ingestion

## Les quatre états d'un événement

```
   source               crp.events.raw        crp.events.normalized
      │                        │                       │
      ▼                        ▼                       ▼
┌───────────┐           ┌─────────────┐         ┌─────────────┐
│  syslog   │──────────▶│             │         │   siem      │
│ connector │ normalisé │  pipeline   │────────▶│   ueba      │
├───────────┤  direct   │   worker    │         └─────────────┘
│ collector │──────────▶│             │
└───────────┘           └──────┬──────┘
                               │ enrichi : IOC, actif, géo, risque
                               ▼
                      crp.events.enriched ──▶ les domaines
                               │
                               ▼  ce qui échoue, après reprises
                        crp.events.dlq
```

---

## Les points d'entrée

### Le connecteur syslog

Pas d'API HTTP : il écoute, il parse, il publie. Sa santé est sur un port à
part (`HEALTH_PORT`, 8031 par défaut).

| Écoute | Port | Norme |
|---|---|---|
| UDP | 5140 | RFC 5426 |
| TCP | 5141 | RFC 6587 — **comptage d'octets** *et* délimitation par retour ligne |
| TLS | 6514 | RFC 5425 |

Trois formats détectés automatiquement :

| Format | Norme |
|---|---|
| BSD | RFC 3164 |
| Structuré | RFC 5424 |
| CEF sur syslog | ArcSight CEF |

> Le comptage d'octets (RFC 6587) n'est pas une option : sans lui, un message
> contenant un retour à la ligne est coupé en deux, et les deux moitiés sont
> analysées comme deux messages invalides. C'est le mode qu'utilisent les
> équipements qui émettent du multi-ligne.

Ces parsers sont la partie de la plateforme la plus couverte par des tests
unitaires, avec le moteur SIEM.

```bash
make syslog-certs   # certificats auto-signés pour le développement
```

`DEFAULT_TENANT_ID` dit à qui appartient un message qui ne le dit pas lui-même.

### Le collecteur HTTP

```
POST /api/v1/events/ingest      permission events:ingest
POST /api/v1/events/heartbeat   permission events:ingest
```

Deux routes, destinées au trafic de service à service. Le collecteur **ne
détient aucune connexion PostgreSQL**, donc il ne peut pas résoudre ce qu'une
personne authentifiée ailleurs a le droit de faire : il n'exige qu'un jeton
valide. L'interface ne l'appelle jamais.

---

## Le contrat : `NormalizedEvent`

C'est ce qui circule entre les étages. Le type est dans
`internal/pkg/event/schema.go` et il est aligné sur ECS.

```go
type NormalizedEvent struct {
    // Identité
    EventID, TenantID, Timestamp, IngestedAt, SchemaVersion

    // Provenance
    ConnectorID, Source, SourceType, RawEventID

    // Contexte identité
    UserID, UserName, UserEmail, UserDepartment, UserRiskScore

    // Contexte actif
    AssetID, AssetHostname, AssetType, AssetCriticality

    // Contexte réseau
    IPSource, IPDestination, PortSource, PortDest

    // Classification
    Action, Category, Severity, Outcome

    // Enrichissement (posé par le pipeline)
    ThreatScore, MitreTactic, MitreTechnique, IOCMatched, GeoCountry, GeoASN

    // Risque et métier
    RiskScore, BusinessService, CBSImpact, SWIFTImpact

    RawEvent string   // la charge d'origine, conservée
}
```

**Les champs de contexte sont des pointeurs.** Un `*string` nul dit « cette
source ne porte pas cette information » ; une chaîne vide dirait « elle la
porte et elle est vide ». Une règle de détection peut s'appuyer sur la
différence.

### Les énumérations

| | Valeurs |
|---|---|
| `Category` | `Security`, `Fraud`, `Network`, `IAM`, `Compliance`, `Transaction`, `Other` |
| `Severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `Outcome` | `success`, `failure`, `unknown` |

Un événement est « à risque immédiat » si sa sévérité est `HIGH` ou `CRITICAL`,
ou si son score de risque atteint 7,0.

---

## L'enrichissement

Le travailleur de pipeline (`services/pipeline`) consomme, enrichit, republie.

### Correspondance d'indicateurs

`internal/pkg/iocindex` répond « cette valeur est-elle un indicateur connu ? »
assez vite pour être interrogé sur **chaque** événement et **chaque** champ.

C'était le défaut le plus coûteux de la chaîne : l'enrichisseur renvoyait une
liste d'IOC vide, avec un commentaire le disant. Le seul composant qui
appariait des indicateurs était un second consommateur du **même sujet** que le
moteur de règles — à côté de lui, pas avant. Aucune règle ne pouvait donc
porter sur une correspondance : onze indicateurs chargés, zéro détection
possible.

> **Un index absent est une réponse légitime.** Un pipeline peut tourner pour
> un test de débit ou dans un laboratoire sans renseignement. Ce qui ne doit
> pas arriver, c'est d'en faire tourner un ainsi en production sans s'en
> apercevoir — d'où un avertissement qui nomme exactement ce qui est éteint.

### Les autres enrichissements

| | Source |
|---|---|
| Contexte d'actif | L'inventaire : criticité, type, service métier |
| Géolocalisation | `GeoCountry`, `GeoASN` |
| Score de menace | Calculé à partir de la sévérité, des correspondances et du contexte |

---

## Les sujets Kafka

| Sujet | Produit par | Consommé par |
|---|---|---|
| `crp.events.raw` | `syslog`, `collector` | `pipeline` |
| `crp.events.normalized` | `pipeline`, `syslog` | `siem`, `ueba` |
| `crp.events.enriched` | `pipeline` | les domaines |
| `crp.events.alerts` | `siem` | `soar`, `dashboard` |
| `crp.events.dlq` | tous | inspection |
| `crp.events.kpi` | les domaines | `dashboard` |
| `crp.notification` | les domaines | `notification` |
| `crp.events.{apifw,attackpath,compliance,cspm,dlp,dspm,easm,fraud,iga,ir,kg,mobile,netsec,ot,risk,scs,soar,ti,ueba,vuln}` | chacun le sien | — |

---

## La reprise et la file d'échec

Un gestionnaire qui renvoie une erreur provoque une reprise, à intervalle
exponentiel, puis un rangement dans la file d'échec.

**Le sujet de la file d'échec est obligatoire à la construction du
consommateur.** Sans lui, une erreur de gestionnaire soit reprenait
indéfiniment, soit abandonnait le message — les deux en silence — et le
décalage d'un message ultérieur se validait au-delà de l'échec : l'événement
était perdu sans trace. L'exiger d'emblée rend ce cas irreprésentable.

L'enveloppe de la file d'échec porte de quoi tracer :

```go
type DLQMessage struct {
    OriginalTopic string
    Offset        int64
    …le tenant, extrait au mieux de la charge…
}
```

Le tenant est extrait de la charge pour qu'une lettre morte remonte à son
client. Au mieux : une charge qui ne s'analyse pas est exactement celle qui
atterrit là.

> **Rien ne consomme `crp.events.dlq`.** Il n'y a ni alerte sur sa profondeur,
> ni outil de rejeu. C'est une inspection manuelle.

---

## Vérifier l'ingestion

```bash
# Un message syslog
logger -n localhost -P 5140 -d "test depuis la documentation"

# Via l'API
make api-ingest TOKEN=<jeton>

# La profondeur de la file d'échec
make redis-cli            # compteurs
make clickhouse-cli       # SELECT count() FROM crp_fabric.raw_events
```

---

## Ce qui n'est pas fait

- **Aucun connecteur vers un outil tiers.** Ni EDR, ni cloud, ni annuaire. Les
  données entrent par syslog, par l'API, ou par le jeu de démonstration.
- **Pas de rejeu depuis la file d'échec.**
- **Pas de surveillance du retard de consommation.** `Stats()` existe sur le
  consommateur ; rien ne l'expose en métrique.
- **Pas de limitation par tenant à l'entrée.** Un tenant bavard peut saturer
  le pipeline des autres.
