# Stack Technique — Cyber Radar Platform

---

## Décision d'architecture (verrouillée)

```
Pattern : Event-driven microservices + polyglot persistence
Principes : AI Native | API First | Event Driven | Zero Trust | Security by Design
            Explainable AI | Sovereign by Design | Vendor Agnostic | Modular | Banking Grade
```

---

## Moteurs de données

| Moteur | Technologie recommandée | Alternative | Usage |
|---|---|---|---|
| Event Store | **ClickHouse** | OpenSearch, Elasticsearch | SIEM, XDR, corrélation temps réel, logs |
| Graph DB | **Neo4j Community/Enterprise** | JanusGraph, Amazon Neptune | Attack Path, Identity Graph, Digital Twin |
| SQL DB | **PostgreSQL 16** | CockroachDB | RBAC, SOAR, config, incidents, tickets |
| Vector DB | **pgvector** (PostgreSQL) | Qdrant, Milvus | AI Copilot, RAG, hunting sémantique |
| Streaming | **Apache Kafka** | Redpanda | Pipeline events, 100K+ EPS |
| Cache | **Redis** | Valkey | IOC cache, session, enrichissement |
| Search | **OpenSearch** | Elasticsearch | Full-text search, threat hunting |

---

## Infrastructure & Orchestration

| Composant | Technologie | Usage |
|---|---|---|
| Conteneurisation | Docker | Packaging microservices |
| Orchestration | Kubernetes (K8s) | Déploiement, scaling, HA |
| Service Mesh | Istio | Zero Trust inter-services, mTLS |
| API Gateway | Kong / KrakenD | Rate limiting, JWT, routing |
| Ingress | NGINX / Traefik | Load balancing |
| Secrets | HashiCorp Vault | API keys, tokens, credentials, rotation |
| Config | etcd / ConfigMaps | Configuration centralisée |
| Registry | Harbor | Docker registry privé + scan |

---

## Identité & Sécurité

| Composant | Technologie | Usage |
|---|---|---|
| IAM / SSO | Keycloak | OIDC, SAML, OAuth2, MFA, SCIM |
| RBAC/ABAC | OPA (Open Policy Agent) | Politique d'accès déclarative |
| mTLS | Istio / cert-manager | Zero Trust inter-services |
| Encryption | AES-256 | Données au repos |
| TLS | TLS 1.3 | Transport |
| SBOM | Syft + Grype | Inventaire dépendances + CVE |

---

## Observabilité

| Composant | Technologie | Usage |
|---|---|---|
| Métriques | Prometheus + Grafana | Dashboards ops |
| Tracing | OpenTelemetry + Jaeger | Distributed tracing |
| Logging | Fluentd / Vector | Centralisation logs plateforme |
| Alerting | Alertmanager | Alertes ops |

---

## Backend (Microservices)

| Couche | Technologie recommandée | Justification |
|---|---|---|
| API Services | **Go (Golang)** | Performance, concurrence, idéal pour event-driven |
| ML / AI Services | **Python (FastAPI)** | Ecosystème ML/AI, scikit-learn, PyTorch |
| Graph Engine | **Neo4j + Java/Go driver** | Performance sur graph queries |
| Streaming Processors | **Go / Kafka Streams** | Faible latence |
| SOAR Engine | **Python** | Flexibilité playbooks |

---

## Frontend

| Composant | Technologie | Usage |
|---|---|---|
| Dashboard SOC/CISO | **React + TypeScript** | Interface principale |
| Graph Visualization | **D3.js / Sigma.js** | Graphe interactif |
| Design System | **Tailwind CSS + Shadcn** | UI composants |
| Real-time | **WebSocket / SSE** | Alertes temps réel |
| Charts | **Recharts / ECharts** | Métriques et dashboards |

---

## CI/CD & DevSecOps

| Composant | Technologie | Usage |
|---|---|---|
| CI/CD | GitHub Actions / GitLab CI | Pipelines automatisés |
| SAST | SonarQube | Analyse statique code |
| DAST | OWASP ZAP | Tests dynamiques APIs |
| Dependency Scan | Dependabot + Grype | CVE dépendances |
| Container Scan | Trivy | Images Docker |
| IaC | Terraform / Helm | Infrastructure as Code |
| Monitoring release | ArgoCD | GitOps déploiement |

---

## AI / Machine Learning

| Composant | Technologie | Usage |
|---|---|---|
| Baseline comportementale | scikit-learn, Isolation Forest | UEBA anomaly detection |
| Classification actifs | Random Forest / XGBoost | Asset classification |
| NLP / RAG | LangChain + Claude API / OpenAI | AI Copilot |
| Vector Embeddings | text-embedding-3 | Similarité sémantique |
| Clustering | DBSCAN / K-means | Clustering attaques |

---

## Connecteurs natifs MVP

```
Identity    : Active Directory, Entra ID, Keycloak, Wallix PAM, CyberArk
Network     : Cisco, Fortinet, Check Point, Palo Alto, F5
Endpoint    : CrowdStrike Falcon, Microsoft Defender, SentinelOne
Cloud       : AWS (CloudTrail, GuardDuty), Azure Sentinel, GCP Chronicle
SaaS        : Microsoft 365, Google Workspace
Banking     : CBS (via API/Syslog custom), SWIFT Alliance, Monétique
ThreatIntel : MISP, AlienVault OTX, STIX/TAXII feeds
```

---

## Déploiements supportés

| Mode | Description |
|---|---|
| SaaS Multi-tenant | Cloud hébergé, isolation par tenant |
| On-Premise | Déploiement K8s sur infrastructure cliente |
| Hybride | Data plane on-prem, control plane cloud |
| Air-Gapped | Déploiement totalement isolé (gouvernements, banques centrales) |
| Souverain | Données localisées, sans sortie vers l'extérieur |

---

## Exigences infrastructure MVP

```
Minimum recommandé (MVP) :
  Control Plane  : 3 nœuds K8s (HA)  — 8 vCPU / 32 GB RAM chacun
  Data Nodes     : 3 nœuds            — 16 vCPU / 64 GB RAM / 2 TB NVMe
  Kafka Cluster  : 3 brokers          — 8 vCPU / 16 GB RAM / 500 GB
  Neo4j          : 1 instance         — 8 vCPU / 32 GB RAM / 500 GB SSD
  PostgreSQL     : 1 primary + 1 replica
  Storage        : Object storage S3-compatible (Hot/Warm/Cold tiering)
```
