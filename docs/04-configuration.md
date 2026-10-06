# 04 — Configuration

Tout se configure par variables d'environnement. Aucun fichier de configuration
n'est lu au démarrage ; `backend/scripts/dev-local.sh` et
`backend/deployments/docker-compose.yml` sont les deux sources qui disent ce
que chaque service reçoit, et un test (`internal/pkg/deploycheck`) vérifie
qu'elles ne divergent pas sur la liste des services.

---

## Ce que reçoivent tous les services

| Variable | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `SERVICE_NAME` | — | nom du binaire | Apparaît dans les journaux et les traces |
| `SERVICE_PORT` | — | le port du service | Sur quoi il écoute |
| `DATABASE_URL` | **oui** | — | DSN PostgreSQL |
| `JWT_PUBLIC_KEY_PATH` | **oui** | — | Clé **publique** RS256. Aucun service hors `identity` n'a besoin de la privée |
| `KAFKA_BROKERS` | selon | `localhost:9092` | Les services qui produisent ou consomment |
| `CORS_ALLOWED_ORIGINS` | **oui** | — | Sans elle, le navigateur bloque tout et chaque panneau affiche « Failed to fetch » sans trace nulle part |
| `OIDC_ISSUER` | **oui** | — | `http://keycloak:8080/realms/cyberradar` |
| `OIDC_AUDIENCE` | **oui** | — | `cyberradar-frontend` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | non | — | Vide : aucune trace n'est exportée, le service démarre quand même |
| `LOG_LEVEL` | non | `info` | `debug`, `info`, `warn`, `error` |
| `CRP_TRUSTED_PROXY_CIDRS` | non | les plages privées et la boucle locale | Les plages des reverses proxies devant le service, séparées par des virgules. Voir ci-dessous |

### `CRP_TRUSTED_PROXY_CIDRS` — à qui appartient l'adresse du client

Un service lit l'adresse du client dans `X-Forwarded-For`, et cet en-tête est
écrit par qui veut. La question n'est donc pas « que dit l'en-tête » mais
« jusqu'où puis-je le croire » : la chaîne est parcourue de droite à gauche et
s'arrête à la première adresse qui n'est pas l'une des nôtres. Celle-là a été
ajoutée par notre propre proxy et personne en aval ne peut la forger ; tout ce
qui est à sa gauche est la déclaration du client.

Le défaut — `127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7`
— convient à un déploiement derrière son propre ingress dans un réseau privé.
Derrière un répartiteur de charge dont l'adresse est publique, il faut nommer
sa plage, sinon le parcours s'arrête sur le répartiteur et c'est **son** adresse
qui est journalisée : faux, mais faux du bon côté — la valeur ne peut pas être
choisie par l'appelant.

Une connexion qui n'arrive pas d'une de ces plages n'a pas de chaîne digne
d'être lue : son adresse de pair est alors la seule donnée disponible, et c'est
celle qui est retenue. Le journal de requêtes porte les deux champs,
`remote_addr` (le pair) et `client_ip` (le client), parce qu'ils ne disent pas
la même chose.

---

## Ce qui est propre à certains services

### `identity` — le seul à signer

| Variable | Rôle |
|---|---|
| `JWT_PRIVATE_KEY_PATH` | La clé privée RS256. **Un seul service la détient.** |
| `JWT_EXPIRY_MINUTES` | Durée de vie du jeton d'accès (60 en développement) |
| `JWT_REFRESH_EXPIRY_HOURS` | Durée de vie du jeton de rafraîchissement (24) |
| `MFA_ISSUER` | L'émetteur affiché dans l'application TOTP |
| `REDIS_URL` | Base 1 |

### Les consommateurs de ClickHouse

`audit`, `siem`, `ueba` : `CLICKHOUSE_DSN`.
`dashboard` : `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`.

> Le DSN prend la forme `clickhouse://default:@localhost:9000/crp_audit`. **Le
> deux-points n'est pas optionnel** : le pilote lit `user:pass` et refuse un
> DSN qui porte un utilisateur sans séparateur.

### Les compteurs partagés

| Service | Base Redis |
|---|---|
| `tenant` | 0 |
| `identity` | 1 |
| `ueba` | 8 |
| `siem` | 9 |

Les compteurs de seuil vivent là et non en mémoire : deux instances d'un même
service doivent compter ensemble, sinon un seuil de 5 se déclenche à 10.

### Les graphes

| Variable | Défaut | Rôle |
|---|---|---|
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` | absent | Sans elles, pas de miroir Neo4j |
| `ATTACKPATH_GRAPH_READS` | `postgres` | `neo4j` bascule les lectures |
| `KG_GRAPH_READS` | `postgres` | idem |

Les écritures vont dans les deux dès que Neo4j est configuré ; les lectures
restent sur PostgreSQL jusqu'à ce qu'une réconciliation rapporte l'égalité
(`make graph-reconcile`, `make kg-reconcile`).

### `soar` — appelle les autres

`IDENTITY_URL`, `SIEM_URL`, `TI_URL`, `VULN_URL`, `ASSET_URL`,
`ATTACKPATH_URL`, `NETSEC_URL`, `IR_URL`, `NOTIFICATION_URL`, `AUDIT_URL`, plus
`SOAR_CLIENT_ID` et `SOAR_CLIENT_SECRET` : **le compte de service du
playbook**. Un playbook agit sous sa propre identité, pas sous celle de
l'analyste — voir [05 — Sécurité](05-securite.md).

Le compte ne s'invente pas : il faut le créer, sinon chaque action répondant à
un autre service échoue en 401 et le SOAR ne peut rien faire. Voir
[14 — SOAR et réponse à incident](14-soar-ir.md#sous-quelle-identité).
`AUDIT_URL` est ce qui permet au playbook de consigner ce qu'il a fait ; sans
elle les actions s'exécutent et journalisent qu'elles n'ont pas été consignées.

### `copilot` — exige une clé

`ANTHROPIC_API_KEY` est obligatoire ; sans elle le service ne démarre pas et le
script d'installation le signale en le passant.

| Variable | Rôle |
|---|---|
| `ANTHROPIC_API_KEY` | **Obligatoire** |
| `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL` | Surcharges |
| `COPILOT_EFFORT`, `COPILOT_MAX_TOKENS` | Réglages de la boucle |
| `EMBEDDINGS_URL`, `EMBEDDINGS_API_KEY`, `EMBEDDINGS_MODEL` | Le RAG pgvector (`BAAI/bge-large-en-v1.5` par défaut) |
| `*_SERVICE_URL` (9) | Les services que ses outils appellent |

### `syslog`

| Variable | Rôle |
|---|---|
| `SYSLOG_UDP_ADDR`, `SYSLOG_TCP_ADDR`, `SYSLOG_TLS_ADDR` | Les écoutes |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | `make syslog-certs` en génère pour le développement |
| `KAFKA_TOPIC` | Où il publie |
| `HEALTH_PORT` | Il n'a pas d'API : la santé est sur son propre port |
| `DEFAULT_TENANT_ID` | À qui appartient un message qui ne le dit pas |

### Le contenu de détection

| Variable | Rôle |
|---|---|
| `CRP_CONTENT_CHANNEL` | Le canal publié à suivre (chemin ou base HTTPS) |
| `CRP_CONTENT_VERSION` | Une version précise ; vide = ce que le canal dit courant |
| `CRP_CONTENT_PACK` | Une livraison isolée, plutôt qu'un canal |
| `CRP_CONTENT_TRUST` | **Les clés que ce déploiement accepte.** Sans elle, le chargement est refusé |
| `CRP_CONTENT_DIR` | Un répertoire — mode auteur, jamais un déploiement |
| `CRP_CONTENT_SIGN_KEY` | La clé privée, côté publication seulement |

Détail complet : [`../plan/20-CONTENT-RELEASE.md`](../plan/20-CONTENT-RELEASE.md).

---

## Les ports

| Service | Port | | Service | Port |
|---|---|---|---|---|
| `tenant` | 8001 | | `compliance` | 8018 |
| `identity` | 8002 | | `easm` | 8019 |
| `audit` | 8003 | | `fraud` | 8020 |
| `notification` | 8004 | | `dlp` | 8021 |
| `collector` | 8005 | | `netsec` | 8022 |
| `asset` | 8006 | | `risk` | 8023 |
| `pam` | 8007 | | `iga` | 8024 |
| `siem` | 8008 | | `cspm` | 8025 |
| `ueba` | 8009 | | `ir` | 8026 |
| `ti` | 8010 | | `scs` | 8027 |
| `vuln` | 8011 | | `ot` | 8028 |
| `attackpath` | 8012 | | `mobile` | 8029 |
| `knowledgegraph` | 8013 | | `dspm` | 8030 |
| `soar` | 8014 | | | |
| `dashboard` | 8015 | | **Interface** | 3000 |
| `copilot` | 8016 | | **Keycloak** | 8080 |
| `apifw` | 8017 | | | |

Infrastructure : PostgreSQL 5432, Redis 6379, ClickHouse 9000, Kafka 9092,
Neo4j 7687, Vault 8200, Jaeger 16686, Prometheus 9090, Grafana 3001.

---

## Les secrets

### Vault

`internal/pkg/vault` lit les secrets d'un Vault. `VAULT_ADDR`, `VAULT_TOKEN`,
`VAULT_KV_MOUNT`, `VAULT_SECRET_PREFIX`. `make vault-seed` charge des secrets
de développement.

### Les clés

| Clé | Générée par | Qui la détient |
|---|---|---|
| Paire RSA des jetons | `make jwt-keys` → `backend/deployments/jwt/` | La privée : `identity` seul. La publique : tous les autres |
| Certificats syslog | `make syslog-certs` | Le connecteur. Auto-signés, développement uniquement |
| Clé de signature du contenu | `contentctl -keygen` | La machine de publication. **Distincte de la clé des jetons** |

**La clé de contenu n'est pas la clé des jetons.** Les réunir ferait d'une
compromission de clé de contenu une forgerie de jetons : le rayon d'action du
portable d'un auteur de détections deviendrait toutes les sessions de la
plateforme.

> Les clés livrées dans le dépôt sont **de développement**. Un déploiement
> réel génère les siennes et ne les met pas dans un dépôt. `*.key` et `*.pem`
> sont ignorés par git, mais la paire de développement y est délibérément pour
> que `make dev` marche du premier coup.

---

## Les valeurs par défaut de développement

Elles sont dans le script, et elles sont surchargeables :

| Variable | Défaut |
|---|---|
| `CRP_PG_USER` / `CRP_PG_PASSWORD` / `CRP_PG_DB` | `crp_user` / `crp_password_dev` / `crp_foundation` |
| `CRP_REDIS_PASSWORD` | `crp_redis_dev` |
| `CRP_NEO4J_PASSWORD` | `crp_password_dev` |
| `CRP_CORS_ORIGINS` | `http://localhost:3000` |
| `CRP_STATE_DIR` | `backend/.dev-local` |
| `CRP_KAFKA_HOME`, `CRP_KEYCLOAK_HOME`, `CRP_NEO4J_HOME`, `CRP_CLICKHOUSE_BIN` | Où trouver les serveurs tiers |

**Aucune ne convient à la production.** Ce sont des valeurs choisies pour
qu'une première installation fonctionne sans décision à prendre.
