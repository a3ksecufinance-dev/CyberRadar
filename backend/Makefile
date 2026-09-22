# ============================================================
# Cyber Radar Platform — Makefile
# ============================================================
.PHONY: help dev down build test lint migrate fmt tidy

DOCKER_COMPOSE = docker compose -f deployments/docker-compose.yml

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Infrastructure ───────────────────────────────────────────────────────────

infra-up: ## Start all infrastructure containers
	$(DOCKER_COMPOSE) up -d postgres clickhouse redis kafka vault jaeger prometheus grafana
	@echo "⏳ Waiting for services to be healthy..."
	@sleep 5

infra-down: ## Stop infrastructure containers
	$(DOCKER_COMPOSE) down

dev: jwt-keys infra-up migrate ## Start infra + run migrations + start all services
	$(DOCKER_COMPOSE) up -d tenant-service identity-service audit-service notification-service collector-service pipeline-worker asset-service pam-service siem-service ueba-service ti-service vuln-service attackpath-service knowledgegraph-service soar-service dashboard-service copilot-service apifw-service compliance-service easm-service fraud-service dlp-service netsec-service risk-service iga-service cspm-service ir-service scs-service ot-service mobile-service dspm-service syslog-connector

down: ## Stop all containers
	$(DOCKER_COMPOSE) down

logs: ## Tail logs from all services
	$(DOCKER_COMPOSE) logs -f tenant-service identity-service audit-service notification-service collector-service pipeline-worker asset-service pam-service siem-service ueba-service ti-service vuln-service attackpath-service knowledgegraph-service soar-service dashboard-service copilot-service apifw-service compliance-service easm-service fraud-service dlp-service netsec-service risk-service iga-service cspm-service ir-service scs-service ot-service mobile-service dspm-service syslog-connector

# ─── Database migrations ──────────────────────────────────────────────────────

migrate: ## Run all PostgreSQL migrations
	@echo "Running PostgreSQL migrations..."
	@for f in migrations/postgres/*.sql; do \
		echo "  → $$f"; \
		PGPASSWORD=crp_password_dev psql -h localhost -U crp_user -d crp_foundation -f $$f; \
	done
	@echo "Running ClickHouse migrations..."
	@for f in migrations/clickhouse/*.sql; do \
		echo "  → $$f"; \
		curl -s -u crp_user:crp_password_dev "http://localhost:8123/?database=default" --data-binary @$$f; \
	done
	@echo "Migrations complete."

migrate-status: ## Show migration status
	PGPASSWORD=crp_password_dev psql -h localhost -U crp_user -d crp_foundation \
		-c "SELECT schemaname, tablename, tableowner FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"

# ─── Build ────────────────────────────────────────────────────────────────────

build: ## Build all service binaries
	@mkdir -p bin
	go build -o bin/tenant-service ./services/tenant/cmd/server/
	go build -o bin/identity-service ./services/identity/cmd/server/
	go build -o bin/audit-service ./services/audit/cmd/server/
	go build -o bin/notification-service ./services/notification/cmd/server/
	go build -o bin/collector-service ./services/collector/cmd/server/
	go build -o bin/pipeline-worker ./services/pipeline/cmd/worker/
	go build -o bin/asset-service ./services/asset/cmd/server/
	go build -o bin/pam-service ./services/pam/cmd/server/
	go build -o bin/siem-service ./services/siem/cmd/server/
	go build -o bin/ueba-service ./services/ueba/cmd/server/
	go build -o bin/ti-service ./services/ti/cmd/server/
	go build -o bin/vuln-service ./services/vuln/cmd/server/
	go build -o bin/attackpath-service ./services/attackpath/cmd/server/
	go build -o bin/knowledgegraph-service ./services/knowledgegraph/cmd/server/
	go build -o bin/soar-service ./services/soar/cmd/server/
	go build -o bin/dashboard-service ./services/dashboard/cmd/server/
	go build -o bin/copilot-service ./services/copilot/cmd/server/
	go build -o bin/apifw-service ./services/apifw/cmd/server/
	go build -o bin/compliance-service ./services/compliance/cmd/server/
	go build -o bin/easm-service ./services/easm/cmd/server/
	go build -o bin/fraud-service ./services/fraud/cmd/server/
	go build -o bin/dlp-service ./services/dlp/cmd/server/
	go build -o bin/netsec-service ./services/netsec/cmd/server/
	go build -o bin/risk-service ./services/risk/cmd/server/
	go build -o bin/iga-service ./services/iga/cmd/server/
	go build -o bin/cspm-service ./services/cspm/cmd/server/
	go build -o bin/ir-service ./services/ir/cmd/server/
	go build -o bin/scs-service ./services/scs/cmd/server/
	go build -o bin/ot-service ./services/ot/cmd/server/
	go build -o bin/mobile-service ./services/mobile/cmd/server/
	go build -o bin/dspm-service ./services/dspm/cmd/server/
	go build -o bin/syslog-connector ./services/syslog/cmd/server/
	@echo "Build complete → bin/"

build-tenant: ## Build tenant service only
	go build -o bin/tenant-service ./services/tenant/cmd/server/

build-identity: ## Build identity service only
	go build -o bin/identity-service ./services/identity/cmd/server/

build-audit: ## Build audit service only
	go build -o bin/audit-service ./services/audit/cmd/server/

docker-build: ## Build Docker images for all services
	docker build -f services/tenant/Dockerfile -t crp/tenant-service:dev .
	docker build -f services/identity/Dockerfile -t crp/identity-service:dev .
	docker build -f services/audit/Dockerfile -t crp/audit-service:dev .
	docker build -f services/notification/Dockerfile -t crp/notification-service:dev .
	docker build -f services/collector/Dockerfile -t crp/collector-service:dev .
	docker build -f services/pipeline/Dockerfile -t crp/pipeline-worker:dev .
	docker build -f services/asset/Dockerfile -t crp/asset-service:dev .
	docker build -f services/pam/Dockerfile -t crp/pam-service:dev .
	docker build -f services/siem/Dockerfile -t crp/siem-service:dev .
	docker build -f services/ueba/Dockerfile -t crp/ueba-service:dev .
	docker build -f services/ti/Dockerfile -t crp/ti-service:dev .
	docker build -f services/vuln/Dockerfile -t crp/vuln-service:dev .
	docker build -f services/attackpath/Dockerfile -t crp/attackpath-service:dev .
	docker build -f services/knowledgegraph/Dockerfile -t crp/knowledgegraph-service:dev .
	docker build -f services/soar/Dockerfile -t crp/soar-service:dev .
	docker build -f services/dashboard/Dockerfile -t crp/dashboard-service:dev .
	docker build -f services/copilot/Dockerfile -t crp/copilot-service:dev .
	docker build -f services/apifw/Dockerfile -t crp/apifw-service:dev .
	docker build -f services/compliance/Dockerfile -t crp/compliance-service:dev .
	docker build -f services/easm/Dockerfile -t crp/easm-service:dev .
	docker build -f services/fraud/Dockerfile -t crp/fraud-service:dev .
	docker build -f services/dlp/Dockerfile -t crp/dlp-service:dev .
	docker build -f services/netsec/Dockerfile -t crp/netsec-service:dev .
	docker build -f services/risk/Dockerfile -t crp/risk-service:dev .
	docker build -f services/iga/Dockerfile -t crp/iga-service:dev .
	docker build -f services/cspm/Dockerfile -t crp/cspm-service:dev .
	docker build -f services/ir/Dockerfile -t crp/ir-service:dev .
	docker build -f services/scs/Dockerfile -t crp/scs-service:dev .
	docker build -f services/ot/Dockerfile -t crp/ot-service:dev .
	docker build -f services/mobile/Dockerfile -t crp/mobile-service:dev .
	docker build -f services/dspm/Dockerfile -t crp/dspm-service:dev .
	docker build -f services/syslog/Dockerfile -t crp/syslog-connector:dev .

syslog-certs: ## Generate self-signed TLS certs for syslog connector (dev only)
	./scripts/gen-syslog-certs.sh

jwt-keys: ## Generate the RSA key pair used to sign JWTs (dev only)
	./scripts/gen-jwt-keys.sh

# ─── Tests ────────────────────────────────────────────────────────────────────

# Each service is its own module, so ./... from the root matches nothing —
# every target below iterates over the modules listed in go.work.
MODULES := internal $(patsubst %/,%,$(wildcard services/*/))

test: ## Run all tests
	@fail=0; for m in $(MODULES); do \
		(cd $$m && go test ./... -timeout 120s) || fail=1; \
	done; exit $$fail

test-tenant: ## Run tenant service tests
	cd services/tenant && go test ./... -v

test-identity: ## Run identity service tests
	cd services/identity && go test ./... -v

test-audit: ## Run audit service tests
	cd services/audit && go test ./... -v

test-cover: ## Run tests with coverage
	@echo "mode: set" > $(CURDIR)/coverage.out
	@for m in $(MODULES); do \
		(cd $$m && go test ./... -coverprofile=cover.tmp -covermode=set >/dev/null 2>&1; \
		 [ -f cover.tmp ] && tail -n +2 cover.tmp >> $(CURDIR)/coverage.out; rm -f cover.tmp) || true; \
	done
	go tool cover -html=$(CURDIR)/coverage.out -o coverage.html
	@echo "Coverage report → coverage.html"

# ─── Code quality ─────────────────────────────────────────────────────────────

lint: ## Run golangci-lint
	@fail=0; for m in $(MODULES); do \
		(cd $$m && golangci-lint run ./...) || fail=1; \
	done; exit $$fail

fmt: ## Format all Go code
	gofmt -w -s .

fmt-check: ## Fail if any Go file is not gofmt-formatted
	@out=$$(gofmt -l -s .); \
	if [ -n "$$out" ]; then echo "not gofmt'd:"; echo "$$out"; exit 1; fi

tidy: ## Tidy all go.mod files
	go work sync
	@for m in $(MODULES); do \
		echo "  → $$m"; \
		(cd $$m && go mod tidy); \
	done

vet: ## Run go vet
	@fail=0; for m in $(MODULES); do \
		(cd $$m && go vet ./...) || fail=1; \
	done; exit $$fail

# ─── Utilities ────────────────────────────────────────────────────────────────

psql: ## Open a psql shell
	PGPASSWORD=crp_password_dev psql -h localhost -U crp_user -d crp_foundation

clickhouse-cli: ## Open a clickhouse-client shell
	docker exec -it crp-clickhouse clickhouse-client -u crp_user --password crp_password_dev -d crp_audit

redis-cli: ## Open a redis-cli shell
	docker exec -it crp-redis redis-cli -a crp_redis_dev

vault-token: ## Print vault dev token
	@echo "VAULT_TOKEN=crp-vault-dev-token"
	@echo "VAULT_ADDR=http://localhost:8200"

# ─── API quick tests (requires services running) ─────────────────────────────

api-health: ## Check all service health endpoints
	@echo "Tenant service:"
	@curl -s http://localhost:8001/health | python3 -m json.tool
	@echo "Identity service:"
	@curl -s http://localhost:8002/health | python3 -m json.tool
	@echo "Audit service:"
	@curl -s http://localhost:8003/health | python3 -m json.tool
	@echo "Notification service:"
	@curl -s http://localhost:8004/health | python3 -m json.tool
	@echo "Collector service:"
	@curl -s http://localhost:8005/health | python3 -m json.tool
	@echo "Asset service:"
	@curl -s http://localhost:8006/health | python3 -m json.tool
	@echo "PAM service:"
	@curl -s http://localhost:8007/health | python3 -m json.tool
	@echo "SIEM service:"
	@curl -s http://localhost:8008/health | python3 -m json.tool
	@echo "UEBA service:"
	@curl -s http://localhost:8009/health | python3 -m json.tool
	@echo "TI service:"
	@curl -s http://localhost:8010/health | python3 -m json.tool
	@echo "Vuln service:"
	@curl -s http://localhost:8011/health | python3 -m json.tool
	@echo "Attack Path service:"
	@curl -s http://localhost:8012/health | python3 -m json.tool
	@echo "Knowledge Graph service:"
	@curl -s http://localhost:8013/health | python3 -m json.tool
	@echo "SOAR service:"
	@curl -s http://localhost:8014/health | python3 -m json.tool
	@echo "Dashboard service:"
	@curl -s http://localhost:8015/health | python3 -m json.tool
	@echo "Copilot service:"
	@curl -s http://localhost:8016/health | python3 -m json.tool
	@echo "API Framework service:"
	@curl -s http://localhost:8017/health | python3 -m json.tool
	@echo "Compliance service:"
	@curl -s http://localhost:8018/health | python3 -m json.tool
	@echo "EASM service:"
	@curl -s http://localhost:8019/health | python3 -m json.tool
	@echo "Fraud service:"
	@curl -s http://localhost:8020/health | python3 -m json.tool
	@echo "DLP service:"
	@curl -s http://localhost:8021/health | python3 -m json.tool
	@echo "NetSec service:"
	@curl -s http://localhost:8022/health | python3 -m json.tool
	@echo "Risk service:"
	@curl -s http://localhost:8023/health | python3 -m json.tool
	@echo "IGA service:"
	@curl -s http://localhost:8024/health | python3 -m json.tool
	@echo "CSPM service:"
	@curl -s http://localhost:8025/health | python3 -m json.tool
	@echo "IR service:"
	@curl -s http://localhost:8026/health | python3 -m json.tool
	@echo "SCS service:"
	@curl -s http://localhost:8027/health | python3 -m json.tool
	@echo "OT/ICS service:"
	@curl -s http://localhost:8028/health | python3 -m json.tool
	@echo "Mobile Security service:"
	@curl -s http://localhost:8029/health | python3 -m json.tool
	@echo "DSPM service:"
	@curl -s http://localhost:8030/health | python3 -m json.tool

api-ingest: ## Test event ingestion (requires collector service + valid TOKEN)
	@echo "Ingesting test JSON event..."
	@curl -s -X POST http://localhost:8005/api/v1/events/ingest \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $${TOKEN}" \
		-d '{"connector_id":"00000000-0000-0000-0000-000000000001","source":"test-host","source_type":"firewall","format":"json","events":["{\"timestamp\":\"2026-05-24T10:00:00Z\",\"action\":\"LOGIN_FAILED\",\"category\":\"IAM\",\"severity\":\"HIGH\",\"outcome\":\"failure\",\"src_ip\":\"192.168.1.100\",\"user_name\":\"jdoe\"}"]}' \
		| python3 -m json.tool

api-login: ## Test login (requires identity service running)
	@curl -s -X POST http://localhost:8002/api/v1/auth/login \
		-H "Content-Type: application/json" \
		-H "X-Tenant-ID: 00000000-0000-0000-0000-000000000001" \
		-d '{"email":"admin@cyberradar.io","password":"changeme123!"}' \
		| python3 -m json.tool
