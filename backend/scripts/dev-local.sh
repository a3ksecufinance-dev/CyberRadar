#!/usr/bin/env bash
#
# Run the whole platform on one machine, without Docker.
#
# deployments/docker-compose.yml stays the reference for how the platform is
# deployed. This is for the case where Docker is not available or images cannot
# be pulled — a locked-down network, an air-gapped laptop, a CI runner without
# a daemon. It runs the same binaries against the same schemas on the same
# ports, so an address that works here works there.
#
#   ./scripts/dev-local.sh up         everything, in order
#   ./scripts/dev-local.sh demo       fill the tenant with a demonstration estate
#   ./scripts/dev-local.sh accounts   create the service accounts services need
#   ./scripts/dev-local.sh smoke      read every service's lists, fail on any 5xx
#   ./scripts/dev-local.sh e2e        drive the interface in a browser
#   ./scripts/dev-local.sh status     what is listening and what is healthy
#   ./scripts/dev-local.sh logs siem-service
#   ./scripts/dev-local.sh down       stop everything this script started
#
# Steps can be run on their own: infra, migrate, services, frontend.
#
# It only ever stops what it started, by the process identifiers it wrote:
# killing by name would take a developer's own PostgreSQL with it.
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$BACKEND_DIR/.." && pwd)"
STATE_DIR="${CRP_STATE_DIR:-$BACKEND_DIR/.dev-local}"
LOG_DIR="$STATE_DIR/logs"
PID_DIR="$STATE_DIR/pids"

PGUSER_NAME="${CRP_PG_USER:-crp_user}"
PGPASS="${CRP_PG_PASSWORD:-crp_password_dev}"
PGDB="${CRP_PG_DB:-crp_foundation}"
REDIS_PASS="${CRP_REDIS_PASSWORD:-crp_redis_dev}"
NEO4J_PASS="${CRP_NEO4J_PASSWORD:-crp_password_dev}"

DATABASE_URL="postgres://$PGUSER_NAME:$PGPASS@localhost:5432/$PGDB?sslmode=disable"
# The colon is not optional: the driver reads user:pass and rejects a DSN
# that carries a user with no separator ("invalid user:pass in DSN").
CLICKHOUSE_DSN="clickhouse://default:@localhost:9000/crp_audit"

# Where the third-party servers live. Override to point at your own.
KAFKA_HOME="${CRP_KAFKA_HOME:-/opt/kafka_2.13-3.7.1}"
KEYCLOAK_HOME="${CRP_KEYCLOAK_HOME:-/opt/keycloak-24.0.4}"
# The single-binary release is called "clickhouse", but a machine that carries
# more than one major version names them apart. Take the override if there is
# one, otherwise the first name that exists on PATH — a install that works once
# should not need the variable set again on the next session.
CLICKHOUSE_BIN="${CRP_CLICKHOUSE_BIN:-}"
if [[ -z "$CLICKHOUSE_BIN" ]]; then
	for candidate in clickhouse clickhouse24 clickhouse-server; do
		if command -v "$candidate" >/dev/null 2>&1; then CLICKHOUSE_BIN="$candidate"; break; fi
	done
	CLICKHOUSE_BIN="${CLICKHOUSE_BIN:-clickhouse}"
fi
NEO4J_HOME="${CRP_NEO4J_HOME:-}"   # empty: Neo4j is skipped, graphs stay in PostgreSQL

mkdir -p "$LOG_DIR" "$PID_DIR"

# ─── Output ───────────────────────────────────────────────────────────────────

step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
fail() { printf '   \033[31m✗\033[0m %s\n' "$*" >&2; }

# ─── Process bookkeeping ──────────────────────────────────────────────────────

# A pid on its own is not an identity.
#
# The pid file holds two lines: the pid, and the process start time the kernel
# records for it. A pid is reused; a pid together with its start time is not.
# After a reboot this script read a pid file holding 482, found that 482 existed
# — it was a kernel worker by then — and reported Redis as already running while
# nothing listened on its port. The same mistake in the other direction is
# worse: stop would have killed that kernel worker.
#
# The start time survives exec, which matters: `npm run start` becomes a node
# process, and a marker taken from the command line would stop matching.

# proc_started PID prints the start time the kernel recorded for PID.
#
# Field 22 of /proc/<pid>/stat, counted after the executable name — which is
# parenthesised and may itself contain spaces, so the fields before it cannot
# simply be split on whitespace.
proc_started() {
	local stat="/proc/$1/stat"
	[[ -r "$stat" ]] || return 1
	local raw; raw="$(cat "$stat" 2>/dev/null)" || return 1
	local after=")${raw#*)}"          # from the closing parenthesis onwards
	# shellcheck disable=SC2086 # deliberate word splitting into positional args
	set -- $after                     # $1 is ")", $2 is state, so field 22 is $21
	printf '%s\n' "${21:-}"
}

# start NAME COMMAND... — run in the background in its own process group,
# record the pid and its start time, log to a file.
start() {
	local name="$1"; shift
	if running "$name"; then ok "$name already running"; return 0; fi
	# Its own session, so stop can signal the whole group. `npm run start`
	# spawns the real server as a child; killing only the recorded pid left it
	# holding the port, and the next start failed with EADDRINUSE.
	setsid "$@" > "$LOG_DIR/$name.log" 2>&1 &
	local pid=$!
	printf '%s\n%s\n' "$pid" "$(proc_started "$pid")" > "$PID_DIR/$name.pid"
}

# pid_of NAME prints the pid only when the process is still the one recorded.
pid_of() {
	local pidfile="$PID_DIR/$1.pid"
	[[ -f "$pidfile" ]] || return 1

	local pid started
	{ read -r pid; read -r started; } < "$pidfile"
	[[ -n "$pid" ]] || return 1
	kill -0 "$pid" 2>/dev/null || return 1

	# An older pid file has no start time. Trusting it is what this exists to
	# stop, so treat it as not ours and let the caller start afresh.
	[[ -n "$started" ]] || return 1
	[[ "$(proc_started "$pid")" == "$started" ]] || return 1

	printf '%s\n' "$pid"
}

running() {
	pid_of "$1" >/dev/null 2>&1
}

stop() {
	local name="$1" pidfile="$PID_DIR/$1.pid"
	[[ -f "$pidfile" ]] || return 0

	local pid
	if ! pid="$(pid_of "$name")"; then
		# Either gone, or a pid that now belongs to something else. Removing
		# the file is right; sending a signal would not be.
		rm -f "$pidfile"
		return 0
	fi

	# The negative pid is the process group, which start put this process at
	# the head of. A wrapper that forwards no signal to its child would
	# otherwise leave the child holding the port.
	kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
	for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
	kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
	rm -f "$pidfile"
}

# wait_port PORT SECONDS NAME — a port that never opens is a failure to report,
# not a service to carry on without.
wait_port() {
	local port="$1" timeout="$2" name="$3"
	for _ in $(seq 1 "$((timeout * 2))"); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- ; ok "$name on :$port"; return 0; fi
		sleep 0.5
	done
	fail "$name did not open :$port within ${timeout}s — see $LOG_DIR/$name.log"
	return 1
}

# ─── The services ─────────────────────────────────────────────────────────────
#
# name:port:path-under-services. Kept in the order the platform's own
# documentation uses. A test asserts this list matches docker-compose.yml, so
# the two cannot drift apart.
SERVICES=(
	"tenant-service:8001:tenant"
	"identity-service:8002:identity"
	"audit-service:8003:audit"
	"notification-service:8004:notification"
	"collector-service:8005:collector"
	"asset-service:8006:asset"
	"pam-service:8007:pam"
	"siem-service:8008:siem"
	"ueba-service:8009:ueba"
	"ti-service:8010:ti"
	"vuln-service:8011:vuln"
	"attackpath-service:8012:attackpath"
	"knowledgegraph-service:8013:knowledgegraph"
	"soar-service:8014:soar"
	"dashboard-service:8015:dashboard"
	"copilot-service:8016:copilot"
	"apifw-service:8017:apifw"
	"compliance-service:8018:compliance"
	"easm-service:8019:easm"
	"fraud-service:8020:fraud"
	"dlp-service:8021:dlp"
	"netsec-service:8022:netsec"
	"risk-service:8023:risk"
	"iga-service:8024:iga"
	"cspm-service:8025:cspm"
	"ir-service:8026:ir"
	"scs-service:8027:scs"
	"ot-service:8028:ot"
	"mobile-service:8029:mobile"
	"dspm-service:8030:dspm"
)

# service_env NAME PORT — the environment one service needs, with the container
# hostnames of docker-compose rewritten to localhost. Everything shared is set
# here; the per-service block below adds only what is specific to it.
service_env() {
	local name="$1" port="$2"
	SVC_ENV=(
		"SERVICE_NAME=$name"
		"SERVICE_PORT=$port"
		"DATABASE_URL=$DATABASE_URL"
		"KAFKA_BROKERS=localhost:9092"
		"KAFKA_BROKER=localhost:9092"
		"JWT_PUBLIC_KEY_PATH=$BACKEND_DIR/deployments/jwt/public.pem"
		"LOG_LEVEL=${CRP_LOG_LEVEL:-info}"
		# The interface is on :3000 and every service on its own port, so every
		# call it makes is cross-origin. Without this the browser blocks them
		# all and each panel reports "Failed to fetch" with nothing in any log.
		"CORS_ALLOWED_ORIGINS=${CRP_CORS_ORIGINS:-http://localhost:3000}"
		# The interface signs users in against Keycloak and sends Keycloak's
		# token. Services verify it against the realm's published keys and then
		# resolve what the person may do from this platform's own tables.
		# ${VAR-default}, not ${VAR:-default}: an explicitly empty
		# CRP_OIDC_ISSUER has to mean "no identity provider", which is how the
		# end-to-end chain runs in CI — it authenticates with the platform's
		# own signed tokens and has no Keycloak to talk to. With the colon an
		# empty value would silently take the default and every service would
		# fail at start-up probing an issuer that is not there.
		"OIDC_ISSUER=${CRP_OIDC_ISSUER-http://localhost:8080/realms/cyberradar}"
		"OIDC_AUDIENCE=${CRP_OIDC_AUDIENCE:-cyberradar-frontend}"
	)
	case "$name" in
		tenant-service)
			SVC_ENV+=("REDIS_URL=redis://:$REDIS_PASS@localhost:6379/0") ;;
		identity-service)
			SVC_ENV+=(
				"REDIS_URL=redis://:$REDIS_PASS@localhost:6379/1"
				"JWT_PRIVATE_KEY_PATH=$BACKEND_DIR/deployments/jwt/private.pem"
				"JWT_EXPIRY_MINUTES=60" "JWT_REFRESH_EXPIRY_HOURS=24"
				"MFA_ISSUER=CyberRadar") ;;
		audit-service)
			SVC_ENV+=("CLICKHOUSE_DSN=$CLICKHOUSE_DSN") ;;
		ueba-service)
			SVC_ENV+=("CLICKHOUSE_DSN=$CLICKHOUSE_DSN" "REDIS_URL=redis://:$REDIS_PASS@localhost:6379/8") ;;
		siem-service)
			SVC_ENV+=("CLICKHOUSE_DSN=$CLICKHOUSE_DSN" "REDIS_URL=redis://:$REDIS_PASS@localhost:6379/9") ;;
		notification-service)
			SVC_ENV+=("SMTP_HOST=localhost" "SMTP_PORT=1025" "SMTP_FROM=noreply@cyberradar.io") ;;
		dashboard-service)
			SVC_ENV+=("CLICKHOUSE_URL=localhost:9000" "CLICKHOUSE_USER=default" "CLICKHOUSE_PASSWORD=") ;;
		attackpath-service)
			# The mirror only turns on when a Neo4j is configured. Reads stay on
			# PostgreSQL either way until a reconciliation reports parity.
			if [[ -n "$NEO4J_HOME" ]]; then
				SVC_ENV+=("NEO4J_URI=bolt://localhost:7687" "NEO4J_USERNAME=neo4j"
					"NEO4J_PASSWORD=$NEO4J_PASS" "ATTACKPATH_GRAPH_READS=postgres")
			fi ;;
		knowledgegraph-service)
			if [[ -n "$NEO4J_HOME" ]]; then
				SVC_ENV+=("NEO4J_URI=bolt://localhost:7687" "NEO4J_USERNAME=neo4j"
					"NEO4J_PASSWORD=$NEO4J_PASS" "KG_GRAPH_READS=postgres")
			fi ;;
		soar-service)
			SVC_ENV+=(
				"IDENTITY_URL=http://localhost:8002" "SIEM_URL=http://localhost:8008"
				"AUDIT_URL=http://localhost:8003"
				"TI_URL=http://localhost:8010" "VULN_URL=http://localhost:8011"
				"ASSET_URL=http://localhost:8006" "ATTACKPATH_URL=http://localhost:8012"
				"NETSEC_URL=http://localhost:8022" "IR_URL=http://localhost:8026"
				"NOTIFICATION_URL=http://localhost:8004"
				"SOAR_CLIENT_ID=${SOAR_CLIENT_ID:-$(soar_client_id)}"
				"SOAR_CLIENT_SECRET=${SOAR_CLIENT_SECRET:-$(soar_client_secret)}") ;;
		copilot-service)
			SVC_ENV+=(
				"SIEM_SERVICE_URL=http://localhost:8008" "UEBA_SERVICE_URL=http://localhost:8009"
				"TI_SERVICE_URL=http://localhost:8010" "VULN_SERVICE_URL=http://localhost:8011"
				"ATTACKPATH_SERVICE_URL=http://localhost:8012" "KG_SERVICE_URL=http://localhost:8013"
				"SOAR_SERVICE_URL=http://localhost:8014" "DASHBOARD_SERVICE_URL=http://localhost:8015"
				"ASSET_SERVICE_URL=http://localhost:8006"
				"ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}"
				"ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL:-}"
				"ANTHROPIC_MODEL=${ANTHROPIC_MODEL:-}"
				"COPILOT_EFFORT=${COPILOT_EFFORT:-}"
				"COPILOT_MAX_TOKENS=${COPILOT_MAX_TOKENS:-}"
				"EMBEDDINGS_URL=${EMBEDDINGS_URL:-}" "EMBEDDINGS_API_KEY=${EMBEDDINGS_API_KEY:-}"
				"EMBEDDINGS_MODEL=${EMBEDDINGS_MODEL:-BAAI/bge-large-en-v1.5}") ;;
	esac
	# An explicit success: under `set -e`, a case branch whose last statement is
	# a false test would otherwise end this function non-zero and take the whole
	# script with it. It did, once, and only two services started.
	return 0
}

# ─── Infrastructure ───────────────────────────────────────────────────────────

infra_postgres() {
	if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
		ok "PostgreSQL already accepting connections"
	else
		if command -v pg_ctlcluster >/dev/null; then
			pg_ctlcluster "$(ls /etc/postgresql | head -1)" main start 2>/dev/null || true
		else
			warn "start PostgreSQL yourself — no pg_ctlcluster here"
		fi
		wait_port 5432 30 postgres
	fi
	# The role and databases the platform expects. Created here rather than
	# assumed, so a fresh machine needs no manual step.
	local psql="psql -v ON_ERROR_STOP=1 -q"
	sudo_pg() { su postgres -c "$*" 2>/dev/null || eval "$*"; }
	sudo_pg "$psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$PGUSER_NAME'\" | grep -q 1" \
		|| sudo_pg "$psql -c \"CREATE ROLE $PGUSER_NAME LOGIN SUPERUSER PASSWORD '$PGPASS'\"" >/dev/null
	for db in "$PGDB" crp_keycloak; do
		sudo_pg "$psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$db'\" | grep -q 1" \
			|| sudo_pg "$psql -c \"CREATE DATABASE $db OWNER $PGUSER_NAME\"" >/dev/null
	done
	ok "role $PGUSER_NAME, databases $PGDB and crp_keycloak"

	# Thirty services against one server: at PostgreSQL's default of 100
	# connections the platform cannot start. Raising it needs a restart, so it
	# is done once and only when it is actually too low.
	local maxconn; maxconn="$(sudo_pg "psql -tAc 'SHOW max_connections'" | tr -d ' ')"
	if [[ "${maxconn:-0}" -lt 400 ]]; then
		sudo_pg "psql -q -c 'ALTER SYSTEM SET max_connections = 400'" >/dev/null
		if command -v pg_ctlcluster >/dev/null; then
			pg_ctlcluster "$(ls /etc/postgresql | head -1)" main restart 2>/dev/null || true
			wait_port 5432 30 postgres
		else
			warn "max_connections is $maxconn; restart PostgreSQL to pick up 400"
		fi
		ok "max_connections raised from $maxconn to 400"
	else
		ok "max_connections is $maxconn"
	fi
}

infra_redis() {
	if redis-cli -a "$REDIS_PASS" --no-auth-warning ping >/dev/null 2>&1; then
		ok "Redis already running"; return
	fi
	# noeviction, not the default allkeys-lru: the detection counters live in
	# Redis, and evicting one loses a threshold silently.
	start redis redis-server --port 6379 --requirepass "$REDIS_PASS" \
		--maxmemory-policy noeviction --save '' --appendonly no \
		--dir "$STATE_DIR"
	wait_port 6379 20 redis
}

infra_clickhouse() {
	if ! command -v "$CLICKHOUSE_BIN" >/dev/null; then
		warn "no ClickHouse binary (CRP_CLICKHOUSE_BIN) — SIEM, UEBA and audit will not store events"
		return
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/9000) 2>/dev/null; then exec 3>&-; ok "ClickHouse already running"; return; fi
	mkdir -p "$STATE_DIR/clickhouse"
	# Started from the state directory, because the paths in the configuration
	# are relative to the working directory: run from anywhere else and
	# ClickHouse writes its data there — which, from backend/, means into the
	# repository.
	start clickhouse env -C "$STATE_DIR" "$CLICKHOUSE_BIN" server \
		--config-file="$BACKEND_DIR/scripts/dev-local/clickhouse-config.xml"
	wait_port 9000 60 clickhouse
}

infra_kafka() {
	if [[ ! -d "$KAFKA_HOME" ]]; then
		warn "no Kafka at $KAFKA_HOME (CRP_KAFKA_HOME) — events and KPI publishing will not flow"
		return
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/9092) 2>/dev/null; then exec 3>&-; ok "Kafka already running"; return; fi
	local data="$STATE_DIR/kafka-logs"
	local cfg="$STATE_DIR/kafka.properties"
	cat > "$cfg" <<-EOF
		process.roles=broker,controller
		node.id=1
		controller.quorum.voters=1@localhost:9093
		listeners=PLAINTEXT://:9092,CONTROLLER://:9093
		advertised.listeners=PLAINTEXT://localhost:9092
		controller.listener.names=CONTROLLER
		listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
		log.dirs=$data
		offsets.topic.replication.factor=1
		transaction.state.log.replication.factor=1
		transaction.state.log.min.isr=1
		auto.create.topics.enable=true
	EOF
	if [[ ! -f "$data/meta.properties" ]]; then
		local uuid; uuid="$("$KAFKA_HOME/bin/kafka-storage.sh" random-uuid)"
		"$KAFKA_HOME/bin/kafka-storage.sh" format -t "$uuid" -c "$cfg" >/dev/null
	fi
	KAFKA_HEAP_OPTS="-Xmx512m -Xms256m" start kafka "$KAFKA_HOME/bin/kafka-server-start.sh" "$cfg"
	wait_port 9092 60 kafka
}

infra_neo4j() {
	if [[ -z "$NEO4J_HOME" ]]; then
		warn "no Neo4j (CRP_NEO4J_HOME) — the attack and knowledge graphs stay in PostgreSQL, which is where reads point by default anyway"
		return
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/7687) 2>/dev/null; then exec 3>&-; ok "Neo4j already running"; return; fi
	start neo4j "$NEO4J_HOME/bin/neo4j" console
	wait_port 7687 90 neo4j
}

infra_keycloak() {
	if [[ ! -d "$KEYCLOAK_HOME" ]]; then
		warn "no Keycloak at $KEYCLOAK_HOME (CRP_KEYCLOAK_HOME) — the API works, the web interface cannot sign anyone in"
		return
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&-; ok "Keycloak already running"; return; fi
	# start-dev --import-realm reads data/import inside the installation; there
	# is no option to point it elsewhere, so the realm is copied in. That writes
	# into $KEYCLOAK_HOME, which is why this only ever runs against a Keycloak
	# the developer unpacked for this purpose.
	mkdir -p "$KEYCLOAK_HOME/data/import"
	cp "$BACKEND_DIR"/deployments/keycloak/import/*.json "$KEYCLOAK_HOME/data/import/"
	KC_DB=postgres \
	KC_DB_URL="jdbc:postgresql://localhost:5432/crp_keycloak" \
	KC_DB_USERNAME="$PGUSER_NAME" KC_DB_PASSWORD="$PGPASS" \
	KC_HOSTNAME=localhost KC_HOSTNAME_PORT=8080 \
	KC_HOSTNAME_STRICT=false KC_HOSTNAME_STRICT_HTTPS=false \
	KC_HTTP_ENABLED=true KC_HTTP_PORT=8080 KC_HEALTH_ENABLED=true \
	KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-Admin@CyberRadar2025!}" \
	JAVA_OPTS_APPEND="-Xmx768m" \
	start keycloak "$KEYCLOAK_HOME/bin/kc.sh" start-dev --import-realm
	wait_port 8080 240 keycloak
}

cmd_infra() {
	step "Infrastructure"
	infra_postgres
	infra_redis
	infra_clickhouse
	infra_kafka
	infra_neo4j
	infra_keycloak
}

# ─── Migrations and keys ──────────────────────────────────────────────────────

# cmd_reset drops and recreates the platform database.
#
# Since the migrations carry a version table, `migrate` is replayable and a
# reset is no longer the way to pick up a new one — this is here for starting
# from a clean slate on purpose, not as the only way forward.
cmd_reset() {
	step "Resetting $PGDB"
	local psql="psql -v ON_ERROR_STOP=1 -q"
	sudo_pg() { su postgres -c "$*" 2>/dev/null || eval "$*"; }
	sudo_pg "$psql -c \"DROP DATABASE IF EXISTS $PGDB WITH (FORCE)\"" >/dev/null
	sudo_pg "$psql -c \"CREATE DATABASE $PGDB OWNER $PGUSER_NAME\"" >/dev/null
	ok "$PGDB recreated, empty"
	if (exec 3<>/dev/tcp/127.0.0.1/9000) 2>/dev/null; then
		exec 3>&-
		for db in crp_siem crp_ueba crp_ti crp_vuln crp_audit crp_dash; do
			"$CLICKHOUSE_BIN" client --port 9000 --query "DROP DATABASE IF EXISTS $db" || true
		done
		ok "ClickHouse databases dropped"
	fi
}

cmd_migrate() {
	step "Keys"
	if [[ -f "$BACKEND_DIR/deployments/jwt/private.pem" ]]; then
		ok "JWT key pair already present"
	else
		"$BACKEND_DIR/scripts/gen-jwt-keys.sh"
	fi

	step "Migrations"
	local n=0
	# PostgreSQL through the version table: the command applies what is not yet
	# applied and says so, which is why this step can simply be run again after
	# a new migration lands. What stood here before was a loop guarded by "the
	# database already has the schema, start over with reset" — and that guard
	# covered the whole function, so an install that first came up without
	# ClickHouse could never be given its schema afterwards: the one store that
	# was missing was the one the guard made unreachable.
	local pg_out
	if pg_out=$(cd "$BACKEND_DIR" && DATABASE_URL="$DATABASE_URL" \
		go run ./internal/cmd/migrate up 2>&1); then
		ok "PostgreSQL: ${pg_out//$'\n'/; }"
	else
		printf '%s\n' "$pg_out" >&2
		if printf '%s' "$pg_out" | grep -q "migrate baseline"; then
			warn "adopt the schema this database already carries, then migrate again:"
			warn "  $0 migrate-baseline && $0 migrate"
		fi
		fail "PostgreSQL migrations"
		return 1
	fi

	if (exec 3<>/dev/tcp/127.0.0.1/9000) 2>/dev/null; then
		exec 3>&-
		n=0
		for f in "$BACKEND_DIR"/migrations/clickhouse/*.sql; do
			"$CLICKHOUSE_BIN" client --port 9000 --multiquery < "$f" \
				|| { fail "ClickHouse: $(basename "$f")"; return 1; }
			n=$((n + 1))
		done
		ok "$n ClickHouse migrations"
	else
		warn "ClickHouse is not running — its migrations were skipped"
	fi

	if [[ -n "$NEO4J_HOME" ]] && (exec 3<>/dev/tcp/127.0.0.1/7687) 2>/dev/null; then
		exec 3>&-
		n=0
		for f in "$BACKEND_DIR"/migrations/neo4j/*.cypher; do
			"$NEO4J_HOME/bin/cypher-shell" -u neo4j -p "$NEO4J_PASS" -f "$f" >/dev/null \
				|| { fail "Neo4j: $(basename "$f")"; return 1; }
			n=$((n + 1))
		done
		ok "$n Neo4j migrations"
	fi
}

# cmd_migrate_baseline adopts a schema applied before the version table existed.
#
# Every installation that predates `internal/cmd/migrate` is in that state: the
# tables are there and nothing records that they are. The command refuses an
# empty database and one that already has a version, so this is safe to run
# when unsure.
cmd_migrate_baseline() {
	step "Adopting the existing schema"
	(cd "$BACKEND_DIR" && DATABASE_URL="$DATABASE_URL" go run ./internal/cmd/migrate baseline) \
		|| { fail "baseline"; return 1; }
}

# ─── Detection content ────────────────────────────────────────────────────────

# cmd_content reconciles the detection catalogue with the content pack.
#
# The detections are no longer in a migration: they are files, and this is what
# puts them in the database. Separate from migrate because that is the whole
# point — content ships on its own cadence, so loading it has to be a step you
# can run on its own, as often as the content changes and never because the
# schema did.
#
# Idempotent by construction: a pack whose fingerprints match what is already
# published reports "nothing to change" and leaves every version number alone.
cmd_content() {
	step "Detection content"

	# Rebuilt whenever a source file is newer than the binary, not only when
	# the binary is missing. A cached contentctl that predates a new flag fails
	# by printing the usage of the tool it used to be, which reads as a mistake
	# in the caller rather than as a stale build.
	local ctl="$BACKEND_DIR/bin/contentctl"
	local stale=0
	if [[ ! -x "$ctl" ]]; then
		stale=1
	elif [[ -n "$(find "$BACKEND_DIR/services/siem/cmd/contentctl" \
	                   "$BACKEND_DIR/services/siem/internal/content" \
	                   -name '*.go' -newer "$ctl" -print -quit 2>/dev/null)" ]]; then
		stale=1
	fi
	if (( stale )); then
		(cd "$BACKEND_DIR" && go build -o bin/contentctl ./services/siem/cmd/contentctl) \
			|| { fail "could not build contentctl"; return 1; }
	fi

	# A deployment loads a signed release; a developer box loads the directory
	# it is editing. Both go through the same reconciliation, which is the point
	# — the difference is only whether anything vouched for where it came from.
	local -a args=(-db "$DATABASE_URL" -apply -quiet)
	local what from=""
	if [[ -n "${CRP_CONTENT_CHANNEL:-}" ]]; then
		# A channel is how a real deployment gets content: it follows a
		# published index and installs whatever that calls current, rather than
		# being handed a file by whoever happened to copy one over.
		args+=(-channel "$CRP_CONTENT_CHANNEL")
		what="${CRP_CONTENT_VERSION:-the current version} from $CRP_CONTENT_CHANNEL"
		[[ -n "${CRP_CONTENT_VERSION:-}" ]] && args+=(-version "$CRP_CONTENT_VERSION")
		from="channel"
	elif [[ -n "${CRP_CONTENT_PACK:-}" ]]; then
		args+=(-pack "$CRP_CONTENT_PACK")
		what="$(basename "$CRP_CONTENT_PACK")"
		from="pack"
	else
		args+=(-dir "$BACKEND_DIR/content/detections")
		what="the working directory"
	fi

	if [[ -n "$from" ]]; then
		if [[ -n "${CRP_CONTENT_TRUST:-}" ]]; then
			args+=(-trust "$CRP_CONTENT_TRUST")
		else
			# Said out loud every time. A deployment reaching this by accident
			# is a deployment that verifies nothing and looks like it does.
			warn "a published release is configured and CRP_CONTENT_TRUST is not — loading unsigned"
			args+=(-allow-unsigned)
		fi
	fi

	local out
	if ! out="$("$ctl" "${args[@]}" 2>&1)"; then
		fail "detection content"
		printf '%s\n' "$out" | sed 's/^/      /'
		return 1
	fi
	if [[ -n "$out" ]]; then
		printf '%s\n' "$out" | sed 's/^/      /'
	fi
	ok "catalogue reconciled with $what"
}

# ─── Seed ─────────────────────────────────────────────────────────────────────

# cmd_seed gives the realm's users an identity on the platform.
#
# Keycloak authenticates; this platform authorises. A person the directory
# knows and the platform does not gets a clear 403 rather than an empty
# interface, which is the right answer — but it also means a fresh install has
# nobody who can see anything until identities exist. This creates them, with
# the roles the realm's own users are meant to have.
#
# Emails match deployments/keycloak/import/cyberradar-realm.json. A role a user
# is given here must exist in the platform's roles table: the two vocabularies
# are not the same, and the mapping is a judgement rather than a translation.
cmd_seed() {
	step "Seeding identities"
	# The statements live in migrations/seed so that the Docker path and this
	# script run exactly the same ones, rather than two copies free to drift.
	PGPASSWORD="$PGPASS" psql -h localhost -U "$PGUSER_NAME" -d "$PGDB" \
		-v ON_ERROR_STOP=1 -q -f "$BACKEND_DIR/migrations/seed/001_identities.sql" \
		|| { fail "seeding identities"; return 1; }
	local n
	n="$(PGPASSWORD="$PGPASS" psql -h localhost -U "$PGUSER_NAME" -d "$PGDB" -tAc \
		"SELECT count(*) FROM identities WHERE status='active'")"
	ok "$n identities, each with the roles its permissions come from"
}

# cmd_demo fills the tenant with a demonstration estate.
#
# Separate from seed on purpose: seed creates the people who may sign in, and
# an install needs it. This creates a bank's worth of assets, vulnerabilities,
# indicators, incidents and controls, which an install being prepared for real
# data does not want.
cmd_demo() {
	[[ -x "$BACKEND_DIR/bin/demo-seed" ]] || cmd_build
	(cd "$BACKEND_DIR" && CRP_STATE_DIR="$STATE_DIR" DATABASE_URL="$DATABASE_URL" \
		JWT_PRIVATE_KEY_PATH="$BACKEND_DIR/deployments/jwt/private.pem" \
		./bin/demo-seed "$@")
}

# cmd_smoke reads every service's list endpoints and fails on any 5xx.
#
# It is the check that a class of defect no build sees — a nullable column
# scanned into a Go string — has not come back. Run it after `demo`: a read of
# an empty table cannot hit a NULL, so a pass against an empty install means
# very little.
cmd_smoke() {
	step "Reading every service's list endpoints"
	(cd "$BACKEND_DIR" && APICHECK_DSN="$DATABASE_URL" \
		JWT_PRIVATE_KEY_PATH="$BACKEND_DIR/deployments/jwt/private.pem" \
		go test ./internal/pkg/apicheck/ -run TestEveryReadRouteAnswers -v -count=1)
}

# cmd_e2e drives the interface in a browser against this installation.
#
# Run it after `demo`: the tests assert that figures are on screen, and a page
# reading zero is indistinguishable from a page that is broken.
cmd_e2e() {
	step "End-to-end, in a browser"
	local chromium="${CRP_CHROMIUM_PATH:-}"
	if [[ -z "$chromium" && -x /opt/pw-browsers/chromium ]]; then
		chromium=/opt/pw-browsers/chromium
	fi
	(cd "$REPO_DIR/frontend" && [[ -d node_modules ]] || npm ci --silent)
	(cd "$REPO_DIR/frontend" && CRP_CHROMIUM_PATH="$chromium" npx playwright test "$@")
}

# ─── Services ─────────────────────────────────────────────────────────────────

cmd_build() {
	step "Building"
	(cd "$BACKEND_DIR" && make build >/dev/null) || { fail "build failed"; return 1; }
	ok "$(ls "$BACKEND_DIR/bin" | wc -l) binaries in backend/bin"
}

# resolve_unit NAME — accept "siem" for "siem-service".
#
# The suffix is the deployment's, not the reader's: nobody debugging the SIEM
# thinks of it as siem-service, and a restart that answers "no such unit" over a
# missing suffix is friction with no purpose.
resolve_unit() {
	local name="$1"
	if [[ -f "$PID_DIR/$name.pid" || -x "$BACKEND_DIR/bin/$name" ]]; then
		printf '%s\n' "$name"; return 0
	fi
	if [[ -f "$PID_DIR/$name-service.pid" || -x "$BACKEND_DIR/bin/$name-service" ]]; then
		printf '%s\n' "$name-service"; return 0
	fi
	printf '%s\n' "$name"
}

# cmd_restart [NAME…] — stop, then start again.
#
# `services` starts only what is not already running, so it leaves a service on
# the binary it was launched with. That is how a freshly built fix ends up not
# being the thing that answers: health passes, the logs look right, and the route
# you just added is a 404 from a process started ten minutes ago. Restarting by
# hand has the same trap one level down — the frontend keeps serving HTML that
# names chunk hashes the new build has replaced, and every page renders empty
# with no error anywhere.
#
# With no name, everything. With names, only those.
cmd_restart() {
	local names=()
	if [[ $# -eq 0 ]]; then
		names=(frontend pipeline-worker)
		local entry name
		for entry in "${SERVICES[@]}"; do IFS=: read -r name _ <<< "$entry"; names+=("$name"); done
	else
		local arg
		for arg in "$@"; do names+=("$(resolve_unit "$arg")"); done
	fi

	step "Restarting"
	local want_services=0 want_frontend=0 name
	for name in "${names[@]}"; do
		stop "$name"
		ok "$name stopped"
		if [[ "$name" == frontend ]]; then want_frontend=1; else want_services=1; fi
	done

	# Started through the ordinary paths, so a restarted unit gets exactly the
	# environment a fresh one would rather than a second, drifting copy of it.
	if [[ $want_services -eq 1 ]]; then cmd_services; fi
	if [[ $want_frontend -eq 1 ]]; then cmd_frontend; fi
}

SOAR_CREDENTIAL="${CRP_SOAR_CREDENTIAL:-$STATE_DIR/soar-executor.json}"

# soar_client_id / soar_client_secret read the credential the accounts step
# wrote. Empty when it has not run yet, which the SOAR reports at start-up
# rather than failing silently at its first action.
soar_client_id()     { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_id"])' "$SOAR_CREDENTIAL" 2>/dev/null || true; }
soar_client_secret() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_secret"])' "$SOAR_CREDENTIAL" 2>/dev/null || true; }

# cmd_accounts creates the service accounts a service needs to call the others.
#
# The SOAR acts under its own identity, by design and as documented: a playbook
# that blocks an address must not do it as the analyst who pressed run. The
# design was right and nothing created the account — every installation ran with
# SOAR_CLIENT_SECRET=change-me-create-the-account-first, so every action that
# reached another service answered 401. The end-to-end chain found it; this is
# the step that was missing.
#
# It needs the identity service listening, so it runs after `services` and the
# SOAR is restarted with the credential it just got.
cmd_accounts() {
	step "Service accounts"
	local out
	if ! out=$(cd "$BACKEND_DIR" && JWT_PRIVATE_KEY_PATH="$BACKEND_DIR/deployments/jwt/private.pem" \
		DATABASE_URL="$DATABASE_URL" IDENTITY_URL="http://localhost:8002" \
		go run ./internal/cmd/svcaccount \
		-client-id soar-executor -role soar_executor -out "$SOAR_CREDENTIAL" 2>&1); then
		fail "could not provision soar-executor:"
		printf '%s\n' "$out" | sed 's/^/     /'
		return 1
	fi
	ok "soar-executor (credential in $SOAR_CREDENTIAL)"
	if [[ -f "$PID_DIR/soar-service.pid" ]]; then
		cmd_restart soar-service >/dev/null 2>&1 || warn "restart soar-service by hand to pick the credential up"
		ok "soar-service restarted with its credential"
	fi
}

cmd_services() {
	cmd_build
	step "Services"
	local started=0
	for entry in "${SERVICES[@]}"; do
		IFS=: read -r name port _ <<< "$entry"
		local bin="$BACKEND_DIR/bin/$name"
		[[ -x "$bin" ]] || { fail "$name: no binary"; continue; }
		# The Copilot refuses to start without a model key, which is the right
		# behaviour: an assistant that silently answers nothing is worse than
		# one that is absent. Skipped rather than left dead in the list.
		if [[ "$name" == "copilot-service" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
			warn "copilot-service skipped — set ANTHROPIC_API_KEY to run it"
			continue
		fi
		service_env "$name" "$port"
		start "$name" env "${SVC_ENV[@]}" "$bin"
		started=$((started + 1))
	done
	ok "$started services starting"

	# The pipeline worker has no port: it consumes from Kafka and writes to
	# ClickHouse.
	if [[ -x "$BACKEND_DIR/bin/pipeline-worker" ]]; then
		start pipeline-worker env \
			"DATABASE_URL=$DATABASE_URL" "KAFKA_BROKERS=localhost:9092" \
			"KAFKA_GROUP_ID=crp-pipeline" "CLICKHOUSE_DSN=$CLICKHOUSE_DSN" \
			"IOC_REFRESH_SECONDS=${CRP_IOC_REFRESH_SECONDS:-15}" \
			"CLICKHOUSE_BATCH_SIZE=1000" "LOG_LEVEL=${CRP_LOG_LEVEL:-info}" \
			"$BACKEND_DIR/bin/pipeline-worker"
	fi

	sleep 3
	local up=0 down=0
	for entry in "${SERVICES[@]}"; do
		IFS=: read -r name port _ <<< "$entry"
		running "$name" || continue
		if curl -fsS -m 2 "http://localhost:$port/health" >/dev/null 2>&1; then
			up=$((up + 1))
		else
			down=$((down + 1)); fail "$name (:$port) — $LOG_DIR/$name.log"
		fi
	done
	if [[ $down -eq 0 ]]; then ok "all $up services answer /health"; else warn "$up up, $down down"; fi
}

# ─── Frontend ─────────────────────────────────────────────────────────────────

cmd_frontend() {
	step "Frontend"
	local env_file="$REPO_DIR/frontend/.env.local"
	if [[ ! -f "$env_file" ]]; then
		cat > "$env_file" <<-EOF
			NEXT_PUBLIC_APP_NAME=CyberRadar
			NEXTAUTH_URL=http://localhost:3000
			NEXTAUTH_SECRET=$(openssl rand -base64 32)
			AUTH_TRUST_HOST=true
			KEYCLOAK_CLIENT_ID=cyberradar-frontend
			KEYCLOAK_CLIENT_SECRET=crp-frontend-secret-dev-change-in-prod
			KEYCLOAK_ISSUER=http://localhost:8080/realms/cyberradar
			NEXT_PUBLIC_API_URL=http://localhost:8001
			NEXT_PUBLIC_ENABLE_COPILOT=true
			NEXT_PUBLIC_ENABLE_DEMO_MODE=false
		EOF
		ok "wrote frontend/.env.local (the client secret is the realm's development one)"
	else
		ok "frontend/.env.local already present"
	fi

	(cd "$REPO_DIR/frontend" && [[ -d node_modules ]] || npm ci --silent)
	(cd "$REPO_DIR/frontend" && npm run build >/dev/null) || { fail "next build failed"; return 1; }
	# AUTH_TRUST_HOST is passed in the process environment, not left to
	# .env.local: Auth.js checks it inside the Next middleware, and a value that
	# only lives in .env.local never reaches the edge runtime there. Signing in
	# fails with UntrustedHost and a 500 that says only "a problem with the
	# server configuration".
	start frontend env -C "$REPO_DIR/frontend" AUTH_TRUST_HOST=true npm run start
	wait_port 3000 60 frontend
}

# ─── Status and teardown ──────────────────────────────────────────────────────

cmd_status() {
	step "Infrastructure"
	local checks=(
		"PostgreSQL:5432" "Redis:6379" "ClickHouse:9000" "Kafka:9092"
		"Neo4j:7687" "Keycloak:8080" "Frontend:3000"
	)
	for c in "${checks[@]}"; do
		IFS=: read -r label port <<< "$c"
		if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&-; ok "$label :$port"
		else warn "$label :$port not listening"; fi
	done

	step "Services"
	local up=0 down=0
	for entry in "${SERVICES[@]}"; do
		IFS=: read -r name port _ <<< "$entry"
		if curl -fsS -m 2 "http://localhost:$port/health" >/dev/null 2>&1; then
			up=$((up + 1))
		else
			down=$((down + 1)); fail "$name :$port"
		fi
	done
	printf '\n   %d of %d services healthy\n' "$up" "$((up + down))"
}

cmd_logs() {
	local name="${1:-}"
	[[ -n "$name" ]] || { ls "$LOG_DIR" | sed 's/\.log$//'; return; }
	tail -f "$LOG_DIR/$name.log"
}

cmd_down() {
	step "Stopping"
	local stopped=0
	for pidfile in "$PID_DIR"/*.pid; do
		[[ -e "$pidfile" ]] || continue
		local name; name="$(basename "$pidfile" .pid)"
		stop "$name"; stopped=$((stopped + 1))
	done
	ok "$stopped process(es) stopped"
	warn "PostgreSQL was left running: this script does not stop what it found already up"
}

cmd_up() {
	cmd_infra
	cmd_migrate
	cmd_content
	cmd_seed
	cmd_services
	cmd_accounts
	cmd_frontend
	cmd_status
	printf '\n   Web interface  http://localhost:3000\n'
	printf '   Sign in as     admin@cyberradar.io / Admin@CyberRadar2025!\n'
	printf '   Keycloak       http://localhost:8080 (admin / Admin@CyberRadar2025!)\n'
	printf '   Demonstration  %s demo   (assets, vulnerabilities, alerts, incidents, controls)\n\n' "$0"
}

case "${1:-up}" in
	up) cmd_up ;;
	reset) cmd_reset ;;
	seed) cmd_seed ;;
	demo) shift; cmd_demo "$@" ;;
	accounts) cmd_accounts ;;
	smoke) cmd_smoke ;;
	e2e) shift; cmd_e2e "$@" ;;
	infra) cmd_infra ;;
	migrate) cmd_migrate ;;
	migrate-baseline) cmd_migrate_baseline ;;
	content) cmd_content ;;
	build) cmd_build ;;
	services) cmd_services ;;
	frontend) cmd_frontend ;;
	restart) shift; cmd_restart "$@" ;;
	status) cmd_status ;;
	logs) shift; cmd_logs "$@" ;;
	down) cmd_down ;;
	*) echo "usage: $0 {up|infra|reset|migrate|migrate-baseline|content|seed|demo|smoke|e2e|build|services|frontend|restart [name…]|status|logs [name]|down}" >&2; exit 2 ;;
esac
