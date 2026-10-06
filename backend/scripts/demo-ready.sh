#!/usr/bin/env bash
# demo-ready.sh — one verdict before presenting: is this installation safe to
# demonstrate?
#
# Why this exists rather than a checklist on paper. A demonstration fails in
# front of a room for reasons nobody looked at: the migrations are one version
# behind, a service answered /health and then died, the estate is empty so every
# chart reads zero, or the detection chain is broken in a way no log mentions —
# that last one cost this platform four CI runs before the broker's offsets gave
# it away. Each check below is one of those, in the order they bite.
#
#   ./scripts/demo-ready.sh            check, and say go or no-go
#   ./scripts/demo-ready.sh --chain    also drive the live attack (adds ~15s)
#
# Exit status is 0 only when every check passes. Nothing here changes the
# installation: it reads, it does not repair.
set -uo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$BACKEND_DIR/.." && pwd)"
STATE_DIR="${CRP_STATE_DIR:-$BACKEND_DIR/.dev-local}"

PGUSER_NAME="${CRP_PG_USER:-crp_user}"
PGPASS="${CRP_PG_PASSWORD-crp_password_dev}"
PGDB="${CRP_PG_DB:-crp_foundation}"
DATABASE_URL="postgres://$PGUSER_NAME:$PGPASS@localhost:5432/$PGDB?sslmode=disable"
FRONTEND_URL="${CRP_FRONTEND_URL:-http://localhost:3000}"

WITH_CHAIN=0
[[ "${1:-}" == "--chain" ]] && WITH_CHAIN=1

bold=$'\033[1m'; green=$'\033[32m'; red=$'\033[31m'; yellow=$'\033[33m'; off=$'\033[0m'
failures=0
warnings=0
ok()   { printf '   %s✓%s %s\n' "$green" "$off" "$1"; }
bad()  { printf '   %s✗%s %s\n' "$red" "$off" "$1"; failures=$((failures + 1)); }
warn() { printf '   %s!%s %s\n' "$yellow" "$off" "$1"; warnings=$((warnings + 1)); }
step() { printf '\n%s── %s%s\n' "$bold" "$1" "$off"; }

psql_q() { PGPASSWORD="$PGPASS" psql -h localhost -U "$PGUSER_NAME" -d "$PGDB" -tAc "$1" 2>/dev/null; }

# ─── 1. The stores ────────────────────────────────────────────────────────────
step "Infrastructure"
for probe in "PostgreSQL:5432" "Redis:6379" "ClickHouse:9000" "Kafka:9092"; do
	name="${probe%%:*}"; port="${probe##*:}"
	if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
		exec 3>&-; ok "$name on :$port"
	else
		bad "$name is not listening on :$port"
	fi
done
if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then
	exec 3>&-; ok "Keycloak on :8080 — the interface can sign people in"
else
	warn "Keycloak is not running: the API works, nobody can sign in to the interface"
fi

# ─── 2. The schema ────────────────────────────────────────────────────────────
#
# A schema one version behind shows itself as a 500 on one screen, which is the
# worst possible moment to discover it.
step "Schema"
version=$(cd "$BACKEND_DIR" && DATABASE_URL="$DATABASE_URL" go run ./internal/cmd/migrate version 2>&1)
latest=$(ls "$BACKEND_DIR"/migrations/postgres/*.up.sql 2>/dev/null | tail -1 | grep -oE '[0-9]{6}' | sed 's/^0*//')
case "$version" in
	"$latest") ok "at version $version, the latest on disk" ;;
	*dirty*)   bad "the version table is dirty: $version" ;;
	*)         bad "at '$version' but the files go to $latest — run: make migrate" ;;
esac

# ─── 3. The services ──────────────────────────────────────────────────────────
#
# Asked twice, three seconds apart. A service that answers once and not again is
# the case that put a dead SOAR behind a successful start-up.
step "Services"
# The one list of name:port, read from the runner rather than copied, so this
# cannot drift from what actually starts.
mapfile -t ports < <(sed -n '/^SERVICES=(/,/^)/p' "$BACKEND_DIR/scripts/dev-local.sh" \
	| grep -oE '"[a-z0-9-]+:[0-9]{4}' | tr -d '"')
if [[ ${#ports[@]} -eq 0 ]]; then
	bad "cannot read the service list from dev-local.sh"
	ports=()
fi
up=0; down=(); skipped=()
for entry in "${ports[@]}"; do
	name="${entry%%:*}"; port="${entry##*:}"
	# The Copilot refuses to start without a model key, and that is the right
	# behaviour: an assistant that silently answers nothing is worse than an
	# absent one. Absent on purpose is not a blocking fault, but the room has to
	# be told the screen will not be shown.
	if [[ "$name" == "copilot-service" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
		skipped+=("$name")
		continue
	fi
	if curl -fsS -m 3 "http://localhost:$port/health" >/dev/null 2>&1 \
	   && sleep 0.1 && curl -fsS -m 3 "http://localhost:$port/health" >/dev/null 2>&1; then
		up=$((up + 1))
	else
		down+=("$name (:$port)")
	fi
done
if [[ ${#down[@]} -eq 0 && ${#ports[@]} -gt 0 ]]; then
	ok "$up services answer /health, twice"
elif [[ ${#ports[@]} -gt 0 ]]; then
	bad "$up up, ${#down[@]} not answering: ${down[*]}"
fi
if [[ ${#skipped[@]} -gt 0 ]]; then
	warn "${skipped[*]} absent without ANTHROPIC_API_KEY: do not open the Copilot screen"
fi

# ─── 4. The estate ────────────────────────────────────────────────────────────
#
# An empty platform cannot be demonstrated: every page reads zero and a reviewer
# cannot tell a working product from one that merely starts.
step "Demonstration estate"
assets=$(psql_q "SELECT count(*) FROM assets")
vulns=$(psql_q "SELECT count(*) FROM vulnerabilities")
rules=$(psql_q "SELECT count(*) FROM detection_rules WHERE enabled")
ident=$(psql_q "SELECT count(*) FROM identities WHERE status='active'")
printf '   assets %s · vulnérabilités %s · règles actives %s · identités %s\n' \
	"${assets:-?}" "${vulns:-?}" "${rules:-?}" "${ident:-?}"
# Two different questions, and conflating them hides both. Did the seeder run
# at all, and is what it produced enough to carry a room?
alerts=$(psql_q "SELECT count(*) FROM siem_alerts" 2>/dev/null)
if [[ "${assets:-0}" -eq 0 ]]; then
	bad "no assets at all — run: make demo"
elif [[ "${assets:-0}" -lt 10 ]]; then
	bad "only ${assets} assets: the seeder did not finish — run: make demo"
else
	ok "the seeder has run"
	if [[ "${assets:-0}" -lt 40 ]]; then
		warn "${assets} assets and ${vulns} vulnerabilities is a small estate for a decision-maker audience; the alert and compliance screens carry more weight"
	fi
fi
[[ "${rules:-0}" -gt 5 ]]  && ok "the detection catalogue is loaded" || bad "no detection rules — run: make content"
[[ "${ident:-0}" -gt 0 ]]  && ok "somebody can sign in" || bad "no active identity — run: make seed"

# ─── 5. The credential the SOAR needs ─────────────────────────────────────────
step "Containment"
if [[ -f "${CRP_SOAR_CREDENTIAL:-$STATE_DIR/soar-executor.json}" ]]; then
	ok "the SOAR holds its service account"
else
	bad "no SOAR credential: every containment answers 401 — run: ./scripts/dev-local.sh accounts"
fi

# ─── 6. The interface ─────────────────────────────────────────────────────────
step "Interface"
if curl -fsS -m 5 "$FRONTEND_URL" >/dev/null 2>&1; then
	ok "answering on $FRONTEND_URL"
else
	warn "nothing on $FRONTEND_URL — run: ./scripts/dev-local.sh frontend"
fi

# ─── 7. The live chain ────────────────────────────────────────────────────────
#
# The only check that exercises the handovers between services, which is where
# this platform's defects have actually lived.
if [[ $WITH_CHAIN -eq 1 ]]; then
	step "The live attack, end to end"
	if (cd "$BACKEND_DIR" && make e2e-chain >/tmp/demo-chain.log 2>&1); then
		ok "$(grep -oE 'contained [0-9.]+ in [0-9.]+s' /tmp/demo-chain.log | tail -1)"
	else
		bad "the chain failed — see /tmp/demo-chain.log"
		grep -E "where it stopped|what the broker says|→ " /tmp/demo-chain.log | head -6 | sed 's/^/      /'
	fi
else
	step "The live attack, end to end"
	warn "not run; add --chain to drive it (this is the check that matters most)"
fi

# ─── Verdict ──────────────────────────────────────────────────────────────────
printf '\n%s── Verdict%s\n' "$bold" "$off"
if [[ $failures -eq 0 && $warnings -eq 0 ]]; then
	printf '   %sPrêt à démontrer.%s\n\n' "$green" "$off"
	exit 0
fi
if [[ $failures -eq 0 ]]; then
	printf '   %s%d réserve(s), rien de bloquant.%s Lisez-les avant de présenter.\n\n' \
		"$yellow" "$warnings" "$off"
	exit 0
fi
printf '   %s%d point(s) bloquant(s)%s, %d réserve(s). Ne présentez pas en l'\''état.\n\n' \
	"$red" "$failures" "$off" "$warnings"
exit 1
