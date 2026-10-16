#!/usr/bin/env bash
# bench-clean.sh — remove the events `make bench` wrote, and nothing else.
#
# The bench authenticates as a real identity, so its events land in that
# identity's tenant: the same one the demonstration estate uses. A few runs
# bury the estate — 151 403 bench events against 1 357 real ones, all of the
# bench's at LOW severity, which is then what a severity chart shows.
#
# The delete is scoped to source = 'crp-bench', the marker the bench writes on
# every event it produces (benchSource, internal/cmd/bench/main.go). Nothing
# else matches it. The counts are printed before anything is removed, and
# --yes is required to remove them.
set -euo pipefail

CH_URL="${CLICKHOUSE_HTTP:-http://localhost:8123/}"
SOURCE="crp-bench"

q() { curl -sS --fail-with-body "$CH_URL" --data "$1"; }

printf '\nCe qui porte la marque du banc (source = %s)\n\n' "$SOURCE"
q "SELECT tenant_id AS locataire, count() AS evenements
   FROM crp_audit.cyber_events WHERE source = '${SOURCE}'
   GROUP BY tenant_id ORDER BY evenements DESC FORMAT PrettyCompact"

total=$(q "SELECT count() FROM crp_audit.cyber_events WHERE source = '${SOURCE}' FORMAT TabSeparated")
printf '\ntotal : %s événements\n\n' "$total"

if [[ "${1:-}" != "--yes" ]]; then
	echo "Rien n'a été supprimé. Relancer avec --yes pour supprimer ces lignes."
	exit 0
fi

q "ALTER TABLE crp_audit.cyber_events DELETE WHERE source = '${SOURCE}'" >/dev/null
echo "Suppression demandée (ClickHouse la applique en arrière-plan)."
echo "Vérifier avec : SELECT count() FROM crp_audit.cyber_events WHERE source = '${SOURCE}'"
