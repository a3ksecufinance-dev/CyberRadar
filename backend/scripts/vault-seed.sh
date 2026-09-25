#!/usr/bin/env bash
# vault-seed.sh — Load the development secrets into Vault (dev only)
# Usage: ./scripts/vault-seed.sh
# Requires: the vault container running (make infra-up) and ./scripts/gen-jwt-keys.sh
#
# Services read secrets from crp/<service>/<name> on the KV v2 mount and fall
# back to environment variables, so this script is optional for local work —
# it exists to exercise the Vault path the way production will use it.

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-crp-vault-dev-token}"
KEY_DIR="$(dirname "$0")/../deployments/jwt"
PRIVATE_KEY="$KEY_DIR/private.pem"

if [ ! -f "$PRIVATE_KEY" ]; then
  echo "[vault-seed] $PRIVATE_KEY is missing — run ./scripts/gen-jwt-keys.sh first." >&2
  exit 1
fi

write_secret() {
  local path="$1"; shift
  curl -sf -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    --data "$1" \
    "$VAULT_ADDR/v1/secret/data/$path" > /dev/null
  echo "  → secret/$path"
}

echo "[vault-seed] Writing development secrets to $VAULT_ADDR..."

write_secret "crp/identity/database" "$(printf '{"data":{"url":"%s"}}' \
  "postgres://crp_user:crp_password_dev@postgres:5432/crp_foundation?sslmode=disable")"

# jq is not assumed: python does the JSON escaping of the PEM's newlines.
write_secret "crp/identity/jwt" "$(python3 -c '
import json, sys
print(json.dumps({"data": {"private_key": open(sys.argv[1]).read()}}))' "$PRIVATE_KEY")"

echo "[vault-seed] Done. identity-service will now read its database URL and"
echo "             signing key from Vault instead of its environment."
echo
echo "In production, replace the dev root token with AppRole or Kubernetes auth,"
echo "and give each service a policy scoped to its own crp/<service>/* path."
