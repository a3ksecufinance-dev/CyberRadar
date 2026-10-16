#!/usr/bin/env bash
# gen-jwt-keys.sh — Generate the RSA key pair used to sign platform JWTs (dev only)
# Usage: ./scripts/gen-jwt-keys.sh
# Output: deployments/jwt/{private,public}.pem
#
# Only identity-service is given the private key; every other service mounts the
# public key alone and can therefore verify tokens but never mint one.

set -euo pipefail

KEY_DIR="$(dirname "$0")/../deployments/jwt"
mkdir -p "$KEY_DIR"

PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

if [ -f "$PRIVATE_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
  echo "[jwt-keys] Key pair already exists at $KEY_DIR — skipping generation."
  echo "  Delete them to regenerate: rm $PRIVATE_KEY $PUBLIC_KEY"
  echo "  Regenerating invalidates every token already issued."
  exit 0
fi

echo "[jwt-keys] Generating RSA-4096 key pair for JWT signing..."

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$PRIVATE_KEY" 2>/dev/null
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "[jwt-keys] Done:"
echo "  private key : $PRIVATE_KEY  (identity-service only — never commit)"
echo "  public key  : $PUBLIC_KEY   (mounted read-only into every service)"
echo
echo "In production, issue these from Vault or your KMS instead of a local file,"
echo "and rotate them on a schedule."
