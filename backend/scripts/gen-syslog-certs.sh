#!/usr/bin/env bash
# gen-syslog-certs.sh — Generate self-signed TLS certificates for the syslog connector (dev only)
# Usage: ./scripts/gen-syslog-certs.sh
# Output: deployments/certs/syslog.{crt,key}

set -euo pipefail

CERT_DIR="$(dirname "$0")/../deployments/certs"
mkdir -p "$CERT_DIR"

CERT_FILE="$CERT_DIR/syslog.crt"
KEY_FILE="$CERT_DIR/syslog.key"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
  echo "[syslog-certs] Certificates already exist at $CERT_DIR — skipping generation."
  echo "  Delete them to regenerate: rm $CERT_FILE $KEY_FILE"
  exit 0
fi

echo "[syslog-certs] Generating self-signed TLS certificate for syslog connector..."

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 3650 \
  -nodes \
  -subj "/C=FR/ST=IDF/L=Paris/O=CyberRadar/OU=Infra/CN=syslog-connector.crp.internal" \
  -addext "subjectAltName=DNS:syslog-connector,DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "[syslog-certs] Done."
echo "  Certificate: $CERT_FILE"
echo "  Private key: $KEY_FILE"
echo "  Valid for:   3650 days"
echo ""
echo "  WARNING: Self-signed certificates are for development only."
echo "  Use a proper CA-signed certificate in production."
