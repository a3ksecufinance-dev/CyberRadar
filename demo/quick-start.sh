#!/usr/bin/env bash
# ============================================================
# CyberRadar Platform — Quick Start
# Starts the full stack and runs the interactive demo
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/../backend"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  CyberRadar Platform — Quick Start"
echo "  ─────────────────────────────────"
echo -e "${RESET}"

# 1. Check dependencies
for dep in docker docker-compose curl python3; do
  if ! command -v "$dep" &>/dev/null; then
    echo -e "${RED}  ✗ Missing dependency: $dep${RESET}"
    exit 1
  fi
done
echo -e "${GREEN}  ✓ All dependencies present${RESET}"

# 2. Start infrastructure
echo -e "\n${BOLD}  Starting infrastructure (Postgres, Kafka, Redis)...${RESET}"
cd "$BACKEND_DIR"
docker compose -f deployments/docker-compose.yml up -d postgres kafka redis 2>/dev/null
echo -e "${GREEN}  ✓ Infrastructure started${RESET}"

# 3. Wait for postgres
echo -e "\n${BOLD}  Waiting for PostgreSQL to be ready...${RESET}"
for i in $(seq 1 30); do
  if docker compose -f deployments/docker-compose.yml exec -T postgres pg_isready -U crp_user -d crp_foundation &>/dev/null; then
    echo -e "${GREEN}  ✓ PostgreSQL ready${RESET}"
    break
  fi
  sleep 2
  if [[ $i == 30 ]]; then
    echo -e "${RED}  ✗ PostgreSQL failed to start${RESET}"
    exit 1
  fi
done

# 4. Run migrations
echo -e "\n${BOLD}  Running database migrations...${RESET}"
if command -v migrate &>/dev/null; then
  migrate -path migrations/postgres -database "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable" up 2>/dev/null
  echo -e "${GREEN}  ✓ Migrations complete${RESET}"
else
  echo -e "  ⚠  'migrate' CLI not found — skipping (run manually with: make migrate)"
fi

# 5. Start all services
echo -e "\n${BOLD}  Starting all 26 security services...${RESET}"
docker compose -f deployments/docker-compose.yml up -d 2>/dev/null
echo -e "${GREEN}  ✓ All services starting${RESET}"

# 6. Wait for key services
echo -e "\n${BOLD}  Waiting for services to be ready (30s)...${RESET}"
sleep 30

# 7. Launch demo
echo -e "\n${BOLD}  Launching interactive demo...${RESET}\n"
cd "$SCRIPT_DIR"
bash cyberradar-demo.sh --menu
