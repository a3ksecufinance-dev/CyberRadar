#!/usr/bin/env bash
# ============================================================
# CyberRadar Platform — Interactive Demo
# Sovereign Next-Gen Cybersecurity Platform for Banks
# ============================================================
# Usage: bash demo/cyberradar-demo.sh [--seed | --scenario | --health | --menu]
# Compatible: bash 3.2+ (macOS default)
# ============================================================

set -uo pipefail

# ─── Colors ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Config ───────────────────────────────────────────────
BASE_URL="${CYBERRADAR_URL:-http://localhost}"
TOKEN="${CYBERRADAR_TOKEN:-}"
DELAY="${DEMO_DELAY:-0.4}"

# ─── Service lookups (bash 3.2 compatible) ────────────────
get_port() {
  case "$1" in
    tenant)        echo "8001" ;;
    identity)      echo "8002" ;;
    audit)         echo "8003" ;;
    notification)  echo "8004" ;;
    collector)     echo "8005" ;;
    asset)         echo "8006" ;;
    pam)           echo "8007" ;;
    siem)          echo "8008" ;;
    ueba)          echo "8009" ;;
    ti)            echo "8010" ;;
    vuln)          echo "8011" ;;
    attackpath)    echo "8012" ;;
    knowledgegraph) echo "8013" ;;
    soar)          echo "8014" ;;
    dashboard)     echo "8015" ;;
    copilot)       echo "8016" ;;
    apifw)         echo "8017" ;;
    compliance)    echo "8018" ;;
    easm)          echo "8019" ;;
    fraud)         echo "8020" ;;
    dlp)           echo "8021" ;;
    netsec)        echo "8022" ;;
    risk)          echo "8023" ;;
    iga)           echo "8024" ;;
    cspm)          echo "8025" ;;
    ir)            echo "8026" ;;
    scs)           echo "8027" ;;
    ot)            echo "8028" ;;
    mobile)        echo "8029" ;;
    dspm)          echo "8030" ;;
    *)             echo "0"   ;;
  esac
}

get_label() {
  case "$1" in
    tenant)        echo "Tenant Management" ;;
    identity)      echo "Identity & Access" ;;
    audit)         echo "Audit & Logging" ;;
    notification)  echo "Notifications" ;;
    collector)     echo "Event Collector" ;;
    asset)         echo "Asset Intelligence" ;;
    pam)           echo "Privileged Access Mgmt" ;;
    siem)          echo "SIEM" ;;
    ueba)          echo "UEBA" ;;
    ti)            echo "Threat Intelligence" ;;
    vuln)          echo "Vulnerability Mgmt" ;;
    attackpath)    echo "Attack Path Analysis" ;;
    knowledgegraph) echo "Knowledge Graph" ;;
    soar)          echo "SOAR / Orchestration" ;;
    dashboard)     echo "Dashboards" ;;
    copilot)       echo "AI Copilot" ;;
    apifw)         echo "API Firewall" ;;
    compliance)    echo "Compliance" ;;
    easm)          echo "Ext. Attack Surface" ;;
    fraud)         echo "Fraud Detection" ;;
    dlp)           echo "Data Loss Prevention" ;;
    netsec)        echo "Network Security" ;;
    risk)          echo "Risk Management" ;;
    iga)           echo "Identity Governance" ;;
    cspm)          echo "Cloud Security Posture" ;;
    ir)            echo "Incident Response" ;;
    scs)           echo "Supply Chain Security" ;;
    ot)            echo "OT/ICS Security" ;;
    mobile)        echo "Mobile Security" ;;
    dspm)          echo "Data Security Posture" ;;
    *)             echo "$1" ;;
  esac
}

ALL_SERVICES="tenant identity audit notification collector asset pam siem ueba ti vuln attackpath knowledgegraph soar dashboard copilot apifw compliance easm fraud dlp netsec risk iga cspm ir scs ot mobile dspm"

# ─── Helpers ──────────────────────────────────────────────
banner() {
  clear
  printf "${CYAN}"
  cat << 'EOF'
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  █████╗ ██████╗  █████╗ ██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝███████║██║  ██║███████║██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
EOF
  printf "${RESET}\n"
  printf "${WHITE}  Sovereign Next-Gen Cybersecurity Platform for Banks${RESET}\n"
  printf "${DIM}  26 Security Domains · Real-time Kafka Events · AI-Powered${RESET}\n"
  printf "${DIM}  ─────────────────────────────────────────────────────────${RESET}\n\n"
}

log()     { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
info()    { printf "${BLUE}  ℹ${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}  ⚠${RESET} %s\n" "$*"; }
step()    { printf "\n${BOLD}${MAGENTA}  ▶ %s${RESET}\n" "$*"; }
section() {
  printf "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}\n"
  printf "${BOLD}${WHITE}  %s${RESET}\n" "$*"
  printf "${BOLD}${CYAN}══════════════════════════════════════════${RESET}\n"
}
pause()   { sleep "$DELAY"; }

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local port="${4:-8001}"
  local url="${BASE_URL}:${port}${path}"

  if [ -n "$TOKEN" ]; then
    AUTH="-H \"Authorization: Bearer ${TOKEN}\""
  else
    AUTH=""
  fi

  if [ -n "$body" ]; then
    curl -sf --max-time 5 -X "$method" \
      -H "Content-Type: application/json" \
      ${TOKEN:+-H "Authorization: Bearer ${TOKEN}"} \
      -d "$body" "$url" 2>/dev/null || printf '{"error":"unavailable"}'
  else
    curl -sf --max-time 5 -X "$method" \
      -H "Content-Type: application/json" \
      ${TOKEN:+-H "Authorization: Bearer ${TOKEN}"} \
      "$url" 2>/dev/null || printf '{"error":"unavailable"}'
  fi
}

check_service() {
  local name="$1"
  local port
  port=$(get_port "$name")
  local label
  label=$(get_label "$name")
  local result
  result=$(curl -sf --max-time 2 "${BASE_URL}:${port}/health" 2>/dev/null || true)
  if [ -n "$result" ]; then
    printf "  ${GREEN}●${RESET} %-30s ${DIM}:%s${RESET}  ${GREEN}UP${RESET}\n" "$label" "$port"
    return 0
  else
    printf "  ${RED}●${RESET} %-30s ${DIM}:%s${RESET}  ${RED}DOWN${RESET}\n" "$label" "$port"
    return 1
  fi
}

pretty_json() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -m json.tool 2>/dev/null || printf '%s\n' "$1"
  else
    printf '%s\n' "$1"
  fi
}

press_enter() {
  printf "\n${DIM}  Press [ENTER] to continue...${RESET}\n"
  read -r _
}

# ─── Health Check ─────────────────────────────────────────
cmd_health() {
  banner
  section "Service Health Check — All 26 Domains"
  printf "\n"

  local up=0 down=0
  for svc in $ALL_SERVICES; do
    if check_service "$svc"; then
      up=$((up + 1))
    else
      down=$((down + 1))
    fi
    pause
  done

  printf "\n  ${BOLD}Summary:${RESET} ${GREEN}%d UP${RESET}  ${RED}%d DOWN${RESET}  (total: %d)\n\n" \
    "$up" "$down" "$((up + down))"
}

# ─── Seed Demo Data ───────────────────────────────────────
cmd_seed() {
  banner
  section "Seeding Demo Data — Banque Nationale de France"
  printf "\n"
  info "Tenant: Banque Nationale de France (BNF)"
  info "Scenario: Realistic banking security environment"
  printf "\n"

  # Domain 2: Assets
  step "Domain 02 · Asset Intelligence"
  api POST "/api/v1/assets" '{
    "name":"Core Banking System","asset_type":"application","criticality":"critical",
    "ip_address":"10.0.1.100","department":"IT","environment":"production",
    "tags":["critical","banking","core"]
  }' 8006 >/dev/null
  log "Core Banking System registered"
  pause

  api POST "/api/v1/assets" '{
    "name":"SWIFT Gateway","asset_type":"network_device","criticality":"critical",
    "ip_address":"10.0.2.50","department":"Treasury","environment":"production",
    "tags":["swift","payments","critical"]
  }' 8006 >/dev/null
  log "SWIFT Gateway registered"
  pause

  api POST "/api/v1/assets" '{
    "name":"Customer Portal","asset_type":"web_application","criticality":"high",
    "ip_address":"192.168.1.200","department":"Digital","environment":"production",
    "is_internet_facing":true,"tags":["web","customer-facing"]
  }' 8006 >/dev/null
  log "Customer Portal registered (internet-facing)"
  pause

  api POST "/api/v1/assets" '{
    "name":"Trading Workstation FX-01","asset_type":"workstation","criticality":"high",
    "ip_address":"10.0.3.101","department":"Trading","environment":"production",
    "tags":["trading","fx"]
  }' 8006 >/dev/null
  log "Trading Workstation FX-01 registered"
  pause

  # Domain 6: Threat Intel
  step "Domain 06 · Threat Intelligence — IOCs"
  api POST "/api/v1/ti/iocs" '{
    "type":"ip","value":"185.220.101.47","severity":"critical",
    "tags":["tor-exit-node","c2","apt29"],
    "source":"ANSSI","description":"Known APT29 C2 server"
  }' 8010 >/dev/null
  log "IOC: APT29 C2 IP ingested (185.220.101.47)"
  pause

  api POST "/api/v1/ti/iocs" '{
    "type":"domain","value":"update-security-bnf.com","severity":"high",
    "tags":["phishing","typosquatting"],
    "source":"Internal","description":"Typosquatting BNF customers"
  }' 8010 >/dev/null
  log "IOC: Phishing domain ingested"
  pause

  api POST "/api/v1/ti/iocs" '{
    "type":"hash","value":"e3b0c44298fc1c149afbf4c8996fb924","severity":"critical",
    "tags":["ransomware","lockbit"],
    "source":"CERT-FR","description":"LockBit 3.0 targeting financial institutions"
  }' 8010 >/dev/null
  log "IOC: LockBit 3.0 hash ingested"
  pause

  # Domain 7: Vulns
  step "Domain 07 · Vulnerability Management"
  api POST "/api/v1/vulnerabilities" '{
    "cve_id":"CVE-2024-3400","title":"PAN-OS Command Injection","severity":"critical",
    "cvss_score":10.0,"affected_component":"Palo Alto GlobalProtect",
    "description":"Unauthenticated RCE, actively exploited",
    "tags":["rce","actively-exploited","cisa-kev"]
  }' 8011 >/dev/null
  log "CVE-2024-3400 registered (CVSS 10.0)"
  pause

  api POST "/api/v1/vulnerabilities" '{
    "cve_id":"CVE-2024-21762","title":"Fortinet SSL-VPN RCE","severity":"critical",
    "cvss_score":9.6,"affected_component":"FortiOS SSL VPN",
    "description":"Critical RCE exploited in the wild",
    "tags":["vpn","rce","fortinet","cisa-kev"]
  }' 8011 >/dev/null
  log "CVE-2024-21762 registered (CVSS 9.6)"
  pause

  # Domain 22: IR
  step "Domain 22 · Incident Response"
  api POST "/api/v1/ir/playbooks" '{
    "name":"Banking Ransomware Response","category":"ransomware","severity":"critical",
    "description":"Immediate response for ransomware targeting banking systems",
    "tasks":[
      {"title":"Isolate affected systems","phase":"containment","priority":"critical"},
      {"title":"Preserve forensic evidence","phase":"identification","priority":"high"},
      {"title":"Notify CERT-FR","phase":"notification","priority":"critical"},
      {"title":"Activate BCP","phase":"recovery","priority":"high"}
    ]
  }' 8026 >/dev/null
  log "Playbook: Banking Ransomware Response created"
  pause

  api POST "/api/v1/ir/incidents" '{
    "title":"Suspicious lateral movement — Trading floor",
    "severity":"high","incident_type":"unauthorized_access",
    "description":"UEBA detected abnormal access patterns from FX-01 to core banking at 02:47 UTC.",
    "affected_systems":["Trading Workstation FX-01","Core Banking System"],
    "detected_by":"UEBA Engine","tags":["lateral-movement","trading","after-hours"]
  }' 8026 >/dev/null
  log "Incident: Suspicious lateral movement (high)"
  pause

  # Domain 25: Mobile
  step "Domain 25 · Mobile Security"
  api POST "/api/v1/mobile/devices" '{
    "device_name":"iPhone 15 Pro — Directeur Général","device_type":"smartphone",
    "platform":"ios","os_version":"17.4","model":"iPhone 15 Pro",
    "manufacturer":"Apple","ownership":"corporate",
    "owner_name":"Jean-Marc Dupont","owner_email":"jm.dupont@bnf.fr",
    "department":"Direction","is_encrypted":true,"is_screen_lock":true,
    "tags":["vip","c-suite","corporate"]
  }' 8029 >/dev/null
  log "iOS device enrolled: iPhone 15 Pro (CEO)"
  pause

  api POST "/api/v1/mobile/devices" '{
    "device_name":"Android BYOD — Trader","device_type":"smartphone",
    "platform":"android","os_version":"13.0","model":"Samsung Galaxy S23",
    "manufacturer":"Samsung","ownership":"byod",
    "owner_name":"Sophie Martin","owner_email":"s.martin@bnf.fr",
    "department":"Trading","is_encrypted":false,"is_screen_lock":true,
    "tags":["byod","trading"]
  }' 8029 >/dev/null
  log "Android BYOD enrolled: Galaxy S23 (Trader) — NON CHIFFRÉ"
  pause

  # Domain 23: SCS
  step "Domain 23 · Supply Chain Security"
  api POST "/api/v1/scs/vendors" '{
    "name":"OpenSSL Foundation","vendor_type":"open_source","risk_tier":1,
    "description":"Critical crypto library used across all banking systems"
  }' 8027 >/dev/null
  log "Vendor: OpenSSL Foundation (Tier 1 — critique)"
  pause

  api POST "/api/v1/scs/alerts" '{
    "alert_type":"new_vulnerability","severity":"critical",
    "title":"Backdoor in xz-utils (CVE-2024-3094)",
    "description":"Supply chain attack in xz-utils 5.6.0-5.6.1. Verify all Linux deployments.",
    "source":"NVD","tags":["supply-chain","backdoor","xz","linux"]
  }' 8027 >/dev/null
  log "Alert SCS: Backdoor xz-utils (CVE-2024-3094)"
  pause

  # Domain 24: OT/ICS
  step "Domain 24 · OT/ICS Security"
  api POST "/api/v1/ot/zones" '{
    "name":"Data Center Control Zone","zone_type":"control",
    "is_air_gapped":false,"firewall_present":true,"ids_present":true,
    "network_ranges":["172.16.100.0/24"]
  }' 8028 >/dev/null
  log "Zone OT: Data Center Control Zone"
  pause

  api POST "/api/v1/ot/assets" '{
    "name":"DC HVAC Controller","asset_type":"plc","vendor":"Siemens",
    "model":"S7-1500","ip_address":"172.16.100.10","purdue_level":1,
    "criticality":"critical","is_internet_facing":false,
    "protocols":["Modbus","S7comm"],"tags":["hvac","datacenter"]
  }' 8028 >/dev/null
  log "Asset OT: Siemens S7-1500 HVAC (Purdue L1, critique)"
  pause

  # Domain 26: DSPM
  step "Domain 26 · Data Security Posture Management"
  api POST "/api/v1/dspm/data-stores" '{
    "name":"Customer PII Database","store_type":"database",
    "cloud_provider":"on_premise","endpoint":"db-cust-01.bnf.internal:5432",
    "sensitivity_level":"restricted","data_categories":["pii","financial","pci"],
    "is_encrypted":true,"is_access_controlled":true,"is_monitored":true,
    "owner":"DBA Team","department":"IT","tags":["gdpr","pci-dss"]
  }' 8030 >/dev/null
  log "DSPM: Customer PII Database (restricted, chiffrée)"
  pause

  api POST "/api/v1/dspm/data-stores" '{
    "name":"Legacy Transaction Archive S3","store_type":"object_storage",
    "cloud_provider":"aws","region":"eu-west-3",
    "endpoint":"s3://bnf-txn-archive-prod",
    "sensitivity_level":"confidential","data_categories":["financial","pci"],
    "is_encrypted":false,"is_access_controlled":false,"is_monitored":false,
    "owner":"Archive Team","department":"Operations",
    "tags":["legacy","unencrypted","high-risk"]
  }' 8030 >/dev/null
  log "DSPM: Archive S3 legacy — NON CHIFFRÉ, PAS DE CONTRÔLE D'ACCÈS"
  pause

  printf "\n"
  section "✅ Demo Data Seeded"
  printf "\n"
  log "4 assets critiques enregistrés"
  log "3 IOCs ingérés (APT29 C2, phishing, LockBit)"
  log "2 CVE critiques (CVSS 10.0 + 9.6)"
  log "1 incident de mouvement latéral"
  log "2 devices mobiles (1 BYOD non chiffré)"
  log "Alerte supply chain: backdoor xz-utils"
  log "HVAC Controller OT/ICS (Purdue L1)"
  log "2 data stores DSPM (1 non sécurisé)"
  printf "\n"
}

# ─── Scenario: APT29 Attack ───────────────────────────────
cmd_scenario_breach() {
  banner
  section "SCENARIO: Attaque APT29 sur Banque Nationale de France"
  printf "\n"
  printf "  ${YELLOW}Scénario nation-state sur 72h spanning 10 domaines de sécurité${RESET}\n\n"
  press_enter

  # Phase 1
  section "Phase 1 · Initial Access — Spear Phishing  (T-72h)"
  printf "\n"
  info "APT29 envoie un email ciblé à la trader Sophie Martin"
  info "Pièce jointe: security_patch_Q1_2024.iso (banking trojan)"
  printf "\n"
  pause

  step "SIEM détecte la livraison de l'email suspect..."
  api POST "/api/v1/siem/events" '{
    "source":"email_gateway","event_type":"email_received","severity":"medium",
    "title":"Email suspect avec pièce jointe .iso",
    "raw_log":"{\"from\":\"it-support@bnf-secure.com\",\"attachment\":\"security_patch.iso\"}",
    "source_ip":"185.220.101.47","tags":["phishing","iso","apt29-ioc"]
  }' 8008 >/dev/null
  log "SIEM: Email suspect loggé — source IP = IOC APT29"
  pause

  step "UEBA détecte une déviation de baseline..."
  api POST "/api/v1/ueba/alerts" '{
    "entity_type":"user","entity_id":"sophie.martin","risk_score":72,
    "alert_type":"anomalous_download",
    "title":"Téléchargement ISO anormal — 1ère fois en 18 mois",
    "description":"650MB ISO file. Déviation 4.2σ par rapport au baseline.",
    "tags":["anomaly","iso-download","4sigma"]
  }' 8009 >/dev/null
  log "UEBA: Déviation 4.2σ — téléchargement ISO (première fois)"
  pause

  printf "\n  ${YELLOW}  IOC Match: 185.220.101.47 ↔ APT29 C2 (ANSSI Intel)${RESET}\n"
  printf "  ${RED}  HAUTE CONFIANCE: Acteur nation-state confirmé${RESET}\n"
  pause

  press_enter

  # Phase 2
  section "Phase 2 · Execution & Persistence  (T-70h)"
  printf "\n"
  info "L'utilisateur ouvre l'ISO. Banking trojan s'exécute."
  info "Connexion C2 établie vers 185.220.101.47"
  printf "\n"
  pause

  step "Mobile Security — MitM sur le téléphone du trader..."
  api POST "/api/v1/mobile/threats" '{
    "threat_type":"man_in_the_middle","severity":"high",
    "title":"Rogue AP — SSL Strip sur appli bancaire",
    "description":"Téléphone connecté à un faux point d'\''accès WiFi. Tentative de vol de credentials bancaires.",
    "detected_by":"MTD Engine","tags":["mitm","ssl-strip","credentials","byod"]
  }' 8029 >/dev/null
  log "Mobile MTD: Attaque MitM sur device trader — credentials compromis"
  pause

  step "Incident Response — Création incident critique..."
  api POST "/api/v1/ir/incidents" '{
    "title":"APT29 Active Intrusion — BNF Trading Systems",
    "severity":"critical","incident_type":"apt",
    "description":"Acteur nation-state (APT29) a établi un foothold via spear-phishing. Communications C2 confirmées vers 185.220.101.47. Anomalies UEBA et MitM mobile indiquent une attaque coordonnée.",
    "affected_systems":["Trading Workstation FX-01","Sophie Martin Laptop"],
    "detected_by":"SOC Tier 2",
    "tags":["apt29","nation-state","critical","trading"]
  }' 8026 >/dev/null
  log "IR: Incident CRITIQUE créé — APT29 Active Intrusion"
  pause

  press_enter

  # Phase 3
  section "Phase 3 · Lateral Movement  (T-48h)"
  printf "\n"
  info "Attaquant se déplace de FX-01 vers le Core Banking System"
  info "Credentials volés via MitM sur le mobile du trader"
  printf "\n"
  pause

  step "PAM: Accès anormal avec compte de service..."
  api POST "/api/v1/pam/alerts" '{
    "session_type":"rdp","account":"svc_corebanking_admin",
    "source_ip":"10.0.3.101","alert_type":"anomalous_access","severity":"critical",
    "title":"Compte service utilisé interactivement depuis poste trading",
    "description":"svc_corebanking_admin accède au Core Banking via RDP depuis FX-01 à 02h47 UTC. Les comptes de service ne doivent jamais être utilisés interactivement.",
    "tags":["credential-abuse","lateral-movement","service-account","02h47"]
  }' 8007 >/dev/null
  log "PAM CRITIQUE: Mouvement latéral via compte service — 02h47 UTC"
  pause

  step "OT/ICS: Sonde non autorisée sur contrôleur HVAC..."
  api POST "/api/v1/ot/events" '{
    "event_type":"unauthorized_access","severity":"critical",
    "title":"Poste compromis sonde le contrôleur HVAC Modbus",
    "description":"FX-01 (10.0.3.101) a envoyé 847 requêtes Modbus READ au contrôleur HVAC. Risque de sabotage physique du datacenter.",
    "source_ip":"10.0.3.101","tags":["modbus","hvac","physical-risk","apt29"]
  }' 8028 >/dev/null
  log "OT CRITIQUE: FX-01 → HVAC PLC (risque sabotage physique datacenter!)"
  pause

  press_enter

  # Phase 4
  section "Phase 4 · Data Exfiltration Attempt  (T-24h)"
  printf "\n"
  info "L'attaquant cible la base de données clients et l'archive transactions"
  printf "\n"
  pause

  step "DLP: Extraction massive de données PCI détectée..."
  api POST "/api/v1/dlp/alerts" '{
    "rule_name":"PCI Data Bulk Export","severity":"critical",
    "title":"Export massif PCI — 2.1M enregistrements",
    "description":"svc_corebanking_admin a exécuté SELECT * sur card_transactions. 2.1M lignes. Données staging avant tentative d'\''exfiltration.",
    "source_ip":"10.0.3.101","data_classification":"pci","record_count":2100000,
    "tags":["pci","exfiltration","bulk-export","apt29"]
  }' 8021 >/dev/null
  log "DLP CRITIQUE: 2.1M records PCI — tentative d'extraction BLOQUÉE"
  pause

  step "Network Security: Communication C2 bloquée..."
  api POST "/api/v1/netsec/events" '{
    "event_type":"c2_communication","severity":"critical",
    "title":"Egress C2 vers 185.220.101.47 BLOQUÉ",
    "description":"Pare-feu a bloqué la tentative d'\''exfiltration vers le C2 APT29. 847MB en attente d'\''upload. Attaque contenue.",
    "source_ip":"10.0.3.101","destination_ip":"185.220.101.47",
    "bytes_attempted":887558144,"action":"blocked",
    "tags":["c2","blocked","apt29","exfiltration"]
  }' 8022 >/dev/null
  log "NetSec: Exfiltration BLOQUÉE au pare-feu — 847MB sauvegardés"
  pause

  step "DSPM: Escalade de risque sur les data stores..."
  log "DSPM: Archive S3 legacy (non chiffrée) — risque breach CRITIQUE"
  log "DSPM: Base PCI clients — tentative d'accès non autorisé détectée"
  pause

  press_enter

  # Phase 5
  section "Phase 5 · SOAR Orchestrated Response  (T: MAINTENANT)"
  printf "\n"
  info "Le SOAR orchestre automatiquement la réponse sur tous les domaines"
  printf "\n"
  pause

  step "SOAR: Exécution playbook 'Banking Ransomware Response'..."
  pause
  log "  → Isolation des postes compromis (FX-01, laptop Sophie Martin)"
  pause
  log "  → Révocation du compte svc_corebanking_admin"
  pause
  log "  → Blocage de 185.220.101.47 sur tous les pare-feux"
  pause
  log "  → MDM remote wipe du device BYOD compromis"
  pause
  log "  → Notification CERT-FR (obligation réglementaire)"
  pause
  log "  → Activation du Plan de Continuité d'Activité (PCA)"
  pause
  log "  → Collecte d'evidence forensique (dump mémoire)"
  pause

  step "Risk Management: Évaluation d'impact..."
  api POST "/api/v1/risk/assessments" '{
    "name":"APT29 Attack Impact Assessment",
    "risk_type":"cyber","severity":"critical",
    "title":"Attaque nation-state — Systèmes trading compromis",
    "description":"APT29 a accédé aux systèmes de trading. Tentative d'\''exfiltration bloquée. Exposition estimée: 4.2M€ (amendes RGPD/PCI + réputation).",
    "financial_impact":4200000,
    "tags":["apt29","rgpd","pci","réglementaire"]
  }' 8023 >/dev/null
  log "Risk: Exposition estimée 4.2M€ (amendes réglementaires)"
  pause

  printf "\n"
  section "🛡️  Attaque Contenue — Résumé"
  printf "\n"
  printf "  ${BOLD}Vecteur d'attaque:${RESET}      Spear-phishing → ISO → Banking Trojan\n"
  printf "  ${BOLD}Acteur:${RESET}                APT29 (Cozy Bear) — État nation\n"
  printf "  ${BOLD}Durée:${RESET}                 72h (accès initial → confinement)\n"
  printf "  ${BOLD}Systèmes compromis:${RESET}    2 postes, 1 mobile BYOD\n"
  printf "  ${BOLD}Données menacées:${RESET}      2.1M records PCI (exfiltration BLOQUÉE)\n"
  printf "  ${BOLD}Risque OT:${RESET}             Contrôleur HVAC sondé (aucun dégât)\n"
  printf "  ${BOLD}Statut:${RESET}                ${GREEN}CONTENU${RESET}\n"
  printf "\n"
  printf "  ${BOLD}Domaines impliqués:${RESET}\n"
  printf "  ${DIM}  SIEM · UEBA · TI · IR · PAM · Mobile · OT · DLP · DSPM · NetSec · SOAR · Risk${RESET}\n"
  printf "\n"
}

# ─── Stats Dashboard ───────────────────────────────────────
cmd_stats() {
  banner
  section "Live Stats — Domaines Actifs"
  printf "\n"

  for entry in "ir:8026:/api/v1/ir/stats" "mobile:8029:/api/v1/mobile/stats" "ot:8028:/api/v1/ot/stats" "scs:8027:/api/v1/scs/stats" "dspm:8030:/api/v1/dspm/stats" "asset:8006:/api/v1/assets/stats"; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    port="${rest%%:*}"
    path="${rest#*:}"
    label=$(get_label "$name")

    printf "\n  ${BOLD}${WHITE}%s${RESET} ${DIM}(port %s)${RESET}\n" "$label" "$port"
    local result
    result=$(curl -sf --max-time 3 "${BASE_URL}:${port}${path}" 2>/dev/null || printf '{"error":"unavailable"}')
    printf '%s' "$result" | python3 -m json.tool 2>/dev/null | head -15 | sed 's/^/    /'
    pause
  done
  printf "\n"
}

# ─── Service Details ──────────────────────────────────────
cmd_service_details() {
  banner
  section "Service Details"
  printf "\n"

  local i=1
  local svc_list="tenant identity audit notification collector asset pam siem ueba ti vuln attackpath knowledgegraph soar dashboard copilot apifw compliance easm fraud dlp netsec risk iga cspm ir scs ot mobile dspm"
  for svc in $svc_list; do
    local port
    port=$(get_port "$svc")
    local label
    label=$(get_label "$svc")
    printf "  ${CYAN}%2d)${RESET} %-30s ${DIM}(port %s)${RESET}\n" "$i" "$label" "$port"
    i=$((i + 1))
  done

  printf "\n  ${BOLD}Sélectionnez un service (1-30): ${RESET}"
  read -r sel

  if printf '%s' "$sel" | grep -qE '^[0-9]+$' && [ "$sel" -ge 1 ] && [ "$sel" -le 30 ]; then
    local idx=1
    for svc in $svc_list; do
      if [ "$idx" -eq "$sel" ]; then
        local port
        port=$(get_port "$svc")
        local label
        label=$(get_label "$svc")
        printf "\n  ${BOLD}%s${RESET} — Port %s\n" "$label" "$port"
        local health
        health=$(curl -sf --max-time 3 "${BASE_URL}:${port}/health" 2>/dev/null || printf '{"error":"unavailable"}')
        local status
        status=$(printf '%s' "$health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || printf "unavailable")
        printf "  Health: %s\n" "$status"
        printf "  URL: %s:%s/api/v1/%s\n" "$BASE_URL" "$port" "$svc"
        break
      fi
      idx=$((idx + 1))
    done
  fi
}

# ─── API Explorer ─────────────────────────────────────────
cmd_api_explorer() {
  banner
  section "API Explorer"
  printf "\n"
  printf "  ${BOLD}Port: ${RESET}"; read -r port
  printf "  ${BOLD}Path (ex: /api/v1/ir/stats): ${RESET}"; read -r path
  printf "  ${BOLD}Method [GET]: ${RESET}"; read -r method
  method="${method:-GET}"

  local body=""
  if [ "$method" != "GET" ]; then
    printf "  ${BOLD}Body (JSON): ${RESET}"; read -r body
  fi

  printf "\n"
  result=$(api "$method" "$path" "$body" "$port")
  pretty_json "$result"
}

# ─── Main Menu ────────────────────────────────────────────
cmd_menu() {
  while true; do
    banner
    printf "  ${BOLD}DEMO MENU${RESET}\n\n"
    printf "  ${CYAN}1)${RESET} Health Check        — Vérifier les 26 services\n"
    printf "  ${CYAN}2)${RESET} Seed Demo Data      — Peupler le scénario BNF\n"
    printf "  ${CYAN}3)${RESET} Scénario APT29      — Attaque nation-state (72h)\n"
    printf "  ${CYAN}4)${RESET} Live Stats          — Statistiques temps réel\n"
    printf "  ${CYAN}5)${RESET} Service Details     — Inspecter un domaine\n"
    printf "  ${CYAN}6)${RESET} API Explorer        — Appel API personnalisé\n"
    printf "  ${CYAN}q)${RESET} Quitter\n"
    printf "\n  ${BOLD}Option: ${RESET}"
    read -r choice

    case "$choice" in
      1) cmd_health; press_enter ;;
      2) cmd_seed; press_enter ;;
      3) cmd_scenario_breach; press_enter ;;
      4) cmd_stats; press_enter ;;
      5) cmd_service_details; press_enter ;;
      6) cmd_api_explorer; press_enter ;;
      q|Q) printf "\n  ${DIM}Au revoir.${RESET}\n\n"; exit 0 ;;
      *) warn "Option invalide" ;;
    esac
  done
}

# ─── Entrypoint ───────────────────────────────────────────
main() {
  local cmd="${1:---menu}"
  case "$cmd" in
    --health|-h)   cmd_health ;;
    --seed|-s)     cmd_seed ;;
    --scenario|-a) cmd_scenario_breach ;;
    --stats)       cmd_stats ;;
    *)             cmd_menu ;;
  esac
}

main "${1:-}"
