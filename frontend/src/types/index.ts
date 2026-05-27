// ─── API Envelope ────────────────────────────────────────────
export interface ApiResponse<T> {
  data: T
  meta?: {
    page: number
    limit: number
    total: number
    tenant_id?: string
  }
  error: null | { code: string; message: string; details?: unknown }
}

export interface PageMeta {
  page: number
  limit: number
  total: number
}

// ─── SIEM ────────────────────────────────────────────────────
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Outcome = 'success' | 'failure' | 'unknown'

export interface SIEMAlert {
  alert_id: string
  rule_id: string
  rule_name: string
  severity: Severity
  category: string
  mitre_tactic?: string
  mitre_technique?: string
  entity_type: string
  entity_value: string
  ip_source?: string
  ip_destination?: string
  title: string
  description: string
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive'
  event_time: string
  created_at: string
  updated_at: string
}

export interface SIEMStats {
  total_alerts: number
  open_alerts: number
  critical_alerts: number
  high_alerts: number
  rules_active: number
  events_last_24h: number
  mttr_minutes: number
}

// ─── Assets ──────────────────────────────────────────────────
export interface Asset {
  id: string
  name: string
  asset_type: string
  ip_address?: string
  hostname?: string
  mac_address?: string
  os?: string
  os_version?: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  environment: string
  department?: string
  owner?: string
  risk_score: number
  vulnerability_count: number
  last_seen_at: string
  created_at: string
}

export interface AssetStats {
  total: number
  critical: number
  high_risk: number
  online: number
  avg_risk_score: number
}

// ─── Incident Response ───────────────────────────────────────
export interface Incident {
  id: string
  incident_number: string
  title: string
  description?: string
  severity: Severity
  status: 'open' | 'in_progress' | 'contained' | 'eradicated' | 'recovered' | 'closed'
  incident_type: string
  affected_assets?: string[]
  assigned_to?: string
  lead_analyst?: string
  reported_by?: string
  detected_at: string
  contained_at?: string
  resolved_at?: string
  created_at: string
  updated_at: string
  mttd_minutes?: number
  mttr_minutes?: number
}

export interface IRStats {
  open_incidents: number
  in_progress: number
  critical_open: number
  avg_mttd_hours: number
  avg_mttr_hours: number
  resolved_last_30d: number
}

// ─── Mobile ──────────────────────────────────────────────────
export interface MobDevice {
  id: string
  device_name: string
  device_type: string
  platform: 'ios' | 'android' | 'windows'
  os_version?: string
  model?: string
  manufacturer?: string
  enrollment_status: 'enrolled' | 'pending' | 'unenrolled' | 'retired'
  ownership: 'corporate' | 'byod' | 'cope'
  owner_name?: string
  owner_email?: string
  department?: string
  is_encrypted: boolean
  is_jailbroken: boolean
  is_compliant: boolean
  mdm_profile_installed: boolean
  risk_score: number
  last_seen_at: string
}

export interface MobileStats {
  total_devices: number
  enrolled: number
  non_compliant: number
  jailbroken: number
  unencrypted: number
  byod_count: number
}

// ─── DSPM ────────────────────────────────────────────────────
export interface DSPMDataStore {
  id: string
  name: string
  store_type: string
  cloud_provider?: string
  region?: string
  sensitivity_level: 'public' | 'internal' | 'confidential' | 'restricted' | 'top_secret'
  data_categories: string[]
  is_encrypted: boolean
  is_access_controlled: boolean
  is_monitored: boolean
  owner?: string
  department?: string
  risk_score: number
  risk_level: string
  open_finding_count: number
  last_scanned_at?: string
  created_at: string
}

export interface DSPMFinding {
  id: string
  data_store_id: string
  data_store_name: string
  title: string
  finding_type: string
  severity: Severity
  status: 'open' | 'in_progress' | 'resolved' | 'accepted'
  location_path: string
  record_count: number
  is_public_accessible: boolean
  compliance_violations: string[]
  created_at: string
}

export interface DSPMStats {
  total_stores: number
  sensitive_stores: number
  unencrypted_stores: number
  open_findings: number
  critical_findings: number
  records_at_risk: number
}

// ─── Threat Intelligence ─────────────────────────────────────
export interface IOC {
  id: string
  ioc_type: 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cve'
  value: string
  severity: Severity
  confidence: number
  source: string
  tags: string[]
  description?: string
  is_active: boolean
  first_seen_at: string
  last_seen_at: string
}

export interface TIStats {
  total_iocs: number
  active_iocs: number
  critical_iocs: number
  matched_events: number
}

// ─── Vulnerabilities ─────────────────────────────────────────
export interface Vulnerability {
  id: string
  cve_id: string
  title: string
  description?: string
  severity: Severity
  cvss_score: number
  cvss_vector?: string
  affected_component: string
  affected_versions?: string
  patch_available: boolean
  remediation_status: 'open' | 'in_progress' | 'resolved' | 'accepted_risk' | 'wont_fix'
  asset_count: number
  exploit_available: boolean
  exploit_in_wild: boolean
  first_seen_at: string
  updated_at: string
}

export interface VulnStats {
  total: number
  open: number
  critical: number
  patch_available: number
  exploit_in_wild: number
  avg_cvss: number
}

// ─── OT / ICS ────────────────────────────────────────────────
export interface OTAsset {
  id: string
  name: string
  asset_type: string
  vendor?: string
  model?: string
  firmware_version?: string
  purdue_level: number
  zone?: string
  protocol: string
  ip_address?: string
  mac_address?: string
  is_internet_facing: boolean
  affects_safety: boolean
  is_patched: boolean
  risk_score: number
  last_seen_at: string
}

export interface OTEvent {
  id: string
  title: string
  severity: Severity
  source: string
  asset_id?: string
  asset_name?: string
  created_at: string
}

export interface OTStats {
  total_assets: number
  internet_facing: number
  safety_critical: number
  unpatched: number
}

// ─── Dashboard ───────────────────────────────────────────────
export interface DashboardStats {
  security_score: number
  active_incidents: number
  critical_alerts: number
  open_vulnerabilities: number
  assets_at_risk: number
  compliance_score: number
  events_last_24h: number
  threats_blocked: number
}

export interface PlatformOverview {
  // SIEM
  open_alerts: number
  critical_alerts: number
  // UEBA
  active_anomalies: number
  high_risk_entities: number
  // TI
  active_iocs: number
  ioc_hits_today: number
  // Vuln
  critical_vulns: number
  sla_breached_vulns: number
  // Attack Path
  attack_paths: number
  choke_points: number
  // SOAR
  open_incidents: number
  sla_breached_incidents: number
  // KG
  total_entities: number
  // Platform risk
  overall_risk_score: number
  generated_at: string
}

export interface KPIPoint {
  timestamp: string
  value: number
}

// ─── API Gateway ─────────────────────────────────────────────
export interface APIKey {
  id: string
  tenant_id: string
  name: string
  key_prefix: string
  description?: string
  scopes: string[]
  rate_limit_rpm: number
  rate_limit_rpd: number
  is_active: boolean
  last_used_at?: string
  expires_at?: string
  created_by?: string
  created_at: string
  updated_at: string
  plain_key?: string // only at creation/rotation
}

export interface Webhook {
  id: string
  tenant_id: string
  name: string
  url: string
  events: string[]
  is_active: boolean
  failure_count: number
  last_triggered_at?: string
  last_status_code?: number
  created_by?: string
  created_at: string
  updated_at: string
}

export interface WebhookDelivery {
  id: string
  tenant_id: string
  webhook_id: string
  event_type: string
  payload?: Record<string, unknown>
  response_status?: number
  response_body?: string
  attempt: number
  success: boolean
  delivered_at?: string
  created_at: string
}

export interface EndpointStat {
  endpoint: string
  method: string
  count: number
  avg_latency_ms: number
  error_rate: number
}

export interface APIFWStats {
  active_keys: number
  total_requests_today: number
  active_webhooks: number
  delivery_success_rate: number
  top_endpoints: EndpointStat[]
}
