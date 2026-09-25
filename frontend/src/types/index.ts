// Types mirroring the backend's Go models, field for field.
//
// Every interface here is transcribed from a struct's `json:` tags — not from
// what a screen would like to receive. A field that is absent from the Go
// struct is absent here, so a page that reads one fails to compile instead of
// rendering an empty cell.
//
// Two Go conventions matter when reading this file:
//   - a pointer or `omitempty` field may be missing from the payload → `?`
//   - a nil slice marshals to `null`, not `[]` → `| null` on anything a
//     component maps over. The guard is not optional: `.map` on null throws.

// ─── API envelope ────────────────────────────────────────────
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

export type Severity = 'low' | 'medium' | 'high' | 'critical'

/** A `map[string]int` breakdown. The backend builds these with make(), so the
 *  map itself is present, but never assume a given key is. */
export type Breakdown = Record<string, number>

// ─── SIEM — services/siem/internal/model ─────────────────────
export interface SIEMAlert {
  alert_id: string
  tenant_id: string
  rule_id: string
  rule_name: string
  severity: Severity
  category: string
  mitre_tactic?: string
  mitre_technique?: string
  entity_type: string
  entity_value: string
  source_event_id?: string
  user_id?: string
  ip_source?: string
  ip_destination?: string
  title: string
  description: string
  raw_evidence?: string
  dedup_key: string
  event_time: string
  detected_at: string
  event_count: number
  risk_score: number
  /** alert_metadata.status; the column defaults to 'open', so an alert with
   *  no metadata row yet is open. */
  status?: 'open' | 'acknowledged' | 'in_progress' | 'closed' | 'false_positive' | 'suppressed'
  assignee_id?: string
  case_id?: string
  notes?: string
}

export interface RuleStat {
  rule_id: string
  rule_name: string
  count: number
}

export interface SIEMStats {
  total: number
  open: number
  by_severity: Breakdown
  by_category: Breakdown
  top_rules: RuleStat[] | null
  fired_last_24h: number
  fired_last_7d: number
}

// ─── Assets — services/asset/internal/model ──────────────────
export interface Asset {
  id: string
  tenant_id: string
  name: string
  hostname?: string
  fqdn?: string
  ip_addresses: string[] | null
  mac_addresses: string[] | null
  asset_type: string
  os?: string
  os_version?: string
  /** 1 low · 2 medium · 3 high · 4 critical — an int in the service, not a word. */
  criticality: number
  status: string
  environment: string
  owner_id?: string
  department?: string
  location?: string
  business_service?: string
  is_cbs_connected: boolean
  is_swift_connected: boolean
  is_pci_scope: boolean
  risk_score: number
  vuln_critical: number
  vuln_high: number
  vuln_medium: number
  vuln_low: number
  tags: string[] | null
  metadata?: Record<string, unknown>
  discovered_by: string
  last_seen_at?: string
  first_seen_at: string
  created_at: string
  updated_at: string
}

export interface AssetStats {
  total: number
  by_type: Breakdown
  by_criticality: Breakdown
  by_status: Breakdown
  high_risk: number
  cbs_connected: number
  swift_connected: number
  pci_scope: number
  never_seen: number
  stale: number
  discovery_queue: number
}

// ─── Incident response — services/ir/internal/model ──────────
export interface Incident {
  id: string
  tenant_id: string
  incident_number: string
  title: string
  description?: string
  incident_type: string
  severity: Severity
  status: string
  priority: number
  source?: string
  source_ref?: string
  affected_systems: string[] | null
  affected_users: string[] | null
  affected_data: string[] | null
  is_contained: boolean
  data_exfiltrated: boolean
  estimated_impact?: string
  attack_vector?: string
  mitre_tactics: string[] | null
  mitre_techniques: string[] | null
  lead_id?: string
  lead_name?: string
  team_members: string[] | null
  playbook_id?: string
  detected_at: string
  reported_at?: string
  contained_at?: string
  eradicated_at?: string
  recovered_at?: string
  closed_at?: string
  mttd_minutes?: number
  mttr_minutes?: number
  requires_notification: boolean
  notification_sent_at?: string
  tags: string[] | null
  created_by?: string
  created_at: string
  updated_at: string
  task_count?: number
  timeline_count?: number
  evidence_count?: number
}

export interface IRStats {
  total_incidents: number
  open_incidents: number
  critical_incidents: number
  avg_mttd_minutes: number
  avg_mttr_minutes: number
  by_status: Breakdown
  by_severity: Breakdown
  by_type: Breakdown
  recent_incidents: Incident[] | null
  total_playbooks: number
  total_evidence: number
  require_notification: number
}

// ─── Mobile — services/mobile/internal/model ─────────────────
export interface MobDevice {
  id: string
  tenant_id: string
  device_name: string
  device_type: string
  platform: string
  os_version?: string
  model?: string
  manufacturer?: string
  serial_number?: string
  enrollment_status: string
  enrollment_date: string
  mdm_profile_installed: boolean
  ownership: string
  owner_name?: string
  owner_id?: string
  owner_email?: string
  department?: string
  is_jailbroken: boolean
  is_rooted: boolean
  is_encrypted: boolean
  is_screen_lock: boolean
  is_compliant: boolean
  compliance_issues: string[] | null
  risk_score: number
  risk_level: string
  last_location?: string
  last_seen_at: string
  last_checkin_at: string
  last_ip?: string
  carrier?: string
  tags: string[] | null
  notes?: string
  created_at: string
  updated_at: string
  app_count?: number
  threat_count?: number
}

export interface MobileStats {
  total_devices: number
  enrolled_devices: number
  non_compliant_devices: number
  jailbroken_devices: number
  high_risk_devices: number
  total_apps: number
  blocklisted_apps: number
  vulnerable_apps: number
  active_threats: number
  critical_threats: number
  pending_actions: number
  devices_by_platform: Breakdown
  devices_by_ownership: Breakdown
  threats_by_severity: Breakdown
  threats_by_type: Breakdown
}

// ─── DSPM — services/dspm/internal/model ─────────────────────
export interface DSPMDataStore {
  id: string
  tenant_id: string
  name: string
  store_type: string
  cloud_provider?: string
  region?: string
  endpoint?: string
  sensitivity_level: string
  data_categories: string[] | null
  is_encrypted: boolean
  is_access_controlled: boolean
  is_monitored: boolean
  is_backup_enabled: boolean
  owner?: string
  department?: string
  risk_score: number
  risk_level: string
  last_scanned_at?: string
  scan_status: string
  tags: string[] | null
  created_at: string
  updated_at: string
  finding_count?: number
  open_finding_count?: number
}

export interface DSPMFinding {
  id: string
  tenant_id: string
  data_store_id: string
  scan_job_id?: string
  finding_type: string
  severity: Severity
  status: string
  location_path?: string
  location_field?: string
  record_count: number
  is_public_accessible: boolean
  is_encrypted: boolean
  title: string
  description?: string
  remediation?: string
  compliance_violations: string[] | null
  resolved_by?: string
  resolved_at?: string
  tags: string[] | null
  detected_at: string
  created_at: string
  updated_at: string
  remediation_count?: number
}

export interface DSPMStats {
  total_data_stores: number
  unencrypted_stores: number
  publicly_accessible: number
  high_risk_stores: number
  total_findings: number
  open_findings: number
  critical_findings: number
  pii_exposures: number
  pci_exposures: number
  total_scans: number
  active_scans: number
  open_remediations: number
  overdue_remediations: number
  stores_by_type: Breakdown
  stores_by_risk: Breakdown
  findings_by_type: Breakdown
  findings_by_severity: Breakdown
}

// ─── Threat intelligence — services/ti/internal/model ────────
export interface IOC {
  id: string
  tenant_id: string
  feed_id?: string
  ioc_type: string
  value: string
  normalized: string
  tlp: number
  confidence: number
  severity: Severity
  is_active: boolean
  mitre_tactic?: string
  mitre_technique?: string
  threat_actor?: string
  malware_family?: string
  campaign?: string
  valid_from: string
  valid_until?: string
  hit_count: number
  last_hit_at?: string
  tags: string[] | null
  description?: string
  created_at: string
  updated_at: string
}

export interface TIStats {
  total_iocs: number
  active_iocs: number
  total_feeds: number
  enabled_feeds: number
  hits_last_24h: number
  hits_last_7d: number
  by_type: Breakdown
  by_severity: Breakdown
  top_iocs: IOC[] | null
  threat_actors: number
  banking_threats: number
}

// ─── Vulnerabilities — services/vuln/internal/model ──────────
export interface Vulnerability {
  id: string
  tenant_id: string
  cve_id?: string
  title: string
  description?: string
  cvss_score: number
  cvss_vector?: string
  cvss_severity: string
  is_exploited: boolean
  exploit_available: boolean
  epss_score: number
  cwe_id?: string
  cwe_name?: string
  mitre_technique?: string
  affected_products: string[] | null
  patch_available: boolean
  patch_url?: string
  published_at?: string
  modified_at?: string
  nvd_url?: string
  references: string[] | null
  tags: string[] | null
  created_at: string
  updated_at: string
}

export interface ExposureScore {
  asset_id: string
  total_findings: number
  open_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  avg_cvss: number
  max_cvss: number
  exposure_score: number
  sla_breached: number
  has_kev: boolean
}

export interface VulnStats {
  total_vulns: number
  total_findings: number
  open_findings: number
  sla_breached: number
  kev_findings: number
  avg_cvss: number
  by_severity: Breakdown
  by_status: Breakdown
  top_vulnerable_assets: ExposureScore[] | null
}

// ─── OT / ICS — services/ot/internal/model ───────────────────
export interface OTAsset {
  id: string
  tenant_id: string
  name: string
  description?: string
  asset_type: string
  vendor?: string
  model?: string
  firmware_version?: string
  serial_number?: string
  ip_address?: string
  mac_address?: string
  protocol: string[] | null
  site?: string
  zone?: string
  purdue_level: number
  risk_score: number
  risk_level: string
  is_internet_facing: boolean
  is_patched: boolean
  last_patched_at?: string
  is_active: boolean
  criticality: string
  install_date?: string
  end_of_life_date?: string
  tags: string[] | null
  created_at: string
  updated_at: string
  vuln_count?: number
  event_count?: number
}

export interface OTEvent {
  id: string
  tenant_id: string
  asset_id?: string
  zone_id?: string
  event_type: string
  severity: Severity
  status: string
  title: string
  description?: string
  source_ip?: string
  dest_ip?: string
  protocol?: string
  detected_by?: string
  detection_rule?: string
  acknowledged_by?: string
  acknowledged_at?: string
  resolved_by?: string
  resolved_at?: string
  event_time: string
  tags: string[] | null
  created_at: string
  updated_at: string
}

export interface OTStats {
  total_assets: number
  active_assets: number
  critical_assets: number
  internet_facing_assets: number
  unpatched_assets: number
  total_zones: number
  total_vulnerabilities: number
  critical_vulns: number
  safety_impact_vulns: number
  open_events: number
  critical_events: number
  anomalous_communications: number
  pending_patches: number
  assets_by_type: Breakdown
  assets_by_purdue: Breakdown
  events_by_severity: Breakdown
  vulns_by_severity: Breakdown
}

// ─── Attack paths — services/attackpath/internal/model ───────
export interface AttackNode {
  id: string
  tenant_id: string
  ref_id: string
  node_type: string
  label: string
  risk_score: number
  criticality: number
  is_internet_facing: boolean
  is_privileged: boolean
  is_critical_system: boolean
  is_compromised: boolean
  has_critical_vuln: boolean
  has_known_exploit: boolean
  open_vuln_count: number
  network_zone?: string
  ip_address?: string
  hostname?: string
  last_updated_at: string
  created_at: string
}

export interface AttackEdge {
  id: string
  tenant_id: string
  source_id: string
  target_id: string
  edge_type: string
  attack_complexity: string
  privileges_required: string
  vuln_id?: string
  cve_id?: string
  mitre_technique?: string
  weight: number
  is_active: boolean
  evidence_source: string
  created_at: string
  updated_at: string
}

export interface AttackScenario {
  id: string
  tenant_id: string
  name: string
  description?: string
  entry_node_ids: string[] | null
  target_node_ids: string[] | null
  max_hops: number
  include_types: string[] | null
  status: string
  path_count: number
  shortest_path?: number
  critical_path?: number
  last_run_at?: string
  last_run_ms?: number
  risk_score: number
  created_at: string
  updated_at: string
}

export interface AttackPath {
  id: string
  tenant_id: string
  scenario_id: string
  entry_node_id: string
  target_node_id: string
  node_sequence: string[] | null
  edge_sequence: string[] | null
  hop_count: number
  path_score: number
  likelihood: number
  impact: number
  path_type: string
  has_internet_entry: boolean
  has_exploit_step: boolean
  has_priv_esc: boolean
  mitre_tactics: string[] | null
  choke_point_node_id?: string
  choke_point_edge_id?: string
  discovered_at: string
  /** Present only on /attack/paths/graph, which hydrates the hops. */
  nodes?: AttackNode[] | null
  edges?: AttackEdge[] | null
}

export interface ChokePoint {
  node_id: string
  label: string
  paths_blocked: number
  risk_reduction: number
}

export interface AttackGraphStats {
  total_nodes: number
  total_edges: number
  internet_facing_nodes: number
  critical_system_nodes: number
  compromised_nodes: number
  total_scenarios: number
  total_paths: number
  high_risk_paths: number
  shortest_path: number
  avg_path_length: number
  paths_with_exploit: number
  paths_with_priv_esc: number
}

// ─── Compliance — services/compliance/internal/model ─────────
export interface Framework {
  id: string
  tenant_id: string
  code: string
  name: string
  description?: string
  version: string
  total_controls: number
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface Control {
  id: string
  tenant_id: string
  framework_id: string
  control_id: string
  domain: string
  title: string
  description?: string
  guidance?: string
  priority: string
  is_automated: boolean
  created_at: string
}

export interface ComplianceAssessment {
  id: string
  tenant_id: string
  framework_id: string
  control_id: string
  status: string
  score: number
  evidence_refs: string[] | null
  notes?: string
  assessed_by?: string
  assessed_at?: string
  next_review_at?: string
  created_at: string
  updated_at: string
}

export interface ComplianceScore {
  framework_id: string
  framework_code: string
  framework_name: string
  total_controls: number
  assessed: number
  compliant: number
  partial: number
  non_compliant: number
  not_applicable: number
  not_assessed: number
  score_pct: number
}

export interface ComplianceRisk {
  id: string
  tenant_id: string
  title: string
  description?: string
  category: string
  likelihood: number
  impact: number
  risk_score: number
  status: string
  owner_id?: string
  related_controls: string[] | null
  mitigation_plan?: string
  residual_likelihood?: number
  residual_impact?: number
  due_date?: string
  created_at: string
  updated_at: string
}

export interface ComplianceStats {
  frameworks: ComplianceScore[] | null
  top_risks: ComplianceRisk[] | null
}

// ─── Risk (FAIR) — services/risk/internal/model ──────────────
export interface RiskAsset {
  id: string
  tenant_id: string
  name: string
  description?: string
  asset_type: string
  business_unit?: string
  owner?: string
  criticality: string
  business_value: number
  revenue_impact: number
  regulatory_impact: number
  reputational_impact: number
  inherent_risk: number
  residual_risk: number
  control_effectiveness: number
  threat_event_frequency: number
  vulnerability: number
  loss_magnitude: number
  ale: number
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface RiskScenario {
  id: string
  tenant_id: string
  name: string
  description?: string
  scenario_type: string
  threat_actor?: string
  annual_probability: number
  primary_loss: number
  secondary_loss: number
  total_loss: number
  risk_level: string
  risk_score: number
  mitigating_controls: string[] | null
  residual_probability: number
  residual_loss: number
  frameworks: string[] | null
  asset_ids: string[] | null
  status: string
  reviewed_at?: string
  created_at: string
  updated_at: string
}

export interface RiskKRI {
  id: string
  tenant_id: string
  name: string
  description?: string
  category: string
  metric_name: string
  unit: string
  current_value: number
  threshold_green?: number
  threshold_amber?: number
  status: string
  trend: string
  source_service?: string
  last_updated_at: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface RiskStats {
  total_assets: number
  total_scenarios: number
  open_treatments: number
  total_ale: number
  avg_residual_risk: number
  scenarios_by_level: Breakdown
  scenarios_by_type: Breakdown
  assets_by_criticality: Breakdown
  kris_by_status: Breakdown
  top_risky_assets: RiskAsset[] | null
  top_scenarios: RiskScenario[] | null
}

// ─── Supply chain — services/scs/internal/model ──────────────
export interface SCSVendor {
  id: string
  tenant_id: string
  name: string
  website?: string
  vendor_type: string
  risk_tier: number
  risk_score: number
  risk_level: string
  contact_name?: string
  contact_email?: string
  has_soc2: boolean
  has_iso27001: boolean
  has_pci_dss: boolean
  last_assessment_at?: string
  next_assessment_at?: string
  status: string
  tags: string[] | null
  created_at: string
  updated_at: string
  component_count?: number
  assessment_count?: number
  open_alert_count?: number
}

export interface SCSComponent {
  id: string
  tenant_id: string
  vendor_id?: string
  name: string
  version: string
  component_type: string
  ecosystem?: string
  purl?: string
  license?: string
  is_deprecated: boolean
  is_end_of_life: boolean
  has_known_vulns: boolean
  vuln_count: number
  critical_vuln_count: number
  risk_score: number
  source_repo?: string
  used_in: string[] | null
  is_direct: boolean
  tags: string[] | null
  created_at: string
  updated_at: string
}

export interface SCSAlert {
  id: string
  tenant_id: string
  vendor_id?: string
  component_id?: string
  alert_type: string
  severity: Severity
  status: string
  title: string
  description?: string
  affected_components: string[] | null
  affected_systems: string[] | null
  cve_ids: string[] | null
  advisory_url?: string
  remediation?: string
  resolved_by?: string
  resolved_at?: string
  source?: string
  detected_at: string
  tags: string[] | null
  created_at: string
  updated_at: string
}

export interface SCSStats {
  total_vendors: number
  high_risk_vendors: number
  total_components: number
  vulnerable_components: number
  eol_components: number
  total_sboms: number
  open_alerts: number
  critical_alerts: number
  pending_assessments: number
  overdue_assessments: number
  alerts_by_severity: Breakdown
  alerts_by_type: Breakdown
  vendors_by_tier: Breakdown
  top_risky_vendors: SCSVendor[] | null
  recent_alerts: SCSAlert[] | null
}

// ─── Identity — services/identity/internal/model ─────────────
export interface Identity {
  id: string
  tenant_id: string
  username: string
  email: string
  display_name?: string
  identity_type: string
  department?: string
  business_unit?: string
  manager_id?: string
  privilege_level: string
  mfa_enabled: boolean
  pam_managed: boolean
  risk_score: number
  behavior_score: number
  status: string
  last_activity?: string
  roles?: string[] | null
  created_at: string
  updated_at: string
}

// ─── Dashboard — services/dashboard/internal/model ───────────
export interface PlatformOverview {
  open_alerts: number
  critical_alerts: number
  active_anomalies: number
  high_risk_entities: number
  active_iocs: number
  ioc_hits_today: number
  critical_vulns: number
  sla_breached_vulns: number
  attack_paths: number
  choke_points: number
  open_incidents: number
  sla_breached_incidents: number
  total_entities: number
  overall_risk_score: number
  generated_at: string
}

export interface KPIPoint {
  timestamp: string
  value: number
}

// ─── Copilot — services/copilot/internal/model ───────────────
export interface CopilotSession {
  id: string
  tenant_id: string
  user_id: string
  title?: string
  context?: Record<string, unknown>
  is_active: boolean
  message_count: number
  last_message_at?: string
  created_at: string
  updated_at: string
}

export interface CopilotMessage {
  id: string
  session_id: string
  tenant_id: string
  role: string
  content: string
  tool_name?: string
  tool_input?: Record<string, unknown>
  tool_output?: Record<string, unknown>
  input_tokens: number
  output_tokens: number
  latency_ms: number
  created_at: string
}

// ─── API gateway — services/apifw/internal/model ─────────────
export interface APIKey {
  id: string
  tenant_id: string
  name: string
  key_prefix: string
  description?: string
  scopes: string[] | null
  rate_limit_rpm: number
  rate_limit_rpd: number
  is_active: boolean
  last_used_at?: string
  expires_at?: string
  created_by?: string
  created_at: string
  updated_at: string
  plain_key?: string // returned once, at creation and rotation
}

export interface Webhook {
  id: string
  tenant_id: string
  name: string
  url: string
  events: string[] | null
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
  top_endpoints: EndpointStat[] | null
}
