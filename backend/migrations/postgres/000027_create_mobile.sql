-- ============================================================
-- Domain 25: Mobile Security (MDM / MAM / MTD)
-- ============================================================

-- Enrolled mobile devices
CREATE TABLE IF NOT EXISTS mob_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    -- Device identity
    device_name     TEXT NOT NULL,
    device_type     TEXT NOT NULL CHECK (device_type IN (
                        'smartphone','tablet','laptop','wearable','iot_mobile','other')),
    platform        TEXT NOT NULL CHECK (platform IN ('ios','android','windows','macos','linux','other')),
    os_version      TEXT,
    model           TEXT,
    manufacturer    TEXT,
    serial_number   TEXT,
    imei            TEXT,
    udid            TEXT UNIQUE,                   -- Apple UDID or Android device ID
    -- MDM enrollment
    enrollment_status TEXT DEFAULT 'enrolled' CHECK (enrollment_status IN (
                        'enrolled','pending','unenrolled','retired','lost','wiped')),
    enrollment_date TIMESTAMPTZ DEFAULT NOW(),
    mdm_profile_installed BOOL DEFAULT FALSE,
    -- Ownership
    ownership       TEXT DEFAULT 'corporate' CHECK (ownership IN ('corporate','byod','cope')),
    owner_name      TEXT,
    owner_id        UUID,
    owner_email     TEXT,
    department      TEXT,
    -- Security posture
    is_jailbroken   BOOL DEFAULT FALSE,
    is_rooted       BOOL DEFAULT FALSE,
    is_encrypted    BOOL DEFAULT FALSE,
    is_screen_lock  BOOL DEFAULT FALSE,
    is_compliant    BOOL DEFAULT TRUE,
    compliance_issues TEXT[] DEFAULT '{}',
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT DEFAULT 'low' CHECK (risk_level IN ('critical','high','medium','low')),
    -- Location (last known)
    last_location   TEXT,
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    last_checkin_at TIMESTAMPTZ DEFAULT NOW(),
    -- Network
    last_ip         TEXT,
    carrier         TEXT,
    -- Metadata
    tags            TEXT[] DEFAULT '{}',
    notes           TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mob_devices_tenant     ON mob_devices (tenant_id, enrollment_status, risk_level);
CREATE INDEX IF NOT EXISTS idx_mob_devices_owner      ON mob_devices (tenant_id, owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mob_devices_platform   ON mob_devices (tenant_id, platform, os_version);
CREATE INDEX IF NOT EXISTS idx_mob_devices_compliance ON mob_devices (tenant_id, is_compliant);

-- Mobile applications inventory
CREATE TABLE IF NOT EXISTS mob_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    -- App identity
    app_name        TEXT NOT NULL,
    bundle_id       TEXT NOT NULL,                 -- e.g. com.example.app
    version         TEXT NOT NULL,
    platform        TEXT NOT NULL CHECK (platform IN ('ios','android','cross_platform')),
    -- Distribution
    store_source    TEXT DEFAULT 'enterprise' CHECK (store_source IN (
                        'app_store','play_store','enterprise','sideload','unknown')),
    is_managed      BOOL DEFAULT FALSE,            -- MDM-managed
    is_approved     BOOL DEFAULT TRUE,
    -- Risk
    risk_level      TEXT DEFAULT 'low' CHECK (risk_level IN ('critical','high','medium','low')),
    permissions     TEXT[] DEFAULT '{}',           -- requested permissions
    has_known_vulns BOOL DEFAULT FALSE,
    vuln_count      INT DEFAULT 0,
    -- Policy
    is_blocklisted  BOOL DEFAULT FALSE,
    blocklist_reason TEXT,
    -- Metadata
    developer       TEXT,
    category        TEXT,
    install_count   INT DEFAULT 0,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, bundle_id, version, platform)
);

CREATE INDEX IF NOT EXISTS idx_mob_apps_tenant  ON mob_apps (tenant_id, platform, is_approved);
CREATE INDEX IF NOT EXISTS idx_mob_apps_blocked ON mob_apps (tenant_id, is_blocklisted) WHERE is_blocklisted = TRUE;

-- Device ↔ App installation mapping
CREATE TABLE IF NOT EXISTS mob_device_apps (
    device_id       UUID NOT NULL REFERENCES mob_devices(id) ON DELETE CASCADE,
    app_id          UUID NOT NULL REFERENCES mob_apps(id) ON DELETE CASCADE,
    installed_at    TIMESTAMPTZ DEFAULT NOW(),
    is_active       BOOL DEFAULT TRUE,
    PRIMARY KEY (device_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_mob_device_apps_app ON mob_device_apps (app_id);

-- MDM / MAM Policies
CREATE TABLE IF NOT EXISTS mob_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'device_compliance','app_management','network','data_protection',
                        'passcode','encryption','vpn','geofencing','other')),
    platform        TEXT DEFAULT 'all' CHECK (platform IN ('ios','android','windows','macos','all')),
    -- Rules (flexible JSONB)
    rules           JSONB NOT NULL DEFAULT '{}',
    -- Enforcement
    action          TEXT DEFAULT 'alert' CHECK (action IN (
                        'alert','block','wipe','lock','notify','enforce')),
    is_active       BOOL DEFAULT TRUE,
    -- Scope
    applies_to      TEXT DEFAULT 'all' CHECK (applies_to IN (
                        'all','corporate','byod','cope','department')),
    department      TEXT,
    assigned_count  INT DEFAULT 0,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mob_policies_tenant ON mob_policies (tenant_id, policy_type, is_active);

-- Mobile Threat Defense (MTD) detections
CREATE TABLE IF NOT EXISTS mob_threats (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    device_id       UUID NOT NULL REFERENCES mob_devices(id) ON DELETE CASCADE,
    -- Threat classification
    threat_type     TEXT NOT NULL CHECK (threat_type IN (
                        'malware','spyware','ransomware','phishing','network_attack',
                        'man_in_the_middle','rogue_ap','ssl_strip','device_exploit',
                        'app_vulnerability','data_leakage','jailbreak_root',
                        'os_vulnerability','behavioral_anomaly','other')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status          TEXT DEFAULT 'detected' CHECK (status IN (
                        'detected','investigating','contained','resolved','false_positive')),
    title           TEXT NOT NULL,
    description     TEXT,
    -- Technical details
    threat_indicator TEXT,                         -- hash, domain, IP, etc.
    affected_app    TEXT,
    network_details JSONB DEFAULT '{}',
    -- Detection
    detected_by     TEXT,                          -- MTD engine / rule
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    -- Response
    auto_remediated BOOL DEFAULT FALSE,
    remediation     TEXT,
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mob_threats_device ON mob_threats (device_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_mob_threats_tenant ON mob_threats (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_mob_threats_time   ON mob_threats (tenant_id, detected_at DESC);

-- Compliance evaluations per device
CREATE TABLE IF NOT EXISTS mob_compliance_checks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    device_id       UUID NOT NULL REFERENCES mob_devices(id) ON DELETE CASCADE,
    policy_id       UUID REFERENCES mob_policies(id) ON DELETE SET NULL,
    -- Result
    is_compliant    BOOL NOT NULL,
    violations      JSONB DEFAULT '[]',            -- list of {rule, description, severity}
    compliance_score INT DEFAULT 100 CHECK (compliance_score BETWEEN 0 AND 100),
    -- Action taken
    action_taken    TEXT,
    checked_at      TIMESTAMPTZ DEFAULT NOW(),
    next_check_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mob_compliance_device ON mob_compliance_checks (device_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_mob_compliance_tenant ON mob_compliance_checks (tenant_id, is_compliant, checked_at DESC);

-- Remote actions (wipe, lock, locate, push config)
CREATE TABLE IF NOT EXISTS mob_remote_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    device_id       UUID NOT NULL REFERENCES mob_devices(id) ON DELETE CASCADE,
    action_type     TEXT NOT NULL CHECK (action_type IN (
                        'remote_wipe','selective_wipe','lock','unlock',
                        'locate','push_config','install_app','remove_app',
                        'reset_passcode','reboot','message')),
    status          TEXT DEFAULT 'pending' CHECK (status IN (
                        'pending','sent','acknowledged','completed','failed','cancelled')),
    -- Details
    payload         JSONB DEFAULT '{}',
    message         TEXT,
    -- Execution
    requested_by    TEXT,
    requested_by_id UUID,
    sent_at         TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    failure_reason  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mob_actions_device ON mob_remote_actions (device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mob_actions_tenant ON mob_remote_actions (tenant_id, status, action_type);
