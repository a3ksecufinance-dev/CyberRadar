-- ============================================================
-- Domain 19: Cyber Risk Quantification (CRQ)
-- ============================================================

-- Risk register: assets with business criticality and risk scores
CREATE TABLE IF NOT EXISTS risk_assets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    asset_type          TEXT NOT NULL CHECK (asset_type IN (
                            'application','database','infrastructure','network',
                            'data','third_party','process','people')),
    business_unit       TEXT,
    owner               TEXT,
    criticality         TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN (
                            'critical','high','medium','low')),
    -- Business impact values (in thousands of currency units)
    business_value      BIGINT DEFAULT 0,     -- estimated asset value
    revenue_impact      BIGINT DEFAULT 0,     -- potential revenue loss per incident
    regulatory_impact   BIGINT DEFAULT 0,     -- potential regulatory fine
    reputational_impact BIGINT DEFAULT 0,     -- estimated reputational cost
    -- Computed risk scores (updated by risk engine)
    inherent_risk       INT DEFAULT 0 CHECK (inherent_risk BETWEEN 0 AND 100),
    residual_risk       INT DEFAULT 0 CHECK (residual_risk BETWEEN 0 AND 100),
    control_effectiveness INT DEFAULT 0 CHECK (control_effectiveness BETWEEN 0 AND 100),
    -- FAIR model components (0-10 scale)
    threat_event_frequency NUMERIC(4,2) DEFAULT 0,   -- TEF: how often threats occur
    vulnerability           NUMERIC(4,2) DEFAULT 0,  -- Vuln: % of threats that succeed
    loss_magnitude          NUMERIC(4,2) DEFAULT 0,  -- LM: impact when successful
    -- Annualised Loss Expectancy in thousands
    ale                 BIGINT DEFAULT 0,
    is_active           BOOL DEFAULT TRUE,
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_assets_tenant      ON risk_assets (tenant_id, criticality);
CREATE INDEX IF NOT EXISTS idx_risk_assets_residual    ON risk_assets (tenant_id, residual_risk DESC);

-- Risk scenarios: threat scenarios with probability and impact
CREATE TABLE IF NOT EXISTS risk_scenarios (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    scenario_type   TEXT NOT NULL CHECK (scenario_type IN (
                        'ransomware','data_breach','insider_threat','supply_chain',
                        'ddos','fraud','regulatory','business_interruption',
                        'apt','phishing','privilege_abuse','third_party_breach')),
    threat_actor    TEXT CHECK (threat_actor IN (
                        'nation_state','cybercriminal','insider','hacktivist',
                        'competitor','opportunist','unknown')),
    -- FAIR: Loss Event Frequency = TEF * Vulnerability
    annual_probability  NUMERIC(5,4) NOT NULL DEFAULT 0.1, -- 0.0001 to 1.0
    -- Impact dimensions (in thousands of currency units)
    primary_loss        BIGINT DEFAULT 0,    -- direct financial loss
    secondary_loss      BIGINT DEFAULT 0,    -- secondary loss (regulatory, legal, etc.)
    total_loss          BIGINT GENERATED ALWAYS AS (primary_loss + secondary_loss) STORED,
    -- Risk level computed
    risk_level          TEXT DEFAULT 'medium' CHECK (risk_level IN ('critical','high','medium','low')),
    risk_score          INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    -- Control mitigations
    mitigating_controls TEXT[] DEFAULT '{}',
    residual_probability NUMERIC(5,4) DEFAULT 0.1,
    residual_loss        BIGINT DEFAULT 0,
    -- Regulatory mapping
    frameworks          TEXT[] DEFAULT '{}',  -- DORA, Basel III, ISO27001, etc.
    -- Linked assets
    asset_ids           UUID[] DEFAULT '{}',
    status              TEXT DEFAULT 'active' CHECK (status IN ('active','mitigated','accepted','transferred','closed')),
    reviewed_at         TIMESTAMPTZ,
    reviewed_by         UUID,
    created_by          UUID,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_scenarios_tenant   ON risk_scenarios (tenant_id, scenario_type);
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_level    ON risk_scenarios (tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_score    ON risk_scenarios (tenant_id, risk_score DESC);

-- Risk treatments: mitigations and accepted risks
CREATE TABLE IF NOT EXISTS risk_treatments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    scenario_id     UUID NOT NULL REFERENCES risk_scenarios(id) ON DELETE CASCADE,
    treatment_type  TEXT NOT NULL CHECK (treatment_type IN (
                        'mitigate','accept','transfer','avoid')),
    description     TEXT NOT NULL,
    cost            BIGINT DEFAULT 0,        -- cost of treatment (thousands)
    roi             NUMERIC(6,2) DEFAULT 0,  -- return on investment %
    risk_reduction  INT DEFAULT 0 CHECK (risk_reduction BETWEEN 0 AND 100),
    due_date        DATE,
    assigned_to     TEXT,
    status          TEXT DEFAULT 'planned' CHECK (status IN (
                        'planned','in_progress','completed','cancelled')),
    completed_at    TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_treatments_scenario ON risk_treatments (scenario_id);
CREATE INDEX IF NOT EXISTS idx_risk_treatments_tenant   ON risk_treatments (tenant_id, status);

-- Risk assessments: periodic reviews of the overall risk posture
CREATE TABLE IF NOT EXISTS risk_assessments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    assessment_type TEXT NOT NULL CHECK (assessment_type IN (
                        'annual','quarterly','ad_hoc','incident_triggered','regulatory')),
    framework       TEXT,                -- DORA, Basel III, ISO27001, NIST CSF, etc.
    scope           TEXT,
    methodology     TEXT DEFAULT 'FAIR', -- FAIR, OCTAVE, CRAMM
    status          TEXT DEFAULT 'draft' CHECK (status IN (
                        'draft','in_progress','review','approved','archived')),
    -- Aggregate scores
    overall_risk_score  INT DEFAULT 0 CHECK (overall_risk_score BETWEEN 0 AND 100),
    total_ale           BIGINT DEFAULT 0,       -- total annualised loss expectancy (thousands)
    scenarios_count     INT DEFAULT 0,
    critical_count      INT DEFAULT 0,
    high_count          INT DEFAULT 0,
    -- Key findings
    key_findings    TEXT[] DEFAULT '{}',
    recommendations TEXT[] DEFAULT '{}',
    -- Dates
    assessment_date DATE NOT NULL DEFAULT CURRENT_DATE,
    next_review     DATE,
    approved_by     UUID,
    approved_at     TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_tenant  ON risk_assessments (tenant_id, assessment_date DESC);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_status  ON risk_assessments (tenant_id, status);

-- Risk KRIs (Key Risk Indicators): real-time risk metrics
CREATE TABLE IF NOT EXISTS risk_kris (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    category        TEXT NOT NULL CHECK (category IN (
                        'cyber','operational','regulatory','third_party',
                        'people','technology','financial')),
    metric_name     TEXT NOT NULL,          -- e.g. "patch_compliance_rate"
    unit            TEXT DEFAULT '%',        -- %, count, days, thousands
    current_value   NUMERIC(12,4) DEFAULT 0,
    threshold_green NUMERIC(12,4),          -- below this = green
    threshold_amber NUMERIC(12,4),          -- below this = amber, else red
    status          TEXT DEFAULT 'green' CHECK (status IN ('green','amber','red','unknown')),
    trend           TEXT DEFAULT 'stable' CHECK (trend IN ('improving','stable','degrading')),
    source_service  TEXT,                   -- which microservice feeds this KRI
    last_updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_active       BOOL DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_kris_tenant   ON risk_kris (tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_risk_kris_status   ON risk_kris (tenant_id, status);

-- KRI history for trending
CREATE TABLE IF NOT EXISTS risk_kri_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    kri_id      UUID NOT NULL REFERENCES risk_kris(id) ON DELETE CASCADE,
    value       NUMERIC(12,4) NOT NULL,
    status      TEXT NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_kri_history_kri    ON risk_kri_history (kri_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_kri_history_tenant ON risk_kri_history (tenant_id, recorded_at DESC);
