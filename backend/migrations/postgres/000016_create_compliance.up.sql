-- Domain 14: Security & Compliance — Frameworks, Controls, Assessments, Risks, Evidence

-- ── Compliance Frameworks ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comp_frameworks (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    code           TEXT        NOT NULL
                   CHECK (code IN ('ISO27001','SOC2','PCIDSS','SWIFTCSP','NIS2','DORA','GDPR')),
    name           TEXT        NOT NULL,
    description    TEXT,
    version        TEXT        NOT NULL DEFAULT '1.0',
    total_controls INT         NOT NULL DEFAULT 0,
    is_active      BOOL        NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_comp_frameworks_tenant        ON comp_frameworks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_frameworks_tenant_active ON comp_frameworks (tenant_id, is_active);

-- ── Compliance Controls ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comp_controls (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    framework_id  UUID        NOT NULL REFERENCES comp_frameworks(id) ON DELETE CASCADE,
    control_id    TEXT        NOT NULL,   -- e.g. A.5.1.1, CC6.1, Req-8.3
    domain        TEXT        NOT NULL,   -- e.g. "Access Control", "Cryptography"
    title         TEXT        NOT NULL,
    description   TEXT,
    guidance      TEXT,
    priority      TEXT        NOT NULL DEFAULT 'MEDIUM'
                  CHECK (priority IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    is_automated  BOOL        NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comp_controls_framework  ON comp_controls (framework_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_tenant     ON comp_controls (tenant_id, framework_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_domain     ON comp_controls (tenant_id, domain);
CREATE INDEX IF NOT EXISTS idx_comp_controls_priority   ON comp_controls (tenant_id, priority);
CREATE INDEX IF NOT EXISTS idx_comp_controls_automated  ON comp_controls (tenant_id, is_automated) WHERE is_automated = TRUE;

-- ── Control Assessments ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comp_assessments (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    framework_id   UUID        NOT NULL REFERENCES comp_frameworks(id) ON DELETE CASCADE,
    control_id     UUID        NOT NULL REFERENCES comp_controls(id) ON DELETE CASCADE,
    status         TEXT        NOT NULL DEFAULT 'not_assessed'
                   CHECK (status IN ('compliant','partial','non_compliant','not_applicable','not_assessed')),
    score          FLOAT       NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100),
    evidence_refs  TEXT[]      NOT NULL DEFAULT '{}',
    notes          TEXT,
    assessed_by    UUID,
    assessed_at    TIMESTAMPTZ,
    next_review_at TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_comp_assessments_tenant          ON comp_assessments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_assessments_framework       ON comp_assessments (tenant_id, framework_id);
CREATE INDEX IF NOT EXISTS idx_comp_assessments_status          ON comp_assessments (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_comp_assessments_next_review     ON comp_assessments (tenant_id, next_review_at) WHERE next_review_at IS NOT NULL;

-- ── Risk Register ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comp_risks (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL,
    title               TEXT        NOT NULL,
    description         TEXT,
    category            TEXT        NOT NULL
                        CHECK (category IN ('operational','cybersecurity','regulatory','third_party','data_breach')),
    likelihood          INT         NOT NULL CHECK (likelihood >= 1 AND likelihood <= 5),
    impact              INT         NOT NULL CHECK (impact >= 1 AND impact <= 5),
    risk_score          INT         GENERATED ALWAYS AS (likelihood * impact) STORED,
    status              TEXT        NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','mitigating','accepted','closed')),
    owner_id            UUID,
    related_controls    UUID[]      NOT NULL DEFAULT '{}',
    mitigation_plan     TEXT,
    residual_likelihood INT         CHECK (residual_likelihood >= 1 AND residual_likelihood <= 5),
    residual_impact     INT         CHECK (residual_impact >= 1 AND residual_impact <= 5),
    due_date            TIMESTAMPTZ,
    created_by          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comp_risks_tenant        ON comp_risks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_risks_status        ON comp_risks (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_comp_risks_category      ON comp_risks (tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_comp_risks_score         ON comp_risks (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_comp_risks_owner         ON comp_risks (tenant_id, owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_comp_risks_due_date      ON comp_risks (tenant_id, due_date) WHERE due_date IS NOT NULL;

-- ── Evidence ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS comp_evidence (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    assessment_id  UUID        NOT NULL REFERENCES comp_assessments(id) ON DELETE CASCADE,
    title          TEXT        NOT NULL,
    evidence_type  TEXT        NOT NULL
                   CHECK (evidence_type IN ('document','screenshot','log','policy','audit_report','automated')),
    source_service TEXT
                   CHECK (source_service IN ('siem','ueba','ti','vuln','attackpath','soar','manual')),
    reference_url  TEXT,
    collected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    collected_by   UUID,
    properties     JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comp_evidence_assessment ON comp_evidence (assessment_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_tenant     ON comp_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_type       ON comp_evidence (tenant_id, evidence_type);
CREATE INDEX IF NOT EXISTS idx_comp_evidence_source     ON comp_evidence (tenant_id, source_service) WHERE source_service IS NOT NULL;
