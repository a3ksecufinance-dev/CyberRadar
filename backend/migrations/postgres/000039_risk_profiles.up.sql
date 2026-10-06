-- Migration: 000039_risk_profiles
--
-- The risk score was a formula with the weights written into it. That is the
-- wrong place for them, and not because hard-coding is untidy: the weights are
-- not facts about the estate, they are one institution's risk appetite.
--
-- CVSS 9.8 is 9.8 everywhere. Whether a critical vulnerability on an
-- internet-facing card-scope asset scores 7 or 9 is a decision a bank's risk
-- function makes, defends to its regulator, and revisits. A vendor who decides
-- it for them is either wrong or asking to be argued with in every deal.
--
-- So: the platform ships standard profiles, a tenant adopts one, and adjusts.
--
-- Three things that make this defensible rather than merely configurable:
--
--   Named columns, not a JSON blob. A weight can then carry a CHECK that bounds
--   it, the view can join it without extracting anything, and a factor added to
--   the model is a migration somebody reviewed rather than a key that appears
--   in production.
--
--   Versioned and effective-dated, never updated in place. Under DORA and
--   ISO 27001 a score that drove a decision has to be explicable months later,
--   and the first question is "what was the formula that day". A profile that
--   is edited in place cannot answer it.
--
--   A fixed set of factors, weighted — not an expression language. A customer
--   who can write arbitrary formulas gets a number nobody can explain, no
--   breakdown, and no comparison between tenants. Full control over the
--   judgement, none over the vocabulary, is the trade that keeps the score
--   meaning something. A factor that genuinely does not exist yet is a product
--   conversation, not a configuration field.

CREATE TABLE IF NOT EXISTS risk_profiles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NULL means a standard profile the platform ships, available to every
    -- tenant. A tenant's own profile always names its tenant.
    tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,

    code        VARCHAR(40)  NOT NULL,
    name        VARCHAR(200) NOT NULL,
    description TEXT,

    -- The standard profile this one started from, so the difference from it is
    -- what a tenant shows an auditor. NULL for the standard profiles.
    based_on    VARCHAR(40),

    -- Versioned: a change inserts the next version and closes the previous one.
    version       INT         NOT NULL DEFAULT 1,
    effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to   TIMESTAMPTZ,

    -- ── Criticality: 0 for the lowest tier, this much per step above it ──────
    criticality_step   DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    criticality_cap    DOUBLE PRECISION NOT NULL DEFAULT 3.0,

    -- ── Open findings, by severity ──────────────────────────────────────────
    vuln_critical      DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    vuln_high          DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    vuln_medium        DOUBLE PRECISION NOT NULL DEFAULT 0.4,
    vuln_low           DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    vuln_cap           DOUBLE PRECISION NOT NULL DEFAULT 4.0,

    -- ── Inherent exposure of a banking asset ────────────────────────────────
    cbs_connected      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    swift_connected    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    pci_scope          DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    exposure_cap       DOUBLE PRECISION NOT NULL DEFAULT 2.0,

    -- ── Visibility: an asset no sensor has seen is unknown risk, not none ───
    never_seen         DOUBLE PRECISION NOT NULL DEFAULT 0.5,

    -- ── Context ─────────────────────────────────────────────────────────────
    critical_production DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    banking_type        DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    context_cap         DOUBLE PRECISION NOT NULL DEFAULT 1.0,

    total_cap           DOUBLE PRECISION NOT NULL DEFAULT 10.0,

    -- What this institution calls high risk. It drives the counter on the
    -- asset page and any alerting built on it, so it is a decision too.
    high_risk_threshold DOUBLE PRECISION NOT NULL DEFAULT 7.0,

    notes       TEXT,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A weight outside 0–10 is not a risk appetite, it is a typo. The cap
    -- columns are bounded the same way, and the total cap is what keeps the
    -- score on the scale the whole product presents.
    CONSTRAINT risk_profiles_weights_in_range CHECK (
        criticality_step    BETWEEN 0 AND 10 AND criticality_cap BETWEEN 0 AND 10 AND
        vuln_critical       BETWEEN 0 AND 10 AND vuln_high       BETWEEN 0 AND 10 AND
        vuln_medium         BETWEEN 0 AND 10 AND vuln_low        BETWEEN 0 AND 10 AND
        vuln_cap            BETWEEN 0 AND 10 AND
        cbs_connected       BETWEEN 0 AND 10 AND swift_connected BETWEEN 0 AND 10 AND
        pci_scope           BETWEEN 0 AND 10 AND exposure_cap    BETWEEN 0 AND 10 AND
        never_seen          BETWEEN 0 AND 10 AND
        critical_production BETWEEN 0 AND 10 AND banking_type    BETWEEN 0 AND 10 AND
        context_cap         BETWEEN 0 AND 10 AND
        total_cap           BETWEEN 1 AND 10 AND
        high_risk_threshold BETWEEN 0 AND 10
    ),
    CONSTRAINT risk_profiles_version_positive CHECK (version >= 1),
    CONSTRAINT risk_profiles_period_ordered CHECK (effective_to IS NULL OR effective_to > effective_from)
);

-- Exactly one active profile per tenant. Without this a second active row
-- would make the score depend on which one the join happened to pick.
CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_profiles_active_tenant
    ON risk_profiles (tenant_id) WHERE effective_to IS NULL AND tenant_id IS NOT NULL;

-- And one active row per standard profile code.
CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_profiles_active_standard
    ON risk_profiles (code) WHERE effective_to IS NULL AND tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_risk_profiles_history
    ON risk_profiles (tenant_id, version DESC);

COMMENT ON TABLE risk_profiles IS
  'Risk-appetite weights. One active row per tenant; rows with tenant_id NULL are the standard profiles the platform ships.';

-- ─── The standard profiles ───────────────────────────────────────────────────
--
-- Four, because a bank does not have one risk appetite: what a card-scope
-- assessor asks about and what a SWIFT attestation asks about are different
-- questions, and a customer should be able to say which one this tenant is
-- being scored for. They are starting points a risk function argues with, not
-- recommendations.

INSERT INTO risk_profiles (tenant_id, code, name, description,
       criticality_step, criticality_cap,
       vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_cap,
       cbs_connected, swift_connected, pci_scope, exposure_cap,
       never_seen, critical_production, banking_type, context_cap,
       total_cap, high_risk_threshold)
VALUES
  (NULL, 'balanced', 'Équilibré (par défaut)',
   'Le profil d''origine de la plateforme. Aucun domaine n''est privilégié : à utiliser tant que la fonction risque n''a pas tranché.',
   1.0, 3.0,  2.0, 1.0, 0.4, 0.1, 4.0,  1.0, 1.0, 0.5, 2.0,  0.5, 0.5, 0.5, 1.0,  10.0, 7.0),

  (NULL, 'vulnerability_led', 'Orienté vulnérabilités',
   'Ce qui est ouvert et exploitable pèse plus que ce que l''actif est. Convient à un parc dont la criticité déclarée est peu fiable.',
   0.75, 2.5,  2.5, 1.5, 0.6, 0.15, 5.5,  0.75, 0.75, 0.5, 1.5,  0.5, 0.25, 0.25, 0.75,  10.0, 7.0),

  (NULL, 'pci_dss', 'Orienté PCI DSS',
   'Le périmètre carte domine, et le délai de correction y est contractuel. À utiliser quand l''évaluateur PCI est le lecteur principal du score.',
   0.75, 2.5,  2.25, 1.25, 0.5, 0.1, 4.5,  0.5, 0.5, 1.5, 2.5,  0.5, 0.5, 0.25, 1.0,  10.0, 6.5),

  (NULL, 'swift_cscf', 'Orienté SWIFT CSCF',
   'La zone de paiement et son administration dominent. À utiliser quand l''attestation CSCF est le lecteur principal du score.',
   1.0, 3.0,  2.0, 1.0, 0.4, 0.1, 3.5,  1.0, 2.0, 0.5, 3.0,  0.5, 0.5, 0.75, 1.25,  10.0, 6.5)
ON CONFLICT DO NOTHING;

-- ─── What the asset domain reads ─────────────────────────────────────────────

-- tenant_risk_profile is the one active profile per tenant, falling back to the
-- standard 'balanced' profile for a tenant that has not chosen.
--
-- The fallback is the point: a fresh install scores correctly with standard
-- values, and adopting a profile is a decision, not a prerequisite.
CREATE OR REPLACE VIEW tenant_risk_profile AS
SELECT t.id AS tenant_id,
       COALESCE(own.id, std.id)                   AS profile_id,
       COALESCE(own.code, std.code)               AS code,
       COALESCE(own.name, std.name)               AS name,
       COALESCE(own.version, std.version)         AS version,
       (own.id IS NOT NULL)                       AS is_tenant_profile,
       COALESCE(own.based_on, std.code)           AS based_on,
       COALESCE(own.criticality_step, std.criticality_step)       AS criticality_step,
       COALESCE(own.criticality_cap, std.criticality_cap)         AS criticality_cap,
       COALESCE(own.vuln_critical, std.vuln_critical)             AS vuln_critical,
       COALESCE(own.vuln_high, std.vuln_high)                     AS vuln_high,
       COALESCE(own.vuln_medium, std.vuln_medium)                 AS vuln_medium,
       COALESCE(own.vuln_low, std.vuln_low)                       AS vuln_low,
       COALESCE(own.vuln_cap, std.vuln_cap)                       AS vuln_cap,
       COALESCE(own.cbs_connected, std.cbs_connected)             AS cbs_connected,
       COALESCE(own.swift_connected, std.swift_connected)         AS swift_connected,
       COALESCE(own.pci_scope, std.pci_scope)                     AS pci_scope,
       COALESCE(own.exposure_cap, std.exposure_cap)               AS exposure_cap,
       COALESCE(own.never_seen, std.never_seen)                   AS never_seen,
       COALESCE(own.critical_production, std.critical_production) AS critical_production,
       COALESCE(own.banking_type, std.banking_type)               AS banking_type,
       COALESCE(own.context_cap, std.context_cap)                 AS context_cap,
       COALESCE(own.total_cap, std.total_cap)                     AS total_cap,
       COALESCE(own.high_risk_threshold, std.high_risk_threshold) AS high_risk_threshold
FROM tenants t
LEFT JOIN risk_profiles own
       ON own.tenant_id = t.id AND own.effective_to IS NULL
CROSS JOIN risk_profiles std
WHERE std.tenant_id IS NULL AND std.code = 'balanced' AND std.effective_to IS NULL;

COMMENT ON VIEW tenant_risk_profile IS
  'The weights in force for each tenant, falling back to the standard balanced profile. Read this, not risk_profiles.';

-- asset_risk, rebuilt on the profile.
--
-- Dropped first: CREATE OR REPLACE cannot insert a column in the middle of a
-- view, and the profile columns belong beside the score they produced rather
-- than appended at the end where nobody looks.
DROP VIEW IF EXISTS asset_risk;

--
-- The arithmetic still mirrors ScoreAsset in services/asset/internal/service,
-- and asset_risk_test.go still runs both over the same rows — now across
-- several profiles, because a formula that agrees on one set of weights and
-- diverges on another is the failure this duplication invites.
CREATE OR REPLACE VIEW asset_risk AS
SELECT a.*,
       COALESCE(s.vuln_critical, 0) AS vuln_critical,
       COALESCE(s.vuln_high, 0)     AS vuln_high,
       COALESCE(s.vuln_medium, 0)   AS vuln_medium,
       COALESCE(s.vuln_low, 0)      AS vuln_low,
       p.profile_id                 AS risk_profile_id,
       p.code                       AS risk_profile_code,
       p.high_risk_threshold        AS risk_high_threshold,
       LEAST(p.total_cap,
             LEAST(p.criticality_cap, (a.criticality - 1)::double precision * p.criticality_step)
           + LEAST(p.vuln_cap, COALESCE(s.vuln_critical, 0) * p.vuln_critical
                             + COALESCE(s.vuln_high, 0)     * p.vuln_high
                             + COALESCE(s.vuln_medium, 0)   * p.vuln_medium
                             + COALESCE(s.vuln_low, 0)      * p.vuln_low)
           + LEAST(p.exposure_cap, (CASE WHEN a.is_cbs_connected   THEN p.cbs_connected   ELSE 0.0 END)
                                 + (CASE WHEN a.is_swift_connected THEN p.swift_connected ELSE 0.0 END)
                                 + (CASE WHEN a.is_pci_scope       THEN p.pci_scope       ELSE 0.0 END))
           + (CASE WHEN a.last_seen_at IS NULL THEN p.never_seen ELSE 0.0 END)
           + LEAST(p.context_cap, (CASE WHEN a.environment = 'production' AND a.criticality >= 3
                                        THEN p.critical_production ELSE 0.0 END)
                                + (CASE WHEN a.asset_type IN ('cbs_server', 'atm', 'swift_gateway',
                                                              'payment_terminal', 'monetique', 'hsm')
                                        THEN p.banking_type ELSE 0.0 END))
       )::double precision AS risk_score
FROM assets a
JOIN tenant_risk_profile p ON p.tenant_id = a.tenant_id
LEFT JOIN asset_vulnerability_summary s
       ON s.tenant_id = a.tenant_id AND s.asset_id = a.id;

COMMENT ON VIEW asset_risk IS
  'Assets with their live vulnerability counters and the risk score their tenant profile produces.';
