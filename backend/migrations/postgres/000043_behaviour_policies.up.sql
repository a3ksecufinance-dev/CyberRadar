-- ─── Ce que cet établissement considère comme un comportement anormal ───────
--
-- The behavioural thresholds were Go constants with a comment above them. Eighty
-- events a minute, five failures in five, three distinct hours before a baseline
-- is trusted — none of those are facts about human behaviour. They are what one
-- institution decided was worth waking someone for, and a bank running three
-- shifts across four time zones does not have the same answer as a regional one
-- whose branches close at five.
--
-- Worse than being wrong, a fixed threshold is wrong invisibly: a detection that
-- fires every night at the same institution stops being a detection and becomes
-- a filter rule somebody wrote in their mail client.
--
-- Same shape as risk_profiles and remediation_policies: named columns, versioned,
-- effective-dated. "Why did this not alert in March" is a question about the
-- thresholds that were in force in March.

CREATE TABLE IF NOT EXISTS behaviour_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NULL for a standard policy the platform ships; set for a tenant's own.
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,

    code            VARCHAR(40)  NOT NULL,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    based_on        VARCHAR(40),

    version         INT         NOT NULL DEFAULT 1,
    effective_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to    TIMESTAMPTZ,

    -- ── When a baseline is trusted enough to detect against ────────────────
    -- An entity seen three times is not a pattern. Detecting "unusual" against a
    -- baseline of one observation is how a platform greets a new joiner with
    -- four alerts on their first morning.
    min_hours_for_baseline     INT NOT NULL DEFAULT 3,
    min_countries_for_baseline INT NOT NULL DEFAULT 1,

    -- ── The always-on counters ─────────────────────────────────────────────
    velocity_threshold    INT NOT NULL DEFAULT 80,
    velocity_window_s     INT NOT NULL DEFAULT 60,
    brute_force_threshold INT NOT NULL DEFAULT 5,
    brute_force_window_s  INT NOT NULL DEFAULT 300,

    -- ── Per anomaly type: whether it fires, how loud, and what it adds ──────
    -- Switching one off is a legitimate decision, not a gap to be ashamed of.
    -- The alternative is the institution switching it off downstream, where
    -- nobody can see that they did.
    -- OFF_HOURS_ACCESS
    off_hours_enabled   BOOLEAN NOT NULL DEFAULT true,
    off_hours_severity  VARCHAR(10) NOT NULL DEFAULT 'MEDIUM',
    off_hours_score     FLOAT NOT NULL DEFAULT 3.5,
    -- NEW_COUNTRY
    new_country_enabled   BOOLEAN NOT NULL DEFAULT true,
    new_country_severity  VARCHAR(10) NOT NULL DEFAULT 'HIGH',
    new_country_score     FLOAT NOT NULL DEFAULT 6.5,
    -- NEW_IP_PREFIX
    new_ip_prefix_enabled   BOOLEAN NOT NULL DEFAULT true,
    new_ip_prefix_severity  VARCHAR(10) NOT NULL DEFAULT 'LOW',
    new_ip_prefix_score     FLOAT NOT NULL DEFAULT 2.0,
    -- VELOCITY_SPIKE
    velocity_enabled   BOOLEAN NOT NULL DEFAULT true,
    velocity_severity  VARCHAR(10) NOT NULL DEFAULT 'HIGH',
    velocity_score     FLOAT NOT NULL DEFAULT 5.0,
    -- BRUTE_FORCE
    brute_force_enabled   BOOLEAN NOT NULL DEFAULT true,
    brute_force_severity  VARCHAR(10) NOT NULL DEFAULT 'HIGH',
    brute_force_score     FLOAT NOT NULL DEFAULT 6.0,
    -- PRIVILEGE_ESCALATION
    priv_escalation_enabled   BOOLEAN NOT NULL DEFAULT true,
    priv_escalation_severity  VARCHAR(10) NOT NULL DEFAULT 'HIGH',
    priv_escalation_score     FLOAT NOT NULL DEFAULT 7.0,
    -- LATERAL_MOVEMENT
    lateral_movement_enabled   BOOLEAN NOT NULL DEFAULT true,
    lateral_movement_severity  VARCHAR(10) NOT NULL DEFAULT 'CRITICAL',
    lateral_movement_score     FLOAT NOT NULL DEFAULT 8.5,
    -- DATA_EXFILTRATION
    data_exfiltration_enabled   BOOLEAN NOT NULL DEFAULT true,
    data_exfiltration_severity  VARCHAR(10) NOT NULL DEFAULT 'CRITICAL',
    data_exfiltration_score     FLOAT NOT NULL DEFAULT 9.0,
    notes           TEXT,
    created_by      UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ueba_baseline_sane CHECK (
        min_hours_for_baseline BETWEEN 1 AND 24 AND min_countries_for_baseline BETWEEN 1 AND 50
    ),
    CONSTRAINT ueba_velocity_sane CHECK (
        velocity_threshold BETWEEN 1 AND 100000 AND velocity_window_s BETWEEN 10 AND 3600
    ),
    CONSTRAINT ueba_brute_force_sane CHECK (
        brute_force_threshold BETWEEN 1 AND 10000 AND brute_force_window_s BETWEEN 10 AND 86400
    ),
    CONSTRAINT ueba_off_hours_signal CHECK (
        off_hours_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND off_hours_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_new_country_signal CHECK (
        new_country_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND new_country_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_new_ip_prefix_signal CHECK (
        new_ip_prefix_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND new_ip_prefix_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_velocity_signal CHECK (
        velocity_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND velocity_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_brute_force_signal CHECK (
        brute_force_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND brute_force_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_priv_escalation_signal CHECK (
        priv_escalation_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND priv_escalation_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_lateral_movement_signal CHECK (
        lateral_movement_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND lateral_movement_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_data_exfiltration_signal CHECK (
        data_exfiltration_severity IN ('LOW','MEDIUM','HIGH','CRITICAL') AND data_exfiltration_score BETWEEN 0 AND 10
    ),
    CONSTRAINT ueba_version_positive CHECK (version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_behaviour_policy_active
    ON behaviour_policies (tenant_id) WHERE tenant_id IS NOT NULL AND effective_to IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_behaviour_policy_standard
    ON behaviour_policies (code) WHERE tenant_id IS NULL AND effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_behaviour_policy_history
    ON behaviour_policies (tenant_id, version DESC) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE behaviour_policies IS
  'What one institution considers anomalous behaviour. Versioned and effective-dated: "why did this not alert in March" is a question about the thresholds in force in March.';

-- ─── The standard policies ───────────────────────────────────────────────────

INSERT INTO behaviour_policies
    (tenant_id, code, name, description,
     min_hours_for_baseline, min_countries_for_baseline,
     velocity_threshold, velocity_window_s, brute_force_threshold, brute_force_window_s,
     off_hours_enabled, off_hours_severity, off_hours_score, new_country_enabled, new_country_severity, new_country_score, new_ip_prefix_enabled, new_ip_prefix_severity, new_ip_prefix_score, velocity_enabled, velocity_severity, velocity_score, brute_force_enabled, brute_force_severity, brute_force_score, priv_escalation_enabled, priv_escalation_severity, priv_escalation_score, lateral_movement_enabled, lateral_movement_severity, lateral_movement_score, data_exfiltration_enabled, data_exfiltration_severity, data_exfiltration_score)
VALUES
(NULL, 'balanced', 'Équilibré (par défaut)',
 'Exactement les seuils que le moteur appliquait avant que ceci soit paramétrable : 80 événements par minute, 5 échecs en 5 minutes, une ligne de base prête après 3 heures distinctes. L''adopter ne change aucune détection.',
 3, 1, 80, 60, 5, 300,
 true, 'MEDIUM', 3.5,
 true, 'HIGH', 6.5,
 true, 'LOW', 2.0,
 true, 'HIGH', 5.0,
 true, 'HIGH', 6.0,
 true, 'HIGH', 7.0,
 true, 'CRITICAL', 8.5,
 true, 'CRITICAL', 9.0),
(NULL, 'round_the_clock', 'Activité continue',
 'Pour un établissement dont les équipes tournent en 3x8 et dont les adresses sortantes changent : l''accès hors horaires et le nouveau préfixe IP sont désactivés, parce qu''une détection qui part toutes les nuits ne se lit plus. Le reste est resserré pour compenser.',
 3, 1, 60, 60, 4, 300,
 false, 'MEDIUM', 3.5,
 true, 'HIGH', 6.5,
 false, 'LOW', 2.0,
 true, 'HIGH', 5.0,
 true, 'HIGH', 6.0,
 true, 'HIGH', 7.0,
 true, 'CRITICAL', 8.5,
 true, 'CRITICAL', 9.0),
(NULL, 'privileged_watch', 'Surveillance renforcée des comptes à privilèges',
 'Tout est actif et les seuils sont bas : 40 événements par minute, 3 échecs en 5 minutes, et un nouveau pays passe en CRITICAL. À appliquer sur un périmètre d''administration, pas sur un parc entier — le volume n''y serait pas tenable.',
 2, 1, 40, 60, 3, 300,
 true, 'MEDIUM', 3.5,
 true, 'CRITICAL', 8.0,
 true, 'LOW', 2.0,
 true, 'HIGH', 5.0,
 true, 'HIGH', 6.0,
 true, 'CRITICAL', 8.5,
 true, 'CRITICAL', 8.5,
 true, 'CRITICAL', 9.0),
(NULL, 'low_noise', 'Bruit réduit',
 'Pour une première mise en service, le temps que les lignes de base se constituent : seuils relevés (150 par minute, 8 échecs), nouveau préfixe IP désactivé, hors horaires en LOW. À resserrer une fois le parc connu — ce profil manque délibérément des choses.',
 6, 2, 150, 60, 8, 300,
 true, 'LOW', 1.5,
 true, 'HIGH', 6.5,
 false, 'LOW', 2.0,
 true, 'HIGH', 5.0,
 true, 'HIGH', 6.0,
 true, 'HIGH', 7.0,
 true, 'CRITICAL', 8.5,
 true, 'CRITICAL', 9.0)
ON CONFLICT DO NOTHING;

-- ─── The policy in force, for the engine ─────────────────────────────────────
--
-- A published shape rather than the table. The behaviour engine reads thresholds
-- and never decides them, and the fallback to the standard lives here instead of
-- in the consumer's hot path.
CREATE OR REPLACE VIEW tenant_behaviour_policy AS
SELECT
    t.id AS tenant_id,
    COALESCE(own.code, std.code)       AS code,
    COALESCE(own.version, std.version) AS version,
    own.id IS NOT NULL                 AS chosen,
    COALESCE(own.min_hours_for_baseline,     std.min_hours_for_baseline)     AS min_hours_for_baseline,
    COALESCE(own.min_countries_for_baseline, std.min_countries_for_baseline) AS min_countries_for_baseline,
    COALESCE(own.velocity_threshold,    std.velocity_threshold)    AS velocity_threshold,
    COALESCE(own.velocity_window_s,     std.velocity_window_s)     AS velocity_window_s,
    COALESCE(own.brute_force_threshold, std.brute_force_threshold) AS brute_force_threshold,
    COALESCE(own.brute_force_window_s,  std.brute_force_window_s)  AS brute_force_window_s,
    COALESCE(own.off_hours_enabled,  std.off_hours_enabled)  AS off_hours_enabled,
    COALESCE(own.off_hours_severity, std.off_hours_severity) AS off_hours_severity,
    COALESCE(own.off_hours_score,    std.off_hours_score)    AS off_hours_score,
    COALESCE(own.new_country_enabled,  std.new_country_enabled)  AS new_country_enabled,
    COALESCE(own.new_country_severity, std.new_country_severity) AS new_country_severity,
    COALESCE(own.new_country_score,    std.new_country_score)    AS new_country_score,
    COALESCE(own.new_ip_prefix_enabled,  std.new_ip_prefix_enabled)  AS new_ip_prefix_enabled,
    COALESCE(own.new_ip_prefix_severity, std.new_ip_prefix_severity) AS new_ip_prefix_severity,
    COALESCE(own.new_ip_prefix_score,    std.new_ip_prefix_score)    AS new_ip_prefix_score,
    COALESCE(own.velocity_enabled,  std.velocity_enabled)  AS velocity_enabled,
    COALESCE(own.velocity_severity, std.velocity_severity) AS velocity_severity,
    COALESCE(own.velocity_score,    std.velocity_score)    AS velocity_score,
    COALESCE(own.brute_force_enabled,  std.brute_force_enabled)  AS brute_force_enabled,
    COALESCE(own.brute_force_severity, std.brute_force_severity) AS brute_force_severity,
    COALESCE(own.brute_force_score,    std.brute_force_score)    AS brute_force_score,
    COALESCE(own.priv_escalation_enabled,  std.priv_escalation_enabled)  AS priv_escalation_enabled,
    COALESCE(own.priv_escalation_severity, std.priv_escalation_severity) AS priv_escalation_severity,
    COALESCE(own.priv_escalation_score,    std.priv_escalation_score)    AS priv_escalation_score,
    COALESCE(own.lateral_movement_enabled,  std.lateral_movement_enabled)  AS lateral_movement_enabled,
    COALESCE(own.lateral_movement_severity, std.lateral_movement_severity) AS lateral_movement_severity,
    COALESCE(own.lateral_movement_score,    std.lateral_movement_score)    AS lateral_movement_score,
    COALESCE(own.data_exfiltration_enabled,  std.data_exfiltration_enabled)  AS data_exfiltration_enabled,
    COALESCE(own.data_exfiltration_severity, std.data_exfiltration_severity) AS data_exfiltration_severity,
    COALESCE(own.data_exfiltration_score,    std.data_exfiltration_score)    AS data_exfiltration_score
FROM tenants t
LEFT JOIN behaviour_policies own
       ON own.tenant_id = t.id AND own.effective_to IS NULL
CROSS JOIN LATERAL (
    SELECT * FROM behaviour_policies
    WHERE tenant_id IS NULL AND code = 'balanced' AND effective_to IS NULL
) std;

COMMENT ON VIEW tenant_behaviour_policy IS
  'The behavioural thresholds in force for each tenant: their own policy, or the standard one when they have not chosen.';
