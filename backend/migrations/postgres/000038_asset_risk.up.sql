-- Migration: 000038_asset_risk
--
-- An asset's risk score never moved.
--
-- assets.vuln_critical, vuln_high, vuln_medium and vuln_low were read by the
-- scorer and written by nobody — not one of the thirty-three modules assigned
-- them. A whole term of the formula was therefore dead: an estate with nine
-- critical assets carrying ten actively exploited CVEs answered high_risk = 0,
-- and every asset's score reflected only its declared criticality and its
-- flags. The number looked considered. It was arithmetic over zeros.
--
-- The counters are a projection of the vulnerability domain into the asset
-- table, and a cache nobody refreshes is worse than no cache: it is wrong in a
-- way that reads as authoritative. So they stop being stored and start being
-- derived, and the columns go with them — a column that looks like a fact and
-- is not is exactly the trap that produced this.
--
-- Two views, in two layers, so the seam stays where the ownership is:
--
--   asset_vulnerability_summary  belongs to the vulnerability domain and is
--                                what it publishes about an asset.
--   asset_risk                   belongs to the asset domain and is what the
--                                asset service reads instead of the table.
--
-- The asset service reads the second and never touches the vulnerability
-- tables. If the vulnerability schema changes, the view it publishes is what
-- must keep its shape — which is the contract one wants between two domains
-- that share a database.

-- ─── What the vulnerability domain publishes about an asset ──────────────────

-- Only open work counts. A resolved finding is history: leaving it in the
-- score would mean an asset could never improve by being fixed.
CREATE OR REPLACE VIEW asset_vulnerability_summary AS
SELECT av.tenant_id,
       av.asset_id,
       COUNT(*) FILTER (WHERE v.cvss_severity = 'CRITICAL')::int AS vuln_critical,
       COUNT(*) FILTER (WHERE v.cvss_severity = 'HIGH')::int     AS vuln_high,
       COUNT(*) FILTER (WHERE v.cvss_severity = 'MEDIUM')::int   AS vuln_medium,
       COUNT(*) FILTER (WHERE v.cvss_severity = 'LOW')::int      AS vuln_low,
       COUNT(*)::int                                             AS open_findings,
       COALESCE(MAX(v.cvss_score), 0)::double precision          AS max_cvss,
       COALESCE(BOOL_OR(v.is_exploited), false)                  AS has_known_exploit,
       COUNT(*) FILTER (WHERE av.sla_due_at < NOW())::int        AS sla_breached
FROM asset_vulnerabilities av
JOIN vulnerabilities v ON v.id = av.vuln_id
WHERE av.status IN ('open', 'in_remediation')
GROUP BY av.tenant_id, av.asset_id;

COMMENT ON VIEW asset_vulnerability_summary IS
  'What the vulnerability domain publishes about one asset: open findings by severity. Read it rather than asset_vulnerabilities.';

-- ─── The asset, with its risk ────────────────────────────────────────────────

-- The columns go before the view is created: a view built on SELECT a.* would
-- otherwise carry both the stale column and the derived one under the same
-- name.
DROP INDEX IF EXISTS idx_assets_tenant_risk;
ALTER TABLE assets
    DROP COLUMN IF EXISTS risk_score,
    DROP COLUMN IF EXISTS vuln_critical,
    DROP COLUMN IF EXISTS vuln_high,
    DROP COLUMN IF EXISTS vuln_medium,
    DROP COLUMN IF EXISTS vuln_low;

-- The arithmetic mirrors ScoreAsset in services/asset/internal/service. Two
-- expressions of one formula is a cost, paid so that a list of a hundred
-- thousand assets can be ordered and counted by risk in the database rather
-- than in memory. asset_risk_test.go runs both over the same rows and fails
-- if they ever disagree, so the duplication cannot drift unnoticed.
CREATE OR REPLACE VIEW asset_risk AS
SELECT a.*,
       COALESCE(s.vuln_critical, 0) AS vuln_critical,
       COALESCE(s.vuln_high, 0)     AS vuln_high,
       COALESCE(s.vuln_medium, 0)   AS vuln_medium,
       COALESCE(s.vuln_low, 0)      AS vuln_low,
       LEAST(10.0,
             -- criticality 1..4 → 0..3
             (a.criticality - 1)::double precision
             -- open findings, weighted by severity, capped at 4
           + LEAST(4.0, COALESCE(s.vuln_critical, 0) * 2.0
                      + COALESCE(s.vuln_high, 0) * 1.0
                      + COALESCE(s.vuln_medium, 0) * 0.4
                      + COALESCE(s.vuln_low, 0) * 0.1)
             -- inherent exposure of a banking asset, capped at 2
           + LEAST(2.0, (CASE WHEN a.is_cbs_connected   THEN 1.0 ELSE 0.0 END)
                      + (CASE WHEN a.is_swift_connected THEN 1.0 ELSE 0.0 END)
                      + (CASE WHEN a.is_pci_scope       THEN 0.5 ELSE 0.0 END))
             -- an asset no sensor has ever seen is unknown risk, not no risk
           + (CASE WHEN a.last_seen_at IS NULL THEN 0.5 ELSE 0.0 END)
             -- context, capped at 1
           + LEAST(1.0, (CASE WHEN a.environment = 'production' AND a.criticality >= 3
                              THEN 0.5 ELSE 0.0 END)
                      + (CASE WHEN a.asset_type IN ('cbs_server', 'atm', 'swift_gateway',
                                                    'payment_terminal', 'monetique', 'hsm')
                              THEN 0.5 ELSE 0.0 END))
       )::double precision AS risk_score
FROM assets a
LEFT JOIN asset_vulnerability_summary s
       ON s.tenant_id = a.tenant_id AND s.asset_id = a.id;

COMMENT ON VIEW asset_risk IS
  'Assets with their live vulnerability counters and risk score. The asset service reads this, not the assets table.';
