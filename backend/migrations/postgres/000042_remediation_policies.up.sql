-- ─── How long this institution gives itself to fix something ─────────────────
--
-- The deadlines were four numbers in a Go map — 3, 7, 30, 90 days by severity —
-- and a comment calling them "banking-grade". They are not a fact about a
-- vulnerability. They are what an institution committed to, to its regulator, to
-- its card scheme, or to its own board, and that commitment differs between a
-- retail bank and a payment processor and changes when a contract is renewed.
--
-- The same shape as risk_profiles, for the same reasons: named columns rather
-- than a JSON blob, so a deadline carries a type and a CHECK; versioned and
-- effective-dated, because "this finding breached its SLA" is a claim about the
-- policy that was in force when it was raised, not the one in force today.
--
-- The base is the severity. On top of it sit ceilings: conditions that can only
-- tighten a deadline, never extend one. That is how a policy actually reads —
-- "critical within 3 days, or 24 hours if it is being exploited" — and it is
-- why they are applied as a minimum rather than as a multiplier.

CREATE TABLE IF NOT EXISTS remediation_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NULL for a standard policy the platform ships; set for a tenant's own.
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,

    code            VARCHAR(40)  NOT NULL,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,

    -- The standard policy this one started from, so the difference from it is
    -- what a tenant shows an auditor.
    based_on        VARCHAR(40),

    version         INT         NOT NULL DEFAULT 1,
    effective_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to    TIMESTAMPTZ,

    -- ── The base, in days from when the finding was first seen ──────────────
    critical_days   INT NOT NULL,
    high_days       INT NOT NULL,
    medium_days     INT NOT NULL,
    low_days        INT NOT NULL,

    -- ── Ceilings. NULL means this condition does not tighten anything ───────
    -- Known exploited. A critical with a working exploit in the wild is not the
    -- same deadline as a critical nobody has weaponised.
    exploited_days  INT,
    -- The asset sits in the DMZ. The platform has no internet-facing flag, and
    -- inventing one it could not populate would be a ceiling that never applies.
    dmz_days        INT,
    -- Regulated scope: core banking, payments, card.
    cbs_days        INT,
    swift_days      INT,
    pci_days        INT,

    -- The floor. No combination of ceilings goes below it, because a deadline of
    -- zero days is not a commitment, it is a breach the moment it is recorded.
    minimum_days    INT NOT NULL DEFAULT 1,

    notes           TEXT,
    created_by      UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT remediation_base_ordered CHECK (
        critical_days <= high_days AND high_days <= medium_days AND medium_days <= low_days
    ),
    CONSTRAINT remediation_base_positive CHECK (
        critical_days >= 1 AND low_days <= 3650
    ),
    CONSTRAINT remediation_minimum_sane CHECK (minimum_days >= 1 AND minimum_days <= critical_days),
    CONSTRAINT remediation_ceilings_positive CHECK (
        COALESCE(exploited_days, 1) >= 1 AND COALESCE(dmz_days, 1) >= 1 AND
        COALESCE(cbs_days, 1)       >= 1 AND COALESCE(swift_days, 1) >= 1 AND
        COALESCE(pci_days, 1)       >= 1
    ),
    CONSTRAINT remediation_version_positive CHECK (version >= 1)
);

-- One policy in force per tenant, and one current version per standard code.
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_policy_active
    ON remediation_policies (tenant_id) WHERE tenant_id IS NOT NULL AND effective_to IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_policy_standard
    ON remediation_policies (code) WHERE tenant_id IS NULL AND effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_remediation_policy_history
    ON remediation_policies (tenant_id, version DESC) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE remediation_policies IS
  'What an institution committed to fixing something in. Versioned and effective-dated: whether a finding breached its deadline is a claim about the policy in force when it was raised.';

-- ─── The standard policies ───────────────────────────────────────────────────
--
-- The figures are the platform''s reading of what these regimes ask for, meant
-- to be argued with by a risk function that knows the institution''s own
-- commitments. They are a starting point, not a citation.

INSERT INTO remediation_policies
    (tenant_id, code, name, description,
     critical_days, high_days, medium_days, low_days,
     exploited_days, dmz_days, cbs_days, swift_days, pci_days, minimum_days)
VALUES
-- Exactly what the platform did before any of this was configurable. No ceiling
-- applies, so adopting it changes not one deadline — which is the point: making
-- something configurable must not silently move the numbers it was computing.
(NULL, 'banking_default', 'Bancaire par défaut',
 'Les délais que la plateforme appliquait avant que ceci soit paramétrable : 3 / 7 / 30 / 90 jours, sans condition. L''adopter ne déplace aucune échéance. À garder tant que la fonction risque n''a pas tranché.',
 3, 7, 30, 90, NULL, NULL, NULL, NULL, NULL, 1),

-- What we would advise, and do not impose.
(NULL, 'exploit_aware', 'Piloté par l''exploitabilité',
 'Même base, mais une vulnérabilité réellement exploitée passe à 24 heures et une exposition en DMZ à 7 jours. Ce qui est attaqué aujourd''hui ne se traite pas au rythme de ce qui pourrait l''être un jour.',
 3, 7, 30, 90, 1, 7, NULL, NULL, NULL, 1),

(NULL, 'pci_dss', 'Orienté PCI DSS',
 'Le périmètre carte porte un engagement contractuel : tout constat sur un actif dans le périmètre est plafonné à 14 jours, quelle que soit sa sévérité. À utiliser quand l''évaluateur PCI est le lecteur principal.',
 3, 7, 30, 90, 1, 7, NULL, NULL, 14, 1),

(NULL, 'swift_cscf', 'Orienté SWIFT CSCF',
 'La zone de paiement et le core banking sont plafonnés à 7 jours. À utiliser quand l''attestation CSCF est le lecteur principal du reporting de remédiation.',
 3, 7, 30, 90, 1, 7, 7, 7, NULL, 1),

(NULL, 'dora_critical', 'Orienté DORA — fonctions critiques',
 'Resserre tout ce qui touche une fonction critique ou importante : core banking et paiements à 5 jours, DMZ à 5 jours, exploité à 24 heures. À utiliser quand le registre DORA pilote la priorisation.',
 2, 5, 21, 60, 1, 5, 5, 5, 14, 1)
ON CONFLICT DO NOTHING;

-- ─── The policy in force, for whoever computes a deadline ────────────────────
--
-- A published shape rather than a shared table: the vulnerability service reads
-- the policy, it never writes it, and the fallback to the standard lives here
-- rather than in each caller.
CREATE OR REPLACE VIEW tenant_remediation_policy AS
SELECT
    t.id AS tenant_id,
    COALESCE(own.id,   std.id)   AS policy_id,
    COALESCE(own.code, std.code) AS code,
    COALESCE(own.version, std.version) AS version,
    own.id IS NOT NULL AS chosen,
    COALESCE(own.critical_days, std.critical_days) AS critical_days,
    COALESCE(own.high_days,     std.high_days)     AS high_days,
    COALESCE(own.medium_days,   std.medium_days)   AS medium_days,
    COALESCE(own.low_days,      std.low_days)      AS low_days,
    CASE WHEN own.id IS NOT NULL THEN own.exploited_days ELSE std.exploited_days END AS exploited_days,
    CASE WHEN own.id IS NOT NULL THEN own.dmz_days       ELSE std.dmz_days       END AS dmz_days,
    CASE WHEN own.id IS NOT NULL THEN own.cbs_days       ELSE std.cbs_days       END AS cbs_days,
    CASE WHEN own.id IS NOT NULL THEN own.swift_days     ELSE std.swift_days     END AS swift_days,
    CASE WHEN own.id IS NOT NULL THEN own.pci_days       ELSE std.pci_days       END AS pci_days,
    COALESCE(own.minimum_days, std.minimum_days) AS minimum_days
FROM tenants t
LEFT JOIN remediation_policies own
       ON own.tenant_id = t.id AND own.effective_to IS NULL
CROSS JOIN LATERAL (
    SELECT * FROM remediation_policies
    WHERE tenant_id IS NULL AND code = 'banking_default' AND effective_to IS NULL
) std;

COMMENT ON VIEW tenant_remediation_policy IS
  'The remediation deadlines in force for each tenant: their own policy, or the standard one when they have not chosen. A nullable ceiling is taken from whichever policy applies, never mixed between the two.';
