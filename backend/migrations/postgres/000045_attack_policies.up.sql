-- ─── Ce qu'un attaquant trouve difficile, selon cet établissement ────────────
--
-- The attack-path weightings were Go constants: an edge costs 1.0, plus 1.5 if
-- the technique is hard, plus 1.0 if it needs administrative rights; each extra
-- hop takes 15% off a path's threat; reaching an unknown target is worth 4.5.
--
-- None of those are facts about attackers. They are a stance. An institution
-- that has run a red team and watched it cross the estate in an afternoon does
-- not weigh "high complexity" the way one reasoning from CVSS does, and a bank
-- whose board asks about the crown jewels does not weigh impact the way one
-- asked about exposure does. The numbers decide which path an analyst is shown
-- first, which is to say what gets fixed first.
--
-- Same shape as the other three: named columns, versioned, effective-dated.
-- "Why was this path ranked second in March" is a question about the weightings
-- that were in force in March, and a scenario run now records which version
-- scored it.

CREATE TABLE IF NOT EXISTS attack_policies (
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

    -- ── What a step costs an attacker ──────────────────────────────────────
    -- Cost is effort: higher means the attacker is less likely to take it, so
    -- the path ranks lower. The base is what any step costs before anything is
    -- known about it.
    base_cost             FLOAT NOT NULL DEFAULT 1.0,
    complexity_medium     FLOAT NOT NULL DEFAULT 0.5,
    complexity_high       FLOAT NOT NULL DEFAULT 1.5,
    privilege_low         FLOAT NOT NULL DEFAULT 0.3,
    privilege_high        FLOAT NOT NULL DEFAULT 1.0,

    -- ── How distance protects you ──────────────────────────────────────────
    -- Each extra hop multiplies a path's threat by this. 1.0 is the
    -- assume-breach stance: once inside, distance is not a control.
    hop_decay             FLOAT NOT NULL DEFAULT 0.85,

    -- ── What reaching a target is worth ────────────────────────────────────
    -- The ceiling is deliberately below 10 so the critical-system bonus has
    -- somewhere to go; mapping criticality straight onto 0–10 saturates at the
    -- top level and the flag stops distinguishing what it exists to distinguish.
    impact_ceiling        FLOAT NOT NULL DEFAULT 9.0,
    -- What to assume when the inventory records nothing about the target. High
    -- means an unknown is treated as dangerous — safer, noisier.
    unknown_target_impact FLOAT NOT NULL DEFAULT 4.5,
    critical_system_bonus FLOAT NOT NULL DEFAULT 1.0,

    -- ── Many ways in ───────────────────────────────────────────────────────
    -- Added as boost × ln(1 + paths), so the tenth route matters less than the
    -- second. Zero means the count does not move the scenario's risk at all.
    many_paths_boost      FLOAT NOT NULL DEFAULT 0.3,

    notes           TEXT,
    created_by      UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT attack_cost_sane CHECK (
        base_cost BETWEEN 0.1 AND 10 AND
        complexity_medium BETWEEN 0 AND 10 AND complexity_high BETWEEN 0 AND 10 AND
        privilege_low BETWEEN 0 AND 10 AND privilege_high BETWEEN 0 AND 10
    ),
    -- A decay above 1 would make a longer path more threatening than a shorter
    -- one of the same cost, which is the bug this formula was written to fix.
    CONSTRAINT attack_decay_sane CHECK (hop_decay > 0 AND hop_decay <= 1),
    CONSTRAINT attack_impact_sane CHECK (
        impact_ceiling BETWEEN 1 AND 10 AND
        unknown_target_impact BETWEEN 0 AND 10 AND
        critical_system_bonus BETWEEN 0 AND 10
    ),
    CONSTRAINT attack_boost_sane CHECK (many_paths_boost BETWEEN 0 AND 5),
    CONSTRAINT attack_version_positive CHECK (version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_policy_active
    ON attack_policies (tenant_id) WHERE tenant_id IS NOT NULL AND effective_to IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_policy_standard
    ON attack_policies (code) WHERE tenant_id IS NULL AND effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_attack_policy_history
    ON attack_policies (tenant_id, version DESC) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE attack_policies IS
  'What an institution considers hard for an attacker. The numbers decide which path an analyst is shown first, which is to say what gets fixed first.';

-- ─── The standard policies ───────────────────────────────────────────────────

INSERT INTO attack_policies
    (tenant_id, code, name, description,
     base_cost, complexity_medium, complexity_high, privilege_low, privilege_high,
     hop_decay, impact_ceiling, unknown_target_impact, critical_system_bonus,
     many_paths_boost)
VALUES
-- Exactly the constants the analyzer used before any of this was configurable.
-- Adopting it re-ranks nothing.
(NULL, 'balanced', 'Équilibré (par défaut)',
 'Les pondérations que l''analyseur appliquait avant que ceci soit paramétrable. L''adopter ne change le classement d''aucun chemin. À garder tant que l''équipe n''a pas d''avis arrêté.',
 1.0, 0.5, 1.5, 0.3, 1.0, 0.85, 9.0, 4.5, 1.0, 0.3),

-- The stance of a team that has watched a red team cross the estate.
(NULL, 'assume_breach', 'Compromission présumée',
 'Part du principe qu''un attaquant déjà entré est compétent : la complexité et les privilèges le freinent peu, et la distance ne protège pas (décroissance 1.0). Beaucoup plus de chemins ressortent comme praticables — c''est le but, et c''est bruyant. À utiliser après un exercice d''équipe rouge qui a traversé le parc.',
 1.0, 0.2, 0.6, 0.1, 0.4, 1.0, 9.0, 5.5, 1.0, 0.4),

-- The opposite: an attack is only as real as its difficulty.
(NULL, 'exploitability_led', 'Piloté par l''exploitabilité',
 'Une attaque ne vaut que par sa difficulté réelle : complexité élevée et privilèges administrateur coûtent cher, et chaque saut retire un quart de la menace. Moins de chemins, plus tranchés. Convient à une équipe qui doit prioriser un petit nombre de corrections.',
 1.0, 0.8, 2.5, 0.5, 2.0, 0.75, 9.0, 3.0, 1.0, 0.2),

-- When the board asks about the crown jewels.
(NULL, 'crown_jewels', 'Joyaux de la couronne',
 'L''impact domine : un système critique pèse deux points de plus et le plafond monte à 10. Un actif dont l''inventaire ne dit rien est supposé peu important (3.0) — c''est ce qui concentre l''attention, et c''est aussi par là qu''on passe à côté de quelque chose. À n''utiliser qu''avec un inventaire tenu.',
 1.0, 0.5, 1.5, 0.3, 1.0, 0.85, 10.0, 3.0, 2.0, 0.3)
ON CONFLICT DO NOTHING;

-- ─── The policy in force, for the analyzer ───────────────────────────────────
CREATE OR REPLACE VIEW tenant_attack_policy AS
SELECT
    t.id AS tenant_id,
    COALESCE(own.code, std.code)       AS code,
    COALESCE(own.version, std.version) AS version,
    own.id IS NOT NULL                 AS chosen,
    COALESCE(own.base_cost,         std.base_cost)         AS base_cost,
    COALESCE(own.complexity_medium, std.complexity_medium) AS complexity_medium,
    COALESCE(own.complexity_high,   std.complexity_high)   AS complexity_high,
    COALESCE(own.privilege_low,     std.privilege_low)     AS privilege_low,
    COALESCE(own.privilege_high,    std.privilege_high)    AS privilege_high,
    COALESCE(own.hop_decay,         std.hop_decay)         AS hop_decay,
    COALESCE(own.impact_ceiling,        std.impact_ceiling)        AS impact_ceiling,
    COALESCE(own.unknown_target_impact, std.unknown_target_impact) AS unknown_target_impact,
    COALESCE(own.critical_system_bonus, std.critical_system_bonus) AS critical_system_bonus,
    COALESCE(own.many_paths_boost,  std.many_paths_boost)  AS many_paths_boost
FROM tenants t
LEFT JOIN attack_policies own
       ON own.tenant_id = t.id AND own.effective_to IS NULL
CROSS JOIN LATERAL (
    SELECT * FROM attack_policies
    WHERE tenant_id IS NULL AND code = 'balanced' AND effective_to IS NULL
) std;

COMMENT ON VIEW tenant_attack_policy IS
  'The attack-path weightings in force for each tenant: their own, or the standard ones when they have not chosen.';

-- ─── Which weightings scored this run ────────────────────────────────────────
--
-- Without this, a scenario's risk score is a number with no provenance: re-run
-- it after the weightings move and the old figure in a report becomes
-- irreproducible with nothing recording why.
ALTER TABLE attack_scenarios
    ADD COLUMN IF NOT EXISTS policy_code    VARCHAR(40),
    ADD COLUMN IF NOT EXISTS policy_version INT;

COMMENT ON COLUMN attack_scenarios.policy_code IS
  'The weightings this scenario was last scored under. A risk score without it cannot be reproduced.';
