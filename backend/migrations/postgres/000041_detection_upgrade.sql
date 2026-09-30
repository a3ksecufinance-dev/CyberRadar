-- ─── Bringing an adopted detection up to the current content version ─────────
--
-- Adoption already records which version a tenant took. This records when they
-- last moved, which is a different question and one an auditor asks: "you have
-- been running this since March — is it still the March detection?"
--
-- Kept apart from updated_at, which the table's trigger moves on any edit. A
-- rule whose name was corrected yesterday has not been brought up to a newer
-- detection, and a column that conflates the two cannot say so.

ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS content_upgraded_at TIMESTAMPTZ;

COMMENT ON COLUMN detection_rules.content_upgraded_at IS
  'When this rule was last brought to a newer catalogue version. NULL means it still runs the version it was adopted at.';

-- Why a tenant moved, or why they resolved a conflict the way they did. The
-- decision outlives the person who took it only if it is written down next to
-- what it decided.
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS lineage_notes TEXT;

COMMENT ON COLUMN detection_rules.lineage_notes IS
  'Why this rule was last brought to a newer catalogue version, and how any conflict with the tenant''s own changes was resolved.';
