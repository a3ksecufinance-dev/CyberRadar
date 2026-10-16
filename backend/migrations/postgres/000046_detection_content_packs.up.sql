-- ─── Le catalogue se livre sans le code ──────────────────────────────────────
--
-- The fifteen detections arrived as INSERT statements inside migration 000040.
-- That made improving one of them a schema change: a new migration, a rebuild,
-- a deployment window — for a sentence of rationale or a threshold somebody
-- wanted tightened. Content that can only ship with the code ships at the
-- code's cadence, which is the wrong cadence for detection content.
--
-- They now live as files, and a loader reconciles them with this table. These
-- columns are what makes that reconciliation honest rather than destructive.

ALTER TABLE detection_content
    -- The fingerprint of everything that decides what the detection does and
    -- says. The loader compares it to decide whether a file is a new version or
    -- the one already published.
    --
    -- Derived rather than declared, because a version number in a file is a
    -- number somebody forgets to change — and a forgotten bump means a tenant
    -- on v1 is told they are current while running something else.
    ADD COLUMN IF NOT EXISTS content_hash CHAR(64),

    -- Which content release introduced this version. "We are running 2026.10.1"
    -- has to be answerable without reading fifteen rows.
    ADD COLUMN IF NOT EXISTS pack_version VARCHAR(40);

COMMENT ON COLUMN detection_content.content_hash IS
  'Fingerprint of the substantive fields. The loader publishes a new version when a file''s hash differs from the current row''s, and leaves it alone when it matches.';

CREATE INDEX IF NOT EXISTS idx_detection_content_pack
    ON detection_content (pack_version) WHERE pack_version IS NOT NULL;

-- ─── What was loaded, and when ───────────────────────────────────────────────
--
-- "When did our catalogue last change, and what moved" is an operational
-- question, and before this the only answer was to diff created_at across
-- fifteen rows and hope.
CREATE TABLE IF NOT EXISTS detection_content_loads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    pack_name     VARCHAR(100) NOT NULL,
    pack_version  VARCHAR(40)  NOT NULL,

    -- Where it came from: a directory on a deployment, or the pack's own
    -- identifier. Recorded because a catalogue loaded from somebody's laptop
    -- and one loaded from a release are not the same claim.
    source        TEXT NOT NULL,

    -- What the reconciliation did. Unchanged is reported too: a load that
    -- changes nothing is the normal case and has to be distinguishable from a
    -- load that did not run.
    published     INT NOT NULL DEFAULT 0,
    retired       INT NOT NULL DEFAULT 0,
    unchanged     INT NOT NULL DEFAULT 0,

    loaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT content_load_counts_sane CHECK (
        published >= 0 AND retired >= 0 AND unchanged >= 0
    )
);

CREATE INDEX IF NOT EXISTS idx_content_loads_recent
    ON detection_content_loads (loaded_at DESC);

COMMENT ON TABLE detection_content_loads IS
  'Each reconciliation of the detection catalogue with a content pack: which pack, from where, and what moved.';
