-- Migration: 000040_detection_library
--
-- A detection engine with an empty rule table is a detection engine that
-- detects nothing. Every customer then writes the same fifteen rules that every
-- other customer writes, badly, from memory, and nobody can say what the
-- platform covers.
--
-- So the platform ships detection content, the tenant adopts what fits, tunes
-- it, and writes its own in the same grammar. Same shape as the risk profiles
-- (000039), for the same reason: what to detect is a judgement, and the vendor's
-- job is to bring a defensible starting point, not to decide.
--
-- The lineage is the point. A tenant rule records which catalogue entry it came
-- from and at which content version, so three questions have answers:
--
--   What do we run that CyberRadar shipped, and what did we change about it?
--   — the difference from the catalogue entry, computed on read so it cannot
--     go stale.
--
--   Has the platform improved a rule we adopted?
--   — the catalogue entry's version is higher than the one we adopted.
--
--   What do we cover, and against which framework?
--   — the catalogue carries the ATT&CK mapping and the control references, so
--     coverage is a query rather than a spreadsheet.
--
-- Two things the catalogue does that a list of rules would not:
--
--   It declares what a rule needs. A detection keyed on a field nothing
--   populates loads, matches nothing, and looks like working coverage — which
--   is worse than no rule. Those entries ship disabled, with the reason.
--
--   It carries the reasoning: why the detection exists, what legitimately trips
--   it, and what to do when it fires. An analyst at three in the morning needs
--   the third one, and a rule without it is a pager that says nothing.

CREATE TABLE IF NOT EXISTS detection_content (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- A stable identifier that survives renaming. It is what a tenant rule
    -- points at, and what an audit report cites.
    code        VARCHAR(40)  NOT NULL,
    version     INT          NOT NULL DEFAULT 1,

    title       VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL,

    category        VARCHAR(50)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL
                        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    mitre_tactic    VARCHAR(10),
    mitre_technique VARCHAR(10),

    -- The rule, in the engine's own grammar. Nothing here is a new dialect:
    -- what the catalogue ships is what a tenant could have written.
    conditions     JSONB NOT NULL,
    actions        JSONB NOT NULL DEFAULT '[]',
    dedup_window_s INT   NOT NULL DEFAULT 300,

    -- Why it exists, what trips it legitimately, what to do. The third is what
    -- an analyst needs at three in the morning.
    rationale       TEXT NOT NULL,
    false_positives TEXT,
    response        TEXT,

    -- Which frameworks this detection helps evidence, and the control it maps
    -- to. A compliance report can then cite the rules that support a control
    -- rather than asserting the control is met.
    frameworks TEXT[] NOT NULL DEFAULT '{}',
    controls   TEXT[] NOT NULL DEFAULT '{}',

    -- What has to be in place for it to fire at all: a connector, an
    -- enrichment, a licensed database. Empty means it works on what the
    -- platform already produces.
    requires TEXT[] NOT NULL DEFAULT '{}',

    -- A rule that cannot fire yet ships off, with requires saying why. Enabling
    -- it by default would present coverage the platform does not have.
    enabled_by_default BOOLEAN NOT NULL DEFAULT true,

    tags       TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ,

    CONSTRAINT detection_content_version_positive CHECK (version >= 1)
);

-- One current version per code. Superseding sets retired_at on the old row, so
-- a tenant that adopted v1 can still be told what v1 said.
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_content_current
    ON detection_content (code) WHERE retired_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_content_code_version
    ON detection_content (code, version);

CREATE INDEX IF NOT EXISTS idx_detection_content_technique
    ON detection_content (mitre_technique) WHERE retired_at IS NULL;

COMMENT ON TABLE detection_content IS
  'The detection rules the platform ships. A tenant adopts from here into detection_rules; the lineage columns there point back.';

-- ─── Lineage on a tenant's rules ─────────────────────────────────────────────

ALTER TABLE detection_rules
    -- The catalogue entry this rule was adopted from, and the version adopted.
    -- NULL for a rule the tenant wrote itself, which is a first-class case:
    -- the library is a starting point, not a cage.
    ADD COLUMN IF NOT EXISTS content_code    VARCHAR(40),
    ADD COLUMN IF NOT EXISTS content_version INT,
    -- When it was adopted, so "we have been running this since March" is an
    -- answer the platform can give.
    ADD COLUMN IF NOT EXISTS adopted_at      TIMESTAMPTZ;

-- A tenant adopts a catalogue entry once. Adopting it twice would double every
-- alert it raises, and the second copy would drift from the first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_adopted
    ON detection_rules (tenant_id, content_code) WHERE content_code IS NOT NULL;

COMMENT ON COLUMN detection_rules.content_code IS
  'The catalogue entry this rule came from, or NULL for a rule the tenant wrote. The difference from the entry is computed on read.';

-- ─── Le catalogue lui-même n'est plus ici ───────────────────────────────────
--
-- Fifteen detections used to be INSERT statements below this line. That made
-- improving one of them a schema change: a new migration, a rebuild, a
-- deployment window — for a sentence of rationale or a threshold somebody
-- wanted tightened. Content that can only ship with the code ships at the
-- code's cadence, which is the wrong cadence for detection content.
--
-- They now live as files under backend/content/detections, and `contentctl`
-- reconciles them with this table: it publishes a new version of any detection
-- whose content changed, retires any the pack no longer carries, and leaves the
-- rest — and their version numbers — alone.
--
-- The rows this migration created on databases that already ran it are kept.
-- The loader recognised them by content and adopted them rather than
-- republishing: converting where content lives moved no version number, and so
-- told no tenant that an update was available when nothing had changed.
--
-- A fresh database therefore has an empty catalogue until the loader runs. That
-- is deliberate — a schema migration that also carries content is the thing
-- this removed.
