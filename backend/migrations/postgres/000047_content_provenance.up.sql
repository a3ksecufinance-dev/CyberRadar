-- ─── D'où vient ce catalogue ────────────────────────────────────────────────
--
-- The load record says which pack version was loaded and what moved. It does
-- not say whether anybody could tell where that pack came from — and a
-- catalogue assembled from a directory on somebody's laptop and one from a
-- signed release are not the same claim, however identical their contents.
--
-- These two columns are the difference between "we are running 2026.10.1" and
-- "we are running 2026.10.1, signed by the key we trust, and here is its
-- digest". The second is the one an auditor is asking for.

ALTER TABLE detection_content_loads
    -- The identifier of the key whose signature was verified. NULL means the
    -- pack was loaded unsigned, which is a legitimate thing to do while
    -- authoring and a thing that has to be visible afterwards.
    ADD COLUMN IF NOT EXISTS signed_by   VARCHAR(64),

    -- The digest of the signed manifest. Two deployments claiming the same
    -- version can be compared on this; the version alone is a label anybody
    -- can write.
    ADD COLUMN IF NOT EXISTS pack_digest CHAR(64);

COMMENT ON COLUMN detection_content_loads.signed_by IS
  'The key whose signature was verified over this pack''s manifest. NULL means it was loaded unsigned.';
COMMENT ON COLUMN detection_content_loads.pack_digest IS
  'Digest of the signed manifest. Two deployments claiming one version are only running the same content if this matches.';
