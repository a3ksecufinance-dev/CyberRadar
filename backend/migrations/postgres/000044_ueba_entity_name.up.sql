-- ─── Qui est cette entité ────────────────────────────────────────────────────
--
-- ueba_profiles keys on entity_id, a UUID, and carried no name. That was fine
-- while nothing ever created a profile — which, until now, nothing did: the
-- engine resolved an entity only from user_id or asset_id, and a log line
-- carries a username, not a UUID. Every event was discarded one step after it
-- arrived, and ueba_profiles had zero rows on a platform that had ingested
-- thousands of events.
--
-- Now that a username becomes a stable derived identifier, the name has to be
-- stored beside it. A console showing "4f2a…c1" and no way to resolve it is not
-- an improvement on showing nothing.

ALTER TABLE ueba_profiles
    ADD COLUMN IF NOT EXISTS entity_name VARCHAR(255);

COMMENT ON COLUMN ueba_profiles.entity_name IS
  'What the source called this entity — a username or a hostname. entity_id may be derived from it, so this is the only human-readable form.';

CREATE INDEX IF NOT EXISTS idx_ueba_profiles_name
    ON ueba_profiles (tenant_id, entity_name) WHERE entity_name IS NOT NULL;
