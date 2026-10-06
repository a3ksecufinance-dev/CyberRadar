-- Migration: 000033_create_identity_activity_daily
-- Give the PAM's "7-day" and "30-day" figures a window to be true about.
--
-- identity_risk_profiles.events_7d, events_today, anomaly_count_7d,
-- anomaly_count_30d and priv_sessions_30d were incremented on every event and
-- never reset, decremented or recomputed anywhere in this repository. They
-- were lifetime totals shown to an analyst as rolling windows. The practical
-- consequence: ComputeBreakdown labels an identity "persistent risk" once
-- anomaly_count_30d passes three, so every identity eventually earns that
-- label and can never shed it — the signal degrades to noise, and an analyst
-- learns to ignore it.
--
-- A second defect rode along: the profile row was read, incremented in memory
-- and written back whole, so two replicas handling events for the same
-- identity lost one another's increments.
--
-- One row per identity per day. The windowed figures are then a SUM over the
-- last N days, and each event is an atomic upsert that adds to the day's row
-- rather than a read-modify-write of the profile.

CREATE TABLE IF NOT EXISTS identity_activity_daily (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

    -- UTC calendar day. "Today" therefore means the UTC day, consistently for
    -- every tenant, rather than whichever timezone a replica happens to run in.
    day           DATE NOT NULL,

    events        INT NOT NULL DEFAULT 0,
    anomalies     INT NOT NULL DEFAULT 0,
    priv_sessions INT NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant_id, identity_id, day)
);

-- The windowed read is "this identity, the last N days", so the index leads
-- with the identity and orders by day.
CREATE INDEX idx_identity_activity_lookup
    ON identity_activity_daily (tenant_id, identity_id, day DESC);

-- Retention: the widest window any figure uses is 30 days, so rows older than
-- that are dead weight. This index makes the purge cheap; the purge itself
-- runs in the PAM service, which is the only writer.
CREATE INDEX idx_identity_activity_day ON identity_activity_daily (day);
