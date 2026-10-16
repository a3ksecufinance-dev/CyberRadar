-- Migration: 000048_drop_unwired_tables
--
-- ─── Cinq tables que rien n'a jamais lues ───────────────────────────────────
--
-- These five were declared with the schema of the domain they belonged to and
-- never wired to a line of Go. plan/22-ECART-PREVU-MESURE.md §3 counted them:
-- 137 of the 142 tables are really read or written, and these are the five
-- that are not.
--
-- A table with no code is worse than a missing table. A missing one is an
-- obvious gap; this kind answers "does the platform do X?" with a schema that
-- says yes while nothing implements it. A schema review concludes that
-- centralised configuration exists, because config_entries and config_history
-- are right there with their indexes, their foreign keys and an updated_at
-- trigger.
--
-- They are dropped rather than implemented because implementing them is other
-- work, already scheduled and already costed: the configuration epic
-- (US-FND-CFG-001 to 003) and notification escalation (US-FND-NOT-002) are in
-- lot L12 of plan/23-PLAN-EXECUTION.md, at 25 and 15 days. Dropping costs two
-- days and makes the schema honest today; L12 will create them again, with the
-- code that reads them, in the same commit.
--
-- What is NOT lost by dropping them:
--
--   · config_entries / config_history — no service ever wrote a config entry.
--     Configuration is read from the environment (see docs/04-configuration.md),
--     and the four versioned policies that DO exist live in their own tables
--     (risk_profiles, remediation_policies, behaviour_policies, attack_policies),
--     which are untouched here.
--   · notification_rules — notification channels and sends work and are wired;
--     only the escalation ruleset was never implemented.
--   · identity_privileges — privileges are carried by the RBAC tables
--     (roles, permissions, identity_roles), which are the ones authmw reads.
--   · asset_scans — vulnerability scan history lives in vuln_scans, which the
--     vuln service does use. This was a second, parallel scan table for the
--     asset domain that nothing ever filled.
--
-- Safe to run on a populated database: each is empty by construction, since no
-- code path can insert into a table no code names. The DROPs are ordered so a
-- referenced table goes after its referrer (config_history → config_entries);
-- no CASCADE, so if anything unexpected references one of these the migration
-- fails loudly instead of quietly removing it.

-- ─── Configuration (000003) ─────────────────────────────────────────────────
-- config_history carries a foreign key to config_entries, so it goes first.
DROP TABLE IF EXISTS config_history;
DROP TABLE IF EXISTS config_entries;

-- ─── Notification escalation (000003) ───────────────────────────────────────
DROP TABLE IF EXISTS notification_rules;

-- ─── Identity privileges (000002) ───────────────────────────────────────────
DROP TABLE IF EXISTS identity_privileges;

-- ─── Asset scan history (000004) ────────────────────────────────────────────
DROP TABLE IF EXISTS asset_scans;
