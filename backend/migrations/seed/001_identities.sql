-- Seed: identities for the realm's users.
--
-- Keycloak authenticates; this platform authorises. A person the directory
-- knows and the platform does not gets a clear 403 rather than an empty
-- interface, which is the right answer — but it also means a fresh install has
-- nobody who can see anything until identities exist.
--
-- Emails match deployments/keycloak/import/cyberradar-realm.json. A role given
-- here must exist in the platform's roles table: the two vocabularies are not
-- the same, and the mapping is a judgement rather than a translation.
--
-- It is a file rather than a heredoc inside the native script so that the
-- Docker path runs the same statements, rather than a second copy free to
-- drift from this one.

WITH tenant AS (
    INSERT INTO tenants (name, slug, status)
    VALUES ('Banque Nationale de France', 'bnf', 'active')
    -- The unique indexes are partial (WHERE deleted_at IS NULL), so
    -- ON CONFLICT has to carry the same predicate to match one.
    ON CONFLICT (slug) WHERE deleted_at IS NULL DO UPDATE SET status = 'active'
    RETURNING id
), people(email, display_name, privilege, role_name) AS (
    VALUES
      ('admin@cyberradar.io', 'Platform Administrator', 'super_admin', 'super_admin'),
      ('ciso@almassira.ma',         'CISO',                  'elevated',    'ciso'),
      ('soc-l2@almassira.ma',       'SOC Analyst L2',        'standard',    'soc_analyst_l2'),
      ('soc-l1@almassira.ma',       'SOC Analyst L1',        'standard',    'soc_analyst_l1'),
      ('auditor@almassira.ma',      'Auditor',               'standard',    'auditor'),
      ('risk@almassira.ma',         'Risk Manager',          'standard',    'compliance_officer'),
      ('dpo@almassira.ma',          'Data Protection Officer','standard',   'compliance_officer')
), inserted AS (
    INSERT INTO identities (tenant_id, username, email, display_name, identity_type, privilege_level, status)
    SELECT tenant.id, split_part(p.email, '@', 1), p.email, p.display_name, 'user', p.privilege, 'active'
    FROM people p, tenant
    ON CONFLICT (tenant_id, username) WHERE deleted_at IS NULL DO UPDATE
      SET email = EXCLUDED.email,
          display_name = EXCLUDED.display_name,
          privilege_level = EXCLUDED.privilege_level,
          status = 'active'
    RETURNING id, email
)
INSERT INTO identity_roles (identity_id, role_id)
SELECT i.id, r.id
FROM inserted i
JOIN people p ON p.email = i.email
JOIN roles r ON r.name = p.role_name
ON CONFLICT DO NOTHING;
