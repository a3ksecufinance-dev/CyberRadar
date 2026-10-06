-- ============================================================================
-- 000029 — Seed role → permission assignments
-- ============================================================================
-- 000002 seeds the permissions and the system roles but never connects them,
-- so role_permissions was empty and every role carried no permission at all.
--
-- The matrix below is least-privilege: a role receives only what its job
-- requires. super_admin is deliberately absent — it bypasses the check
-- entirely via the is_admin claim, mirroring policies/rbac.rego.
-- ============================================================================

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON (r.name, p.resource || ':' || p.action) IN (
        -- ─── tenant_admin — full administration of its own tenant ───────────
        ('tenant_admin', 'users:read'),        ('tenant_admin', 'users:write'),
        ('tenant_admin', 'users:delete'),      ('tenant_admin', 'roles:read'),
        ('tenant_admin', 'roles:write'),       ('tenant_admin', 'config:read'),
        ('tenant_admin', 'config:write'),      ('tenant_admin', 'connectors:read'),
        ('tenant_admin', 'connectors:write'),  ('tenant_admin', 'connectors:delete'),
        ('tenant_admin', 'assets:read'),       ('tenant_admin', 'assets:write'),
        ('tenant_admin', 'audit:read'),        ('tenant_admin', 'reports:read'),
        ('tenant_admin', 'tenants:read'),

        -- ─── ciso — oversight, plus incident direction ──────────────────────
        ('ciso', 'alerts:read'),        ('ciso', 'incidents:read'),
        ('ciso', 'incidents:write'),    ('ciso', 'assets:read'),
        ('ciso', 'rules:read'),         ('ciso', 'reports:read'),
        ('ciso', 'reports:generate'),   ('ciso', 'audit:read'),
        ('ciso', 'config:read'),        ('ciso', 'users:read'),
        ('ciso', 'tenants:read'),

        -- ─── soc_analyst_l1 — triage only, no mutation ──────────────────────
        ('soc_analyst_l1', 'alerts:read'),     ('soc_analyst_l1', 'incidents:read'),
        ('soc_analyst_l1', 'assets:read'),     ('soc_analyst_l1', 'rules:read'),
        ('soc_analyst_l1', 'reports:read'),

        -- ─── soc_analyst_l2 — triage plus alert and incident handling ───────
        ('soc_analyst_l2', 'alerts:read'),     ('soc_analyst_l2', 'alerts:write'),
        ('soc_analyst_l2', 'alerts:suppress'), ('soc_analyst_l2', 'incidents:read'),
        ('soc_analyst_l2', 'incidents:write'), ('soc_analyst_l2', 'assets:read'),
        ('soc_analyst_l2', 'rules:read'),      ('soc_analyst_l2', 'reports:read'),

        -- ─── threat_hunter — authors detection rules ────────────────────────
        ('threat_hunter', 'alerts:read'),      ('threat_hunter', 'alerts:write'),
        ('threat_hunter', 'rules:read'),       ('threat_hunter', 'rules:write'),
        ('threat_hunter', 'assets:read'),      ('threat_hunter', 'incidents:read'),
        ('threat_hunter', 'reports:read'),

        -- ─── incident_responder — drives incidents to closure ───────────────
        ('incident_responder', 'incidents:read'),  ('incident_responder', 'incidents:write'),
        ('incident_responder', 'alerts:read'),     ('incident_responder', 'alerts:write'),
        ('incident_responder', 'alerts:suppress'), ('incident_responder', 'assets:read'),
        ('incident_responder', 'reports:read'),

        -- ─── fraud_analyst — fraud cases, no infrastructure access ──────────
        ('fraud_analyst', 'alerts:read'),      ('fraud_analyst', 'incidents:read'),
        ('fraud_analyst', 'incidents:write'),  ('fraud_analyst', 'reports:read'),
        ('fraud_analyst', 'reports:generate'),

        -- ─── compliance_officer — evidence and reporting ────────────────────
        ('compliance_officer', 'audit:read'),      ('compliance_officer', 'audit:export'),
        ('compliance_officer', 'reports:read'),    ('compliance_officer', 'reports:generate'),
        ('compliance_officer', 'config:read'),     ('compliance_officer', 'assets:read'),
        ('compliance_officer', 'users:read'),

        -- ─── auditor — strictly read-only, plus evidence export ─────────────
        ('auditor', 'alerts:read'),      ('auditor', 'assets:read'),
        ('auditor', 'audit:read'),       ('auditor', 'audit:export'),
        ('auditor', 'config:read'),      ('auditor', 'connectors:read'),
        ('auditor', 'incidents:read'),   ('auditor', 'reports:read'),
        ('auditor', 'roles:read'),       ('auditor', 'rules:read'),
        ('auditor', 'tenants:read'),     ('auditor', 'users:read'),

        -- ─── executive_viewer — dashboards only ─────────────────────────────
        ('executive_viewer', 'reports:read'),  ('executive_viewer', 'alerts:read')
     )
ON CONFLICT (role_id, permission_id) DO NOTHING;
