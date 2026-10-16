-- ============================================================================
-- 000030 — Extend the permission catalogue to the remaining service domains
-- ============================================================================
-- 000002 declares permissions for 11 resources only, so the other services had
-- nothing to authorize against and could not be gated at all.
--
-- One resource per service domain. Actions are limited to read / write /
-- delete because authmw.RequirePermissionByMethod derives the action from the
-- HTTP method: GET is read, DELETE is delete, everything else is write.
-- "delete" is declared only for the domains that actually expose a DELETE
-- route, so it is never granted where nothing can be deleted.
--
-- The grants below follow the role descriptions seeded in 000002. They are a
-- defensible starting point, not a finished security policy: who may read OT
-- assets or approve privileged access is an organizational decision, and this
-- matrix should be reviewed before production.
-- ============================================================================

-- ─── Resources, one per service domain ──────────────────────────────────────
INSERT INTO permissions (resource, action, description) VALUES
    ('pam',             'read',   'View privileged accounts and sessions'),
    ('pam',             'write',  'Request, approve and revoke privileged access'),
    ('pam',             'delete', 'Delete privileged account records'),
    ('ueba',            'read',   'View behavioral analytics and anomalies'),
    ('ueba',            'write',  'Tune behavioral baselines and triage anomalies'),
    ('threat_intel',    'read',   'View indicators and threat actors'),
    ('threat_intel',    'write',  'Create and enrich indicators'),
    ('threat_intel',    'delete', 'Delete indicators'),
    ('vulnerabilities', 'read',   'View vulnerabilities and findings'),
    ('vulnerabilities', 'write',  'Triage findings and manage remediation'),
    ('soar',            'read',   'View playbook executions'),
    ('soar',            'write',  'Execute playbooks and response actions'),
    ('playbooks',       'read',   'View incident response playbooks'),
    ('playbooks',       'write',  'Author incident response playbooks'),
    ('attack_paths',    'read',   'View attack paths and choke points'),
    ('attack_paths',    'write',  'Manage attack path scenarios'),
    ('knowledge_graph', 'read',   'Query the cyber knowledge graph'),
    ('knowledge_graph', 'write',  'Create graph entities and relationships'),
    ('knowledge_graph', 'delete', 'Delete graph entities'),
    ('copilot',         'read',   'View AI assistant sessions'),
    ('copilot',         'write',  'Converse with the AI assistant'),
    ('api_keys',        'read',   'View API keys and webhooks'),
    ('api_keys',        'write',  'Create API keys and webhooks'),
    ('api_keys',        'delete', 'Revoke API keys and webhooks'),
    ('compliance',      'read',   'View frameworks, controls and assessments'),
    ('compliance',      'write',  'Manage controls and record assessments'),
    ('cspm',            'read',   'View cloud posture findings'),
    ('cspm',            'write',  'Manage cloud posture policies and exceptions'),
    ('dspm',            'read',   'View data stores and data findings'),
    ('dspm',            'write',  'Manage data policies and remediation'),
    ('dspm',            'delete', 'Delete data store records'),
    ('easm',            'read',   'View external attack surface'),
    ('easm',            'write',  'Manage external assets and scans'),
    ('easm',            'delete', 'Delete external asset records'),
    ('fraud',           'read',   'View fraud signals and cases'),
    ('fraud',           'write',  'Manage fraud rules and cases'),
    ('fraud',           'delete', 'Delete fraud records'),
    ('dlp',             'read',   'View data loss prevention events'),
    ('dlp',             'write',  'Manage data loss prevention policies'),
    ('netsec',          'read',   'View network security posture'),
    ('netsec',          'write',  'Manage network policies and blocks'),
    ('risk',            'read',   'View risk register and scores'),
    ('risk',            'write',  'Record and accept risks'),
    ('iga',             'read',   'View entitlements and access reviews'),
    ('iga',             'write',  'Manage entitlements and certification campaigns'),
    ('supply_chain',    'read',   'View third-party and component risk'),
    ('supply_chain',    'write',  'Manage vendors and assessments'),
    ('ot_assets',       'read',   'View OT and industrial assets'),
    ('ot_assets',       'write',  'Manage OT assets and patches'),
    ('mobile',          'read',   'View mobile devices and apps'),
    ('mobile',          'write',  'Manage mobile policies and actions'),
    ('mobile',          'delete', 'Delete device records'),
    ('notifications',   'read',   'View notifications'),
    ('notifications',   'write',  'Send and configure notifications')
ON CONFLICT (resource, action) DO NOTHING;

-- reports already exists with read/generate; the dashboard service also
-- mutates and deletes, which the method mapping expresses as write/delete.
INSERT INTO permissions (resource, action, description) VALUES
    ('reports', 'write',  'Create and update dashboards'),
    ('reports', 'delete', 'Delete dashboards')
ON CONFLICT (resource, action) DO NOTHING;

-- ─── Grants ─────────────────────────────────────────────────────────────────
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON (r.name, p.resource || ':' || p.action) IN (
        -- ─── auditor — read-only across every new domain ────────────────────
        ('auditor', 'pam:read'),             ('auditor', 'ueba:read'),
        ('auditor', 'threat_intel:read'),    ('auditor', 'vulnerabilities:read'),
        ('auditor', 'soar:read'),            ('auditor', 'playbooks:read'),
        ('auditor', 'attack_paths:read'),    ('auditor', 'knowledge_graph:read'),
        ('auditor', 'copilot:read'),         ('auditor', 'api_keys:read'),
        ('auditor', 'compliance:read'),      ('auditor', 'cspm:read'),
        ('auditor', 'dspm:read'),            ('auditor', 'easm:read'),
        ('auditor', 'fraud:read'),           ('auditor', 'dlp:read'),
        ('auditor', 'netsec:read'),          ('auditor', 'risk:read'),
        ('auditor', 'iga:read'),             ('auditor', 'supply_chain:read'),
        ('auditor', 'ot_assets:read'),       ('auditor', 'mobile:read'),
        ('auditor', 'notifications:read'),

        -- ─── ciso — oversight everywhere, and owns risk acceptance ──────────
        ('ciso', 'pam:read'),                ('ciso', 'ueba:read'),
        ('ciso', 'threat_intel:read'),       ('ciso', 'vulnerabilities:read'),
        ('ciso', 'soar:read'),               ('ciso', 'playbooks:read'),
        ('ciso', 'attack_paths:read'),       ('ciso', 'knowledge_graph:read'),
        ('ciso', 'copilot:read'),            ('ciso', 'copilot:write'),
        ('ciso', 'compliance:read'),         ('ciso', 'cspm:read'),
        ('ciso', 'dspm:read'),               ('ciso', 'easm:read'),
        ('ciso', 'fraud:read'),              ('ciso', 'dlp:read'),
        ('ciso', 'netsec:read'),             ('ciso', 'risk:read'),
        ('ciso', 'risk:write'),              ('ciso', 'iga:read'),
        ('ciso', 'supply_chain:read'),       ('ciso', 'ot_assets:read'),
        ('ciso', 'mobile:read'),             ('ciso', 'reports:write'),

        -- ─── tenant_admin — administrative domains, posture read-only ───────
        ('tenant_admin', 'pam:read'),            ('tenant_admin', 'pam:write'),
        ('tenant_admin', 'pam:delete'),          ('tenant_admin', 'iga:read'),
        ('tenant_admin', 'iga:write'),           ('tenant_admin', 'notifications:read'),
        ('tenant_admin', 'notifications:write'), ('tenant_admin', 'api_keys:read'),
        ('tenant_admin', 'api_keys:write'),      ('tenant_admin', 'api_keys:delete'),
        ('tenant_admin', 'copilot:read'),        ('tenant_admin', 'copilot:write'),
        ('tenant_admin', 'cspm:read'),           ('tenant_admin', 'dspm:read'),
        ('tenant_admin', 'easm:read'),           ('tenant_admin', 'netsec:read'),
        ('tenant_admin', 'mobile:read'),         ('tenant_admin', 'mobile:write'),
        ('tenant_admin', 'ot_assets:read'),      ('tenant_admin', 'supply_chain:read'),
        ('tenant_admin', 'vulnerabilities:read'),('tenant_admin', 'reports:write'),

        -- ─── soc_analyst_l1 — triage, read-only, may use the assistant ──────
        ('soc_analyst_l1', 'ueba:read'),          ('soc_analyst_l1', 'threat_intel:read'),
        ('soc_analyst_l1', 'vulnerabilities:read'),('soc_analyst_l1', 'attack_paths:read'),
        ('soc_analyst_l1', 'knowledge_graph:read'),('soc_analyst_l1', 'netsec:read'),
        ('soc_analyst_l1', 'soar:read'),          ('soc_analyst_l1', 'playbooks:read'),
        ('soc_analyst_l1', 'copilot:read'),       ('soc_analyst_l1', 'copilot:write'),

        -- ─── soc_analyst_l2 — L1 plus execution and triage authority ────────
        ('soc_analyst_l2', 'ueba:read'),          ('soc_analyst_l2', 'ueba:write'),
        ('soc_analyst_l2', 'threat_intel:read'),  ('soc_analyst_l2', 'threat_intel:write'),
        ('soc_analyst_l2', 'vulnerabilities:read'),('soc_analyst_l2', 'vulnerabilities:write'),
        ('soc_analyst_l2', 'attack_paths:read'),  ('soc_analyst_l2', 'knowledge_graph:read'),
        ('soc_analyst_l2', 'netsec:read'),        ('soc_analyst_l2', 'soar:read'),
        ('soc_analyst_l2', 'soar:write'),         ('soc_analyst_l2', 'playbooks:read'),
        ('soc_analyst_l2', 'copilot:read'),       ('soc_analyst_l2', 'copilot:write'),

        -- ─── threat_hunter — owns intelligence and graph exploration ────────
        ('threat_hunter', 'threat_intel:read'),   ('threat_hunter', 'threat_intel:write'),
        ('threat_hunter', 'threat_intel:delete'), ('threat_hunter', 'ueba:read'),
        ('threat_hunter', 'attack_paths:read'),   ('threat_hunter', 'attack_paths:write'),
        ('threat_hunter', 'knowledge_graph:read'),('threat_hunter', 'knowledge_graph:write'),
        ('threat_hunter', 'vulnerabilities:read'),('threat_hunter', 'soar:read'),
        ('threat_hunter', 'copilot:read'),        ('threat_hunter', 'copilot:write'),

        -- ─── incident_responder — contains and remediates ───────────────────
        ('incident_responder', 'soar:read'),        ('incident_responder', 'soar:write'),
        ('incident_responder', 'playbooks:read'),   ('incident_responder', 'playbooks:write'),
        ('incident_responder', 'netsec:read'),      ('incident_responder', 'netsec:write'),
        ('incident_responder', 'pam:read'),         ('incident_responder', 'threat_intel:read'),
        ('incident_responder', 'ueba:read'),        ('incident_responder', 'attack_paths:read'),
        ('incident_responder', 'ot_assets:read'),   ('incident_responder', 'mobile:read'),
        ('incident_responder', 'mobile:write'),     ('incident_responder', 'copilot:read'),
        ('incident_responder', 'copilot:write'),

        -- ─── fraud_analyst — fraud only, no infrastructure authority ────────
        ('fraud_analyst', 'fraud:read'),   ('fraud_analyst', 'fraud:write'),
        ('fraud_analyst', 'fraud:delete'), ('fraud_analyst', 'ueba:read'),
        ('fraud_analyst', 'risk:read'),    ('fraud_analyst', 'copilot:read'),
        ('fraud_analyst', 'copilot:write'),

        -- ─── compliance_officer — evidence across the posture domains ───────
        ('compliance_officer', 'compliance:read'),  ('compliance_officer', 'compliance:write'),
        ('compliance_officer', 'dspm:read'),        ('compliance_officer', 'dlp:read'),
        ('compliance_officer', 'iga:read'),         ('compliance_officer', 'risk:read'),
        ('compliance_officer', 'supply_chain:read'),('compliance_officer', 'mobile:read'),
        ('compliance_officer', 'ot_assets:read'),   ('compliance_officer', 'cspm:read'),
        ('compliance_officer', 'vulnerabilities:read'),

        -- ─── executive_viewer — risk and compliance headlines only ──────────
        ('executive_viewer', 'risk:read'), ('executive_viewer', 'compliance:read')
     )
ON CONFLICT (role_id, permission_id) DO NOTHING;
