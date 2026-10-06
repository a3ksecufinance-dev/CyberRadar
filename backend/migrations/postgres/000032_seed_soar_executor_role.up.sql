-- Migration: 000032_seed_soar_executor_role
-- The SOAR can now act, so it needs the rights to do so — and no more.
--
-- Its playbook actions call the platform's own services with a service-account
-- token, and every one of those routes checks a permission. Without this role
-- every remediation step would fail with 403, which is the correct failure but
-- a useless product.
--
-- This is a separate role from platform_service on purpose. platform_service
-- is for a service writing about its own activity; these are rights to change
-- a customer's environment — disable an account, deny traffic, isolate a host
-- — and they should be visible as their own grant, reviewable on their own.

INSERT INTO roles (id, tenant_id, name, description, is_system) VALUES
    ('10000000-0000-0000-0000-000000000014', '00000000-0000-0000-0000-000000000001',
     'soar_executor', 'Carries out automated playbook remediation', true)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON (p.resource, p.action) IN (
    -- block_ip, unblock_ip, isolate_host, unisolate_host
    ('netsec', 'write'),
    -- disable_user (DELETE on the identity) and enable_user
    ('users', 'delete'), ('users', 'write'),
    -- isolate_host resolves an asset to its address; tag_entity reads then writes
    ('assets', 'read'), ('assets', 'write'),
    -- enrich_ioc, add_to_blocklist
    ('threat_intel', 'write'),
    -- create_ticket, close_ticket
    ('vulnerabilities', 'write'),
    -- send_notification
    ('notifications', 'write'),
    -- run_siem_query
    ('alerts', 'read'),
    -- create_incident
    ('incidents', 'write'),
    -- mark_compromised
    ('attack_paths', 'write')
)
WHERE r.name = 'soar_executor'
  AND r.tenant_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;

-- Deliberately absent: anything :delete beyond users, and every read right the
-- actions do not need. A captured SOAR credential should not be a way to read
-- a customer's alerts, assets or vulnerabilities at will.
