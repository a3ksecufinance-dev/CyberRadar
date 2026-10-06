-- ============================================================
-- The SOAR records what it does
-- ============================================================
--
-- A playbook acts under its own service account, by design: the analyst who
-- pressed run may not hold netsec:write, and an audit trail saying "the analyst
-- blocked 203.0.113.5" is false when all the analyst did was click. The design
-- was in place and documented, and the trail was empty — nothing wrote an entry
-- for an action a playbook carried out. A platform that contains a threat by
-- changing a firewall, isolating a host or disabling an account, and keeps no
-- record of having done so, cannot answer the one question an auditor asks.
--
-- The SOAR writes those entries now, as itself. For that it needs the one
-- permission its role was never given.

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'soar_executor'
  AND p.resource = 'audit'
  AND p.action = 'write'
ON CONFLICT DO NOTHING;
