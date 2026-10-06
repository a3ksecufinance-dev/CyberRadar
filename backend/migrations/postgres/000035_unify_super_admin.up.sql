-- ============================================================================
-- 000035 — Make super_admin one thing instead of two
-- ============================================================================
-- The platform had two unrelated notions of administrator:
--
--   * the role named `super_admin`, seeded by 000002 and deliberately left out
--     of the grant matrix in 000029 on the grounds that it "bypasses the check
--     entirely";
--   * the column `identities.privilege_level`, whose value 'super_admin' is
--     what actually sets the `is_admin` claim on a token.
--
-- So granting someone the role called super_admin gave them nothing at all,
-- while a value in a descriptive column was the real switch. It fails closed,
-- which is why it went unnoticed, but an administrator who assigns the role
-- named "full platform access" does not get it, and an auditor reading
-- role_permissions cannot see what a platform operator may do — the row simply
-- is not there.
--
-- They are separated here along the axis that actually distinguishes them:
--
--   permissions answer WHAT a caller may do  → the matrix, for every role
--   is_admin answers WHOSE data they may do it to → cross-tenant scope
--
-- super_admin now holds every permission like any other role, so its authority
-- is enumerable, and it is also what grants the cross-tenant claim.
-- ============================================================================

-- ─── 1. super_admin holds every permission ──────────────────────────────────
-- Selected from the catalogue rather than listed, so this cannot drift from
-- the 82 permissions that exist today. A permission added by a later migration
-- must be granted there too; `TestSuperAdminHoldsEveryPermission` fails the
-- build if one is missed.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'super_admin'
ON CONFLICT DO NOTHING;

-- ─── 2. Nobody loses access ─────────────────────────────────────────────────
-- Anyone who was an administrator through the column becomes one through the
-- role, which is where the token now reads it from.
INSERT INTO identity_roles (identity_id, role_id)
SELECT i.id, r.id
FROM identities i
CROSS JOIN roles r
WHERE i.privilege_level = 'super_admin'
  AND r.name = 'super_admin'
ON CONFLICT DO NOTHING;

-- ─── 3. And the column follows the role ─────────────────────────────────────
-- privilege_level stays: PAM and UEBA score risk from it, and an identity that
-- can act across tenants is exactly the one those engines should watch most
-- closely. It is now a consequence of the role rather than a second switch.
UPDATE identities i
SET privilege_level = 'super_admin'
WHERE i.privilege_level <> 'super_admin'
  AND EXISTS (
    SELECT 1
    FROM identity_roles ir
    JOIN roles r ON r.id = ir.role_id
    WHERE ir.identity_id = i.id
      AND r.name = 'super_admin'
  );

COMMENT ON COLUMN identities.privilege_level IS
  'Descriptive: how privileged this identity is, used for risk scoring. '
  'Authority comes from roles — holding the super_admin role is what grants '
  'cross-tenant scope, not this column.';
