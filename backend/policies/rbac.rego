package crp.rbac

import future.keywords.if
import future.keywords.in

# ─── Main decision ────────────────────────────────────────────────────────────

# Allow if the user has the required permission via any assigned role.
default allow := false

allow if {
    required_permission := input.permission
    some role in input.user.roles
    some perm in data.role_permissions[role]
    perm == required_permission
}

# Super-admin bypass — granted access to every permission.
allow if {
    input.user.is_super_admin == true
}

# ─── Permission definitions ──────────────────────────────────────────────────
# These mirror the permissions seeded in 000002_create_identities.sql.
# In production, load from the database via OPA bundle or REST data API.

# data.role_permissions is expected to be loaded as OPA data, e.g.:
# {
#   "platform_admin":   ["tenants:create", "tenants:read", ...],
#   "tenant_admin":     ["users:create", "users:read", ...],
#   ...
# }

# ─── Tenant isolation check ──────────────────────────────────────────────────

# Verify the caller's tenant_id matches the resource's tenant_id.
tenant_match if {
    input.user.tenant_id == input.resource.tenant_id
}

# Super-admins can cross tenant boundaries.
tenant_match if {
    input.user.is_super_admin == true
}

# ─── Helper: effective permissions ───────────────────────────────────────────

effective_permissions[perm] if {
    some role in input.user.roles
    some perm in data.role_permissions[role]
}
