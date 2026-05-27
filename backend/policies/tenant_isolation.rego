package crp.tenant_isolation

import future.keywords.if
import future.keywords.in

# ─── Tenant isolation enforcement ────────────────────────────────────────────
# Every data-access decision must pass this policy.
# input.user.tenant_id  — caller's tenant (from verified JWT)
# input.resource.tenant_id — resource's tenant (from DB row)

default allow := false

# Same-tenant access is always permitted for authenticated callers.
allow if {
    input.user.tenant_id != ""
    input.user.tenant_id == input.resource.tenant_id
}

# Platform super-admin can access any tenant's resources.
allow if {
    input.user.is_super_admin == true
}

# MSSP parent-tenant access to child-tenant resources.
allow if {
    input.user.tenant_id != ""
    some child in data.tenant_tree[input.user.tenant_id]
    child == input.resource.tenant_id
}

# ─── Hierarchical listing ─────────────────────────────────────────────────────
# Returns all tenant IDs the caller is authorized to see.

visible_tenants[tid] if {
    tid := input.user.tenant_id
}

visible_tenants[tid] if {
    input.user.is_super_admin == true
    some tid in data.all_tenants
}

visible_tenants[tid] if {
    some tid in data.tenant_tree[input.user.tenant_id]
}

# ─── Write isolation ─────────────────────────────────────────────────────────
# Writes (create / update / delete) are restricted to the caller's own tenant
# unless the caller is super-admin.

default allow_write := false

allow_write if {
    allow
    # Non-super-admin callers can only mutate their own tenant's data.
    input.user.tenant_id == input.resource.tenant_id
}

allow_write if {
    input.user.is_super_admin == true
}
