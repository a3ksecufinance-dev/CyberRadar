package crp.abac

import future.keywords.if
import future.keywords.in

# ─── Attribute-Based Access Control ──────────────────────────────────────────
# Extends RBAC with dynamic attribute evaluation for fine-grained decisions.
#
# input.user        — {tenant_id, roles[], risk_score, mfa_verified, is_super_admin}
# input.resource    — {tenant_id, type, id, classification, owner_id}
# input.action      — e.g. "read", "write", "export", "approve"
# input.environment — {ip, time_utc, geo_country}

default allow := false

# ─── Rule 1: Base RBAC must pass first ───────────────────────────────────────
allow if {
    data.crp.rbac.allow
    not high_risk_block
    not mfa_required_block
    not geo_block
    not working_hours_required_block
}

# ─── Rule 2: Super-admin is unrestricted ────────────────────────────────────
allow if {
    input.user.is_super_admin == true
}

# ─── Risk-based blocks ───────────────────────────────────────────────────────

# Block high-risk users from sensitive write operations.
high_risk_block if {
    input.user.risk_score >= 0.8
    input.action in {"write", "delete", "export", "approve"}
}

# Require MFA for export and approval actions.
mfa_required_block if {
    input.action in {"export", "approve", "delete"}
    input.user.mfa_verified != true
}

# ─── Classification-based rules ──────────────────────────────────────────────

# Only analysts and above can read CONFIDENTIAL data.
allow if {
    input.resource.classification == "CONFIDENTIAL"
    some role in input.user.roles
    role in {"tenant_admin", "soc_analyst", "soc_lead", "incident_manager",
             "threat_hunter", "compliance_officer", "platform_admin"}
    data.crp.tenant_isolation.allow
}

# SECRET data restricted to admins and security leads.
allow if {
    input.resource.classification == "SECRET"
    some role in input.user.roles
    role in {"tenant_admin", "soc_lead", "platform_admin"}
    data.crp.tenant_isolation.allow
    input.user.mfa_verified == true
}

# ─── Geo-restriction ─────────────────────────────────────────────────────────

# Block access from sanctioned countries (configurable via OPA data).
geo_block if {
    some country in data.sanctioned_countries
    input.environment.geo_country == country
    not input.user.is_super_admin
}

# ─── Working hours restriction for write ops ─────────────────────────────────

working_hours_required_block if {
    # If tenant enforces working-hours-only writes.
    data.tenant_policies[input.user.tenant_id].restrict_writes_to_business_hours == true
    input.action in {"write", "delete", "approve"}
    hour := time.clock(time.now_ns())[0]
    not hour_in_business_range(hour)
}

hour_in_business_range(h) if {
    h >= 8
    h < 18
}
