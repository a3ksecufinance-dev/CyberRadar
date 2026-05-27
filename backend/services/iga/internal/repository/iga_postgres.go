package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/iga/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IGARepository handles all persistence for the IGA domain.
type IGARepository struct {
	pool *pgxpool.Pool
}

// NewIGARepository creates an IGARepository.
func NewIGARepository(pool *pgxpool.Pool) *IGARepository {
	return &IGARepository{pool: pool}
}

// ─── Roles ────────────────────────────────────────────────────────────────────

const roleSelect = `
SELECT r.id, r.tenant_id, r.name, r.description, r.role_type, r.category, r.owner,
       r.risk_level, r.is_active, r.requires_mfa, r.max_duration_days, r.metadata,
       r.created_at, r.updated_at,
       COUNT(a.id) FILTER (WHERE a.status='active') AS assignment_count
FROM iga_roles r
LEFT JOIN iga_role_assignments a ON a.role_id = r.id`

func scanRole(row pgx.Row) (*model.IGARole, error) {
	r := &model.IGARole{}
	err := row.Scan(
		&r.ID, &r.TenantID, &r.Name, &r.Description, &r.RoleType, &r.Category, &r.Owner,
		&r.RiskLevel, &r.IsActive, &r.RequiresMFA, &r.MaxDurationDays, &r.Metadata,
		&r.CreatedAt, &r.UpdatedAt, &r.AssignmentCount,
	)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *IGARepository) CreateRole(ctx context.Context, tenantID uuid.UUID, req *model.CreateRoleRequest) (*model.IGARole, error) {
	riskLevel := req.RiskLevel
	if riskLevel == "" {
		riskLevel = "low"
	}
	metadata := req.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO iga_roles
		(tenant_id, name, description, role_type, category, owner, risk_level,
		 requires_mfa, max_duration_days, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.RoleType, req.Category, req.Owner, riskLevel,
		req.RequiresMFA, req.MaxDurationDays, metadata,
	).Scan(&id)
	if err != nil {
		return nil, err
	}

	// Insert entitlements
	for _, e := range req.Entitlements {
		eType := e.EntitlementType
		if eType == "" {
			eType = "permission"
		}
		_, _ = r.pool.Exec(ctx, `INSERT INTO iga_role_entitlements
			(tenant_id, role_id, system_name, entitlement, entitlement_type)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (role_id, system_name, entitlement) DO NOTHING`,
			tenantID, id, e.SystemName, e.Entitlement, eType)
	}

	return r.GetRole(ctx, tenantID, id)
}

func (r *IGARepository) GetRole(ctx context.Context, tenantID, roleID uuid.UUID) (*model.IGARole, error) {
	row := r.pool.QueryRow(ctx,
		roleSelect+` WHERE r.id=$1 AND r.tenant_id=$2 GROUP BY r.id`,
		roleID, tenantID)
	role, err := scanRole(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Load entitlements
	role.Entitlements, _ = r.listEntitlements(ctx, tenantID, roleID)
	return role, nil
}

func (r *IGARepository) listEntitlements(ctx context.Context, tenantID, roleID uuid.UUID) ([]*model.RoleEntitlement, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, role_id, system_name, entitlement, entitlement_type, created_at
		FROM iga_role_entitlements WHERE role_id=$1 ORDER BY system_name, entitlement`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ents []*model.RoleEntitlement
	for rows.Next() {
		e := &model.RoleEntitlement{}
		if err := rows.Scan(&e.ID, &e.TenantID, &e.RoleID, &e.SystemName, &e.Entitlement, &e.EntitlementType, &e.CreatedAt); err != nil {
			return nil, err
		}
		ents = append(ents, e)
	}
	return ents, nil
}

func (r *IGARepository) ListRoles(ctx context.Context, tenantID uuid.UUID, roleType, riskLevel string, activeOnly bool, page, pageSize int) ([]*model.IGARole, int, error) {
	conditions := []string{"r.tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if activeOnly {
		conditions = append(conditions, "r.is_active=TRUE")
	}
	if roleType != "" {
		conditions = append(conditions, fmt.Sprintf("r.role_type=$%d", n))
		args = append(args, roleType)
		n++
	}
	if riskLevel != "" {
		conditions = append(conditions, fmt.Sprintf("r.risk_level=$%d", n))
		args = append(args, riskLevel)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_roles r `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, roleSelect+` `+where+
		fmt.Sprintf(` GROUP BY r.id ORDER BY r.name LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var roles []*model.IGARole
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, 0, err
		}
		roles = append(roles, role)
	}
	return roles, total, nil
}

func (r *IGARepository) UpdateRole(ctx context.Context, tenantID, roleID uuid.UUID, req *model.UpdateRoleRequest) (*model.IGARole, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1

	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, req.Description)
		n++
	}
	if req.Category != "" {
		sets = append(sets, fmt.Sprintf("category=$%d", n))
		args = append(args, req.Category)
		n++
	}
	if req.Owner != "" {
		sets = append(sets, fmt.Sprintf("owner=$%d", n))
		args = append(args, req.Owner)
		n++
	}
	if req.RiskLevel != "" {
		sets = append(sets, fmt.Sprintf("risk_level=$%d", n))
		args = append(args, req.RiskLevel)
		n++
	}
	if req.RequiresMFA != nil {
		sets = append(sets, fmt.Sprintf("requires_mfa=$%d", n))
		args = append(args, *req.RequiresMFA)
		n++
	}
	if req.MaxDurationDays != nil {
		sets = append(sets, fmt.Sprintf("max_duration_days=$%d", n))
		args = append(args, *req.MaxDurationDays)
		n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}
	if req.Metadata != nil {
		sets = append(sets, fmt.Sprintf("metadata=$%d", n))
		args = append(args, req.Metadata)
		n++
	}

	args = append(args, roleID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE iga_roles SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetRole(ctx, tenantID, roleID)
}

// ─── Role Assignments ─────────────────────────────────────────────────────────

const assignmentSelect = `
SELECT id, tenant_id, identity_id, identity_name, identity_email,
       role_id, role_name, assignment_type, status, justification,
       requested_by, approved_by, approved_at,
       valid_from, valid_until, last_reviewed_at, created_at, updated_at
FROM iga_role_assignments`

func scanAssignment(row pgx.Row) (*model.RoleAssignment, error) {
	a := &model.RoleAssignment{}
	var requestedBy, approvedBy *uuid.UUID
	err := row.Scan(
		&a.ID, &a.TenantID, &a.IdentityID, &a.IdentityName, &a.IdentityEmail,
		&a.RoleID, &a.RoleName, &a.AssignmentType, &a.Status, &a.Justification,
		&requestedBy, &approvedBy, &a.ApprovedAt,
		&a.ValidFrom, &a.ValidUntil, &a.LastReviewedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.RequestedBy = requestedBy
	a.ApprovedBy = approvedBy
	return a, nil
}

func (r *IGARepository) AssignRole(ctx context.Context, tenantID uuid.UUID, req *model.AssignRoleRequest, requestedBy uuid.UUID) (*model.RoleAssignment, error) {
	// Fetch role name
	var roleName string
	if err := r.pool.QueryRow(ctx, `SELECT name FROM iga_roles WHERE id=$1 AND tenant_id=$2`, req.RoleID, tenantID).Scan(&roleName); err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	assignType := req.AssignmentType
	if assignType == "" {
		assignType = model.AssignmentDirect
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO iga_role_assignments
		(tenant_id, identity_id, identity_name, identity_email,
		 role_id, role_name, assignment_type, justification, requested_by, valid_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant_id, identity_id, role_id) DO UPDATE SET
			status='active', assignment_type=EXCLUDED.assignment_type,
			justification=EXCLUDED.justification, valid_until=EXCLUDED.valid_until,
			updated_at=NOW()
		RETURNING id`,
		tenantID, req.IdentityID, req.IdentityName, req.IdentityEmail,
		req.RoleID, roleName, assignType, req.Justification, requestedBy, req.ValidUntil,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetAssignment(ctx, tenantID, id)
}

func (r *IGARepository) GetAssignment(ctx context.Context, tenantID, assignmentID uuid.UUID) (*model.RoleAssignment, error) {
	row := r.pool.QueryRow(ctx, assignmentSelect+` WHERE id=$1 AND tenant_id=$2`, assignmentID, tenantID)
	a, err := scanAssignment(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (r *IGARepository) ListAssignments(ctx context.Context, tenantID uuid.UUID, f model.ListAssignmentsFilter) ([]*model.RoleAssignment, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if f.IdentityID != nil {
		conditions = append(conditions, fmt.Sprintf("identity_id=$%d", n))
		args = append(args, *f.IdentityID)
		n++
	}
	if f.RoleID != nil {
		conditions = append(conditions, fmt.Sprintf("role_id=$%d", n))
		args = append(args, *f.RoleID)
		n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, f.Status)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_role_assignments `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 50
	}
	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)

	rows, err := r.pool.Query(ctx, assignmentSelect+` `+where+
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assignments []*model.RoleAssignment
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, 0, err
		}
		assignments = append(assignments, a)
	}
	return assignments, total, nil
}

func (r *IGARepository) UpdateAssignment(ctx context.Context, tenantID, assignmentID uuid.UUID, req *model.UpdateAssignmentRequest) (*model.RoleAssignment, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1

	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, req.Status)
		n++
	}
	if req.ValidUntil != nil {
		sets = append(sets, fmt.Sprintf("valid_until=$%d", n))
		args = append(args, *req.ValidUntil)
		n++
	}
	if req.Justification != "" {
		sets = append(sets, fmt.Sprintf("justification=$%d", n))
		args = append(args, req.Justification)
		n++
	}

	args = append(args, assignmentID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE iga_role_assignments SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetAssignment(ctx, tenantID, assignmentID)
}

// ExpireAssignments marks assignments past their valid_until as expired.
func (r *IGARepository) ExpireAssignments(ctx context.Context) (int64, error) {
	result, err := r.pool.Exec(ctx, `
		UPDATE iga_role_assignments SET status='expired', updated_at=NOW()
		WHERE status='active' AND valid_until IS NOT NULL AND valid_until < NOW()`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// ─── Campaigns ────────────────────────────────────────────────────────────────

const campaignSelect = `
SELECT id, tenant_id, name, description, campaign_type, scope, scope_filter,
       status, reviewer_type, total_items, reviewed_items, certified_items, revoked_items,
       start_date, due_date, completed_at, created_by, created_at, updated_at
FROM iga_campaigns`

func scanCampaign(row pgx.Row) (*model.Campaign, error) {
	c := &model.Campaign{}
	var createdBy *uuid.UUID
	err := row.Scan(
		&c.ID, &c.TenantID, &c.Name, &c.Description, &c.CampaignType, &c.Scope, &c.ScopeFilter,
		&c.Status, &c.ReviewerType, &c.TotalItems, &c.ReviewedItems, &c.CertifiedItems, &c.RevokedItems,
		&c.StartDate, &c.DueDate, &c.CompletedAt, &createdBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.CreatedBy = createdBy
	return c, nil
}

func (r *IGARepository) CreateCampaign(ctx context.Context, tenantID uuid.UUID, req *model.CreateCampaignRequest, createdBy uuid.UUID) (*model.Campaign, error) {
	scope := req.Scope
	if scope == "" {
		scope = "all"
	}
	reviewerType := req.ReviewerType
	if reviewerType == "" {
		reviewerType = "manager"
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO iga_campaigns
		(tenant_id, name, description, campaign_type, scope, scope_filter,
		 reviewer_type, due_date, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.CampaignType, scope, req.ScopeFilter,
		reviewerType, req.DueDate, createdBy,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetCampaign(ctx, tenantID, id)
}

func (r *IGARepository) GetCampaign(ctx context.Context, tenantID, campaignID uuid.UUID) (*model.Campaign, error) {
	row := r.pool.QueryRow(ctx, campaignSelect+` WHERE id=$1 AND tenant_id=$2`, campaignID, tenantID)
	c, err := scanCampaign(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (r *IGARepository) ListCampaigns(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*model.Campaign, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_campaigns `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, campaignSelect+` `+where+
		fmt.Sprintf(` ORDER BY due_date ASC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var campaigns []*model.Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, 0, err
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, total, nil
}

// LaunchCampaign sets status to active and populates review items from active assignments.
func (r *IGARepository) LaunchCampaign(ctx context.Context, tenantID, campaignID uuid.UUID) (*model.Campaign, error) {
	campaign, err := r.GetCampaign(ctx, tenantID, campaignID)
	if err != nil || campaign == nil {
		return campaign, err
	}

	// Build assignment query based on campaign scope
	assignmentQuery := `SELECT a.id, a.identity_id, a.identity_name, a.identity_email,
		a.role_id, a.role_name
		FROM iga_role_assignments a
		JOIN iga_roles ro ON ro.id = a.role_id
		WHERE a.tenant_id=$1 AND a.status='active'`
	args := []any{tenantID}

	switch campaign.Scope {
	case "privileged":
		assignmentQuery += ` AND ro.role_type='privileged'`
	case "role":
		if campaign.ScopeFilter != "" {
			assignmentQuery += ` AND ro.name=$2`
			args = append(args, campaign.ScopeFilter)
		}
	}

	rows, err := r.pool.Query(ctx, assignmentQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Insert review items
	count := 0
	for rows.Next() {
		var assignID, identityID, roleID uuid.UUID
		var identityName, identityEmail, roleName string
		if err := rows.Scan(&assignID, &identityID, &identityName, &identityEmail, &roleID, &roleName); err != nil {
			continue
		}
		// Compute risk flags
		flags, score := r.computeReviewRisk(ctx, tenantID, identityID, roleID)
		_, _ = r.pool.Exec(ctx, `INSERT INTO iga_review_items
			(tenant_id, campaign_id, identity_id, identity_name, identity_email,
			 role_id, role_name, assignment_id, risk_flags, risk_score)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT DO NOTHING`,
			tenantID, campaignID, identityID, identityName, identityEmail,
			roleID, roleName, assignID, flags, score)
		count++
	}

	// Update campaign
	_, err = r.pool.Exec(ctx, `UPDATE iga_campaigns SET status='active', total_items=$1, updated_at=NOW() WHERE id=$2`,
		count, campaignID)
	if err != nil {
		return nil, err
	}
	return r.GetCampaign(ctx, tenantID, campaignID)
}

func (r *IGARepository) computeReviewRisk(ctx context.Context, tenantID, identityID, roleID uuid.UUID) ([]string, int) {
	flags := []string{}
	score := 0

	// Check role risk level
	var roleType, riskLevel string
	r.pool.QueryRow(ctx, `SELECT role_type, risk_level FROM iga_roles WHERE id=$1`, roleID).Scan(&roleType, &riskLevel)
	if roleType == "privileged" {
		flags = append(flags, model.FlagPrivilegedRole)
		score += 30
	}
	if riskLevel == "critical" {
		score += 25
	} else if riskLevel == "high" {
		score += 15
	}

	// Check number of active roles for this identity
	var roleCount int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_role_assignments WHERE tenant_id=$1 AND identity_id=$2 AND status='active'`,
		tenantID, identityID).Scan(&roleCount)
	if roleCount > 10 {
		flags = append(flags, model.FlagExcessiveAccess)
		score += 20
	} else if roleCount > 5 {
		flags = append(flags, model.FlagMultipleRoles)
		score += 10
	}

	// Check SoD conflicts
	var sodCount int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_sod_violations WHERE tenant_id=$1 AND identity_id=$2 AND status='open'`,
		tenantID, identityID).Scan(&sodCount)
	if sodCount > 0 {
		flags = append(flags, model.FlagSoDConflict)
		score += 25
	}

	if score > 100 {
		score = 100
	}
	return flags, score
}

// ─── Review Items ─────────────────────────────────────────────────────────────

func (r *IGARepository) ListReviewItems(ctx context.Context, tenantID uuid.UUID, f model.ListReviewItemsFilter) ([]*model.ReviewItem, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if f.CampaignID != nil {
		conditions = append(conditions, fmt.Sprintf("campaign_id=$%d", n))
		args = append(args, *f.CampaignID)
		n++
	}
	if f.IdentityID != nil {
		conditions = append(conditions, fmt.Sprintf("identity_id=$%d", n))
		args = append(args, *f.IdentityID)
		n++
	}
	if f.Decision == "pending" {
		conditions = append(conditions, "decision IS NULL")
	} else if f.Decision != "" {
		conditions = append(conditions, fmt.Sprintf("decision=$%d", n))
		args = append(args, f.Decision)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_review_items `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 50
	}
	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)

	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, campaign_id, identity_id, identity_name, identity_email,
		       role_id, role_name, assignment_id, decision, decision_reason,
		       reviewer_id, reviewer_name, reviewed_at, risk_flags, risk_score, created_at
		FROM iga_review_items `+where+
		fmt.Sprintf(` ORDER BY risk_score DESC, created_at LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []*model.ReviewItem
	for rows.Next() {
		item := &model.ReviewItem{}
		var reviewerID *uuid.UUID
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.CampaignID, &item.IdentityID, &item.IdentityName, &item.IdentityEmail,
			&item.RoleID, &item.RoleName, &item.AssignmentID, &item.Decision, &item.DecisionReason,
			&reviewerID, &item.ReviewerName, &item.ReviewedAt, &item.RiskFlags, &item.RiskScore, &item.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.ReviewerID = reviewerID
		items = append(items, item)
	}
	return items, total, nil
}

func (r *IGARepository) SubmitReviewDecision(ctx context.Context, tenantID, itemID, reviewerID uuid.UUID, req *model.ReviewDecisionRequest) (*model.ReviewItem, error) {
	now := time.Now()
	_, err := r.pool.Exec(ctx, `
		UPDATE iga_review_items SET
			decision=$1, decision_reason=$2, reviewer_id=$3, reviewer_name=$4, reviewed_at=$5
		WHERE id=$6 AND tenant_id=$7 AND decision IS NULL`,
		req.Decision, req.DecisionReason, reviewerID, req.ReviewerName, now, itemID, tenantID)
	if err != nil {
		return nil, err
	}

	// Get the item to update campaign counters and potentially revoke assignment
	var item model.ReviewItem
	var reviewerIDScanned *uuid.UUID
	err = r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, campaign_id, identity_id, identity_name, identity_email,
		       role_id, role_name, assignment_id, decision, decision_reason,
		       reviewer_id, reviewer_name, reviewed_at, risk_flags, risk_score, created_at
		FROM iga_review_items WHERE id=$1`, itemID).Scan(
		&item.ID, &item.TenantID, &item.CampaignID, &item.IdentityID, &item.IdentityName, &item.IdentityEmail,
		&item.RoleID, &item.RoleName, &item.AssignmentID, &item.Decision, &item.DecisionReason,
		&reviewerIDScanned, &item.ReviewerName, &item.ReviewedAt, &item.RiskFlags, &item.RiskScore, &item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	item.ReviewerID = reviewerIDScanned

	// Update campaign counters
	if req.Decision == "certified" {
		_, _ = r.pool.Exec(ctx, `UPDATE iga_campaigns SET reviewed_items=reviewed_items+1, certified_items=certified_items+1, updated_at=NOW() WHERE id=$1`, item.CampaignID)
	} else if req.Decision == "revoked" {
		_, _ = r.pool.Exec(ctx, `UPDATE iga_campaigns SET reviewed_items=reviewed_items+1, revoked_items=revoked_items+1, updated_at=NOW() WHERE id=$1`, item.CampaignID)
		// Revoke the assignment
		if item.AssignmentID != nil {
			_, _ = r.pool.Exec(ctx, `UPDATE iga_role_assignments SET status='revoked', updated_at=NOW() WHERE id=$1`, *item.AssignmentID)
		}
	} else {
		_, _ = r.pool.Exec(ctx, `UPDATE iga_campaigns SET reviewed_items=reviewed_items+1, updated_at=NOW() WHERE id=$1`, item.CampaignID)
	}

	// Check if campaign is complete
	r.checkCampaignCompletion(ctx, item.CampaignID)

	return &item, nil
}

func (r *IGARepository) checkCampaignCompletion(ctx context.Context, campaignID uuid.UUID) {
	var total, reviewed int
	r.pool.QueryRow(ctx, `SELECT total_items, reviewed_items FROM iga_campaigns WHERE id=$1`, campaignID).Scan(&total, &reviewed)
	if total > 0 && reviewed >= total {
		_, _ = r.pool.Exec(ctx, `UPDATE iga_campaigns SET status='completed', completed_at=NOW(), updated_at=NOW() WHERE id=$1`, campaignID)
	}
}

// ─── SoD Policies ─────────────────────────────────────────────────────────────

func (r *IGARepository) CreateSoDPolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreateSoDPolicyRequest) (*model.SoDPolicy, error) {
	// Fetch role names
	var roleAName, roleBName string
	r.pool.QueryRow(ctx, `SELECT name FROM iga_roles WHERE id=$1 AND tenant_id=$2`, req.RoleAID, tenantID).Scan(&roleAName)
	r.pool.QueryRow(ctx, `SELECT name FROM iga_roles WHERE id=$1 AND tenant_id=$2`, req.RoleBID, tenantID).Scan(&roleBName)

	action := req.Action
	if action == "" {
		action = "block"
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO iga_sod_policies
		(tenant_id, name, description, role_a_id, role_a_name, role_b_id, role_b_name, severity, action)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.RoleAID, roleAName, req.RoleBID, roleBName, req.Severity, action,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetSoDPolicy(ctx, tenantID, id)
}

func (r *IGARepository) GetSoDPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.SoDPolicy, error) {
	p := &model.SoDPolicy{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, description, role_a_id, role_a_name, role_b_id, role_b_name,
		       severity, action, is_active, created_at, updated_at
		FROM iga_sod_policies WHERE id=$1 AND tenant_id=$2`, policyID, tenantID).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.RoleAID, &p.RoleAName, &p.RoleBID, &p.RoleBName,
		&p.Severity, &p.Action, &p.IsActive, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func (r *IGARepository) ListSoDPolicies(ctx context.Context, tenantID uuid.UUID) ([]*model.SoDPolicy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, name, description, role_a_id, role_a_name, role_b_id, role_b_name,
		       severity, action, is_active, created_at, updated_at
		FROM iga_sod_policies WHERE tenant_id=$1 AND is_active=TRUE ORDER BY severity DESC, name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*model.SoDPolicy
	for rows.Next() {
		p := &model.SoDPolicy{}
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Description, &p.RoleAID, &p.RoleAName, &p.RoleBID, &p.RoleBName,
			&p.Severity, &p.Action, &p.IsActive, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// DetectSoDViolations scans all active assignments for SoD conflicts.
func (r *IGARepository) DetectSoDViolations(ctx context.Context, tenantID uuid.UUID) (int, error) {
	policies, err := r.ListSoDPolicies(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	detected := 0
	for _, policy := range policies {
		// Find identities that have BOTH role_a and role_b active
		rows, err := r.pool.Query(ctx, `
			SELECT a1.identity_id, a1.identity_name, a1.identity_email
			FROM iga_role_assignments a1
			JOIN iga_role_assignments a2 ON a1.identity_id=a2.identity_id AND a1.tenant_id=a2.tenant_id
			WHERE a1.tenant_id=$1 AND a1.role_id=$2 AND a1.status='active'
			  AND a2.role_id=$3 AND a2.status='active'`,
			tenantID, policy.RoleAID, policy.RoleBID)
		if err != nil {
			continue
		}

		for rows.Next() {
			var identityID uuid.UUID
			var identityName, identityEmail string
			if err := rows.Scan(&identityID, &identityName, &identityEmail); err != nil {
				continue
			}
			// Insert violation (ignore duplicates)
			_, _ = r.pool.Exec(ctx, `INSERT INTO iga_sod_violations
				(tenant_id, policy_id, policy_name, identity_id, identity_name, identity_email,
				 role_a_id, role_a_name, role_b_id, role_b_name, severity)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT DO NOTHING`,
				tenantID, policy.ID, policy.Name, identityID, identityName, identityEmail,
				policy.RoleAID, policy.RoleAName, policy.RoleBID, policy.RoleBName, policy.Severity)
			detected++
		}
		rows.Close()
	}
	return detected, nil
}

func (r *IGARepository) ListSoDViolations(ctx context.Context, tenantID uuid.UUID, status, severity string, page, pageSize int) ([]*model.SoDViolation, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}
	if severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", n))
		args = append(args, severity)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_sod_violations `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, policy_id, policy_name, identity_id, identity_name, identity_email,
		       role_a_id, role_a_name, role_b_id, role_b_name, severity, status,
		       exception_reason, exception_by, exception_at, detected_at, created_at
		FROM iga_sod_violations `+where+
		fmt.Sprintf(` ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var violations []*model.SoDViolation
	for rows.Next() {
		v := &model.SoDViolation{}
		var exceptionBy *uuid.UUID
		if err := rows.Scan(
			&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyName, &v.IdentityID, &v.IdentityName, &v.IdentityEmail,
			&v.RoleAID, &v.RoleAName, &v.RoleBID, &v.RoleBName, &v.Severity, &v.Status,
			&v.ExceptionReason, &exceptionBy, &v.ExceptionAt, &v.DetectedAt, &v.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		v.ExceptionBy = exceptionBy
		violations = append(violations, v)
	}
	return violations, total, nil
}

func (r *IGARepository) UpdateViolation(ctx context.Context, tenantID, violationID, updatedBy uuid.UUID, req *model.UpdateViolationRequest) (*model.SoDViolation, error) {
	sets := []string{fmt.Sprintf("status=$1")}
	args := []any{req.Status}
	n := 2

	if req.ExceptionReason != "" {
		sets = append(sets, fmt.Sprintf("exception_reason=$%d", n))
		args = append(args, req.ExceptionReason)
		n++
		sets = append(sets, fmt.Sprintf("exception_by=$%d", n))
		args = append(args, updatedBy)
		n++
		sets = append(sets, "exception_at=NOW()")
	}

	args = append(args, violationID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE iga_sod_violations SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}

	v := &model.SoDViolation{}
	var exceptionBy *uuid.UUID
	err = r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, policy_id, policy_name, identity_id, identity_name, identity_email,
		       role_a_id, role_a_name, role_b_id, role_b_name, severity, status,
		       exception_reason, exception_by, exception_at, detected_at, created_at
		FROM iga_sod_violations WHERE id=$1 AND tenant_id=$2`, violationID, tenantID).Scan(
		&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyName, &v.IdentityID, &v.IdentityName, &v.IdentityEmail,
		&v.RoleAID, &v.RoleAName, &v.RoleBID, &v.RoleBName, &v.Severity, &v.Status,
		&v.ExceptionReason, &exceptionBy, &v.ExceptionAt, &v.DetectedAt, &v.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	v.ExceptionBy = exceptionBy
	return v, err
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *IGARepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.IGAStats, error) {
	stats := &model.IGAStats{
		RolesByType:          map[string]int{},
		AssignmentsByStatus:  map[string]int{},
		ViolationsBySeverity: map[string]int{},
	}

	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_roles WHERE tenant_id=$1 AND is_active=TRUE`, tenantID).Scan(&stats.TotalRoles)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_role_assignments WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&stats.TotalAssignments)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_campaigns WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&stats.ActiveCampaigns)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_review_items WHERE tenant_id=$1 AND decision IS NULL`, tenantID).Scan(&stats.PendingReviews)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_sod_violations WHERE tenant_id=$1 AND status='open'`, tenantID).Scan(&stats.OpenSoDViolations)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iga_role_assignments WHERE tenant_id=$1 AND status='active' AND valid_until BETWEEN NOW() AND NOW()+INTERVAL '7 days'`, tenantID).Scan(&stats.ExpiringSoon)

	typeRows, _ := r.pool.Query(ctx, `SELECT role_type, COUNT(*) FROM iga_roles WHERE tenant_id=$1 AND is_active=TRUE GROUP BY role_type`, tenantID)
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var t string
			var c int
			typeRows.Scan(&t, &c)
			stats.RolesByType[t] = c
		}
	}

	statusRows, _ := r.pool.Query(ctx, `SELECT status, COUNT(*) FROM iga_role_assignments WHERE tenant_id=$1 GROUP BY status`, tenantID)
	if statusRows != nil {
		defer statusRows.Close()
		for statusRows.Next() {
			var s string
			var c int
			statusRows.Scan(&s, &c)
			stats.AssignmentsByStatus[s] = c
		}
	}

	sevRows, _ := r.pool.Query(ctx, `SELECT severity, COUNT(*) FROM iga_sod_violations WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if sevRows != nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var s string
			var c int
			sevRows.Scan(&s, &c)
			stats.ViolationsBySeverity[s] = c
		}
	}

	// Top roles by assignment count
	topRows, _ := r.pool.Query(ctx, roleSelect+`
		WHERE r.tenant_id=$1 AND r.is_active=TRUE
		GROUP BY r.id ORDER BY assignment_count DESC LIMIT 5`, tenantID)
	if topRows != nil {
		defer topRows.Close()
		for topRows.Next() {
			role, _ := scanRole(topRows)
			if role != nil {
				stats.TopRoles = append(stats.TopRoles, role)
			}
		}
	}

	return stats, nil
}
