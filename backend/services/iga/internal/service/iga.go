package service

import (
	"context"
	"encoding/json"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/iga/internal/model"
	"github.com/cyberradar/platform/services/iga/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// IGAService orchestrates Identity Governance & Administration.
type IGAService struct {
	repo     *repository.IGARepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewIGAService creates an IGAService.
func NewIGAService(repo *repository.IGARepository, producer *pkgkafka.Producer, logger zerolog.Logger) *IGAService {
	return &IGAService{repo: repo, producer: producer, logger: logger}
}

// ─── Roles ────────────────────────────────────────────────────────────────────

func (s *IGAService) CreateRole(ctx context.Context, tenantID uuid.UUID, req *model.CreateRoleRequest) (*model.IGARole, error) {
	role, err := s.repo.CreateRole(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create role", err)
	}
	s.logger.Info().Str("role_id", role.ID.String()).Str("type", role.RoleType).Str("risk", role.RiskLevel).Msg("iga_role_created")
	return role, nil
}

func (s *IGAService) GetRole(ctx context.Context, tenantID, roleID uuid.UUID) (*model.IGARole, error) {
	role, err := s.repo.GetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, apierrors.Internal("get role", err)
	}
	if role == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "role not found")
	}
	return role, nil
}

func (s *IGAService) ListRoles(ctx context.Context, tenantID uuid.UUID, roleType, riskLevel string, activeOnly bool, page, pageSize int) ([]*model.IGARole, int, error) {
	roles, total, err := s.repo.ListRoles(ctx, tenantID, roleType, riskLevel, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list roles", err)
	}
	return roles, total, nil
}

func (s *IGAService) UpdateRole(ctx context.Context, tenantID, roleID uuid.UUID, req *model.UpdateRoleRequest) (*model.IGARole, error) {
	role, err := s.repo.UpdateRole(ctx, tenantID, roleID, req)
	if err != nil {
		return nil, apierrors.Internal("update role", err)
	}
	if role == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "role not found")
	}
	return role, nil
}

// ─── Assignments ──────────────────────────────────────────────────────────────

func (s *IGAService) AssignRole(ctx context.Context, tenantID uuid.UUID, req *model.AssignRoleRequest, requestedBy uuid.UUID) (*model.RoleAssignment, error) {
	assignment, err := s.repo.AssignRole(ctx, tenantID, req, requestedBy)
	if err != nil {
		return nil, apierrors.Internal("assign role", err)
	}
	s.logger.Info().
		Str("assignment_id", assignment.ID.String()).
		Str("identity", assignment.IdentityName).
		Str("role", assignment.RoleName).
		Msg("iga_role_assigned")

	// Async SoD check after new assignment
	go s.runSoDCheck(tenantID)
	return assignment, nil
}

func (s *IGAService) GetAssignment(ctx context.Context, tenantID, assignmentID uuid.UUID) (*model.RoleAssignment, error) {
	a, err := s.repo.GetAssignment(ctx, tenantID, assignmentID)
	if err != nil {
		return nil, apierrors.Internal("get assignment", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "assignment not found")
	}
	return a, nil
}

func (s *IGAService) ListAssignments(ctx context.Context, tenantID uuid.UUID, f model.ListAssignmentsFilter) ([]*model.RoleAssignment, int, error) {
	assignments, total, err := s.repo.ListAssignments(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list assignments", err)
	}
	return assignments, total, nil
}

func (s *IGAService) UpdateAssignment(ctx context.Context, tenantID, assignmentID uuid.UUID, req *model.UpdateAssignmentRequest) (*model.RoleAssignment, error) {
	a, err := s.repo.UpdateAssignment(ctx, tenantID, assignmentID, req)
	if err != nil {
		return nil, apierrors.Internal("update assignment", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "assignment not found")
	}
	return a, nil
}

// ─── Campaigns ────────────────────────────────────────────────────────────────

func (s *IGAService) CreateCampaign(ctx context.Context, tenantID uuid.UUID, req *model.CreateCampaignRequest, createdBy uuid.UUID) (*model.Campaign, error) {
	c, err := s.repo.CreateCampaign(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create campaign", err)
	}
	s.logger.Info().Str("campaign_id", c.ID.String()).Str("type", c.CampaignType).Msg("iga_campaign_created")
	return c, nil
}

func (s *IGAService) LaunchCampaign(ctx context.Context, tenantID, campaignID uuid.UUID) (*model.Campaign, error) {
	c, err := s.repo.LaunchCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return nil, apierrors.Internal("launch campaign", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "campaign not found")
	}
	s.logger.Info().Str("campaign_id", c.ID.String()).Int("total_items", c.TotalItems).Msg("iga_campaign_launched")
	return c, nil
}

func (s *IGAService) GetCampaign(ctx context.Context, tenantID, campaignID uuid.UUID) (*model.Campaign, error) {
	c, err := s.repo.GetCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return nil, apierrors.Internal("get campaign", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "campaign not found")
	}
	return c, nil
}

func (s *IGAService) ListCampaigns(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*model.Campaign, int, error) {
	campaigns, total, err := s.repo.ListCampaigns(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list campaigns", err)
	}
	return campaigns, total, nil
}

// ─── Review Items ─────────────────────────────────────────────────────────────

func (s *IGAService) ListReviewItems(ctx context.Context, tenantID uuid.UUID, f model.ListReviewItemsFilter) ([]*model.ReviewItem, int, error) {
	items, total, err := s.repo.ListReviewItems(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list review items", err)
	}
	return items, total, nil
}

func (s *IGAService) SubmitDecision(ctx context.Context, tenantID, itemID, reviewerID uuid.UUID, req *model.ReviewDecisionRequest) (*model.ReviewItem, error) {
	item, err := s.repo.SubmitReviewDecision(ctx, tenantID, itemID, reviewerID, req)
	if err != nil {
		return nil, apierrors.Internal("submit review decision", err)
	}
	if item == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "review item not found or already decided")
	}
	s.logger.Info().
		Str("item_id", item.ID.String()).
		Str("decision", item.Decision).
		Str("identity", item.IdentityName).
		Str("role", item.RoleName).
		Msg("iga_review_decision_submitted")

	if item.Decision == "revoked" {
		go s.publishRevocationEvent(tenantID, item)
	}
	return item, nil
}

// ─── SoD ──────────────────────────────────────────────────────────────────────

func (s *IGAService) CreateSoDPolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreateSoDPolicyRequest) (*model.SoDPolicy, error) {
	policy, err := s.repo.CreateSoDPolicy(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create SoD policy", err)
	}
	s.logger.Info().Str("policy_id", policy.ID.String()).Str("severity", policy.Severity).Msg("iga_sod_policy_created")
	go s.runSoDCheck(tenantID)
	return policy, nil
}

func (s *IGAService) ListSoDPolicies(ctx context.Context, tenantID uuid.UUID) ([]*model.SoDPolicy, error) {
	policies, err := s.repo.ListSoDPolicies(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list SoD policies", err)
	}
	return policies, nil
}

func (s *IGAService) RunSoDScan(ctx context.Context, tenantID uuid.UUID) (int, error) {
	count, err := s.repo.DetectSoDViolations(ctx, tenantID)
	if err != nil {
		return 0, apierrors.Internal("run SoD scan", err)
	}
	s.logger.Info().Int("violations_detected", count).Msg("iga_sod_scan_complete")
	return count, nil
}

func (s *IGAService) ListSoDViolations(ctx context.Context, tenantID uuid.UUID, status, severity string, page, pageSize int) ([]*model.SoDViolation, int, error) {
	violations, total, err := s.repo.ListSoDViolations(ctx, tenantID, status, severity, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list SoD violations", err)
	}
	return violations, total, nil
}

func (s *IGAService) UpdateViolation(ctx context.Context, tenantID, violationID, updatedBy uuid.UUID, req *model.UpdateViolationRequest) (*model.SoDViolation, error) {
	v, err := s.repo.UpdateViolation(ctx, tenantID, violationID, updatedBy, req)
	if err != nil {
		return nil, apierrors.Internal("update SoD violation", err)
	}
	if v == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "violation not found")
	}
	return v, nil
}

func (s *IGAService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.IGAStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("iga stats", err)
	}
	return stats, nil
}

// ─── Async helpers ────────────────────────────────────────────────────────────

func (s *IGAService) runSoDCheck(tenantID uuid.UUID) {
	ctx := context.Background()
	count, err := s.repo.DetectSoDViolations(ctx, tenantID)
	if err != nil {
		s.logger.Error().Err(err).Msg("iga_sod_check_failed")
		return
	}
	if count > 0 {
		s.logger.Warn().Int("new_violations", count).Str("tenant_id", tenantID.String()).Msg("iga_sod_violations_detected")
		payload := map[string]any{
			"event_type":      "iga.sod_violation",
			"tenant_id":       tenantID.String(),
			"violations_count": count,
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(payload)
		_ = s.producer.Publish(ctx, tenantID.String(), data)
	}
}

func (s *IGAService) publishRevocationEvent(tenantID uuid.UUID, item *model.ReviewItem) {
	ctx := context.Background()
	payload := map[string]any{
		"event_type":    "iga.access_revoked",
		"tenant_id":     tenantID.String(),
		"item_id":       item.ID.String(),
		"identity_id":   item.IdentityID.String(),
		"identity_name": item.IdentityName,
		"role_name":     item.RoleName,
		"reason":        item.DecisionReason,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	_ = s.producer.Publish(ctx, item.ID.String(), data)
}
