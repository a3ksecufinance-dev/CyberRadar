package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// SIEMService orchestrates rules, alerts, and cases.
type SIEMService struct {
	ruleRepo  *repository.RuleRepository
	alertRepo *repository.AlertRepository
	caseRepo  *repository.CaseRepository
	logger    zerolog.Logger
}

// NewSIEMService creates a SIEMService.
func NewSIEMService(
	ruleRepo *repository.RuleRepository,
	alertRepo *repository.AlertRepository,
	caseRepo *repository.CaseRepository,
	logger zerolog.Logger,
) *SIEMService {
	return &SIEMService{ruleRepo: ruleRepo, alertRepo: alertRepo, caseRepo: caseRepo, logger: logger}
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (s *SIEMService) CreateRule(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateRuleRequest) (*model.DetectionRule, error) {
	rule, err := s.ruleRepo.Create(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create rule", err)
	}
	s.logger.Info().Str("rule_id", rule.ID.String()).Str("name", rule.Name).Msg("detection_rule_created")
	return rule, nil
}

func (s *SIEMService) GetRule(ctx context.Context, tenantID, ruleID uuid.UUID) (*model.DetectionRule, error) {
	rule, err := s.ruleRepo.GetByID(ctx, tenantID, ruleID)
	if err != nil {
		return nil, apierrors.Internal("get rule", err)
	}
	if rule == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "rule not found")
	}
	return rule, nil
}

func (s *SIEMService) ListRules(ctx context.Context, tenantID uuid.UUID, enabledOnly bool) ([]*model.DetectionRule, error) {
	rules, err := s.ruleRepo.List(ctx, tenantID, enabledOnly)
	if err != nil {
		return nil, apierrors.Internal("list rules", err)
	}
	return rules, nil
}

func (s *SIEMService) UpdateRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *model.UpdateRuleRequest) (*model.DetectionRule, error) {
	rule, err := s.ruleRepo.Update(ctx, tenantID, ruleID, req)
	if err != nil {
		return nil, apierrors.Internal("update rule", err)
	}
	if rule == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "rule not found")
	}
	return rule, nil
}

func (s *SIEMService) DeleteRule(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	if err := s.ruleRepo.Delete(ctx, tenantID, ruleID); err != nil {
		return apierrors.Wrap(apierrors.KindNotFound, "rule not found or is a system rule", err)
	}
	return nil
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *SIEMService) ListAlerts(ctx context.Context, f model.AlertFilter) ([]*model.Alert, int, error) {
	alerts, total, err := s.alertRepo.List(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list alerts", err)
	}
	return alerts, total, nil
}

func (s *SIEMService) UpdateAlert(ctx context.Context, tenantID, alertID uuid.UUID, req *model.UpdateAlertRequest) (*model.AlertMetadata, error) {
	meta, err := s.caseRepo.UpdateAlertMetadata(ctx, tenantID, alertID, req)
	if err != nil {
		return nil, apierrors.Internal("update alert", err)
	}
	return meta, nil
}

func (s *SIEMService) GetAlertStats(ctx context.Context, tenantID uuid.UUID) (*model.AlertStats, error) {
	stats, err := s.alertRepo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("alert stats", err)
	}
	return stats, nil
}

// PromoteToCase creates a new case and links the alert to it.
func (s *SIEMService) PromoteToCase(ctx context.Context, tenantID, alertID uuid.UUID, callerID *uuid.UUID, req *model.CreateCaseRequest) (*model.Case, error) {
	// Link existing alert IDs if not already included
	if req.AlertIDs == nil {
		req.AlertIDs = []uuid.UUID{}
	}
	req.AlertIDs = append(req.AlertIDs, alertID)

	c, err := s.CreateCase(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, err
	}
	_ = s.caseRepo.LinkAlert(ctx, tenantID, c.ID, alertID)
	return c, nil
}

// ─── Cases ────────────────────────────────────────────────────────────────────

func (s *SIEMService) CreateCase(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateCaseRequest) (*model.Case, error) {
	c, err := s.caseRepo.CreateCase(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create case", err)
	}
	// Link any supplied alerts
	for _, aid := range req.AlertIDs {
		_ = s.caseRepo.LinkAlert(ctx, tenantID, c.ID, aid)
	}
	s.logger.Info().Str("case_id", c.ID.String()).Str("title", c.Title).Msg("case_created")
	return c, nil
}

func (s *SIEMService) GetCase(ctx context.Context, tenantID, caseID uuid.UUID) (*model.Case, error) {
	c, err := s.caseRepo.GetCase(ctx, tenantID, caseID)
	if err != nil {
		return nil, apierrors.Internal("get case", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "case not found")
	}
	return c, nil
}

func (s *SIEMService) ListCases(ctx context.Context, f model.CaseFilter) ([]*model.Case, int, error) {
	cases, total, err := s.caseRepo.ListCases(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list cases", err)
	}
	return cases, total, nil
}

func (s *SIEMService) UpdateCase(ctx context.Context, tenantID, caseID uuid.UUID, req *model.UpdateCaseRequest) (*model.Case, error) {
	c, err := s.caseRepo.UpdateCase(ctx, tenantID, caseID, req)
	if err != nil {
		return nil, apierrors.Internal("update case", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "case not found")
	}
	return c, nil
}

func (s *SIEMService) AddComment(ctx context.Context, tenantID, caseID uuid.UUID, authorID *uuid.UUID, req *model.AddCommentRequest) (*model.CaseComment, error) {
	if _, err := s.GetCase(ctx, tenantID, caseID); err != nil {
		return nil, err
	}
	comment, err := s.caseRepo.AddComment(ctx, tenantID, caseID, authorID, req)
	if err != nil {
		return nil, apierrors.Internal("add comment", err)
	}
	return comment, nil
}

func (s *SIEMService) ListComments(ctx context.Context, tenantID, caseID uuid.UUID) ([]*model.CaseComment, error) {
	if _, err := s.GetCase(ctx, tenantID, caseID); err != nil {
		return nil, err
	}
	comments, err := s.caseRepo.ListComments(ctx, tenantID, caseID)
	if err != nil {
		return nil, apierrors.Internal("list comments", err)
	}
	return comments, nil
}

func (s *SIEMService) AddObservable(ctx context.Context, tenantID, caseID uuid.UUID, addedBy *uuid.UUID, req *model.AddObservableRequest) (*model.Observable, error) {
	if _, err := s.GetCase(ctx, tenantID, caseID); err != nil {
		return nil, err
	}
	obs, err := s.caseRepo.AddObservable(ctx, tenantID, caseID, addedBy, req)
	if err != nil {
		return nil, apierrors.Internal("add observable", err)
	}
	return obs, nil
}
