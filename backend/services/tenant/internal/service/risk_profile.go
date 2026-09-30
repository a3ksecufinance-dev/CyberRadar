package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
)

// RiskProfileService owns the tenant's risk appetite.
type RiskProfileService struct {
	repo   *repository.RiskProfileRepository
	logger zerolog.Logger
}

// NewRiskProfileService creates a RiskProfileService.
func NewRiskProfileService(repo *repository.RiskProfileRepository, logger zerolog.Logger) *RiskProfileService {
	return &RiskProfileService{repo: repo, logger: logger}
}

// Presets are the standard profiles the platform ships.
func (s *RiskProfileService) Presets(ctx context.Context) ([]*model.RiskProfile, error) {
	presets, err := s.repo.Presets(ctx)
	if err != nil {
		return nil, apierrors.Internal("list risk profiles", err)
	}
	return presets, nil
}

// Effective is the profile a tenant's scores are actually produced under: its
// own if it has one, otherwise the standard balanced profile.
//
// The distinction is reported rather than hidden — an interface should be able
// to say "you have not chosen, these are our values" instead of presenting the
// default as a decision the customer made.
func (s *RiskProfileService) Effective(ctx context.Context, tenantID uuid.UUID) (*model.RiskProfile, bool, error) {
	own, err := s.repo.Active(ctx, tenantID)
	if err != nil {
		return nil, false, apierrors.Internal("active risk profile", err)
	}
	if own != nil {
		return own, true, nil
	}

	standard, err := s.repo.Preset(ctx, DefaultProfileCode)
	if err != nil {
		return nil, false, apierrors.Internal("standard risk profile", err)
	}
	return standard, false, nil
}

// DefaultProfileCode is the standard profile a tenant that has not chosen is
// scored under.
const DefaultProfileCode = "balanced"

// History is every version this tenant has had, newest first.
func (s *RiskProfileService) History(ctx context.Context, tenantID uuid.UUID) ([]*model.RiskProfile, error) {
	history, err := s.repo.History(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("risk profile history", err)
	}
	return history, nil
}

// Set records a new version of the tenant's risk appetite.
//
// The base is whatever the caller named, or what is already in force, or the
// standard profile — in that order. Then the factors the caller sent are
// applied on top. That ordering is what lets a risk function change one number
// without restating the other sixteen, and what stops an omitted factor being
// silently read as zero.
func (s *RiskProfileService) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	callerID *uuid.UUID,
	req *model.SetRiskProfileRequest,
) (*model.RiskProfile, error) {
	base, _, err := s.Effective(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	basedOn := base.Code
	if base.TenantID != nil && base.BasedOn != "" {
		basedOn = base.BasedOn
	}

	if req.BasedOn != "" {
		preset, err := s.repo.Preset(ctx, req.BasedOn)
		if err != nil {
			if errors.Is(err, repository.ErrNoSuchPreset) {
				return nil, apierrors.New(apierrors.KindBadInput,
					fmt.Sprintf("no standard risk profile named %q", req.BasedOn))
			}
			return nil, apierrors.Internal("standard risk profile", err)
		}
		base = preset
		basedOn = preset.Code
	}

	next := &model.RiskProfile{
		Code:        basedOn,
		Name:        req.Name,
		Description: base.Description,
		BasedOn:     basedOn,
		Notes:       req.Notes,
		Weights:     req.Weights.Apply(base.Weights),
	}
	if next.Name == "" {
		next.Name = base.Name
	}

	// The schema bounds each weight, but a cap below a single step is a profile
	// that can never reach its own ceiling — accepted by the CHECK, useless in
	// practice, and confusing to explain. Worth refusing here, where the
	// message can say why.
	if next.Weights.TotalCap < next.Weights.HighRiskThreshold {
		return nil, apierrors.New(apierrors.KindBadInput,
			"high_risk_threshold is above total_cap, so no asset could ever be high risk")
	}

	saved, err := s.repo.Set(ctx, tenantID, callerID, next)
	if err != nil {
		return nil, apierrors.Internal("set risk profile", err)
	}

	// Worth a log line at info: this changes every risk score in the tenant,
	// and the audit trail should not be the only place that says who did it.
	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("based_on", saved.BasedOn).
		Int("version", saved.Version).
		Float64("high_risk_threshold", saved.Weights.HighRiskThreshold).
		Msg("risk_profile_set")

	return saved, nil
}
