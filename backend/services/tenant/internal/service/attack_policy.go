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

// AttackPolicyService owns what a tenant considers hard for an attacker.
type AttackPolicyService struct {
	repo   *repository.AttackPolicyRepository
	logger zerolog.Logger
}

// NewAttackPolicyService creates an AttackPolicyService.
func NewAttackPolicyService(
	repo *repository.AttackPolicyRepository,
	logger zerolog.Logger,
) *AttackPolicyService {
	return &AttackPolicyService{repo: repo, logger: logger}
}

// DefaultAttackCode is the standard stance a tenant that has not chosen is
// scored under — exactly the constants the analyzer used before this existed.
const DefaultAttackCode = "balanced"

// Presets are the standard stances the platform ships.
func (s *AttackPolicyService) Presets(ctx context.Context) ([]*model.AttackPolicy, error) {
	presets, err := s.repo.Presets(ctx)
	if err != nil {
		return nil, apierrors.Internal("list attack policies", err)
	}
	return presets, nil
}

// Effective is the stance paths are actually scored under, and whether the
// tenant chose it.
func (s *AttackPolicyService) Effective(
	ctx context.Context,
	tenantID uuid.UUID,
) (*model.AttackPolicy, bool, error) {
	own, err := s.repo.Active(ctx, tenantID)
	if err != nil {
		return nil, false, apierrors.Internal("active attack policy", err)
	}
	if own != nil {
		return own, true, nil
	}

	standard, err := s.repo.Preset(ctx, DefaultAttackCode)
	if err != nil {
		return nil, false, apierrors.Internal("standard attack policy", err)
	}
	return standard, false, nil
}

// History is every version this tenant has had, newest first.
func (s *AttackPolicyService) History(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*model.AttackPolicy, error) {
	history, err := s.repo.History(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("attack policy history", err)
	}
	return history, nil
}

// Set records a new version of the tenant's stance.
func (s *AttackPolicyService) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	callerID *uuid.UUID,
	req *model.SetAttackPolicyRequest,
) (*model.AttackPolicy, error) {
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
			if errors.Is(err, repository.ErrNoSuchAttackPolicy) {
				return nil, apierrors.New(apierrors.KindBadInput,
					fmt.Sprintf("no standard attack policy named %q", req.BasedOn))
			}
			return nil, apierrors.Internal("standard attack policy", err)
		}
		base = preset
		basedOn = preset.Code
	}

	next := &model.AttackPolicy{
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

	// A ceiling below the bonus means every critical system lands on the same
	// number, and the flag stops distinguishing what it exists to distinguish.
	// Accepted by the CHECK, useless in practice, and worth saying out loud.
	if next.Weights.CriticalSystemBonus > 0 &&
		next.Weights.ImpactCeiling+next.Weights.CriticalSystemBonus < 10 {
		s.logger.Warn().
			Str("tenant_id", tenantID.String()).
			Float64("impact_ceiling", next.Weights.ImpactCeiling).
			Float64("critical_system_bonus", next.Weights.CriticalSystemBonus).
			Msg("attack_policy_impact_cannot_reach_ten")
	}

	// Every step costing nothing makes every path score the same, which is not
	// a stance, it is a ranking that has stopped ranking.
	w := next.Weights
	if w.BaseCost+w.ComplexityMedium+w.ComplexityHigh+w.PrivilegeLow+w.PrivilegeHigh <= 0 {
		return nil, apierrors.New(apierrors.KindBadInput,
			"every step would cost nothing, so every path would score the same; keep at least the base cost above zero")
	}

	saved, err := s.repo.Set(ctx, tenantID, callerID, next)
	if err != nil {
		return nil, apierrors.Internal("set attack policy", err)
	}

	// Worth info: this re-ranks every scenario the next time it runs, and the
	// audit trail should not be the only place recording who decided it.
	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("based_on", saved.BasedOn).
		Int("version", saved.Version).
		Float64("hop_decay", saved.Weights.HopDecay).
		Msg("attack_policy_set")

	return saved, nil
}
