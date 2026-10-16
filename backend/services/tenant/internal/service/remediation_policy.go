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

// RemediationPolicyService owns the deadlines a tenant is held to.
type RemediationPolicyService struct {
	repo   *repository.RemediationPolicyRepository
	logger zerolog.Logger
}

// NewRemediationPolicyService creates a RemediationPolicyService.
func NewRemediationPolicyService(
	repo *repository.RemediationPolicyRepository,
	logger zerolog.Logger,
) *RemediationPolicyService {
	return &RemediationPolicyService{repo: repo, logger: logger}
}

// DefaultPolicyCode is the standard policy a tenant that has not chosen is held
// to. It carries no ceilings, so it is exactly what the platform computed before
// any of this was configurable.
const DefaultPolicyCode = "banking_default"

// Presets are the standard policies the platform ships.
func (s *RemediationPolicyService) Presets(ctx context.Context) ([]*model.RemediationPolicy, error) {
	presets, err := s.repo.Presets(ctx)
	if err != nil {
		return nil, apierrors.Internal("list remediation policies", err)
	}
	return presets, nil
}

// Effective is the policy deadlines are actually computed under: the tenant's
// own if they have one, otherwise the standard.
//
// The distinction is reported rather than hidden. A deadline is a commitment,
// and presenting ours as theirs is how a vendor ends up defending someone else's
// SLA to a regulator.
func (s *RemediationPolicyService) Effective(
	ctx context.Context,
	tenantID uuid.UUID,
) (*model.RemediationPolicy, bool, error) {
	own, err := s.repo.Active(ctx, tenantID)
	if err != nil {
		return nil, false, apierrors.Internal("active remediation policy", err)
	}
	if own != nil {
		return own, true, nil
	}

	standard, err := s.repo.Preset(ctx, DefaultPolicyCode)
	if err != nil {
		return nil, false, apierrors.Internal("standard remediation policy", err)
	}
	return standard, false, nil
}

// History is every version this tenant has had, newest first.
func (s *RemediationPolicyService) History(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*model.RemediationPolicy, error) {
	history, err := s.repo.History(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("remediation policy history", err)
	}
	return history, nil
}

// Set records a new version of the tenant's deadlines.
//
// The base is whatever the caller named, or what is already in force, or the
// standard — in that order. Then the deadlines the caller sent are applied on
// top, so moving one number does not mean restating the other nine.
func (s *RemediationPolicyService) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	callerID *uuid.UUID,
	req *model.SetRemediationPolicyRequest,
) (*model.RemediationPolicy, error) {
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
			if errors.Is(err, repository.ErrNoSuchPolicy) {
				return nil, apierrors.New(apierrors.KindBadInput,
					fmt.Sprintf("no standard remediation policy named %q", req.BasedOn))
			}
			return nil, apierrors.Internal("standard remediation policy", err)
		}
		base = preset
		basedOn = preset.Code
	}

	next := &model.RemediationPolicy{
		Code:        basedOn,
		Name:        req.Name,
		Description: base.Description,
		BasedOn:     basedOn,
		Notes:       req.Notes,
		Deadlines:   req.Deadlines.Apply(base.Deadlines),
	}
	if next.Name == "" {
		next.Name = base.Name
	}

	// The schema enforces this too, but a constraint violation reaches the
	// caller as a 500 naming a constraint. A policy that gives a critical longer
	// than a low is almost certainly a typo, and saying so beats refusing.
	if !next.Deadlines.Ordered() {
		return nil, apierrors.New(apierrors.KindBadInput, fmt.Sprintf(
			"the deadlines run backwards: critical %d, high %d, medium %d, low %d days — a critical cannot be given longer than a low",
			next.Deadlines.CriticalDays, next.Deadlines.HighDays,
			next.Deadlines.MediumDays, next.Deadlines.LowDays))
	}
	if next.Deadlines.MinimumDays > next.Deadlines.CriticalDays {
		return nil, apierrors.New(apierrors.KindBadInput, fmt.Sprintf(
			"the floor of %d days is above the critical deadline of %d, so no ceiling could ever apply",
			next.Deadlines.MinimumDays, next.Deadlines.CriticalDays))
	}

	saved, err := s.repo.Set(ctx, tenantID, callerID, next)
	if err != nil {
		return nil, apierrors.Internal("set remediation policy", err)
	}

	// Worth info: this moves the deadline on every open finding in the tenant,
	// and the audit trail should not be the only place that records who did it.
	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("based_on", saved.BasedOn).
		Int("version", saved.Version).
		Int("critical_days", saved.Deadlines.CriticalDays).
		Msg("remediation_policy_set")

	return saved, nil
}
