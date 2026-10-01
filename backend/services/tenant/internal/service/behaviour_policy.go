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

// BehaviourPolicyService owns what a tenant considers anomalous behaviour.
type BehaviourPolicyService struct {
	repo   *repository.BehaviourPolicyRepository
	logger zerolog.Logger
}

// NewBehaviourPolicyService creates a BehaviourPolicyService.
func NewBehaviourPolicyService(
	repo *repository.BehaviourPolicyRepository,
	logger zerolog.Logger,
) *BehaviourPolicyService {
	return &BehaviourPolicyService{repo: repo, logger: logger}
}

// DefaultBehaviourCode is the standard policy a tenant that has not chosen is
// detected against. It is exactly the thresholds the engine used before any of
// this was configurable.
const DefaultBehaviourCode = "balanced"

// Presets are the standard policies the platform ships.
func (s *BehaviourPolicyService) Presets(ctx context.Context) ([]*model.BehaviourPolicy, error) {
	presets, err := s.repo.Presets(ctx)
	if err != nil {
		return nil, apierrors.Internal("list behaviour policies", err)
	}
	return presets, nil
}

// Effective is the policy detection actually runs under, and whether the tenant
// chose it.
func (s *BehaviourPolicyService) Effective(
	ctx context.Context,
	tenantID uuid.UUID,
) (*model.BehaviourPolicy, bool, error) {
	own, err := s.repo.Active(ctx, tenantID)
	if err != nil {
		return nil, false, apierrors.Internal("active behaviour policy", err)
	}
	if own != nil {
		return own, true, nil
	}

	standard, err := s.repo.Preset(ctx, DefaultBehaviourCode)
	if err != nil {
		return nil, false, apierrors.Internal("standard behaviour policy", err)
	}
	return standard, false, nil
}

// History is every version this tenant has had, newest first.
func (s *BehaviourPolicyService) History(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*model.BehaviourPolicy, error) {
	history, err := s.repo.History(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("behaviour policy history", err)
	}
	return history, nil
}

// Set records a new version of the tenant's thresholds.
func (s *BehaviourPolicyService) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	callerID *uuid.UUID,
	req *model.SetBehaviourPolicyRequest,
) (*model.BehaviourPolicy, error) {
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
			if errors.Is(err, repository.ErrNoSuchBehaviourPolicy) {
				return nil, apierrors.New(apierrors.KindBadInput,
					fmt.Sprintf("no standard behaviour policy named %q", req.BasedOn))
			}
			return nil, apierrors.Internal("standard behaviour policy", err)
		}
		base = preset
		basedOn = preset.Code
	}

	next := &model.BehaviourPolicy{
		Code:        basedOn,
		Name:        req.Name,
		Description: base.Description,
		BasedOn:     basedOn,
		Notes:       req.Notes,
		Thresholds:  req.Thresholds.Apply(base.Thresholds),
		Signals:     req.Signals.Apply(base.Signals),
	}
	if next.Name == "" {
		next.Name = base.Name
	}

	// Turning every signal off is a legitimate thing to want for a few hours and
	// an alarming thing to leave in place. Refused here rather than accepted
	// silently: a UEBA engine that detects nothing should be a decision someone
	// has to argue for, not one they can reach by unticking eight boxes.
	if !anySignalEnabled(next.Signals) {
		return nil, apierrors.New(apierrors.KindBadInput,
			"every behavioural signal is switched off, which leaves the engine detecting nothing; keep at least one on")
	}

	saved, err := s.repo.Set(ctx, tenantID, callerID, next)
	if err != nil {
		return nil, apierrors.Internal("set behaviour policy", err)
	}

	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("based_on", saved.BasedOn).
		Int("version", saved.Version).
		Int("velocity_threshold", saved.Thresholds.VelocityThreshold).
		Int("signals_off", countDisabled(saved.Signals)).
		Msg("behaviour_policy_set")

	return saved, nil
}

// each walks the eight signals. Written once so adding a ninth to the model
// fails to compile here rather than being silently left out of both checks.
func each(s model.Signals) []model.Signal {
	return []model.Signal{
		s.OffHours, s.NewCountry, s.NewIPPrefix, s.Velocity,
		s.BruteForce, s.PrivEscalation, s.LateralMovement, s.DataExfiltration,
	}
}

func anySignalEnabled(s model.Signals) bool {
	for _, sig := range each(s) {
		if sig.Enabled {
			return true
		}
	}
	return false
}

func countDisabled(s model.Signals) int {
	n := 0
	for _, sig := range each(s) {
		if !sig.Enabled {
			n++
		}
	}
	return n
}
