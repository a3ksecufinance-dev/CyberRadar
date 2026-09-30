package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/repository"
)

// ─── Bringing an adopted detection up to the current version ─────────────────
//
// Reporting that a newer version exists and being unable to take it is half an
// answer. Taking it by overwriting the rule is the wrong other half: the point
// of recording lineage was to keep the customer's own changes, and an upgrade
// that discards them destroys exactly what it was built to protect.
//
// So an upgrade here is a three-way merge — the version adopted, the version
// shipping now, the rule as it stands — and where both sides moved the same
// field it stops and asks. A silent pick would be a vendor deciding a bank's
// detection threshold on its behalf.

// resolution values a caller may give for a conflicting field.
const (
	resolveIncoming = "incoming"
	resolveTenant   = "tenant"
)

// upgradeField is one field of the merge, with the means to apply the outcome.
type upgradeField struct {
	name                      string
	adopted, incoming, tenant string
	// take writes the chosen side onto the rule being built.
	take func(rule *model.DetectionRule, incoming bool)
}

// classify is the three-way comparison, and the only place the rules for it
// live.
func (f upgradeField) classify() string {
	switch {
	case f.adopted == f.incoming && f.adopted == f.tenant:
		return model.UpgradeUnchanged
	case f.adopted == f.tenant:
		// The tenant never touched it, so the new value is simply the new value.
		return model.UpgradeTakeIncoming
	case f.adopted == f.incoming:
		// The catalogue did not touch it; the tenant's decision stands.
		return model.UpgradeKeepTenant
	case f.incoming == f.tenant:
		// Both moved, to the same place. Nothing to decide.
		return model.UpgradeConverged
	default:
		return model.UpgradeConflict
	}
}

// upgradeFields is the merge surface: the fields a tenant can change when
// adopting, and can therefore disagree with the catalogue about.
//
// Category and the MITRE mapping are deliberately absent. They are the
// catalogue's classification, not the tenant's judgement, and the coverage
// report is only as truthful as the technique on the rule — so an upgrade always
// takes them.
func upgradeFields(adopted, incoming *model.ContentEntry, tenant *model.DetectionRule) []upgradeField {
	return []upgradeField{
		{
			name: "name", adopted: adopted.Title, incoming: incoming.Title, tenant: tenant.Name,
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.Name = incoming.Title
				} else {
					r.Name = tenant.Name
				}
			},
		},
		{
			name: "description", adopted: adopted.Description, incoming: incoming.Description, tenant: tenant.Description,
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.Description = incoming.Description
				} else {
					r.Description = tenant.Description
				}
			},
		},
		{
			name:    "severity",
			adopted: string(adopted.Severity), incoming: string(incoming.Severity), tenant: string(tenant.Severity),
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.Severity = incoming.Severity
				} else {
					r.Severity = tenant.Severity
				}
			},
		},
		{
			name:     "dedup_window_s",
			adopted:  fmt.Sprintf("%d", adopted.DedupWindowS),
			incoming: fmt.Sprintf("%d", incoming.DedupWindowS),
			tenant:   fmt.Sprintf("%d", tenant.DedupWindowS),
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.DedupWindowS = incoming.DedupWindowS
				} else {
					r.DedupWindowS = tenant.DedupWindowS
				}
			},
		},
		{
			name:    "conditions",
			adopted: canonical(adopted.Conditions), incoming: canonical(incoming.Conditions), tenant: canonical(tenant.Conditions),
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.Conditions = incoming.Conditions
				} else {
					r.Conditions = tenant.Conditions
				}
			},
		},
		{
			name:    "actions",
			adopted: canonical(adopted.Actions), incoming: canonical(incoming.Actions), tenant: canonical(tenant.Actions),
			take: func(r *model.DetectionRule, inc bool) {
				if inc {
					r.Actions = incoming.Actions
				} else {
					r.Actions = tenant.Actions
				}
			},
		},
	}
}

// UpgradePlan is what taking the current version would do, computed and shown
// before anything is written.
func (s *LibraryService) UpgradePlan(
	ctx context.Context,
	tenantID uuid.UUID,
	code string,
) (*model.UpgradePlan, error) {
	plan, _, _, _, err := s.planUpgrade(ctx, tenantID, code)
	return plan, err
}

// planUpgrade computes the plan and hands back what applying it needs, so the
// plan a caller reviewed and the merge that runs are the same code.
func (s *LibraryService) planUpgrade(
	ctx context.Context,
	tenantID uuid.UUID,
	code string,
) (*model.UpgradePlan, []upgradeField, *model.ContentEntry, *repository.Adoption, error) {
	incoming, err := s.library.Entry(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNoSuchEntry) {
			return nil, nil, nil, nil, apierrors.New(apierrors.KindNotFound,
				fmt.Sprintf("no detection named %q in the library", code))
		}
		return nil, nil, nil, nil, apierrors.Internal("library entry", err)
	}

	adoptions, err := s.library.Adoptions(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, nil, apierrors.Internal("adoptions", err)
	}
	adoption, ok := adoptions[code]
	if !ok {
		return nil, nil, nil, nil, apierrors.New(apierrors.KindConflict,
			fmt.Sprintf("%s is not adopted; there is nothing to upgrade", code))
	}

	plan := &model.UpgradePlan{
		Code:        code,
		RuleID:      adoption.Lineage.RuleID,
		FromVersion: adoption.Lineage.AtVersion,
		ToVersion:   incoming.Version,
		Fields:      []model.UpgradeField{},
		Conflicts:   []string{},
	}

	if adoption.Lineage.AtVersion >= incoming.Version {
		// Already current. Reported rather than refused, so a caller that asks
		// twice gets the same answer instead of an error the second time.
		plan.UpToDate = true
		return plan, nil, incoming, adoption, nil
	}

	adoptedVersion, err := s.library.EntryVersion(ctx, code, adoption.Lineage.AtVersion)
	if err != nil {
		// Without the version they adopted there is no baseline, and every
		// field would look like a change the tenant made. Refusing is the only
		// honest answer.
		return nil, nil, nil, nil, apierrors.New(apierrors.KindConflict, fmt.Sprintf(
			"%s v%d is no longer on record, so the upgrade cannot tell your changes from ours",
			code, adoption.Lineage.AtVersion))
	}

	fields := upgradeFields(adoptedVersion, incoming, adoption.Current)
	for _, f := range fields {
		action := f.classify()
		out := model.UpgradeField{
			Field:    f.name,
			Adopted:  f.adopted,
			Incoming: f.incoming,
			Tenant:   f.tenant,
			Action:   action,
		}
		switch action {
		case model.UpgradeTakeIncoming, model.UpgradeConverged:
			out.Result = f.incoming
		case model.UpgradeUnchanged, model.UpgradeKeepTenant:
			out.Result = f.tenant
		case model.UpgradeConflict:
			plan.Conflicts = append(plan.Conflicts, f.name)
		}
		plan.Fields = append(plan.Fields, out)
	}

	// A newer version that leans on data the platform does not produce would
	// turn a detection that fires today into one that cannot. Said out loud
	// rather than acted on: switching off a running detection is the customer's
	// call, not the upgrade's.
	if len(incoming.Requires) > 0 && len(adoptedVersion.Requires) == 0 && adoption.Lineage.Enabled {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"v%d needs %s, which this deployment does not populate; the detection will load and match nothing",
			incoming.Version, strings.Join(incoming.Requires, ", ")))
	}

	return plan, fields, incoming, adoption, nil
}

// Upgrade applies the plan, resolving whatever the caller decided.
func (s *LibraryService) Upgrade(
	ctx context.Context,
	tenantID uuid.UUID,
	code string,
	req *model.UpgradeRequest,
) (*model.UpgradeResult, error) {
	plan, fields, incoming, adoption, err := s.planUpgrade(ctx, tenantID, code)
	if err != nil {
		return nil, err
	}

	if plan.UpToDate {
		rule, err := s.rules.GetByID(ctx, tenantID, adoption.Lineage.RuleID)
		if err != nil {
			return nil, apierrors.Internal("read the rule", err)
		}
		return &model.UpgradeResult{Plan: plan, Rule: rule}, nil
	}

	// A decision taken against one diff must not land on another. The catalogue
	// can move between reading the plan and applying it.
	if req != nil && req.ToVersion != 0 && req.ToVersion != plan.ToVersion {
		return nil, apierrors.New(apierrors.KindConflict, fmt.Sprintf(
			"the catalogue moved to v%d since that plan was for v%d; review the difference again",
			plan.ToVersion, req.ToVersion))
	}

	resolve := map[string]string{}
	if req != nil {
		for field, side := range req.Resolve {
			if side != resolveIncoming && side != resolveTenant {
				return nil, apierrors.New(apierrors.KindBadInput, fmt.Sprintf(
					"resolve[%s] must be %q or %q", field, resolveIncoming, resolveTenant))
			}
			resolve[field] = side
		}
	}

	var unresolved []string
	for _, name := range plan.Conflicts {
		if _, ok := resolve[name]; !ok {
			unresolved = append(unresolved, name)
		}
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		return nil, apierrors.New(apierrors.KindConflict, fmt.Sprintf(
			"you and the catalogue both changed %s; say for each whether to keep yours or take ours",
			strings.Join(unresolved, ", ")))
	}

	// Start from the rule as it stands, so anything outside the merge surface —
	// whether it is enabled, what it has fired, who created it — is untouched.
	merged := *adoption.Current
	for i, f := range fields {
		var takeIncoming bool
		switch plan.Fields[i].Action {
		case model.UpgradeTakeIncoming, model.UpgradeConverged:
			takeIncoming = true
		case model.UpgradeConflict:
			takeIncoming = resolve[f.name] == resolveIncoming
			plan.Fields[i].Result = f.tenant
			if takeIncoming {
				plan.Fields[i].Result = f.incoming
			}
		}
		f.take(&merged, takeIncoming)
	}

	notes := ""
	if req != nil {
		notes = req.Notes
	}
	err = s.library.Upgrade(ctx, tenantID, adoption.Lineage.RuleID,
		plan.FromVersion, plan.ToVersion, &merged, incoming, notes)
	if err != nil {
		if errors.Is(err, repository.ErrUpgradeRaced) {
			return nil, apierrors.New(apierrors.KindConflict,
				"the rule was upgraded by someone else while you were deciding; review the difference again")
		}
		return nil, apierrors.Internal("upgrade rule", err)
	}

	saved, err := s.rules.GetByID(ctx, tenantID, adoption.Lineage.RuleID)
	if err != nil {
		return nil, apierrors.Internal("read the upgraded rule", err)
	}

	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("code", code).
		Int("from_version", plan.FromVersion).
		Int("to_version", plan.ToVersion).
		Int("conflicts_resolved", len(plan.Conflicts)).
		Msg("detection_upgraded")

	return &model.UpgradeResult{Plan: plan, Rule: saved}, nil
}
