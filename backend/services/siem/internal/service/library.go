package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/repository"
)

// LibraryService serves the detection content the platform ships, and the
// lineage from a tenant's rules back to it.
type LibraryService struct {
	library *repository.LibraryRepository
	rules   *repository.RuleRepository
	logger  zerolog.Logger
}

// NewLibraryService creates a LibraryService.
func NewLibraryService(
	library *repository.LibraryRepository,
	rules *repository.RuleRepository,
	logger zerolog.Logger,
) *LibraryService {
	return &LibraryService{library: library, rules: rules, logger: logger}
}

// Catalogue is the library seen from one tenant: every entry, whether this
// tenant runs it, and how their copy differs from what they adopted.
func (s *LibraryService) Catalogue(ctx context.Context, tenantID uuid.UUID) ([]*model.LibraryEntry, error) {
	entries, err := s.library.Catalogue(ctx)
	if err != nil {
		return nil, apierrors.Internal("detection library", err)
	}
	adoptions, err := s.library.Adoptions(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("adoptions", err)
	}

	out := make([]*model.LibraryEntry, 0, len(entries))
	for _, entry := range entries {
		view := &model.LibraryEntry{Content: *entry}
		if adoption, ok := adoptions[entry.Code]; ok {
			lineage := *adoption.Lineage
			lineage.UpdateAvailable = entry.Version > lineage.AtVersion
			lineage.Changes = s.changesFrom(ctx, entry, adoption)
			view.Adopted = &lineage
		}
		out = append(out, view)
	}
	return out, nil
}

// Entry is one catalogue entry, with this tenant's lineage for it.
func (s *LibraryService) Entry(ctx context.Context, tenantID uuid.UUID, code string) (*model.LibraryEntry, error) {
	entry, err := s.library.Entry(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNoSuchEntry) {
			return nil, apierrors.New(apierrors.KindNotFound, fmt.Sprintf("no detection named %q in the library", code))
		}
		return nil, apierrors.Internal("library entry", err)
	}

	adoptions, err := s.library.Adoptions(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("adoptions", err)
	}

	view := &model.LibraryEntry{Content: *entry}
	if adoption, ok := adoptions[code]; ok {
		lineage := *adoption.Lineage
		lineage.UpdateAvailable = entry.Version > lineage.AtVersion
		lineage.Changes = s.changesFrom(ctx, entry, adoption)
		view.Adopted = &lineage
	}
	return view, nil
}

// changesFrom is how a tenant's copy differs from the version they adopted.
//
// Against the adopted version, not against whatever ships today: comparing a
// tenant on v1 to v2 would report the platform's own improvements as the
// customer's changes, which is precisely the wrong answer to "what did you
// change".
//
// Computed rather than stored, so an edit made directly to the rule shows up
// here instead of being invisible, and so a stored flag cannot go stale.
func (s *LibraryService) changesFrom(
	ctx context.Context,
	current *model.ContentEntry,
	adoption *repository.Adoption,
) []model.FieldChange {
	base := current
	if adoption.Lineage.AtVersion != current.Version {
		adopted, err := s.library.EntryVersion(ctx, current.Code, adoption.Lineage.AtVersion)
		if err != nil {
			// The version adopted is no longer on record. Say so rather than
			// comparing against the wrong thing and calling it a difference.
			s.logger.Warn().Err(err).
				Str("code", current.Code).
				Int("adopted_version", adoption.Lineage.AtVersion).
				Msg("adopted content version is missing; cannot compute the difference")
			return []model.FieldChange{{
				Field:    "_baseline",
				Standard: fmt.Sprintf("v%d is no longer on record", adoption.Lineage.AtVersion),
				Tenant:   "the difference cannot be computed",
			}}
		}
		base = adopted
	}

	var changes []model.FieldChange
	add := func(field, standard, tenant string) {
		if standard != tenant {
			changes = append(changes, model.FieldChange{Field: field, Standard: standard, Tenant: tenant})
		}
	}

	add("name", base.Title, adoption.Current.Name)
	add("severity", string(base.Severity), string(adoption.Current.Severity))
	add("dedup_window_s",
		fmt.Sprintf("%d", base.DedupWindowS),
		fmt.Sprintf("%d", adoption.Current.DedupWindowS))
	add("conditions", canonical(base.Conditions), canonical(adoption.Current.Conditions))
	add("actions", canonical(base.Actions), canonical(adoption.Current.Actions))

	return changes
}

// canonical renders a value for comparison and for display in a difference.
//
// Marshalling rather than reflecting: the conditions are a small tree, the JSON
// form is what a reviewer reads anyway, and Go's encoder orders struct fields
// deterministically — so equal values render equal.
func canonical(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}

// Adopt takes a catalogue entry into the tenant's rule set.
//
// With no overrides the detection runs exactly as it ships, which is what makes
// the difference meaningful afterwards. An entry that cannot fire yet must be
// enabled explicitly: adopting it silently on would present coverage the
// platform does not have.
func (s *LibraryService) Adopt(
	ctx context.Context,
	tenantID uuid.UUID,
	callerID *uuid.UUID,
	code string,
	req *model.AdoptRequest,
) (*model.DetectionRule, error) {
	entry, err := s.library.Entry(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNoSuchEntry) {
			return nil, apierrors.New(apierrors.KindNotFound, fmt.Sprintf("no detection named %q in the library", code))
		}
		return nil, apierrors.Internal("library entry", err)
	}

	rule := &model.DetectionRule{
		Name:         entry.Title,
		Severity:     entry.Severity,
		Conditions:   entry.Conditions,
		Actions:      entry.Actions,
		DedupWindowS: entry.DedupWindowS,
		Enabled:      entry.EnabledByDefault,
	}
	if req != nil {
		if req.Name != nil {
			rule.Name = *req.Name
		}
		if req.Severity != nil {
			rule.Severity = *req.Severity
		}
		if req.Conditions != nil {
			rule.Conditions = *req.Conditions
		}
		if req.Actions != nil {
			rule.Actions = req.Actions
		}
		if req.DedupWindowS != nil {
			rule.DedupWindowS = *req.DedupWindowS
		}
		if req.Enabled != nil {
			rule.Enabled = *req.Enabled
		}
	}

	if rule.Enabled && len(entry.Requires) > 0 && (req == nil || req.Enabled == nil) {
		// Belt and braces: the catalogue already ships these off, and this
		// stops a future entry that forgets to.
		rule.Enabled = false
	}

	id, err := s.library.Adopt(ctx, tenantID, callerID, entry, rule)
	if err != nil {
		if errors.Is(err, repository.ErrAlreadyAdopted) {
			return nil, apierrors.New(apierrors.KindConflict,
				fmt.Sprintf("%s is already adopted; edit the rule it created instead", code))
		}
		return nil, apierrors.Internal("adopt detection", err)
	}

	saved, err := s.rules.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, apierrors.Internal("read the adopted rule", err)
	}

	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("code", entry.Code).
		Int("version", entry.Version).
		Bool("enabled", rule.Enabled).
		Msg("detection_adopted")

	return saved, nil
}

// Coverage is what the tenant detects, by ATT&CK technique, against what the
// library offers.
//
// It is what turns "choose your use cases" into a decision rather than a list:
// a gap names the entries that would close it.
func (s *LibraryService) Coverage(ctx context.Context, tenantID uuid.UUID) (*model.Coverage, error) {
	entries, err := s.library.Catalogue(ctx)
	if err != nil {
		return nil, apierrors.Internal("detection library", err)
	}
	adoptions, err := s.library.Adoptions(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("adoptions", err)
	}
	own, err := s.library.OwnRuleCount(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("count own rules", err)
	}

	byTechnique := map[string]*model.CoverageEntry{}
	cov := &model.Coverage{OwnRules: own, CatalogueSize: len(entries)}

	for _, entry := range entries {
		key := entry.MitreTactic + "/" + entry.MitreTechnique
		e, ok := byTechnique[key]
		if !ok {
			e = &model.CoverageEntry{
				MitreTactic:    entry.MitreTactic,
				MitreTechnique: entry.MitreTechnique,
			}
			byTechnique[key] = e
		}
		e.Available++
		e.Codes = append(e.Codes, entry.Code)

		adoption, adopted := adoptions[entry.Code]
		if !adopted {
			continue
		}
		e.Adopted++
		cov.AdoptedTotal++
		if adoption.Lineage.Enabled {
			e.Enabled++
			cov.EnabledTotal++
		}
	}

	cov.Techniques = make([]model.CoverageEntry, 0, len(byTechnique))
	for _, e := range byTechnique {
		cov.Techniques = append(cov.Techniques, *e)
	}
	// Gaps first: a coverage report is read to find what is missing.
	sort.Slice(cov.Techniques, func(i, j int) bool {
		a, b := cov.Techniques[i], cov.Techniques[j]
		if (a.Enabled == 0) != (b.Enabled == 0) {
			return a.Enabled == 0
		}
		if a.MitreTactic != b.MitreTactic {
			return a.MitreTactic < b.MitreTactic
		}
		return a.MitreTechnique < b.MitreTechnique
	})

	return cov, nil
}
