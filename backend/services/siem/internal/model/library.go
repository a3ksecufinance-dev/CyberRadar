package model

import (
	"time"

	"github.com/google/uuid"
)

// ContentEntry is one detection the platform ships.
//
// It carries more than the rule. A detection without its reasoning is a pager
// that says nothing at three in the morning, and a detection without its
// prerequisites is coverage a customer thinks they have.
type ContentEntry struct {
	ID      uuid.UUID `json:"id"`
	Code    string    `json:"code"`
	Version int       `json:"version"`

	Title       string `json:"title"`
	Description string `json:"description"`

	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	MitreTactic    string   `json:"mitre_tactic,omitempty"`
	MitreTechnique string   `json:"mitre_technique,omitempty"`

	Conditions   RuleConditions `json:"conditions"`
	Actions      []RuleAction   `json:"actions"`
	DedupWindowS int            `json:"dedup_window_s"`

	// Why it exists, what trips it legitimately, what to do about it.
	Rationale      string `json:"rationale"`
	FalsePositives string `json:"false_positives,omitempty"`
	Response       string `json:"response,omitempty"`

	// Which frameworks this detection helps evidence, and the controls it maps
	// to, so a compliance report can cite the detections behind a control.
	Frameworks []string `json:"frameworks"`
	Controls   []string `json:"controls"`

	// What has to be in place for it to fire. Empty means it works on what the
	// platform already produces.
	Requires []string `json:"requires"`

	// EnabledByDefault is false for an entry that cannot fire yet — see
	// Requires. Shipping it on would present coverage the platform lacks.
	EnabledByDefault bool `json:"enabled_by_default"`

	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

// LibraryEntry is a catalogue entry seen from one tenant: the content, whether
// this tenant runs it, and how their copy differs.
type LibraryEntry struct {
	Content ContentEntry `json:"content"`

	// Adopted is the tenant's rule, or nil when they have not taken this one.
	Adopted *AdoptedRule `json:"adopted,omitempty"`
}

// AdoptedRule is the lineage of a tenant rule that came from the catalogue.
type AdoptedRule struct {
	RuleID      uuid.UUID `json:"rule_id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	AdoptedAt   time.Time `json:"adopted_at"`
	AtVersion   int       `json:"at_version"`
	AlertsTotal int       `json:"alerts_total"`

	// UpdateAvailable is true when the catalogue has moved on since this copy
	// was taken. What changed is in the entry's own content.
	UpdateAvailable bool `json:"update_available"`

	// Changes is how this tenant's copy differs from the version they adopted.
	// Computed on read rather than stored, so it cannot go stale — and so an
	// edit made directly to the rule shows up here rather than being invisible.
	Changes []FieldChange `json:"changes,omitempty"`
}

// FieldChange is one difference between a tenant's rule and the catalogue entry
// it came from.
type FieldChange struct {
	Field    string `json:"field"`
	Standard string `json:"standard"`
	Tenant   string `json:"tenant"`
}

// AdoptRequest takes a catalogue entry into a tenant's rule set.
//
// Every override is optional and applied over the catalogue's own values, so
// adopting with no body runs the detection exactly as it ships — which is what
// makes "what did you change" answerable.
type AdoptRequest struct {
	// Enabled defaults to the entry's own enabled_by_default. Set it
	// explicitly to take an entry that ships off, having read what it requires.
	Enabled *bool `json:"enabled"`

	Name         *string         `json:"name"          validate:"omitempty,min=3,max=255"`
	Severity     *Severity       `json:"severity"      validate:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`
	Conditions   *RuleConditions `json:"conditions"`
	Actions      []RuleAction    `json:"actions"`
	DedupWindowS *int            `json:"dedup_window_s" validate:"omitempty,min=0,max=86400"`
}

// CoverageEntry is what the tenant detects, and does not, for one technique.
type CoverageEntry struct {
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`

	// Available is how many catalogue entries address this technique;
	// Adopted how many the tenant has taken; Enabled how many are actually on.
	Available int `json:"available"`
	Adopted   int `json:"adopted"`
	Enabled   int `json:"enabled"`

	// Codes lets an interface offer the entries that would close the gap.
	Codes []string `json:"codes"`
}

// Coverage is the whole picture, plus the rules that came from nowhere.
type Coverage struct {
	Techniques []CoverageEntry `json:"techniques"`

	// OwnRules counts the rules this tenant wrote rather than adopted. They are
	// a first-class case — the library is a starting point, not a cage — but
	// they are not coverage the vendor can vouch for, so they are counted apart.
	OwnRules int `json:"own_rules"`

	CatalogueSize int `json:"catalogue_size"`
	AdoptedTotal  int `json:"adopted_total"`
	EnabledTotal  int `json:"enabled_total"`
}
