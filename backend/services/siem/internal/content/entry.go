// Package content is the detection catalogue as files, and the reconciliation
// that puts them in the database.
//
// The fifteen detections used to be INSERT statements inside a migration, which
// made improving one of them a schema change: a new migration, a rebuild, a
// deployment window — for a sentence of rationale or a threshold somebody
// wanted tightened. Content that can only ship with the code ships at the
// code's cadence, and that is the wrong cadence for detection content.
package content

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cyberradar/platform/services/siem/internal/model"
)

// Pack is a content release: a set of detections with an identity.
//
// The version is the pack's, not each detection's. "We are running 2026.10.1"
// is the question an operator asks; which individual entry moved is what the
// load record answers.
type Pack struct {
	Name        string `yaml:"name"        json:"name"`
	Version     string `yaml:"version"     json:"version"`
	Released    string `yaml:"released"    json:"released"`
	Description string `yaml:"description" json:"description"`
}

// Entry is one detection as it is authored.
//
// Deliberately without a version field. A version in a file is a number
// somebody forgets to change, and a forgotten bump tells a tenant on v1 that
// they are current while they run something else. The loader derives it from
// the content instead: change anything substantive and a new version is
// published, change nothing and nothing happens.
type Entry struct {
	Code        string `yaml:"code"        json:"code"`
	Title       string `yaml:"title"       json:"title"`
	Description string `yaml:"description" json:"description"`
	Category    string `yaml:"category"    json:"category"`

	Severity string `yaml:"severity" json:"severity"`

	Mitre struct {
		Tactic    string `yaml:"tactic"    json:"tactic"`
		Technique string `yaml:"technique" json:"technique"`
	} `yaml:"mitre" json:"mitre"`

	Conditions model.RuleConditions `yaml:"-" json:"conditions"`
	Actions    []model.RuleAction   `yaml:"-" json:"actions"`

	// RawConditions and RawActions hold what YAML parsed, before it is converted
	// through JSON so the model's own json tags apply. Two spellings of the same
	// field names would be a second vocabulary to keep in step.
	RawConditions any `yaml:"conditions" json:"-"`
	RawActions    any `yaml:"actions"    json:"-"`

	DedupWindowS int `yaml:"dedup_window_s" json:"dedup_window_s"`

	Rationale      string `yaml:"rationale"       json:"rationale"`
	FalsePositives string `yaml:"false_positives" json:"false_positives"`
	Response       string `yaml:"response"        json:"response"`

	Frameworks []string `yaml:"frameworks" json:"frameworks"`
	Controls   []string `yaml:"controls"   json:"controls"`
	Requires   []string `yaml:"requires"   json:"requires"`

	EnabledByDefault bool     `yaml:"enabled_by_default" json:"enabled_by_default"`
	Tags             []string `yaml:"tags"               json:"tags"`

	// Source is the file this came from, for an error message that names it.
	Source string `yaml:"-" json:"-"`
}

// resolve converts what YAML parsed into the engine's own types.
//
// Through JSON rather than with a second set of yaml tags on the rule model:
// the conditions are the engine's vocabulary, and giving them two spellings
// would be two things to keep in step for no gain. yaml.v3 decodes mappings as
// map[string]any, so the round trip is lossless for everything this format
// carries.
func (e *Entry) resolve() error {
	if e.RawConditions == nil {
		return fmt.Errorf("%s has no conditions", e.Code)
	}
	raw, err := json.Marshal(e.RawConditions)
	if err != nil {
		return fmt.Errorf("conditions of %s: %w", e.Code, err)
	}
	if err := json.Unmarshal(raw, &e.Conditions); err != nil {
		return fmt.Errorf("conditions of %s: %w", e.Code, err)
	}

	// No actions is legitimate: the detection raises the alert and nothing more.
	e.Actions = []model.RuleAction{}
	if e.RawActions != nil {
		raw, err := json.Marshal(e.RawActions)
		if err != nil {
			return fmt.Errorf("actions of %s: %w", e.Code, err)
		}
		if err := json.Unmarshal(raw, &e.Actions); err != nil {
			return fmt.Errorf("actions of %s: %w", e.Code, err)
		}
	}
	return nil
}

// Hash is the fingerprint of everything that decides what this detection does
// and what it says.
//
// Computed over a canonical JSON form with the slices sorted, so reordering a
// framework list or re-indenting a file is not a new version. The source path
// is excluded for the same reason: moving a file is not a content change.
//
// If this ever stops covering a field, a change to that field would ship
// silently under the old version number — so the test that walks every exported
// field is not decoration.
func (e *Entry) Hash() string {
	type canonical struct {
		Code             string               `json:"code"`
		Title            string               `json:"title"`
		Description      string               `json:"description"`
		Category         string               `json:"category"`
		Severity         string               `json:"severity"`
		Tactic           string               `json:"tactic"`
		Technique        string               `json:"technique"`
		Conditions       model.RuleConditions `json:"conditions"`
		Actions          []model.RuleAction   `json:"actions"`
		DedupWindowS     int                  `json:"dedup_window_s"`
		Rationale        string               `json:"rationale"`
		FalsePositives   string               `json:"false_positives"`
		Response         string               `json:"response"`
		Frameworks       []string             `json:"frameworks"`
		Controls         []string             `json:"controls"`
		Requires         []string             `json:"requires"`
		EnabledByDefault bool                 `json:"enabled_by_default"`
		Tags             []string             `json:"tags"`
	}

	c := canonical{
		Code: e.Code, Title: e.Title, Description: e.Description,
		Category: e.Category, Severity: e.Severity,
		Tactic: e.Mitre.Tactic, Technique: e.Mitre.Technique,
		Conditions: e.Conditions, Actions: e.Actions,
		DedupWindowS: e.DedupWindowS,
		Rationale:    e.Rationale, FalsePositives: e.FalsePositives, Response: e.Response,
		Frameworks: sortedCopy(e.Frameworks), Controls: sortedCopy(e.Controls),
		Requires:         sortedCopy(e.Requires),
		EnabledByDefault: e.EnabledByDefault, Tags: sortedCopy(e.Tags),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		// Marshalling a struct of strings, numbers and the rule model cannot
		// fail; if it somehow does, a hash that changes every time is safer
		// than one that collides.
		return hashOf([]byte(fmt.Sprintf("unmarshalable:%s:%v", e.Code, err)))
	}
	return hashOf(raw)
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sortedCopy orders a list without disturbing the caller's.
//
// A nil list stays nil rather than becoming empty: the hash has to be the same
// whether an author wrote `requires: []` or left the key out, because they mean
// the same thing and neither is a new version of the detection.
func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// Normalised trims what an author's editor may have left behind, so whitespace
// is never the difference between two versions.
func (e *Entry) Normalised() {
	trim := func(s *string) { *s = strings.TrimSpace(*s) }
	trim(&e.Code)
	trim(&e.Title)
	trim(&e.Description)
	trim(&e.Category)
	trim(&e.Severity)
	trim(&e.Mitre.Tactic)
	trim(&e.Mitre.Technique)
	trim(&e.Rationale)
	trim(&e.FalsePositives)
	trim(&e.Response)
	for _, list := range [][]string{e.Frameworks, e.Controls, e.Requires, e.Tags} {
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
		}
	}
}
