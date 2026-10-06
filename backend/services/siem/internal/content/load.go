package content

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/service"
)

// PackFile is the name the pack's own identity lives under.
const PackFile = "pack.yaml"

// Load reads a content directory and returns the pack and its entries, in code
// order, having checked every one of them.
//
// Validation happens here rather than at publication because the point of
// taking content out of the code is that it ships without the code's tests
// running. A detection naming a field the engine does not read would load,
// match nothing, and present itself as coverage — which is the failure the
// catalogue exists to prevent, and it must not become reachable by editing a
// file.
func Load(dir string) (*Pack, []*Entry, error) {
	pack, err := loadPack(filepath.Join(dir, PackFile))
	if err != nil {
		return nil, nil, err
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var entries []*Entry
	var problems []string
	seen := map[string]string{}

	for _, path := range paths {
		if filepath.Base(path) == PackFile {
			continue
		}
		entry, err := loadEntry(path)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if first, ok := seen[entry.Code]; ok {
			problems = append(problems, fmt.Sprintf(
				"%s: %s is already defined in %s", filepath.Base(path), entry.Code, first))
			continue
		}
		seen[entry.Code] = filepath.Base(path)

		if errs := Validate(entry); len(errs) > 0 {
			for _, e := range errs {
				problems = append(problems, fmt.Sprintf("%s: %s", filepath.Base(path), e))
			}
			continue
		}
		entries = append(entries, entry)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, nil, fmt.Errorf("%d problem(s) in %s:\n  %s",
			len(problems), dir, strings.Join(problems, "\n  "))
	}
	if len(entries) == 0 {
		// An empty directory would otherwise retire the whole catalogue, which
		// is a thing somebody might mean and never a thing they mean by
		// accident. Said rather than done.
		return nil, nil, fmt.Errorf("%s holds no detection; refusing to treat that as a catalogue of nothing", dir)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Code < entries[j].Code })
	return pack, entries, nil
}

func loadPack(path string) (*Pack, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a content directory the operator named
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var pack Pack
	if err := yaml.Unmarshal(raw, &pack); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if strings.TrimSpace(pack.Version) == "" {
		return nil, fmt.Errorf("%s has no version; a pack nobody can name is one nobody can say they are running", path)
	}
	if strings.TrimSpace(pack.Name) == "" {
		return nil, fmt.Errorf("%s has no name", path)
	}
	return &pack, nil
}

func loadEntry(path string) (*Entry, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a content directory the operator named
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	var entry Entry
	// KnownFields so a misspelled key is an error rather than a field silently
	// left at its zero value — "rational:" instead of "rationale:" would
	// otherwise ship a detection with no reasoning and no complaint.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&entry); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	entry.Source = filepath.Base(path)
	entry.Normalised()
	if err := entry.resolve(); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return &entry, nil
}

var (
	// The family may carry a digit: C2 is what command and control is called,
	// and a pattern that forbade it would rename an established convention to
	// suit itself.
	codePattern      = regexp.MustCompile(`^CRP-[A-Z][A-Z0-9]{1,3}-\d{4}$`)
	tacticPattern    = regexp.MustCompile(`^TA\d{4}$`)
	techniquePattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

var severities = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

// Validate reports everything wrong with one entry, rather than the first thing.
//
// All of them, because an author fixing content one error per run is an author
// who stops reading the errors.
func Validate(e *Entry) []string {
	var errs []string
	say := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if !codePattern.MatchString(e.Code) {
		say("code %q does not look like CRP-XXX-0000", e.Code)
	}
	if e.Title == "" {
		say("no title")
	}
	if e.Category == "" {
		say("no category")
	}
	if !severities[e.Severity] {
		say("severity %q is not LOW, MEDIUM, HIGH or CRITICAL", e.Severity)
	}
	if e.Mitre.Tactic != "" && !tacticPattern.MatchString(e.Mitre.Tactic) {
		say("mitre tactic %q is not a TA#### identifier", e.Mitre.Tactic)
	}
	if e.Mitre.Technique != "" && !techniquePattern.MatchString(e.Mitre.Technique) {
		say("mitre technique %q is not a T#### or T####.### identifier", e.Mitre.Technique)
	}
	if e.DedupWindowS < 0 || e.DedupWindowS > 86400 {
		say("dedup_window_s %d is outside 0–86400", e.DedupWindowS)
	}

	// The reasoning is the third thing an analyst reads at three in the
	// morning, and the one a rule list never carries. A detection without it is
	// a pager that says nothing.
	if len(strings.TrimSpace(e.Rationale)) < 20 {
		say("rationale is missing or too short to be a reason")
	}

	// Every field a condition names has to be one the engine reads. A detection
	// keyed on an unknown field loads, matches nothing, and presents itself as
	// coverage — worse than no detection at all.
	for _, f := range conditionFields(e.Conditions) {
		if !service.KnownField(f) {
			say("condition names %q, which the rule engine does not read", f)
		}
	}
	if len(conditionFields(e.Conditions)) == 0 && e.Conditions.Threshold == nil {
		say("has neither a field match nor a threshold, so it can never fire")
	}

	// An entry that needs something this deployment does not produce must ship
	// off. Shipping it on would present coverage the platform does not have.
	if len(e.Requires) > 0 && e.EnabledByDefault {
		say("needs %s and is still enabled_by_default", strings.Join(e.Requires, ", "))
	}

	return errs
}

// conditionFields is every field name a condition tree mentions.
func conditionFields(c model.RuleConditions) []string {
	var out []string
	for _, m := range c.FieldMatches {
		out = append(out, m.Field)
	}
	if c.Threshold != nil {
		out = append(out, c.Threshold.GroupBy...)
	}
	return out
}
