package content

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// packDir is the catalogue this repository ships.
func packDir() string { return filepath.Join("..", "..", "..", "..", "content", "detections") }

// The pack the platform ships has to load and validate. This replaces the test
// that read the catalogue back out of a database seeded by a migration: the
// files are the source now, and the database is a consequence.
//
// It needs no database, which matters more than it sounds: content ships
// without the code, so the check that content is sound has to run without the
// platform running.
func TestTheShippedPackIsValid(t *testing.T) {
	pack, entries, err := Load(packDir())
	if err != nil {
		t.Fatalf("the shipped pack does not load:\n%v", err)
	}
	if pack.Version == "" {
		t.Error("the pack has no version")
	}
	if len(entries) < 10 {
		t.Fatalf("%d detections in the pack; it carried fifteen", len(entries))
	}

	// Every fingerprint distinct: two detections hashing the same would make
	// one of them invisible to the reconciliation.
	seen := map[string]string{}
	for _, e := range entries {
		if first, ok := seen[e.Hash()]; ok {
			t.Errorf("%s and %s have the same fingerprint", first, e.Code)
		}
		seen[e.Hash()] = e.Code
	}
}

// If the fingerprint ever stops covering a field, a change to that field ships
// silently under the old version number — and every tenant running it is told
// they are current while running something else.
//
// Walked by reflection rather than listed by hand, so a field added to Entry
// and forgotten in the canonical form fails here instead of in a customer's
// catalogue.
func TestTheFingerprintCoversEverySubstantiveField(t *testing.T) {
	base := minimalEntry()
	original := base.Hash()

	// Source is the file a detection came from. Moving a file is not a content
	// change, so it is deliberately outside the fingerprint — and the raw
	// fields are what YAML parsed before conversion, which the typed ones
	// already carry.
	outside := map[string]bool{"Source": true, "RawConditions": true, "RawActions": true}

	v := reflect.ValueOf(&base).Elem()
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if outside[name] {
			continue
		}
		mutated := minimalEntry()
		field := reflect.ValueOf(&mutated).Elem().Field(i)
		if !mutate(field) {
			t.Fatalf("the test does not know how to change %s (%s)", name, field.Type())
		}
		if mutated.Hash() == original {
			t.Errorf("changing %s does not change the fingerprint, so a change to it would ship under the old version", name)
		}
	}
}

// mutate changes a field to something else of its type, and reports whether it
// could.
func mutate(f reflect.Value) bool {
	switch f.Kind() {
	case reflect.String:
		f.SetString(f.String() + "-moved")
		return true
	case reflect.Int:
		f.SetInt(f.Int() + 7)
		return true
	case reflect.Bool:
		f.SetBool(!f.Bool())
		return true
	case reflect.Slice:
		if f.Type().Elem().Kind() == reflect.String {
			f.Set(reflect.ValueOf([]string{"moved"}))
			return true
		}
		// A slice of structs: the rule actions. Appending one is a change.
		grown := reflect.Append(f, reflect.New(f.Type().Elem()).Elem())
		f.Set(grown)
		return true
	case reflect.Struct:
		// Mitre, and the conditions. Changing any one leaf is enough.
		for i := 0; i < f.NumField(); i++ {
			if f.Field(i).CanSet() && mutate(f.Field(i)) {
				return true
			}
		}
		return false
	case reflect.Ptr:
		if f.IsNil() {
			f.Set(reflect.New(f.Type().Elem()))
		}
		return mutate(f.Elem())
	default:
		return false
	}
}

// Re-indenting a file or reordering a list is not a new version of a detection,
// and treating it as one would tell every tenant that an update is available
// because somebody ran a formatter.
func TestReorderingAListIsNotAChange(t *testing.T) {
	a := minimalEntry()
	a.Frameworks = []string{"DORA", "PCIDSS", "ISO27001"}
	a.Tags = []string{"standard", "authentification"}

	b := minimalEntry()
	b.Frameworks = []string{"ISO27001", "DORA", "PCIDSS"}
	b.Tags = []string{"authentification", "standard"}

	if a.Hash() != b.Hash() {
		t.Error("reordering frameworks and tags produced a different fingerprint")
	}
}

// An author who writes `requires: []` and one who leaves the key out mean the
// same thing, and neither has published a new version.
func TestAnEmptyListAndAnAbsentOneAreTheSame(t *testing.T) {
	absent := minimalEntry()
	absent.Requires = nil
	empty := minimalEntry()
	empty.Requires = []string{}

	if absent.Hash() != empty.Hash() {
		t.Error("an absent list and an empty one produced different fingerprints")
	}
}

// A detection keyed on a field the engine does not read loads, matches nothing,
// and presents itself as coverage. It must not be reachable by editing a file.
func TestAConditionOnAnUnknownFieldIsRefused(t *testing.T) {
	e := minimalEntry()
	e.Conditions.FieldMatches[0].Field = "cbs_impact_that_nothing_writes"
	errs := Validate(&e)
	if !mentions(errs, "does not read") {
		t.Errorf("a condition on an unknown field was accepted: %v", errs)
	}
}

// A detection that needs something this deployment does not produce must ship
// off. Shipping it on would present coverage the platform does not have.
func TestAnEntryThatNeedsSomethingCannotShipEnabled(t *testing.T) {
	e := minimalEntry()
	e.Requires = []string{"a licensed GeoIP database"}
	e.EnabledByDefault = true
	if errs := Validate(&e); !mentions(errs, "enabled_by_default") {
		t.Errorf("an entry with prerequisites shipped enabled: %v", errs)
	}
}

// The reasoning is what an analyst reads at three in the morning. A detection
// without it is a pager that says nothing.
func TestADetectionWithNoReasonIsRefused(t *testing.T) {
	e := minimalEntry()
	e.Rationale = "parce que"
	if errs := Validate(&e); !mentions(errs, "rationale") {
		t.Errorf("a detection with no reason was accepted: %v", errs)
	}
}

// Validation reports everything wrong at once. An author fixing content one
// error per run is an author who stops reading the errors.
func TestEverythingWrongIsReportedAtOnce(t *testing.T) {
	e := minimalEntry()
	e.Code = "nonsense"
	e.Severity = "URGENT"
	e.Rationale = ""
	if errs := Validate(&e); len(errs) < 3 {
		t.Errorf("three things are wrong and %d were reported: %v", len(errs), errs)
	}
}

// A misspelled key would otherwise leave a field at its zero value in silence:
// "rational:" instead of "rationale:" would ship a detection with no reasoning
// and no complaint.
func TestAMisspelledKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, PackFile, "name: test\nversion: \"0.1\"\n")
	write(t, dir, "CRP-TST-0001.yaml", `
code: CRP-TST-0001
title: Essai
category: IAM
severity: HIGH
rational: ceci est une faute de frappe sur le nom du champ
conditions:
  field_matches:
    - { field: category, op: eq, value: IAM }
`)
	_, _, err := Load(dir)
	if err == nil {
		t.Fatal("a misspelled key loaded without complaint")
	}
	if !strings.Contains(err.Error(), "rational") {
		t.Errorf("the error does not name the misspelled key: %v", err)
	}
}

// Two files claiming the same code is an authoring mistake with a silent
// outcome: whichever sorted last would win.
func TestTwoFilesCannotClaimTheSameCode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, PackFile, "name: test\nversion: \"0.1\"\n")
	for _, name := range []string{"a.yaml", "b.yaml"} {
		write(t, dir, name, `
code: CRP-TST-0001
title: Essai
category: IAM
severity: HIGH
rationale: une raison assez longue pour passer la validation
conditions:
  field_matches:
    - { field: category, op: eq, value: IAM }
`)
	}
	_, _, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("two files claiming one code loaded: %v", err)
	}
}

// An empty directory would retire the whole catalogue. Somebody might mean
// that; nobody means it by accident.
func TestAnEmptyPackIsRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, PackFile, "name: test\nversion: \"0.1\"\n")
	if _, _, err := Load(dir); err == nil {
		t.Fatal("a pack with no detection loaded")
	}
}

// A pack nobody can name is one nobody can say they are running.
func TestAPackWithoutAVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, PackFile, "name: test\n")
	if _, _, err := Load(dir); err == nil {
		t.Fatal("a pack with no version loaded")
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func minimalEntry() Entry {
	var e Entry
	e.Code = "CRP-TST-0001"
	e.Title = "Essai"
	e.Description = "Une détection d'essai."
	e.Category = "IAM"
	e.Severity = "HIGH"
	e.Mitre.Tactic = "TA0006"
	e.Mitre.Technique = "T1110.004"
	e.DedupWindowS = 300
	e.Rationale = "une raison assez longue pour passer la validation"
	e.FalsePositives = "des choses"
	e.Response = "autre chose"
	e.Frameworks = []string{"DORA"}
	e.Controls = []string{"DORA-10.3"}
	e.Requires = nil
	e.EnabledByDefault = true
	e.Tags = []string{"standard"}
	e.RawConditions = map[string]any{
		"field_matches": []any{map[string]any{"field": "category", "op": "eq", "value": "IAM"}},
	}
	if err := e.resolve(); err != nil {
		panic(err)
	}
	return e
}

func mentions(errs []string, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
