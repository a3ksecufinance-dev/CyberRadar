package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/repository"
)

// libraryTestDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a skip
// reads like a pass in CI output, so setting SIEM_TEST_DSN turns it into a
// failure. CI sets it.
func libraryTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn, required := os.LookupEnv("SIEM_TEST_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_fresh?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("SIEM_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set SIEM_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func libraryFixture(t *testing.T, pool *pgxpool.Pool) (*LibraryService, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		tenantID, "library fixture", "libfix-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		//nolint:errcheck // best effort on a tenant unique to this run
		pool.Exec(ctx, `DELETE FROM detection_rules WHERE tenant_id = $1`, tenantID)
		//nolint:errcheck // idem
		pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	svc := NewLibraryService(
		repository.NewLibraryRepository(pool),
		repository.NewRuleRepository(pool),
		zerolog.Nop(),
	)
	return svc, tenantID
}

func entryFor(t *testing.T, entries []*model.LibraryEntry, code string) *model.LibraryEntry {
	t.Helper()
	for _, e := range entries {
		if e.Content.Code == code {
			return e
		}
	}
	t.Fatalf("%s is not in the library", code)
	return nil
}

// Adopting with no overrides has to produce no differences. Otherwise "what did
// you change" is never answerable: every tenant would look as though they had
// changed something from the moment they started.
func TestAdoptingUnchangedShowsNoDifference(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	if _, err := svc.Adopt(ctx, tenantID, nil, "CRP-IAM-0001", &model.AdoptRequest{}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	entries, err := svc.Catalogue(ctx, tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	entry := entryFor(t, entries, "CRP-IAM-0001")
	if entry.Adopted == nil {
		t.Fatal("the entry does not report itself as adopted")
	}
	if len(entry.Adopted.Changes) != 0 {
		t.Errorf("an unchanged adoption reports %d differences: %#v",
			len(entry.Adopted.Changes), entry.Adopted.Changes)
	}
	if entry.Adopted.UpdateAvailable {
		t.Error("an adoption of the current version reports an update available")
	}
}

// An override has to show up as exactly that field, and no other.
func TestAnOverrideIsReportedAsADifference(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	critical := model.SeverityCritical
	window := 111
	if _, err := svc.Adopt(ctx, tenantID, nil, "CRP-EXF-0001", &model.AdoptRequest{
		Severity:     &critical,
		DedupWindowS: &window,
	}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	entries, err := svc.Catalogue(ctx, tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	entry := entryFor(t, entries, "CRP-EXF-0001")

	changed := map[string]model.FieldChange{}
	for _, c := range entry.Adopted.Changes {
		changed[c.Field] = c
	}
	if len(changed) != 2 {
		t.Fatalf("two overrides produced %d differences: %#v", len(changed), entry.Adopted.Changes)
	}
	if got := changed["severity"]; got.Tenant != "CRITICAL" {
		t.Errorf("severity difference = %#v, want the tenant at CRITICAL", got)
	}
	if got := changed["dedup_window_s"]; got.Tenant != "111" {
		t.Errorf("dedup_window_s difference = %#v, want the tenant at 111", got)
	}
}

// The difference is against the version adopted, not against whatever ships
// today. Comparing to the current version would report the platform's own
// improvement as the customer's change — the exact wrong answer.
func TestTheDifferenceIsAgainstTheAdoptedVersion(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-DIS-0001"
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// The platform publishes a stricter version: same detection, different
	// severity and a wider window.
	publishNextVersion(t, pool, code)

	entries, err := svc.Catalogue(ctx, tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	entry := entryFor(t, entries, code)

	if !entry.Adopted.UpdateAvailable {
		t.Error("a newer content version is available and the entry does not say so")
	}
	if entry.Adopted.AtVersion != 1 {
		t.Errorf("adopted version = %d, want 1", entry.Adopted.AtVersion)
	}
	if len(entry.Adopted.Changes) != 0 {
		t.Errorf("the platform's own change is reported as the tenant's: %#v", entry.Adopted.Changes)
	}
}

// publishNextVersion supersedes a catalogue entry the way a content release
// would: the old row is retired, a new version takes its place.
func publishNextVersion(t *testing.T, pool *pgxpool.Pool, code string) {
	t.Helper()
	ctx := context.Background()

	// Retire first, then insert. The unique index allows one current row per
	// code, so the other order fails — which is the point of the index: two
	// current versions would make "which one ships today" ambiguous.
	if _, err := pool.Exec(ctx, `
		INSERT INTO detection_content
			(code, version, title, description, category, severity,
			 mitre_tactic, mitre_technique, conditions, actions, dedup_window_s,
			 rationale, frameworks, controls, requires, enabled_by_default, tags, retired_at)
		SELECT code, version + 1, title, description, category,
		       CASE severity WHEN 'MEDIUM' THEN 'HIGH' ELSE 'CRITICAL' END,
		       mitre_tactic, mitre_technique, conditions, actions, dedup_window_s + 60,
		       rationale, frameworks, controls, requires, enabled_by_default, tags, NOW()
		FROM detection_content WHERE code = $1 AND retired_at IS NULL`, code); err != nil {
		t.Fatalf("stage the next version of %s: %v", code, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE detection_content SET retired_at = NOW() WHERE code = $1 AND version = 1`,
		code); err != nil {
		t.Fatalf("retire version 1 of %s: %v", code, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE detection_content SET retired_at = NULL WHERE code = $1 AND version = 2`,
		code); err != nil {
		t.Fatalf("publish version 2 of %s: %v", code, err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		//nolint:errcheck // best effort
		pool.Exec(ctx, `DELETE FROM detection_content WHERE code = $1 AND version > 1`, code)
		//nolint:errcheck // idem
		pool.Exec(ctx, `UPDATE detection_content SET retired_at = NULL WHERE code = $1 AND version = 1`, code)
	})
}

// Adopting twice would double every alert the detection raises, and the two
// copies would drift apart.
func TestAdoptingTwiceIsRefused(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	if _, err := svc.Adopt(ctx, tenantID, nil, "CRP-C2-0001", &model.AdoptRequest{}); err != nil {
		t.Fatalf("first adoption: %v", err)
	}
	if _, err := svc.Adopt(ctx, tenantID, nil, "CRP-C2-0001", &model.AdoptRequest{}); err == nil {
		t.Fatal("the same detection was adopted twice")
	}
}

// An entry that cannot fire yet must arrive disabled, whatever its own default
// says. Enabling it silently would present coverage the platform does not have.
func TestAnEntryWithPrerequisitesArrivesDisabled(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	rule, err := svc.Adopt(ctx, tenantID, nil, "CRP-GEO-0001", &model.AdoptRequest{})
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if rule.Enabled {
		t.Error("an entry that needs a GeoIP database was adopted enabled")
	}

	// And it can still be taken on purpose, by someone who has read what it
	// needs — the catalogue informs, it does not forbid.
	svc2, tenant2 := libraryFixture(t, pool)
	on := true
	rule2, err := svc2.Adopt(ctx, tenant2, nil, "CRP-GEO-0001", &model.AdoptRequest{Enabled: &on})
	if err != nil {
		t.Fatalf("adopt explicitly enabled: %v", err)
	}
	if !rule2.Enabled {
		t.Error("an explicit enable was ignored")
	}
}

// Every condition the platform ships must name a field the engine reads.
//
// This is the check that stops a shipped detection that can never fire. A rule
// naming an unknown field loads, matches nothing, and looks like coverage — and
// the analyst finds out when an incident is not detected.
func TestEveryShippedConditionNamesAKnownField(t *testing.T) {
	pool := libraryTestDB(t)
	repo := repository.NewLibraryRepository(pool)

	entries, err := repo.Catalogue(context.Background())
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	if len(entries) < 10 {
		t.Fatalf("%d entries in the library; migration 000040 seeds fifteen", len(entries))
	}

	for _, entry := range entries {
		for _, fm := range entry.Conditions.FieldMatches {
			if !KnownField(fm.Field) {
				t.Errorf("%s matches on %q, which the engine does not read: the rule would never fire",
					entry.Code, fm.Field)
			}
		}
		if threshold := entry.Conditions.Threshold; threshold != nil {
			for _, field := range threshold.GroupBy {
				if !KnownField(field) {
					t.Errorf("%s groups by %q, which the engine does not read", entry.Code, field)
				}
			}
		}
		if len(entry.Conditions.FieldMatches) == 0 && entry.Conditions.Threshold == nil {
			t.Errorf("%s has no condition at all", entry.Code)
		}
		if entry.Rationale == "" {
			t.Errorf("%s ships without a rationale; a detection nobody can explain is a pager that says nothing", entry.Code)
		}
	}
}

// And the other half of that contract: every field the engine advertises has to
// resolve to something. A name in KnownFields that getField does not handle
// would let a rule through this test and still never fire.
func TestEveryKnownFieldResolves(t *testing.T) {
	name := "svc-admin"
	src, dst := "198.51.100.23", "10.40.3.41"
	tactic, technique := "TA0011", "T1071.001"
	country := "FR"
	ev := &event.NormalizedEvent{
		Category: event.CategorySecurity, Severity: event.SeverityCritical,
		Outcome: event.OutcomeSuccess, Action: "process_exec", SourceType: "application",
		MitreTactic: &tactic, MitreTechnique: &technique,
		UserID: &name, UserName: &name, IPSource: &src, IPDestination: &dst,
		GeoCountry: &country,
		RiskScore:  9, ThreatScore: 9, CBSImpact: 1, SWIFTImpact: 1,
		IOCMatched: []string{"ip:198.51.100.23@ip_destination"},
	}

	for _, field := range KnownFields {
		if got := getField(ev, field); got == "" {
			t.Errorf("getField(%q) is empty on a fully populated event: a rule naming it could never match", field)
		}
	}
}
