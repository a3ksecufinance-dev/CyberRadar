package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/ir/internal/model"
)

// testDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting IR_TEST_DSN
// turns the skip into a failure. CI sets it.
func testDB(t *testing.T) (*IRRepository, uuid.UUID) {
	t.Helper()

	dsn, required := os.LookupEnv("IR_TEST_DSN")
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
			t.Fatalf("IR_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set IR_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)

	// A tenant of our own, so the test never depends on seed data and never
	// collides with another test's rows.
	tenantID := uuid.New()
	slug := "test-" + tenantID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		tenantID, slug, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		// ir_incidents carries a tenant_id but no foreign key to tenants, so
		// dropping the tenant leaves its incidents behind — invisible to
		// every tenant-scoped query and still counted by anything that is
		// not. Clear the rows this test owns, then the tenant.
		bg := context.Background()
		//nolint:errcheck // best-effort cleanup; the next run uses a fresh tenant anyway
		pool.Exec(bg, `DELETE FROM ir_incidents WHERE tenant_id = $1`, tenantID) // cascades to timeline, tasks, evidence
		//nolint:errcheck // same
		pool.Exec(bg, `DELETE FROM ir_playbooks WHERE tenant_id = $1`, tenantID)
		//nolint:errcheck // same
		pool.Exec(bg, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	return NewIRRepository(pool), tenantID
}

// An incident whose optional text fields are all omitted is the ordinary case:
// description, source, source_ref, attack_vector, estimated_impact and
// lead_name are nullable and have no default, so every freshly created row has
// NULLs in them. They are scanned into plain Go strings, which cannot hold
// NULL — so CreateIncident failed with
//
//	can't scan into dest[16]: cannot scan NULL into *string
//
// and no incident could be created at all. The columns are COALESCEd in every
// query that reads the row; this test is what keeps them that way.
func TestCreateIncidentWithNoOptionalText(t *testing.T) {
	repo, tenantID := testDB(t)
	ctx := context.Background()

	inc, err := repo.CreateIncident(ctx, tenantID, &model.CreateIncidentRequest{
		Title:        "Minimal incident",
		IncidentType: "phishing",
		Severity:     "high",
	}, nil)
	if err != nil {
		t.Fatalf("CreateIncident with no optional text: %v", err)
	}

	// The absent fields must read back as empty strings, not as an error and
	// not as the literal "NULL".
	for name, got := range map[string]string{
		"description":      inc.Description,
		"source":           inc.Source,
		"source_ref":       inc.SourceRef,
		"attack_vector":    inc.AttackVector,
		"estimated_impact": inc.EstimatedImpact,
		"lead_name":        inc.LeadName,
	} {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
	}
	if inc.IncidentNumber == "" {
		t.Error("incident_number is empty")
	}

	// Reading it back goes through a different query, with the same hazard.
	again, err := repo.GetIncident(ctx, tenantID, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if again.Title != inc.Title {
		t.Errorf("GetIncident title = %q, want %q", again.Title, inc.Title)
	}

	// And so does listing.
	list, total, err := repo.ListIncidents(ctx, tenantID, model.ListIncidentsFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("ListIncidents returned %d of %d, want 1 of 1", len(list), total)
	}
}

// The detection delay, derived from the timeline.
//
// mttd_minutes had no writer: it was declared in the schema, averaged by the
// statistics query and shown on the incident screen as "Avg MTTD", and nothing
// in the service ever set it — so the figure a CISO is judged on was
// permanently empty, next to a time-to-recover the same table computes. It is
// derived here from the two facts the responders record: when the attacker
// first did something, and when the institution saw it.
func TestTheDetectionDelayComesFromTheTimeline(t *testing.T) {
	repo, tenantID := testDB(t)
	ctx := context.Background()

	detected := time.Now().UTC().Add(-2 * time.Hour)
	inc, err := repo.CreateIncident(ctx, tenantID, &model.CreateIncidentRequest{
		Title: "Exfiltration depuis le socle de sauvegarde", IncidentType: "data_breach",
		Severity: "high", DetectedAt: &detected,
	}, nil)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if inc.MTTDMinutes != nil {
		t.Errorf("an incident with no timeline already claims a detection delay: %d", *inc.MTTDMinutes)
	}

	// An analyst note is not attacker activity, and says nothing about when
	// the attack began.
	if _, err := repo.AddTimelineEvent(ctx, tenantID, inc.ID, &model.CreateTimelineEventRequest{
		EventTime: detected.Add(5 * time.Minute), EventType: "note",
		Title: "Prise en charge par l'astreinte", Actor: "SOC", ActorType: "analyst",
	}, nil); err != nil {
		t.Fatalf("AddTimelineEvent(note): %v", err)
	}
	after, err := repo.GetIncident(ctx, tenantID, inc.ID)
	if err != nil || after == nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if after.MTTDMinutes != nil {
		t.Errorf("an analyst note set the detection delay to %d", *after.MTTDMinutes)
	}

	// The first recorded attacker step, ninety minutes before the detection.
	if _, err := repo.AddTimelineEvent(ctx, tenantID, inc.ID, &model.CreateTimelineEventRequest{
		EventTime: detected.Add(-90 * time.Minute), EventType: "attacker_activity",
		Title: "Première connexion du compte de service depuis une adresse externe",
		Actor: "inconnu", ActorType: "attacker",
	}, nil); err != nil {
		t.Fatalf("AddTimelineEvent(attacker_activity): %v", err)
	}
	timed, err := repo.GetIncident(ctx, tenantID, inc.ID)
	if err != nil || timed == nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if timed.MTTDMinutes == nil {
		t.Fatal("the attacker's first step left the detection delay empty")
	}
	if *timed.MTTDMinutes != 90 {
		t.Errorf("the detection delay reads %d minutes, want 90", *timed.MTTDMinutes)
	}

	// An earlier step moves it; a later one does not, because the delay runs
	// from the first thing the attacker did.
	if _, err := repo.AddTimelineEvent(ctx, tenantID, inc.ID, &model.CreateTimelineEventRequest{
		EventTime: detected.Add(-30 * time.Minute), EventType: "attacker_activity",
		Title: "Copie de l'export vers un hébergeur public", ActorType: "attacker",
	}, nil); err != nil {
		t.Fatalf("AddTimelineEvent(later): %v", err)
	}
	still, err := repo.GetIncident(ctx, tenantID, inc.ID)
	if err != nil || still == nil || still.MTTDMinutes == nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if *still.MTTDMinutes != 90 {
		t.Errorf("a later attacker step moved the delay to %d, want it still 90", *still.MTTDMinutes)
	}
}
