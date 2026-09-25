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
		//nolint:errcheck // best-effort cleanup; the next run uses a fresh tenant anyway
		pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID) // cascades
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
