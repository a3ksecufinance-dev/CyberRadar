package repository

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const dim = 1024

// testRepo connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting
// COPILOT_TEST_DSN turns the skip into a failure. CI sets it.
func testRepo(t *testing.T) (*CopilotRepository, uuid.UUID) {
	t.Helper()

	dsn, required := os.LookupEnv("COPILOT_TEST_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_vec2?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("COPILOT_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set COPILOT_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		tenantID, "t-"+tenantID.String()[:8], "t-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	return NewCopilotRepository(pool), tenantID
}

// unit returns a unit vector pointing along one axis, so similarity between
// two of them is exactly 1 when equal and 0 when different.
func unit(axis int) []float32 {
	v := make([]float32, dim)
	v[axis] = 1
	return v
}

// blend points between two axes, so its similarity to each is predictable.
func blend(a, b int, weight float32) []float32 {
	v := make([]float32, dim)
	v[a] = 1 - weight
	v[b] = weight
	return v
}

func index(t *testing.T, r *CopilotRepository, tenantID uuid.UUID, ref string, vec []float32) {
	t.Helper()
	_, err := r.UpsertKnowledge(context.Background(), tenantID, &model.IndexKnowledgeRequest{
		SourceType: model.KnowledgeSourceIncident, SourceRef: ref,
		Title: "Title " + ref, Content: "Content " + ref,
	}, vec)
	if err != nil {
		t.Fatalf("UpsertKnowledge(%s): %v", ref, err)
	}
}

// ─── The column the index is built on ─────────────────────────────────────────

func TestEmbeddingDimensionMatchesTheSchema(t *testing.T) {
	// The service checks its model against this at startup. If it ever read
	// something other than the column's real width, a mismatched model would
	// be accepted and every row it wrote would be unusable.
	r, _ := testRepo(t)

	got, err := r.EmbeddingDimension(context.Background())
	if err != nil {
		t.Fatalf("EmbeddingDimension: %v", err)
	}
	if got != dim {
		t.Errorf("dimension = %d, want %d", got, dim)
	}
}

func TestAWrongWidthVectorIsRefused(t *testing.T) {
	r, tenantID := testRepo(t)

	_, err := r.UpsertKnowledge(context.Background(), tenantID, &model.IndexKnowledgeRequest{
		SourceType: model.KnowledgeSourceNote, SourceRef: "short", Title: "t", Content: "c",
	}, make([]float32, 8))
	if err == nil {
		t.Error("an 8-dimension vector was written into a 1024-dimension column")
	}
}

// ─── Similarity ───────────────────────────────────────────────────────────────

func TestSearchRanksBySimilarity(t *testing.T) {
	r, tenantID := testRepo(t)

	index(t, r, tenantID, "exact", unit(0))
	index(t, r, tenantID, "close", blend(0, 1, 0.3))
	index(t, r, tenantID, "unrelated", unit(2))

	got, err := r.SearchKnowledge(context.Background(), tenantID, unit(0), 5, 0)
	if err != nil {
		t.Fatalf("SearchKnowledge: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("%d results, want 3", len(got))
	}
	if got[0].SourceRef != "exact" || got[1].SourceRef != "close" {
		t.Errorf("order = %s, %s, %s; want exact, close, unrelated",
			got[0].SourceRef, got[1].SourceRef, got[2].SourceRef)
	}
	if math.Abs(got[0].Similarity-1.0) > 1e-4 {
		t.Errorf("an identical vector scored %.4f, want 1", got[0].Similarity)
	}
}

func TestWeakMatchesAreDropped(t *testing.T) {
	// An unrelated question must retrieve nothing, so the model says it has
	// nothing — rather than being handed the least-unrelated document in the
	// corpus and treating it as evidence.
	r, tenantID := testRepo(t)

	index(t, r, tenantID, "unrelated", unit(2))

	got, err := r.SearchKnowledge(context.Background(), tenantID, unit(0), 5, 0.35)
	if err != nil {
		t.Fatalf("SearchKnowledge: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("%d results for an orthogonal query, want 0 (similarity %.4f)", len(got), got[0].Similarity)
	}
}

func TestSearchIsScopedToItsTenant(t *testing.T) {
	// The tenant filter is in the WHERE clause, not applied after ordering:
	// an ORDER BY over the index followed by a filter returns another
	// customer's documents whenever they are the closest match.
	r, tenantA := testRepo(t)
	_, tenantB := testRepo(t)

	index(t, r, tenantA, "tenant-a-doc", unit(0))

	got, err := r.SearchKnowledge(context.Background(), tenantB, unit(0), 5, 0)
	if err != nil {
		t.Fatalf("SearchKnowledge: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("tenant B retrieved %d of tenant A's documents", len(got))
	}
}

func TestLimitIsHonoured(t *testing.T) {
	r, tenantID := testRepo(t)
	for i := 0; i < 8; i++ {
		index(t, r, tenantID, "doc-"+uuid.NewString()[:8], blend(0, 1, float32(i)/100))
	}

	got, err := r.SearchKnowledge(context.Background(), tenantID, unit(0), 3, 0)
	if err != nil {
		t.Fatalf("SearchKnowledge: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("%d results, want 3", len(got))
	}
}

// ─── Re-indexing ──────────────────────────────────────────────────────────────

func TestReindexingReplacesRatherThanDuplicates(t *testing.T) {
	// An incident edited three times would otherwise sit in the index three
	// times and crowd out everything else for the queries it matches.
	r, tenantID := testRepo(t)
	ctx := context.Background()

	for _, title := range []string{"First draft", "Second draft", "Final"} {
		if _, err := r.UpsertKnowledge(ctx, tenantID, &model.IndexKnowledgeRequest{
			SourceType: model.KnowledgeSourceIncident, SourceRef: "INC-1",
			Title: title, Content: "body",
		}, unit(0)); err != nil {
			t.Fatalf("UpsertKnowledge: %v", err)
		}
	}

	got, err := r.SearchKnowledge(ctx, tenantID, unit(0), 10, 0)
	if err != nil {
		t.Fatalf("SearchKnowledge: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d copies of one document, want 1", len(got))
	}
	if got[0].Title != "Final" {
		t.Errorf("title = %q, want the latest", got[0].Title)
	}
}

func TestDeleteRemovesTheDocument(t *testing.T) {
	r, tenantID := testRepo(t)
	ctx := context.Background()

	index(t, r, tenantID, "INC-9", unit(0))
	if err := r.DeleteKnowledge(ctx, tenantID, model.KnowledgeSourceIncident, "INC-9"); err != nil {
		t.Fatalf("DeleteKnowledge: %v", err)
	}

	got, _ := r.SearchKnowledge(ctx, tenantID, unit(0), 5, 0)
	if len(got) != 0 {
		t.Errorf("%d results after deletion, want 0", len(got))
	}
	if err := r.DeleteKnowledge(ctx, tenantID, model.KnowledgeSourceIncident, "INC-9"); err == nil {
		t.Error("deleting a document that is not there reported success")
	}
}

// ─── Vectors that would poison the index ──────────────────────────────────────

func TestAZeroVectorIsRefused(t *testing.T) {
	// Cosine distance divides by the norm, so a zero vector makes every
	// similarity involving that row NaN — which sorts unpredictably instead of
	// failing. Some embedding servers return one for empty input.
	r, tenantID := testRepo(t)

	_, err := r.UpsertKnowledge(context.Background(), tenantID, &model.IndexKnowledgeRequest{
		SourceType: model.KnowledgeSourceNote, SourceRef: "zero", Title: "t", Content: "c",
	}, make([]float32, dim))
	if err == nil {
		t.Error("an all-zero vector was indexed")
	}
}

func TestNonFiniteValuesAreRefused(t *testing.T) {
	r, tenantID := testRepo(t)

	for name, bad := range map[string]float32{
		"NaN":  float32(math.NaN()),
		"+Inf": float32(math.Inf(1)),
		"-Inf": float32(math.Inf(-1)),
	} {
		t.Run(name, func(t *testing.T) {
			v := unit(0)
			v[5] = bad
			_, err := r.UpsertKnowledge(context.Background(), tenantID, &model.IndexKnowledgeRequest{
				SourceType: model.KnowledgeSourceNote, SourceRef: "bad-" + name, Title: "t", Content: "c",
			}, v)
			if err == nil {
				t.Errorf("a vector containing %s was indexed", name)
			}
		})
	}
}

func TestAnEmptyVectorIsRefused(t *testing.T) {
	r, tenantID := testRepo(t)
	_, err := r.UpsertKnowledge(context.Background(), tenantID, &model.IndexKnowledgeRequest{
		SourceType: model.KnowledgeSourceNote, SourceRef: "empty", Title: "t", Content: "c",
	}, nil)
	if err == nil {
		t.Error("an empty vector was indexed")
	}
}
