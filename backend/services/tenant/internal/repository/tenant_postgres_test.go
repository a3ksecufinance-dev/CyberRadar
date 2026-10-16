package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// The tenant repository itself.
//
// A tenant is the boundary every other table in the platform hangs off, so the
// properties worth a database to prove are the ones about that boundary: a new
// tenant arrives with the quota the platform promises, a deleted tenant stops
// being visible through every read path, and a partial update moves only what
// the caller named.

func repoAndPool(t *testing.T) (*TenantRepository, *pgxpool.Pool) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewTenantRepository(pool), pool
}

func create(t *testing.T, r *TenantRepository, slug string) *model.Tenant {
	t.Helper()
	got, err := r.Create(context.Background(), &model.CreateTenantRequest{
		Name: "Banque " + slug, Slug: slug, Plan: "standard",
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", slug, err)
	}
	return got
}

func slug() string { return "t" + uuid.NewString()[:8] }

// A tenant created through the repository arrives active, on the plan asked
// for, and with the quota the platform advertises. The limits are not a
// database default the repository happens to inherit: Create writes them, so
// they are a promise this test holds it to.
func TestCreateGivesTheAdvertisedQuota(t *testing.T) {
	r, _ := repoAndPool(t)
	got := create(t, r, slug())

	if got.ID == uuid.Nil {
		t.Error("no id was returned")
	}
	if got.Status != "active" {
		t.Errorf("status is %q, want active", got.Status)
	}
	if got.Plan != "standard" {
		t.Errorf("plan is %q, want standard", got.Plan)
	}
	if got.ParentID != nil {
		t.Errorf("parent_id is %v, want none", got.ParentID)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("the timestamps came back zero")
	}

	var limits struct {
		MaxUsers  int `json:"max_users"`
		MaxAssets int `json:"max_assets"`
		MaxEPS    int `json:"max_eps"`
	}
	if err := json.Unmarshal(got.Limits, &limits); err != nil {
		t.Fatalf("limits is not JSON: %v (%s)", err, got.Limits)
	}
	if limits.MaxUsers != 100 || limits.MaxAssets != 10000 || limits.MaxEPS != 1000 {
		t.Errorf("limits are %+v, want 100 users / 10000 assets / 1000 eps", limits)
	}

	// An empty JSONB column must read back as an object, not as nil: a nil
	// here would serialise to `null` and break a client that indexes into it.
	for name, raw := range map[string]model.JSONB{"config": got.Config, "features": got.Features} {
		if string(raw) != "{}" {
			t.Errorf("%s is %q, want {}", name, raw)
		}
	}
}

// A child tenant keeps its parent, and the hierarchy is a filter on List.
func TestAChildIsListedUnderItsParent(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)

	parent := create(t, r, slug())
	child, err := r.Create(ctx, &model.CreateTenantRequest{
		Name: "Filiale", Slug: slug(), Plan: "professional", ParentID: &parent.ID,
	})
	if err != nil {
		t.Fatalf("create the child: %v", err)
	}
	if child.ParentID == nil || *child.ParentID != parent.ID {
		t.Fatalf("parent_id is %v, want %v", child.ParentID, parent.ID)
	}
	create(t, r, slug()) // a third tenant, under nobody

	got, total, err := r.List(ctx, &model.ListTenantsFilter{ParentID: &parent.ID, Page: 1, Limit: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != child.ID {
		t.Fatalf("listing the children of %s gave total=%d, %d rows", parent.ID, total, len(got))
	}
}

// Two reads of the same tenant agree, whichever key they are given.
func TestGetByIDAndGetBySlugFindTheSameTenant(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	made := create(t, r, slug())

	byID, err := r.GetByID(ctx, made.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	bySlug, err := r.GetBySlug(ctx, made.Slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if bySlug == nil {
		t.Fatal("GetBySlug found nothing")
	}
	if byID.ID != made.ID || bySlug.ID != made.ID {
		t.Fatalf("GetByID gave %s, GetBySlug gave %s, want %s", byID.ID, bySlug.ID, made.ID)
	}
}

// Absence is reported differently by the two reads, and a caller that got this
// wrong would dereference a nil or swallow an error. The asymmetry is
// deliberate in the code — GetBySlug's nil, nil is what the uniqueness check
// upstream reads — so it is pinned here rather than left to be rediscovered.
func TestAbsenceIsReportedTheWayEachReadDocuments(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)

	got, err := r.GetByID(ctx, uuid.New())
	if err == nil {
		t.Error("GetByID of an unknown id returned no error")
	}
	if got != nil {
		t.Error("GetByID returned a tenant and an error at once")
	}

	bySlug, err := r.GetBySlug(ctx, "nobody-"+slug())
	if err != nil {
		t.Errorf("GetBySlug of an unknown slug returned an error: %v", err)
	}
	if bySlug != nil {
		t.Error("GetBySlug of an unknown slug returned a tenant")
	}
}

// A soft-deleted tenant disappears from every read path. This is the property
// that makes the deletion safe: any one path that still returned it would hand
// a caller a tenant the operator believes is gone.
func TestASoftDeletedTenantIsGoneFromEveryRead(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	made := create(t, r, slug())

	if err := r.SoftDelete(ctx, made.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	if _, err := r.GetByID(ctx, made.ID); err == nil {
		t.Error("GetByID still finds the deleted tenant")
	}
	if got, err := r.GetBySlug(ctx, made.Slug); err != nil || got != nil {
		t.Errorf("GetBySlug still finds the deleted tenant: %v, %v", got, err)
	}
	if _, err := r.Update(ctx, made.ID, &model.UpdateTenantRequest{Name: ptr("Renommé")}); err == nil {
		t.Error("Update still touches the deleted tenant")
	}
	rows, total, err := r.List(ctx, &model.ListTenantsFilter{Page: 1, Limit: 500})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, row := range rows {
		if row.ID == made.ID {
			t.Errorf("the deleted tenant is still listed among the %d", total)
		}
	}

	// And deleting it again is reported, not silently accepted: a caller
	// retrying a delete has to be able to tell a no-op from a success.
	if err := r.SoftDelete(ctx, made.ID); err == nil {
		t.Error("the second SoftDelete reported success")
	}
}

// SlugExists has to agree with the index that enforces it. The index is partial
// on deleted_at IS NULL, so a deleted tenant's slug becomes free again — and a
// SlugExists that still said "taken" would block a legitimate re-creation while
// one that said "free" where the index disagreed would turn a 409 into a 500.
func TestSlugExistsAgreesWithTheIndexThatEnforcesIt(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	s := slug()
	made := create(t, r, s)

	taken, err := r.SlugExists(ctx, s)
	if err != nil {
		t.Fatalf("SlugExists: %v", err)
	}
	if !taken {
		t.Fatal("SlugExists says free for a slug that is in use")
	}
	if _, err := r.Create(ctx, &model.CreateTenantRequest{Name: "Doublon", Slug: s, Plan: "standard"}); err == nil {
		t.Fatal("the database accepted a second tenant on the same slug")
	}

	if err := r.SoftDelete(ctx, made.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	taken, err = r.SlugExists(ctx, s)
	if err != nil {
		t.Fatalf("SlugExists after the delete: %v", err)
	}
	if taken {
		t.Error("SlugExists still says taken after the tenant was deleted")
	}
	if _, err := r.Create(ctx, &model.CreateTenantRequest{Name: "Reprise", Slug: s, Plan: "standard"}); err != nil {
		t.Errorf("the slug SlugExists called free was refused by the index: %v", err)
	}
}

// An update moves what the caller named and nothing else.
func TestUpdateMovesOnlyTheNamedFields(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	made := create(t, r, slug())

	got, err := r.Update(ctx, made.ID, &model.UpdateTenantRequest{
		Status: ptr("suspended"),
		Config: model.JSONB(`{"retention_days":400}`),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.Status != "suspended" {
		t.Errorf("status is %q, want suspended", got.Status)
	}
	if string(got.Config) != `{"retention_days": 400}` && string(got.Config) != `{"retention_days":400}` {
		t.Errorf("config is %q, want the one that was sent", got.Config)
	}
	if got.Name != made.Name {
		t.Errorf("name moved to %q although it was not in the request", got.Name)
	}
	if got.Plan != made.Plan {
		t.Errorf("plan moved to %q although it was not in the request", got.Plan)
	}
	if got.Slug != made.Slug {
		t.Errorf("slug moved to %q — it is not updatable at all", got.Slug)
	}
	if string(got.Features) != "{}" || string(got.Limits) == "{}" {
		t.Errorf("features/limits moved: %q / %q", got.Features, got.Limits)
	}
}

// An update that names nothing is a read, not an error and not a write that
// bumps updated_at. The handler reaches this whenever a client PATCHes an empty
// body.
func TestAnEmptyUpdateIsARead(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	made := create(t, r, slug())

	got, err := r.Update(ctx, made.ID, &model.UpdateTenantRequest{})
	if err != nil {
		t.Fatalf("Update with nothing set: %v", err)
	}
	if got.ID != made.ID || got.Name != made.Name {
		t.Fatalf("the empty update did not return the tenant unchanged: %+v", got)
	}
	if !got.UpdatedAt.Equal(made.UpdatedAt) {
		t.Errorf("updated_at moved from %s to %s on an update that changed nothing",
			made.UpdatedAt, got.UpdatedAt)
	}
}

// Paging walks the whole set without repeating or losing a row, and the total
// is the size of the set rather than of the page.
//
// The counts are relative: migration 000001 seeds the platform tenant, so the
// table is never empty and a test that asserted an absolute total would be
// asserting the seed rather than the paging.
func TestListPagesWithoutLosingOrRepeatingARow(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)

	before := totalTenants(t, r, &model.ListTenantsFilter{Page: 1, Limit: 1})

	made := map[uuid.UUID]bool{}
	for i := 0; i < 5; i++ {
		made[create(t, r, slug()).ID] = false
	}
	want := before + 5

	seen := map[uuid.UUID]int{}
	const perPage = 2
	pages := int(want/perPage) + 1
	for page := 1; page <= pages; page++ {
		rows, total, err := r.List(ctx, &model.ListTenantsFilter{Page: page, Limit: perPage})
		if err != nil {
			t.Fatalf("List page %d: %v", page, err)
		}
		if total != want {
			t.Fatalf("page %d reports total=%d, want %d", page, total, want)
		}
		for _, row := range rows {
			seen[row.ID]++
		}
	}
	for id := range made {
		switch seen[id] {
		case 1:
		case 0:
			t.Errorf("%s was never returned by any page", id)
		default:
			t.Errorf("%s was returned by %d pages", id, seen[id])
		}
	}
}

// A page number of zero or below is clamped rather than sent to PostgreSQL as a
// negative OFFSET, which would be an error the caller never asked for.
func TestListSurvivesAPageBelowOne(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)
	create(t, r, slug())

	first, _, err := r.List(ctx, &model.ListTenantsFilter{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	for _, page := range []int{0, -3} {
		rows, _, err := r.List(ctx, &model.ListTenantsFilter{Page: page, Limit: 10})
		if err != nil {
			t.Fatalf("List with page=%d: %v", page, err)
		}
		if len(rows) != len(first) {
			t.Errorf("page=%d gave %d rows, page 1 gives %d", page, len(rows), len(first))
			continue
		}
		for i := range rows {
			if rows[i].ID != first[i].ID {
				t.Errorf("page=%d row %d is %s, page 1 has %s", page, i, rows[i].ID, first[i].ID)
			}
		}
	}
}

// The status filter counts and lists the same set: a count built from a
// different WHERE than the list is the classic pagination bug, where the last
// page is empty but the total promises rows.
func TestTheStatusFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _ := repoAndPool(t)

	activeBefore := totalTenants(t, r, &model.ListTenantsFilter{Status: "active", Page: 1, Limit: 1})
	suspendedBefore := totalTenants(t, r, &model.ListTenantsFilter{Status: "suspended", Page: 1, Limit: 1})

	for i := 0; i < 3; i++ {
		create(t, r, slug())
	}
	suspended := create(t, r, slug())
	if _, err := r.Update(ctx, suspended.ID, &model.UpdateTenantRequest{Status: ptr("suspended")}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	rows, total, err := r.List(ctx, &model.ListTenantsFilter{Status: "suspended", Page: 1, Limit: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != suspendedBefore+1 || int64(len(rows)) != total {
		t.Fatalf("filtering on suspended gave total=%d, %d rows, want %d of each",
			total, len(rows), suspendedBefore+1)
	}
	var found bool
	for _, row := range rows {
		if row.ID == suspended.ID {
			found = true
		}
		if row.Status != "suspended" {
			t.Errorf("%s is %q, in a listing filtered on suspended", row.ID, row.Status)
		}
	}
	if !found {
		t.Error("the tenant that was suspended is not in the suspended listing")
	}

	rows, total, err = r.List(ctx, &model.ListTenantsFilter{Status: "active", Page: 1, Limit: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Three created and one of them suspended: the active set grew by three,
	// because the suspended one was created active and then moved.
	if total != activeBefore+3 || int64(len(rows)) != total {
		t.Fatalf("filtering on active gave total=%d, %d rows, want %d of each",
			total, len(rows), activeBefore+3)
	}
}

// totalTenants is the count the filter reports, read before a test adds rows of
// its own.
func totalTenants(t *testing.T, r *TenantRepository, f *model.ListTenantsFilter) int64 {
	t.Helper()
	_, total, err := r.List(context.Background(), f)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return total
}

func ptr(s string) *string { return &s }
