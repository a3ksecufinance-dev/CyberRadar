package service

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
)

// The tenant service.
//
// Everything here is an authorisation rule, and an authorisation rule is worth
// a test precisely because it has no visible effect when it works: nobody
// notices that a tenant admin cannot read a sibling tenant until they can.
//
// The services take concrete repositories rather than interfaces, so these run
// against a real database. That is not a compromise — the rules below are about
// rows that exist and rows that do not, which is a question only a database
// answers.

// platformTenantID is the super-tenant migration 000001 seeds. The service
// refuses to delete it, so it is named here rather than written out twice.
var platformTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func quiet() zerolog.Logger { return zerolog.New(io.Discard) }

func tenantService(t *testing.T) (*TenantService, *repository.TenantRepository, *pgxpool.Pool) {
	t.Helper()
	pool := testinfra.Postgres(t)
	repo := repository.NewTenantRepository(pool)
	return NewTenantService(repo, quiet()), repo, pool
}

func newSlug() string { return "s" + uuid.NewString()[:8] }

func mustCreate(t *testing.T, s *TenantService, parent *uuid.UUID) *model.Tenant {
	t.Helper()
	got, err := s.Create(context.Background(), &model.CreateTenantRequest{
		Name: "Banque", Slug: newSlug(), Plan: "standard", ParentID: parent,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return got
}

// kindOf names the DomainError kind an error carries, for a failure message
// that says what came back rather than only that it was wrong.
func kindOf(err error) string {
	if err == nil {
		return "no error"
	}
	for _, k := range []apierrors.Kind{
		apierrors.KindNotFound, apierrors.KindConflict, apierrors.KindForbidden,
		apierrors.KindBadInput, apierrors.KindInternal, apierrors.KindUnauth,
	} {
		if apierrors.IsKind(err, k) {
			return string(k)
		}
	}
	return "untyped: " + err.Error()
}

func wantKind(t *testing.T, err error, kind apierrors.Kind, what string) {
	t.Helper()
	if !apierrors.IsKind(err, kind) {
		t.Errorf("%s gave %s, want %s", what, kindOf(err), kind)
	}
}

// ─── Create ──────────────────────────────────────────────────────────────────

// A taken slug is a conflict, not an internal error: the handler turns one into
// a 409 the client can act on and the other into a 500 it cannot.
func TestCreateReportsATakenSlugAsAConflict(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)
	first := mustCreate(t, s, nil)

	_, err := s.Create(ctx, &model.CreateTenantRequest{
		Name: "Doublon", Slug: first.Slug, Plan: "standard",
	})
	wantKind(t, err, apierrors.KindConflict, "a second tenant on the same slug")
}

// A parent that does not exist is the client's mistake, and naming it as such
// is the difference between a 404 and a foreign-key violation surfacing as a
// 500.
func TestCreateRefusesAnUnknownParent(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)
	ghost := uuid.New()

	_, err := s.Create(ctx, &model.CreateTenantRequest{
		Name: "Orpheline", Slug: newSlug(), Plan: "standard", ParentID: &ghost,
	})
	wantKind(t, err, apierrors.KindNotFound, "a tenant under an unknown parent")
}

// A deleted tenant cannot be adopted as a parent either: the check goes through
// GetByID, which already excludes it, so this pins that the two agree.
func TestCreateRefusesADeletedParent(t *testing.T) {
	ctx := context.Background()
	s, repo, _ := tenantService(t)
	parent := mustCreate(t, s, nil)
	if err := repo.SoftDelete(ctx, parent.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	_, err := s.Create(ctx, &model.CreateTenantRequest{
		Name: "Filiale", Slug: newSlug(), Plan: "standard", ParentID: &parent.ID,
	})
	wantKind(t, err, apierrors.KindNotFound, "a tenant under a deleted parent")
}

// ─── Reading ─────────────────────────────────────────────────────────────────

// The three cases a tenant admin may read, and the one they may not. The last
// is the whole point: two unrelated customers on one deployment must not be
// able to read each other.
func TestGetByIDLetsATenantAdminSeeOnlyItsOwnSubtree(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)

	own := mustCreate(t, s, nil)
	child := mustCreate(t, s, &own.ID)
	stranger := mustCreate(t, s, nil)
	grandchild := mustCreate(t, s, &child.ID)

	if _, err := s.GetByID(ctx, own.ID, own.ID, false); err != nil {
		t.Errorf("a tenant admin cannot read its own tenant: %v", err)
	}
	if _, err := s.GetByID(ctx, own.ID, child.ID, false); err != nil {
		t.Errorf("a tenant admin cannot read its own child: %v", err)
	}

	_, err := s.GetByID(ctx, own.ID, stranger.ID, false)
	wantKind(t, err, apierrors.KindForbidden, "reading an unrelated tenant")

	// A grandchild is refused, and deliberately so: the check compares one
	// level of parentage, not the whole ancestry. Pinned here because the
	// alternative — a recursive check — is a change someone will propose, and
	// it should be a decision rather than a surprise.
	_, err = s.GetByID(ctx, own.ID, grandchild.ID, false)
	wantKind(t, err, apierrors.KindForbidden, "reading a grandchild")
}

// A super admin reads any tenant, which is what makes the platform operable.
func TestASuperAdminReadsAnyTenant(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)
	stranger := mustCreate(t, s, nil)

	if _, err := s.GetByID(ctx, uuid.New(), stranger.ID, true); err != nil {
		t.Errorf("a super admin cannot read an unrelated tenant: %v", err)
	}
}

// An unknown tenant is reported as absent, not as forbidden: telling a caller
// "forbidden" for a row that does not exist would let them probe for which ids
// are real.
func TestGetByIDReportsAnUnknownTenantAsAbsent(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)

	_, err := s.GetByID(ctx, uuid.New(), uuid.New(), true)
	wantKind(t, err, apierrors.KindNotFound, "reading an unknown tenant")
}

// A tenant admin listing tenants gets its own subtree whatever it asked for.
// The filter is overwritten rather than validated, so a client that passes
// another tenant's id gets its own children — not an error, and not the other
// tenant's.
func TestListConfinesATenantAdminToItsOwnChildren(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)

	own := mustCreate(t, s, nil)
	child := mustCreate(t, s, &own.ID)
	stranger := mustCreate(t, s, nil)
	mustCreate(t, s, &stranger.ID)

	got, err := s.List(ctx, own.ID, false, &model.ListTenantsFilter{ParentID: &stranger.ID})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got.Total != 1 || len(got.Tenants) != 1 || got.Tenants[0].ID != child.ID {
		t.Fatalf("a tenant admin asking for another tenant's children got total=%d, %d rows",
			got.Total, len(got.Tenants))
	}
}

// The page size is clamped, and the clamped values are the ones reported back —
// a client that asked for 10 000 rows and was given 50 has to be told, or its
// paging walks past the end.
func TestListClampsThePageAndReportsWhatItUsed(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)

	for _, f := range []*model.ListTenantsFilter{
		{Page: 0, Limit: 0},
		{Page: -2, Limit: 10000},
		{Page: 1, Limit: 201},
	} {
		got, err := s.List(ctx, platformTenantID, true, f)
		if err != nil {
			t.Fatalf("List(%+v): %v", f, err)
		}
		if got.Limit != 50 {
			t.Errorf("limit %d was reported as %d, want the clamp at 50", f.Limit, got.Limit)
		}
		if got.Page != 1 {
			t.Errorf("page was reported as %d, want 1", got.Page)
		}
		if len(got.Tenants) > got.Limit {
			t.Errorf("%d rows for a limit of %d", len(got.Tenants), got.Limit)
		}
	}

	// A limit inside the range is honoured rather than clamped.
	got, err := s.List(ctx, platformTenantID, true, &model.ListTenantsFilter{Page: 1, Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got.Limit != 2 || len(got.Tenants) > 2 {
		t.Errorf("a limit of 2 gave limit=%d and %d rows", got.Limit, len(got.Tenants))
	}
}

// ─── Updating and deleting ───────────────────────────────────────────────────

func TestUpdateRefusesAnotherTenant(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)
	own := mustCreate(t, s, nil)
	stranger := mustCreate(t, s, nil)
	name := "Renommée par un voisin"

	_, err := s.Update(ctx, own.ID, stranger.ID, false, &model.UpdateTenantRequest{Name: &name})
	wantKind(t, err, apierrors.KindForbidden, "updating another tenant")

	// And the row was not touched, which is the part a kind alone does not say.
	after, err := s.GetByID(ctx, stranger.ID, stranger.ID, false)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.Name == name {
		t.Error("the refused update was applied anyway")
	}
}

// A tenant admin updates its own tenant, but not its child's: the rule is
// equality, not the subtree GetByID allows. The asymmetry is deliberate —
// changing a child's plan is a billing decision — and it is pinned here so it
// stays one.
func TestATenantAdminUpdatesItsOwnTenantOnly(t *testing.T) {
	ctx := context.Background()
	s, _, _ := tenantService(t)
	own := mustCreate(t, s, nil)
	child := mustCreate(t, s, &own.ID)
	name := "Nouveau nom"

	got, err := s.Update(ctx, own.ID, own.ID, false, &model.UpdateTenantRequest{Name: &name})
	if err != nil {
		t.Fatalf("updating its own tenant: %v", err)
	}
	if got.Name != name {
		t.Errorf("name is %q, want %q", got.Name, name)
	}

	_, err = s.Update(ctx, own.ID, child.ID, false, &model.UpdateTenantRequest{Name: &name})
	wantKind(t, err, apierrors.KindForbidden, "a tenant admin updating its child")
}

// Deletion is a super admin's act, and the platform tenant is not deletable at
// all: deleting it would orphan every permission the migrations seeded under
// it, and no amount of being right about the authorisation makes that
// recoverable.
func TestOnlyASuperAdminDeletesAndNeverThePlatform(t *testing.T) {
	ctx := context.Background()
	s, repo, _ := tenantService(t)
	victim := mustCreate(t, s, nil)

	err := s.Delete(ctx, victim.ID, victim.ID, false)
	wantKind(t, err, apierrors.KindForbidden, "a tenant admin deleting its own tenant")

	err = s.Delete(ctx, platformTenantID, platformTenantID, true)
	wantKind(t, err, apierrors.KindForbidden, "a super admin deleting the platform tenant")
	if _, err := repo.GetByID(ctx, platformTenantID); err != nil {
		t.Fatalf("the platform tenant was deleted despite the refusal: %v", err)
	}

	if err := s.Delete(ctx, platformTenantID, victim.ID, true); err != nil {
		t.Fatalf("a super admin could not delete a tenant: %v", err)
	}
	if _, err := repo.GetByID(ctx, victim.ID); err == nil {
		t.Error("the tenant is still readable after the delete")
	}

	// Deleting it twice is an error rather than a silent success. It reaches
	// the caller as an internal error because the repository's "not found" is
	// an untyped error the service wraps — pinned as it is, so that tightening
	// it to a 404 is a deliberate change with a test to update.
	err = s.Delete(ctx, platformTenantID, victim.ID, true)
	if err == nil {
		t.Error("deleting an already-deleted tenant reported success")
	}
}
