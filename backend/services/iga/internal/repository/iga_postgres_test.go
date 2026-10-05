package repository

import (
	"context"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/iga/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The IGA repository against a real PostgreSQL.
//
// The access review is the part of this domain an auditor reads: who holds
// which role, who certified it, and when. A review item that has not been
// decided yet carries decision IS NULL — which is the normal state of every
// item the moment a campaign is launched — so the column that says "not yet
// reviewed" is exactly the column no unit test with a stubbed database ever
// sees.

func repo(t *testing.T) (*IGARepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewIGARepository(pool), pool, testinfra.NewTenant(t, pool)
}

func role(t *testing.T, r *IGARepository, tenant uuid.UUID, name, roleType, risk string) *model.IGARole {
	t.Helper()
	ro, err := r.CreateRole(context.Background(), tenant, &model.CreateRoleRequest{
		Name: name, Description: "Rôle de test", RoleType: roleType,
		Category: "finance", Owner: "dsi@exemple.fr", RiskLevel: risk,
		RequiresMFA: roleType == model.RoleTypePrivileged,
		Entitlements: []model.EntitlementInput{
			{SystemName: "SAP", Entitlement: "FI_" + name, EntitlementType: "profile"},
			{SystemName: "AD", Entitlement: "GRP_" + name},
		},
		Metadata: map[string]any{"propriétaire": "dsi"},
	})
	if err != nil {
		t.Fatalf("CreateRole(%s): %v", name, err)
	}
	return ro
}

func assign(t *testing.T, r *IGARepository, tenant uuid.UUID, roleID uuid.UUID, identity uuid.UUID, name string) *model.RoleAssignment {
	t.Helper()
	a, err := r.AssignRole(context.Background(), tenant, &model.AssignRoleRequest{
		IdentityID: identity, IdentityName: name, IdentityEmail: name + "@exemple.fr",
		RoleID: roleID, Justification: "Prise de fonction",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AssignRole(%s): %v", name, err)
	}
	return a
}

func campaign(t *testing.T, r *IGARepository, tenant uuid.UUID, name, scope, filter string) *model.Campaign {
	t.Helper()
	c, err := r.CreateCampaign(context.Background(), tenant, &model.CreateCampaignRequest{
		Name: name, Description: "Revue de test", CampaignType: model.CampaignPeriodic,
		Scope: scope, ScopeFilter: filter, ReviewerType: "manager",
		DueDate: time.Now().AddDate(0, 1, 0),
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateCampaign(%s): %v", name, err)
	}
	return c
}

// ─── The round trip ──────────────────────────────────────────────────────────

// A role keeps its entitlements, and an assignment with nothing optional
// reads back.
func TestARoleAndAnAssignmentReadBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	ro := role(t, r, tenant, "Comptable", model.RoleTypeBusiness, "medium")
	if len(ro.Entitlements) != 2 {
		t.Fatalf("the role kept %d entitlements, want 2", len(ro.Entitlements))
	}
	if ro.AssignmentCount != 0 {
		t.Errorf("a fresh role counts %d assignments", ro.AssignmentCount)
	}
	if ro.MaxDurationDays != nil {
		t.Errorf("max_duration_days is %v, want the schema's NULL for permanent", *ro.MaxDurationDays)
	}

	// Nothing optional: no email, no validity window. Both columns are
	// nullable and both land in Go values.
	a, err := r.AssignRole(ctx, tenant, &model.AssignRoleRequest{
		IdentityID: uuid.New(), IdentityName: "Jean Dupont",
		RoleID: ro.ID, Justification: "Prise de fonction",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AssignRole with nothing optional: %v", err)
	}
	if a.Status != model.AssignmentActive {
		t.Errorf("status is %q, want the schema's default", a.Status)
	}
	if a.AssignmentType != model.AssignmentDirect {
		t.Errorf("assignment_type is %q", a.AssignmentType)
	}
	if a.RoleName != "Comptable" {
		t.Errorf("the assignment denormalised the role name as %q", a.RoleName)
	}
	if a.ValidUntil != nil {
		t.Errorf("valid_until is %v, want NULL for permanent", *a.ValidUntil)
	}
	if a.IdentityEmail != "" {
		t.Errorf("identity_email is %q", a.IdentityEmail)
	}

	live, err := r.GetRole(ctx, tenant, ro.ID)
	if err != nil || live == nil {
		t.Fatalf("GetRole: %v", err)
	}
	if live.AssignmentCount != 1 {
		t.Errorf("the role counts %d active assignments, want 1", live.AssignmentCount)
	}
}

// The same identity and role twice is one assignment, revived.
func TestAssigningTwiceRevivesTheSameAssignment(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	ro := role(t, r, tenant, "Comptable", model.RoleTypeBusiness, "low")
	who := uuid.New()

	first := assign(t, r, tenant, ro.ID, who, "jdupont")
	if _, err := r.UpdateAssignment(ctx, tenant, first.ID, &model.UpdateAssignmentRequest{
		Status: model.AssignmentRevoked,
	}); err != nil {
		t.Fatalf("UpdateAssignment(revoked): %v", err)
	}

	second := assign(t, r, tenant, ro.ID, who, "jdupont")
	if second.ID != first.ID {
		t.Errorf("a second assignment was created: %s then %s", first.ID, second.ID)
	}
	if second.Status != model.AssignmentActive {
		t.Errorf("the revived assignment is %q", second.Status)
	}
	if _, total, err := r.ListAssignments(ctx, tenant, model.ListAssignmentsFilter{
		IdentityID: &who, Page: 1, PageSize: 10,
	}); err != nil || total != 1 {
		t.Errorf("%d assignments for one identity and one role: %v", total, err)
	}
}

// An assignment past its window is expired by the sweep, and only then.
func TestTheSweepExpiresWhatIsPastItsWindow(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	ro := role(t, r, tenant, "Intérim", model.RoleTypeBusiness, "low")

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(24 * time.Hour)
	expired, err := r.AssignRole(ctx, tenant, &model.AssignRoleRequest{
		IdentityID: uuid.New(), IdentityName: "partie", RoleID: ro.ID,
		Justification: "mission terminée", ValidUntil: &past,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AssignRole(past): %v", err)
	}
	live, err := r.AssignRole(ctx, tenant, &model.AssignRoleRequest{
		IdentityID: uuid.New(), IdentityName: "en poste", RoleID: ro.ID,
		Justification: "mission en cours", ValidUntil: &future,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AssignRole(future): %v", err)
	}

	if _, err := r.ExpireAssignments(ctx); err != nil {
		t.Fatalf("ExpireAssignments: %v", err)
	}

	got, err := r.GetAssignment(ctx, tenant, expired.ID)
	if err != nil || got == nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if got.Status != model.AssignmentExpired {
		t.Errorf("an assignment an hour past its window is %q", got.Status)
	}
	still, err := r.GetAssignment(ctx, tenant, live.ID)
	if err != nil || still == nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if still.Status != model.AssignmentActive {
		t.Errorf("an assignment valid until tomorrow is %q", still.Status)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ExpiringSoon != 1 {
		t.Errorf("%d assignments expiring within seven days, want 1", stats.ExpiringSoon)
	}
	if stats.TotalAssignments != 1 {
		t.Errorf("%d active assignments, want the one still in its window", stats.TotalAssignments)
	}
}

// ─── The campaign ────────────────────────────────────────────────────────────

// A launched campaign lists its items, and every one of them is pending —
// which is the state the nullable decision column encodes.
func TestALaunchedCampaignListsItsPendingItems(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	admin := role(t, r, tenant, "Admin SAP", model.RoleTypePrivileged, "critical")
	clerk := role(t, r, tenant, "Saisie", model.RoleTypeBusiness, "low")
	assign(t, r, tenant, admin.ID, uuid.New(), "jdupont")
	assign(t, r, tenant, clerk.ID, uuid.New(), "mdurand")

	c := campaign(t, r, tenant, "Revue annuelle", "all", "")
	if c.Status != "draft" || c.TotalItems != 0 {
		t.Errorf("a fresh campaign is %+v", c)
	}

	launched, err := r.LaunchCampaign(ctx, tenant, c.ID)
	if err != nil || launched == nil {
		t.Fatalf("LaunchCampaign: %v", err)
	}
	if launched.Status != "active" {
		t.Errorf("a launched campaign is %q", launched.Status)
	}
	if launched.TotalItems != 2 {
		t.Errorf("the campaign counted %d items, want the two active assignments", launched.TotalItems)
	}

	items, total, err := r.ListReviewItems(ctx, tenant, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Page: 1, PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListReviewItems: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("%d items listed (total=%d), want 2", len(items), total)
	}
	for _, it := range items {
		if it.Decision != "" {
			t.Errorf("%s is already decided as %q", it.IdentityName, it.Decision)
		}
		if it.ReviewedAt != nil || it.ReviewerID != nil || it.ReviewerName != "" {
			t.Errorf("%s carries a reviewer before anyone reviewed it", it.IdentityName)
		}
	}
	// The riskiest first: the privileged role carries flags, the clerk's does
	// not.
	if items[0].RiskScore <= items[1].RiskScore {
		t.Errorf("the list is not ordered by risk: %d then %d", items[0].RiskScore, items[1].RiskScore)
	}
	if len(items[0].RiskFlags) == 0 {
		t.Error("the privileged assignment carries no risk flag")
	}

	pending, total, err := r.ListReviewItems(ctx, tenant, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Decision: "pending", Page: 1, PageSize: 50,
	})
	if err != nil || total != 2 || len(pending) != 2 {
		t.Errorf("the pending filter found %d (total=%d): %v", len(pending), total, err)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.PendingReviews != 2 || stats.ActiveCampaigns != 1 {
		t.Errorf("stats say %d pending / %d active campaigns", stats.PendingReviews, stats.ActiveCampaigns)
	}
}

// A campaign scoped to privileged roles reviews only those.
func TestAPrivilegedCampaignReviewsOnlyPrivilegedRoles(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	admin := role(t, r, tenant, "Admin SAP", model.RoleTypePrivileged, "critical")
	clerk := role(t, r, tenant, "Saisie", model.RoleTypeBusiness, "low")
	assign(t, r, tenant, admin.ID, uuid.New(), "jdupont")
	assign(t, r, tenant, clerk.ID, uuid.New(), "mdurand")

	c := campaign(t, r, tenant, "Revue des comptes à privilèges", "privileged", "")
	launched, err := r.LaunchCampaign(ctx, tenant, c.ID)
	if err != nil || launched == nil {
		t.Fatalf("LaunchCampaign: %v", err)
	}
	if launched.TotalItems != 1 {
		t.Errorf("the privileged campaign counted %d items, want 1", launched.TotalItems)
	}
	items, _, err := r.ListReviewItems(ctx, tenant, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Page: 1, PageSize: 50,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("ListReviewItems: %d %v", len(items), err)
	}
	if items[0].RoleName != "Admin SAP" {
		t.Errorf("the campaign reviews %q", items[0].RoleName)
	}
}

// A revocation decision revokes the assignment, a certification does not, and
// the counters add up to the items reviewed.
func TestADecisionMovesTheAssignmentAndTheCounters(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	admin := role(t, r, tenant, "Admin SAP", model.RoleTypePrivileged, "critical")
	clerk := role(t, r, tenant, "Saisie", model.RoleTypeBusiness, "low")
	keep := assign(t, r, tenant, clerk.ID, uuid.New(), "mdurand")
	drop := assign(t, r, tenant, admin.ID, uuid.New(), "jdupont")

	c := campaign(t, r, tenant, "Revue annuelle", "all", "")
	if _, err := r.LaunchCampaign(ctx, tenant, c.ID); err != nil {
		t.Fatalf("LaunchCampaign: %v", err)
	}
	items, _, err := r.ListReviewItems(ctx, tenant, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Page: 1, PageSize: 50,
	})
	if err != nil || len(items) != 2 {
		t.Fatalf("ListReviewItems: %d %v", len(items), err)
	}

	byAssignment := map[uuid.UUID]*model.ReviewItem{}
	for _, it := range items {
		if it.AssignmentID == nil {
			t.Fatalf("%s's item names no assignment", it.IdentityName)
		}
		byAssignment[*it.AssignmentID] = it
	}

	reviewer := uuid.New()
	certified, err := r.SubmitReviewDecision(ctx, tenant, byAssignment[keep.ID].ID, reviewer,
		&model.ReviewDecisionRequest{
			Decision: "certified", DecisionReason: "Accès conforme à la fonction",
			ReviewerName: "Chef comptable",
		})
	if err != nil {
		t.Fatalf("SubmitReviewDecision(certified): %v", err)
	}
	if certified.Decision != "certified" || certified.ReviewedAt == nil {
		t.Errorf("the certified item reads %+v", certified)
	}
	if certified.ReviewerName != "Chef comptable" || certified.ReviewerID == nil || *certified.ReviewerID != reviewer {
		t.Errorf("the certified item lost its reviewer: %+v", certified)
	}

	revoked, err := r.SubmitReviewDecision(ctx, tenant, byAssignment[drop.ID].ID, reviewer,
		&model.ReviewDecisionRequest{
			Decision: "revoked", DecisionReason: "A changé de poste",
			ReviewerName: "Chef comptable",
		})
	if err != nil {
		t.Fatalf("SubmitReviewDecision(revoked): %v", err)
	}
	if revoked.Decision != "revoked" {
		t.Errorf("the revoked item reads %q", revoked.Decision)
	}

	// The revocation reached the assignment; the certification left the other
	// alone.
	gone, err := r.GetAssignment(ctx, tenant, drop.ID)
	if err != nil || gone == nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if gone.Status != model.AssignmentRevoked {
		t.Errorf("the revoked assignment is %q", gone.Status)
	}
	stays, err := r.GetAssignment(ctx, tenant, keep.ID)
	if err != nil || stays == nil {
		t.Fatalf("GetAssignment: %v", err)
	}
	if stays.Status != model.AssignmentActive {
		t.Errorf("the certified assignment is %q", stays.Status)
	}

	// Both items decided: the campaign closes itself, and the counters say
	// what happened.
	done, err := r.GetCampaign(ctx, tenant, c.ID)
	if err != nil || done == nil {
		t.Fatalf("GetCampaign: %v", err)
	}
	if done.ReviewedItems != 2 || done.CertifiedItems != 1 || done.RevokedItems != 1 {
		t.Errorf("the counters read %d reviewed / %d certified / %d revoked",
			done.ReviewedItems, done.CertifiedItems, done.RevokedItems)
	}
	if done.Status != "completed" || done.CompletedAt == nil {
		t.Errorf("a fully reviewed campaign is %q", done.Status)
	}
}

// A decision is taken once. A second one does not move the counters, because
// the counters are what the auditor reads.
func TestADecisionIsTakenOnce(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	ro := role(t, r, tenant, "Saisie", model.RoleTypeBusiness, "low")
	assign(t, r, tenant, ro.ID, uuid.New(), "mdurand")
	c := campaign(t, r, tenant, "Revue annuelle", "all", "")
	if _, err := r.LaunchCampaign(ctx, tenant, c.ID); err != nil {
		t.Fatalf("LaunchCampaign: %v", err)
	}
	items, _, err := r.ListReviewItems(ctx, tenant, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Page: 1, PageSize: 10,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("ListReviewItems: %d %v", len(items), err)
	}

	if _, err := r.SubmitReviewDecision(ctx, tenant, items[0].ID, uuid.New(),
		&model.ReviewDecisionRequest{Decision: "certified"}); err != nil {
		t.Fatalf("SubmitReviewDecision: %v", err)
	}
	if _, err := r.SubmitReviewDecision(ctx, tenant, items[0].ID, uuid.New(),
		&model.ReviewDecisionRequest{Decision: "revoked"}); err == nil {
		t.Error("the same item was decided twice")
	}

	c2, err := r.GetCampaign(ctx, tenant, c.ID)
	if err != nil || c2 == nil {
		t.Fatalf("GetCampaign: %v", err)
	}
	if c2.ReviewedItems != 1 || c2.CertifiedItems != 1 || c2.RevokedItems != 0 {
		t.Errorf("after one decision and one refusal the counters read %d/%d/%d",
			c2.ReviewedItems, c2.CertifiedItems, c2.RevokedItems)
	}
}

// ─── Separation of duties ────────────────────────────────────────────────────

// Two roles the same person must not hold at once, and the detection that
// finds them. Run twice, it finds the same conflict, not two of them.
func TestTheSoDDetectionFindsEachConflictOnce(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	payer := role(t, r, tenant, "Émission de paiement", model.RoleTypeBusiness, "high")
	approver := role(t, r, tenant, "Validation de paiement", model.RoleTypeBusiness, "high")
	unrelated := role(t, r, tenant, "Lecture", model.RoleTypeBusiness, "low")

	p, err := r.CreateSoDPolicy(ctx, tenant, &model.CreateSoDPolicyRequest{
		Name: "Paiement : émission et validation", Description: "Principe des quatre yeux",
		RoleAID: payer.ID, RoleBID: approver.ID, Severity: "critical",
	})
	if err != nil {
		t.Fatalf("CreateSoDPolicy: %v", err)
	}
	if p.RoleAName != "Émission de paiement" || p.RoleBName != "Validation de paiement" {
		t.Errorf("the policy denormalised the role names as %q and %q", p.RoleAName, p.RoleBName)
	}
	if p.Action != "block" {
		t.Errorf("the default action is %q", p.Action)
	}

	// One person holds both; another holds one and something unrelated.
	guilty := uuid.New()
	assign(t, r, tenant, payer.ID, guilty, "jdupont")
	assign(t, r, tenant, approver.ID, guilty, "jdupont")
	innocent := uuid.New()
	assign(t, r, tenant, payer.ID, innocent, "mdurand")
	assign(t, r, tenant, unrelated.ID, innocent, "mdurand")

	n, err := r.DetectSoDViolations(ctx, tenant)
	if err != nil {
		t.Fatalf("DetectSoDViolations: %v", err)
	}
	if n != 1 {
		t.Errorf("the first detection reported %d violations, want 1", n)
	}

	again, err := r.DetectSoDViolations(ctx, tenant)
	if err != nil {
		t.Fatalf("DetectSoDViolations again: %v", err)
	}
	if again != 0 {
		t.Errorf("a second detection reported %d new violations, want 0", again)
	}

	viols, total, err := r.ListSoDViolations(ctx, tenant, "", "", 1, 50)
	if err != nil {
		t.Fatalf("ListSoDViolations: %v", err)
	}
	if total != 1 || len(viols) != 1 {
		t.Fatalf("%d violations stored (total=%d), want 1", len(viols), total)
	}
	v := viols[0]
	if v.IdentityID != guilty {
		t.Errorf("the violation names %s, want the person holding both roles", v.IdentityID)
	}
	if v.Status != "open" || v.ExceptionReason != "" || v.ExceptionBy != nil {
		t.Errorf("a fresh violation reads %+v", v)
	}
	if v.Severity != "critical" || v.PolicyName != p.Name {
		t.Errorf("the violation lost the policy it came from: %+v", v)
	}

	// An exception is granted, with a reason and a name attached to it.
	who := uuid.New()
	ex, err := r.UpdateViolation(ctx, tenant, v.ID, who, &model.UpdateViolationRequest{
		Status: "exception_granted", ExceptionReason: "Effectif réduit, contrôle compensatoire",
	})
	if err != nil || ex == nil {
		t.Fatalf("UpdateViolation: %v", err)
	}
	if ex.Status != "exception_granted" {
		t.Errorf("status is %q", ex.Status)
	}
	if ex.ExceptionReason == "" || ex.ExceptionBy == nil || *ex.ExceptionBy != who || ex.ExceptionAt == nil {
		t.Errorf("the exception kept no trace of who granted it or why: %+v", ex)
	}
	if _, total, err := r.ListSoDViolations(ctx, tenant, "open", "", 1, 50); err != nil || total != 0 {
		t.Errorf("%d violations still open: %v", total, err)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.OpenSoDViolations != 0 {
		t.Errorf("stats count %d open violations", stats.OpenSoDViolations)
	}
}

// A policy the product must not accept: a role against itself, and a role
// that is not ours.
func TestTheSchemaAcceptsSoDPoliciesTheProductMustNot(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")
	ours := role(t, r, mine, "Émission de paiement", model.RoleTypeBusiness, "high")
	foreign := role(t, r, theirs, "Trésorerie voisine", model.RoleTypeBusiness, "high")

	if got, err := r.CreateSoDPolicy(ctx, mine, &model.CreateSoDPolicyRequest{
		Name: "Contre elle-même", RoleAID: ours.ID, RoleBID: ours.ID, Severity: "high",
	}); err == nil {
		t.Errorf("a policy was created pitting a role against itself: %+v", got)
	}

	if got, err := r.CreateSoDPolicy(ctx, mine, &model.CreateSoDPolicyRequest{
		Name: "Avec un rôle voisin", RoleAID: ours.ID, RoleBID: foreign.ID, Severity: "high",
	}); err == nil {
		t.Errorf("a policy was created naming the neighbour's role: %+v", got)
	}

	if rows, err := r.ListSoDPolicies(ctx, mine); err != nil || len(rows) != 0 {
		t.Errorf("%d policies stored: %v", len(rows), err)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing a caller names lets them read a neighbour's review, move their
// counters, or revoke their access.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	ro := role(t, r, mine, "Admin SAP", model.RoleTypePrivileged, "critical")
	a := assign(t, r, mine, ro.ID, uuid.New(), "jdupont")
	c := campaign(t, r, mine, "Revue annuelle", "all", "")
	if _, err := r.LaunchCampaign(ctx, mine, c.ID); err != nil {
		t.Fatalf("LaunchCampaign: %v", err)
	}
	items, _, err := r.ListReviewItems(ctx, mine, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Page: 1, PageSize: 10,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("ListReviewItems: %d %v", len(items), err)
	}
	item := items[0]

	// Reads
	if got, err := r.GetRole(ctx, theirs, ro.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the role: %v / %v", got, err)
	}
	if got, err := r.GetAssignment(ctx, theirs, a.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the assignment: %v / %v", got, err)
	}
	if got, err := r.GetCampaign(ctx, theirs, c.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the campaign: %v / %v", got, err)
	}
	if rows, total, err := r.ListRoles(ctx, theirs, "", "", false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d roles (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListAssignments(ctx, theirs, model.ListAssignmentsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assignments (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListReviewItems(ctx, theirs, model.ListReviewItemsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d review items (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListCampaigns(ctx, theirs, "", 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d campaigns (total=%d): %v", len(rows), total, err)
	}

	// Writes that name one of our rows
	if got, err := r.UpdateRole(ctx, theirs, ro.ID, &model.UpdateRoleRequest{Owner: "eux"}); err != nil || got != nil {
		t.Errorf("the neighbour took ownership of the role: %v / %v", got, err)
	}
	if got, err := r.UpdateAssignment(ctx, theirs, a.ID, &model.UpdateAssignmentRequest{
		Status: model.AssignmentRevoked,
	}); err != nil || got != nil {
		t.Errorf("the neighbour revoked the assignment: %v / %v", got, err)
	}
	if got, err := r.LaunchCampaign(ctx, theirs, c.ID); err != nil || got != nil {
		t.Errorf("the neighbour launched our campaign: %v / %v", got, err)
	}
	if got, err := r.SubmitReviewDecision(ctx, theirs, item.ID, uuid.New(),
		&model.ReviewDecisionRequest{Decision: "revoked", ReviewerName: "intrus"}); err == nil {
		t.Errorf("the neighbour decided our review item, and read it back: %+v", got)
	}
	if got, err := r.AssignRole(ctx, theirs, &model.AssignRoleRequest{
		IdentityID: uuid.New(), IdentityName: "intrus", RoleID: ro.ID,
		Justification: "profitons-en",
	}, uuid.Nil); err == nil {
		t.Errorf("the neighbour assigned our role: %+v", got)
	}

	// Our rows are exactly as we left them.
	live, err := r.GetAssignment(ctx, mine, a.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the assignment: %v", err)
	}
	if live.Status != model.AssignmentActive {
		t.Errorf("our assignment is %q", live.Status)
	}
	liveCampaign, err := r.GetCampaign(ctx, mine, c.ID)
	if err != nil || liveCampaign == nil {
		t.Fatalf("re-read the campaign: %v", err)
	}
	if liveCampaign.ReviewedItems != 0 || liveCampaign.RevokedItems != 0 {
		t.Errorf("our campaign counts %d reviewed / %d revoked",
			liveCampaign.ReviewedItems, liveCampaign.RevokedItems)
	}
	if liveCampaign.Status != "active" {
		t.Errorf("our campaign is %q", liveCampaign.Status)
	}
	liveItems, _, err := r.ListReviewItems(ctx, mine, model.ListReviewItemsFilter{
		CampaignID: &c.ID, Decision: "pending", Page: 1, PageSize: 10,
	})
	if err != nil || len(liveItems) != 1 {
		t.Errorf("%d of our items are still pending: %v", len(liveItems), err)
	}
	liveRole, err := r.GetRole(ctx, mine, ro.ID)
	if err != nil || liveRole == nil {
		t.Fatalf("re-read the role: %v", err)
	}
	if liveRole.AssignmentCount != 1 {
		t.Errorf("our role counts %d assignments", liveRole.AssignmentCount)
	}
}

// ─── Lists and filters ───────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	admin := role(t, r, tenant, "Admin SAP", model.RoleTypePrivileged, "critical")
	clerk := role(t, r, tenant, "Saisie", model.RoleTypeBusiness, "low")
	who := uuid.New()
	first := assign(t, r, tenant, admin.ID, who, "jdupont")
	assign(t, r, tenant, clerk.ID, uuid.New(), "mdurand")
	if _, err := r.UpdateAssignment(ctx, tenant, first.ID, &model.UpdateAssignmentRequest{
		Status: model.AssignmentSuspended,
	}); err != nil {
		t.Fatalf("UpdateAssignment: %v", err)
	}

	for _, c := range []struct {
		name     string
		roleType string
		risk     string
		active   bool
		want     int
	}{
		{"everything", "", "", false, 2},
		{"by type", model.RoleTypePrivileged, "", false, 1},
		{"by risk", "", "critical", false, 1},
		{"by type and risk together", model.RoleTypeBusiness, "critical", false, 0},
		{"active only", "", "", true, 2},
	} {
		rows, total, err := r.ListRoles(ctx, tenant, c.roleType, c.risk, c.active, 1, 50)
		if err != nil {
			t.Fatalf("ListRoles(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	for _, c := range []struct {
		name string
		f    model.ListAssignmentsFilter
		want int
	}{
		{"everything", model.ListAssignmentsFilter{}, 2},
		{"by identity", model.ListAssignmentsFilter{IdentityID: &who}, 1},
		{"by role", model.ListAssignmentsFilter{RoleID: &clerk.ID}, 1},
		{"by status", model.ListAssignmentsFilter{Status: model.AssignmentSuspended}, 1},
		{"by a status nothing has", model.ListAssignmentsFilter{Status: model.AssignmentExpired}, 0},
	} {
		c.f.Page, c.f.PageSize = 1, 50
		rows, total, err := r.ListAssignments(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListAssignments(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	// The role's assignment count follows the status: a suspended assignment
	// is not an active one.
	live, err := r.GetRole(ctx, tenant, admin.ID)
	if err != nil || live == nil {
		t.Fatalf("GetRole: %v", err)
	}
	if live.AssignmentCount != 0 {
		t.Errorf("a role whose only assignment is suspended counts %d active ones", live.AssignmentCount)
	}
}

// A fresh tenant gets zeros rather than an error.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	r, _, tenant := repo(t)
	stats, err := r.Stats(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalRoles != 0 || stats.TotalAssignments != 0 || stats.PendingReviews != 0 {
		t.Errorf("a tenant with no data reports %+v", stats)
	}
	if stats.RolesByType == nil || stats.AssignmentsByStatus == nil {
		t.Error("the breakdowns are nil, which serialises as null rather than {}")
	}
}
