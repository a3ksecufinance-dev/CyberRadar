package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/compliance/internal/model"
)

// The compliance repository: the first test this service has ever had.
//
// A compliance score is a number a bank shows an auditor, so what matters is
// not that it is computed but that it is computed from the right rows: a
// control nobody has assessed must count against the score, not be quietly
// excluded from the denominator. That arithmetic has never been exercised.

func repo(t *testing.T) (*ComplianceRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewComplianceRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func framework(t *testing.T, r *ComplianceRepository, tenant uuid.UUID, code string) *model.Framework {
	t.Helper()
	fw, err := r.CreateFramework(context.Background(), tenant, &model.CreateFrameworkRequest{
		Code: code, Name: code, Description: "Référentiel de test", Version: "2022",
	})
	if err != nil {
		t.Fatalf("CreateFramework(%s): %v", code, err)
	}
	return fw
}

func control(t *testing.T, r *ComplianceRepository, tenant uuid.UUID, fw uuid.UUID, ref string) *model.Control {
	t.Helper()
	c, err := r.CreateControl(context.Background(), tenant, &model.CreateControlRequest{
		FrameworkID: fw, ControlID: ref, Domain: "A.5", Title: "Politique de sécurité",
		Description: "Description", Guidance: "Conseils", Priority: "HIGH",
	})
	if err != nil {
		t.Fatalf("CreateControl(%s): %v", ref, err)
	}
	// The framework's control count is maintained separately, and the score
	// divides by it.
	if err := r.UpdateFrameworkControlCount(context.Background(), fw); err != nil {
		t.Fatalf("UpdateFrameworkControlCount: %v", err)
	}
	return c
}

func assess(t *testing.T, r *ComplianceRepository, tenant, fw, ctl uuid.UUID, status string, score float64) *model.Assessment {
	t.Helper()
	a, err := r.UpsertAssessment(context.Background(), tenant, nil, &model.CreateAssessmentRequest{
		FrameworkID: fw, ControlID: ctl, Status: status, Score: score,
		Notes: "Évalué par le test",
	})
	if err != nil {
		t.Fatalf("UpsertAssessment(%s): %v", status, err)
	}
	return a
}

// ─── The round trip ──────────────────────────────────────────────────────────

// Everything with only its required fields reads back. priority and
// source_service both carry a CHECK that enumerates their values, and a CHECK
// rejects the empty string where it accepts NULL — the class that refused every
// fraud watchlist entry without a severity and every risk scenario without a
// named actor.
func TestEverythingWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw, err := r.CreateFramework(ctx, tenant, &model.CreateFrameworkRequest{
		Code: "ISO27001", Name: "ISO/IEC 27001",
	})
	if err != nil {
		t.Fatalf("CreateFramework with nothing optional: %v", err)
	}
	// A framework arrives inactive: adopting one is a decision, not a side
	// effect of adding it to the catalogue. So the active-only listing is
	// empty until someone activates it, which is what an interface showing
	// "frameworks in force" reads.
	if fw.IsActive {
		t.Error("a framework is active the moment it is created")
	}
	if got, err := r.GetFramework(ctx, tenant, fw.ID); err != nil || got == nil {
		t.Fatalf("GetFramework: %+v / %v", got, err)
	}
	if rows, err := r.ListFrameworks(ctx, model.FrameworkFilter{TenantID: tenant}); err != nil || len(rows) != 1 {
		t.Fatalf("ListFrameworks gave %d rows: %v", len(rows), err)
	}
	active := true
	if rows, err := r.ListFrameworks(ctx, model.FrameworkFilter{TenantID: tenant, IsActive: &active}); err != nil || len(rows) != 0 {
		t.Fatalf("the active-only listing gave %d rows: %v", len(rows), err)
	}
	if err := r.SetFrameworkActive(ctx, tenant, fw.ID, true); err != nil {
		t.Fatalf("SetFrameworkActive: %v", err)
	}
	if rows, err := r.ListFrameworks(ctx, model.FrameworkFilter{TenantID: tenant, IsActive: &active}); err != nil || len(rows) != 1 {
		t.Fatalf("after activation the listing gave %d rows: %v", len(rows), err)
	}

	// A control with no description, no guidance and no priority.
	ctl, err := r.CreateControl(ctx, tenant, &model.CreateControlRequest{
		FrameworkID: fw.ID, ControlID: "A.5.1.1", Domain: "A.5",
		Title: "Politique de sécurité de l'information",
	})
	if err != nil {
		t.Fatalf("CreateControl with nothing optional: %v", err)
	}
	if got, err := r.GetControl(ctx, tenant, ctl.ID); err != nil || got == nil {
		t.Fatalf("GetControl: %+v / %v", got, err)
	}
	if rows, total, err := r.ListControls(ctx, model.ControlFilter{TenantID: tenant, Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListControls gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// An assessment with no notes and no review date.
	as, err := r.UpsertAssessment(ctx, tenant, nil, &model.CreateAssessmentRequest{
		FrameworkID: fw.ID, ControlID: ctl.ID, Status: "not_assessed",
	})
	if err != nil {
		t.Fatalf("UpsertAssessment with nothing optional: %v", err)
	}
	if as.EvidenceRefs == nil {
		t.Error("evidence_refs came back nil rather than empty")
	}
	if got, err := r.GetAssessment(ctx, tenant, as.ID); err != nil || got == nil {
		t.Fatalf("GetAssessment: %+v / %v", got, err)
	}
	if rows, total, err := r.ListAssessments(ctx, model.AssessmentFilter{TenantID: tenant, Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListAssessments gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A risk with no description, no mitigation plan, no owner, no due date.
	risk, err := r.CreateRisk(ctx, tenant, nil, &model.CreateRiskRequest{
		Title: "Dépendance à un prestataire unique", Category: "third_party",
		Likelihood: 3, Impact: 4,
	})
	if err != nil {
		t.Fatalf("CreateRisk with nothing optional: %v", err)
	}
	if risk.RelatedControls == nil {
		t.Error("related_controls came back nil rather than empty")
	}
	if got, err := r.GetRisk(ctx, tenant, risk.ID); err != nil || got == nil {
		t.Fatalf("GetRisk: %+v / %v", got, err)
	}
	if rows, total, err := r.ListRisks(ctx, model.RiskFilter{TenantID: tenant, Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListRisks gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// Evidence with no source service and no reference URL.
	ev, err := r.CreateEvidence(ctx, tenant, nil, &model.CreateEvidenceRequest{
		AssessmentID: as.ID, Title: "Capture de la configuration", EvidenceType: "screenshot",
	})
	if err != nil {
		t.Fatalf("CreateEvidence with nothing optional: %v", err)
	}
	if ev.SourceService != "" {
		t.Errorf("source_service is %q, want empty", ev.SourceService)
	}
	if rows, err := r.ListEvidence(ctx, tenant, as.ID); err != nil || len(rows) != 1 {
		t.Fatalf("ListEvidence gave %d rows: %v", len(rows), err)
	}
}

// ─── The score an auditor reads ──────────────────────────────────────────────

// The score is (compliant × 100 + partial × 50) / total controls, and the total
// is every control in the framework — not only the assessed ones. A control
// nobody has looked at has to pull the score down, or a bank that assessed one
// control out of a hundred would show 100 %.
func TestTheScoreDividesByEveryControlNotOnlyTheAssessedOnes(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw := framework(t, r, tenant, "ISO27001")
	controls := make([]*model.Control, 0, 4)
	for _, ref := range []string{"A.5.1.1", "A.5.1.2", "A.6.1.1", "A.6.1.2"} {
		controls = append(controls, control(t, r, tenant, fw.ID, ref))
	}

	// One compliant, one partial, one non-compliant, one never looked at.
	assess(t, r, tenant, fw.ID, controls[0].ID, "compliant", 100)
	assess(t, r, tenant, fw.ID, controls[1].ID, "partial", 50)
	assess(t, r, tenant, fw.ID, controls[2].ID, "non_compliant", 0)

	score, err := r.FrameworkScore(ctx, tenant, fw.ID)
	if err != nil {
		t.Fatalf("FrameworkScore: %v", err)
	}
	if score == nil {
		t.Fatal("FrameworkScore returned nothing")
	}
	if score.TotalControls != 4 {
		t.Errorf("total_controls is %d, want 4", score.TotalControls)
	}
	if score.Assessed != 3 {
		t.Errorf("assessed is %d, want 3", score.Assessed)
	}
	if score.Compliant != 1 || score.Partial != 1 || score.NonCompliant != 1 {
		t.Errorf("the breakdown is %d/%d/%d", score.Compliant, score.Partial, score.NonCompliant)
	}
	if score.NotAssessed != 1 {
		t.Errorf("not_assessed is %d, want the one nobody looked at", score.NotAssessed)
	}
	// (1 × 100 + 1 × 50) / 4 = 37.5
	if score.ScorePct != 37.5 {
		t.Errorf("score_pct is %v, want 37.5", score.ScorePct)
	}
	if score.FrameworkCode != "ISO27001" {
		t.Errorf("the score does not name its framework: %q", score.FrameworkCode)
	}

	// A control marked not applicable is neither compliant nor a failure, and
	// it still sits in the denominator — which is a stance worth pinning,
	// because the alternative (excluding it) raises every score.
	assess(t, r, tenant, fw.ID, controls[3].ID, "not_applicable", 0)
	score, err = r.FrameworkScore(ctx, tenant, fw.ID)
	if err != nil {
		t.Fatalf("FrameworkScore: %v", err)
	}
	if score.NotApplicable != 1 {
		t.Errorf("not_applicable is %d", score.NotApplicable)
	}
	if score.ScorePct != 37.5 {
		t.Errorf("score_pct moved to %v when a control was marked not applicable", score.ScorePct)
	}
}

// A framework with no control at all scores zero rather than dividing by it.
func TestAFrameworkWithNoControlScoresZero(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw := framework(t, r, tenant, "DORA")
	score, err := r.FrameworkScore(ctx, tenant, fw.ID)
	if err != nil {
		t.Fatalf("FrameworkScore: %v", err)
	}
	if score == nil {
		t.Fatal("FrameworkScore returned nothing")
	}
	if score.ScorePct != 0 || score.TotalControls != 0 {
		t.Errorf("an empty framework scores %+v", score)
	}

	// And a framework nobody created is absent rather than an error.
	if got, err := r.FrameworkScore(ctx, tenant, uuid.New()); err != nil || got != nil {
		t.Errorf("an unknown framework gave %v / %v", got, err)
	}
}

// Assessing the same control twice is one row, not two: a register with two
// verdicts for one control cannot be reported on.
func TestAssessingAControlTwiceKeepsOneVerdict(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw := framework(t, r, tenant, "SOC2")
	ctl := control(t, r, tenant, fw.ID, "CC6.1")

	first := assess(t, r, tenant, fw.ID, ctl.ID, "non_compliant", 0)
	second := assess(t, r, tenant, fw.ID, ctl.ID, "compliant", 100)
	if second.ID != first.ID {
		t.Fatalf("the same control has two assessments: %s and %s", first.ID, second.ID)
	}
	if second.Status != "compliant" || second.Score != 100 {
		t.Errorf("the second verdict did not take: %+v", second)
	}
	if _, total, err := r.ListAssessments(ctx, model.AssessmentFilter{TenantID: tenant, Limit: 50}); err != nil || total != 1 {
		t.Errorf("%d assessments for one control: %v", total, err)
	}

	// A partial update moves what it names and leaves the rest.
	updated, err := r.UpdateAssessment(ctx, tenant, first.ID, &model.UpdateAssessmentRequest{
		Notes: strp("Revu en comité"),
	}, nil)
	if err != nil {
		t.Fatalf("UpdateAssessment: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateAssessment returned nothing")
	}
	if updated.Status != "compliant" {
		t.Errorf("status moved to %q on an update that only set notes", updated.Status)
	}
	if updated.Notes != "Revu en comité" {
		t.Errorf("notes are %q", updated.Notes)
	}
}

// A bulk upsert is the import path, and it has to count what it wrote.
func TestABulkUpsertCountsWhatItWrote(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw := framework(t, r, tenant, "PCIDSS")
	a := control(t, r, tenant, fw.ID, "1.1")
	b := control(t, r, tenant, fw.ID, "1.2")

	n, err := r.BulkUpsertAssessments(ctx, tenant, nil, []model.BulkAssessmentItem{
		{FrameworkID: fw.ID, ControlID: a.ID, Status: "compliant", Score: 100},
		{FrameworkID: fw.ID, ControlID: b.ID, Status: "partial", Score: 50},
	})
	if err != nil {
		t.Fatalf("BulkUpsertAssessments: %v", err)
	}
	if n != 2 {
		t.Errorf("the import reported %d rows, want 2", n)
	}
	if _, total, err := r.ListAssessments(ctx, model.AssessmentFilter{TenantID: tenant, Limit: 50}); err != nil || total != 2 {
		t.Errorf("%d assessments after importing 2: %v", total, err)
	}

	// Re-importing the same two is still two rows.
	if _, err := r.BulkUpsertAssessments(ctx, tenant, nil, []model.BulkAssessmentItem{
		{FrameworkID: fw.ID, ControlID: a.ID, Status: "compliant", Score: 100},
		{FrameworkID: fw.ID, ControlID: b.ID, Status: "compliant", Score: 100},
	}); err != nil {
		t.Fatalf("BulkUpsertAssessments: %v", err)
	}
	if _, total, err := r.ListAssessments(ctx, model.AssessmentFilter{TenantID: tenant, Limit: 50}); err != nil || total != 2 {
		t.Errorf("%d assessments after re-importing the same 2: %v", total, err)
	}
}

// ─── The risk register ───────────────────────────────────────────────────────

// The risk score is derived from likelihood and impact, and closing a risk
// takes it out of the register without deleting it.
func TestARiskScoresItselfAndClosesWithoutVanishing(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	risk, err := r.CreateRisk(ctx, tenant, nil, &model.CreateRiskRequest{
		Title: "Fuite de données clients", Category: "data_breach",
		Likelihood: 4, Impact: 5, MitigationPlan: "Chiffrement et cloisonnement",
	})
	if err != nil {
		t.Fatalf("CreateRisk: %v", err)
	}
	if risk.RiskScore != 20 {
		t.Errorf("risk_score is %d, want 4 × 5", risk.RiskScore)
	}
	if risk.Status != "open" {
		t.Errorf("a fresh risk is %q", risk.Status)
	}

	// Lowering the likelihood lowers the score, because the score is derived
	// and not stored by the caller.
	lowered, err := r.UpdateRisk(ctx, tenant, risk.ID, &model.UpdateRiskRequest{
		Likelihood: intp(2),
	})
	if err != nil {
		t.Fatalf("UpdateRisk: %v", err)
	}
	if lowered == nil || lowered.RiskScore != 10 {
		t.Errorf("risk_score is %+v, want 2 × 5", lowered)
	}

	if err := r.CloseRisk(ctx, tenant, risk.ID); err != nil {
		t.Fatalf("CloseRisk: %v", err)
	}
	closed, err := r.GetRisk(ctx, tenant, risk.ID)
	if err != nil || closed == nil {
		t.Fatalf("a closed risk disappeared: %v", err)
	}
	if closed.Status != "closed" {
		t.Errorf("status is %q after being closed", closed.Status)
	}
	// It is out of the open register but still auditable.
	if _, total, err := r.ListRisks(ctx, model.RiskFilter{TenantID: tenant, Status: "open", Limit: 50}); err != nil || total != 0 {
		t.Errorf("%d open risks after closing the only one: %v", total, err)
	}
	if _, total, err := r.ListRisks(ctx, model.RiskFilter{TenantID: tenant, Limit: 50}); err != nil || total != 1 {
		t.Errorf("the closed risk is gone from the register: %d, %v", total, err)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	fw := framework(t, r, mine, "ISO27001")
	ctl := control(t, r, mine, fw.ID, "A.5.1.1")
	as := assess(t, r, mine, fw.ID, ctl.ID, "compliant", 100)
	risk, err := r.CreateRisk(ctx, mine, nil, &model.CreateRiskRequest{
		Title: "Mon risque", Category: "operational", Likelihood: 3, Impact: 3,
	})
	if err != nil {
		t.Fatalf("CreateRisk: %v", err)
	}
	if _, err := r.CreateEvidence(ctx, mine, nil, &model.CreateEvidenceRequest{
		AssessmentID: as.ID, Title: "Ma preuve", EvidenceType: "document",
	}); err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}

	// Reads
	if got, err := r.GetFramework(ctx, theirs, fw.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the framework: %v / %v", got, err)
	}
	if got, err := r.GetControl(ctx, theirs, ctl.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the control: %v / %v", got, err)
	}
	if got, err := r.GetAssessment(ctx, theirs, as.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the assessment: %v / %v", got, err)
	}
	if got, err := r.GetRisk(ctx, theirs, risk.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the risk: %v / %v", got, err)
	}
	if got, err := r.FrameworkScore(ctx, theirs, fw.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the score: %v / %v", got, err)
	}
	if rows, err := r.ListFrameworks(ctx, model.FrameworkFilter{TenantID: theirs}); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d frameworks: %v", len(rows), err)
	}
	if rows, total, err := r.ListControls(ctx, model.ControlFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d controls (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListAssessments(ctx, model.AssessmentFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assessments (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListRisks(ctx, model.RiskFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d risks (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListEvidence(ctx, theirs, as.ID); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d pieces of evidence: %v", len(rows), err)
	}
	if rows, err := r.ListAutomatedControls(ctx, theirs); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d automated controls: %v", len(rows), err)
	}
	// A filter with no tenant matches nothing rather than everything.
	if rows, err := r.ListFrameworks(ctx, model.FrameworkFilter{}); err != nil || len(rows) != 0 {
		t.Errorf("a filter with no tenant listed %d frameworks: %v", len(rows), err)
	}

	// Writes
	if got, err := r.UpdateAssessment(ctx, theirs, as.ID, &model.UpdateAssessmentRequest{
		Status: strp("non_compliant"),
	}, nil); err != nil || got != nil {
		t.Errorf("the neighbour failed our assessment: %v / %v", got, err)
	}
	if got, err := r.UpdateRisk(ctx, theirs, risk.ID, &model.UpdateRiskRequest{
		Status: strp("closed"),
	}); err != nil || got != nil {
		t.Errorf("the neighbour closed our risk: %v / %v", got, err)
	}
	if err := r.SetFrameworkActive(ctx, theirs, fw.ID, false); err != nil {
		t.Errorf("SetFrameworkActive by the neighbour: %v", err)
	}
	if err := r.CloseRisk(ctx, theirs, risk.ID); err != nil {
		t.Errorf("CloseRisk by the neighbour: %v", err)
	}

	// Nothing moved: the assessment is still compliant, the risk still open,
	// the framework still active — so the score is unchanged.
	score, err := r.FrameworkScore(ctx, mine, fw.ID)
	if err != nil || score == nil {
		t.Fatalf("re-read the score: %v", err)
	}
	if score.Compliant != 1 {
		t.Errorf("the neighbour's verdict landed: %+v", score)
	}
	live, err := r.GetRisk(ctx, mine, risk.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the risk: %v", err)
	}
	if live.Status != "open" {
		t.Errorf("the risk is %q — the neighbour closed it", live.Status)
	}
	// A framework is created inactive — is_active defaults to FALSE, so
	// adopting a framework is a deliberate act — so what the neighbour must
	// not be able to do is change that state either way.
	if err := r.SetFrameworkActive(ctx, mine, fw.ID, true); err != nil {
		t.Fatalf("SetFrameworkActive: %v", err)
	}
	if err := r.SetFrameworkActive(ctx, theirs, fw.ID, false); err != nil {
		t.Errorf("SetFrameworkActive by the neighbour: %v", err)
	}
	fwLive, err := r.GetFramework(ctx, mine, fw.ID)
	if err != nil || fwLive == nil {
		t.Fatalf("re-read the framework: %v", err)
	}
	if !fwLive.IsActive {
		t.Error("the neighbour deactivated our framework")
	}
}

// ─── The dashboard ───────────────────────────────────────────────────────────

func TestTheStatisticsCoverEveryFrameworkAndTheTopRisks(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	iso := framework(t, r, tenant, "ISO27001")
	pci := framework(t, r, tenant, "PCIDSS")
	isoCtl := control(t, r, tenant, iso.ID, "A.5.1.1")
	control(t, r, tenant, pci.ID, "1.1")
	assess(t, r, tenant, iso.ID, isoCtl.ID, "compliant", 100)

	for i, c := range []struct {
		title              string
		likelihood, impact int
	}{
		{"Risque majeur", 5, 5},
		{"Risque moyen", 3, 3},
		{"Risque faible", 1, 2},
	} {
		if _, err := r.CreateRisk(ctx, tenant, nil, &model.CreateRiskRequest{
			Title: c.title, Category: "operational",
			Likelihood: c.likelihood, Impact: c.impact,
		}); err != nil {
			t.Fatalf("CreateRisk %d: %v", i, err)
		}
	}

	// The neighbour's posture, which must appear nowhere below.
	nbFw := framework(t, r, other, "SOC2")
	control(t, r, other, nbFw.ID, "CC1.1")

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats.Frameworks) != 2 {
		t.Fatalf("%d frameworks in the statistics, want 2", len(stats.Frameworks))
	}
	byCode := map[string]model.ComplianceScore{}
	for _, f := range stats.Frameworks {
		byCode[f.FrameworkCode] = f
	}
	if byCode["ISO27001"].ScorePct != 100 {
		t.Errorf("ISO 27001 scores %v, want 100 for its one compliant control", byCode["ISO27001"].ScorePct)
	}
	if byCode["PCIDSS"].ScorePct != 0 {
		t.Errorf("PCI DSS scores %v, want 0 for its unassessed control", byCode["PCIDSS"].ScorePct)
	}
	if _, ok := byCode["SOC2"]; ok {
		t.Error("the neighbour's framework is in our statistics")
	}

	if len(stats.TopRisks) != 3 {
		t.Fatalf("%d top risks, want 3", len(stats.TopRisks))
	}
	// Highest first: that is what makes the list useful.
	if stats.TopRisks[0].RiskScore != 25 {
		t.Errorf("the first risk scores %d, want the highest", stats.TopRisks[0].RiskScore)
	}
	for i := 1; i < len(stats.TopRisks); i++ {
		if stats.TopRisks[i-1].RiskScore < stats.TopRisks[i].RiskScore {
			t.Errorf("the risks are not ordered: %d before %d",
				stats.TopRisks[i-1].RiskScore, stats.TopRisks[i].RiskScore)
		}
	}
}

func TestAFreshTenantGetsAnEmptyPostureRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if len(stats.Frameworks) != 0 || len(stats.TopRisks) != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
}

// ─── Filters ─────────────────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	fw := framework(t, r, tenant, "ISO27001")
	control(t, r, tenant, fw.ID, "A.5.1.1")
	auto, err := r.CreateControl(ctx, tenant, &model.CreateControlRequest{
		FrameworkID: fw.ID, ControlID: "A.12.6.1", Domain: "A.12",
		Title: "Gestion des vulnérabilités", Priority: "CRITICAL", IsAutomated: true,
	})
	if err != nil {
		t.Fatalf("CreateControl: %v", err)
	}

	yes := true
	for _, c := range []struct {
		what   string
		filter model.ControlFilter
		want   int
	}{
		{"all", model.ControlFilter{TenantID: tenant, Limit: 50}, 2},
		{"by framework", model.ControlFilter{TenantID: tenant, FrameworkID: &fw.ID, Limit: 50}, 2},
		{"by domain", model.ControlFilter{TenantID: tenant, Domain: "A.12", Limit: 50}, 1},
		{"by priority", model.ControlFilter{TenantID: tenant, Priority: "CRITICAL", Limit: 50}, 1},
		{"automated only", model.ControlFilter{TenantID: tenant, IsAutomated: &yes, Limit: 50}, 1},
	} {
		rows, total, err := r.ListControls(ctx, c.filter)
		if err != nil {
			t.Fatalf("ListControls %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	// The automated controls are what the auto-assessment path reads, so they
	// have to be exactly the ones marked automated.
	autos, err := r.ListAutomatedControls(ctx, tenant)
	if err != nil {
		t.Fatalf("ListAutomatedControls: %v", err)
	}
	if len(autos) != 1 || autos[0].ID != auto.ID {
		t.Fatalf("%d automated controls, want only the one marked so", len(autos))
	}

	for i, c := range []struct {
		title              string
		category           string
		likelihood, impact int
	}{
		{"Cyber", "cybersecurity", 5, 5},
		{"Tiers", "third_party", 2, 2},
	} {
		if _, err := r.CreateRisk(ctx, tenant, nil, &model.CreateRiskRequest{
			Title: c.title, Category: c.category,
			Likelihood: c.likelihood, Impact: c.impact,
		}); err != nil {
			t.Fatalf("CreateRisk %d: %v", i, err)
		}
	}
	for _, c := range []struct {
		what   string
		filter model.RiskFilter
		want   int
	}{
		{"all", model.RiskFilter{TenantID: tenant, Limit: 50}, 2},
		{"by category", model.RiskFilter{TenantID: tenant, Category: "cybersecurity", Limit: 50}, 1},
		{"by status", model.RiskFilter{TenantID: tenant, Status: "open", Limit: 50}, 2},
		{"above a score", model.RiskFilter{TenantID: tenant, MinScore: 20, Limit: 50}, 1},
		{"above a score nobody reaches", model.RiskFilter{TenantID: tenant, MinScore: 26, Limit: 50}, 0},
	} {
		rows, total, err := r.ListRisks(ctx, c.filter)
		if err != nil {
			t.Fatalf("ListRisks %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
}

func strp(s string) *string { return &s }
func intp(n int) *int       { return &n }
