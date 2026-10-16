package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/risk/internal/model"
)

// The quantified-risk repository: the first test this service has ever had.
//
// This is the service whose numbers go in front of a board: the annualised loss
// expectancy of an estate, the scenarios that drive it, the key risk indicators
// an audit committee reads. Every one of them is produced by SQL whose error
// this repository discards, so a query that stopped matching the schema would
// put zero in front of the board rather than fail.

func repo(t *testing.T) (*RiskRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewRiskRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func asset(t *testing.T, r *RiskRepository, tenant uuid.UUID, name string) *model.RiskAsset {
	t.Helper()
	a, err := r.CreateAsset(context.Background(), tenant, &model.CreateRiskAssetRequest{
		Name: name, AssetType: "application", BusinessUnit: "Banque de détail",
		Owner: "DSI", Criticality: "critical", Description: "Actif de test",
		BusinessValue: 5000, RevenueImpact: 2000, RegulatoryImpact: 1000,
		ReputationalImpact:   500,
		ThreatEventFrequency: 4.5, Vulnerability: 6, LossMagnitude: 8,
		Metadata: map[string]any{"site": "Paris"},
	})
	if err != nil {
		t.Fatalf("CreateAsset(%s): %v", name, err)
	}
	return a
}

func scenario(t *testing.T, r *RiskRepository, tenant uuid.UUID, name, kind string, probability float64, primary, secondary int64) *model.RiskScenario {
	t.Helper()
	s, err := r.CreateScenario(context.Background(), tenant, &model.CreateScenarioRequest{
		Name: name, ScenarioType: kind, ThreatActor: "cybercriminal",
		Description: "Scénario de test", AnnualProbability: probability,
		PrimaryLoss: primary, SecondaryLoss: secondary,
		Frameworks: []string{"iso27005"},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScenario(%s): %v", name, err)
	}
	return s
}

// ─── The round trip ──────────────────────────────────────────────────────────

// An asset reads back with its four impact dimensions and its FAIR inputs
// intact: they are what the loss expectancy is computed from, so a figure lost
// in the round trip is a figure wrong on the report.
func TestAnAssetKeepsItsImpactDimensions(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	made := asset(t, r, tenant, "Core banking")
	got, err := r.GetAsset(ctx, tenant, made.ID)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got == nil {
		t.Fatal("GetAsset found nothing")
	}
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"business_value", got.BusinessValue, 5000},
		{"revenue_impact", got.RevenueImpact, 2000},
		{"regulatory_impact", got.RegulatoryImpact, 1000},
		{"reputational_impact", got.ReputationalImpact, 500},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if got.ThreatEventFrequency != 4.5 || got.Vulnerability != 6 || got.LossMagnitude != 8 {
		t.Errorf("the FAIR inputs are %v/%v/%v", got.ThreatEventFrequency, got.Vulnerability, got.LossMagnitude)
	}
	if got.Criticality != "critical" {
		t.Errorf("criticality is %q", got.Criticality)
	}
	if !got.IsActive {
		t.Error("a fresh asset is inactive")
	}
	// The annualised loss expectancy is derived, so it must be there without
	// anyone computing it by hand.
	if got.ALE == 0 {
		t.Error("the annualised loss expectancy is zero although every input is above it")
	}
}

// Everything with only its required fields reads back. threat_actor is the one
// to watch: it carries a CHECK that enumerates its values, and a CHECK rejects
// the empty string where it accepts NULL — so an optional field held as a Go
// string has to be sent as NULL when unset, or the insert is refused outright.
func TestEverythingWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	bare, err := r.CreateAsset(ctx, tenant, &model.CreateRiskAssetRequest{
		Name: "Partage de fichiers", AssetType: "data",
	})
	if err != nil {
		t.Fatalf("CreateAsset with nothing optional: %v", err)
	}
	if got, err := r.GetAsset(ctx, tenant, bare.ID); err != nil || got == nil {
		t.Fatalf("GetAsset: %+v / %v", got, err)
	}
	if rows, total, err := r.ListAssets(ctx, tenant, model.ListAssetsFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListAssets gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A scenario with no threat actor named: the case the CHECK refuses if the
	// empty string reaches it.
	sc, err := r.CreateScenario(ctx, tenant, &model.CreateScenarioRequest{
		Name: "Panne majeure", ScenarioType: "business_interruption",
		AnnualProbability: 0.2,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScenario with no threat actor: %v", err)
	}
	if sc.ThreatActor != "" {
		t.Errorf("threat_actor is %q, want empty", sc.ThreatActor)
	}
	if got, err := r.GetScenario(ctx, tenant, sc.ID); err != nil || got == nil {
		t.Fatalf("GetScenario: %+v / %v", got, err)
	}
	if rows, total, err := r.ListScenarios(ctx, tenant, model.ListScenariosFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListScenarios gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A treatment with nobody assigned and no due date.
	tr, err := r.CreateTreatment(ctx, tenant, &model.CreateTreatmentRequest{
		ScenarioID: sc.ID, TreatmentType: "mitigate", Description: "Redondance",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateTreatment with nothing optional: %v", err)
	}
	if tr.DueDate != nil || tr.CompletedAt != nil {
		t.Errorf("a fresh treatment is dated or done: %+v", tr)
	}
	if got, err := r.GetTreatment(ctx, tenant, tr.ID); err != nil || got == nil {
		t.Fatalf("GetTreatment: %+v / %v", got, err)
	}
	if rows, total, err := r.ListTreatments(ctx, tenant, nil, "", 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListTreatments gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// An assessment with no framework and no scope.
	as, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		Name: "Revue annuelle", AssessmentType: "annual",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateAssessment with nothing optional: %v", err)
	}
	if got, err := r.GetAssessment(ctx, tenant, as.ID); err != nil || got == nil {
		t.Fatalf("GetAssessment: %+v / %v", got, err)
	}
	if rows, total, err := r.ListAssessments(ctx, tenant, "", 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListAssessments gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A KRI with no description, no unit and no source service.
	kri, err := r.CreateKRI(ctx, tenant, &model.CreateKRIRequest{
		Name: "Vulnérabilités critiques ouvertes", Category: "cyber",
		MetricName: "open_critical_vulns",
	})
	if err != nil {
		t.Fatalf("CreateKRI with nothing optional: %v", err)
	}
	if got, err := r.GetKRI(ctx, tenant, kri.ID); err != nil || got == nil {
		t.Fatalf("GetKRI: %+v / %v", got, err)
	}
	if rows, err := r.ListKRIs(ctx, tenant, "", ""); err != nil || len(rows) != 1 {
		t.Fatalf("ListKRIs gave %d rows: %v", len(rows), err)
	}
}

// ─── The numbers that reach a board ──────────────────────────────────────────

// A scenario's total loss is derived from its two components, and the
// assessment aggregates what is active. These are the figures a risk committee
// is shown.
func TestAnAssessmentAggregatesTheActiveScenarios(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// 1 000 + 500 at a probability of 0.5 → 750 of expected loss.
	big := scenario(t, r, tenant, "Rançongiciel", "ransomware", 0.5, 1000, 500)
	if big.TotalLoss != 1500 {
		t.Errorf("total_loss is %d, want the 1500 its components make", big.TotalLoss)
	}
	// A second, smaller one.
	scenario(t, r, tenant, "Hameçonnage", "phishing", 0.2, 100, 0)
	// And one that has been closed, which must not count.
	closed := scenario(t, r, tenant, "Ancien risque", "ddos", 0.9, 10000, 0)
	if _, err := r.UpdateScenario(ctx, tenant, closed.ID, &model.UpdateScenarioRequest{
		Status: "closed",
	}); err != nil {
		t.Fatalf("UpdateScenario: %v", err)
	}

	as, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		Name: "Revue trimestrielle", AssessmentType: "annual", Framework: "iso27005",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateAssessment: %v", err)
	}
	if err := r.ComputeAssessment(ctx, tenant, as.ID); err != nil {
		t.Fatalf("ComputeAssessment: %v", err)
	}

	got, err := r.GetAssessment(ctx, tenant, as.ID)
	if err != nil || got == nil {
		t.Fatalf("GetAssessment: %v", err)
	}
	if got.ScenariosCount != 2 {
		t.Errorf("scenarios_count is %d, want the 2 still active", got.ScenariosCount)
	}
	// 1500 × 0.5 + 100 × 0.2 = 770.
	if got.TotalALE != 770 {
		t.Errorf("total_ale is %d, want 770", got.TotalALE)
	}
	if got.Status != "in_progress" {
		t.Errorf("status is %q after being computed", got.Status)
	}
}

// A KRI changes colour when it crosses its own thresholds, and every change is
// kept: a committee asks how a figure moved, not only where it is.
func TestAKRIChangesColourAndKeepsItsHistory(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	green, amber := 10.0, 25.0
	kri, err := r.CreateKRI(ctx, tenant, &model.CreateKRIRequest{
		Name: "Vulnérabilités critiques", Category: "cyber",
		MetricName: "open_critical", Unit: "count",
		ThresholdGreen: &green, ThresholdAmber: &amber,
		SourceService: "vuln",
	})
	if err != nil {
		t.Fatalf("CreateKRI: %v", err)
	}
	if kri.ThresholdGreen == nil || *kri.ThresholdGreen != 10 {
		t.Errorf("threshold_green is %v", kri.ThresholdGreen)
	}

	// The thresholds are floors, not ceilings: at or above the green threshold
	// is amber, at or above the amber one is red. Green therefore means
	// strictly below the first threshold, which is what "below this = green"
	// in the schema says.
	for _, c := range []struct {
		value float64
		want  string
	}{
		{5, "green"},
		{9.99, "green"},
		{10, "amber"},
		{24.99, "amber"},
		{25, "red"},
		{40, "red"},
	} {
		got, err := r.UpdateKRIValue(ctx, tenant, kri.ID, c.value)
		if err != nil {
			t.Fatalf("UpdateKRIValue(%v): %v", c.value, err)
		}
		if got == nil {
			t.Fatalf("UpdateKRIValue(%v) returned nothing", c.value)
		}
		if got.Status != c.want {
			t.Errorf("a value of %v is %q, want %q", c.value, got.Status, c.want)
		}
		if got.CurrentValue != c.value {
			t.Errorf("current_value is %v, want %v", got.CurrentValue, c.value)
		}
	}

	history, err := r.GetKRIHistory(ctx, tenant, kri.ID, 50)
	if err != nil {
		t.Fatalf("GetKRIHistory: %v", err)
	}
	if len(history) != 6 {
		t.Fatalf("%d history entries after six updates", len(history))
	}
	// Newest first, and each entry carries the colour it was at the time.
	if history[0].Value != 40 || history[0].Status != "red" {
		t.Errorf("the newest entry is %+v", history[0])
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	a := asset(t, r, mine, "Core banking")
	sc := scenario(t, r, mine, "Rançongiciel", "ransomware", 0.4, 2000, 1000)
	tr, err := r.CreateTreatment(ctx, mine, &model.CreateTreatmentRequest{
		ScenarioID: sc.ID, TreatmentType: "mitigate", Description: "Sauvegardes hors ligne",
		Cost: 300, RiskReduction: 40,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateTreatment: %v", err)
	}
	as, err := r.CreateAssessment(ctx, mine, &model.CreateAssessmentRequest{
		Name: "Ma revue", AssessmentType: "annual",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateAssessment: %v", err)
	}
	kri, err := r.CreateKRI(ctx, mine, &model.CreateKRIRequest{
		Name: "Mon indicateur", Category: "cyber", MetricName: "m",
	})
	if err != nil {
		t.Fatalf("CreateKRI: %v", err)
	}

	// Reads
	if got, err := r.GetAsset(ctx, theirs, a.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the asset: %v / %v", got, err)
	}
	if got, err := r.GetScenario(ctx, theirs, sc.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the scenario: %v / %v", got, err)
	}
	if got, err := r.GetTreatment(ctx, theirs, tr.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the treatment: %v / %v", got, err)
	}
	if got, err := r.GetAssessment(ctx, theirs, as.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the assessment: %v / %v", got, err)
	}
	if got, err := r.GetKRI(ctx, theirs, kri.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the KRI: %v / %v", got, err)
	}
	for _, c := range []struct {
		what  string
		count func() (int, error)
	}{
		{"assets", func() (int, error) {
			_, total, err := r.ListAssets(ctx, theirs, model.ListAssetsFilter{Page: 1, PageSize: 50})
			return total, err
		}},
		{"scenarios", func() (int, error) {
			_, total, err := r.ListScenarios(ctx, theirs, model.ListScenariosFilter{Page: 1, PageSize: 50})
			return total, err
		}},
		{"treatments", func() (int, error) {
			_, total, err := r.ListTreatments(ctx, theirs, nil, "", 1, 50)
			return total, err
		}},
		{"assessments", func() (int, error) {
			_, total, err := r.ListAssessments(ctx, theirs, "", 1, 50)
			return total, err
		}},
		{"KRIs", func() (int, error) {
			rows, err := r.ListKRIs(ctx, theirs, "", "")
			return len(rows), err
		}},
		{"KRI history", func() (int, error) {
			rows, err := r.GetKRIHistory(ctx, theirs, kri.ID, 50)
			return len(rows), err
		}},
	} {
		n, err := c.count()
		if err != nil || n != 0 {
			t.Errorf("the neighbour saw %d %s: %v", n, c.what, err)
		}
	}

	// Writes
	if got, err := r.UpdateAsset(ctx, theirs, a.ID, &model.UpdateRiskAssetRequest{Owner: "voisin"}); err != nil || got != nil {
		t.Errorf("the neighbour reassigned the asset: %v / %v", got, err)
	}
	if got, err := r.UpdateScenario(ctx, theirs, sc.ID, &model.UpdateScenarioRequest{Status: "accepted"}); err != nil || got != nil {
		t.Errorf("the neighbour accepted the scenario: %v / %v", got, err)
	}
	if got, err := r.UpdateTreatment(ctx, theirs, tr.ID, &model.UpdateTreatmentRequest{Status: "completed"}); err != nil || got != nil {
		t.Errorf("the neighbour completed the treatment: %v / %v", got, err)
	}
	if got, err := r.UpdateKRIValue(ctx, theirs, kri.ID, 999); err != nil || got != nil {
		t.Errorf("the neighbour moved the KRI: %v / %v", got, err)
	}
	if err := r.ComputeAssessment(ctx, theirs, as.ID); err != nil {
		t.Errorf("ComputeAssessment by the neighbour: %v", err)
	}

	// Nothing moved.
	again, err := r.GetScenario(ctx, mine, sc.ID)
	if err != nil || again == nil {
		t.Fatalf("re-read the scenario: %v", err)
	}
	if again.Status != "active" {
		t.Errorf("the scenario is %q — the neighbour's change landed", again.Status)
	}
	liveKRI, err := r.GetKRI(ctx, mine, kri.ID)
	if err != nil || liveKRI == nil {
		t.Fatalf("re-read the KRI: %v", err)
	}
	if liveKRI.CurrentValue == 999 {
		t.Error("the neighbour's value landed on our KRI")
	}
	liveAs, err := r.GetAssessment(ctx, mine, as.ID)
	if err != nil || liveAs == nil {
		t.Fatalf("re-read the assessment: %v", err)
	}
	if liveAs.ScenariosCount != 0 {
		t.Errorf("the neighbour's computation landed on our assessment: %d scenarios", liveAs.ScenariosCount)
	}
}

// ─── The dashboard ───────────────────────────────────────────────────────────

func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	asset(t, r, tenant, "Core banking")
	low, err := r.CreateAsset(ctx, tenant, &model.CreateRiskAssetRequest{
		Name: "Intranet", AssetType: "application", Criticality: "low",
		BusinessValue: 100, ThreatEventFrequency: 1, Vulnerability: 1,
		LossMagnitude: 1,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	retired, err := r.CreateAsset(ctx, tenant, &model.CreateRiskAssetRequest{
		Name: "Ancien système", AssetType: "application", Criticality: "medium",
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := r.UpdateAsset(ctx, tenant, retired.ID, &model.UpdateRiskAssetRequest{
		IsActive: boolp(false),
	}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	sc := scenario(t, r, tenant, "Rançongiciel", "ransomware", 0.5, 2000, 1000)
	scenario(t, r, tenant, "Hameçonnage", "phishing", 0.3, 200, 0)

	// Two treatments, one of them already done.
	if _, err := r.CreateTreatment(ctx, tenant, &model.CreateTreatmentRequest{
		ScenarioID: sc.ID, TreatmentType: "mitigate", Description: "En cours",
	}, uuid.Nil); err != nil {
		t.Fatalf("CreateTreatment: %v", err)
	}
	done, err := r.CreateTreatment(ctx, tenant, &model.CreateTreatmentRequest{
		ScenarioID: sc.ID, TreatmentType: "avoid", Description: "Terminé",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateTreatment: %v", err)
	}
	if _, err := r.UpdateTreatment(ctx, tenant, done.ID, &model.UpdateTreatmentRequest{
		Status: "completed",
	}); err != nil {
		t.Fatalf("UpdateTreatment: %v", err)
	}

	amber := 10.0
	kri, err := r.CreateKRI(ctx, tenant, &model.CreateKRIRequest{
		Name: "Indicateur", Category: "cyber", MetricName: "m",
		ThresholdGreen: &amber,
	})
	if err != nil {
		t.Fatalf("CreateKRI: %v", err)
	}
	if _, err := r.UpdateKRIValue(ctx, tenant, kri.ID, 5); err != nil {
		t.Fatalf("UpdateKRIValue: %v", err)
	}

	// The neighbour's estate, which must change nothing below.
	asset(t, r, other, "Voisin")
	scenario(t, r, other, "Voisin", "ddos", 0.9, 9999, 0)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalAssets != 2 {
		t.Errorf("total_assets is %d, want the 2 still active", stats.TotalAssets)
	}
	if stats.TotalScenarios != 2 {
		t.Errorf("total_scenarios is %d, want 2", stats.TotalScenarios)
	}
	if stats.OpenTreatments != 1 {
		t.Errorf("open_treatments is %d, want 1 — the completed one is counted", stats.OpenTreatments)
	}
	if stats.TotalALE == 0 {
		t.Error("total_ale is zero although the assets carry a loss expectancy")
	}
	if stats.AvgResidualRisk < 0 {
		t.Errorf("avg_residual_risk is %v", stats.AvgResidualRisk)
	}
	if stats.AssetsByCriticality["critical"] != 1 || stats.AssetsByCriticality["low"] != 1 {
		t.Errorf("assets by criticality is %v", stats.AssetsByCriticality)
	}
	if stats.AssetsByCriticality["medium"] != 0 {
		t.Errorf("the retired asset is still counted: %v", stats.AssetsByCriticality)
	}
	if stats.ScenariosByType["ransomware"] != 1 || stats.ScenariosByType["phishing"] != 1 {
		t.Errorf("scenarios by type is %v", stats.ScenariosByType)
	}
	if stats.KRIsByStatus["green"] != 1 {
		t.Errorf("KRIs by status is %v", stats.KRIsByStatus)
	}
	_ = low
}

func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.TotalAssets != 0 || stats.TotalScenarios != 0 || stats.TotalALE != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	if stats.AvgResidualRisk != 0 {
		t.Errorf("avg_residual_risk is %v with no asset at all", stats.AvgResidualRisk)
	}
	for name, m := range map[string]map[string]int{
		"scenarios_by_level":    stats.ScenariosByLevel,
		"scenarios_by_type":     stats.ScenariosByType,
		"assets_by_criticality": stats.AssetsByCriticality,
		"kris_by_status":        stats.KRIsByStatus,
	} {
		if m == nil {
			t.Errorf("%s came back nil rather than empty", name)
		}
	}

	// An assessment computed over nothing is zero rather than an error: an
	// AVG over no rows is NULL, and that is a first assessment on day one.
	as, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		Name: "Première revue", AssessmentType: "annual",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateAssessment: %v", err)
	}
	if err := r.ComputeAssessment(ctx, tenant, as.ID); err != nil {
		t.Fatalf("ComputeAssessment over nothing: %v", err)
	}
	got, err := r.GetAssessment(ctx, tenant, as.ID)
	if err != nil || got == nil {
		t.Fatalf("GetAssessment: %v", err)
	}
	if got.ScenariosCount != 0 || got.TotalALE != 0 || got.OverallRiskScore != 0 {
		t.Errorf("an assessment over nothing is %+v", got)
	}
}

// ─── Filters ─────────────────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	asset(t, r, tenant, "Core banking")
	if _, err := r.CreateAsset(ctx, tenant, &model.CreateRiskAssetRequest{
		Name: "Serveur de fichiers", AssetType: "infrastructure",
		Criticality: "low", BusinessUnit: "Support",
	}); err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	for _, c := range []struct {
		what   string
		filter model.ListAssetsFilter
		want   int
	}{
		{"all", model.ListAssetsFilter{Page: 1, PageSize: 50}, 2},
		{"by type", model.ListAssetsFilter{AssetType: "infrastructure", Page: 1, PageSize: 50}, 1},
		{"by criticality", model.ListAssetsFilter{Criticality: "critical", Page: 1, PageSize: 50}, 1},
		{"by business unit", model.ListAssetsFilter{BusinessUnit: "Support", Page: 1, PageSize: 50}, 1},
		{"by a unit nobody has", model.ListAssetsFilter{BusinessUnit: "Mars", Page: 1, PageSize: 50}, 0},
	} {
		rows, total, err := r.ListAssets(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListAssets %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	sc := scenario(t, r, tenant, "Rançongiciel", "ransomware", 0.5, 2000, 1000)
	scenario(t, r, tenant, "Fraude interne", "insider_threat", 0.1, 500, 0)

	for _, c := range []struct {
		what   string
		filter model.ListScenariosFilter
		want   int
	}{
		{"all", model.ListScenariosFilter{Page: 1, PageSize: 50}, 2},
		{"by type", model.ListScenariosFilter{ScenarioType: "ransomware", Page: 1, PageSize: 50}, 1},
		{"by status", model.ListScenariosFilter{Status: "active", Page: 1, PageSize: 50}, 2},
		{"by framework", model.ListScenariosFilter{Framework: "iso27005", Page: 1, PageSize: 50}, 2},
		{"by a framework nobody uses", model.ListScenariosFilter{Framework: "nist-csf-2", Page: 1, PageSize: 50}, 0},
	} {
		rows, total, err := r.ListScenarios(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListScenarios %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	// Treatments can be narrowed to one scenario, which is how a risk owner
	// sees what is being done about their own risk.
	if _, err := r.CreateTreatment(ctx, tenant, &model.CreateTreatmentRequest{
		ScenarioID: sc.ID, TreatmentType: "mitigate", Description: "Sauvegardes",
	}, uuid.Nil); err != nil {
		t.Fatalf("CreateTreatment: %v", err)
	}
	if rows, total, err := r.ListTreatments(ctx, tenant, &sc.ID, "", 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Errorf("the per-scenario listing gave %d rows (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListTreatments(ctx, tenant, nil, "planned", 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Errorf("the per-status listing gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// And KRIs by category and status.
	if _, err := r.CreateKRI(ctx, tenant, &model.CreateKRIRequest{
		Name: "Indicateur", Category: "cyber", MetricName: "m",
	}); err != nil {
		t.Fatalf("CreateKRI: %v", err)
	}
	if rows, err := r.ListKRIs(ctx, tenant, "cyber", ""); err != nil || len(rows) != 1 {
		t.Errorf("the per-category listing gave %d rows: %v", len(rows), err)
	}
	if rows, err := r.ListKRIs(ctx, tenant, "financial", ""); err != nil || len(rows) != 0 {
		t.Errorf("a category nobody uses gave %d rows: %v", len(rows), err)
	}
}

func boolp(b bool) *bool { return &b }

var _ = time.Now
