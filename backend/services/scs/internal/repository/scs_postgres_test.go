package repository

import (
	"context"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/scs/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The software supply chain repository against a real PostgreSQL.
//
// Two columns here are filled in only when something happens later —
// scs_alerts.resolved_by when the alert is closed, scs_assessments.risk_rating
// when the assessment is graded. Both are nullable, both are read into Go
// strings, and neither is written at creation: the kind of defect that a test
// with a stubbed database cannot see and that fails on the very first call.
//
// The other thing a database shows is what an SBOM upload actually records.
// An SBOM is an attestation of what ships; a component quietly dropped from it
// is worse than a refused upload.

func repo(t *testing.T) (*SCSRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewSCSRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func vendor(t *testing.T, r *SCSRepository, tenant uuid.UUID, name, vendorType string, tier int) *model.SCSVendor {
	t.Helper()
	v, err := r.CreateVendor(context.Background(), tenant, &model.CreateVendorRequest{
		Name: name, Website: "https://" + name + ".example", VendorType: vendorType,
		RiskTier: tier, ContactName: "Service achats", ContactEmail: "achats@" + name + ".example",
		HasSOC2: true, Tags: []string{"critique"}, Notes: "Fournisseur de test",
	}, nil)
	if err != nil {
		t.Fatalf("CreateVendor(%s): %v", name, err)
	}
	return v
}

func component(t *testing.T, r *SCSRepository, tenant uuid.UUID, name, version, ecosystem string, vendorID *uuid.UUID) *model.SCSComponent {
	t.Helper()
	c, err := r.CreateComponent(context.Background(), tenant, &model.CreateComponentRequest{
		VendorID: vendorID, Name: name, Version: version, ComponentType: "library",
		Ecosystem: ecosystem, PURL: "pkg:" + ecosystem + "/" + name + "@" + version,
		License: "Apache-2.0", SourceRepo: "https://github.com/x/" + name,
		UsedIn: []string{"api-paiement"}, IsDirect: true, Tags: []string{"runtime"},
	})
	if err != nil {
		t.Fatalf("CreateComponent(%s): %v", name, err)
	}
	return c
}

// ─── The round trip ──────────────────────────────────────────────────────────

// An alert with nothing optional. resolved_by is NULL until somebody closes
// it, and the column is read into a string.
func TestAnAlertWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	a, err := r.CreateAlert(ctx, tenant, &model.CreateAlertRequest{
		AlertType: "new_vulnerability", Severity: "critical",
		Title: "CVE-2024-0001 dans une dépendance directe",
	})
	if err != nil {
		t.Fatalf("CreateAlert with nothing optional: %v", err)
	}
	if a.Status != "open" {
		t.Errorf("a fresh alert is %q, want the schema's default", a.Status)
	}
	if a.ResolvedBy != "" || a.ResolvedAt != nil {
		t.Errorf("a fresh alert is already resolved: %+v", a)
	}
	if a.CVEIDs == nil || a.AffectedComponents == nil || a.Tags == nil {
		t.Error("an array came back nil, which serialises as null rather than []")
	}
	if a.VendorID != nil || a.ComponentID != nil {
		t.Errorf("the alert invented a subject: %+v", a)
	}

	// Closed, with a name and a date.
	resolved := "resolved"
	who := "jdupont"
	done, err := r.UpdateAlert(ctx, tenant, a.ID, &model.UpdateAlertRequest{
		Status: &resolved, ResolvedBy: &who,
	})
	if err != nil || done == nil {
		t.Fatalf("UpdateAlert: %v", err)
	}
	if done.Status != "resolved" || done.ResolvedBy != who {
		t.Errorf("the closed alert reads %+v", done)
	}
	if done.ResolvedAt == nil {
		t.Error("a resolved alert carries no date")
	}
	if done.Title != a.Title {
		t.Errorf("the update lost a field it did not name: %q", done.Title)
	}
}

// An assessment with nothing optional. risk_rating is NULL until the
// assessment is graded, and the column carries a CHECK that the empty string
// does not satisfy.
func TestAnAssessmentWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	v := vendor(t, r, tenant, "prestataire", "managed_service", 1)

	a, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		VendorID: v.ID,
	}, nil)
	if err != nil {
		t.Fatalf("CreateAssessment with nothing optional: %v", err)
	}
	if a.Status != "planned" || a.AssessmentType != "security_questionnaire" {
		t.Errorf("the assessment defaults read %+v", a)
	}
	if a.RiskRating != "" {
		t.Errorf("an ungraded assessment is rated %q", a.RiskRating)
	}
	if a.Score != nil {
		t.Errorf("an ungraded assessment scores %d", *a.Score)
	}
	if a.MaxScore != 100 {
		t.Errorf("max_score is %d", a.MaxScore)
	}
	if a.Findings == nil {
		t.Error("findings is nil, which serialises as null rather than []")
	}

	// Graded. The grade is what the vendor's own risk level follows.
	completed := "completed"
	score := 42
	rating := "high"
	recs := "Chiffrer les sauvegardes, et revoir les accès prestataires"
	graded, err := r.UpdateAssessment(ctx, tenant, a.ID, &model.UpdateAssessmentRequest{
		Status: &completed, Score: &score, RiskRating: &rating,
		Recommendations: &recs,
		Findings:        []any{map[string]any{"id": "F-1", "severity": "high"}},
	})
	if err != nil || graded == nil {
		t.Fatalf("UpdateAssessment: %v", err)
	}
	if graded.Status != "completed" || graded.RiskRating != "high" {
		t.Errorf("the graded assessment reads %+v", graded)
	}
	if graded.Score == nil || *graded.Score != 42 {
		t.Errorf("the score reads %v", graded.Score)
	}
	if graded.CompletedAt == nil {
		t.Error("a completed assessment carries no date")
	}
	if graded.Recommendations != recs {
		t.Errorf("the recommendations read %q", graded.Recommendations)
	}

	// And the vendor knows it was assessed. last_assessment_at is a column of
	// scs_vendors; the update used to name it on scs_assessments, where it
	// does not exist, so completing an assessment failed outright.
	live, err := r.GetVendor(ctx, tenant, v.ID)
	if err != nil || live == nil {
		t.Fatalf("GetVendor: %v", err)
	}
	if live.AssessmentCount != 1 {
		t.Errorf("the vendor counts %d assessments, want 1", live.AssessmentCount)
	}
	if live.LastAssessmentAt == nil {
		t.Error("the vendor records no last assessment date after one was completed")
	}
}

// A vendor keeps what it was given, and its risk level follows its tier.
func TestAVendorKeepsItsTierAndItsCounts(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	v := vendor(t, r, tenant, "editeur", "software", 1)
	if v.RiskLevel != "critical" {
		t.Errorf("a tier 1 vendor is %q, want critical", v.RiskLevel)
	}
	if v.Status != "active" {
		t.Errorf("a fresh vendor is %q", v.Status)
	}

	component(t, r, tenant, "libpaiement", "1.2.3", "maven", &v.ID)
	component(t, r, tenant, "libjournal", "0.9.0", "maven", &v.ID)
	if _, err := r.CreateAlert(ctx, tenant, &model.CreateAlertRequest{
		VendorID: &v.ID, AlertType: "vendor_breach", Severity: "critical",
		Title: "Fuite annoncée par l'éditeur",
	}); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	live, err := r.GetVendor(ctx, tenant, v.ID)
	if err != nil || live == nil {
		t.Fatalf("GetVendor: %v", err)
	}
	if live.ComponentCount != 2 {
		t.Errorf("the vendor counts %d components, want 2", live.ComponentCount)
	}
	if live.OpenAlertCount != 1 {
		t.Errorf("the vendor counts %d open alerts, want 1", live.OpenAlertCount)
	}

	tier := 4
	lowered, err := r.UpdateVendor(ctx, tenant, v.ID, &model.UpdateVendorRequest{RiskTier: &tier})
	if err != nil || lowered == nil {
		t.Fatalf("UpdateVendor: %v", err)
	}
	if lowered.RiskTier != 4 || lowered.RiskLevel != "low" {
		t.Errorf("after lowering the tier the vendor reads %d / %q", lowered.RiskTier, lowered.RiskLevel)
	}
	if lowered.Name != "editeur" || lowered.Website == "" {
		t.Errorf("the update lost a field it did not name: %+v", lowered)
	}
}

// A component's risk score follows the vulnerabilities recorded against it.
func TestAComponentRiskFollowsItsVulnerabilities(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	c := component(t, r, tenant, "libpaiement", "1.2.3", "maven", nil)
	if c.RiskScore != 0 || c.HasKnownVulns {
		t.Errorf("a fresh component reads %+v", c)
	}

	// Two critical and one high, end of life: 2×25 + 1×12 + 20 = 82.
	yes := true
	two, one := 3, 2
	scored, err := r.UpdateComponent(ctx, tenant, c.ID, &model.UpdateComponentRequest{
		HasKnownVulns: &yes, IsEndOfLife: &yes,
		VulnCount: &two, CriticalVulnCount: &one,
	})
	if err != nil || scored == nil {
		t.Fatalf("UpdateComponent: %v", err)
	}
	if scored.VulnCount != 3 || scored.CriticalVulnCount != 2 {
		t.Errorf("the counts read %d / %d", scored.VulnCount, scored.CriticalVulnCount)
	}
	if !scored.IsEndOfLife || !scored.HasKnownVulns {
		t.Errorf("the flags read %+v", scored)
	}
	if scored.RiskScore == 0 {
		t.Error("a component with two critical vulnerabilities and past its end of life scores zero")
	}
	if scored.License != "Apache-2.0" {
		t.Errorf("the update lost the licence: %q", scored.License)
	}
}

// ─── The SBOM ────────────────────────────────────────────────────────────────

// An SBOM records every component it was given, and says how many.
func TestAnSBOMRecordsEveryComponentItWasGiven(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	comps := []model.CreateComponentRequest{
		{Name: "libpaiement", Version: "1.2.3", ComponentType: "library", Ecosystem: "maven", IsDirect: true},
		{Name: "libjournal", Version: "0.9.0", ComponentType: "library", Ecosystem: "maven", IsDirect: true},
		{Name: "libtransit", Version: "4.1.0", ComponentType: "library", Ecosystem: "maven", IsDirect: false},
	}
	s, err := r.CreateSBOM(ctx, tenant, &model.CreateSBOMRequest{
		Name: "api-paiement", Version: "2026.4.1", Source: "CI/CD pipeline",
		SourceRef: "a1b2c3d", Components: comps,
		RawData: map[string]any{"bomFormat": "CycloneDX"},
	}, nil)
	if err != nil {
		t.Fatalf("CreateSBOM: %v", err)
	}
	if s.TotalComponents != 3 {
		t.Errorf("the SBOM counts %d components, want the 3 it was given", s.TotalComponents)
	}
	if s.DirectComponents != 2 || s.TransitiveComponents != 1 {
		t.Errorf("the SBOM counts %d direct / %d transitive", s.DirectComponents, s.TransitiveComponents)
	}
	if s.SBOMFormat != "cyclonedx" {
		t.Errorf("the format reads %q", s.SBOMFormat)
	}
	if s.RawData == nil {
		t.Error("raw_data came back nil")
	}

	// And the components are in the inventory, once each.
	rows, total, err := r.ListComponents(ctx, tenant, model.ListComponentsFilter{})
	if err != nil {
		t.Fatalf("ListComponents: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Errorf("%d components in the inventory (total=%d), want 3", len(rows), total)
	}

	read, err := r.GetSBOM(ctx, tenant, s.ID)
	if err != nil || read == nil {
		t.Fatalf("GetSBOM: %v", err)
	}
	if read.TotalComponents != 3 {
		t.Errorf("the re-read SBOM counts %d components", read.TotalComponents)
	}
}

// An SBOM whose component cannot be recorded is refused, rather than stored
// short of what it claims.
//
// An SBOM is an attestation of what ships. CreateSBOM used to run each
// component through CreateComponent and `continue` on error, so a component the
// database refused — an unknown component_type, a value too long, a connection
// lost halfway — vanished from the document, and total_components counted only
// what survived. The upload answered 201 with a number nobody could reconcile
// against the build.
func TestAnSBOMThatCannotRecordAComponentIsRefused(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	_, err := r.CreateSBOM(ctx, tenant, &model.CreateSBOMRequest{
		Name: "api-paiement", Version: "2026.4.1",
		Components: []model.CreateComponentRequest{
			{Name: "libpaiement", Version: "1.2.3", ComponentType: "library", Ecosystem: "maven"},
			// component_type carries a CHECK, and this is not one of its values.
			{Name: "libinconnue", Version: "0.0.1", ComponentType: "quelque_chose", Ecosystem: "maven"},
		},
	}, nil)
	if err == nil {
		t.Fatal("an SBOM was stored with a component the database refused")
	}
	if _, total, err := r.ListSBOMs(ctx, tenant, 50, 0); err != nil || total != 0 {
		t.Errorf("%d SBOMs stored after the refusal: %v", total, err)
	}
}

// The same build uploaded twice does not double the inventory.
//
// scs_components carries no unique constraint, so every re-upload of an SBOM
// inserted the same libraries again: the component inventory grew by the size
// of the dependency tree on each CI run, and every count built on it drifted.
func TestTheSameBuildUploadedTwiceDoesNotDoubleTheInventory(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	req := &model.CreateSBOMRequest{
		Name: "api-paiement", Version: "2026.4.1",
		Components: []model.CreateComponentRequest{
			{Name: "libpaiement", Version: "1.2.3", ComponentType: "library", Ecosystem: "maven", IsDirect: true},
			{Name: "libjournal", Version: "0.9.0", ComponentType: "library", Ecosystem: "maven", IsDirect: true},
		},
	}
	if _, err := r.CreateSBOM(ctx, tenant, req, nil); err != nil {
		t.Fatalf("CreateSBOM: %v", err)
	}
	second, err := r.CreateSBOM(ctx, tenant, req, nil)
	if err != nil {
		t.Fatalf("CreateSBOM again: %v", err)
	}
	if second.TotalComponents != 2 {
		t.Errorf("the second SBOM counts %d components", second.TotalComponents)
	}

	_, total, err := r.ListComponents(ctx, tenant, model.ListComponentsFilter{})
	if err != nil {
		t.Fatalf("ListComponents: %v", err)
	}
	if total != 2 {
		t.Errorf("%d components in the inventory after two uploads of the same two, want 2", total)
	}

	// A new version of one of them is a new component, not an update.
	req.Components[0].Version = "1.3.0"
	if _, err := r.CreateSBOM(ctx, tenant, req, nil); err != nil {
		t.Fatalf("CreateSBOM with a bumped version: %v", err)
	}
	if _, total, err := r.ListComponents(ctx, tenant, model.ListComponentsFilter{}); err != nil || total != 3 {
		t.Errorf("%d components after bumping one version, want 3: %v", total, err)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing a caller names lets them attach anything to another customer's
// vendor, or count it against them.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	v := vendor(t, r, mine, "editeur", "software", 1)
	c := component(t, r, mine, "libpaiement", "1.2.3", "maven", &v.ID)
	a, err := r.CreateAssessment(ctx, mine, &model.CreateAssessmentRequest{VendorID: v.ID}, nil)
	if err != nil {
		t.Fatalf("CreateAssessment: %v", err)
	}
	al, err := r.CreateAlert(ctx, mine, &model.CreateAlertRequest{
		VendorID: &v.ID, ComponentID: &c.ID, AlertType: "new_vulnerability",
		Severity: "critical", Title: "CVE-2024-0001",
	})
	if err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	// Reads
	if got, err := r.GetVendor(ctx, theirs, v.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the vendor: %v / %v", got, err)
	}
	if got, err := r.GetComponent(ctx, theirs, c.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the component: %v / %v", got, err)
	}
	if rows, total, err := r.ListVendors(ctx, theirs, model.ListVendorsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d vendors (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListComponents(ctx, theirs, model.ListComponentsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d components (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListAlerts(ctx, theirs, model.ListAlertsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d alerts (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListAssessments(ctx, theirs, v.ID, ""); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assessments: %v", len(rows), err)
	}

	// Writes that name one of our rows
	newName := "volé"
	if got, err := r.UpdateVendor(ctx, theirs, v.ID, &model.UpdateVendorRequest{Name: &newName}); err == nil && got != nil {
		t.Errorf("the neighbour renamed our vendor: %+v", got)
	}
	eol := true
	if got, err := r.UpdateComponent(ctx, theirs, c.ID, &model.UpdateComponentRequest{
		IsEndOfLife: &eol,
	}); err == nil && got != nil {
		t.Errorf("the neighbour declared our component end of life: %+v", got)
	}
	falsePositive := "false_positive"
	if got, err := r.UpdateAlert(ctx, theirs, al.ID, &model.UpdateAlertRequest{
		Status: &falsePositive,
	}); err == nil && got != nil {
		t.Errorf("the neighbour dismissed our alert: %+v", got)
	}
	cancelled := "cancelled"
	if got, err := r.UpdateAssessment(ctx, theirs, a.ID, &model.UpdateAssessmentRequest{
		Status: &cancelled,
	}); err == nil && got != nil {
		t.Errorf("the neighbour cancelled our assessment: %+v", got)
	}

	// Writes that point at one of our rows from their side.
	if got, err := r.CreateAssessment(ctx, theirs, &model.CreateAssessmentRequest{
		VendorID: v.ID, Assessor: "intrus",
	}, nil); err == nil {
		t.Errorf("the neighbour opened an assessment on our vendor: %+v", got)
	}
	if got, err := r.CreateComponent(ctx, theirs, &model.CreateComponentRequest{
		VendorID: &v.ID, Name: "intruse", Version: "1.0.0", ComponentType: "library",
	}); err == nil {
		t.Errorf("the neighbour attributed a component to our vendor: %+v", got)
	}
	if got, err := r.CreateAlert(ctx, theirs, &model.CreateAlertRequest{
		VendorID: &v.ID, AlertType: "vendor_breach", Severity: "critical",
		Title: "diffamation",
	}); err == nil {
		t.Errorf("the neighbour raised a breach alert against our vendor: %+v", got)
	}
	if got, err := r.CreateAlert(ctx, theirs, &model.CreateAlertRequest{
		ComponentID: &c.ID, AlertType: "malicious_package", Severity: "critical",
		Title: "diffamation",
	}); err == nil {
		t.Errorf("the neighbour raised an alert against our component: %+v", got)
	}

	// Our rows are exactly as we left them.
	live, err := r.GetVendor(ctx, mine, v.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the vendor: %v", err)
	}
	if live.Name != "editeur" || live.RiskTier != 1 {
		t.Errorf("our vendor reads %+v", live)
	}
	if live.ComponentCount != 1 {
		t.Errorf("our vendor counts %d components, want the one we recorded", live.ComponentCount)
	}
	if live.AssessmentCount != 1 {
		t.Errorf("our vendor counts %d assessments, want 1", live.AssessmentCount)
	}
	if live.OpenAlertCount != 1 {
		t.Errorf("our vendor counts %d open alerts, want 1", live.OpenAlertCount)
	}
	stats, err := r.GetStats(ctx, mine)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalVendors != 1 || stats.TotalComponents != 1 || stats.OpenAlerts != 1 {
		t.Errorf("our stats read %d vendors / %d components / %d open alerts",
			stats.TotalVendors, stats.TotalComponents, stats.OpenAlerts)
	}
}

// ─── Lists and filters ───────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	soft := vendor(t, r, tenant, "editeur", "software", 1)
	vendor(t, r, tenant, "hebergeur", "cloud", 3)

	component(t, r, tenant, "libpaiement", "1.2.3", "maven", &soft.ID)
	eolComp := component(t, r, tenant, "libvieille", "0.1.0", "npm", &soft.ID)
	yes := true
	one := 1
	if _, err := r.UpdateComponent(ctx, tenant, eolComp.ID, &model.UpdateComponentRequest{
		IsEndOfLife: &yes, HasKnownVulns: &yes, VulnCount: &one, CriticalVulnCount: &one,
	}); err != nil {
		t.Fatalf("UpdateComponent: %v", err)
	}

	for _, c := range []struct {
		name string
		f    model.ListVendorsFilter
		want int
	}{
		{"everything", model.ListVendorsFilter{}, 2},
		{"by tier", model.ListVendorsFilter{RiskTier: 1}, 1},
		{"by risk level", model.ListVendorsFilter{RiskLevel: "medium"}, 1},
		{"by a risk level nothing has", model.ListVendorsFilter{RiskLevel: "low"}, 0},
		{"by status", model.ListVendorsFilter{Status: "active"}, 2},
		{"by a status nothing has", model.ListVendorsFilter{Status: "suspended"}, 0},
	} {
		rows, total, err := r.ListVendors(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListVendors(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	no := false
	for _, c := range []struct {
		name string
		f    model.ListComponentsFilter
		want int
	}{
		{"everything", model.ListComponentsFilter{}, 2},
		{"by ecosystem", model.ListComponentsFilter{Ecosystem: "npm"}, 1},
		{"with vulnerabilities", model.ListComponentsFilter{HasVulns: &yes}, 1},
		{"without vulnerabilities", model.ListComponentsFilter{HasVulns: &no}, 1},
		{"end of life", model.ListComponentsFilter{IsEOL: &yes}, 1},
	} {
		rows, total, err := r.ListComponents(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListComponents(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	for _, sev := range []string{"critical", "high", "low"} {
		if _, err := r.CreateAlert(ctx, tenant, &model.CreateAlertRequest{
			AlertType: "new_vulnerability", Severity: sev, Title: "alerte " + sev,
		}); err != nil {
			t.Fatalf("CreateAlert(%s): %v", sev, err)
		}
	}
	for _, c := range []struct {
		name string
		f    model.ListAlertsFilter
		want int
	}{
		{"everything", model.ListAlertsFilter{}, 3},
		{"by severity", model.ListAlertsFilter{Severity: "critical"}, 1},
		{"by status", model.ListAlertsFilter{Status: "open"}, 3},
		{"by type", model.ListAlertsFilter{AlertType: "new_vulnerability"}, 3},
		{"by a type nothing has", model.ListAlertsFilter{AlertType: "typosquatting"}, 0},
	} {
		rows, total, err := r.ListAlerts(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListAlerts(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalVendors != 2 || stats.TotalComponents != 2 {
		t.Errorf("stats say %d vendors / %d components", stats.TotalVendors, stats.TotalComponents)
	}
	if stats.VulnerableComponents != 1 || stats.EOLComponents != 1 {
		t.Errorf("stats say %d vulnerable / %d end of life", stats.VulnerableComponents, stats.EOLComponents)
	}
	if stats.OpenAlerts != 3 || stats.CriticalAlerts != 1 {
		t.Errorf("stats say %d open alerts / %d critical", stats.OpenAlerts, stats.CriticalAlerts)
	}
	if stats.AlertsBySeverity["critical"] != 1 {
		t.Errorf("the severity breakdown reads %v", stats.AlertsBySeverity)
	}
}

// An overdue assessment is counted as overdue.
func TestAnOverdueAssessmentIsCountedAsOverdue(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	v := vendor(t, r, tenant, "prestataire", "managed_service", 2)

	past := time.Now().Add(-48 * time.Hour)
	future := time.Now().Add(48 * time.Hour)
	if _, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		VendorID: v.ID, DueAt: &past,
	}, nil); err != nil {
		t.Fatalf("CreateAssessment(past): %v", err)
	}
	if _, err := r.CreateAssessment(ctx, tenant, &model.CreateAssessmentRequest{
		VendorID: v.ID, DueAt: &future, AssessmentType: "audit",
	}, nil); err != nil {
		t.Fatalf("CreateAssessment(future): %v", err)
	}

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.PendingAssessments != 2 {
		t.Errorf("%d pending assessments, want 2", stats.PendingAssessments)
	}
	if stats.OverdueAssessments != 1 {
		t.Errorf("%d overdue assessments, want the one past its date", stats.OverdueAssessments)
	}
}

// A fresh tenant gets zeros rather than an error.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	r, _, tenant := repo(t)
	stats, err := r.GetStats(context.Background(), tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalVendors != 0 || stats.TotalComponents != 0 || stats.OpenAlerts != 0 {
		t.Errorf("a tenant with no data reports %+v", stats)
	}
	if stats.AlertsBySeverity == nil || stats.VendorsByTier == nil {
		t.Error("the breakdowns are nil, which serialises as null rather than {}")
	}
}
