package repository

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/dspm/internal/model"
)

// The DSPM repository: the first test this service has ever had.
//
// DSPM is the service that says where a bank's sensitive data is and what is
// wrong with it, so two things have to hold without exception: a finding
// belongs to exactly one customer, and a number on the posture dashboard is
// the number of rows that are really there. A zero that means "the query
// broke" and a zero that means "nothing is exposed" look identical on a
// screen, and this repository has queries whose errors are discarded.

func repo(t *testing.T) (*DSPMRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewDSPMRepository(pool, zerolog.New(io.Discard)), pool, testinfra.NewTenant(t, pool)
}

func store(t *testing.T, r *DSPMRepository, tenant uuid.UUID, name string) *model.DSPMDataStore {
	t.Helper()
	s, err := r.CreateDataStore(context.Background(), tenant, model.CreateDataStoreRequest{
		Name: name, StoreType: "database",
		CloudProvider: "aws", Region: "eu-west-3", Endpoint: "db." + name + ".internal",
		SensitivityLevel: "confidential", DataCategories: []string{"pii", "pci"},
		IsEncrypted: true, IsAccessControlled: true,
		Owner: "DSI", Department: "Production",
	}, nil)
	if err != nil {
		t.Fatalf("CreateDataStore(%s): %v", name, err)
	}
	return s
}

func finding(t *testing.T, r *DSPMRepository, tenant uuid.UUID, storeID uuid.UUID, kind, severity string) *model.DSPMFinding {
	t.Helper()
	f, err := r.CreateFinding(context.Background(), tenant, model.CreateFindingRequest{
		DataStoreID: storeID, FindingType: kind, Severity: severity,
		LocationPath: "public.clients", LocationField: "numero_carte",
		RecordCount: 12000, Title: "Données de carte en clair",
		Description: "Colonne non chiffrée", Evidence: "4970 ** ** 1234",
		Remediation: "Chiffrer la colonne", ComplianceViolations: []string{"pci_req3"},
	})
	if err != nil {
		t.Fatalf("CreateFinding(%s/%s): %v", kind, severity, err)
	}
	return f
}

// ─── The write paths ─────────────────────────────────────────────────────────

// A scan job can be created, read back and listed.
//
// All three were broken: error_message and duration_seconds are nullable with
// no default, and a job that has just started has neither — so the three
// queries that return them raw into a Go string and a Go int failed with
// "cannot scan NULL" on every call. The whole scan-job surface of this service
// answered 500.
func TestAScanJobCanBeCreatedReadAndListed(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	ds := store(t, r, tenant, "cbs-prod")

	job, err := r.CreateScanJob(ctx, tenant, model.CreateScanJobRequest{
		DataStoreID: ds.ID, ScanType: "classification", TriggeredBy: "manual",
	})
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if job.Status != "pending" && job.Status != "running" {
		t.Errorf("a fresh job is %q", job.Status)
	}
	if job.ErrorMessage != "" {
		t.Errorf("a fresh job carries the error %q", job.ErrorMessage)
	}
	if job.DurationSeconds != 0 {
		t.Errorf("a fresh job lasted %d seconds", job.DurationSeconds)
	}
	if job.TriggeredBy != "manual" {
		t.Errorf("triggered_by is %q", job.TriggeredBy)
	}

	got, err := r.GetScanJob(ctx, tenant, job.ID)
	if err != nil {
		t.Fatalf("GetScanJob: %v", err)
	}
	if got == nil || got.ID != job.ID {
		t.Fatalf("GetScanJob gave %+v", got)
	}

	jobs, err := r.ListScanJobs(ctx, tenant, ds.ID)
	if err != nil {
		t.Fatalf("ListScanJobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("ListScanJobs gave %d jobs", len(jobs))
	}

	// Finishing the job fills in what was NULL, and the duration is computed
	// rather than left to the caller.
	done, err := r.UpdateScanJob(ctx, tenant, job.ID, model.UpdateScanJobRequest{
		Status: strp("completed"), FindingsCount: intp(7),
		SensitiveFindingsCount: intp(3), ScannedObjects: intp(4200),
	})
	if err != nil {
		t.Fatalf("UpdateScanJob: %v", err)
	}
	if done.Status != "completed" {
		t.Errorf("status is %q", done.Status)
	}
	if done.FindingsCount != 7 || done.SensitiveFindingsCount != 3 || done.ScannedObjects != 4200 {
		t.Errorf("the counts are %d/%d/%d", done.FindingsCount, done.SensitiveFindingsCount, done.ScannedObjects)
	}
	if done.CompletedAt == nil {
		t.Error("a completed job has no completion time")
	}
}

// Every nullable column, left NULL, reads back — on the store, the finding, the
// policy and the remediation item alike.
func TestEveryNullableColumnReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// A store with no provider, no region, no endpoint, no owner, no notes.
	bare, err := r.CreateDataStore(ctx, tenant, model.CreateDataStoreRequest{
		Name: "partage-rh", StoreType: "file_share",
	}, nil)
	if err != nil {
		t.Fatalf("CreateDataStore with nothing optional: %v", err)
	}
	if got, err := r.GetDataStore(ctx, tenant, bare.ID); err != nil || got == nil {
		t.Fatalf("GetDataStore: %+v / %v", got, err)
	}
	if rows, total, err := r.ListDataStores(ctx, tenant, model.ListDataStoresFilter{Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListDataStores gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A finding with no location, no description, no evidence, no remediation.
	f, err := r.CreateFinding(ctx, tenant, model.CreateFindingRequest{
		DataStoreID: bare.ID, FindingType: "pii", Severity: "high",
		Title: "Données personnelles non classifiées",
	})
	if err != nil {
		t.Fatalf("CreateFinding with nothing optional: %v", err)
	}
	if f.ResolvedAt != nil {
		t.Error("a fresh finding is already resolved")
	}
	if got, err := r.GetFinding(ctx, tenant, f.ID); err != nil || got == nil {
		t.Fatalf("GetFinding: %+v / %v", got, err)
	}
	if rows, total, err := r.ListFindings(ctx, tenant, model.ListFindingsFilter{Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListFindings gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A policy with no description.
	p, err := r.CreatePolicy(ctx, tenant, model.CreatePolicyRequest{
		Name: "Chiffrement au repos", PolicyType: "encryption",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePolicy with no description: %v", err)
	}
	if got, err := r.GetPolicy(ctx, tenant, p.ID); err != nil || got == nil {
		t.Fatalf("GetPolicy: %+v / %v", got, err)
	}
	if rows, err := r.ListPolicies(ctx, tenant); err != nil || len(rows) != 1 {
		t.Fatalf("ListPolicies gave %d rows: %v", len(rows), err)
	}

	// A remediation item with no assignee, no due date, no notes.
	item, err := r.CreateRemediationItem(ctx, tenant, model.CreateRemediationRequest{
		FindingID: f.ID, Priority: "high",
	})
	if err != nil {
		t.Fatalf("CreateRemediationItem with nothing optional: %v", err)
	}
	if item.AssigneeID != nil || item.DueDate != nil {
		t.Errorf("the item came back assigned: %v / %v", item.AssigneeID, item.DueDate)
	}
	if got, err := r.GetRemediationItem(ctx, tenant, item.ID); err != nil || got == nil {
		t.Fatalf("GetRemediationItem: %+v / %v", got, err)
	}
	if rows, err := r.ListRemediationItems(ctx, tenant, f.ID); err != nil || len(rows) != 1 {
		t.Fatalf("ListRemediationItems gave %d rows: %v", len(rows), err)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing one tenant wrote is reachable by another. In this service that is the
// difference between a data-protection report and a data breach.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	ds := store(t, r, mine, "cbs-prod")
	f := finding(t, r, mine, ds.ID, "pci_data", "critical")
	job, err := r.CreateScanJob(ctx, mine, model.CreateScanJobRequest{
		DataStoreID: ds.ID, ScanType: "full", TriggeredBy: "scheduled",
	})
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	pol, err := r.CreatePolicy(ctx, mine, model.CreatePolicyRequest{
		Name: "Résidence des données", PolicyType: "data_residency",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	item, err := r.CreateRemediationItem(ctx, mine, model.CreateRemediationRequest{
		FindingID: f.ID, Priority: "critical",
	})
	if err != nil {
		t.Fatalf("CreateRemediationItem: %v", err)
	}

	// Reads
	if got, err := r.GetDataStore(ctx, theirs, ds.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the data store: %v / %v", got, err)
	}
	if got, err := r.GetFinding(ctx, theirs, f.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the finding: %v / %v", got, err)
	}
	if got, err := r.GetScanJob(ctx, theirs, job.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the scan job: %v / %v", got, err)
	}
	if got, err := r.GetPolicy(ctx, theirs, pol.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the policy: %v / %v", got, err)
	}
	if got, err := r.GetRemediationItem(ctx, theirs, item.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the remediation item: %v / %v", got, err)
	}
	if rows, total, err := r.ListDataStores(ctx, theirs, model.ListDataStoresFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d stores (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListFindings(ctx, theirs, model.ListFindingsFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d findings (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListScanJobs(ctx, theirs, ds.ID); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d scan jobs: %v", len(rows), err)
	}
	if rows, err := r.ListPolicies(ctx, theirs); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d policies: %v", len(rows), err)
	}
	if rows, err := r.ListRemediationItems(ctx, theirs, f.ID); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d remediation items: %v", len(rows), err)
	}

	// Writes
	if got, err := r.UpdateDataStore(ctx, theirs, ds.ID, model.UpdateDataStoreRequest{Name: strp("volé")}); err != nil || got != nil {
		t.Errorf("the neighbour renamed the data store: %v / %v", got, err)
	}
	if got, err := r.UpdateFinding(ctx, theirs, f.ID, model.UpdateFindingRequest{Status: strp("false_positive")}); err != nil || got != nil {
		t.Errorf("the neighbour dismissed the finding: %v / %v", got, err)
	}
	if got, err := r.UpdateScanJob(ctx, theirs, job.ID, model.UpdateScanJobRequest{Status: strp("cancelled")}); err != nil || got != nil {
		t.Errorf("the neighbour cancelled the scan: %v / %v", got, err)
	}
	if got, err := r.UpdatePolicy(ctx, theirs, pol.ID, model.UpdatePolicyRequest{IsActive: boolp(false)}); err != nil || got != nil {
		t.Errorf("the neighbour disabled the policy: %v / %v", got, err)
	}
	if got, err := r.UpdateRemediationItem(ctx, theirs, item.ID, model.UpdateRemediationRequest{Status: strp("wont_fix")}); err != nil || got != nil {
		t.Errorf("the neighbour closed the remediation item: %v / %v", got, err)
	}
	if err := r.DeleteDataStore(ctx, theirs, ds.ID); err == nil {
		t.Error("the neighbour deleted the data store")
	}
	if err := r.DeletePolicy(ctx, theirs, pol.ID); err == nil {
		t.Error("the neighbour deleted the policy")
	}

	// And nothing moved.
	again, err := r.GetFinding(ctx, mine, f.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if again == nil {
		t.Fatal("the finding is gone")
	}
	if again.Status != "open" {
		t.Errorf("the finding is %q — the neighbour's dismissal landed", again.Status)
	}
	if ours, err := r.GetDataStore(ctx, mine, ds.ID); err != nil || ours == nil || ours.Name != "cbs-prod" {
		t.Errorf("the data store is %+v", ours)
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

// The posture statistics, against known rows. Every count here is produced by
// a query whose error the code discards, so a wrong number is the only symptom
// a broken one would ever have.
func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	// Two stores, one of them unencrypted.
	encrypted := store(t, r, tenant, "cbs-prod")
	clear, err := r.CreateDataStore(ctx, tenant, model.CreateDataStoreRequest{
		Name: "sauvegardes", StoreType: "object_storage",
		SensitivityLevel: "restricted", IsEncrypted: false,
	}, nil)
	if err != nil {
		t.Fatalf("CreateDataStore: %v", err)
	}

	// Findings: a critical PCI one, a high PII one, and a medium one already
	// remediated — which must stop counting as open.
	finding(t, r, tenant, encrypted.ID, "pci_data", "critical")
	finding(t, r, tenant, clear.ID, "pii", "high")
	fixed := finding(t, r, tenant, clear.ID, "credentials", "medium")
	if got, err := r.UpdateFinding(ctx, tenant, fixed.ID, model.UpdateFindingRequest{
		Status: strp("remediated"), ResolvedBy: strp("équipe données"),
	}); err != nil || got == nil {
		t.Fatalf("UpdateFinding: %+v / %v", got, err)
	}

	// Two scans, one still running.
	if _, err := r.CreateScanJob(ctx, tenant, model.CreateScanJobRequest{
		DataStoreID: encrypted.ID, ScanType: "discovery", TriggeredBy: "manual",
	}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	finished, err := r.CreateScanJob(ctx, tenant, model.CreateScanJobRequest{
		DataStoreID: clear.ID, ScanType: "full", TriggeredBy: "scheduled",
	})
	if err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if _, err := r.UpdateScanJob(ctx, tenant, finished.ID, model.UpdateScanJobRequest{
		Status: strp("completed"),
	}); err != nil {
		t.Fatalf("UpdateScanJob: %v", err)
	}

	// Two remediation items, one of them overdue.
	open, err := r.GetFinding(ctx, tenant, fixed.ID)
	if err != nil || open == nil {
		t.Fatalf("GetFinding: %v", err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if _, err := r.CreateRemediationItem(ctx, tenant, model.CreateRemediationRequest{
		FindingID: open.ID, Priority: "high", DueDate: &past,
	}); err != nil {
		t.Fatalf("CreateRemediationItem: %v", err)
	}
	future := time.Now().Add(48 * time.Hour)
	if _, err := r.CreateRemediationItem(ctx, tenant, model.CreateRemediationRequest{
		FindingID: open.ID, Priority: "low", DueDate: &future,
	}); err != nil {
		t.Fatalf("CreateRemediationItem: %v", err)
	}

	// The neighbour's rows, which must change nothing below.
	nb := store(t, r, other, "voisine-db")
	finding(t, r, other, nb.ID, "pci_data", "critical")

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_data_stores", stats.TotalDataStores, 2},
		{"unencrypted_stores", stats.UnencryptedStores, 1},
		{"total_findings", stats.TotalFindings, 3},
		{"open_findings", stats.OpenFindings, 2},
		{"critical_findings", stats.CriticalFindings, 1},
		{"pii_exposures", stats.PIIExposures, 1},
		{"pci_exposures", stats.PCIExposures, 1},
		{"total_scans", stats.TotalScans, 2},
		{"active_scans", stats.ActiveScans, 1},
		{"open_remediations", stats.OpenRemediations, 2},
		{"overdue_remediations", stats.OverdueRemediations, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if stats.StoresByType["database"] != 1 || stats.StoresByType["object_storage"] != 1 {
		t.Errorf("stores by type is %v", stats.StoresByType)
	}
	if stats.FindingsBySeverity["critical"] != 1 || stats.FindingsBySeverity["high"] != 1 {
		t.Errorf("findings by severity is %v", stats.FindingsBySeverity)
	}
}

// A tenant with nothing gets zeros and empty maps rather than an error. The
// aggregate query is a FROM over no rows, which is the shape that breaks a
// scan into a non-nullable Go type — and it is every customer's first screen.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats on an empty tenant: %v", err)
	}
	if stats.TotalDataStores != 0 || stats.TotalFindings != 0 || stats.OpenRemediations != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	for name, m := range map[string]map[string]int{
		"stores_by_type":       stats.StoresByType,
		"stores_by_risk":       stats.StoresByRisk,
		"findings_by_type":     stats.FindingsByType,
		"findings_by_severity": stats.FindingsBySeverity,
	} {
		if m == nil {
			t.Errorf("%s came back nil rather than empty", name)
		}
	}
	if stats.TopRiskyStores == nil || stats.RecentFindings == nil {
		t.Error("the lists came back nil rather than empty")
	}
}

// ─── Filters, cascades and risk ──────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	db := store(t, r, tenant, "cbs-prod")
	bucket, err := r.CreateDataStore(ctx, tenant, model.CreateDataStoreRequest{
		Name: "sauvegardes", StoreType: "object_storage",
		SensitivityLevel: "public", Department: "Infra", IsEncrypted: false,
	}, nil)
	if err != nil {
		t.Fatalf("CreateDataStore: %v", err)
	}

	yes, no := true, false
	for _, c := range []struct {
		what   string
		filter model.ListDataStoresFilter
		want   int
	}{
		{"no filter", model.ListDataStoresFilter{Limit: 50}, 2},
		{"by type", model.ListDataStoresFilter{StoreType: "database", Limit: 50}, 1},
		{"by sensitivity", model.ListDataStoresFilter{SensitivityLevel: "public", Limit: 50}, 1},
		{"encrypted only", model.ListDataStoresFilter{IsEncrypted: &yes, Limit: 50}, 1},
		{"unencrypted only", model.ListDataStoresFilter{IsEncrypted: &no, Limit: 50}, 1},
		{"by department", model.ListDataStoresFilter{Department: "Infra", Limit: 50}, 1},
		{"by a department nobody has", model.ListDataStoresFilter{Department: "Mars", Limit: 50}, 0},
	} {
		rows, total, err := r.ListDataStores(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListDataStores %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	finding(t, r, tenant, db.ID, "pci_data", "critical")
	finding(t, r, tenant, bucket.ID, "pii", "low")

	for _, c := range []struct {
		what   string
		filter model.ListFindingsFilter
		want   int
	}{
		{"all", model.ListFindingsFilter{Limit: 50}, 2},
		{"on one store", model.ListFindingsFilter{DataStoreID: &db.ID, Limit: 50}, 1},
		{"by type", model.ListFindingsFilter{FindingType: "pii", Limit: 50}, 1},
		{"by severity", model.ListFindingsFilter{Severity: "critical", Limit: 50}, 1},
		{"by status", model.ListFindingsFilter{Status: "open", Limit: 50}, 2},
		{"by a status nothing is in", model.ListFindingsFilter{Status: "accepted_risk", Limit: 50}, 0},
	} {
		rows, total, err := r.ListFindings(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListFindings %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
}

// Deleting a data store takes its findings and its scan jobs with it: a finding
// about a store that no longer exists keeps appearing on the dashboard and
// nobody can act on it.
func TestDeletingAStoreTakesItsFindingsAndScans(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	ds := store(t, r, tenant, "cbs-prod")
	finding(t, r, tenant, ds.ID, "pii", "high")
	if _, err := r.CreateScanJob(ctx, tenant, model.CreateScanJobRequest{
		DataStoreID: ds.ID, ScanType: "discovery", TriggeredBy: "manual",
	}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	if err := r.DeleteDataStore(ctx, tenant, ds.ID); err != nil {
		t.Fatalf("DeleteDataStore: %v", err)
	}
	if _, total, err := r.ListFindings(ctx, tenant, model.ListFindingsFilter{Limit: 50}); err != nil || total != 0 {
		t.Errorf("%d findings survive their store: %v", total, err)
	}
	if jobs, err := r.ListScanJobs(ctx, tenant, ds.ID); err != nil || len(jobs) != 0 {
		t.Errorf("%d scan jobs survive their store: %v", len(jobs), err)
	}
	if err := r.DeleteDataStore(ctx, tenant, ds.ID); err == nil {
		t.Error("deleting the store twice reported success")
	}
}

// The risk score is a property of the posture, not of the row: an unencrypted
// store holding restricted data must score worse than an encrypted one holding
// internal data, whatever the order the rows were written in.
func TestTheRiskScoreFollowsThePosture(t *testing.T) {
	for _, c := range []struct {
		what                                string
		sensitivity                         string
		encrypted, accessControlled, public bool
		openFindings                        int
		atLeast                             int
	}{
		{"internal, encrypted, controlled", "internal", true, true, false, 0, 0},
		{"restricted, unencrypted", "restricted", false, true, false, 0, 20},
		{"top secret, unencrypted, public", "top_secret", false, false, true, 5, 70},
	} {
		got := dataStoreRiskScore(c.sensitivity, c.encrypted, c.accessControlled, c.public, c.openFindings)
		if got < c.atLeast {
			t.Errorf("%s scores %d, want at least %d", c.what, got, c.atLeast)
		}
		if got > 100 {
			t.Errorf("%s scores %d, above the ceiling", c.what, got)
		}
		level := riskLevelFromScore(got)
		if level == "" {
			t.Errorf("%s has no risk level", c.what)
		}
	}

	// The two must agree at every boundary, or a store is shown as high risk in
	// one column and medium in the next.
	for _, c := range []struct {
		score int
		want  string
	}{
		{0, "low"}, {24, "low"}, {25, "medium"}, {49, "medium"},
		{50, "high"}, {74, "high"}, {75, "critical"}, {100, "critical"},
	} {
		if got := riskLevelFromScore(c.score); got != c.want {
			t.Errorf("riskLevelFromScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func strp(s string) *string { return &s }
func intp(n int) *int       { return &n }
func boolp(b bool) *bool    { return &b }
