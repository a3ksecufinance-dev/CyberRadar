package repository

import (
	"context"
	"testing"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/ot/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The OT repository against a real PostgreSQL.
//
// This domain inventories the plant: programmable controllers, their
// vulnerabilities, the patches queued for the next maintenance window. Almost
// every write names an asset the caller chose, and the row written carries the
// caller's own tenant_id — so the asset identifier is the thing that has to be
// checked, not the tenant on the insert.
//
// The other thing only a database shows here is the published risk formula.
// It is written down in assetRiskScore, and the question a test can answer is
// whether the number stored on the asset follows it as vulnerabilities are
// raised and closed.

func repo(t *testing.T) (*OTRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewOTRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func asset(t *testing.T, r *OTRepository, tenant uuid.UUID, name, assetType, crit string, purdue int, internetFacing bool) *model.OTAsset {
	t.Helper()
	a, err := r.CreateAsset(context.Background(), tenant, &model.CreateAssetRequest{
		Name: name, Description: "Équipement de test", AssetType: assetType,
		Vendor: "Siemens", Model: "S7-1500", FirmwareVersion: "2.9.2",
		SerialNumber: "SN-" + name, IPAddress: "10.20.0.5", MACAddress: "00:1b:1b:00:00:01",
		Protocol: []string{"Modbus", "OPC-UA"}, Site: "Usine de Lyon", Zone: "Cellule 3",
		PurdueLevel: purdue, Criticality: crit, IsInternetFacing: internetFacing,
		Tags: []string{"production"}, Metadata: map[string]any{"ligne": "L2"},
	}, nil)
	if err != nil {
		t.Fatalf("CreateAsset(%s): %v", name, err)
	}
	return a
}

func zone(t *testing.T, r *OTRepository, tenant uuid.UUID, name, zoneType string, purdue int) *model.OTZone {
	t.Helper()
	z, err := r.CreateZone(context.Background(), tenant, &model.CreateZoneRequest{
		Name: name, Description: "Zone de test", ZoneType: zoneType,
		PurdueLevel: purdue, Site: "Usine de Lyon", FirewallPresent: true,
		NetworkRanges: []string{"10.20.0.0/24"},
	}, nil)
	if err != nil {
		t.Fatalf("CreateZone(%s): %v", name, err)
	}
	return z
}

func vuln(t *testing.T, r *OTRepository, tenant uuid.UUID, assetID uuid.UUID, cve, severity string) *model.OTVulnerability {
	t.Helper()
	v, err := r.CreateVulnerability(context.Background(), tenant, &model.CreateVulnerabilityRequest{
		AssetID: assetID, CVEID: cve, Title: "Faille " + cve, Severity: severity,
		AffectsAvailability: true, AffectsSafety: severity == "critical",
		Tags: []string{"ics"},
	})
	if err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", cve, err)
	}
	return v
}

// ─── The round trip ──────────────────────────────────────────────────────────

// Each of the six writes, with nothing optional given.
func TestEverythingWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	a, err := r.CreateAsset(ctx, tenant, &model.CreateAssetRequest{
		Name: "API-L2-01", AssetType: "plc",
	}, nil)
	if err != nil {
		t.Fatalf("CreateAsset with nothing optional: %v", err)
	}
	if a.Criticality != "medium" {
		t.Errorf("criticality is %q, want the repository's default", a.Criticality)
	}
	if !a.IsActive || a.IsPatched {
		t.Errorf("the asset defaults read %+v", a)
	}
	if a.Protocol == nil || a.Tags == nil {
		t.Error("protocol or tags is nil, which serialises as null rather than []")
	}
	if a.InstallDate != nil || a.EndOfLifeDate != nil || a.LastPatchedAt != nil {
		t.Errorf("a date was invented: %+v", a)
	}

	z, err := r.CreateZone(ctx, tenant, &model.CreateZoneRequest{
		Name: "Cellule 3", ZoneType: "control",
	}, nil)
	if err != nil {
		t.Fatalf("CreateZone with nothing optional: %v", err)
	}
	if z.NetworkRanges == nil {
		t.Error("network_ranges is nil")
	}

	v, err := r.CreateVulnerability(ctx, tenant, &model.CreateVulnerabilityRequest{
		AssetID: a.ID, Title: "Firmware obsolète", Severity: "high",
	})
	if err != nil {
		t.Fatalf("CreateVulnerability with nothing optional: %v", err)
	}
	if v.Status != "open" {
		t.Errorf("a fresh vulnerability is %q", v.Status)
	}
	if v.CVEID != "" || v.ICSCertID != "" || v.Workaround != "" {
		t.Errorf("an optional field came back filled: %+v", v)
	}
	if v.CVSSScore != nil {
		t.Errorf("cvss_score is %v, want NULL when none was given", *v.CVSSScore)
	}

	e, err := r.CreateEvent(ctx, tenant, &model.CreateEventRequest{
		EventType: "unauthorized_access", Severity: "critical",
		Title: "Accès non autorisé à l'automate",
	})
	if err != nil {
		t.Fatalf("CreateEvent with nothing optional: %v", err)
	}
	if e.Status != "open" || e.AssetID != nil || e.ZoneID != nil {
		t.Errorf("the event reads back as %+v", e)
	}

	p, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "Pas d'écriture depuis le niveau 3", PolicyType: "zone_isolation",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePolicy with nothing optional: %v", err)
	}
	if p.Scope != "global" || p.Action != "alert" || !p.IsActive {
		t.Errorf("the policy defaults read %+v", p)
	}
	if p.Rule == nil {
		t.Error("rule is nil, which serialises as null rather than {}")
	}

	pa, err := r.CreatePatch(ctx, tenant, &model.CreatePatchRequest{
		AssetID: a.ID, Title: "Firmware 2.9.7",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePatch with nothing optional: %v", err)
	}
	if pa.Status != "pending" || pa.PatchType != "firmware" {
		t.Errorf("the patch defaults read %+v", pa)
	}
	if pa.CVEIDs == nil {
		t.Error("cve_ids is nil")
	}

	c, err := r.CreateCommunication(ctx, tenant, &model.CreateCommunicationRequest{
		SrcAssetID: &a.ID, SrcZoneID: &z.ID, Protocol: "Modbus", Port: 502,
	})
	if err != nil {
		t.Fatalf("CreateCommunication with nothing optional: %v", err)
	}
	if c.Direction != "bidirectional" {
		t.Errorf("direction is %q, want the repository's default", c.Direction)
	}
	if c.DstAssetID != nil || c.DstZoneID != nil {
		t.Errorf("the communication invented a destination: %+v", c)
	}
}

// The risk score on an asset follows the published formula, and it comes back
// down when the vulnerabilities are closed.
func TestTheAssetRiskFollowsItsVulnerabilities(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// criticality critical (40) + internet facing (25) + Purdue 1 (15) = 80
	a := asset(t, r, tenant, "API-L2-01", "plc", "critical", 1, true)
	if a.RiskScore != 80 || a.RiskLevel != "critical" {
		t.Fatalf("a fresh asset scores %d (%s), want 80 (critical)", a.RiskScore, a.RiskLevel)
	}

	// Two open vulnerabilities: 80 + 2×3, capped at 100 — here 86.
	v1 := vuln(t, r, tenant, a.ID, "CVE-2024-0001", "critical")
	vuln(t, r, tenant, a.ID, "CVE-2024-0002", "high")

	live, err := r.GetAsset(ctx, tenant, a.ID)
	if err != nil || live == nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if live.RiskScore != 86 {
		t.Errorf("after two vulnerabilities the asset scores %d, want 86", live.RiskScore)
	}
	if live.VulnCount != 2 {
		t.Errorf("the asset shows %d open vulnerabilities, want 2", live.VulnCount)
	}

	// Closing one brings the score back down. The remediation is the whole
	// point of recording the vulnerability.
	patched := "patched"
	if _, err := r.UpdateVulnerability(ctx, tenant, v1.ID, &model.UpdateVulnerabilityRequest{
		Status: &patched,
	}); err != nil {
		t.Fatalf("UpdateVulnerability: %v", err)
	}
	live, err = r.GetAsset(ctx, tenant, a.ID)
	if err != nil || live == nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if live.RiskScore != 83 {
		t.Errorf("after patching one of two the asset scores %d, want 83", live.RiskScore)
	}
	if live.VulnCount != 1 {
		t.Errorf("the asset still shows %d open vulnerabilities", live.VulnCount)
	}

	// A low-exposure asset scores low: medium (10) + Purdue 4 (0) = 10.
	quiet := asset(t, r, tenant, "IHM-bureau", "hmi", "medium", 4, false)
	if quiet.RiskScore != 10 || quiet.RiskLevel != "low" {
		t.Errorf("the quiet asset scores %d (%s), want 10 (low)", quiet.RiskScore, quiet.RiskLevel)
	}
}

// A remediated vulnerability records when, and an acknowledged event records
// by whom.
func TestClosingAVulnerabilityAndAnEventKeepsTheTrace(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a := asset(t, r, tenant, "API-L2-01", "plc", "high", 2, false)
	v := vuln(t, r, tenant, a.ID, "CVE-2024-0001", "critical")

	patched := "patched"
	notes := "Correctif appliqué pendant la fenêtre du 12"
	done, err := r.UpdateVulnerability(ctx, tenant, v.ID, &model.UpdateVulnerabilityRequest{
		Status: &patched, PatchNotes: &notes,
	})
	if err != nil || done == nil {
		t.Fatalf("UpdateVulnerability: %v", err)
	}
	if done.Status != "patched" {
		t.Errorf("status is %q", done.Status)
	}
	if done.RemediatedAt == nil {
		t.Error("a remediated vulnerability carries no date")
	}
	if done.PatchNotes != notes {
		t.Errorf("patch_notes reads %q", done.PatchNotes)
	}
	if done.CVEID != "CVE-2024-0001" || done.Title == "" {
		t.Errorf("the update lost a field it did not name: %+v", done)
	}

	e, err := r.CreateEvent(ctx, tenant, &model.CreateEventRequest{
		AssetID: &a.ID, EventType: "unauthorized_access", Severity: "high",
		Title: "Écriture Modbus inattendue", SourceIP: "10.20.0.99",
		DetectedBy: "sonde-lyon-1", DetectionRule: "MODBUS-WRITE-OUTSIDE-WINDOW",
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	ack := "acknowledged"
	who := "jdupont"
	taken, err := r.UpdateEvent(ctx, tenant, e.ID, &model.UpdateEventRequest{
		Status: &ack, AcknowledgedBy: &who,
	})
	if err != nil || taken == nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	if taken.Status != "acknowledged" || taken.AcknowledgedBy != who {
		t.Errorf("the event reads %+v", taken)
	}
	if taken.AcknowledgedAt == nil {
		t.Error("an acknowledged event carries no date")
	}
	if taken.ResolvedAt != nil {
		t.Error("an acknowledged event already carries a resolution date")
	}
}

// A patch is scheduled and then applied.
func TestAPatchIsScheduledThenApplied(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a := asset(t, r, tenant, "API-L2-01", "plc", "high", 2, false)

	p, err := r.CreatePatch(ctx, tenant, &model.CreatePatchRequest{
		AssetID: a.ID, PatchType: "firmware", Title: "Firmware 2.9.7",
		VersionBefore: "2.9.2", VersionAfter: "2.9.7",
		CVEIDs: []string{"CVE-2024-0001"}, RiskLevel: "high",
		RequiresDowntime: true, MaintenanceWindow: "Samedi 02:00-06:00 UTC",
		RollbackPlan: "Retour au 2.9.2 depuis la carte SD",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePatch: %v", err)
	}
	if p.Status != "pending" || !p.RequiresDowntime {
		t.Errorf("the patch reads %+v", p)
	}

	applied := "applied"
	by := "equipe-automatisme"
	done, err := r.UpdatePatch(ctx, tenant, p.ID, &model.UpdatePatchRequest{
		Status: &applied, AppliedBy: &by,
	})
	if err != nil || done == nil {
		t.Fatalf("UpdatePatch: %v", err)
	}
	if done.Status != "applied" || done.AppliedBy != by {
		t.Errorf("the applied patch reads %+v", done)
	}
	if done.AppliedAt == nil {
		t.Error("an applied patch carries no date")
	}
	if len(done.CVEIDs) != 1 || done.RollbackPlan == "" {
		t.Errorf("the update lost a field it did not name: %+v", done)
	}

	patches, err := r.ListPatches(ctx, tenant, &a.ID, "applied")
	if err != nil {
		t.Fatalf("ListPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Errorf("%d applied patches for the asset, want 1", len(patches))
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing a caller names lets them attach anything to another customer's
// plant, or count it against them.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Usine voisine")

	a := asset(t, r, mine, "API-L2-01", "plc", "critical", 1, true)
	z := zone(t, r, mine, "Cellule 3", "control", 1)
	v := vuln(t, r, mine, a.ID, "CVE-2024-0001", "critical")
	e, err := r.CreateEvent(ctx, mine, &model.CreateEventRequest{
		AssetID: &a.ID, EventType: "unauthorized_access", Severity: "high",
		Title: "Écriture Modbus inattendue",
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	p, err := r.CreatePatch(ctx, mine, &model.CreatePatchRequest{
		AssetID: a.ID, Title: "Firmware 2.9.7",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePatch: %v", err)
	}

	// Reads
	if got, err := r.GetAsset(ctx, theirs, a.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the asset: %v / %v", got, err)
	}
	if rows, total, err := r.ListAssets(ctx, theirs, model.ListAssetsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assets (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListZones(ctx, theirs, ""); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d zones: %v", len(rows), err)
	}
	if rows, total, err := r.ListVulnerabilities(ctx, theirs, model.ListVulnsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d vulnerabilities (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListEvents(ctx, theirs, model.ListEventsFilter{}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d events (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListPatches(ctx, theirs, nil, ""); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d patches: %v", len(rows), err)
	}
	if rows, err := r.ListCommunications(ctx, theirs, false); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d communications: %v", len(rows), err)
	}

	// Writes that name one of our rows
	// An update that matches no row of the caller's reports pgx.ErrNoRows,
	// which httperr turns into a 404. What matters is that nothing is written
	// and nothing is handed back — a pointer to a zero-filled record would be
	// read by a caller that tests the pointer rather than the error.
	newName := "volé"
	if got, err := r.UpdateAsset(ctx, theirs, a.ID, &model.UpdateAssetRequest{Name: &newName}); err == nil || got != nil {
		t.Errorf("the neighbour renamed our asset: %v / %v", got, err)
	}
	if got, err := r.UpdateZone(ctx, theirs, z.ID, &model.UpdateZoneRequest{Name: &newName}); err == nil || got != nil {
		t.Errorf("the neighbour renamed our zone: %v / %v", got, err)
	}
	falsePositive := "false_positive"
	if got, err := r.UpdateVulnerability(ctx, theirs, v.ID, &model.UpdateVulnerabilityRequest{
		Status: &falsePositive,
	}); err == nil || got != nil {
		t.Errorf("the neighbour dismissed our vulnerability: %v / %v", got, err)
	}
	resolved := "resolved"
	if got, err := r.UpdateEvent(ctx, theirs, e.ID, &model.UpdateEventRequest{
		Status: &resolved,
	}); err == nil || got != nil {
		t.Errorf("the neighbour closed our event: %v / %v", got, err)
	}
	applied := "applied"
	if got, err := r.UpdatePatch(ctx, theirs, p.ID, &model.UpdatePatchRequest{
		Status: &applied,
	}); err == nil || got != nil {
		t.Errorf("the neighbour marked our patch applied: %v / %v", got, err)
	}

	// Writes that point at one of our assets or zones from their side. Each
	// row would carry their tenant, so the identifier is what must be refused:
	// a vulnerability or an event attached to our controller is counted on it,
	// and a patch queued against it claims a maintenance window on our plant.
	if got, err := r.CreateVulnerability(ctx, theirs, &model.CreateVulnerabilityRequest{
		AssetID: a.ID, Title: "faille inventée", Severity: "critical",
	}); err == nil {
		t.Errorf("the neighbour attached a vulnerability to our controller: %+v", got)
	}
	if got, err := r.CreatePatch(ctx, theirs, &model.CreatePatchRequest{
		AssetID: a.ID, Title: "correctif imposé",
	}, nil); err == nil {
		t.Errorf("the neighbour queued a patch on our controller: %+v", got)
	}
	if got, err := r.CreateEvent(ctx, theirs, &model.CreateEventRequest{
		AssetID: &a.ID, EventType: "unauthorized_access", Severity: "low",
		Title: "bruit",
	}); err == nil {
		t.Errorf("the neighbour attached an event to our controller: %+v", got)
	}
	if got, err := r.CreateEvent(ctx, theirs, &model.CreateEventRequest{
		ZoneID: &z.ID, EventType: "unauthorized_access", Severity: "low",
		Title: "bruit",
	}); err == nil {
		t.Errorf("the neighbour attached an event to our zone: %+v", got)
	}
	if got, err := r.CreateCommunication(ctx, theirs, &model.CreateCommunicationRequest{
		SrcAssetID: &a.ID, Protocol: "Modbus", Port: 502,
	}); err == nil {
		t.Errorf("the neighbour recorded a flow from our controller: %+v", got)
	}
	if got, err := r.CreateCommunication(ctx, theirs, &model.CreateCommunicationRequest{
		SrcZoneID: &z.ID, Protocol: "Modbus", Port: 502,
	}); err == nil {
		t.Errorf("the neighbour recorded a flow from our zone: %+v", got)
	}

	// Our asset's counts are our own rows, and nobody else's.
	live, err := r.GetAsset(ctx, mine, a.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the asset: %v", err)
	}
	if live.Name != "API-L2-01" {
		t.Errorf("our asset is named %q", live.Name)
	}
	if live.VulnCount != 1 {
		t.Errorf("our asset shows %d open vulnerabilities, want the one we raised", live.VulnCount)
	}
	if live.EventCount != 1 {
		t.Errorf("our asset shows %d open events, want the one we raised", live.EventCount)
	}
	if live.RiskScore != 83 {
		t.Errorf("our asset scores %d, want 83 — one open vulnerability of ours", live.RiskScore)
	}
	liveVuln, _, err := r.ListVulnerabilities(ctx, mine, model.ListVulnsFilter{Status: "open"})
	if err != nil || len(liveVuln) != 1 {
		t.Errorf("%d of our vulnerabilities are open: %v", len(liveVuln), err)
	}
	stats, err := r.GetStats(ctx, mine)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalVulnerabilities != 1 || stats.OpenEvents != 1 || stats.PendingPatches != 1 {
		t.Errorf("our stats read %d vulnerabilities / %d open events / %d pending patches",
			stats.TotalVulnerabilities, stats.OpenEvents, stats.PendingPatches)
	}
}

// ─── Lists and filters ───────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	plc := asset(t, r, tenant, "API-L2-01", "plc", "critical", 1, true)
	hmi := asset(t, r, tenant, "IHM-bureau", "hmi", "medium", 4, false)
	no := false
	if _, err := r.UpdateAsset(ctx, tenant, hmi.ID, &model.UpdateAssetRequest{IsActive: &no}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	yes := true
	for _, c := range []struct {
		name string
		f    model.ListAssetsFilter
		want int
	}{
		{"everything", model.ListAssetsFilter{}, 2},
		{"by type", model.ListAssetsFilter{AssetType: "plc"}, 1},
		{"by a type nothing has", model.ListAssetsFilter{AssetType: "rtu"}, 0},
		{"by site", model.ListAssetsFilter{Site: "Usine de Lyon"}, 2},
		{"by risk level", model.ListAssetsFilter{RiskLevel: "critical"}, 1},
		{"by Purdue level", model.ListAssetsFilter{PurdueLevel: 4}, 1},
		{"active only", model.ListAssetsFilter{IsActive: &yes}, 1},
		{"inactive only", model.ListAssetsFilter{IsActive: &no}, 1},
	} {
		rows, total, err := r.ListAssets(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListAssets(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	vuln(t, r, tenant, plc.ID, "CVE-2024-0001", "critical")
	vuln(t, r, tenant, plc.ID, "CVE-2024-0002", "high")
	vuln(t, r, tenant, hmi.ID, "CVE-2024-0003", "low")

	for _, c := range []struct {
		name string
		f    model.ListVulnsFilter
		want int
	}{
		{"everything", model.ListVulnsFilter{}, 3},
		{"by asset", model.ListVulnsFilter{AssetID: &plc.ID}, 2},
		{"by severity", model.ListVulnsFilter{Severity: "critical"}, 1},
		{"by status", model.ListVulnsFilter{Status: "open"}, 3},
		{"by a status nothing has", model.ListVulnsFilter{Status: "patched"}, 0},
	} {
		rows, total, err := r.ListVulnerabilities(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListVulnerabilities(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalAssets != 2 || stats.ActiveAssets != 1 {
		t.Errorf("stats say %d assets / %d active", stats.TotalAssets, stats.ActiveAssets)
	}
	if stats.CriticalAssets != 1 || stats.InternetFacingAssets != 1 {
		t.Errorf("stats say %d critical / %d internet facing", stats.CriticalAssets, stats.InternetFacingAssets)
	}
	if stats.TotalVulnerabilities != 3 || stats.CriticalVulns != 1 {
		t.Errorf("stats say %d vulnerabilities / %d critical", stats.TotalVulnerabilities, stats.CriticalVulns)
	}
	if stats.SafetyImpactVulns != 1 {
		t.Errorf("stats say %d vulnerabilities affecting safety, want the critical one", stats.SafetyImpactVulns)
	}
	// The breakdown counts the active assets, and the HMI was deactivated
	// above — so one entry, not two.
	if stats.AssetsByType["plc"] != 1 || stats.AssetsByType["hmi"] != 0 {
		t.Errorf("the type breakdown reads %v", stats.AssetsByType)
	}
	if len(stats.TopRiskyAssets) == 0 || stats.TopRiskyAssets[0].ID != plc.ID {
		t.Errorf("the riskiest asset is %+v, want the internet-facing controller", stats.TopRiskyAssets)
	}
}

// Only the anomalous communications, when that is what was asked for.
func TestTheAnomalousFilterOnCommunications(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a := asset(t, r, tenant, "API-L2-01", "plc", "high", 1, false)
	b := asset(t, r, tenant, "IHM-bureau", "hmi", "medium", 3, false)

	if _, err := r.CreateCommunication(ctx, tenant, &model.CreateCommunicationRequest{
		SrcAssetID: &b.ID, DstAssetID: &a.ID, Protocol: "Modbus", Port: 502,
		IsAuthorized: true,
	}); err != nil {
		t.Fatalf("CreateCommunication: %v", err)
	}
	if _, err := r.CreateCommunication(ctx, tenant, &model.CreateCommunicationRequest{
		SrcAssetID: &a.ID, DstAssetID: &b.ID, Protocol: "FTP", Port: 21,
		IsAnomalous: true,
	}); err != nil {
		t.Fatalf("CreateCommunication: %v", err)
	}

	all, err := r.ListCommunications(ctx, tenant, false)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListCommunications: %d %v", len(all), err)
	}
	odd, err := r.ListCommunications(ctx, tenant, true)
	if err != nil {
		t.Fatalf("ListCommunications(anomalous): %v", err)
	}
	if len(odd) != 1 || odd[0].Protocol != "FTP" {
		t.Errorf("the anomalous list reads %+v", odd)
	}

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.AnomalousCommunications != 1 {
		t.Errorf("stats count %d anomalous communications", stats.AnomalousCommunications)
	}
}

// A fresh tenant gets zeros rather than an error.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	r, _, tenant := repo(t)
	stats, err := r.GetStats(context.Background(), tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalAssets != 0 || stats.TotalZones != 0 || stats.OpenEvents != 0 {
		t.Errorf("a tenant with no data reports %+v", stats)
	}
	if stats.AssetsByType == nil || stats.VulnsBySeverity == nil {
		t.Error("the breakdowns are nil, which serialises as null rather than {}")
	}
}
