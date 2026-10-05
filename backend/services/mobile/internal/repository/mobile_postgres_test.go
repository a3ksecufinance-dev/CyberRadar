package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/mobile/internal/model"
)

// The mobile device management repository: the first test this service has ever
// had.
//
// A fleet of phones is the part of a bank's estate that walks out of the
// building, so this service answers two questions an auditor asks directly:
// which devices are non-compliant, and which of them had a threat raised. Both
// answers are counts produced by queries whose errors this repository discards,
// and both are scoped by a tenant filter that compiles whether or not it is
// there.

func repo(t *testing.T) (*MobileRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewMobileRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func device(t *testing.T, r *MobileRepository, tenant uuid.UUID, name string) *model.MobDevice {
	t.Helper()
	d, err := r.CreateDevice(context.Background(), tenant, model.CreateDeviceRequest{
		DeviceName: name, DeviceType: "smartphone", Platform: "ios",
		OSVersion: "17.4", Model: "iPhone 14", Manufacturer: "Apple",
		SerialNumber: "SN-" + name, IMEI: "35" + name, UDID: "UD-" + name,
		Ownership: "corporate", OwnerName: "Alice Martin",
		OwnerEmail: "alice@banque.test", Department: "Trésorerie",
		IsEncrypted: true, IsScreenLock: true, Carrier: "Orange",
		Tags: []string{"cadre"},
	})
	if err != nil {
		t.Fatalf("CreateDevice(%s): %v", name, err)
	}
	return d
}

func threat(t *testing.T, r *MobileRepository, tenant, deviceID uuid.UUID, kind, severity string) *model.MobThreat {
	t.Helper()
	th, err := r.CreateThreat(context.Background(), tenant, model.CreateThreatRequest{
		DeviceID: deviceID, ThreatType: kind, Severity: severity,
		Title: "Menace détectée", Description: "Détectée par l'agent",
		ThreatIndicator: "hash:abcdef", AffectedApp: "com.exemple.app",
		DetectedBy: "agent", Tags: []string{"mobile"},
	})
	if err != nil {
		t.Fatalf("CreateThreat(%s/%s): %v", kind, severity, err)
	}
	return th
}

// ─── The round trip ──────────────────────────────────────────────────────────

func TestADeviceReadsBackAsItWasEnrolled(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	made := device(t, r, tenant, "iphone-alice")
	got, err := r.GetDevice(ctx, tenant, made.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got == nil {
		t.Fatal("GetDevice found nothing")
	}
	for _, c := range []struct{ name, got, want string }{
		{"device_name", got.DeviceName, "iphone-alice"},
		{"platform", got.Platform, "ios"},
		{"model", got.Model, "iPhone 14"},
		{"manufacturer", got.Manufacturer, "Apple"},
		{"owner_name", got.OwnerName, "Alice Martin"},
		{"owner_email", got.OwnerEmail, "alice@banque.test"},
		{"department", got.Department, "Trésorerie"},
		{"carrier", got.Carrier, "Orange"},
		{"ownership", got.Ownership, "corporate"},
	} {
		if c.got != c.want {
			t.Errorf("%s is %q, want %q", c.name, c.got, c.want)
		}
	}
	if !got.IsEncrypted || !got.IsScreenLock {
		t.Error("the security posture was not kept")
	}
	if got.EnrollmentDate.IsZero() || got.CreatedAt.IsZero() {
		t.Error("the timestamps came back zero")
	}
	if got.ComplianceIssues == nil || got.Tags == nil {
		t.Error("the arrays came back nil rather than empty")
	}
}

// A device enrolled with nothing but the three required fields reads back. Nine
// of its columns are nullable text that the model holds as a string, which is
// the defect class this repository is most exposed to.
func TestADeviceWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	bare, err := r.CreateDevice(ctx, tenant, model.CreateDeviceRequest{
		DeviceName: "android-partagé", DeviceType: "tablet", Platform: "android",
	})
	if err != nil {
		t.Fatalf("CreateDevice with nothing optional: %v", err)
	}
	if bare.Model != "" || bare.IMEI != "" || bare.Carrier != "" {
		t.Errorf("the optional fields came back as %q/%q/%q", bare.Model, bare.IMEI, bare.Carrier)
	}
	if got, err := r.GetDevice(ctx, tenant, bare.ID); err != nil || got == nil {
		t.Fatalf("GetDevice: %+v / %v", got, err)
	}
	if rows, total, err := r.ListDevices(ctx, tenant, model.ListDevicesFilter{Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListDevices gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// An app with no developer and no category.
	app, err := r.CreateApp(ctx, tenant, model.CreateAppRequest{
		AppName: "Appli interne", BundleID: "fr.banque.interne",
		Version: "1.0.0", Platform: "android", StoreSource: "enterprise",
	})
	if err != nil {
		t.Fatalf("CreateApp with nothing optional: %v", err)
	}
	if got, err := r.GetApp(ctx, tenant, app.ID); err != nil || got == nil {
		t.Fatalf("GetApp: %+v / %v", got, err)
	}
	if rows, total, err := r.ListApps(ctx, tenant, model.ListAppsFilter{Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListApps gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A threat with no indicator, no affected app and no detector.
	th, err := r.CreateThreat(ctx, tenant, model.CreateThreatRequest{
		DeviceID: bare.ID, ThreatType: "malware", Severity: "high",
		Title: "Application inconnue",
	})
	if err != nil {
		t.Fatalf("CreateThreat with nothing optional: %v", err)
	}
	if th.ResolvedAt != nil {
		t.Error("a fresh threat is already resolved")
	}
	if got, err := r.GetThreat(ctx, tenant, th.ID); err != nil || got == nil {
		t.Fatalf("GetThreat: %+v / %v", got, err)
	}
	if rows, total, err := r.ListThreats(ctx, tenant, model.ListThreatsFilter{Limit: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListThreats gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A policy with no description and no department.
	pol, err := r.CreatePolicy(ctx, tenant, model.CreatePolicyRequest{
		Name: "Chiffrement obligatoire", PolicyType: "encryption", Platform: "all",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePolicy with nothing optional: %v", err)
	}
	if got, err := r.GetPolicy(ctx, tenant, pol.ID); err != nil || got == nil {
		t.Fatalf("GetPolicy: %+v / %v", got, err)
	}
	if rows, err := r.ListPolicies(ctx, tenant); err != nil || len(rows) != 1 {
		t.Fatalf("ListPolicies gave %d rows: %v", len(rows), err)
	}

	// A remote action with no message and no requester.
	act, err := r.CreateRemoteAction(ctx, tenant, model.CreateRemoteActionRequest{
		DeviceID: bare.ID, ActionType: "lock",
	})
	if err != nil {
		t.Fatalf("CreateRemoteAction with nothing optional: %v", err)
	}
	if got, err := r.GetRemoteAction(ctx, tenant, act.ID); err != nil || got == nil {
		t.Fatalf("GetRemoteAction: %+v / %v", got, err)
	}
	if rows, err := r.ListRemoteActions(ctx, tenant, bare.ID); err != nil || len(rows) != 1 {
		t.Fatalf("ListRemoteActions gave %d rows: %v", len(rows), err)
	}

	// And a compliance check, whose action_taken is nullable and never written
	// on insert — so this call failed every time before the column was
	// coalesced.
	check, err := r.RunComplianceCheck(ctx, tenant, model.RunComplianceRequest{DeviceID: bare.ID})
	if err != nil {
		t.Fatalf("RunComplianceCheck: %v", err)
	}
	if check.ActionTaken != "" {
		t.Errorf("action_taken is %q on a check that took none", check.ActionTaken)
	}
	if rows, err := r.ListComplianceChecks(ctx, tenant, bare.ID, 10); err != nil || len(rows) != 1 {
		t.Fatalf("ListComplianceChecks gave %d rows: %v", len(rows), err)
	}
}

// ─── Compliance ──────────────────────────────────────────────────────────────

// The compliance check is the product claim of this service: it has to find the
// violations that are really there, score them, and write the verdict back onto
// the device — so a list of non-compliant devices is the same set the check
// just produced.
func TestTheComplianceCheckFindsTheViolationsThatAreThere(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// A device in good order: encrypted, locked, MDM installed.
	good := device(t, r, tenant, "iphone-conforme")
	if _, err := r.UpdateDevice(ctx, tenant, good.ID, model.UpdateDeviceRequest{
		MDMProfileInstalled: boolp(true),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	check, err := r.RunComplianceCheck(ctx, tenant, model.RunComplianceRequest{DeviceID: good.ID})
	if err != nil {
		t.Fatalf("RunComplianceCheck: %v", err)
	}
	if !check.IsCompliant {
		t.Errorf("a device with nothing wrong is non-compliant: %+v", check.Violations)
	}
	if check.ComplianceScore != 100 {
		t.Errorf("score is %d, want 100", check.ComplianceScore)
	}
	if check.NextCheckAt == nil {
		t.Error("the check scheduled no next one")
	}

	// A jailbroken, unencrypted device with no screen lock and no MDM: four
	// violations, 30 + 20 + 10 + 20 deducted, so zero rather than a negative.
	bad := device(t, r, tenant, "iphone-compromis")
	if _, err := r.UpdateDevice(ctx, tenant, bad.ID, model.UpdateDeviceRequest{
		IsJailbroken: boolp(true), IsEncrypted: boolp(false), IsScreenLock: boolp(false),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	check, err = r.RunComplianceCheck(ctx, tenant, model.RunComplianceRequest{DeviceID: bad.ID})
	if err != nil {
		t.Fatalf("RunComplianceCheck: %v", err)
	}
	if check.IsCompliant {
		t.Error("a jailbroken, unencrypted device is reported compliant")
	}
	if len(check.Violations) != 4 {
		t.Errorf("%d violations, want 4: %+v", len(check.Violations), check.Violations)
	}
	if check.ComplianceScore != 20 {
		t.Errorf("score is %d, want 20 (100 − 30 − 20 − 10 − 20)", check.ComplianceScore)
	}

	// The verdict landed on the device, which is what the fleet list reads.
	after, err := r.GetDevice(ctx, tenant, bad.ID)
	if err != nil || after == nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if after.IsCompliant {
		t.Error("the device still reads as compliant after a failed check")
	}
	if len(after.ComplianceIssues) != 4 {
		t.Errorf("the device carries %d issues, want 4: %v", len(after.ComplianceIssues), after.ComplianceIssues)
	}
	no := false
	rows, total, err := r.ListDevices(ctx, tenant, model.ListDevicesFilter{IsCompliant: &no, Limit: 50})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].ID != bad.ID {
		t.Errorf("the non-compliant listing gave total=%d, %d rows", total, len(rows))
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	d := device(t, r, mine, "iphone-alice")
	app, err := r.CreateApp(ctx, mine, model.CreateAppRequest{
		AppName: "Appli", BundleID: "fr.banque.appli", Version: "1.0",
		Platform: "ios", StoreSource: "app_store",
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	th := threat(t, r, mine, d.ID, "malware", "critical")
	pol, err := r.CreatePolicy(ctx, mine, model.CreatePolicyRequest{
		Name: "Verrouillage", PolicyType: "passcode", Platform: "ios",
	}, nil)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	act, err := r.CreateRemoteAction(ctx, mine, model.CreateRemoteActionRequest{
		DeviceID: d.ID, ActionType: "remote_wipe", Message: "Appareil perdu",
	})
	if err != nil {
		t.Fatalf("CreateRemoteAction: %v", err)
	}

	// Reads
	if got, err := r.GetDevice(ctx, theirs, d.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the device: %v / %v", got, err)
	}
	if got, err := r.GetApp(ctx, theirs, app.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the app: %v / %v", got, err)
	}
	if got, err := r.GetThreat(ctx, theirs, th.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the threat: %v / %v", got, err)
	}
	if got, err := r.GetPolicy(ctx, theirs, pol.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the policy: %v / %v", got, err)
	}
	if got, err := r.GetRemoteAction(ctx, theirs, act.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the remote action: %v / %v", got, err)
	}
	if rows, total, err := r.ListDevices(ctx, theirs, model.ListDevicesFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d devices (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListApps(ctx, theirs, model.ListAppsFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d apps (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListThreats(ctx, theirs, model.ListThreatsFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d threats (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListPolicies(ctx, theirs); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d policies: %v", len(rows), err)
	}
	if rows, err := r.ListDeviceApps(ctx, theirs, d.ID); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d installed apps: %v", len(rows), err)
	}
	if rows, err := r.ListRemoteActions(ctx, theirs, d.ID); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d remote actions: %v", len(rows), err)
	}
	if rows, err := r.ListComplianceChecks(ctx, theirs, d.ID, 10); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d compliance checks: %v", len(rows), err)
	}

	// Writes. A remote wipe is the one that matters most here: it erases a
	// phone, and the only thing standing between one customer and another's
	// fleet is these checks.
	//
	// This repository reports an absent row as the driver's own no-rows error,
	// which the handler maps to 404 — unlike easm and dspm, which return
	// (nil, nil). What matters for isolation is that the update does not land,
	// so the assertion is "refused", not "refused in one particular way".
	refused := func(what string, got any, err error) {
		t.Helper()
		if err == nil && !isNil(got) {
			t.Errorf("the neighbour %s: %v", what, got)
		}
	}
	gotDev, err := r.UpdateDevice(ctx, theirs, d.ID, model.UpdateDeviceRequest{DeviceName: strp("volé")})
	refused("renamed the device", gotDev, err)
	gotApp, err := r.UpdateApp(ctx, theirs, app.ID, model.UpdateAppRequest{IsBlocklisted: boolp(true)})
	refused("blocklisted the app", gotApp, err)
	gotThreat, err := r.UpdateThreat(ctx, theirs, th.ID, model.UpdateThreatRequest{Status: strp("false_positive")})
	refused("dismissed the threat", gotThreat, err)
	gotPol, err := r.UpdatePolicy(ctx, theirs, pol.ID, model.UpdatePolicyRequest{IsActive: boolp(false)})
	refused("disabled the policy", gotPol, err)
	gotAct, err := r.UpdateRemoteAction(ctx, theirs, act.ID, model.UpdateRemoteActionRequest{Status: strp("failed")})
	refused("failed the remote action", gotAct, err)
	if _, err := r.CreateRemoteAction(ctx, theirs, model.CreateRemoteActionRequest{
		DeviceID: d.ID, ActionType: "remote_wipe",
	}); err == nil {
		t.Error("the neighbour queued a remote wipe on another customer's phone")
	}
	if err := r.InstallApp(ctx, theirs, d.ID, app.ID); err == nil {
		t.Error("the neighbour installed an app on another customer's phone")
	}
	if err := r.DeleteDevice(ctx, theirs, d.ID); err == nil {
		t.Error("the neighbour deleted the device")
	}
	if err := r.DeletePolicy(ctx, theirs, pol.ID); err == nil {
		t.Error("the neighbour deleted the policy")
	}

	// Nothing moved.
	again, err := r.GetDevice(ctx, mine, d.ID)
	if err != nil || again == nil {
		t.Fatalf("re-read: %v", err)
	}
	if again.DeviceName != "iphone-alice" {
		t.Errorf("the device is now %q", again.DeviceName)
	}
	live, err := r.GetThreat(ctx, mine, th.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the threat: %v", err)
	}
	if live.Status != "active" && live.Status != "open" && live.Status != "detected" {
		t.Errorf("the threat is %q — the neighbour's dismissal landed", live.Status)
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	// Three devices: one compliant, one jailbroken, one unenrolled.
	ok := device(t, r, tenant, "iphone-ok")
	if _, err := r.UpdateDevice(ctx, tenant, ok.ID, model.UpdateDeviceRequest{
		MDMProfileInstalled: boolp(true), IsCompliant: boolp(true),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	jail := device(t, r, tenant, "iphone-jail")
	if _, err := r.UpdateDevice(ctx, tenant, jail.ID, model.UpdateDeviceRequest{
		IsJailbroken: boolp(true), IsCompliant: boolp(false),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	retired, err := r.CreateDevice(ctx, tenant, model.CreateDeviceRequest{
		DeviceName: "android-retire", DeviceType: "smartphone", Platform: "android",
		Ownership: "byod",
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if _, err := r.UpdateDevice(ctx, tenant, retired.ID, model.UpdateDeviceRequest{
		EnrollmentStatus: strp("retired"),
	}); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	// Two apps, one of them blocklisted and vulnerable.
	clean, err := r.CreateApp(ctx, tenant, model.CreateAppRequest{
		AppName: "Appli saine", BundleID: "fr.banque.saine", Version: "1.0",
		Platform: "ios", StoreSource: "app_store",
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	risky, err := r.CreateApp(ctx, tenant, model.CreateAppRequest{
		AppName: "Appli risquée", BundleID: "fr.inconnu.risque", Version: "0.1",
		Platform: "android", StoreSource: "sideload",
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if _, err := r.UpdateApp(ctx, tenant, risky.ID, model.UpdateAppRequest{
		IsBlocklisted: boolp(true), HasKnownVulns: boolp(true), VulnCount: intp(3),
	}); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	_ = clean

	// Three threats: a critical one, a high one, and one already resolved.
	threat(t, r, tenant, jail.ID, "jailbreak_root", "critical")
	threat(t, r, tenant, jail.ID, "malware", "high")
	done := threat(t, r, tenant, ok.ID, "phishing", "medium")
	if _, err := r.UpdateThreat(ctx, tenant, done.ID, model.UpdateThreatRequest{
		Status: strp("resolved"), Remediation: strp("Application supprimée"),
		ResolvedBy: strp("équipe mobile"),
	}); err != nil {
		t.Fatalf("UpdateThreat: %v", err)
	}

	// One pending remote action.
	if _, err := r.CreateRemoteAction(ctx, tenant, model.CreateRemoteActionRequest{
		DeviceID: jail.ID, ActionType: "lock", Message: "Appareil compromis",
	}); err != nil {
		t.Fatalf("CreateRemoteAction: %v", err)
	}

	// The neighbour's fleet, which must change nothing below.
	nb := device(t, r, other, "iphone-voisin")
	threat(t, r, other, nb.ID, "malware", "critical")

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_devices", stats.TotalDevices, 3},
		// is_compliant defaults to true, so only the device explicitly marked
		// non-compliant counts — a device nobody has checked yet is not
		// reported as failing, which is the right way round.
		{"non_compliant_devices", stats.NonCompliantDevices, 1},
		{"jailbroken_devices", stats.JailbrokenDevices, 1},
		{"total_apps", stats.TotalApps, 2},
		{"blocklisted_apps", stats.BlocklistedApps, 1},
		{"vulnerable_apps", stats.VulnerableApps, 1},
		{"critical_threats", stats.CriticalThreats, 1},
		{"pending_actions", stats.PendingActions, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if stats.DevicesByPlatform["ios"] != 2 || stats.DevicesByPlatform["android"] != 1 {
		t.Errorf("devices by platform is %v", stats.DevicesByPlatform)
	}
	if stats.ThreatsBySeverity["critical"] != 1 {
		t.Errorf("threats by severity is %v", stats.ThreatsBySeverity)
	}
	// The resolved threat must not count as active.
	if stats.ActiveThreats != 2 {
		t.Errorf("active_threats is %d, want 2 — the resolved one is still counted", stats.ActiveThreats)
	}
}

func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.GetStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GetStats on an empty tenant: %v", err)
	}
	if stats.TotalDevices != 0 || stats.TotalApps != 0 || stats.ActiveThreats != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	for name, m := range map[string]map[string]int{
		"devices_by_platform":  stats.DevicesByPlatform,
		"devices_by_ownership": stats.DevicesByOwnership,
		"threats_by_severity":  stats.ThreatsBySeverity,
		"threats_by_type":      stats.ThreatsByType,
	} {
		if m == nil {
			t.Errorf("%s came back nil rather than empty", name)
		}
	}
	if stats.TopRiskyDevices == nil || stats.RecentThreats == nil {
		t.Error("the lists came back nil rather than empty")
	}
}

// ─── Filters and installs ────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	ios := device(t, r, tenant, "iphone-alice")
	android, err := r.CreateDevice(ctx, tenant, model.CreateDeviceRequest{
		DeviceName: "pixel-bob", DeviceType: "smartphone", Platform: "android",
		Ownership: "byod", Department: "Agence",
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	_ = android

	for _, c := range []struct {
		what   string
		filter model.ListDevicesFilter
		want   int
	}{
		{"no filter", model.ListDevicesFilter{Limit: 50}, 2},
		{"by platform", model.ListDevicesFilter{Platform: "ios", Limit: 50}, 1},
		{"by ownership", model.ListDevicesFilter{Ownership: "byod", Limit: 50}, 1},
		{"by department", model.ListDevicesFilter{Department: "Agence", Limit: 50}, 1},
		{"by a platform nobody has", model.ListDevicesFilter{Platform: "windows", Limit: 50}, 0},
	} {
		rows, total, err := r.ListDevices(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListDevices %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	threat(t, r, tenant, ios.ID, "malware", "critical")
	threat(t, r, tenant, ios.ID, "phishing", "low")

	for _, c := range []struct {
		what   string
		filter model.ListThreatsFilter
		want   int
	}{
		{"all", model.ListThreatsFilter{Limit: 50}, 2},
		{"on one device", model.ListThreatsFilter{DeviceID: &ios.ID, Limit: 50}, 2},
		{"by type", model.ListThreatsFilter{ThreatType: "malware", Limit: 50}, 1},
		{"by severity", model.ListThreatsFilter{Severity: "critical", Limit: 50}, 1},
	} {
		rows, total, err := r.ListThreats(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListThreats %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
}

// Installing an app records it against the device and counts once, however many
// times the agent reports it.
func TestInstallingAnAppIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	d := device(t, r, tenant, "iphone-alice")
	app, err := r.CreateApp(ctx, tenant, model.CreateAppRequest{
		AppName: "Appli", BundleID: "fr.banque.appli", Version: "1.0",
		Platform: "ios", StoreSource: "app_store",
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := r.InstallApp(ctx, tenant, d.ID, app.ID); err != nil {
			t.Fatalf("InstallApp (call %d): %v", i+1, err)
		}
	}
	apps, err := r.ListDeviceApps(ctx, tenant, d.ID)
	if err != nil {
		t.Fatalf("ListDeviceApps: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("%d installed apps after two reports of the same one", len(apps))
	}
	if apps[0].ID != app.ID {
		t.Errorf("the installed app is %s, want %s", apps[0].ID, app.ID)
	}
}

// Deleting a device takes its threats, its checks and its queued actions with
// it: a wipe queued for a phone that is no longer managed is an order nobody
// will ever cancel.
func TestDeletingADeviceTakesWhatHungOffIt(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	d := device(t, r, tenant, "iphone-alice")
	threat(t, r, tenant, d.ID, "malware", "high")
	if _, err := r.RunComplianceCheck(ctx, tenant, model.RunComplianceRequest{DeviceID: d.ID}); err != nil {
		t.Fatalf("RunComplianceCheck: %v", err)
	}
	if _, err := r.CreateRemoteAction(ctx, tenant, model.CreateRemoteActionRequest{
		DeviceID: d.ID, ActionType: "lock",
	}); err != nil {
		t.Fatalf("CreateRemoteAction: %v", err)
	}

	if err := r.DeleteDevice(ctx, tenant, d.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if _, total, err := r.ListThreats(ctx, tenant, model.ListThreatsFilter{Limit: 50}); err != nil || total != 0 {
		t.Errorf("%d threats survive their device: %v", total, err)
	}
	if rows, err := r.ListComplianceChecks(ctx, tenant, d.ID, 10); err != nil || len(rows) != 0 {
		t.Errorf("%d compliance checks survive their device: %v", len(rows), err)
	}
	if rows, err := r.ListRemoteActions(ctx, tenant, d.ID); err != nil || len(rows) != 0 {
		t.Errorf("%d remote actions survive their device: %v", len(rows), err)
	}
	if err := r.DeleteDevice(ctx, tenant, d.ID); err == nil {
		t.Error("deleting the device twice reported success")
	}
}

// isNil reports whether a typed-nil pointer came back, which a plain
// `got != nil` on an interface would miss.
func isNil(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case *model.MobDevice:
		return x == nil
	case *model.MobApp:
		return x == nil
	case *model.MobThreat:
		return x == nil
	case *model.MobPolicy:
		return x == nil
	case *model.MobRemoteAction:
		return x == nil
	}
	return false
}

func strp(s string) *string { return &s }
func intp(n int) *int       { return &n }
func boolp(b bool) *bool    { return &b }
