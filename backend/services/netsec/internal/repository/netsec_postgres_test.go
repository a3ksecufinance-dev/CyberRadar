package repository

import (
	"context"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/netsec/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The network security repository against a real PostgreSQL.
//
// Microsegmentation is a set of zones and the rules between them, so almost
// every write here names a zone the caller chose: a policy from one zone to
// another, a device sitting in one, an anomaly observed between two. The row
// written carries the caller's own tenant_id, and the foreign key behind
// src_zone_id points at netsec_zones with no tenant of its own — so the zone
// identifier is the thing that has to be checked.

func repo(t *testing.T) (*NetSecRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewNetSecRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func zone(t *testing.T, r *NetSecRepository, tenant uuid.UUID, name, zoneType string, trust int, cidrs ...string) *model.NetSecZone {
	t.Helper()
	z, err := r.CreateZone(context.Background(), tenant, &model.CreateZoneRequest{
		Name: name, Description: "Zone de test", ZoneType: zoneType,
		TrustLevel: trust, CIDRBlocks: cidrs, Color: "#112233",
		Metadata: map[string]any{"site": "Paris"},
	})
	if err != nil {
		t.Fatalf("CreateZone(%s): %v", name, err)
	}
	return z
}

func flow(t *testing.T, r *NetSecRepository, tenant uuid.UUID, src, dst string, bytes int64, action string) *model.NetSecFlow {
	t.Helper()
	port := 443
	f, err := r.IngestFlow(context.Background(), tenant, &model.IngestFlowRequest{
		SrcIP: src, DstIP: dst, DstPort: &port, Protocol: "tcp",
		BytesSent: bytes, BytesRecv: bytes / 2, Packets: 120, DurationMs: 900,
		Action: action, FlowStart: time.Now().Add(-time.Minute),
	}, nil, nil)
	if err != nil {
		t.Fatalf("IngestFlow(%s→%s): %v", src, dst, err)
	}
	return f
}

// ─── The round trip ──────────────────────────────────────────────────────────

// A zone, a policy between two zones, and a flow: the three writes that every
// other feature of this service is built on.
func TestAZoneAPolicyAndAFlowReadBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	dmz := zone(t, r, tenant, "DMZ", "dmz", 20, "10.1.0.0/16")
	prod := zone(t, r, tenant, "PROD", "production", 80, "10.2.0.0/16")
	if dmz.TrustLevel != 20 || len(dmz.CIDRBlocks) != 1 {
		t.Errorf("the zone reads back as %+v", dmz)
	}
	if !dmz.IsActive {
		t.Error("a fresh zone is not active")
	}

	// Nothing optional: no description, no CIDR override, no ports.
	p, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "DMZ vers PROD", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID,
		Action: "deny",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreatePolicy with nothing optional: %v", err)
	}
	if p.Protocol != "any" || p.Priority != 100 {
		t.Errorf("the repository's defaults did not apply: %+v", p)
	}
	if p.HitCount != 0 || p.LastHitAt != nil {
		t.Errorf("a fresh policy has been hit: %+v", p)
	}
	if p.SrcZoneName != "DMZ" || p.DstZoneName != "PROD" {
		t.Errorf("the created policy names its zones %q → %q", p.SrcZoneName, p.DstZoneName)
	}

	f := flow(t, r, tenant, "10.1.0.9", "10.2.0.4", 2048, "blocked")
	if f.SrcIP != "10.1.0.9" || f.DstIP != "10.2.0.4" {
		t.Errorf("the flow reads back as %s → %s", f.SrcIP, f.DstIP)
	}
	if f.Action != "blocked" || f.AnomalyScore != 0 {
		t.Errorf("the flow reads back as %+v", f)
	}
	if f.Flags == nil {
		t.Error("flags is nil, which serialises as null rather than []")
	}
	if f.FlowEnd != nil {
		t.Errorf("flow_end is %v, want NULL for a flow still open", *f.FlowEnd)
	}

	// A device with nothing optional either.
	d, err := r.RegisterDevice(ctx, tenant, &model.RegisterDeviceRequest{
		Name: "fw-paris-1", DeviceType: "firewall", IPAddress: "10.1.0.1",
		ZoneID: &dmz.ID,
	})
	if err != nil {
		t.Fatalf("RegisterDevice with nothing optional: %v", err)
	}
	if d.Vendor != "" || d.Model != "" || d.Firmware != "" {
		t.Errorf("an optional field came back filled: %+v", d)
	}
	if d.Status != "online" || !d.IsManaged {
		t.Errorf("the device defaults read %+v", d)
	}
	if d.ZoneName != "DMZ" {
		t.Errorf("the registered device names its zone %q", d.ZoneName)
	}

	// And an anomaly with no IP at all, which is what a zone-level detection
	// reports.
	a, err := r.CreateAnomaly(ctx, tenant, &model.CreateAnomalyRequest{
		AnomalyType: "east_west_anomaly", Severity: "HIGH",
		SrcZoneID: &dmz.ID, DstZoneID: &prod.ID,
		Description: "Trafic est-ouest inhabituel entre la DMZ et la production",
	})
	if err != nil {
		t.Fatalf("CreateAnomaly without an IP: %v", err)
	}
	if a.SrcIP != "" || a.DstIP != "" {
		t.Errorf("the anomaly invented addresses: %q / %q", a.SrcIP, a.DstIP)
	}
	if a.Status != "open" {
		t.Errorf("a fresh anomaly is %q", a.Status)
	}
}

// A policy's hit counter follows the flows that matched it, and only on our
// own policies.
func TestThePolicyHitCounterCountsOurOwnHits(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	dmz := zone(t, r, tenant, "DMZ", "dmz", 20)
	prod := zone(t, r, tenant, "PROD", "production", 80)
	p, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "DMZ vers PROD", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID, Action: "deny",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	for i := 0; i < 3; i++ {
		r.IncrementPolicyHit(ctx, tenant, p.ID)
	}
	live, err := r.GetPolicy(ctx, tenant, p.ID)
	if err != nil || live == nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if live.HitCount != 3 {
		t.Errorf("hit_count is %d, want 3", live.HitCount)
	}
	if live.LastHitAt == nil {
		t.Error("a policy that was hit records no date")
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats.PolicyHits) == 0 || stats.PolicyHits[0].HitCount != 3 {
		t.Errorf("the hit ranking reads %+v", stats.PolicyHits)
	}
}

// An anomaly score written after the fact lands on the flow it describes.
func TestAnAnomalyScoreLandsOnItsFlow(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	f := flow(t, r, tenant, "10.1.0.9", "10.2.0.4", 2048, "allowed")

	if err := r.UpdateFlowAnomaly(ctx, tenant, f.ID, 80, []string{"c2_traffic", "beacon"}); err != nil {
		t.Fatalf("UpdateFlowAnomaly: %v", err)
	}
	min := 50
	rows, total, err := r.ListFlows(ctx, tenant, model.ListFlowsFilter{
		MinScore: &min, Page: 1, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("%d flows above 50 (total=%d), want 1", len(rows), total)
	}
	if rows[0].AnomalyScore != 80 || len(rows[0].Flags) != 2 {
		t.Errorf("the scored flow reads %+v", rows[0])
	}
}

// An anomaly is taken up and then closed, and the closing stamps a date.
func TestAnAnomalyIsClosedWithADate(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a, err := r.CreateAnomaly(ctx, tenant, &model.CreateAnomalyRequest{
		AnomalyType: "port_scan", Severity: "MEDIUM", SrcIP: "10.1.0.9",
		Description: "Balayage de ports depuis la DMZ",
		Evidence:    map[string]any{"ports": 240},
	})
	if err != nil {
		t.Fatalf("CreateAnomaly: %v", err)
	}

	taken, err := r.UpdateAnomaly(ctx, tenant, a.ID, "investigating")
	if err != nil || taken == nil {
		t.Fatalf("UpdateAnomaly(investigating): %v", err)
	}
	if taken.ResolvedAt != nil {
		t.Error("an anomaly under investigation already carries a resolution date")
	}
	if taken.Evidence == nil || taken.Evidence["ports"] == nil {
		t.Errorf("the update lost the evidence: %+v", taken.Evidence)
	}

	closed, err := r.UpdateAnomaly(ctx, tenant, a.ID, "false_positive")
	if err != nil || closed == nil {
		t.Fatalf("UpdateAnomaly(false_positive): %v", err)
	}
	if closed.ResolvedAt == nil {
		t.Error("a closed anomaly carries no date")
	}

	// A status the CHECK does not allow is refused rather than failing inside
	// PostgreSQL.
	if _, err := r.UpdateAnomaly(ctx, tenant, a.ID, ""); err == nil {
		t.Error("an empty status was accepted")
	}

	if _, total, err := r.ListAnomalies(ctx, tenant, model.ListAnomaliesFilter{
		Status: "open", Page: 1, PageSize: 10,
	}); err != nil || total != 0 {
		t.Errorf("%d anomalies still open: %v", total, err)
	}
}

// The topology is the three lists together, each of them ours.
func TestTheTopologyIsOurZonesDevicesAndPolicies(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	dmz := zone(t, r, tenant, "DMZ", "dmz", 20)
	prod := zone(t, r, tenant, "PROD", "production", 80)
	retired := zone(t, r, tenant, "ANCIEN", "development", 10)
	no := false
	if _, err := r.UpdateZone(ctx, tenant, retired.ID, &model.UpdateZoneRequest{IsActive: &no}); err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}
	if _, err := r.RegisterDevice(ctx, tenant, &model.RegisterDeviceRequest{
		Name: "fw-paris-1", DeviceType: "firewall", IPAddress: "10.1.0.1", ZoneID: &dmz.ID,
	}); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if _, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "DMZ vers PROD", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID, Action: "inspect",
	}, uuid.Nil); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	topo, err := r.GetTopology(ctx, tenant)
	if err != nil {
		t.Fatalf("GetTopology: %v", err)
	}
	if len(topo.Zones) != 2 {
		t.Errorf("the topology shows %d zones, want the two active ones", len(topo.Zones))
	}
	if len(topo.Devices) != 1 || len(topo.Policies) != 1 {
		t.Errorf("the topology shows %d devices and %d policies", len(topo.Devices), len(topo.Policies))
	}
	if topo.Devices[0].ZoneName != "DMZ" {
		t.Errorf("the device sits in %q", topo.Devices[0].ZoneName)
	}
	if topo.Policies[0].SrcZoneName != "DMZ" || topo.Policies[0].DstZoneName != "PROD" {
		t.Errorf("the policy runs %q → %q", topo.Policies[0].SrcZoneName, topo.Policies[0].DstZoneName)
	}
}

// Seeing the same device again updates it rather than duplicating it, under
// the unique index on (tenant_id, ip_address).
func TestSeeingADeviceAgainUpdatesIt(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	dmz := zone(t, r, tenant, "DMZ", "dmz", 20)

	first, err := r.RegisterDevice(ctx, tenant, &model.RegisterDeviceRequest{
		Name: "fw-paris-1", DeviceType: "firewall", IPAddress: "10.1.0.1",
		ZoneID: &dmz.ID, Vendor: "Fortinet", Firmware: "7.2.4",
	})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	second, err := r.RegisterDevice(ctx, tenant, &model.RegisterDeviceRequest{
		Name: "fw-paris-1", DeviceType: "firewall", IPAddress: "10.1.0.1",
		ZoneID: &dmz.ID, Vendor: "Fortinet", Firmware: "7.2.9",
	})
	if err != nil {
		t.Fatalf("RegisterDevice again: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("a second device was created: %s then %s", first.ID, second.ID)
	}
	if second.Firmware != "7.2.9" {
		t.Errorf("the firmware is still %q", second.Firmware)
	}
	if _, total, err := r.ListDevices(ctx, tenant, "", nil, 1, 10); err != nil || total != 1 {
		t.Errorf("%d devices for one address: %v", total, err)
	}

	moved, err := r.UpdateDevice(ctx, tenant, first.ID, &model.UpdateDeviceRequest{
		Status: "degraded", Vendor: "Fortinet",
	})
	if err != nil || moved == nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	if moved.Status != "degraded" {
		t.Errorf("the device is %q", moved.Status)
	}
	if moved.ZoneName != "DMZ" {
		t.Errorf("the updated device names its zone %q", moved.ZoneName)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// A zone identifier from the request is checked against the caller's tenant,
// because the foreign key is not.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	dmz := zone(t, r, mine, "DMZ", "dmz", 20)
	prod := zone(t, r, mine, "PROD", "production", 80)
	// The neighbour's zone carries a name that must never appear in our
	// answers, and ours must never appear in theirs.
	foreign := zone(t, r, theirs, "SWIFT-VOISIN", "swift", 95)

	p, err := r.CreatePolicy(ctx, mine, &model.CreatePolicyRequest{
		Name: "DMZ vers PROD", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID, Action: "deny",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	f := flow(t, r, mine, "10.1.0.9", "10.2.0.4", 4096, "blocked")
	a, err := r.CreateAnomaly(ctx, mine, &model.CreateAnomalyRequest{
		AnomalyType: "lateral_movement", Severity: "CRITICAL", SrcZoneID: &dmz.ID,
		Description: "Déplacement latéral",
	})
	if err != nil {
		t.Fatalf("CreateAnomaly: %v", err)
	}
	d, err := r.RegisterDevice(ctx, mine, &model.RegisterDeviceRequest{
		Name: "fw-paris-1", DeviceType: "firewall", IPAddress: "10.1.0.1", ZoneID: &dmz.ID,
	})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Reads
	if got, err := r.GetZone(ctx, theirs, dmz.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the zone: %v / %v", got, err)
	}
	if got, err := r.GetPolicy(ctx, theirs, p.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the policy: %v / %v", got, err)
	}
	if rows, err := r.ListZones(ctx, theirs, false); err != nil || len(rows) != 1 {
		t.Errorf("the neighbour listed %d zones, want only their own: %v", len(rows), err)
	}
	if rows, total, err := r.ListPolicies(ctx, theirs, nil, nil, false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d policies (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListFlows(ctx, theirs, model.ListFlowsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d flows (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListAnomalies(ctx, theirs, model.ListAnomaliesFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d anomalies (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListDevices(ctx, theirs, "", nil, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d devices (total=%d): %v", len(rows), total, err)
	}

	// Writes that name one of our rows
	if got, err := r.UpdateZone(ctx, theirs, dmz.ID, &model.UpdateZoneRequest{Color: "#000000"}); err != nil || got != nil {
		t.Errorf("the neighbour recoloured our zone: %v / %v", got, err)
	}
	if got, err := r.UpdatePolicy(ctx, theirs, p.ID, &model.UpdatePolicyRequest{
		Action: "allow",
	}); err != nil || got != nil {
		t.Errorf("the neighbour turned our deny into an allow: %v / %v", got, err)
	}
	if got, err := r.UpdateAnomaly(ctx, theirs, a.ID, "false_positive"); err != nil || got != nil {
		t.Errorf("the neighbour dismissed our anomaly: %v / %v", got, err)
	}
	if got, err := r.UpdateDevice(ctx, theirs, d.ID, &model.UpdateDeviceRequest{
		Status: "offline",
	}); err != nil || got != nil {
		t.Errorf("the neighbour marked our firewall offline: %v / %v", got, err)
	}
	if err := r.UpdateFlowAnomaly(ctx, theirs, f.ID, 0, []string{}); err == nil {
		t.Error("the neighbour cleared the anomaly score on our flow")
	}
	r.IncrementPolicyHit(ctx, theirs, p.ID)

	// Writes that point at one of our zones from the neighbour's side.
	if got, err := r.CreatePolicy(ctx, theirs, &model.CreatePolicyRequest{
		Name: "intrusion", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID, Action: "allow",
	}, uuid.Nil); err == nil {
		t.Errorf("the neighbour wrote a policy between our zones: %+v", got)
	}
	if got, err := r.RegisterDevice(ctx, theirs, &model.RegisterDeviceRequest{
		Name: "intrus", DeviceType: "switch", IPAddress: "10.9.9.9", ZoneID: &dmz.ID,
	}); err == nil {
		t.Errorf("the neighbour put a device in our zone: %+v", got)
	}
	if got, err := r.CreateAnomaly(ctx, theirs, &model.CreateAnomalyRequest{
		AnomalyType: "c2_traffic", Severity: "LOW", SrcZoneID: &dmz.ID,
		Description: "bruit",
	}); err == nil {
		t.Errorf("the neighbour attached an anomaly to our zone: %+v", got)
	}

	// And our own writes must not reach theirs.
	if got, err := r.CreatePolicy(ctx, mine, &model.CreatePolicyRequest{
		Name: "vers le voisin", SrcZoneID: &dmz.ID, DstZoneID: &foreign.ID, Action: "allow",
	}, uuid.Nil); err == nil {
		t.Errorf("we wrote a policy into the neighbour's zone, named %q: %+v",
			got.DstZoneName, got)
	}

	// Our rows are exactly as we left them.
	live, err := r.GetPolicy(ctx, mine, p.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the policy: %v", err)
	}
	if live.Action != "deny" {
		t.Errorf("our policy now says %q", live.Action)
	}
	if live.HitCount != 0 {
		t.Errorf("our policy counts %d hits", live.HitCount)
	}
	liveDevice, _, err := r.ListDevices(ctx, mine, "", nil, 1, 10)
	if err != nil || len(liveDevice) != 1 {
		t.Fatalf("re-read the devices: %v", err)
	}
	if liveDevice[0].Status != "online" {
		t.Errorf("our firewall is %q", liveDevice[0].Status)
	}
	liveFlow, _, err := r.ListFlows(ctx, mine, model.ListFlowsFilter{Page: 1, PageSize: 10})
	if err != nil || len(liveFlow) != 1 {
		t.Fatalf("re-read the flows: %v", err)
	}
	liveAnomaly, _, err := r.ListAnomalies(ctx, mine, model.ListAnomaliesFilter{Page: 1, PageSize: 10})
	if err != nil || len(liveAnomaly) != 1 {
		t.Fatalf("re-read the anomalies: %v", err)
	}
	if liveAnomaly[0].Status != "open" {
		t.Errorf("our anomaly is %q", liveAnomaly[0].Status)
	}
	liveZone, err := r.GetZone(ctx, mine, dmz.ID)
	if err != nil || liveZone == nil {
		t.Fatalf("re-read the zone: %v", err)
	}
	if liveZone.Color != "#112233" {
		t.Errorf("our zone is %q", liveZone.Color)
	}
}

// ─── Lists and filters ───────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	dmz := zone(t, r, tenant, "DMZ", "dmz", 20)
	prod := zone(t, r, tenant, "PROD", "production", 80)

	if _, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "DMZ vers PROD", SrcZoneID: &dmz.ID, DstZoneID: &prod.ID, Action: "deny",
	}, uuid.Nil); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := r.CreatePolicy(ctx, tenant, &model.CreatePolicyRequest{
		Name: "PROD vers DMZ", SrcZoneID: &prod.ID, DstZoneID: &dmz.ID, Action: "log",
	}, uuid.Nil); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	for _, c := range []struct {
		name string
		src  *uuid.UUID
		dst  *uuid.UUID
		want int
	}{
		{"everything", nil, nil, 2},
		{"from the DMZ", &dmz.ID, nil, 1},
		{"to the DMZ", nil, &dmz.ID, 1},
		{"from the DMZ to the DMZ", &dmz.ID, &dmz.ID, 0},
	} {
		rows, total, err := r.ListPolicies(ctx, tenant, c.src, c.dst, false, 1, 50)
		if err != nil {
			t.Fatalf("ListPolicies(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	flow(t, r, tenant, "10.1.0.9", "10.2.0.4", 2048, "blocked")
	flow(t, r, tenant, "10.1.0.9", "10.2.0.5", 4096, "allowed")
	flow(t, r, tenant, "10.3.0.1", "10.2.0.4", 8192, "allowed")

	for _, c := range []struct {
		name string
		f    model.ListFlowsFilter
		want int
	}{
		{"everything", model.ListFlowsFilter{}, 3},
		{"by source", model.ListFlowsFilter{SrcIP: "10.1.0.9"}, 2},
		{"by destination", model.ListFlowsFilter{DstIP: "10.2.0.4"}, 2},
		{"by action", model.ListFlowsFilter{Action: "blocked"}, 1},
		{"by an action nothing has", model.ListFlowsFilter{Action: "inspected"}, 0},
	} {
		c.f.Page, c.f.PageSize = 1, 50
		rows, total, err := r.ListFlows(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListFlows(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalZones != 2 || stats.TotalPolicies != 2 || stats.ActivePolicies != 2 {
		t.Errorf("stats say %d zones / %d policies / %d active", stats.TotalZones, stats.TotalPolicies, stats.ActivePolicies)
	}
	if stats.FlowsLast24h != 3 || stats.BlockedFlows24h != 1 {
		t.Errorf("stats say %d flows / %d blocked in 24h", stats.FlowsLast24h, stats.BlockedFlows24h)
	}
	if len(stats.TopSrcIPs) == 0 || stats.TopSrcIPs[0].IP != "10.1.0.9" {
		t.Errorf("the busiest source reads %+v", stats.TopSrcIPs)
	}
}

// A fresh tenant gets zeros rather than an error.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalZones != 0 || stats.TotalDevices != 0 || stats.OpenAnomalies != 0 {
		t.Errorf("a tenant with no data reports %+v", stats)
	}
	if stats.AnomaliesBySev == nil || stats.AnomaliesByType == nil {
		t.Error("the breakdowns are nil, which serialises as null rather than {}")
	}
	topo, err := r.GetTopology(ctx, tenant)
	if err != nil {
		t.Fatalf("GetTopology: %v", err)
	}
	if topo == nil {
		t.Fatal("GetTopology returned nothing for an empty tenant")
	}
}
