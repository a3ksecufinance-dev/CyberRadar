package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/ti/internal/model"
)

// The threat-intelligence repository: the first test this service has ever had.
//
// Every event the platform ingests is checked against this table, so two
// properties decide whether threat intelligence works at all: the same
// indicator written two different ways has to be one row and has to match
// either way, and one customer's feed must never match another customer's
// traffic. Both are invisible in code — an indicator that silently fails to
// match is an intrusion nobody is told about.

func repo(t *testing.T) (*IOCRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewIOCRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func ioc(t *testing.T, r *IOCRepository, tenant uuid.UUID, kind, value string) *model.IOC {
	t.Helper()
	got, err := r.UpsertIOC(context.Background(), tenant, &model.CreateIOCRequest{
		IOCType: kind, Value: value, TLP: 2, Confidence: 80, Severity: "HIGH",
		MitreTactic: "TA0011", MitreTechnique: "T1071",
		ThreatActor: "Lazarus", MalwareFamily: "AppleJeus", Campaign: "SWIFT 2026",
		Description: "Indicateur de test", Tags: []string{"banque"},
	})
	if err != nil {
		t.Fatalf("UpsertIOC(%s/%s): %v", kind, value, err)
	}
	return got
}

// ─── Normalisation and matching ──────────────────────────────────────────────

// The same indicator written differently is one row, and it matches however it
// is written. A feed that sends EVIL.COM and an event that carries evil.com are
// the same thing, and a lookup that missed it would be a silent failure to
// detect.
func TestTheSameIndicatorWrittenDifferentlyIsOneRow(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	first := ioc(t, r, tenant, "domain", "EVIL.example")
	second, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "domain", Value: "https://evil.example/", Confidence: 95, Severity: "CRITICAL",
	})
	if err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("the same domain produced two rows: %s and %s", first.ID, second.ID)
	}

	// The confidence of the better source wins rather than the latest one.
	got, err := r.Lookup(ctx, tenant, "domain", "evil.example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("the indicator does not match its own normalised form")
	}
	if got.Confidence != 95 {
		t.Errorf("confidence is %d, want the higher 95", got.Confidence)
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("severity is %q, want the latest", got.Severity)
	}
	// The attribution from the first write is not lost by a second that omits it.
	if got.ThreatActor != "Lazarus" || got.MalwareFamily != "AppleJeus" {
		t.Errorf("the attribution was erased: actor %q, malware %q", got.ThreatActor, got.MalwareFamily)
	}

	// And it matches whichever way an event writes it.
	for _, written := range []string{
		"evil.example", "EVIL.EXAMPLE", "  Evil.Example  ",
		"http://evil.example", "https://evil.example/",
	} {
		got, err := r.Lookup(ctx, tenant, "domain", written)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", written, err)
		}
		if got == nil {
			t.Errorf("%q did not match the indicator", written)
		}
	}

	// A value that is not the indicator does not match.
	for _, other := range []string{"evil.example.com", "notevil.example", "evil", ""} {
		got, err := r.Lookup(ctx, tenant, "domain", other)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", other, err)
		}
		if got != nil {
			t.Errorf("%q matched the indicator", other)
		}
	}
}

// An indicator that is withdrawn or has expired stops matching. A feed's whole
// value is that yesterday's indicator stops blocking today's traffic.
func TestAWithdrawnOrExpiredIndicatorStopsMatching(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// Expired by its own validity window.
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "ip", Value: "203.0.113.9", Severity: "HIGH", ValidUntil: &past,
	}); err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.9"); err != nil || got != nil {
		t.Errorf("an expired indicator still matches: %v / %v", got, err)
	}

	// Still valid for another hour: matches.
	future := time.Now().UTC().Add(time.Hour)
	if _, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "ip", Value: "203.0.113.10", Severity: "HIGH", ValidUntil: &future,
	}); err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.10"); err != nil || got == nil {
		t.Errorf("an indicator valid for another hour does not match: %v / %v", got, err)
	}

	// The sweep deactivates what has expired and leaves the rest alone.
	n, err := r.DeactivateExpired(ctx)
	if err != nil {
		t.Fatalf("DeactivateExpired: %v", err)
	}
	if n < 1 {
		t.Errorf("the sweep deactivated %d indicators, want at least the expired one", n)
	}
	if got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.10"); err != nil || got == nil {
		t.Errorf("the sweep deactivated an indicator that is still valid: %v / %v", got, err)
	}
}

// A hit is counted on the indicator and recorded as its own row, which is what
// makes a match explicable afterwards: which value matched, in which field.
func TestAHitIsCountedAndRecorded(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	ind := ioc(t, r, tenant, "ip", "203.0.113.20")
	if ind.HitCount != 0 || ind.LastHitAt != nil {
		t.Errorf("a fresh indicator has %d hits at %v", ind.HitCount, ind.LastHitAt)
	}

	event := uuid.New()
	for i := 0; i < 2; i++ {
		if err := r.RecordHit(ctx, tenant, ind.ID, &model.IOCHit{
			ID: uuid.New(), SourceEventID: &event,
			MatchedValue: "203.0.113.20", MatchedField: "ip_source",
			Severity: "HIGH", AutoBlocked: i == 1,
		}); err != nil {
			t.Fatalf("RecordHit %d: %v", i, err)
		}
	}

	got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.20")
	if err != nil || got == nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.HitCount != 2 {
		t.Errorf("hit_count is %d after two hits", got.HitCount)
	}
	if got.LastHitAt == nil {
		t.Error("last_hit_at was not set")
	}

	hits, err := r.ListHits(ctx, tenant, 50)
	if err != nil {
		t.Fatalf("ListHits: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("%d hit records, want 2", len(hits))
	}
	if hits[0].MatchedField != "ip_source" || hits[0].MatchedValue != "203.0.113.20" {
		t.Errorf("the hit does not say what matched: %+v", hits[0])
	}
	if hits[0].SourceEventID == nil || *hits[0].SourceEventID != event {
		t.Errorf("the hit does not name the event it came from: %v", hits[0].SourceEventID)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// One customer's feed never matches another customer's traffic. A shared
// indicator table would mean one bank's private intelligence silently driving
// another's blocking decisions.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	ind := ioc(t, r, mine, "domain", "evil.example")
	feed, err := r.CreateFeed(ctx, mine, &model.CreateFeedRequest{
		Name: "Mon flux", FeedType: "misp", URL: "https://misp.banque.example",
		TLP: 2, Confidence: 70, PollIntervalS: 3600,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	actor, err := r.CreateThreatActor(ctx, mine, &model.CreateThreatActorRequest{
		Name: "Lazarus", Motivation: "financial", Sophistication: "advanced",
		TargetsSWIFT: true, MitreGroups: []string{"G0032"},
	})
	if err != nil {
		t.Fatalf("CreateThreatActor: %v", err)
	}

	// The lookup is the one that matters: this is what the pipeline calls on
	// every event.
	if got, err := r.Lookup(ctx, theirs, "domain", "evil.example"); err != nil || got != nil {
		t.Errorf("the neighbour's traffic matched our indicator: %v / %v", got, err)
	}
	if got, err := r.GetFeed(ctx, theirs, feed.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the feed: %v / %v", got, err)
	}
	if rows, err := r.ListFeeds(ctx, theirs); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d feeds: %v", len(rows), err)
	}
	if rows, total, err := r.ListIOCs(ctx, model.IOCFilter{TenantID: theirs, Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d indicators (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListThreatActors(ctx, theirs, false); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d actors: %v", len(rows), err)
	}
	if rows, err := r.ListHits(ctx, theirs, 50); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d hits: %v", len(rows), err)
	}
	// A filter with no tenant at all matches nothing rather than everything.
	if rows, total, err := r.ListIOCs(ctx, model.IOCFilter{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("a filter with no tenant listed %d indicators (total=%d): %v", len(rows), total, err)
	}

	// Writes
	if got, err := r.UpdateFeed(ctx, theirs, feed.ID, &model.UpdateFeedRequest{Enabled: boolp(false)}); err != nil || got != nil {
		t.Errorf("the neighbour disabled the feed: %v / %v", got, err)
	}
	if err := r.DeleteFeed(ctx, theirs, feed.ID); err == nil {
		t.Error("the neighbour deleted the feed")
	}
	if err := r.RecordHit(ctx, theirs, ind.ID, &model.IOCHit{
		ID: uuid.New(), MatchedValue: "evil.example", MatchedField: "domain", Severity: "HIGH",
	}); err == nil {
		// The insert succeeds under the neighbour's own tenant, which is their
		// own row to keep — but it must not have touched our indicator.
		if got, err := r.Lookup(ctx, mine, "domain", "evil.example"); err != nil || got == nil {
			t.Fatalf("Lookup: %v", err)
		} else if got.HitCount != 0 {
			t.Errorf("the neighbour's hit was counted on our indicator: %d", got.HitCount)
		}
	}

	// Ours is untouched.
	live, err := r.GetFeed(ctx, mine, feed.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the feed: %v", err)
	}
	if !live.Enabled {
		t.Error("the neighbour disabled our feed")
	}
	if got, err := r.Lookup(ctx, mine, "domain", "evil.example"); err != nil || got == nil {
		t.Errorf("our own indicator stopped matching: %v / %v", got, err)
	}
	_ = actor
}

// ─── Feeds ───────────────────────────────────────────────────────────────────

// A feed records that it was polled, and an error on a poll is kept with a
// count — which is how an operator sees that a paid feed has been failing for
// a week.
func TestAFeedRecordsItsPollsAndItsFailures(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	feed, err := r.CreateFeed(ctx, tenant, &model.CreateFeedRequest{
		Name: "Flux", FeedType: "taxii", URL: "https://taxii.example",
		ApiKeyRef: "kv/ti/taxii", CollectionID: "collection-1",
		TLP: 2, Confidence: 70, PollIntervalS: 900,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if feed.LastPolledAt != nil || feed.ErrorCount != 0 || feed.LastError != "" {
		t.Errorf("a fresh feed is %+v", feed)
	}
	if !feed.Enabled {
		t.Error("a fresh feed is disabled")
	}

	if err := r.MarkFeedPolled(ctx, feed.ID, 1200); err != nil {
		t.Fatalf("MarkFeedPolled: %v", err)
	}
	polled, err := r.GetFeed(ctx, tenant, feed.ID)
	if err != nil || polled == nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if polled.LastPolledAt == nil {
		t.Error("last_polled_at was not set")
	}
	if polled.LastIOCCount != 1200 {
		t.Errorf("last_ioc_count is %d, want 1200", polled.LastIOCCount)
	}

	if err := r.MarkFeedError(ctx, feed.ID, "401 depuis le fournisseur"); err != nil {
		t.Fatalf("MarkFeedError: %v", err)
	}
	failing, err := r.GetFeed(ctx, tenant, feed.ID)
	if err != nil || failing == nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if failing.ErrorCount != 1 {
		t.Errorf("error_count is %d after one failure", failing.ErrorCount)
	}
	if failing.LastError == "" {
		t.Error("the failure left no message, so nobody can tell why the feed is dry")
	}

	// A feed with no URL and no key reference is legitimate — an internal feed
	// is fed by the platform itself — and must read back.
	internal, err := r.CreateFeed(ctx, tenant, &model.CreateFeedRequest{
		Name: "Interne", FeedType: "internal", TLP: 0, Confidence: 100,
	})
	if err != nil {
		t.Fatalf("CreateFeed with nothing optional: %v", err)
	}
	if got, err := r.GetFeed(ctx, tenant, internal.ID); err != nil || got == nil {
		t.Fatalf("GetFeed: %+v / %v", got, err)
	}
	if rows, err := r.ListFeeds(ctx, tenant); err != nil || len(rows) != 2 {
		t.Fatalf("ListFeeds gave %d rows: %v", len(rows), err)
	}

	// Deleting a feed leaves its indicators: an indicator seen once was seen,
	// whatever happened to the source afterwards.
	ind := ioc(t, r, tenant, "ip", "203.0.113.30")
	if _, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "ip", Value: "203.0.113.31", FeedID: &feed.ID, Severity: "HIGH",
	}); err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if err := r.DeleteFeed(ctx, tenant, feed.ID); err != nil {
		t.Fatalf("DeleteFeed: %v", err)
	}
	if got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.31"); err != nil || got == nil {
		t.Errorf("deleting the feed took its indicator: %v / %v", got, err)
	}
	_ = ind
}

// A threat actor reads back, including the banking-specific flags the product
// exists for, and the banking-only listing uses them.
func TestAThreatActorKeepsItsBankingFlags(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	swift, err := r.CreateThreatActor(ctx, tenant, &model.CreateThreatActorRequest{
		Name: "Lazarus", Aliases: []string{"APT38", "Hidden Cobra"},
		Description: "Vol de fonds par SWIFT", Motivation: "financial",
		Sophistication: "advanced", OriginCountry: "KP",
		MitreGroups: []string{"G0032"}, TTPs: []string{"T1071"},
		TargetsSWIFT: true, TargetsCBS: true,
		Tags: []string{"banque"}, StixID: "intrusion-set--1",
	})
	if err != nil {
		t.Fatalf("CreateThreatActor: %v", err)
	}
	if !swift.TargetsSWIFT || !swift.TargetsCBS || swift.TargetsATM {
		t.Errorf("the flags are %v/%v/%v", swift.TargetsCBS, swift.TargetsSWIFT, swift.TargetsATM)
	}
	if len(swift.Aliases) != 2 {
		t.Errorf("aliases are %v", swift.Aliases)
	}

	// An actor with nothing optional set.
	if _, err := r.CreateThreatActor(ctx, tenant, &model.CreateThreatActorRequest{
		Name: "Inconnu",
	}); err != nil {
		t.Fatalf("CreateThreatActor with nothing optional: %v", err)
	}

	all, err := r.ListThreatActors(ctx, tenant, false)
	if err != nil {
		t.Fatalf("ListThreatActors: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("%d actors, want 2", len(all))
	}
	banking, err := r.ListThreatActors(ctx, tenant, true)
	if err != nil {
		t.Fatalf("ListThreatActors(bankingOnly): %v", err)
	}
	if len(banking) != 1 || banking[0].Name != "Lazarus" {
		t.Fatalf("%d banking actors, want only the one targeting SWIFT", len(banking))
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	ioc(t, r, tenant, "domain", "evil.example")
	ioc(t, r, tenant, "ip", "203.0.113.40")
	hot := ioc(t, r, tenant, "hash_sha256", "ab"+"cd"+"ef00")
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "ip", Value: "203.0.113.41", Severity: "LOW", ValidUntil: &past,
	}); err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if _, err := r.DeactivateExpired(ctx); err != nil {
		t.Fatalf("DeactivateExpired: %v", err)
	}

	if _, err := r.CreateFeed(ctx, tenant, &model.CreateFeedRequest{
		Name: "Actif", FeedType: "misp", TLP: 2, Confidence: 70,
	}); err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	off, err := r.CreateFeed(ctx, tenant, &model.CreateFeedRequest{
		Name: "Coupé", FeedType: "csv", TLP: 2, Confidence: 70,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if _, err := r.UpdateFeed(ctx, tenant, off.ID, &model.UpdateFeedRequest{Enabled: boolp(false)}); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := r.RecordHit(ctx, tenant, hot.ID, &model.IOCHit{
			ID: uuid.New(), MatchedValue: "abcdef00", MatchedField: "hash",
			Severity: "HIGH",
		}); err != nil {
			t.Fatalf("RecordHit: %v", err)
		}
	}

	if _, err := r.CreateThreatActor(ctx, tenant, &model.CreateThreatActorRequest{
		Name: "Lazarus", TargetsSWIFT: true,
	}); err != nil {
		t.Fatalf("CreateThreatActor: %v", err)
	}
	if _, err := r.CreateThreatActor(ctx, tenant, &model.CreateThreatActorRequest{
		Name: "Générique",
	}); err != nil {
		t.Fatalf("CreateThreatActor: %v", err)
	}

	// The neighbour's intelligence, which must change nothing below.
	ioc(t, r, other, "domain", "voisin.example")

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_iocs", stats.TotalIOCs, 4},
		{"active_iocs", stats.ActiveIOCs, 3},
		{"total_feeds", stats.TotalFeeds, 2},
		{"enabled_feeds", stats.EnabledFeeds, 1},
		{"hits_last_24h", stats.HitsLast24h, 3},
		{"hits_last_7d", stats.HitsLast7d, 3},
		{"threat_actors", stats.ThreatActors, 2},
		{"banking_threats", stats.BankingThreats, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if stats.ByType["domain"] != 1 || stats.ByType["ip"] != 1 || stats.ByType["hash_sha256"] != 1 {
		t.Errorf("by_type is %v", stats.ByType)
	}
	if stats.BySeverity["HIGH"] != 3 {
		t.Errorf("by_severity is %v", stats.BySeverity)
	}
	if len(stats.TopIOCs) == 0 || stats.TopIOCs[0].HitCount != 3 {
		t.Errorf("the most-hit indicator is %+v", stats.TopIOCs)
	}
}

func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.TotalIOCs != 0 || stats.TotalFeeds != 0 || stats.ThreatActors != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	if stats.ByType == nil || stats.BySeverity == nil {
		t.Error("the breakdown maps came back nil rather than empty")
	}
	if got, err := r.Lookup(ctx, tenant, "ip", "203.0.113.99"); err != nil || got != nil {
		t.Errorf("a lookup on an empty tenant gave %v / %v", got, err)
	}
	if hits, err := r.ListHits(ctx, tenant, 50); err != nil || len(hits) != 0 {
		t.Errorf("%d hits on an empty tenant: %v", len(hits), err)
	}
}

// ─── Filters ─────────────────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	feed, err := r.CreateFeed(ctx, tenant, &model.CreateFeedRequest{
		Name: "Flux", FeedType: "misp", TLP: 2, Confidence: 70,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	ioc(t, r, tenant, "domain", "evil.example")
	if _, err := r.UpsertIOC(ctx, tenant, &model.CreateIOCRequest{
		IOCType: "ip", Value: "203.0.113.50", Severity: "LOW", FeedID: &feed.ID,
	}); err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}

	yes := true
	for _, c := range []struct {
		what   string
		filter model.IOCFilter
		want   int
	}{
		{"all", model.IOCFilter{TenantID: tenant, Limit: 50}, 2},
		{"by type", model.IOCFilter{TenantID: tenant, IOCType: "domain", Limit: 50}, 1},
		{"by severity", model.IOCFilter{TenantID: tenant, Severity: "LOW", Limit: 50}, 1},
		{"by feed", model.IOCFilter{TenantID: tenant, FeedID: &feed.ID, Limit: 50}, 1},
		{"active only", model.IOCFilter{TenantID: tenant, IsActive: &yes, Limit: 50}, 2},
		{"searching for a value", model.IOCFilter{TenantID: tenant, Search: "evil", Limit: 50}, 1},
		{"searching for nothing that is there", model.IOCFilter{TenantID: tenant, Search: "zzz", Limit: 50}, 0},
	} {
		rows, total, err := r.ListIOCs(ctx, c.filter)
		if err != nil {
			t.Fatalf("ListIOCs %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
}

func boolp(b bool) *bool { return &b }
