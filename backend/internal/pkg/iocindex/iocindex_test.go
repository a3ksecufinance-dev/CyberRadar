package iocindex

import (
	"testing"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
)

func strp(s string) *string { return &s }

// The index and the threat intelligence repository must normalise identically.
// A lookup normalised differently from the stored value misses every time, and
// the miss is silent: "not a known indicator" reads exactly like a clean event.
func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		iocType, in, want string
	}{
		{TypeIP, " 198.51.100.23 ", "198.51.100.23"},
		{TypeDomain, "HTTPS://Evil.Example/", "evil.example"},
		{TypeDomain, "http://evil.example", "evil.example"},
		{TypeURL, "HTTPS://Evil.Example/Path/", "evil.example/path"},
		{TypeEmail, "Someone@Evil.Example", "someone@evil.example"},
		{TypeHashSHA256, "  ABCDEF  ", "abcdef"},
		// A scheme is stripped only where the stored form strips it.
		{TypeEmail, "https://not-a-url", "https://not-a-url"},
	} {
		if got := Normalize(tc.iocType, tc.in); got != tc.want {
			t.Errorf("Normalize(%q, %q) = %q, want %q", tc.iocType, tc.in, got, tc.want)
		}
	}
}

// A private address is never in a feed, and it is the most common value on the
// wire. Looking it up on every event would be the single most frequent wasted
// lookup in the system.
func TestPrivateAddressesAreNotCandidates(t *testing.T) {
	ev := &event.NormalizedEvent{
		IPSource:      strp("10.30.2.21"),
		IPDestination: strp("198.51.100.23"),
	}
	got := Candidates(ev)
	if len(got) != 1 {
		t.Fatalf("%d candidates, want 1: %#v", len(got), got)
	}
	if got[0].Value != "198.51.100.23" || got[0].Field != "ip_destination" {
		t.Errorf("candidate = %#v, want the public destination", got[0])
	}
}

// The same address under two fields is one lookup and one hit, not two.
func TestTheSameValueTwiceIsOneCandidate(t *testing.T) {
	ev := &event.NormalizedEvent{
		UserName:  strp("tresorerie@invoice-portal.example.org"),
		UserEmail: strp("Tresorerie@Invoice-Portal.Example.org"),
	}
	got := Candidates(ev)
	if len(got) != 1 {
		t.Fatalf("%d candidates, want 1: %#v", len(got), got)
	}
}

// Hashes, domains and URLs live in the raw payload and nowhere else in the
// schema — and they are most of what a feed is made of.
func TestCandidatesReadTheRawPayload(t *testing.T) {
	ev := &event.NormalizedEvent{
		RawEvent: `{"action":"process_exec",
		            "file_hash_sha256":"9F2B6C1D",
		            "dns_query":"update-swift-secure.example",
		            "url":"https://update-swift-secure.example/patch/win32.bin"}`,
	}
	byType := map[string]string{}
	for _, c := range Candidates(ev) {
		byType[c.Type] = c.Value
	}
	for _, want := range []string{TypeHashSHA256, TypeDomain, TypeURL} {
		if byType[want] == "" {
			t.Errorf("no %s candidate came out of the payload: %v", want, byType)
		}
	}
}

// A raw payload that is not JSON — syslog, CEF — must cost nothing beyond the
// check, and must not produce candidates out of its text.
func TestANonJSONPayloadYieldsNothing(t *testing.T) {
	ev := &event.NormalizedEvent{
		RawEvent: `<134>Sep 29 16:00:00 host sshd[1]: Accepted password for root from 198.51.100.23`,
	}
	if got := Candidates(ev); len(got) != 0 {
		t.Errorf("%d candidates from a syslog line: %#v", len(got), got)
	}
}

// ─── Snapshot ────────────────────────────────────────────────────────────────

func snapshotWith(tenantID uuid.UUID, entries map[string]Entry) *Snapshot {
	byKey := make(map[string]Entry, len(entries))
	for value, e := range entries {
		byKey[key(tenantID, e.Type, Normalize(e.Type, value))] = e
	}
	return &Snapshot{byKey: byKey}
}

func TestLookupIsNormalisedOnBothSides(t *testing.T) {
	tenant := uuid.New()
	snap := snapshotWith(tenant, map[string]Entry{
		"Evil.Example": {ID: uuid.New(), Type: TypeDomain, Severity: "HIGH"},
	})

	if _, ok := snap.Lookup(tenant, TypeDomain, "https://EVIL.example/"); !ok {
		t.Error("a stored value did not match the same value written differently")
	}
	if _, ok := snap.Lookup(tenant, TypeDomain, "harmless.example"); ok {
		t.Error("an unknown domain matched")
	}
}

// One process serves every tenant. An indicator belonging to one customer must
// not raise an alert in another's estate — which a key without the tenant in
// it would do.
func TestAnIndicatorIsConfinedToItsTenant(t *testing.T) {
	mine, theirs := uuid.New(), uuid.New()
	snap := snapshotWith(mine, map[string]Entry{
		"198.51.100.23": {ID: uuid.New(), Type: TypeIP, Severity: "CRITICAL"},
	})

	if _, ok := snap.Lookup(mine, TypeIP, "198.51.100.23"); !ok {
		t.Fatal("the owning tenant did not match its own indicator")
	}
	if _, ok := snap.Lookup(theirs, TypeIP, "198.51.100.23"); ok {
		t.Error("another tenant matched an indicator that is not theirs")
	}
}

func TestMatchReportsTheFieldItCameFrom(t *testing.T) {
	tenant := uuid.New()
	snap := snapshotWith(tenant, map[string]Entry{
		"198.51.100.23": {ID: uuid.New(), Type: TypeIP, Severity: "CRITICAL",
			MitreTechnique: "T1071.001", ThreatActor: "Lazarus Group"},
	})

	ev := &event.NormalizedEvent{
		IPSource:      strp("10.40.3.41"),
		IPDestination: strp("198.51.100.23"),
	}
	hits := snap.Match(tenant, Candidates(ev))
	if len(hits) != 1 {
		t.Fatalf("%d hits, want 1", len(hits))
	}
	if hits[0].Candidate.Field != "ip_destination" {
		t.Errorf("field = %q, want ip_destination", hits[0].Candidate.Field)
	}
	if hits[0].Entry.ThreatActor != "Lazarus Group" {
		t.Errorf("the attribution did not come back: %#v", hits[0].Entry)
	}
	// The label has to say where it was found: a bare value leaves an analyst
	// asking which field of which event.
	if want := "ip:198.51.100.23@ip_destination"; hits[0].Label() != want {
		t.Errorf("Label() = %q, want %q", hits[0].Label(), want)
	}
}

// A nil snapshot is what a lookup gets before the first load, and it must
// answer rather than panic on the ingest path.
func TestANilSnapshotAnswers(t *testing.T) {
	var snap *Snapshot
	if _, ok := snap.Lookup(uuid.New(), TypeIP, "198.51.100.23"); ok {
		t.Error("a nil snapshot matched something")
	}
	if snap.Size() != 0 || snap.Age() != 0 || snap.Truncated() {
		t.Error("a nil snapshot reported state it does not have")
	}
	if hits := snap.Match(uuid.New(), []Candidate{{Type: TypeIP, Value: "x"}}); hits != nil {
		t.Error("a nil snapshot produced hits")
	}
}
