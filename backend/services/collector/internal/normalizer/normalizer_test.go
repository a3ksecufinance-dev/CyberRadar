package normalizer

import (
	"strings"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
)

// The six format parsers.
//
// This is the platform's front door: every event in every dashboard, every
// correlation rule and every behavioural baseline is whatever came out of these
// four hundred lines. A parser that silently drops a field does not fail — it
// produces an event that is merely wrong, and nothing downstream can tell.
//
// So what is asserted here is not that parsing succeeds. It is that each field
// lands where it belongs, that a sender's own timestamp is preferred to the
// time of arrival, and that a line the parser cannot read is refused rather
// than turned into a plausible-looking event.

const (
	tenant    = "11111111-1111-1111-1111-111111111111"
	connector = "22222222-2222-2222-2222-222222222222"
)

// receivedAt is a fixed arrival time, so a test about which timestamp wins can
// tell the two apart.
var receivedAt = time.Date(2026, time.March, 14, 9, 26, 53, 0, time.UTC)

func rawOf(format event.Format, sourceType, body string) event.RawEvent {
	return event.RawEvent{
		ID:          uuid.New(),
		TenantID:    tenant,
		ConnectorID: connector,
		Source:      "test-source",
		SourceType:  sourceType,
		Format:      format,
		ReceivedAt:  receivedAt,
		Raw:         body,
	}
}

func mustNormalize(t *testing.T, raw event.RawEvent) *event.NormalizedEvent {
	t.Helper()
	got, err := Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize(%s): %v\n%s", raw.Format, err, raw.Raw)
	}
	return got
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func port(p *uint16) int {
	if p == nil {
		return -1
	}
	return int(*p)
}

// ─── Lineage ─────────────────────────────────────────────────────────────────

// Every parser must carry the lineage through, whatever the format. Without it
// an event cannot be traced back to the connector that sent it, which is the
// first question asked about any surprising alert.
func TestEveryFormatCarriesItsLineage(t *testing.T) {
	for _, c := range []struct {
		format event.Format
		body   string
	}{
		{event.FormatJSON, `{"action":"login"}`},
		{event.FormatCEF, `CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.1`},
		{event.FormatSyslog, `<34>Oct 11 22:14:15 host sshd: failed`},
		{event.FormatLEEF, "LEEF:1.0|Vendor|Product|1.0|Login|src=10.0.0.1"},
		{event.FormatWinEvent, `{"EventId":4625,"Computer":"PC01"}`},
		{event.FormatCLF, `10.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326`},
	} {
		raw := rawOf(c.format, "firewall", c.body)
		got := mustNormalize(t, raw)

		if got.EventID == uuid.Nil {
			t.Errorf("%s: no event id", c.format)
		}
		if got.TenantID != tenant {
			t.Errorf("%s: tenant is %q, want %q", c.format, got.TenantID, tenant)
		}
		if got.ConnectorID != connector {
			t.Errorf("%s: connector is %q, want %q", c.format, got.ConnectorID, connector)
		}
		if got.RawEventID != raw.ID.String() {
			t.Errorf("%s: raw_event_id is %q, want %q", c.format, got.RawEventID, raw.ID)
		}
		if got.RawEvent != c.body {
			t.Errorf("%s: the raw event was not kept verbatim", c.format)
		}
		if got.SchemaVersion != 1 {
			t.Errorf("%s: schema version is %d", c.format, got.SchemaVersion)
		}
		if got.IngestedAt.IsZero() {
			t.Errorf("%s: ingested_at is zero", c.format)
		}
		// The IOC list is empty rather than nil: a nil serialises to null and
		// the enrichment step appends to it.
		if got.IOCMatched == nil {
			t.Errorf("%s: ioc_matched is nil rather than empty", c.format)
		}
	}
}

// A format nobody implemented is refused by name, not answered with an empty
// event.
func TestAnUnknownFormatIsRefused(t *testing.T) {
	_, err := Normalize(rawOf(event.Format("netflow"), "netflow", "whatever"))
	if err == nil {
		t.Fatal("netflow was accepted although no parser exists for it")
	}
	if !strings.Contains(err.Error(), "netflow") {
		t.Errorf("the error does not name the format: %v", err)
	}
}

// ─── JSON ────────────────────────────────────────────────────────────────────

func TestJSONMapsEveryFieldItDocuments(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatJSON, "iam", `{
		"timestamp": "2026-03-14T08:00:00Z",
		"action": "user.login",
		"category": "authentication",
		"severity": "HIGH",
		"outcome": "denied",
		"user_id": "u-1", "user_name": "alice", "user_email": "alice@banque.test",
		"asset_id": "a-1", "hostname": "poste-alice", "asset_type": "workstation",
		"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
		"src_port": 51000, "dst_port": 443,
		"risk_score": 7.5
	}`))

	if got.Action != "user.login" {
		t.Errorf("action is %q", got.Action)
	}
	if got.Category != event.CategoryIAM {
		t.Errorf("category is %q, want IAM for \"authentication\"", got.Category)
	}
	if got.Severity != event.SeverityHigh {
		t.Errorf("severity is %q", got.Severity)
	}
	if got.Outcome != event.OutcomeFailure {
		t.Errorf("outcome is %q, want failure for \"denied\"", got.Outcome)
	}
	if got.RiskScore != 7.5 {
		t.Errorf("risk_score is %v", got.RiskScore)
	}
	if !got.Timestamp.Equal(time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp is %s, want the sender's own", got.Timestamp)
	}
	for _, c := range []struct{ name, got, want string }{
		{"user_id", str(got.UserID), "u-1"},
		{"user_name", str(got.UserName), "alice"},
		{"user_email", str(got.UserEmail), "alice@banque.test"},
		{"asset_id", str(got.AssetID), "a-1"},
		{"hostname", str(got.AssetHostname), "poste-alice"},
		{"asset_type", str(got.AssetType), "workstation"},
		{"src_ip", str(got.IPSource), "10.0.0.5"},
		{"dst_ip", str(got.IPDestination), "10.0.0.9"},
	} {
		if c.got != c.want {
			t.Errorf("%s is %q, want %q", c.name, c.got, c.want)
		}
	}
	if port(got.PortSource) != 51000 || port(got.PortDest) != 443 {
		t.Errorf("ports are %d and %d", port(got.PortSource), port(got.PortDest))
	}
}

// An absent field is nil, not an empty string: the difference is whether the
// column is NULL or a row claiming the user is "".
func TestJSONLeavesAbsentFieldsNil(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatJSON, "iam", `{"action":"ping"}`))

	for _, c := range []struct {
		name string
		p    *string
	}{
		{"user_id", got.UserID}, {"user_name", got.UserName}, {"user_email", got.UserEmail},
		{"asset_id", got.AssetID}, {"hostname", got.AssetHostname}, {"asset_type", got.AssetType},
		{"src_ip", got.IPSource}, {"dst_ip", got.IPDestination},
	} {
		if c.p != nil {
			t.Errorf("%s came back as %q rather than nil", c.name, *c.p)
		}
	}
	if got.PortSource != nil || got.PortDest != nil {
		t.Error("a port of zero was recorded rather than left unset")
	}
	// No timestamp in the payload: the time of arrival stands in, rather than
	// a zero time.
	if !got.Timestamp.Equal(receivedAt) {
		t.Errorf("timestamp is %s, want the arrival time %s", got.Timestamp, receivedAt)
	}
	// And the defaults are the cautious ones.
	if got.Category != event.CategoryOther || got.Severity != event.SeverityLow ||
		got.Outcome != event.OutcomeUnknown {
		t.Errorf("the defaults are %q/%q/%q", got.Category, got.Severity, got.Outcome)
	}
}

// A payload that is not JSON is refused. It is the one format where a parse
// failure is unambiguous, and the DLQ exists for it.
func TestJSONRefusesWhatIsNotJSON(t *testing.T) {
	for _, body := range []string{"", "not json", `{"action":`, `{"src_port":"443"}`} {
		if _, err := Normalize(rawOf(event.FormatJSON, "iam", body)); err == nil {
			t.Errorf("%q was accepted as JSON", body)
		}
	}
}

// A timestamp the parser cannot read does not become a zero time: the arrival
// time stands in, because an event in year 0 is outside every query a customer
// will run.
func TestJSONKeepsTheArrivalTimeWhenTheStampIsUnreadable(t *testing.T) {
	for _, stamp := range []string{"", "14/03/2026", "yesterday", "1773475613"} {
		got := mustNormalize(t, rawOf(event.FormatJSON, "iam",
			`{"action":"x","timestamp":"`+stamp+`"}`))
		if !got.Timestamp.Equal(receivedAt) {
			t.Errorf("timestamp %q produced %s, want the arrival time", stamp, got.Timestamp)
		}
	}
}

// ─── CEF ─────────────────────────────────────────────────────────────────────

func TestCEFReadsItsHeaderAndExtensions(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatCEF, "firewall",
		`CEF:0|Fortinet|FortiGate|6.4|00013|Connexion refusée|8|rt=Mar 14 2026 08:00:00 src=10.0.0.5 spt=51000 dst=10.0.0.9 dpt=443 suser=alice dhost=srv-paie outcome=blocked`))

	if got.Action != "Connexion refusée" {
		t.Errorf("action is %q, want the CEF name", got.Action)
	}
	if got.Severity != event.SeverityHigh {
		t.Errorf("severity is %q, want high for a CEF 8", got.Severity)
	}
	if got.Category != event.CategoryNetwork {
		t.Errorf("category is %q, want network for a firewall", got.Category)
	}
	if got.Outcome != event.OutcomeFailure {
		t.Errorf("outcome is %q, want failure for \"blocked\"", got.Outcome)
	}
	if str(got.IPSource) != "10.0.0.5" || str(got.IPDestination) != "10.0.0.9" {
		t.Errorf("addresses are %s and %s", str(got.IPSource), str(got.IPDestination))
	}
	if port(got.PortSource) != 51000 || port(got.PortDest) != 443 {
		t.Errorf("ports are %d and %d", port(got.PortSource), port(got.PortDest))
	}
	if str(got.UserName) != "alice" || str(got.AssetHostname) != "srv-paie" {
		t.Errorf("user is %s on %s", str(got.UserName), str(got.AssetHostname))
	}
	if !got.Timestamp.Equal(time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp is %s, want the rt extension", got.Timestamp)
	}
}

// The CEF severity scale is 0-10 and the mapping has to hold at every boundary:
// a 7 that came out medium would silently demote a whole class of alert.
func TestCEFSeverityAtEveryBoundary(t *testing.T) {
	for _, c := range []struct {
		in   string
		want event.Severity
	}{
		{"0", event.SeverityLow},
		{"3", event.SeverityLow},
		{"4", event.SeverityMedium},
		{"6", event.SeverityMedium},
		{"7", event.SeverityHigh},
		{"8", event.SeverityHigh},
		{"9", event.SeverityCritical},
		{"10", event.SeverityCritical},
		// A sender that writes words rather than numbers falls back to the
		// textual mapping instead of defaulting to low.
		{"High", event.SeverityHigh},
		{"CRITICAL", event.SeverityCritical},
		{"", event.SeverityLow},
	} {
		got := mustNormalize(t, rawOf(event.FormatCEF, "firewall",
			"CEF:0|V|P|1|100|Nom|"+c.in+"|src=10.0.0.1"))
		if got.Severity != c.want {
			t.Errorf("CEF severity %q became %q, want %q", c.in, got.Severity, c.want)
		}
	}
}

func TestCEFRefusesWhatIsNotCEF(t *testing.T) {
	for _, body := range []string{
		"",
		"just a line",
		"CEF:0|only|three|fields",
		`{"action":"login"}`,
	} {
		if _, err := Normalize(rawOf(event.FormatCEF, "firewall", body)); err == nil {
			t.Errorf("%q was accepted as CEF", body)
		}
	}
}

// A header with no extensions is valid CEF and must not be refused — it is what
// a minimal sender emits.
func TestCEFAcceptsAHeaderWithNoExtensions(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatCEF, "edr", "CEF:0|V|P|1|100|Nom|5|"))
	if got.Action != "Nom" {
		t.Errorf("action is %q", got.Action)
	}
	if got.Category != event.CategorySecurity {
		t.Errorf("category is %q, want security for an EDR", got.Category)
	}
	if got.IPSource != nil {
		t.Errorf("src is %q although there were no extensions", *got.IPSource)
	}
}

// ─── Syslog ──────────────────────────────────────────────────────────────────

// An RFC 3164 message carries no year, and parsing its stamp on its own gives
// year 0000 — which puts the event outside every retention window and every
// dashboard range. The year comes from when the event was received.
func TestSyslogRFC3164GetsTheYearFromItsArrival(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatSyslog, "firewall",
		`<34>Mar 14 08:00:00 pare-feu01 sshd[1234]: Failed password for root`))

	if got.Timestamp.Year() != 2026 {
		t.Fatalf("timestamp is %s — an event in year %d is outside every query",
			got.Timestamp, got.Timestamp.Year())
	}
	if !got.Timestamp.Equal(time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp is %s, want 2026-03-14T08:00:00Z", got.Timestamp)
	}
	if str(got.AssetHostname) != "pare-feu01" {
		t.Errorf("hostname is %s", str(got.AssetHostname))
	}
	if !strings.Contains(got.Action, "Failed password") {
		t.Errorf("action is %q", got.Action)
	}
	if got.Severity != event.SeverityCritical {
		t.Errorf("severity is %q, want critical for PRI 34 (auth.crit)", got.Severity)
	}
}

// A message stamped December and received in January belongs to the previous
// year, not to the one that is eleven months away.
func TestSyslogRFC3164StepsBackOverTheNewYear(t *testing.T) {
	raw := rawOf(event.FormatSyslog, "firewall",
		`<38>Dec 31 23:59:58 pare-feu01 sshd: dernier message`)
	raw.ReceivedAt = time.Date(2026, time.January, 1, 0, 0, 3, 0, time.UTC)

	got := mustNormalize(t, raw)
	if got.Timestamp.Year() != 2025 || got.Timestamp.Month() != time.December {
		t.Fatalf("timestamp is %s, want 2025-12-31", got.Timestamp)
	}
}

// RFC 5424 puts the hostname in a different place from RFC 3164. Read
// positionally as a 3164 message, a 5424 one attributes the event to the
// application name instead of the host — so every event from a modern sender
// lands on the wrong asset.
func TestSyslogRFC5424PutsTheHostnameWhereItBelongs(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatSyslog, "iam",
		`<165>1 2026-03-14T08:00:00.123Z serveur-ad01 evntslog 1234 ID47 - Échec d'authentification`))

	if str(got.AssetHostname) != "serveur-ad01" {
		t.Errorf("hostname is %s, want serveur-ad01 (not the app name)", str(got.AssetHostname))
	}
	want := time.Date(2026, time.March, 14, 8, 0, 0, 123000000, time.UTC)
	if !got.Timestamp.Equal(want) {
		t.Errorf("timestamp is %s, want %s", got.Timestamp, want)
	}
	if got.Action != "Échec d'authentification" {
		t.Errorf("action is %q, want the message alone", got.Action)
	}
	if got.Category != event.CategorySecurity {
		t.Errorf("category is %q, want security for PRI 165 (local4)", got.Category)
	}
}

// The structured-data element sits between the header and the message, and a
// reader should see the message rather than the element.
func TestSyslogRFC5424DropsTheStructuredData(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{`<165>1 2026-03-14T08:00:00Z host app - ID47 [exampleSDID@32473 iut="3"] Un message`, "Un message"},
		{`<165>1 2026-03-14T08:00:00Z host app - ID47 [a@1 x="1"][b@2 y="2"] Deux éléments`, "Deux éléments"},
		{`<165>1 2026-03-14T08:00:00Z host app - ID47 - Pas d'élément`, "Pas d'élément"},
		{`<165>1 2026-03-14T08:00:00Z host app - ID47 [a@1 note="un ] crochet"] Crochet cité`, "Crochet cité"},
	} {
		got := mustNormalize(t, rawOf(event.FormatSyslog, "iam", c.line))
		if got.Action != c.want {
			t.Errorf("action is %q, want %q\n  %s", got.Action, c.want, c.line)
		}
	}
}

// The PRI carries both the severity and the facility, and the two are read from
// different bits of the same number.
func TestSyslogReadsSeverityAndFacilityFromThePRI(t *testing.T) {
	for _, c := range []struct {
		pri      int
		severity event.Severity
		category event.Category
	}{
		{0, event.SeverityCritical, event.CategoryOther},    // kern.emerg
		{34, event.SeverityCritical, event.CategoryIAM},     // auth.crit
		{35, event.SeverityHigh, event.CategoryIAM},         // auth.err
		{36, event.SeverityMedium, event.CategoryIAM},       // auth.warning
		{38, event.SeverityLow, event.CategoryIAM},          // auth.info
		{84, event.SeverityMedium, event.CategoryIAM},       // authpriv.warning
		{86, event.SeverityLow, event.CategoryIAM},          // authpriv.info
		{132, event.SeverityMedium, event.CategorySecurity}, // local0.warning
		{134, event.SeverityLow, event.CategorySecurity},    // local0.info
		{12, event.SeverityMedium, event.CategoryOther},     // user.warning
		{14, event.SeverityLow, event.CategoryOther},        // user.info
		{165, event.SeverityLow, event.CategorySecurity},    // local4.notice
	} {
		got := mustNormalize(t, rawOf(event.FormatSyslog, "firewall",
			"<"+itoa(c.pri)+">Mar 14 08:00:00 host app: message"))
		if got.Severity != c.severity {
			t.Errorf("PRI %d gave severity %q, want %q", c.pri, got.Severity, c.severity)
		}
		if got.Category != c.category {
			t.Errorf("PRI %d gave category %q, want %q", c.pri, got.Category, c.category)
		}
	}
}

// Syslog is accepted whatever it looks like: a device that sends something
// unparseable still sends something, and dropping it would lose the only record
// that the device spoke at all. What must not happen is a wrong timestamp.
func TestSyslogAcceptsWhatItCannotStructure(t *testing.T) {
	for _, body := range []string{
		"",
		"un message sans en-tête",
		"<999999999999>débordement",
		"<34>pas de date ici",
	} {
		got, err := Normalize(rawOf(event.FormatSyslog, "firewall", body))
		if err != nil {
			t.Fatalf("%q was refused: %v", body, err)
		}
		if got.Timestamp.Year() < 2000 {
			t.Errorf("%q produced a timestamp in year %d", body, got.Timestamp.Year())
		}
	}
}

// ─── LEEF ────────────────────────────────────────────────────────────────────

func TestLEEFReadsItsTabDelimitedExtensions(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatLEEF, "ids",
		"LEEF:1.0|Fortinet|FortiGate|6.4|Intrusion|src=10.0.0.5\tdst=10.0.0.9\tusrName=alice\tsev=HIGH"))

	if got.Action != "Intrusion" {
		t.Errorf("action is %q, want the LEEF event id", got.Action)
	}
	if str(got.IPSource) != "10.0.0.5" || str(got.IPDestination) != "10.0.0.9" {
		t.Errorf("addresses are %s and %s", str(got.IPSource), str(got.IPDestination))
	}
	if str(got.UserName) != "alice" {
		t.Errorf("user is %s", str(got.UserName))
	}
	if got.Severity != event.SeverityHigh {
		t.Errorf("severity is %q", got.Severity)
	}
	if got.Category != event.CategoryNetwork {
		t.Errorf("category is %q, want network for an IDS", got.Category)
	}
}

func TestLEEFRefusesWhatIsNotLEEF(t *testing.T) {
	for _, body := range []string{"", "LEEF", "LEEF:1.0|V|P|1", "CEF:0|V|P|1|100|N|5|"} {
		if _, err := Normalize(rawOf(event.FormatLEEF, "ids", body)); err == nil {
			t.Errorf("%q was accepted as LEEF", body)
		}
	}
}

// ─── Windows events ──────────────────────────────────────────────────────────

func TestWinEventMapsTheChannelToACategory(t *testing.T) {
	for _, c := range []struct {
		channel string
		want    event.Category
	}{
		{"Security", event.CategoryIAM},
		{"security", event.CategoryIAM},
		{"Microsoft-Windows-Security-Auditing", event.CategoryIAM},
		{"System", event.CategorySecurity},
		{"Application", event.CategorySecurity},
		{"Setup", event.CategoryOther},
	} {
		got := mustNormalize(t, rawOf(event.FormatWinEvent, "winevent",
			`{"EventId":4625,"Channel":"`+c.channel+`","Computer":"PC01"}`))
		if got.Category != c.want {
			t.Errorf("channel %q gave category %q, want %q", c.channel, got.Category, c.want)
		}
	}
}

func TestWinEventReadsTheFieldsAnAnalystNeeds(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatWinEvent, "winevent", `{
		"TimeCreated": "2026-03-14T08:00:00Z",
		"EventId": 4625,
		"Channel": "Security",
		"Computer": "PC-ALICE",
		"Level": "WARNING",
		"UserData": {"SubjectUserName":"SYSTEM","TargetUserName":"alice","IpAddress":"10.0.0.5"}
	}`))

	if got.Action != "EventID:4625" {
		t.Errorf("action is %q, want EventID:4625", got.Action)
	}
	if str(got.AssetHostname) != "PC-ALICE" {
		t.Errorf("hostname is %s", str(got.AssetHostname))
	}
	// The target user, not the subject: on a 4625 the subject is the machine
	// account and the target is whose password failed.
	if str(got.UserName) != "alice" {
		t.Errorf("user is %s, want the target user", str(got.UserName))
	}
	if str(got.IPSource) != "10.0.0.5" {
		t.Errorf("src is %s", str(got.IPSource))
	}
	if got.Severity != event.SeverityMedium {
		t.Errorf("severity is %q, want medium for WARNING", got.Severity)
	}
	if !got.Timestamp.Equal(time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp is %s", got.Timestamp)
	}
}

func TestWinEventRefusesWhatIsNotJSON(t *testing.T) {
	for _, body := range []string{"", "<Event><System/></Event>", `{"EventId":`} {
		if _, err := Normalize(rawOf(event.FormatWinEvent, "winevent", body)); err == nil {
			t.Errorf("%q was accepted as a Windows event", body)
		}
	}
}

// ─── Common Log Format ───────────────────────────────────────────────────────

func TestCLFReadsTheRequestAndTheStatus(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatCLF, "proxy",
		`10.0.0.5 - frank [14/Mar/2026:08:00:00 +0100] "GET /virements HTTP/1.1" 403 2326`))

	if str(got.IPSource) != "10.0.0.5" {
		t.Errorf("src is %s", str(got.IPSource))
	}
	if got.Action != "GET /virements" {
		t.Errorf("action is %q, want the method and path", got.Action)
	}
	if got.Severity != event.SeverityMedium {
		t.Errorf("severity is %q, want medium for a 403", got.Severity)
	}
	if got.Outcome != event.OutcomeFailure {
		t.Errorf("outcome is %q, want failure for a 403", got.Outcome)
	}
	if got.Category != event.CategoryNetwork {
		t.Errorf("category is %q, want network", got.Category)
	}
	// 08:00 in +0100 is 07:00 UTC: the offset has to be applied, or every
	// timeline is an hour out for every customer not on UTC.
	want := time.Date(2026, time.March, 14, 7, 0, 0, 0, time.UTC)
	if !got.Timestamp.Equal(want) {
		t.Errorf("timestamp is %s, want %s", got.Timestamp, want)
	}
}

// The status code decides both the severity and the outcome, and the two must
// agree: a 500 that reported success would hide every server failure.
func TestCLFStatusDecidesSeverityAndOutcome(t *testing.T) {
	for _, c := range []struct {
		code     int
		severity event.Severity
		outcome  event.Outcome
	}{
		{200, event.SeverityLow, event.OutcomeSuccess},
		{301, event.SeverityLow, event.OutcomeSuccess},
		{399, event.SeverityLow, event.OutcomeSuccess},
		{400, event.SeverityMedium, event.OutcomeFailure},
		{404, event.SeverityMedium, event.OutcomeFailure},
		{499, event.SeverityMedium, event.OutcomeFailure},
		{500, event.SeverityHigh, event.OutcomeFailure},
		{503, event.SeverityHigh, event.OutcomeFailure},
	} {
		got := mustNormalize(t, rawOf(event.FormatCLF, "proxy",
			`10.0.0.5 - - [14/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" `+itoa(c.code)+` 10`))
		if got.Severity != c.severity {
			t.Errorf("status %d gave severity %q, want %q", c.code, got.Severity, c.severity)
		}
		if got.Outcome != c.outcome {
			t.Errorf("status %d gave outcome %q, want %q", c.code, got.Outcome, c.outcome)
		}
	}
}

// A line too short to be CLF is kept as an action rather than refused: a web
// server that logs something unusual still logged it.
func TestCLFKeepsAShortLineAsItIs(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatCLF, "proxy", "10.0.0.5 - -"))
	if got.Action != "10.0.0.5 - -" {
		t.Errorf("action is %q, want the line itself", got.Action)
	}
	if !got.Timestamp.Equal(receivedAt) {
		t.Errorf("timestamp is %s, want the arrival time", got.Timestamp)
	}
}

// ─── The mapping tables ──────────────────────────────────────────────────────

// These three functions decide what every dashboard counts, so each alias a
// sender might use is worth a line.
func TestMapSeverity(t *testing.T) {
	for in, want := range map[string]event.Severity{
		"CRITICAL": event.SeverityCritical, "critical": event.SeverityCritical,
		"EMERGENCY": event.SeverityCritical, "ALERT": event.SeverityCritical,
		"FATAL": event.SeverityCritical, "10": event.SeverityCritical, "9": event.SeverityCritical,
		"HIGH": event.SeverityHigh, "ERROR": event.SeverityHigh, "8": event.SeverityHigh,
		"MEDIUM": event.SeverityMedium, "WARN": event.SeverityMedium,
		"WARNING": event.SeverityMedium, "  warning  ": event.SeverityMedium,
		"LOW": event.SeverityLow, "INFO": event.SeverityLow, "DEBUG": event.SeverityLow,
		"": event.SeverityLow, "inconnu": event.SeverityLow,
	} {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapCategory(t *testing.T) {
	for in, want := range map[string]event.Category{
		"security": event.CategorySecurity, "SECURITY": event.CategorySecurity,
		"fraud": event.CategoryFraud, "network": event.CategoryNetwork,
		"iam": event.CategoryIAM, "identity": event.CategoryIAM,
		"authentication": event.CategoryIAM, "authorization": event.CategoryIAM,
		"compliance":  event.CategoryCompliance,
		"transaction": event.CategoryTransaction, "payment": event.CategoryTransaction,
		"": event.CategoryOther, "autre chose": event.CategoryOther,
	} {
		if got := mapCategory(in); got != want {
			t.Errorf("mapCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapOutcome(t *testing.T) {
	for in, want := range map[string]event.Outcome{
		"success": event.OutcomeSuccess, "allow": event.OutcomeSuccess,
		"allowed": event.OutcomeSuccess, "permit": event.OutcomeSuccess,
		"permitted": event.OutcomeSuccess, "SUCCESS": event.OutcomeSuccess,
		"failure": event.OutcomeFailure, "fail": event.OutcomeFailure,
		"deny": event.OutcomeFailure, "denied": event.OutcomeFailure,
		"block": event.OutcomeFailure, "blocked": event.OutcomeFailure,
		"": event.OutcomeUnknown, "peut-être": event.OutcomeUnknown,
	} {
		if got := mapOutcome(in); got != want {
			t.Errorf("mapOutcome(%q) = %q, want %q", in, got, want)
		}
	}
}

// The source type is what CEF and LEEF fall back on for a category, since
// neither format carries one.
func TestCategoryFromSourceType(t *testing.T) {
	for in, want := range map[string]event.Category{
		"firewall": event.CategoryNetwork, "FIREWALL": event.CategoryNetwork,
		"ids": event.CategoryNetwork, "ips": event.CategoryNetwork,
		"proxy": event.CategoryNetwork, "dns": event.CategoryNetwork,
		"vpn": event.CategoryNetwork, "netflow": event.CategoryNetwork,
		"iam": event.CategoryIAM, "pam": event.CategoryIAM, "mfa": event.CategoryIAM,
		"sso": event.CategoryIAM, "ldap": event.CategoryIAM, "ad": event.CategoryIAM,
		"edr": event.CategorySecurity, "av": event.CategorySecurity,
		"dlp": event.CategorySecurity, "siem": event.CategorySecurity,
		"cbs": event.CategoryTransaction, "banking": event.CategoryTransaction,
		"payment": event.CategoryTransaction, "atm": event.CategoryTransaction,
		"swift": event.CategoryTransaction, "monetique": event.CategoryTransaction,
		"": event.CategoryOther, "machine à café": event.CategoryOther,
	} {
		if got := categoryFromSourceType(in); got != want {
			t.Errorf("categoryFromSourceType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStrPtr(t *testing.T) {
	if strPtr("") != nil {
		t.Error("an empty string became a pointer to an empty string")
	}
	if p := strPtr("x"); p == nil || *p != "x" {
		t.Errorf("strPtr(\"x\") = %v", p)
	}
}

// itoa keeps the tables above readable without importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ─── CEF extensions, which are not whitespace-delimited ──────────────────────

// A CEF value may contain spaces: rt and msg both normally do. Splitting the
// extensions on whitespace kept only the first word of each, which threw away
// the event's own timestamp and its message while appearing to parse.
func TestCEFExtensionValuesMayContainSpaces(t *testing.T) {
	got := mustNormalize(t, rawOf(event.FormatCEF, "firewall",
		`CEF:0|Fortinet|FortiGate|6.4|00013||5|rt=Mar 14 2026 08:00:00 src=10.0.0.5 msg=Connexion refusée par la règle 12 dhost=srv-paie`))

	if !got.Timestamp.Equal(time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("timestamp is %s, want the rt extension", got.Timestamp)
	}
	if got.Action != "Connexion refusée par la règle 12" {
		t.Errorf("action is %q, want the whole msg", got.Action)
	}
	if str(got.IPSource) != "10.0.0.5" {
		t.Errorf("src is %s — a key after a multi-word value was lost", str(got.IPSource))
	}
	if str(got.AssetHostname) != "srv-paie" {
		t.Errorf("dhost is %s — the last key was lost", str(got.AssetHostname))
	}
}

// rt is written either in the textual form the specification gives or as
// milliseconds since the epoch, depending on the sender. Accepting one and
// ignoring the other stamps half the senders' events with their arrival time.
func TestCEFAcceptsBothShapesOfRT(t *testing.T) {
	want := time.Date(2026, time.March, 14, 8, 0, 0, 0, time.UTC)
	for _, rt := range []string{
		"Mar 14 2026 08:00:00",
		"Mar 14 2026 08:00:00 UTC",
		"Mar 14 2026 08:00:00.000",
		"1773475200000", // milliseconds
		"1773475200",    // seconds, which some senders send regardless
		"2026-03-14T08:00:00Z",
	} {
		got := mustNormalize(t, rawOf(event.FormatCEF, "firewall",
			"CEF:0|V|P|1|100|Nom|5|rt="+rt))
		if !got.Timestamp.Equal(want) {
			t.Errorf("rt=%q gave %s, want %s", rt, got.Timestamp, want)
		}
	}

	// An unreadable rt leaves the arrival time standing rather than producing
	// a zero.
	got := mustNormalize(t, rawOf(event.FormatCEF, "firewall",
		"CEF:0|V|P|1|100|Nom|5|rt=la semaine dernière"))
	if !got.Timestamp.Equal(receivedAt) {
		t.Errorf("an unreadable rt gave %s, want the arrival time", got.Timestamp)
	}
}

// The specification escapes an = inside a value as \=, and that is not the
// start of a new pair.
func TestCEFKeepsAnEscapedEqualsInsideItsValue(t *testing.T) {
	ext := parseCEFExtensions(`src=10.0.0.5 msg=filtre a\=b appliqué dhost=srv`)
	for _, c := range []struct{ k, want string }{
		{"src", "10.0.0.5"},
		{"msg", "filtre a=b appliqué"},
		{"dhost", "srv"},
	} {
		if got := ext[c.k]; got != c.want {
			t.Errorf("%s is %q, want %q", c.k, got, c.want)
		}
	}
	if len(ext) != 3 {
		t.Errorf("%d pairs were read, want 3: %v", len(ext), ext)
	}
}

// A value containing a word with an = in it, unescaped, is the sender's
// mistake; what matters is that it does not swallow the following keys.
func TestCEFExtensionsAreRobustToOddInput(t *testing.T) {
	for _, c := range []struct {
		ext  string
		key  string
		want string
	}{
		{"", "src", ""},
		{"=novalue src=10.0.0.1", "src", "10.0.0.1"},
		{"src=", "src", ""},
		{"  src=10.0.0.1  ", "src", "10.0.0.1"},
		{"src=10.0.0.1 src=10.0.0.2", "src", "10.0.0.2"}, // the last wins
	} {
		if got := parseCEFExtensions(c.ext)[c.key]; got != c.want {
			t.Errorf("parseCEFExtensions(%q)[%q] = %q, want %q", c.ext, c.key, got, c.want)
		}
	}
}
