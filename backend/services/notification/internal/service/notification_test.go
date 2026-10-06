package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/notification/internal/model"
)

// The notification service: the first test this service has ever had.
//
// It needs no database and no broker — it is an HTTP client — so what is
// exercised here is the whole of it, against real servers started by the test.
//
// Two things make it worth testing carefully. It is the service that tells a
// bank's on-call that something is burning, so a payload the other end rejects
// is a missed alert; and its own idea of success is "not every channel failed",
// which means a caller can be told a notification was sent when most of its
// recipients never got it.

// recorder is a server that keeps what it was sent.
type recorder struct {
	mu     sync.Mutex
	status int
	calls  []map[string]any
	bodies []string
	server *httptest.Server
}

func newRecorder(t *testing.T, status int) *recorder {
	t.Helper()
	r := &recorder{status: status}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.bodies = append(r.bodies, string(body))
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		r.calls = append(r.calls, parsed)
		if req.Header.Get("Content-Type") != "application/json" {
			r.calls[len(r.calls)-1] = map[string]any{"__wrong_content_type": req.Header.Get("Content-Type")}
		}
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recorder) last() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return nil
	}
	return r.calls[len(r.calls)-1]
}

func (r *recorder) lastBody() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return ""
	}
	return r.bodies[len(r.bodies)-1]
}

func svc() *NotificationService {
	s := NewNotificationService(zerolog.New(io.Discard))
	s.httpClient = &http.Client{Timeout: 2 * time.Second}
	return s
}

func alert(channels ...model.ChannelConfig) *model.SendNotificationRequest {
	return &model.SendNotificationRequest{
		TenantID:     "11111111-1111-1111-1111-111111111111",
		Title:        "Virement suspect bloqué",
		Body:         "Un virement de 2 M EUR vers un compte jamais vu a été bloqué.",
		Severity:     model.SeverityCritical,
		ResourceType: "transaction", ResourceID: "tx-4711",
		Channels: channels,
	}
}

// ─── Each channel's payload ──────────────────────────────────────────────────

// Slack is the channel most customers use, and its payload is a contract: the
// colour, the severity and the resource are what an on-call reads first.
func TestSlackCarriesWhatAnOnCallNeeds(t *testing.T) {
	rec := newRecorder(t, http.StatusOK)

	err := svc().Send(context.Background(), alert(model.ChannelConfig{
		Type:   model.ChannelSlack,
		Config: map[string]any{"webhook_url": rec.server.URL},
	}))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("%d calls, want 1", rec.count())
	}

	got := rec.last()
	text, _ := got["text"].(string)
	if !strings.Contains(text, "Virement suspect bloqué") {
		t.Errorf("the message does not carry the title: %q", text)
	}
	if !strings.Contains(text, "CRITICAL") {
		t.Errorf("the message does not carry the severity: %q", text)
	}
	if !strings.Contains(text, "🔴") {
		t.Errorf("a critical alert is not marked as one: %q", text)
	}

	atts, ok := got["attachments"].([]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("attachments is %v", got["attachments"])
	}
	att := atts[0].(map[string]any)
	if att["color"] != "#FF0000" {
		t.Errorf("a critical alert is %v, want red", att["color"])
	}
	body := rec.lastBody()
	for _, want := range []string{"transaction/tx-4711", "11111111-1111-1111-1111-111111111111"} {
		if !strings.Contains(body, want) {
			t.Errorf("the payload does not carry %q", want)
		}
	}
}

// The generic webhook is what a customer wires into their own tooling, so its
// keys are an interface: renaming one silently breaks every integration.
func TestTheWebhookPayloadKeepsItsKeys(t *testing.T) {
	rec := newRecorder(t, http.StatusAccepted)

	err := svc().Send(context.Background(), alert(model.ChannelConfig{
		Type:   model.ChannelWebhook,
		Config: map[string]any{"url": rec.server.URL},
	}))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := rec.last()
	for _, c := range []struct{ key, want string }{
		{"event", "crp.notification"},
		{"tenant_id", "11111111-1111-1111-1111-111111111111"},
		{"title", "Virement suspect bloqué"},
		{"severity", "CRITICAL"},
		{"resource_type", "transaction"},
		{"resource_id", "tx-4711"},
	} {
		if got[c.key] != c.want {
			t.Errorf("%s is %v, want %q", c.key, got[c.key], c.want)
		}
	}
	if got["body"] == nil || got["body"] == "" {
		t.Error("the webhook carries no body")
	}
	ts, _ := got["timestamp"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("timestamp %q is not RFC 3339: %v", ts, err)
	}
}

// Teams takes a message card, whose shape Microsoft rejects if the type or the
// context is wrong — and a rejected card is an alert nobody sees.
func TestTeamsSendsAMessageCard(t *testing.T) {
	rec := newRecorder(t, http.StatusOK)

	err := svc().Send(context.Background(), alert(model.ChannelConfig{
		Type:   model.ChannelTeams,
		Config: map[string]any{"webhook_url": rec.server.URL},
	}))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := rec.last()
	if got["@type"] != "MessageCard" {
		t.Errorf("@type is %v", got["@type"])
	}
	if got["@context"] != "http://schema.org/extensions" {
		t.Errorf("@context is %v", got["@context"])
	}
	if got["themeColor"] != "#FF0000" {
		t.Errorf("themeColor is %v, want red for a critical", got["themeColor"])
	}
	if got["summary"] != "Virement suspect bloqué" {
		t.Errorf("summary is %v", got["summary"])
	}
	sections, ok := got["sections"].([]any)
	if !ok || len(sections) != 1 {
		t.Fatalf("sections is %v", got["sections"])
	}
	sec := sections[0].(map[string]any)
	if sec["activityTitle"] != "Virement suspect bloqué" {
		t.Errorf("activityTitle is %v", sec["activityTitle"])
	}
	if sub, _ := sec["activitySubtitle"].(string); !strings.Contains(sub, "CRITICAL") {
		t.Errorf("activitySubtitle is %q", sub)
	}
}

// A channel with no address is refused rather than silently dropped: a rule
// that was configured wrong has to be visible as a failure.
func TestAChannelWithNoAddressFails(t *testing.T) {
	for _, c := range []struct {
		what    string
		channel model.ChannelConfig
	}{
		{"slack with no webhook_url", model.ChannelConfig{Type: model.ChannelSlack, Config: map[string]any{}}},
		{"slack with an empty webhook_url", model.ChannelConfig{Type: model.ChannelSlack, Config: map[string]any{"webhook_url": ""}}},
		{"slack with a webhook_url that is not a string", model.ChannelConfig{Type: model.ChannelSlack, Config: map[string]any{"webhook_url": 42}}},
		{"webhook with no url", model.ChannelConfig{Type: model.ChannelWebhook, Config: map[string]any{}}},
		{"teams with no webhook_url", model.ChannelConfig{Type: model.ChannelTeams, Config: map[string]any{}}},
		{"a nil config", model.ChannelConfig{Type: model.ChannelSlack}},
	} {
		err := svc().Send(context.Background(), alert(c.channel))
		if err == nil {
			t.Errorf("%s was accepted", c.what)
		}
	}
}

// Two channels are declared in the model and implemented nowhere. A rule
// configured for SMS or push therefore fails at send rather than at
// configuration — pinned here so that shipping either one is a deliberate act
// and this test is what tells its author to remove the line.
func TestSMSAndPushAreDeclaredAndNotImplemented(t *testing.T) {
	for _, ch := range []model.Channel{model.ChannelSMS, model.ChannelPush} {
		err := svc().Send(context.Background(), alert(model.ChannelConfig{
			Type: ch, Config: map[string]any{"to": "+33123456789"},
		}))
		if err == nil {
			t.Errorf("%s reported success although nothing sends it", ch)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported channel") {
			t.Errorf("%s failed with %q, want it named as unsupported", ch, err)
		}
	}
}

// The email channel is a stub that reports success. It is the only channel that
// claims delivery without attempting it, so a customer who configured email
// alone is told their alerts are being sent and receives nothing.
func TestEmailReportsSuccessWithoutSendingAnything(t *testing.T) {
	err := svc().Send(context.Background(), alert(model.ChannelConfig{
		Type: model.ChannelEmail, Config: map[string]any{"to": "soc@banque.test"},
	}))
	if err != nil {
		t.Fatalf("the email stub returned %v — if it now sends, this test is the one to rewrite", err)
	}
}

// ─── What "sent" means ───────────────────────────────────────────────────────

// A channel that answers an error status is a failure, at every status the
// other end can realistically return.
func TestANonSuccessStatusIsAFailure(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusBadRequest,
		http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
	} {
		rec := newRecorder(t, status)
		err := svc().Send(context.Background(), alert(model.ChannelConfig{
			Type: model.ChannelWebhook, Config: map[string]any{"url": rec.server.URL},
		}))
		if err == nil {
			t.Errorf("status %d was treated as a success", status)
		}
	}

	// And every 2xx is a success.
	for _, status := range []int{200, 201, 202, 204} {
		rec := newRecorder(t, status)
		if err := svc().Send(context.Background(), alert(model.ChannelConfig{
			Type: model.ChannelWebhook, Config: map[string]any{"url": rec.server.URL},
		})); err != nil {
			t.Errorf("status %d was treated as a failure: %v", status, err)
		}
	}
}

// A partial failure is reported as a success. That is the service's own rule —
// one channel through is a notification delivered — and it is pinned here
// because it is also how a customer whose Slack works and whose on-call
// webhook does not is never told the second one is broken. The log line is the
// only trace.
func TestOneChannelThroughIsReportedAsSuccess(t *testing.T) {
	good := newRecorder(t, http.StatusOK)
	bad := newRecorder(t, http.StatusInternalServerError)

	err := svc().Send(context.Background(), alert(
		model.ChannelConfig{Type: model.ChannelSlack, Config: map[string]any{"webhook_url": good.server.URL}},
		model.ChannelConfig{Type: model.ChannelWebhook, Config: map[string]any{"url": bad.server.URL}},
	))
	if err != nil {
		t.Fatalf("Send reported a failure although one channel went through: %v", err)
	}
	if good.count() != 1 || bad.count() != 1 {
		t.Errorf("the channels were called %d and %d times", good.count(), bad.count())
	}

	// Every channel failing is a failure, and it is an internal one: nothing
	// the caller sent was wrong.
	alsoBad := newRecorder(t, http.StatusBadGateway)
	err = svc().Send(context.Background(), alert(
		model.ChannelConfig{Type: model.ChannelWebhook, Config: map[string]any{"url": bad.server.URL}},
		model.ChannelConfig{Type: model.ChannelWebhook, Config: map[string]any{"url": alsoBad.server.URL}},
	))
	if err == nil {
		t.Fatal("every channel failed and Send reported success")
	}
	if !apierrors.IsKind(err, apierrors.KindInternal) {
		t.Errorf("the error is %v, want an internal one", err)
	}
}

// A request with no channel at all must not take the service down.
//
// "every channel failed" was written as len(errs) == len(req.Channels), which
// is 0 == 0 for an empty list, and the next line read errs[0] — a panic on an
// empty slice. The handler's validator demands at least one channel, so this
// was unreachable over HTTP and reachable from any internal caller: a rule
// whose channel list was emptied, or a pipeline publishing an event with none.
func TestARequestWithNoChannelIsRefusedRatherThanFatal(t *testing.T) {
	err := svc().Send(context.Background(), alert())
	if err == nil {
		t.Fatal("a notification with no channel reported success")
	}
	if !strings.Contains(err.Error(), "no channel") {
		t.Errorf("the error is %q, want it to name the missing channel", err)
	}
}

// Every channel is attempted even when an earlier one fails: a service that
// stopped at the first error would drop the alert for everyone behind it.
func TestEveryChannelIsAttempted(t *testing.T) {
	first := newRecorder(t, http.StatusInternalServerError)
	second := newRecorder(t, http.StatusOK)
	third := newRecorder(t, http.StatusOK)

	if err := svc().Send(context.Background(), alert(
		model.ChannelConfig{Type: model.ChannelWebhook, Config: map[string]any{"url": first.server.URL}},
		model.ChannelConfig{Type: model.ChannelSlack, Config: map[string]any{"webhook_url": second.server.URL}},
		model.ChannelConfig{Type: model.ChannelTeams, Config: map[string]any{"webhook_url": third.server.URL}},
	)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for name, rec := range map[string]*recorder{"first": first, "second": second, "third": third} {
		if rec.count() != 1 {
			t.Errorf("the %s channel was called %d times", name, rec.count())
		}
	}
}

// A cancelled context stops the send rather than hanging on to a dead
// connection, and is reported.
func TestACancelledContextStopsTheSend(t *testing.T) {
	rec := newRecorder(t, http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := svc().Send(ctx, alert(model.ChannelConfig{
		Type: model.ChannelWebhook, Config: map[string]any{"url": rec.server.URL},
	}))
	if err == nil {
		t.Fatal("a cancelled send reported success")
	}
	if rec.count() != 0 {
		t.Errorf("the server was called %d times despite the cancellation", rec.count())
	}
}

// ─── Severity presentation ───────────────────────────────────────────────────

// The colour and the mark are what distinguishes a critical from a notice in a
// channel full of messages, so each severity has to get its own.
func TestEachSeverityGetsItsOwnColourAndMark(t *testing.T) {
	colours := map[model.Severity]string{
		model.SeverityCritical: "#FF0000",
		model.SeverityHigh:     "#FF8C00",
		model.SeverityMedium:   "#FFD700",
		model.SeverityLow:      "#008000",
	}
	marks := map[model.Severity]string{
		model.SeverityCritical: "🔴",
		model.SeverityHigh:     "🟠",
		model.SeverityMedium:   "🟡",
		model.SeverityLow:      "🟢",
	}
	seen := map[string]bool{}
	for sev, colour := range colours {
		if got := severityColor(sev); got != colour {
			t.Errorf("%s is %s, want %s", sev, got, colour)
		}
		if got := severityEmoji(sev); got != marks[sev] {
			t.Errorf("%s is marked %s, want %s", sev, got, marks[sev])
		}
		if seen[colour] {
			t.Errorf("%s shares its colour with another severity", sev)
		}
		seen[colour] = true
	}

	// An unknown severity falls back to the calmest presentation rather than
	// the loudest: an alert of unknown importance must not look critical.
	if severityColor("INCONNU") != "#008000" || severityEmoji("INCONNU") != "🟢" {
		t.Errorf("an unknown severity is presented as %s/%s",
			severityColor("INCONNU"), severityEmoji("INCONNU"))
	}
}
