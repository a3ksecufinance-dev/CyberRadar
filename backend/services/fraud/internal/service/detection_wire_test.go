package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/services/fraud/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// The wire between a flagged transaction and the detection engine.
//
// This is the product thesis expressed in one topic: a transaction the fraud
// scorer flags must arrive on crp.events.enriched, as a canonical event, so
// the SIEM rule engine can count it in a window, group it by ordering account
// and correlate it with the IT estate.
//
// Until this existed, flagged transactions were published to a topic no
// service consumed. Nothing failed. No alert was raised either.

type capturingPublisher struct {
	key   string
	value any
	calls int
	err   error
}

func (p *capturingPublisher) Publish(_ context.Context, key string, value any) error {
	p.calls++
	p.key = key
	p.value = value
	return p.err
}

func testTxn() *model.FraudTransaction {
	return &model.FraudTransaction{
		ID:              uuid.New(),
		TransactionID:   "TX-4417",
		Channel:         model.ChannelMobile,
		Amount:          9500,
		Currency:        "MAD",
		SenderAccount:   "007-554120",
		SenderEntity:    "Wallet client 554120",
		ReceiverAccount: "007-998001",
		CountryOrigin:   "MA",
		CountryDest:     "MA",
		TransactedAt:    time.Date(2026, 3, 2, 11, 30, 0, 0, time.UTC),
	}
}

func TestFlaggedTransactionReachesTheDetectionTopic(t *testing.T) {
	pub := &capturingPublisher{}
	s := &FraudService{detection: pub, logger: zerolog.Nop()}
	tenant := uuid.New()
	txn := testTxn()

	s.publishForDetection(context.Background(), tenant, txn, 72, model.TxnStatusFlagged, []string{"rule-a"})

	if pub.calls != 1 {
		t.Fatalf("published %d times, want 1 — a flagged transaction that "+
			"reaches no engine raises no alert", pub.calls)
	}
	ev, ok := pub.value.(*event.NormalizedEvent)
	if !ok {
		t.Fatalf("published %T, want *event.NormalizedEvent — the rule engine "+
			"decodes the canonical event and nothing else", pub.value)
	}
	if ev.TenantID != tenant.String() {
		t.Errorf("tenant_id = %q, want %q", ev.TenantID, tenant.String())
	}
	if ev.Category != event.CategoryTransaction {
		t.Errorf("category = %q, want %q — CRP-FRD-0001 matches on it",
			ev.Category, event.CategoryTransaction)
	}
	if ev.CBSImpact != 1 {
		t.Errorf("cbs_impact = %d, want 1 — a transaction is a core banking flow", ev.CBSImpact)
	}
	if ev.UserID == nil || *ev.UserID != "007-554120" {
		t.Errorf("user_id = %v, want the ordering account — without it a rule "+
			"can count transactions but not count them per account", ev.UserID)
	}
	if !ev.Timestamp.Equal(txn.TransactedAt) {
		t.Errorf("timestamp = %v, want the transaction time %v — a window "+
			"counted on arrival time is not a window", ev.Timestamp, txn.TransactedAt)
	}
}

// The scale conversion is what decides whether the shipped detection fires.
// CRP-FRD-0001 matches threat_score >= 7, and the scorer speaks 0–100.
func TestFraudScoreIsScaledSoTheShippedDetectionFires(t *testing.T) {
	cases := []struct {
		score    int
		want     float32
		wantFire bool // CRP-FRD-0001: threat_score >= 7
	}{
		{50, 5.0, false},
		{69, 6.9, false},
		{70, 7.0, true},
		{90, 9.0, true},
		{100, 10.0, true},
	}
	for _, c := range cases {
		ev := fraudEventToNormalized(uuid.New(), testTxn(), c.score, model.TxnStatusFlagged, nil)
		if ev.ThreatScore != c.want {
			t.Errorf("score %d: threat_score = %v, want %v", c.score, ev.ThreatScore, c.want)
		}
		if fires := ev.ThreatScore >= 7; fires != c.wantFire {
			t.Errorf("score %d: CRP-FRD-0001 fires = %v, want %v", c.score, fires, c.wantFire)
		}
	}
}

func TestSeverityAndOutcomeFollowTheScoreAndStatus(t *testing.T) {
	cases := []struct {
		score    int
		status   string
		severity event.Severity
		outcome  event.Outcome
	}{
		{50, model.TxnStatusFlagged, event.SeverityMedium, event.OutcomeSuccess},
		{65, model.TxnStatusFlagged, event.SeverityHigh, event.OutcomeSuccess},
		{79, model.TxnStatusFlagged, event.SeverityHigh, event.OutcomeSuccess},
		{80, model.TxnStatusBlocked, event.SeverityCritical, event.OutcomeFailure},
		{95, model.TxnStatusBlocked, event.SeverityCritical, event.OutcomeFailure},
	}
	for _, c := range cases {
		ev := fraudEventToNormalized(uuid.New(), testTxn(), c.score, c.status, nil)
		if ev.Severity != c.severity {
			t.Errorf("score %d: severity = %q, want %q", c.score, ev.Severity, c.severity)
		}
		if ev.Outcome != c.outcome {
			t.Errorf("status %q: outcome = %q, want %q", c.status, ev.Outcome, c.outcome)
		}
	}
}

func TestSWIFTTransactionCarriesTheSWIFTFlag(t *testing.T) {
	txn := testTxn()
	txn.Channel = model.ChannelSWIFT
	ev := fraudEventToNormalized(uuid.New(), txn, 85, model.TxnStatusBlocked, nil)
	if ev.SWIFTImpact != 1 {
		t.Errorf("swift_impact = %d, want 1", ev.SWIFTImpact)
	}
	if ev.CBSImpact != 1 {
		t.Errorf("cbs_impact = %d, want 1 — a SWIFT flow is a core banking flow", ev.CBSImpact)
	}
}

// The canonical event has no columns for amount or counterparty. An analyst
// opening the alert needs both, so the transaction travels in raw_event.
func TestTheTransactionTravelsInRawEvent(t *testing.T) {
	ev := fraudEventToNormalized(uuid.New(), testTxn(), 72, model.TxnStatusFlagged, []string{"rule-a", "rule-b"})
	var got map[string]any
	if err := json.Unmarshal([]byte(ev.RawEvent), &got); err != nil {
		t.Fatalf("raw_event is not JSON: %v", err)
	}
	for _, k := range []string{"amount", "currency", "receiver_account", "ext_txn_id", "fraud_score", "flagged_by"} {
		if _, ok := got[k]; !ok {
			t.Errorf("raw_event has no %q — the analyst cannot triage without it", k)
		}
	}
	if got["amount"] != float64(9500) {
		t.Errorf("raw_event amount = %v, want 9500", got["amount"])
	}
}

// A broken detection topic must not take the scoring path down with it: the
// transaction is already stored and the integration topic still carries it.
func TestADetectionPublishFailureIsSurvivable(t *testing.T) {
	pub := &capturingPublisher{err: errors.New("broker unreachable")}
	s := &FraudService{detection: pub, logger: zerolog.Nop()}
	s.publishForDetection(context.Background(), uuid.New(), testTxn(), 90, model.TxnStatusBlocked, nil)
	if pub.calls != 1 {
		t.Fatalf("publish attempted %d times, want 1", pub.calls)
	}
}

// A deployment with no detection producer must not panic.
func TestNoDetectionPublisherIsNotAPanic(t *testing.T) {
	s := &FraudService{logger: zerolog.Nop()}
	s.publishForDetection(context.Background(), uuid.New(), testTxn(), 90, model.TxnStatusBlocked, nil)
}

// ─── The call site ───────────────────────────────────────────────────────────
//
// The tests above prove the event is built correctly and published when
// publishForDetection is called. They would all pass with the call removed
// from the scoring path — which is precisely how this platform's worst bugs
// have presented themselves: a correct mechanism nobody invokes.
//
// So these exercise evaluateRules itself, the function that scores a
// transaction and decides what leaves the service.

// fakeStore implements only what the scoring path touches. The embedded
// interface makes any other call a panic rather than a silent zero value.
type fakeStore struct {
	Store
	rules      []*model.FraudRule
	watchlist  []*model.FraudWatchlistEntry
	lastScore  int
	lastStatus string
}

func (f *fakeStore) ListActiveRules(context.Context, uuid.UUID) ([]*model.FraudRule, error) {
	return f.rules, nil
}

func (f *fakeStore) CheckWatchlist(context.Context, uuid.UUID, []string) ([]*model.FraudWatchlistEntry, error) {
	return f.watchlist, nil
}

func (f *fakeStore) CreateSignal(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, string, string, int, map[string]any) (*model.FraudSignal, error) {
	return &model.FraudSignal{ID: uuid.New()}, nil
}

func (f *fakeStore) IncrementRuleCounter(context.Context, uuid.UUID) {}

func (f *fakeStore) UpdateTransactionScore(_ context.Context, _ uuid.UUID, score int, status string, _ []string) error {
	f.lastScore = score
	f.lastStatus = status
	return nil
}

// amountOver builds a threshold rule worth `risk` points above `amount`.
func amountOver(amount float64, risk int) *model.FraudRule {
	return &model.FraudRule{
		ID:         uuid.New(),
		Name:       "montant élevé",
		RuleType:   model.RuleTypeThreshold,
		Category:   model.CategoryWireFraud,
		RiskScore:  risk,
		Conditions: map[string]any{"field": "amount", "operator": "gt", "value": amount},
	}
}

func scoreWith(t *testing.T, rules []*model.FraudRule, amount float64) (*fakeStore, *capturingPublisher, *capturingPublisher) {
	t.Helper()
	store := &fakeStore{rules: rules}
	integration := &capturingPublisher{}
	detection := &capturingPublisher{}
	s := &FraudService{repo: store, producer: integration, detection: detection, logger: zerolog.Nop()}

	txn := testTxn()
	txn.Amount = amount
	s.evaluateRules(uuid.New(), txn, &model.IngestTransactionRequest{
		SenderAccount:   txn.SenderAccount,
		ReceiverAccount: txn.ReceiverAccount,
	})
	return store, integration, detection
}

// The wire, asserted on the real scoring path.
func TestScoringAFlaggedTransactionPublishesItToTheDetectionEngine(t *testing.T) {
	store, integration, detection := scoreWith(t, []*model.FraudRule{amountOver(1000, 75)}, 9500)

	if store.lastScore != 75 {
		t.Fatalf("score = %d, want 75 — the rule should have fired", store.lastScore)
	}
	if integration.calls != 1 {
		t.Errorf("crp.events.fraud published %d times, want 1", integration.calls)
	}
	if detection.calls != 1 {
		t.Fatalf("crp.events.enriched published %d times, want 1 — without this "+
			"the transaction raises no alert and correlates with nothing", detection.calls)
	}
	ev, ok := detection.value.(*event.NormalizedEvent)
	if !ok {
		t.Fatalf("published %T, want *event.NormalizedEvent", detection.value)
	}
	if ev.ThreatScore != 7.5 {
		t.Errorf("threat_score = %v, want 7.5", ev.ThreatScore)
	}
}

// Below the flag threshold nothing leaves: a cleared transaction on the
// detection topic is noise that buries the real ones.
func TestAClearedTransactionReachesNeitherTopic(t *testing.T) {
	store, integration, detection := scoreWith(t, []*model.FraudRule{amountOver(1000, 20)}, 9500)

	if store.lastScore != 20 {
		t.Fatalf("score = %d, want 20", store.lastScore)
	}
	if integration.calls != 0 || detection.calls != 0 {
		t.Errorf("published to fraud=%d enriched=%d, want 0 and 0 — a score of "+
			"20 is not an event the SOC should see", integration.calls, detection.calls)
	}
}

// The two topics carry different payloads on purpose, and a test that only
// counted calls would not notice them being swapped.
func TestTheTwoTopicsCarryDifferentShapes(t *testing.T) {
	_, integration, detection := scoreWith(t, []*model.FraudRule{amountOver(1000, 90)}, 50000)

	if _, ok := integration.value.([]byte); !ok {
		t.Errorf("crp.events.fraud carried %T, want the marshalled JSON payload", integration.value)
	}
	if _, ok := detection.value.(*event.NormalizedEvent); !ok {
		t.Errorf("crp.events.enriched carried %T, want *event.NormalizedEvent", detection.value)
	}
}
