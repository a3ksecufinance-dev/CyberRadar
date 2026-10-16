package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/fraud/internal/model"
)

// The fraud repository: the first test this service has ever had.
//
// This is the service a bank's compliance function answers to. A transaction
// that was blocked has to stay blocked and auditable; a watchlist hit has to
// fire on the right value and only for the customer whose list it is; and the
// suspicious total on the dashboard is a figure a regulator may ask about. All
// three are produced by SQL whose errors this repository discards.

func repo(t *testing.T) (*FraudRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewFraudRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func txn(t *testing.T, r *FraudRepository, tenant uuid.UUID, ref string, amount float64) *model.FraudTransaction {
	t.Helper()
	tx, err := r.IngestTransaction(context.Background(), tenant, &model.IngestTransactionRequest{
		TransactionID: ref, Channel: "swift", Amount: amount, Currency: "EUR",
		SenderAccount: "FR7630006000011234567890189", SenderEntity: "Client A",
		ReceiverAccount: "DE89370400440532013000", ReceiverEntity: "Société B",
		CountryOrigin: "FR", CountryDest: "DE",
		Metadata:     map[string]any{"swift_mt": "103"},
		TransactedAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("IngestTransaction(%s): %v", ref, err)
	}
	return tx
}

// ─── The round trip ──────────────────────────────────────────────────────────

// A transaction reads back with every figure intact. The amount is the one that
// matters: NUMERIC(20,4) read into a Go float has to come back as what was
// sent, or a report of suspicious volume is wrong by the error.
func TestATransactionReadsBackWithItsAmountIntact(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	made := txn(t, r, tenant, "MT103-0001", 1234567.8912)
	got, err := r.GetTransaction(ctx, tenant, made.ID)
	if err != nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	if got == nil {
		t.Fatal("GetTransaction found nothing")
	}
	if got.Amount != 1234567.8912 {
		t.Errorf("amount is %v, want 1234567.8912", got.Amount)
	}
	if got.Currency != "EUR" || got.Channel != "swift" {
		t.Errorf("the transaction is %v %s on %s", got.Amount, got.Currency, got.Channel)
	}
	if got.TransactionID != "MT103-0001" {
		t.Errorf("the external reference is %q", got.TransactionID)
	}
	if got.SenderAccount == "" || got.ReceiverAccount == "" {
		t.Error("the accounts were not kept")
	}
	if got.CountryOrigin != "FR" || got.CountryDest != "DE" {
		t.Errorf("the corridor is %s → %s", got.CountryOrigin, got.CountryDest)
	}
	if got.Metadata["swift_mt"] != "103" {
		t.Errorf("metadata is %v", got.Metadata)
	}
	if got.Status != "pending" {
		t.Errorf("a fresh transaction is %q, want pending", got.Status)
	}
	if got.FlaggedBy == nil {
		t.Error("flagged_by came back nil rather than empty")
	}
	if got.TransactedAt.IsZero() {
		t.Error("transacted_at came back zero")
	}
}

// A transaction with only the required fields reads back: six of its columns
// are nullable text the model holds as strings, and an internal transfer
// carries neither a corridor nor a counterparty name.
func TestATransactionWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	bare, err := r.IngestTransaction(ctx, tenant, &model.IngestTransactionRequest{
		TransactionID: "INT-0001", Channel: "internal", Amount: 500, Currency: "XOF",
		TransactedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("IngestTransaction with nothing optional: %v", err)
	}
	if bare.SenderAccount != "" || bare.CountryOrigin != "" {
		t.Errorf("the optional fields came back as %q/%q", bare.SenderAccount, bare.CountryOrigin)
	}
	if got, err := r.GetTransaction(ctx, tenant, bare.ID); err != nil || got == nil {
		t.Fatalf("GetTransaction: %+v / %v", got, err)
	}
	if rows, total, err := r.ListTransactions(ctx, tenant, model.ListTransactionsFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListTransactions gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A rule with no description.
	rule, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		Name: "Virement hors zone", Category: "wire_fraud", RuleType: "threshold",
		Conditions: map[string]any{"amount_gt": 100000}, RiskScore: 70,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule with no description: %v", err)
	}
	if got, err := r.GetRule(ctx, tenant, rule.ID); err != nil || got == nil {
		t.Fatalf("GetRule: %+v / %v", got, err)
	}
	if rows, total, err := r.ListRules(ctx, tenant, "", false, 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListRules gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A case with no notes and nobody assigned.
	c, err := r.CreateCase(ctx, tenant, &model.CreateCaseRequest{
		Title: "Série de virements", Category: "wire_fraud", Severity: "HIGH",
	})
	if err != nil {
		t.Fatalf("CreateCase with nothing optional: %v", err)
	}
	if c.AssignedTo != nil || c.ResolvedAt != nil || c.SARFiledAt != nil {
		t.Errorf("a fresh case is assigned or closed: %+v", c)
	}
	if got, err := r.GetCase(ctx, tenant, c.ID); err != nil || got == nil {
		t.Fatalf("GetCase: %+v / %v", got, err)
	}
	if rows, total, err := r.ListCases(ctx, tenant, model.ListCasesFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListCases gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A watchlist entry with no severity and no expiry.
	entry, err := r.AddWatchlistEntry(ctx, tenant, &model.AddWatchlistRequest{
		EntityType: "account", EntityValue: "FR7630006000011234567890189",
		Reason: "Signalement interne", ListType: "internal",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AddWatchlistEntry with nothing optional: %v", err)
	}
	if entry.ExpiresAt != nil {
		t.Error("an entry with no expiry came back with one")
	}
	if rows, total, err := r.ListWatchlist(ctx, tenant, "", "", false, 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListWatchlist gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A signal with no transaction and no rule behind it.
	sig, err := r.CreateSignal(ctx, tenant, nil, nil, "manual_review",
		"Signalé par un analyste", 25, map[string]any{"analyste": "alice"})
	if err != nil {
		t.Fatalf("CreateSignal with no transaction: %v", err)
	}
	if sig.TransactionID != nil || sig.RuleID != nil {
		t.Errorf("the signal came back attached: %v / %v", sig.TransactionID, sig.RuleID)
	}
}

// ─── What a blocked transaction means ────────────────────────────────────────

// Scoring a transaction records who flagged it, and the signals raised against
// it come back with it. That is the audit trail: a blocked payment has to be
// explainable months later.
func TestAScoredTransactionCarriesItsReasons(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	rule, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		Name: "Montant hors norme", Category: "aml", RuleType: "threshold",
		Conditions: map[string]any{"amount_gt": 1000000}, RiskScore: 80,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	tx := txn(t, r, tenant, "MT103-0002", 2000000)
	if _, err := r.CreateSignal(ctx, tenant, &tx.ID, &rule.ID, "threshold",
		"Montant supérieur à 1 M EUR", 80, map[string]any{"amount": 2000000}); err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	if err := r.UpdateTransactionScore(ctx, tx.ID, 80, "blocked", []string{rule.Name}); err != nil {
		t.Fatalf("UpdateTransactionScore: %v", err)
	}

	got, err := r.GetTransaction(ctx, tenant, tx.ID)
	if err != nil || got == nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	if got.Status != "blocked" || got.FraudScore != 80 {
		t.Errorf("the transaction is %q at %d", got.Status, got.FraudScore)
	}
	if len(got.FlaggedBy) != 1 || got.FlaggedBy[0] != rule.Name {
		t.Errorf("flagged_by is %v, want the rule that fired", got.FlaggedBy)
	}
	if len(got.Signals) != 1 {
		t.Fatalf("%d signals came back with the transaction, want 1", len(got.Signals))
	}
	sig := got.Signals[0]
	if sig.RiskContribution != 80 || sig.SignalType != "threshold" {
		t.Errorf("the signal is %+v", sig)
	}
	if sig.Evidence["amount"] == nil {
		t.Errorf("the signal carries no evidence: %v", sig.Evidence)
	}

	// Clearing it by hand is recorded, and the reasons stay.
	cleared, err := r.UpdateTransactionStatus(ctx, tenant, tx.ID, "cleared")
	if err != nil {
		t.Fatalf("UpdateTransactionStatus: %v", err)
	}
	if cleared == nil || cleared.Status != "cleared" {
		t.Fatalf("the transaction is %+v", cleared)
	}
	if len(cleared.FlaggedBy) != 1 {
		t.Errorf("clearing the transaction erased why it was flagged: %v", cleared.FlaggedBy)
	}
}

// The watchlist fires on the values it holds and on nothing else, and an entry
// that has expired or been withdrawn stops firing. This is the check a payment
// is held on, so a false negative is a sanctioned payment going through.
func TestTheWatchlistFiresOnlyOnWhatItHolds(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	const sanctioned = "DE89370400440532013000"
	if _, err := r.AddWatchlistEntry(ctx, tenant, &model.AddWatchlistRequest{
		EntityType: "account", EntityValue: sanctioned,
		Reason: "Liste de sanctions", ListType: "sanctions", Severity: "CRITICAL",
	}, uuid.Nil); err != nil {
		t.Fatalf("AddWatchlistEntry: %v", err)
	}

	hits, err := r.CheckWatchlist(ctx, tenant, []string{sanctioned, "FR7630006000011234567890189"})
	if err != nil {
		t.Fatalf("CheckWatchlist: %v", err)
	}
	if len(hits) != 1 || hits[0].EntityValue != sanctioned {
		t.Fatalf("%d hits, want the sanctioned account only: %+v", len(hits), hits)
	}
	if hits[0].Severity != "CRITICAL" {
		t.Errorf("the hit is %q", hits[0].Severity)
	}

	// A value nobody listed does not fire.
	if hits, err := r.CheckWatchlist(ctx, tenant, []string{"GB29NWBK60161331926819"}); err != nil || len(hits) != 0 {
		t.Errorf("%d hits on an unlisted account: %v", len(hits), err)
	}
	// Nothing to check is not a hit either.
	if hits, err := r.CheckWatchlist(ctx, tenant, nil); err != nil || len(hits) != 0 {
		t.Errorf("%d hits on an empty check: %v", len(hits), err)
	}

	// An expired entry stops firing.
	past := time.Now().UTC().Add(-time.Hour)
	expired, err := r.AddWatchlistEntry(ctx, tenant, &model.AddWatchlistRequest{
		EntityType: "account", EntityValue: "IT60X0542811101000000123456",
		Reason: "Ancienne alerte", ListType: "internal", ExpiresAt: &past,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AddWatchlistEntry: %v", err)
	}
	if hits, err := r.CheckWatchlist(ctx, tenant, []string{"IT60X0542811101000000123456"}); err != nil || len(hits) != 0 {
		t.Errorf("an expired entry still fires: %d hits, %v", len(hits), err)
	}
	_ = expired

	// A withdrawn entry stops firing.
	live, _, err := r.ListWatchlist(ctx, tenant, "account", "sanctions", true, 1, 50)
	if err != nil || len(live) != 1 {
		t.Fatalf("ListWatchlist gave %d rows: %v", len(live), err)
	}
	if err := r.RemoveWatchlistEntry(ctx, tenant, live[0].ID); err != nil {
		t.Fatalf("RemoveWatchlistEntry: %v", err)
	}
	if hits, err := r.CheckWatchlist(ctx, tenant, []string{sanctioned}); err != nil || len(hits) != 0 {
		t.Errorf("a withdrawn entry still fires: %d hits, %v", len(hits), err)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing one bank wrote is reachable by another. In this service a leak is not
// a configuration detail: it is one bank's payment flow, its counterparties and
// its suspicion of them.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	rule, err := r.CreateRule(ctx, mine, &model.CreateRuleRequest{
		Name: "Ma règle", Category: "aml", RuleType: "pattern",
		Conditions: map[string]any{"country": "XX"}, RiskScore: 60,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	tx := txn(t, r, mine, "MT103-0003", 750000)
	c, err := r.CreateCase(ctx, mine, &model.CreateCaseRequest{
		Title: "Mon dossier", Category: "aml", Severity: "CRITICAL",
		TransactionIDs: []uuid.UUID{tx.ID}, TotalAmount: 750000, Currency: "EUR",
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	entry, err := r.AddWatchlistEntry(ctx, mine, &model.AddWatchlistRequest{
		EntityType: "account", EntityValue: "DE89370400440532013000",
		Reason: "Ma liste", ListType: "internal",
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("AddWatchlistEntry: %v", err)
	}

	// Reads
	if got, err := r.GetRule(ctx, theirs, rule.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the rule: %v / %v", got, err)
	}
	if got, err := r.GetTransaction(ctx, theirs, tx.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the transaction: %v / %v", got, err)
	}
	if got, err := r.GetCase(ctx, theirs, c.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the case: %v / %v", got, err)
	}
	if rows, total, err := r.ListRules(ctx, theirs, "", false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d rules (total=%d): %v", len(rows), total, err)
	}
	if rows, err := r.ListActiveRules(ctx, theirs); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d active rules: %v", len(rows), err)
	}
	if rows, total, err := r.ListTransactions(ctx, theirs, model.ListTransactionsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d transactions (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListCases(ctx, theirs, model.ListCasesFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d cases (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListWatchlist(ctx, theirs, "", "", false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d watchlist entries (total=%d): %v", len(rows), total, err)
	}

	// The watchlist check is the one that matters most: one bank's suspicion of
	// a counterparty must not become another bank's hold on a payment.
	if hits, err := r.CheckWatchlist(ctx, theirs, []string{"DE89370400440532013000"}); err != nil || len(hits) != 0 {
		t.Errorf("the neighbour got %d hits from our list: %v", len(hits), err)
	}

	// Writes
	if got, err := r.UpdateRule(ctx, theirs, rule.ID, &model.UpdateRuleRequest{IsActive: boolp(false)}); err != nil || got != nil {
		t.Errorf("the neighbour disabled the rule: %v / %v", got, err)
	}
	if got, err := r.UpdateTransactionStatus(ctx, theirs, tx.ID, "cleared"); err != nil || got != nil {
		t.Errorf("the neighbour cleared the transaction: %v / %v", got, err)
	}
	if got, err := r.UpdateCase(ctx, theirs, c.ID, &model.UpdateCaseRequest{Status: "closed_false_positive"}); err != nil || got != nil {
		t.Errorf("the neighbour closed the case: %v / %v", got, err)
	}
	if err := r.RemoveWatchlistEntry(ctx, theirs, entry.ID); err == nil {
		t.Error("the neighbour withdrew our watchlist entry")
	}

	// Nothing moved: the transaction is still pending, the case still open, the
	// entry still fires for us.
	againTx, err := r.GetTransaction(ctx, mine, tx.ID)
	if err != nil || againTx == nil {
		t.Fatalf("re-read the transaction: %v", err)
	}
	if againTx.Status != "pending" {
		t.Errorf("the transaction is %q — the neighbour's clearance landed", againTx.Status)
	}
	againCase, err := r.GetCase(ctx, mine, c.ID)
	if err != nil || againCase == nil {
		t.Fatalf("re-read the case: %v", err)
	}
	if againCase.Status != "open" {
		t.Errorf("the case is %q", againCase.Status)
	}
	if hits, err := r.CheckWatchlist(ctx, mine, []string{"DE89370400440532013000"}); err != nil || len(hits) != 1 {
		t.Errorf("our own list stopped firing: %d hits, %v", len(hits), err)
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

// The compliance dashboard, against known rows. The suspicious total is the
// figure most likely to be quoted to a regulator, and it is a SUM over a
// filtered set — the shape that silently returns NULL over no rows.
func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	// Four transactions: one blocked, one flagged, one under review, one clean.
	blocked := txn(t, r, tenant, "MT103-B", 1000000)
	flagged := txn(t, r, tenant, "MT103-F", 500000)
	review := txn(t, r, tenant, "MT103-R", 250000)
	txn(t, r, tenant, "MT103-C", 1000)
	for id, status := range map[uuid.UUID]string{
		blocked.ID: "blocked", flagged.ID: "flagged", review.ID: "under_review",
	} {
		if err := r.UpdateTransactionScore(ctx, id, 90, status, []string{"règle"}); err != nil {
			t.Fatalf("UpdateTransactionScore: %v", err)
		}
	}

	// Two cases, one closed, and one needing a SAR that has not been filed.
	open, err := r.CreateCase(ctx, tenant, &model.CreateCaseRequest{
		Title: "Dossier ouvert", Category: "aml", Severity: "CRITICAL",
		TotalAmount: 1000000, Currency: "EUR",
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	if _, err := r.UpdateCase(ctx, tenant, open.ID, &model.UpdateCaseRequest{
		SARRequired: boolp(true),
	}); err != nil {
		t.Fatalf("UpdateCase: %v", err)
	}
	closed, err := r.CreateCase(ctx, tenant, &model.CreateCaseRequest{
		Title: "Dossier clos", Category: "card_fraud", Severity: "LOW",
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	if _, err := r.UpdateCase(ctx, tenant, closed.ID, &model.UpdateCaseRequest{
		Status: "closed_false_positive",
	}); err != nil {
		t.Fatalf("UpdateCase: %v", err)
	}

	if _, err := r.AddWatchlistEntry(ctx, tenant, &model.AddWatchlistRequest{
		EntityType: "person", EntityValue: "Jean Dupont",
		Reason: "PEP", ListType: "pep",
	}, uuid.Nil); err != nil {
		t.Fatalf("AddWatchlistEntry: %v", err)
	}

	// A rule that has fired twice.
	rule, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		Name: "Règle qui tire", Category: "aml", RuleType: "velocity",
		Conditions: map[string]any{"count_gt": 3}, RiskScore: 55,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	r.IncrementRuleCounter(ctx, rule.ID)
	r.IncrementRuleCounter(ctx, rule.ID)

	// The neighbour's flow, which must change nothing below.
	txn(t, r, other, "MT103-X", 9000000)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_transactions", stats.TotalTransactions, 4},
		{"flagged_transactions", stats.FlaggedTransactions, 3},
		{"blocked_transactions", stats.BlockedTransactions, 1},
		{"open_cases", stats.OpenCases, 1},
		{"sar_required", stats.SARRequired, 1},
		{"watchlist_entries", stats.WatchlistEntries, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	// 1 000 000 + 500 000 + 250 000, and not the clean one or the neighbour's.
	if stats.TotalSuspiciousAmt != 1750000 {
		t.Errorf("total_suspicious_amount is %v, want 1750000", stats.TotalSuspiciousAmt)
	}
	if stats.TransactionsByStatus["blocked"] != 1 || stats.TransactionsByStatus["pending"] != 1 {
		t.Errorf("transactions by status is %v", stats.TransactionsByStatus)
	}
	if stats.CasesByCategory["aml"] != 1 || stats.CasesByCategory["card_fraud"] != 1 {
		t.Errorf("cases by category is %v", stats.CasesByCategory)
	}
	if len(stats.TopRules) == 0 {
		t.Fatal("no rule appears in the top rules although one fired twice")
	}
	if stats.TopRules[0].Count != 2 || stats.TopRules[0].RuleName != "Règle qui tire" {
		t.Errorf("the top rule is %+v", stats.TopRules[0])
	}
}

// A bank with no flow at all gets zeros, not an error: a SUM over no rows is
// NULL, and that is every customer's first day.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.TotalTransactions != 0 || stats.OpenCases != 0 || stats.WatchlistEntries != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	if stats.TotalSuspiciousAmt != 0 {
		t.Errorf("total_suspicious_amount is %v with no transaction at all", stats.TotalSuspiciousAmt)
	}
	if stats.TransactionsByStatus == nil || stats.CasesByCategory == nil {
		t.Error("the breakdown maps came back nil rather than empty")
	}
}

// ─── Rules and filters ───────────────────────────────────────────────────────

// Only active rules are handed to the scoring path: a rule a compliance officer
// switched off must stop blocking payments on the next transaction.
func TestOnlyActiveRulesReachTheScoringPath(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	live, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		Name: "Active", Category: "aml", RuleType: "threshold",
		Conditions: map[string]any{"amount_gt": 1}, RiskScore: 50,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	off, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		Name: "Coupée", Category: "card_fraud", RuleType: "pattern",
		Conditions: map[string]any{"bin": "490000"}, RiskScore: 50,
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if _, err := r.UpdateRule(ctx, tenant, off.ID, &model.UpdateRuleRequest{IsActive: boolp(false)}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	active, err := r.ListActiveRules(ctx, tenant)
	if err != nil {
		t.Fatalf("ListActiveRules: %v", err)
	}
	if len(active) != 1 || active[0].ID != live.ID {
		t.Fatalf("%d active rules, want only the one left on", len(active))
	}

	// And the listing can show both, or an operator could not switch one back on.
	if rows, total, err := r.ListRules(ctx, tenant, "", false, 1, 50); err != nil || total != 2 || len(rows) != 2 {
		t.Errorf("ListRules gave %d rows (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListRules(ctx, tenant, "", true, 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Errorf("the active-only listing gave %d rows (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListRules(ctx, tenant, "card_fraud", false, 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Errorf("the category filter gave %d rows (total=%d): %v", len(rows), total, err)
	}
}

func TestEachTransactionFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	swift := txn(t, r, tenant, "MT103-1", 1000000)
	card, err := r.IngestTransaction(ctx, tenant, &model.IngestTransactionRequest{
		TransactionID: "CARD-1", Channel: "card", Amount: 250, Currency: "EUR",
		SenderAccount: "4970XXXXXXXX1234", TransactedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("IngestTransaction: %v", err)
	}
	if err := r.UpdateTransactionScore(ctx, swift.ID, 95, "blocked", []string{"règle"}); err != nil {
		t.Fatalf("UpdateTransactionScore: %v", err)
	}

	for _, c := range []struct {
		what   string
		filter model.ListTransactionsFilter
		want   int
	}{
		{"all", model.ListTransactionsFilter{Page: 1, PageSize: 50}, 2},
		{"by channel", model.ListTransactionsFilter{Channel: "card", Page: 1, PageSize: 50}, 1},
		{"by status", model.ListTransactionsFilter{Status: "blocked", Page: 1, PageSize: 50}, 1},
		{"above a score", model.ListTransactionsFilter{MinScore: intp(90), Page: 1, PageSize: 50}, 1},
		{"above a score nobody reaches", model.ListTransactionsFilter{MinScore: intp(99), Page: 1, PageSize: 50}, 0},
		{"by sender", model.ListTransactionsFilter{SenderAcct: "4970XXXXXXXX1234", Page: 1, PageSize: 50}, 1},
	} {
		rows, total, err := r.ListTransactions(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListTransactions %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
	_ = card
}

func boolp(b bool) *bool { return &b }
func intp(n int) *int    { return &n }
