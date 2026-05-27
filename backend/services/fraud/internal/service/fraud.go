package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/fraud/internal/model"
	"github.com/cyberradar/platform/services/fraud/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// FraudService orchestrates fraud detection and financial crime management.
type FraudService struct {
	repo     *repository.FraudRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewFraudService creates a FraudService.
func NewFraudService(repo *repository.FraudRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *FraudService {
	return &FraudService{repo: repo, producer: producer, logger: logger}
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (s *FraudService) CreateRule(ctx context.Context, tenantID uuid.UUID, req *model.CreateRuleRequest, createdBy uuid.UUID) (*model.FraudRule, error) {
	rule, err := s.repo.CreateRule(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create rule", err)
	}
	s.logger.Info().Str("rule_id", rule.ID.String()).Str("name", rule.Name).Msg("fraud_rule_created")
	return rule, nil
}

func (s *FraudService) GetRule(ctx context.Context, tenantID, ruleID uuid.UUID) (*model.FraudRule, error) {
	rule, err := s.repo.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		return nil, apierrors.Internal("get rule", err)
	}
	if rule == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "rule not found")
	}
	return rule, nil
}

func (s *FraudService) ListRules(ctx context.Context, tenantID uuid.UUID, category string, activeOnly bool, page, pageSize int) ([]*model.FraudRule, int, error) {
	rules, total, err := s.repo.ListRules(ctx, tenantID, category, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list rules", err)
	}
	return rules, total, nil
}

func (s *FraudService) UpdateRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *model.UpdateRuleRequest) (*model.FraudRule, error) {
	rule, err := s.repo.UpdateRule(ctx, tenantID, ruleID, req)
	if err != nil {
		return nil, apierrors.Internal("update rule", err)
	}
	if rule == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "rule not found")
	}
	return rule, nil
}

// ─── Transactions ─────────────────────────────────────────────────────────────

// IngestAndScore ingests a transaction, runs all active rules against it, computes
// a composite fraud score, and publishes a Kafka event if score >= 50.
func (s *FraudService) IngestAndScore(ctx context.Context, tenantID uuid.UUID, req *model.IngestTransactionRequest) (*model.FraudTransaction, error) {
	// Persist transaction
	txn, err := s.repo.IngestTransaction(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("ingest transaction", err)
	}

	// Evaluate rules asynchronously so ingestion is non-blocking
	go s.evaluateRules(tenantID, txn, req)
	return txn, nil
}

func (s *FraudService) evaluateRules(tenantID uuid.UUID, txn *model.FraudTransaction, req *model.IngestTransactionRequest) {
	ctx := context.Background()

	// Load active rules
	rules, err := s.repo.ListActiveRules(ctx, tenantID)
	if err != nil {
		s.logger.Error().Err(err).Msg("fraud_eval_load_rules_failed")
		return
	}

	// Check watchlist for sender/receiver
	watchValues := []string{}
	if req.SenderAccount != "" {
		watchValues = append(watchValues, req.SenderAccount)
	}
	if req.ReceiverAccount != "" {
		watchValues = append(watchValues, req.ReceiverAccount)
	}
	if req.SenderEntity != "" {
		watchValues = append(watchValues, req.SenderEntity)
	}
	if req.CountryOrigin != "" {
		watchValues = append(watchValues, req.CountryOrigin)
	}
	if req.CountryDest != "" {
		watchValues = append(watchValues, req.CountryDest)
	}
	watchHits, _ := s.repo.CheckWatchlist(ctx, tenantID, watchValues)

	totalScore := 0
	flaggedBy := []string{}

	// Evaluate each rule
	for _, rule := range rules {
		triggered, contrib, evidence := s.evaluateRule(rule, txn, watchHits)
		if !triggered {
			continue
		}
		flaggedBy = append(flaggedBy, rule.ID.String())
		totalScore += contrib
		_, _ = s.repo.CreateSignal(ctx, tenantID, &txn.ID, &rule.ID, rule.Category,
			fmt.Sprintf("Rule '%s' triggered: %s", rule.Name, rule.Description),
			contrib, evidence)
		s.repo.IncrementRuleCounter(ctx, rule.ID)
	}

	// Watchlist signals (independent of rules)
	for _, wh := range watchHits {
		contrib := 30
		if wh.Severity == model.SeverityCritical {
			contrib = 50
		} else if wh.Severity == model.SeverityHigh {
			contrib = 35
		}
		totalScore += contrib
		_, _ = s.repo.CreateSignal(ctx, tenantID, &txn.ID, nil, "watchlist_hit",
			fmt.Sprintf("Entity '%s' found on %s watchlist: %s", wh.EntityValue, wh.ListType, wh.Reason),
			contrib, map[string]any{"entry_id": wh.ID, "list_type": wh.ListType, "severity": wh.Severity})
	}

	// Cap score at 100
	finalScore := int(math.Min(100, float64(totalScore)))

	// Determine status
	status := model.TxnStatusCleared
	if finalScore >= 80 {
		status = model.TxnStatusBlocked
	} else if finalScore >= 50 {
		status = model.TxnStatusFlagged
	} else if finalScore >= 30 {
		status = model.TxnStatusUnderReview
	}

	_ = s.repo.UpdateTransactionScore(ctx, txn.ID, finalScore, status, flaggedBy)

	// Publish Kafka event for flagged/blocked transactions
	if finalScore >= 50 {
		s.logger.Warn().
			Str("txn_id", txn.TransactionID).
			Int("score", finalScore).
			Str("status", status).
			Msg("fraud_transaction_flagged")

		payload := map[string]any{
			"event_type":     "fraud.transaction_flagged",
			"tenant_id":      tenantID.String(),
			"transaction_id": txn.ID.String(),
			"ext_txn_id":     txn.TransactionID,
			"fraud_score":    finalScore,
			"status":         status,
			"channel":        txn.Channel,
			"amount":         txn.Amount,
			"currency":       txn.Currency,
			"flagged_by":     flaggedBy,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(payload)
		_ = s.producer.Publish(ctx, txn.ID.String(), data)
	}
}

// evaluateRule applies a single rule to a transaction.
// Returns (triggered, riskContribution, evidence).
func (s *FraudService) evaluateRule(rule *model.FraudRule, txn *model.FraudTransaction, watchHits []*model.FraudWatchlistEntry) (bool, int, map[string]any) {
	evidence := map[string]any{"rule_id": rule.ID, "rule_type": rule.RuleType}

	switch rule.RuleType {
	case model.RuleTypeThreshold:
		// conditions: {"field":"amount","operator":"gt","value":10000}
		field, _ := rule.Conditions["field"].(string)
		op, _ := rule.Conditions["operator"].(string)
		threshold, _ := rule.Conditions["value"].(float64)
		var fieldVal float64
		if field == "amount" {
			fieldVal = txn.Amount
		}
		triggered := false
		switch op {
		case "gt":
			triggered = fieldVal > threshold
		case "gte":
			triggered = fieldVal >= threshold
		case "lt":
			triggered = fieldVal < threshold
		}
		if triggered {
			evidence["field"] = field
			evidence["value"] = fieldVal
			evidence["threshold"] = threshold
		}
		return triggered, rule.RiskScore, evidence

	case model.RuleTypeWatchlist:
		return len(watchHits) > 0, rule.RiskScore, map[string]any{"watchlist_hits": len(watchHits)}

	case model.RuleTypePattern:
		// conditions: {"channel":"swift","country_dest":"IR"}
		triggered := true
		for k, v := range rule.Conditions {
			switch k {
			case "channel":
				if txn.Channel != fmt.Sprintf("%v", v) {
					triggered = false
				}
			case "country_dest":
				if txn.CountryDest != fmt.Sprintf("%v", v) {
					triggered = false
				}
			case "country_origin":
				if txn.CountryOrigin != fmt.Sprintf("%v", v) {
					triggered = false
				}
			}
		}
		return triggered, rule.RiskScore, evidence

	default:
		return false, 0, nil
	}
}

func (s *FraudService) GetTransaction(ctx context.Context, tenantID, txnID uuid.UUID) (*model.FraudTransaction, error) {
	txn, err := s.repo.GetTransaction(ctx, tenantID, txnID)
	if err != nil {
		return nil, apierrors.Internal("get transaction", err)
	}
	if txn == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "transaction not found")
	}
	return txn, nil
}

func (s *FraudService) ListTransactions(ctx context.Context, tenantID uuid.UUID, f model.ListTransactionsFilter) ([]*model.FraudTransaction, int, error) {
	txns, total, err := s.repo.ListTransactions(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list transactions", err)
	}
	return txns, total, nil
}

func (s *FraudService) UpdateTransactionStatus(ctx context.Context, tenantID, txnID uuid.UUID, status string) (*model.FraudTransaction, error) {
	txn, err := s.repo.UpdateTransactionStatus(ctx, tenantID, txnID, status)
	if err != nil {
		return nil, apierrors.Internal("update transaction status", err)
	}
	if txn == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "transaction not found")
	}
	return txn, nil
}

// ─── Cases ────────────────────────────────────────────────────────────────────

func (s *FraudService) CreateCase(ctx context.Context, tenantID uuid.UUID, req *model.CreateCaseRequest) (*model.FraudCase, error) {
	c, err := s.repo.CreateCase(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create case", err)
	}
	s.logger.Warn().Str("case_id", c.ID.String()).Str("case_number", c.CaseNumber).Str("category", c.Category).Msg("fraud_case_created")
	return c, nil
}

func (s *FraudService) GetCase(ctx context.Context, tenantID, caseID uuid.UUID) (*model.FraudCase, error) {
	c, err := s.repo.GetCase(ctx, tenantID, caseID)
	if err != nil {
		return nil, apierrors.Internal("get case", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "case not found")
	}
	return c, nil
}

func (s *FraudService) ListCases(ctx context.Context, tenantID uuid.UUID, f model.ListCasesFilter) ([]*model.FraudCase, int, error) {
	cases, total, err := s.repo.ListCases(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list cases", err)
	}
	return cases, total, nil
}

func (s *FraudService) UpdateCase(ctx context.Context, tenantID, caseID uuid.UUID, req *model.UpdateCaseRequest) (*model.FraudCase, error) {
	c, err := s.repo.UpdateCase(ctx, tenantID, caseID, req)
	if err != nil {
		return nil, apierrors.Internal("update case", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "case not found")
	}
	return c, nil
}

// ─── Watchlist ────────────────────────────────────────────────────────────────

func (s *FraudService) AddWatchlistEntry(ctx context.Context, tenantID uuid.UUID, req *model.AddWatchlistRequest, addedBy uuid.UUID) (*model.FraudWatchlistEntry, error) {
	e, err := s.repo.AddWatchlistEntry(ctx, tenantID, req, addedBy)
	if err != nil {
		return nil, apierrors.Internal("add watchlist entry", err)
	}
	s.logger.Info().Str("entry_id", e.ID.String()).Str("value", e.EntityValue).Str("list", e.ListType).Msg("fraud_watchlist_entry_added")
	return e, nil
}

func (s *FraudService) ListWatchlist(ctx context.Context, tenantID uuid.UUID, entityType, listType string, activeOnly bool, page, pageSize int) ([]*model.FraudWatchlistEntry, int, error) {
	entries, total, err := s.repo.ListWatchlist(ctx, tenantID, entityType, listType, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list watchlist", err)
	}
	return entries, total, nil
}

func (s *FraudService) RemoveWatchlistEntry(ctx context.Context, tenantID, entryID uuid.UUID) error {
	if err := s.repo.RemoveWatchlistEntry(ctx, tenantID, entryID); err != nil {
		return apierrors.Internal("remove watchlist entry", err)
	}
	return nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *FraudService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.FraudStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("stats", err)
	}
	return stats, nil
}
