package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/fraud/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FraudRepository handles all fraud persistence.
type FraudRepository struct {
	db *pgxpool.Pool
}

// NewFraudRepository creates a FraudRepository.
func NewFraudRepository(db *pgxpool.Pool) *FraudRepository {
	return &FraudRepository{db: db}
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (r *FraudRepository) CreateRule(ctx context.Context, tenantID uuid.UUID, req *model.CreateRuleRequest, createdBy uuid.UUID) (*model.FraudRule, error) {
	cond, _ := json.Marshal(req.Conditions)
	var rule model.FraudRule
	var condRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO fraud_rules (tenant_id, name, description, category, rule_type, conditions, risk_score, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, tenant_id, name, COALESCE(description,''), category, rule_type,
		          conditions, risk_score, is_active, triggered_count, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.Category, req.RuleType, cond, req.RiskScore, createdBy,
	).Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.Category, &rule.RuleType,
		&condRaw, &rule.RiskScore, &rule.IsActive, &rule.TriggeredCount, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condRaw, &rule.Conditions)
	return &rule, nil
}

func (r *FraudRepository) GetRule(ctx context.Context, tenantID, ruleID uuid.UUID) (*model.FraudRule, error) {
	var rule model.FraudRule
	var condRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), category, rule_type,
		       conditions, risk_score, is_active, triggered_count, created_by, created_at, updated_at
		FROM fraud_rules WHERE id=$1 AND tenant_id=$2`,
		ruleID, tenantID,
	).Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.Category, &rule.RuleType,
		&condRaw, &rule.RiskScore, &rule.IsActive, &rule.TriggeredCount, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condRaw, &rule.Conditions)
	return &rule, nil
}

func (r *FraudRepository) ListRules(ctx context.Context, tenantID uuid.UUID, category string, activeOnly bool, page, pageSize int) ([]*model.FraudRule, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if category != "" {
		conditions = append(conditions, fmt.Sprintf("category=$%d", n))
		args = append(args, category)
		n++
	}
	if activeOnly {
		conditions = append(conditions, "is_active=TRUE")
	}
	where := strings.Join(conditions, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM fraud_rules WHERE "+where, args...).Scan(&total)

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, name, COALESCE(description,''), category, rule_type,
		       conditions, risk_score, is_active, triggered_count, created_by, created_at, updated_at
		FROM fraud_rules WHERE %s ORDER BY triggered_count DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var rules []*model.FraudRule
	for rows.Next() {
		var rule model.FraudRule
		var condRaw []byte
		if err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.Category, &rule.RuleType,
			&condRaw, &rule.RiskScore, &rule.IsActive, &rule.TriggeredCount, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(condRaw, &rule.Conditions)
		rules = append(rules, &rule)
	}
	return rules, total, nil
}

func (r *FraudRepository) UpdateRule(ctx context.Context, tenantID, ruleID uuid.UUID, req *model.UpdateRuleRequest) (*model.FraudRule, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Name != "" {
		sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, req.Name); n++
	}
	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++
	}
	if req.Conditions != nil {
		cond, _ := json.Marshal(req.Conditions)
		sets = append(sets, fmt.Sprintf("conditions=$%d", n)); args = append(args, cond); n++
	}
	if req.RiskScore != nil {
		sets = append(sets, fmt.Sprintf("risk_score=$%d", n)); args = append(args, *req.RiskScore); n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++
	}
	args = append(args, ruleID, tenantID)
	var rule model.FraudRule
	var condRaw []byte
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE fraud_rules SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, name, COALESCE(description,''), category, rule_type,
		          conditions, risk_score, is_active, triggered_count, created_by, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.Category, &rule.RuleType,
		&condRaw, &rule.RiskScore, &rule.IsActive, &rule.TriggeredCount, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condRaw, &rule.Conditions)
	return &rule, nil
}

func (r *FraudRepository) ListActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*model.FraudRule, error) {
	rules, _, err := r.ListRules(ctx, tenantID, "", true, 1, 1000)
	return rules, err
}

func (r *FraudRepository) IncrementRuleCounter(ctx context.Context, ruleID uuid.UUID) {
	_, _ = r.db.Exec(ctx, "UPDATE fraud_rules SET triggered_count=triggered_count+1 WHERE id=$1", ruleID)
}

// ─── Transactions ─────────────────────────────────────────────────────────────

func (r *FraudRepository) IngestTransaction(ctx context.Context, tenantID uuid.UUID, req *model.IngestTransactionRequest) (*model.FraudTransaction, error) {
	meta, _ := json.Marshal(req.Metadata)
	var txn model.FraudTransaction
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO fraud_transactions
		  (tenant_id, transaction_id, channel, amount, currency,
		   sender_account, sender_entity, receiver_account, receiver_entity,
		   country_origin, country_dest, metadata, transacted_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (tenant_id, transaction_id) DO UPDATE
		  SET channel=EXCLUDED.channel, amount=EXCLUDED.amount, metadata=EXCLUDED.metadata
		RETURNING id, tenant_id, transaction_id, channel, amount, currency,
		          COALESCE(sender_account,''), COALESCE(sender_entity,''),
		          COALESCE(receiver_account,''), COALESCE(receiver_entity,''),
		          COALESCE(country_origin,''), COALESCE(country_dest,''),
		          metadata, fraud_score, status, COALESCE(flagged_by,'{}'), transacted_at, created_at`,
		tenantID, req.TransactionID, req.Channel, req.Amount, req.Currency,
		req.SenderAccount, req.SenderEntity, req.ReceiverAccount, req.ReceiverEntity,
		req.CountryOrigin, req.CountryDest, meta, req.TransactedAt,
	).Scan(
		&txn.ID, &txn.TenantID, &txn.TransactionID, &txn.Channel, &txn.Amount, &txn.Currency,
		&txn.SenderAccount, &txn.SenderEntity, &txn.ReceiverAccount, &txn.ReceiverEntity,
		&txn.CountryOrigin, &txn.CountryDest,
		&metaRaw, &txn.FraudScore, &txn.Status, &txn.FlaggedBy, &txn.TransactedAt, &txn.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &txn.Metadata)
	return &txn, nil
}

func (r *FraudRepository) GetTransaction(ctx context.Context, tenantID, txnID uuid.UUID) (*model.FraudTransaction, error) {
	var txn model.FraudTransaction
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, transaction_id, channel, amount, currency,
		       COALESCE(sender_account,''), COALESCE(sender_entity,''),
		       COALESCE(receiver_account,''), COALESCE(receiver_entity,''),
		       COALESCE(country_origin,''), COALESCE(country_dest,''),
		       metadata, fraud_score, status, COALESCE(flagged_by,'{}'), transacted_at, created_at
		FROM fraud_transactions WHERE id=$1 AND tenant_id=$2`,
		txnID, tenantID,
	).Scan(
		&txn.ID, &txn.TenantID, &txn.TransactionID, &txn.Channel, &txn.Amount, &txn.Currency,
		&txn.SenderAccount, &txn.SenderEntity, &txn.ReceiverAccount, &txn.ReceiverEntity,
		&txn.CountryOrigin, &txn.CountryDest,
		&metaRaw, &txn.FraudScore, &txn.Status, &txn.FlaggedBy, &txn.TransactedAt, &txn.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &txn.Metadata)

	// Load signals
	sigs, _ := r.listSignalsByTxn(ctx, txnID)
	txn.Signals = sigs
	return &txn, nil
}

func (r *FraudRepository) ListTransactions(ctx context.Context, tenantID uuid.UUID, f model.ListTransactionsFilter) ([]*model.FraudTransaction, int, error) {
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Channel != "" {
		conditions = append(conditions, fmt.Sprintf("channel=$%d", n)); args = append(args, f.Channel); n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n)); args = append(args, f.Status); n++
	}
	if f.MinScore != nil {
		conditions = append(conditions, fmt.Sprintf("fraud_score>=$%d", n)); args = append(args, *f.MinScore); n++
	}
	if f.SenderAcct != "" {
		conditions = append(conditions, fmt.Sprintf("sender_account=$%d", n)); args = append(args, f.SenderAcct); n++
	}
	if f.ReceiverAcct != "" {
		conditions = append(conditions, fmt.Sprintf("receiver_account=$%d", n)); args = append(args, f.ReceiverAcct); n++
	}
	where := strings.Join(conditions, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM fraud_transactions WHERE "+where, args...).Scan(&total)

	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, transaction_id, channel, amount, currency,
		       COALESCE(sender_account,''), COALESCE(sender_entity,''),
		       COALESCE(receiver_account,''), COALESCE(receiver_entity,''),
		       COALESCE(country_origin,''), COALESCE(country_dest,''),
		       metadata, fraud_score, status, COALESCE(flagged_by,'{}'), transacted_at, created_at
		FROM fraud_transactions WHERE %s
		ORDER BY transacted_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var txns []*model.FraudTransaction
	for rows.Next() {
		var txn model.FraudTransaction
		var metaRaw []byte
		if err := rows.Scan(
			&txn.ID, &txn.TenantID, &txn.TransactionID, &txn.Channel, &txn.Amount, &txn.Currency,
			&txn.SenderAccount, &txn.SenderEntity, &txn.ReceiverAccount, &txn.ReceiverEntity,
			&txn.CountryOrigin, &txn.CountryDest,
			&metaRaw, &txn.FraudScore, &txn.Status, &txn.FlaggedBy, &txn.TransactedAt, &txn.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(metaRaw, &txn.Metadata)
		txns = append(txns, &txn)
	}
	return txns, total, nil
}

func (r *FraudRepository) UpdateTransactionScore(ctx context.Context, txnID uuid.UUID, score int, status string, flaggedBy []string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE fraud_transactions SET fraud_score=$2, status=$3, flagged_by=$4 WHERE id=$1`,
		txnID, score, status, flaggedBy,
	)
	return err
}

func (r *FraudRepository) UpdateTransactionStatus(ctx context.Context, tenantID, txnID uuid.UUID, status string) (*model.FraudTransaction, error) {
	var txn model.FraudTransaction
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		UPDATE fraud_transactions SET status=$3 WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, transaction_id, channel, amount, currency,
		          COALESCE(sender_account,''), COALESCE(sender_entity,''),
		          COALESCE(receiver_account,''), COALESCE(receiver_entity,''),
		          COALESCE(country_origin,''), COALESCE(country_dest,''),
		          metadata, fraud_score, status, COALESCE(flagged_by,'{}'), transacted_at, created_at`,
		txnID, tenantID, status,
	).Scan(
		&txn.ID, &txn.TenantID, &txn.TransactionID, &txn.Channel, &txn.Amount, &txn.Currency,
		&txn.SenderAccount, &txn.SenderEntity, &txn.ReceiverAccount, &txn.ReceiverEntity,
		&txn.CountryOrigin, &txn.CountryDest,
		&metaRaw, &txn.FraudScore, &txn.Status, &txn.FlaggedBy, &txn.TransactedAt, &txn.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &txn.Metadata)
	return &txn, nil
}

// ─── Signals ──────────────────────────────────────────────────────────────────

func (r *FraudRepository) CreateSignal(ctx context.Context, tenantID uuid.UUID, txnID *uuid.UUID, ruleID *uuid.UUID, signalType, desc string, riskContrib int, evidence map[string]any) (*model.FraudSignal, error) {
	ev, _ := json.Marshal(evidence)
	var s model.FraudSignal
	var evRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO fraud_signals (tenant_id, transaction_id, rule_id, signal_type, description, risk_contribution, evidence)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, tenant_id, transaction_id, rule_id, signal_type, description, risk_contribution, evidence, created_at`,
		tenantID, txnID, ruleID, signalType, desc, riskContrib, ev,
	).Scan(&s.ID, &s.TenantID, &s.TransactionID, &s.RuleID, &s.SignalType, &s.Description, &s.RiskContribution, &evRaw, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(evRaw, &s.Evidence)
	return &s, nil
}

func (r *FraudRepository) listSignalsByTxn(ctx context.Context, txnID uuid.UUID) ([]*model.FraudSignal, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, transaction_id, rule_id, signal_type, description, risk_contribution, evidence, created_at
		FROM fraud_signals WHERE transaction_id=$1 ORDER BY created_at`, txnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sigs []*model.FraudSignal
	for rows.Next() {
		var s model.FraudSignal
		var evRaw []byte
		if err := rows.Scan(&s.ID, &s.TenantID, &s.TransactionID, &s.RuleID, &s.SignalType, &s.Description, &s.RiskContribution, &evRaw, &s.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evRaw, &s.Evidence)
		sigs = append(sigs, &s)
	}
	return sigs, nil
}

// ─── Cases ────────────────────────────────────────────────────────────────────

func (r *FraudRepository) CreateCase(ctx context.Context, tenantID uuid.UUID, req *model.CreateCaseRequest) (*model.FraudCase, error) {
	// Generate case number: FRD-YYYY-NNNNN
	var seq int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*)+1 FROM fraud_cases WHERE tenant_id=$1", tenantID).Scan(&seq)
	caseNumber := fmt.Sprintf("FRD-%s-%05d", time.Now().Format("2006"), seq)

	currency := req.Currency
	if currency == "" {
		currency = "USD"
	}
	var c model.FraudCase
	err := r.db.QueryRow(ctx, `
		INSERT INTO fraud_cases (tenant_id, case_number, title, category, severity, transaction_ids, total_amount, currency, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, tenant_id, case_number, title, category, severity, status,
		          assigned_to, COALESCE(transaction_ids,'{}'), total_amount, currency,
		          sar_required, sar_filed_at, COALESCE(notes,''), resolved_at, created_at, updated_at`,
		tenantID, caseNumber, req.Title, req.Category, req.Severity,
		req.TransactionIDs, req.TotalAmount, currency, req.Notes,
	).Scan(
		&c.ID, &c.TenantID, &c.CaseNumber, &c.Title, &c.Category, &c.Severity, &c.Status,
		&c.AssignedTo, &c.TransactionIDs, &c.TotalAmount, &c.Currency,
		&c.SARRequired, &c.SARFiledAt, &c.Notes, &c.ResolvedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	return &c, err
}

func (r *FraudRepository) GetCase(ctx context.Context, tenantID, caseID uuid.UUID) (*model.FraudCase, error) {
	var c model.FraudCase
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, case_number, title, category, severity, status,
		       assigned_to, COALESCE(transaction_ids,'{}'), total_amount, currency,
		       sar_required, sar_filed_at, COALESCE(notes,''), resolved_at, created_at, updated_at
		FROM fraud_cases WHERE id=$1 AND tenant_id=$2`,
		caseID, tenantID,
	).Scan(
		&c.ID, &c.TenantID, &c.CaseNumber, &c.Title, &c.Category, &c.Severity, &c.Status,
		&c.AssignedTo, &c.TransactionIDs, &c.TotalAmount, &c.Currency,
		&c.SARRequired, &c.SARFiledAt, &c.Notes, &c.ResolvedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (r *FraudRepository) ListCases(ctx context.Context, tenantID uuid.UUID, f model.ListCasesFilter) ([]*model.FraudCase, int, error) {
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category=$%d", n)); args = append(args, f.Category); n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n)); args = append(args, f.Status); n++
	}
	if f.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", n)); args = append(args, f.Severity); n++
	}
	where := strings.Join(conditions, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM fraud_cases WHERE "+where, args...).Scan(&total)

	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, case_number, title, category, severity, status,
		       assigned_to, COALESCE(transaction_ids,'{}'), total_amount, currency,
		       sar_required, sar_filed_at, COALESCE(notes,''), resolved_at, created_at, updated_at
		FROM fraud_cases WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var cases []*model.FraudCase
	for rows.Next() {
		var c model.FraudCase
		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.CaseNumber, &c.Title, &c.Category, &c.Severity, &c.Status,
			&c.AssignedTo, &c.TransactionIDs, &c.TotalAmount, &c.Currency,
			&c.SARRequired, &c.SARFiledAt, &c.Notes, &c.ResolvedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		cases = append(cases, &c)
	}
	return cases, total, nil
}

func (r *FraudRepository) UpdateCase(ctx context.Context, tenantID, caseID uuid.UUID, req *model.UpdateCaseRequest) (*model.FraudCase, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, req.Status); n++
		if req.Status == model.CaseStatusClosedConfirmed || req.Status == model.CaseStatusClosedFalsePositive {
			sets = append(sets, fmt.Sprintf("resolved_at=$%d", n)); args = append(args, time.Now()); n++
		}
		if req.Status == model.CaseStatusSARFiled {
			sets = append(sets, fmt.Sprintf("sar_filed_at=$%d", n)); args = append(args, time.Now()); n++
		}
	}
	if req.AssignedTo != nil {
		sets = append(sets, fmt.Sprintf("assigned_to=$%d", n)); args = append(args, *req.AssignedTo); n++
	}
	if req.SARRequired != nil {
		sets = append(sets, fmt.Sprintf("sar_required=$%d", n)); args = append(args, *req.SARRequired); n++
	}
	if req.Notes != "" {
		sets = append(sets, fmt.Sprintf("notes=$%d", n)); args = append(args, req.Notes); n++
	}
	args = append(args, caseID, tenantID)
	var c model.FraudCase
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE fraud_cases SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, case_number, title, category, severity, status,
		          assigned_to, COALESCE(transaction_ids,'{}'), total_amount, currency,
		          sar_required, sar_filed_at, COALESCE(notes,''), resolved_at, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(
		&c.ID, &c.TenantID, &c.CaseNumber, &c.Title, &c.Category, &c.Severity, &c.Status,
		&c.AssignedTo, &c.TransactionIDs, &c.TotalAmount, &c.Currency,
		&c.SARRequired, &c.SARFiledAt, &c.Notes, &c.ResolvedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

// ─── Watchlist ────────────────────────────────────────────────────────────────

func (r *FraudRepository) AddWatchlistEntry(ctx context.Context, tenantID uuid.UUID, req *model.AddWatchlistRequest, addedBy uuid.UUID) (*model.FraudWatchlistEntry, error) {
	var e model.FraudWatchlistEntry
	err := r.db.QueryRow(ctx, `
		INSERT INTO fraud_watchlist (tenant_id, entity_type, entity_value, reason, list_type, severity, expires_at, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id, entity_type, entity_value, list_type) DO UPDATE
		  SET reason=EXCLUDED.reason, severity=EXCLUDED.severity, is_active=TRUE, expires_at=EXCLUDED.expires_at
		RETURNING id, tenant_id, entity_type, entity_value, reason, list_type,
		          COALESCE(severity,''), is_active, expires_at, added_by, created_at`,
		tenantID, req.EntityType, req.EntityValue, req.Reason, req.ListType, req.Severity, req.ExpiresAt, addedBy,
	).Scan(
		&e.ID, &e.TenantID, &e.EntityType, &e.EntityValue, &e.Reason, &e.ListType,
		&e.Severity, &e.IsActive, &e.ExpiresAt, &e.AddedBy, &e.CreatedAt,
	)
	return &e, err
}

func (r *FraudRepository) ListWatchlist(ctx context.Context, tenantID uuid.UUID, entityType, listType string, activeOnly bool, page, pageSize int) ([]*model.FraudWatchlistEntry, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if entityType != "" {
		conditions = append(conditions, fmt.Sprintf("entity_type=$%d", n)); args = append(args, entityType); n++
	}
	if listType != "" {
		conditions = append(conditions, fmt.Sprintf("list_type=$%d", n)); args = append(args, listType); n++
	}
	if activeOnly {
		conditions = append(conditions, "(expires_at IS NULL OR expires_at > NOW()) AND is_active=TRUE")
	}
	where := strings.Join(conditions, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM fraud_watchlist WHERE "+where, args...).Scan(&total)

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, entity_type, entity_value, reason, list_type,
		       COALESCE(severity,''), is_active, expires_at, added_by, created_at
		FROM fraud_watchlist WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var entries []*model.FraudWatchlistEntry
	for rows.Next() {
		var e model.FraudWatchlistEntry
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.EntityType, &e.EntityValue, &e.Reason, &e.ListType,
			&e.Severity, &e.IsActive, &e.ExpiresAt, &e.AddedBy, &e.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		entries = append(entries, &e)
	}
	return entries, total, nil
}

func (r *FraudRepository) RemoveWatchlistEntry(ctx context.Context, tenantID, entryID uuid.UUID) error {
	res, err := r.db.Exec(ctx,
		"UPDATE fraud_watchlist SET is_active=FALSE WHERE id=$1 AND tenant_id=$2", entryID, tenantID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *FraudRepository) CheckWatchlist(ctx context.Context, tenantID uuid.UUID, values []string) ([]*model.FraudWatchlistEntry, error) {
	if len(values) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, entity_type, entity_value, reason, list_type,
		       COALESCE(severity,''), is_active, expires_at, added_by, created_at
		FROM fraud_watchlist
		WHERE tenant_id=$1 AND entity_value=ANY($2) AND is_active=TRUE
		  AND (expires_at IS NULL OR expires_at > NOW())`,
		tenantID, values,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []*model.FraudWatchlistEntry
	for rows.Next() {
		var e model.FraudWatchlistEntry
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.EntityType, &e.EntityValue, &e.Reason, &e.ListType,
			&e.Severity, &e.IsActive, &e.ExpiresAt, &e.AddedBy, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *FraudRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.FraudStats, error) {
	stats := &model.FraudStats{
		TransactionsByStatus: make(map[string]int),
		CasesByCategory:      make(map[string]int),
	}

	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status IN ('flagged','blocked','under_review')),
		       COUNT(*) FILTER (WHERE status='blocked'),
		       COALESCE(SUM(amount) FILTER (WHERE status IN ('flagged','blocked','under_review')),0)
		FROM fraud_transactions WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalTransactions, &stats.FlaggedTransactions, &stats.BlockedTransactions, &stats.TotalSuspiciousAmt)

	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status NOT IN ('closed_confirmed','closed_false_positive')),
		       COUNT(*) FILTER (WHERE sar_required AND sar_filed_at IS NULL)
		FROM fraud_cases WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.OpenCases, &stats.SARRequired)

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM fraud_watchlist WHERE tenant_id=$1 AND is_active=TRUE", tenantID).
		Scan(&stats.WatchlistEntries)

	rows, err := r.db.Query(ctx, "SELECT status, COUNT(*) FROM fraud_transactions WHERE tenant_id=$1 GROUP BY status", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string; var c int
		_ = rows.Scan(&s, &c)
		stats.TransactionsByStatus[s] = c
	}

	rows2, err := r.db.Query(ctx, "SELECT category, COUNT(*) FROM fraud_cases WHERE tenant_id=$1 GROUP BY category", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var s string; var c int
		_ = rows2.Scan(&s, &c)
		stats.CasesByCategory[s] = c
	}

	rows3, err := r.db.Query(ctx, `
		SELECT id, name, triggered_count FROM fraud_rules
		WHERE tenant_id=$1 ORDER BY triggered_count DESC LIMIT 10`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var rs model.RuleStats
		_ = rows3.Scan(&rs.RuleID, &rs.RuleName, &rs.Count)
		stats.TopRules = append(stats.TopRules, &rs)
	}

	return stats, nil
}
