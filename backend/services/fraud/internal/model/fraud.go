package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Categories ───────────────────────────────────────────────────────────────

const (
	CategoryAML             = "aml"
	CategoryCardFraud       = "card_fraud"
	CategoryAccountTakeover = "account_takeover"
	CategoryInsiderThreat   = "insider_threat"
	CategorySWIFTFraud      = "swift_fraud"
	CategoryWireFraud       = "wire_fraud"
	CategoryIdentityTheft   = "identity_theft"
	CategoryMoneyLaundering = "money_laundering"
)

// ─── Rule types ───────────────────────────────────────────────────────────────

const (
	RuleTypeThreshold = "threshold"
	RuleTypePattern   = "pattern"
	RuleTypeVelocity  = "velocity"
	RuleTypeMLScore   = "ml_score"
	RuleTypeWatchlist = "watchlist"
)

// ─── Channels ─────────────────────────────────────────────────────────────────

const (
	ChannelSWIFT    = "swift"
	ChannelWire     = "wire"
	ChannelCard     = "card"
	ChannelATM      = "atm"
	ChannelOnline   = "online"
	ChannelMobile   = "mobile"
	ChannelInternal = "internal"
	ChannelSEPA     = "sepa"
)

// ─── Transaction statuses ─────────────────────────────────────────────────────

const (
	TxnStatusPending     = "pending"
	TxnStatusCleared     = "cleared"
	TxnStatusFlagged     = "flagged"
	TxnStatusBlocked     = "blocked"
	TxnStatusUnderReview = "under_review"
)

// ─── Case statuses ────────────────────────────────────────────────────────────

const (
	CaseStatusOpen               = "open"
	CaseStatusUnderReview        = "under_review"
	CaseStatusEscalated          = "escalated"
	CaseStatusSARFiled           = "sar_filed"
	CaseStatusClosedConfirmed    = "closed_confirmed"
	CaseStatusClosedFalsePositive = "closed_false_positive"
)

// ─── Severities ───────────────────────────────────────────────────────────────

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ─── Watchlist types ──────────────────────────────────────────────────────────

const (
	WatchlistInternal    = "internal"
	WatchlistSanctions   = "sanctions"
	WatchlistPEP         = "pep"
	WatchlistAdverseMedia = "adverse_media"
	WatchlistCustom      = "custom"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type FraudRule struct {
	ID             uuid.UUID      `json:"id"`
	TenantID       uuid.UUID      `json:"tenant_id"`
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	Category       string         `json:"category"`
	RuleType       string         `json:"rule_type"`
	Conditions     map[string]any `json:"conditions"`
	RiskScore      int            `json:"risk_score"`
	IsActive       bool           `json:"is_active"`
	TriggeredCount int64          `json:"triggered_count"`
	CreatedBy      *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type FraudTransaction struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	TransactionID   string         `json:"transaction_id"`
	Channel         string         `json:"channel"`
	Amount          float64        `json:"amount"`
	Currency        string         `json:"currency"`
	SenderAccount   string         `json:"sender_account,omitempty"`
	SenderEntity    string         `json:"sender_entity,omitempty"`
	ReceiverAccount string         `json:"receiver_account,omitempty"`
	ReceiverEntity  string         `json:"receiver_entity,omitempty"`
	CountryOrigin   string         `json:"country_origin,omitempty"`
	CountryDest     string         `json:"country_dest,omitempty"`
	Metadata        map[string]any `json:"metadata"`
	FraudScore      int            `json:"fraud_score"`
	Status          string         `json:"status"`
	FlaggedBy       []string       `json:"flagged_by"`
	TransactedAt    time.Time      `json:"transacted_at"`
	CreatedAt       time.Time      `json:"created_at"`
	Signals         []*FraudSignal `json:"signals,omitempty"`
}

type FraudSignal struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	TransactionID    *uuid.UUID     `json:"transaction_id,omitempty"`
	RuleID           *uuid.UUID     `json:"rule_id,omitempty"`
	SignalType       string         `json:"signal_type"`
	Description      string         `json:"description"`
	RiskContribution int            `json:"risk_contribution"`
	Evidence         map[string]any `json:"evidence"`
	CreatedAt        time.Time      `json:"created_at"`
}

type FraudCase struct {
	ID             uuid.UUID    `json:"id"`
	TenantID       uuid.UUID    `json:"tenant_id"`
	CaseNumber     string       `json:"case_number"`
	Title          string       `json:"title"`
	Category       string       `json:"category"`
	Severity       string       `json:"severity"`
	Status         string       `json:"status"`
	AssignedTo     *uuid.UUID   `json:"assigned_to,omitempty"`
	TransactionIDs []uuid.UUID  `json:"transaction_ids"`
	TotalAmount    float64      `json:"total_amount"`
	Currency       string       `json:"currency"`
	SARRequired    bool         `json:"sar_required"`
	SARFiledAt     *time.Time   `json:"sar_filed_at,omitempty"`
	Notes          string       `json:"notes,omitempty"`
	ResolvedAt     *time.Time   `json:"resolved_at,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type FraudWatchlistEntry struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	EntityType  string     `json:"entity_type"`
	EntityValue string     `json:"entity_value"`
	Reason      string     `json:"reason"`
	ListType    string     `json:"list_type"`
	Severity    string     `json:"severity"`
	IsActive    bool       `json:"is_active"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AddedBy     *uuid.UUID `json:"added_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type FraudStats struct {
	TotalTransactions    int                `json:"total_transactions"`
	FlaggedTransactions  int                `json:"flagged_transactions"`
	BlockedTransactions  int                `json:"blocked_transactions"`
	OpenCases            int                `json:"open_cases"`
	SARRequired          int                `json:"sar_required"`
	WatchlistEntries     int                `json:"watchlist_entries"`
	TotalSuspiciousAmt   float64            `json:"total_suspicious_amount"`
	TransactionsByStatus map[string]int     `json:"transactions_by_status"`
	CasesByCategory      map[string]int     `json:"cases_by_category"`
	TopRules             []*RuleStats       `json:"top_rules"`
}

type RuleStats struct {
	RuleID   uuid.UUID `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	Count    int64     `json:"triggered_count"`
}

// ─── Request models ───────────────────────────────────────────────────────────

type CreateRuleRequest struct {
	Name        string         `json:"name"       validate:"required"`
	Description string         `json:"description"`
	Category    string         `json:"category"   validate:"required"`
	RuleType    string         `json:"rule_type"  validate:"required"`
	Conditions  map[string]any `json:"conditions" validate:"required"`
	RiskScore   int            `json:"risk_score" validate:"min=0,max=100"`
}

type UpdateRuleRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Conditions  map[string]any `json:"conditions"`
	RiskScore   *int           `json:"risk_score"`
	IsActive    *bool          `json:"is_active"`
}

type IngestTransactionRequest struct {
	TransactionID   string         `json:"transaction_id"   validate:"required"`
	Channel         string         `json:"channel"          validate:"required"`
	Amount          float64        `json:"amount"           validate:"required,gt=0"`
	Currency        string         `json:"currency"         validate:"required,len=3"`
	SenderAccount   string         `json:"sender_account"`
	SenderEntity    string         `json:"sender_entity"`
	ReceiverAccount string         `json:"receiver_account"`
	ReceiverEntity  string         `json:"receiver_entity"`
	CountryOrigin   string         `json:"country_origin"`
	CountryDest     string         `json:"country_dest"`
	Metadata        map[string]any `json:"metadata"`
	TransactedAt    time.Time      `json:"transacted_at"    validate:"required"`
}

type UpdateTransactionStatusRequest struct {
	Status string `json:"status" validate:"required"`
}

type CreateCaseRequest struct {
	Title          string      `json:"title"            validate:"required"`
	Category       string      `json:"category"         validate:"required"`
	Severity       string      `json:"severity"         validate:"required"`
	TransactionIDs []uuid.UUID `json:"transaction_ids"`
	TotalAmount    float64     `json:"total_amount"`
	Currency       string      `json:"currency"`
	Notes          string      `json:"notes"`
}

type UpdateCaseRequest struct {
	Status     string     `json:"status"`
	AssignedTo *uuid.UUID `json:"assigned_to"`
	SARRequired *bool     `json:"sar_required"`
	Notes      string     `json:"notes"`
}

type AddWatchlistRequest struct {
	EntityType  string     `json:"entity_type"  validate:"required"`
	EntityValue string     `json:"entity_value" validate:"required"`
	Reason      string     `json:"reason"       validate:"required"`
	ListType    string     `json:"list_type"    validate:"required"`
	Severity    string     `json:"severity"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type ListTransactionsFilter struct {
	Channel      string
	Status       string
	MinScore     *int
	SenderAcct   string
	ReceiverAcct string
	Page         int
	PageSize     int
}

type ListCasesFilter struct {
	Category string
	Status   string
	Severity string
	Page     int
	PageSize int
}
