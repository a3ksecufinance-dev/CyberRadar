package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Asset types ──────────────────────────────────────────────────────────────

const (
	AssetTypeApplication    = "application"
	AssetTypeDatabase       = "database"
	AssetTypeInfrastructure = "infrastructure"
	AssetTypeNetwork        = "network"
	AssetTypeData           = "data"
	AssetTypeThirdParty     = "third_party"
	AssetTypeProcess        = "process"
	AssetTypePeople         = "people"
)

// ─── Criticality levels ───────────────────────────────────────────────────────

const (
	CriticalityCritical = "critical"
	CriticalityHigh     = "high"
	CriticalityMedium   = "medium"
	CriticalityLow      = "low"
)

// ─── Scenario types ───────────────────────────────────────────────────────────

const (
	ScenarioRansomware           = "ransomware"
	ScenarioDataBreach           = "data_breach"
	ScenarioInsiderThreat        = "insider_threat"
	ScenarioSupplyChain          = "supply_chain"
	ScenarioDDoS                 = "ddos"
	ScenarioFraud                = "fraud"
	ScenarioRegulatory           = "regulatory"
	ScenarioBusinessInterruption = "business_interruption"
	ScenarioAPT                  = "apt"
	ScenarioPhishing             = "phishing"
	ScenarioPrivilegeAbuse       = "privilege_abuse"
	ScenarioThirdPartyBreach     = "third_party_breach"
)

// ─── Treatment types ──────────────────────────────────────────────────────────

const (
	TreatmentMitigate = "mitigate"
	TreatmentAccept   = "accept"
	TreatmentTransfer = "transfer"
	TreatmentAvoid    = "avoid"
)

// ─── KRI categories ───────────────────────────────────────────────────────────

const (
	KRICategoryCyber       = "cyber"
	KRICategoryOperational = "operational"
	KRICategoryRegulatory  = "regulatory"
	KRICategoryThirdParty  = "third_party"
	KRICategoryPeople      = "people"
	KRICategoryTechnology  = "technology"
	KRICategoryFinancial   = "financial"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type RiskAsset struct {
	ID                   uuid.UUID      `json:"id"`
	TenantID             uuid.UUID      `json:"tenant_id"`
	Name                 string         `json:"name"`
	Description          string         `json:"description,omitempty"`
	AssetType            string         `json:"asset_type"`
	BusinessUnit         string         `json:"business_unit,omitempty"`
	Owner                string         `json:"owner,omitempty"`
	Criticality          string         `json:"criticality"`
	BusinessValue        int64          `json:"business_value"`
	RevenueImpact        int64          `json:"revenue_impact"`
	RegulatoryImpact     int64          `json:"regulatory_impact"`
	ReputationalImpact   int64          `json:"reputational_impact"`
	InherentRisk         int            `json:"inherent_risk"`
	ResidualRisk         int            `json:"residual_risk"`
	ControlEffectiveness int            `json:"control_effectiveness"`
	ThreatEventFrequency float64        `json:"threat_event_frequency"`
	Vulnerability        float64        `json:"vulnerability"`
	LossMagnitude        float64        `json:"loss_magnitude"`
	ALE                  int64          `json:"ale"`
	IsActive             bool           `json:"is_active"`
	Metadata             map[string]any `json:"metadata"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type RiskScenario struct {
	ID                  uuid.UUID   `json:"id"`
	TenantID            uuid.UUID   `json:"tenant_id"`
	Name                string      `json:"name"`
	Description         string      `json:"description,omitempty"`
	ScenarioType        string      `json:"scenario_type"`
	ThreatActor         string      `json:"threat_actor,omitempty"`
	AnnualProbability   float64     `json:"annual_probability"`
	PrimaryLoss         int64       `json:"primary_loss"`
	SecondaryLoss       int64       `json:"secondary_loss"`
	TotalLoss           int64       `json:"total_loss"`
	RiskLevel           string      `json:"risk_level"`
	RiskScore           int         `json:"risk_score"`
	MitigatingControls  []string    `json:"mitigating_controls"`
	ResidualProbability float64     `json:"residual_probability"`
	ResidualLoss        int64       `json:"residual_loss"`
	Frameworks          []string    `json:"frameworks"`
	AssetIDs            []uuid.UUID `json:"asset_ids"`
	Status              string      `json:"status"`
	ReviewedAt          *time.Time  `json:"reviewed_at,omitempty"`
	ReviewedBy          *uuid.UUID  `json:"reviewed_by,omitempty"`
	CreatedBy           *uuid.UUID  `json:"created_by,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
	UpdatedAt           time.Time   `json:"updated_at"`
}

type RiskTreatment struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	ScenarioID    uuid.UUID  `json:"scenario_id"`
	TreatmentType string     `json:"treatment_type"`
	Description   string     `json:"description"`
	Cost          int64      `json:"cost"`
	ROI           float64    `json:"roi"`
	RiskReduction int        `json:"risk_reduction"`
	DueDate       *time.Time `json:"due_date,omitempty"`
	AssignedTo    string     `json:"assigned_to,omitempty"`
	Status        string     `json:"status"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type RiskAssessment struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	Name             string     `json:"name"`
	AssessmentType   string     `json:"assessment_type"`
	Framework        string     `json:"framework,omitempty"`
	Scope            string     `json:"scope,omitempty"`
	Methodology      string     `json:"methodology"`
	Status           string     `json:"status"`
	OverallRiskScore int        `json:"overall_risk_score"`
	TotalALE         int64      `json:"total_ale"`
	ScenariosCount   int        `json:"scenarios_count"`
	CriticalCount    int        `json:"critical_count"`
	HighCount        int        `json:"high_count"`
	KeyFindings      []string   `json:"key_findings"`
	Recommendations  []string   `json:"recommendations"`
	AssessmentDate   time.Time  `json:"assessment_date"`
	NextReview       *time.Time `json:"next_review,omitempty"`
	ApprovedBy       *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type RiskKRI struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	Category       string    `json:"category"`
	MetricName     string    `json:"metric_name"`
	Unit           string    `json:"unit"`
	CurrentValue   float64   `json:"current_value"`
	ThresholdGreen *float64  `json:"threshold_green,omitempty"`
	ThresholdAmber *float64  `json:"threshold_amber,omitempty"`
	Status         string    `json:"status"`
	Trend          string    `json:"trend"`
	SourceService  string    `json:"source_service,omitempty"`
	LastUpdatedAt  time.Time `json:"last_updated_at"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type RiskKRIHistory struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	KRIID      uuid.UUID `json:"kri_id"`
	Value      float64   `json:"value"`
	Status     string    `json:"status"`
	RecordedAt time.Time `json:"recorded_at"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type RiskStats struct {
	TotalAssets         int             `json:"total_assets"`
	TotalScenarios      int             `json:"total_scenarios"`
	OpenTreatments      int             `json:"open_treatments"`
	TotalALE            int64           `json:"total_ale"`
	AvgResidualRisk     float64         `json:"avg_residual_risk"`
	ScenariosByLevel    map[string]int  `json:"scenarios_by_level"`
	ScenariosByType     map[string]int  `json:"scenarios_by_type"`
	AssetsByCriticality map[string]int  `json:"assets_by_criticality"`
	KRIsByStatus        map[string]int  `json:"kris_by_status"`
	TopRiskyAssets      []*RiskAsset    `json:"top_risky_assets"`
	TopScenarios        []*RiskScenario `json:"top_scenarios"`
}

// ─── Request models ───────────────────────────────────────────────────────────

type CreateRiskAssetRequest struct {
	Name                 string         `json:"name"          validate:"required"`
	Description          string         `json:"description"`
	AssetType            string         `json:"asset_type"    validate:"required"`
	BusinessUnit         string         `json:"business_unit"`
	Owner                string         `json:"owner"`
	Criticality          string         `json:"criticality"`
	BusinessValue        int64          `json:"business_value"`
	RevenueImpact        int64          `json:"revenue_impact"`
	RegulatoryImpact     int64          `json:"regulatory_impact"`
	ReputationalImpact   int64          `json:"reputational_impact"`
	ThreatEventFrequency float64        `json:"threat_event_frequency"`
	Vulnerability        float64        `json:"vulnerability"`
	LossMagnitude        float64        `json:"loss_magnitude"`
	Metadata             map[string]any `json:"metadata"`
}

type UpdateRiskAssetRequest struct {
	Description          string         `json:"description"`
	BusinessUnit         string         `json:"business_unit"`
	Owner                string         `json:"owner"`
	Criticality          string         `json:"criticality"`
	BusinessValue        *int64         `json:"business_value"`
	RevenueImpact        *int64         `json:"revenue_impact"`
	RegulatoryImpact     *int64         `json:"regulatory_impact"`
	ReputationalImpact   *int64         `json:"reputational_impact"`
	ThreatEventFrequency *float64       `json:"threat_event_frequency"`
	Vulnerability        *float64       `json:"vulnerability"`
	LossMagnitude        *float64       `json:"loss_magnitude"`
	IsActive             *bool          `json:"is_active"`
	Metadata             map[string]any `json:"metadata"`
}

type CreateScenarioRequest struct {
	Name                string      `json:"name"               validate:"required"`
	Description         string      `json:"description"`
	ScenarioType        string      `json:"scenario_type"      validate:"required"`
	ThreatActor         string      `json:"threat_actor"`
	AnnualProbability   float64     `json:"annual_probability" validate:"required,min=0,max=1"`
	PrimaryLoss         int64       `json:"primary_loss"`
	SecondaryLoss       int64       `json:"secondary_loss"`
	MitigatingControls  []string    `json:"mitigating_controls"`
	ResidualProbability float64     `json:"residual_probability"`
	ResidualLoss        int64       `json:"residual_loss"`
	Frameworks          []string    `json:"frameworks"`
	AssetIDs            []uuid.UUID `json:"asset_ids"`
}

type UpdateScenarioRequest struct {
	Name                *string     `json:"name"`
	Description         string      `json:"description"`
	AnnualProbability   *float64    `json:"annual_probability"`
	PrimaryLoss         *int64      `json:"primary_loss"`
	SecondaryLoss       *int64      `json:"secondary_loss"`
	MitigatingControls  []string    `json:"mitigating_controls"`
	ResidualProbability *float64    `json:"residual_probability"`
	ResidualLoss        *int64      `json:"residual_loss"`
	Frameworks          []string    `json:"frameworks"`
	AssetIDs            []uuid.UUID `json:"asset_ids"`
	Status              string      `json:"status"`
}

type CreateTreatmentRequest struct {
	ScenarioID    uuid.UUID  `json:"scenario_id"    validate:"required"`
	TreatmentType string     `json:"treatment_type" validate:"required"`
	Description   string     `json:"description"    validate:"required"`
	Cost          int64      `json:"cost"`
	RiskReduction int        `json:"risk_reduction"`
	DueDate       *time.Time `json:"due_date"`
	AssignedTo    string     `json:"assigned_to"`
}

type UpdateTreatmentRequest struct {
	Description   string     `json:"description"`
	Cost          *int64     `json:"cost"`
	RiskReduction *int       `json:"risk_reduction"`
	DueDate       *time.Time `json:"due_date"`
	AssignedTo    string     `json:"assigned_to"`
	Status        string     `json:"status"`
}

type CreateAssessmentRequest struct {
	Name           string     `json:"name"            validate:"required"`
	AssessmentType string     `json:"assessment_type" validate:"required"`
	Framework      string     `json:"framework"`
	Scope          string     `json:"scope"`
	Methodology    string     `json:"methodology"`
	AssessmentDate *time.Time `json:"assessment_date"`
	NextReview     *time.Time `json:"next_review"`
}

type CreateKRIRequest struct {
	Name           string   `json:"name"        validate:"required"`
	Description    string   `json:"description"`
	Category       string   `json:"category"    validate:"required"`
	MetricName     string   `json:"metric_name" validate:"required"`
	Unit           string   `json:"unit"`
	ThresholdGreen *float64 `json:"threshold_green"`
	ThresholdAmber *float64 `json:"threshold_amber"`
	SourceService  string   `json:"source_service"`
}

type UpdateKRIValueRequest struct {
	Value float64 `json:"value" validate:"required"`
}

type ListScenariosFilter struct {
	ScenarioType string
	RiskLevel    string
	Status       string
	Framework    string
	Page         int
	PageSize     int
}

type ListAssetsFilter struct {
	AssetType    string
	Criticality  string
	BusinessUnit string
	Page         int
	PageSize     int
}
