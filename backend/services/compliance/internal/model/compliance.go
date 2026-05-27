package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Framework codes ───────────────────────────────────────────────────────────
const (
	FrameworkISO27001  = "ISO27001"
	FrameworkSOC2      = "SOC2"
	FrameworkPCIDSS    = "PCIDSS"
	FrameworkSWIFTCSP  = "SWIFTCSP"
	FrameworkNIS2      = "NIS2"
	FrameworkDORA      = "DORA"
	FrameworkGDPR      = "GDPR"
)

// ── Assessment statuses ───────────────────────────────────────────────────────
const (
	StatusCompliant      = "compliant"
	StatusPartial        = "partial"
	StatusNonCompliant   = "non_compliant"
	StatusNotApplicable  = "not_applicable"
	StatusNotAssessed    = "not_assessed"
)

// ── Risk statuses ─────────────────────────────────────────────────────────────
const (
	RiskStatusOpen       = "open"
	RiskStatusMitigating = "mitigating"
	RiskStatusAccepted   = "accepted"
	RiskStatusClosed     = "closed"
)

// ── Risk categories ───────────────────────────────────────────────────────────
const (
	RiskCategoryOperational = "operational"
	RiskCategoryCyber       = "cybersecurity"
	RiskCategoryRegulatory  = "regulatory"
	RiskCategoryThirdParty  = "third_party"
	RiskCategoryDataBreach  = "data_breach"
)

// ── Evidence types ────────────────────────────────────────────────────────────
const (
	EvidenceDocument    = "document"
	EvidenceScreenshot  = "screenshot"
	EvidenceLog         = "log"
	EvidencePolicy      = "policy"
	EvidenceAuditReport = "audit_report"
	EvidenceAutomated   = "automated"
)

// ── Control priorities ────────────────────────────────────────────────────────
const (
	PriorityCritical = "CRITICAL"
	PriorityHigh     = "HIGH"
	PriorityMedium   = "MEDIUM"
	PriorityLow      = "LOW"
)

// ─── Core models ──────────────────────────────────────────────────────────────

// Framework is a compliance standard managed for a tenant.
type Framework struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	Code          string    `json:"code"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Version       string    `json:"version"`
	TotalControls int       `json:"total_controls"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Control is a single requirement within a compliance framework.
type Control struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	FrameworkID uuid.UUID `json:"framework_id"`
	ControlID   string    `json:"control_id"`   // e.g. A.5.1.1
	Domain      string    `json:"domain"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Guidance    string    `json:"guidance,omitempty"`
	Priority    string    `json:"priority"`
	IsAutomated bool      `json:"is_automated"`
	CreatedAt   time.Time `json:"created_at"`
}

// Assessment is the compliance posture for one control at a point in time.
type Assessment struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	FrameworkID  uuid.UUID  `json:"framework_id"`
	ControlID    uuid.UUID  `json:"control_id"`
	Status       string     `json:"status"`
	Score        float64    `json:"score"`
	EvidenceRefs []string   `json:"evidence_refs"`
	Notes        string     `json:"notes,omitempty"`
	AssessedBy   *uuid.UUID `json:"assessed_by,omitempty"`
	AssessedAt   *time.Time `json:"assessed_at,omitempty"`
	NextReviewAt *time.Time `json:"next_review_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Risk is an entry in the organisational risk register.
type Risk struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	Title              string     `json:"title"`
	Description        string     `json:"description,omitempty"`
	Category           string     `json:"category"`
	Likelihood         int        `json:"likelihood"`
	Impact             int        `json:"impact"`
	RiskScore          int        `json:"risk_score"`
	Status             string     `json:"status"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	RelatedControls    []uuid.UUID `json:"related_controls"`
	MitigationPlan     string     `json:"mitigation_plan,omitempty"`
	ResidualLikelihood *int       `json:"residual_likelihood,omitempty"`
	ResidualImpact     *int       `json:"residual_impact,omitempty"`
	DueDate            *time.Time `json:"due_date,omitempty"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// Evidence is an artefact attached to an assessment.
type Evidence struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	AssessmentID  uuid.UUID      `json:"assessment_id"`
	Title         string         `json:"title"`
	EvidenceType  string         `json:"evidence_type"`
	SourceService string         `json:"source_service,omitempty"`
	ReferenceURL  string         `json:"reference_url,omitempty"`
	CollectedAt   time.Time      `json:"collected_at"`
	CollectedBy   *uuid.UUID     `json:"collected_by,omitempty"`
	Properties    map[string]any `json:"properties,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// ComplianceScore holds computed compliance posture for one framework.
type ComplianceScore struct {
	FrameworkID    uuid.UUID `json:"framework_id"`
	FrameworkCode  string    `json:"framework_code"`
	FrameworkName  string    `json:"framework_name"`
	TotalControls  int       `json:"total_controls"`
	Assessed       int       `json:"assessed"`
	Compliant      int       `json:"compliant"`
	Partial        int       `json:"partial"`
	NonCompliant   int       `json:"non_compliant"`
	NotApplicable  int       `json:"not_applicable"`
	NotAssessed    int       `json:"not_assessed"`
	ScorePct       float64   `json:"score_pct"` // (compliant*100 + partial*50) / total_controls
}

// ComplianceStats aggregates all framework scores and top risks.
type ComplianceStats struct {
	Frameworks []ComplianceScore `json:"frameworks"`
	TopRisks   []*Risk           `json:"top_risks"` // top 5 open risks by risk_score DESC
}

// AutoAssessmentSuggestion is the result of an automated control check.
type AutoAssessmentSuggestion struct {
	ControlID   uuid.UUID `json:"control_id"`
	ControlRef  string    `json:"control_ref"`
	Title       string    `json:"title"`
	SuggestedStatus string `json:"suggested_status"`
	Score       float64   `json:"score"`
	Rationale   string    `json:"rationale"`
	EvidenceRef string    `json:"evidence_ref"`
}

// ── Request / filter models ───────────────────────────────────────────────────

type CreateFrameworkRequest struct {
	Code        string `json:"code"        validate:"required,oneof=ISO27001 SOC2 PCIDSS SWIFTCSP NIS2 DORA GDPR"`
	Name        string `json:"name"        validate:"required,min=2,max=200"`
	Description string `json:"description"`
	Version     string `json:"version"     validate:"omitempty,max=50"`
}

type CreateControlRequest struct {
	FrameworkID uuid.UUID `json:"framework_id" validate:"required"`
	ControlID   string    `json:"control_id"   validate:"required,min=1,max=50"`
	Domain      string    `json:"domain"       validate:"required,min=1,max=200"`
	Title       string    `json:"title"        validate:"required,min=2,max=500"`
	Description string    `json:"description"`
	Guidance    string    `json:"guidance"`
	Priority    string    `json:"priority"     validate:"omitempty,oneof=CRITICAL HIGH MEDIUM LOW"`
	IsAutomated bool      `json:"is_automated"`
}

type CreateAssessmentRequest struct {
	FrameworkID  uuid.UUID  `json:"framework_id"   validate:"required"`
	ControlID    uuid.UUID  `json:"control_id"     validate:"required"`
	Status       string     `json:"status"         validate:"required,oneof=compliant partial non_compliant not_applicable not_assessed"`
	Score        float64    `json:"score"          validate:"omitempty,min=0,max=100"`
	EvidenceRefs []string   `json:"evidence_refs"`
	Notes        string     `json:"notes"`
	NextReviewAt *time.Time `json:"next_review_at"`
}

type UpdateAssessmentRequest struct {
	Status       *string    `json:"status"         validate:"omitempty,oneof=compliant partial non_compliant not_applicable not_assessed"`
	Score        *float64   `json:"score"          validate:"omitempty,min=0,max=100"`
	EvidenceRefs []string   `json:"evidence_refs"`
	Notes        *string    `json:"notes"`
	NextReviewAt *time.Time `json:"next_review_at"`
}

type BulkAssessmentItem struct {
	FrameworkID  uuid.UUID  `json:"framework_id"  validate:"required"`
	ControlID    uuid.UUID  `json:"control_id"    validate:"required"`
	Status       string     `json:"status"        validate:"required,oneof=compliant partial non_compliant not_applicable not_assessed"`
	Score        float64    `json:"score"         validate:"omitempty,min=0,max=100"`
	EvidenceRefs []string   `json:"evidence_refs"`
	Notes        string     `json:"notes"`
}

type BulkAssessmentRequest struct {
	Assessments []BulkAssessmentItem `json:"assessments" validate:"required,min=1"`
}

type CreateRiskRequest struct {
	Title              string      `json:"title"        validate:"required,min=2,max=500"`
	Description        string      `json:"description"`
	Category           string      `json:"category"     validate:"required,oneof=operational cybersecurity regulatory third_party data_breach"`
	Likelihood         int         `json:"likelihood"   validate:"required,min=1,max=5"`
	Impact             int         `json:"impact"       validate:"required,min=1,max=5"`
	OwnerID            *uuid.UUID  `json:"owner_id"`
	RelatedControls    []uuid.UUID `json:"related_controls"`
	MitigationPlan     string      `json:"mitigation_plan"`
	ResidualLikelihood *int        `json:"residual_likelihood" validate:"omitempty,min=1,max=5"`
	ResidualImpact     *int        `json:"residual_impact"     validate:"omitempty,min=1,max=5"`
	DueDate            *time.Time  `json:"due_date"`
}

type UpdateRiskRequest struct {
	Title              *string     `json:"title"`
	Description        *string     `json:"description"`
	Category           *string     `json:"category"     validate:"omitempty,oneof=operational cybersecurity regulatory third_party data_breach"`
	Likelihood         *int        `json:"likelihood"   validate:"omitempty,min=1,max=5"`
	Impact             *int        `json:"impact"       validate:"omitempty,min=1,max=5"`
	Status             *string     `json:"status"       validate:"omitempty,oneof=open mitigating accepted closed"`
	OwnerID            *uuid.UUID  `json:"owner_id"`
	RelatedControls    []uuid.UUID `json:"related_controls"`
	MitigationPlan     *string     `json:"mitigation_plan"`
	ResidualLikelihood *int        `json:"residual_likelihood" validate:"omitempty,min=1,max=5"`
	ResidualImpact     *int        `json:"residual_impact"     validate:"omitempty,min=1,max=5"`
	DueDate            *time.Time  `json:"due_date"`
}

type CreateEvidenceRequest struct {
	AssessmentID  uuid.UUID      `json:"assessment_id"  validate:"required"`
	Title         string         `json:"title"          validate:"required,min=2,max=500"`
	EvidenceType  string         `json:"evidence_type"  validate:"required,oneof=document screenshot log policy audit_report automated"`
	SourceService string         `json:"source_service" validate:"omitempty,oneof=siem ueba ti vuln attackpath soar manual"`
	ReferenceURL  string         `json:"reference_url"`
	Properties    map[string]any `json:"properties"`
}

type FrameworkFilter struct {
	TenantID uuid.UUID
	IsActive *bool
}

type ControlFilter struct {
	TenantID    uuid.UUID
	FrameworkID *uuid.UUID
	Domain      string
	Priority    string
	IsAutomated *bool
	Limit       int
	Offset      int
}

type AssessmentFilter struct {
	TenantID    uuid.UUID
	FrameworkID *uuid.UUID
	Status      string
	Limit       int
	Offset      int
}

type RiskFilter struct {
	TenantID uuid.UUID
	Status   string
	Category string
	OwnerID  *uuid.UUID
	MinScore int
	Limit    int
	Offset   int
}
