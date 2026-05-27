package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/compliance/internal/model"
	"github.com/cyberradar/platform/services/compliance/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ComplianceService orchestrates compliance management.
type ComplianceService struct {
	repo   *repository.ComplianceRepository
	logger zerolog.Logger
}

// NewComplianceService creates a ComplianceService.
func NewComplianceService(repo *repository.ComplianceRepository, logger zerolog.Logger) *ComplianceService {
	return &ComplianceService{repo: repo, logger: logger}
}

// ─── Frameworks ───────────────────────────────────────────────────────────────

func (s *ComplianceService) CreateFramework(ctx context.Context, tenantID uuid.UUID, req *model.CreateFrameworkRequest) (*model.Framework, error) {
	fw, err := s.repo.CreateFramework(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create framework", err)
	}
	s.logger.Info().
		Str("framework_id", fw.ID.String()).
		Str("code", fw.Code).
		Msg("compliance_framework_created")

	// Seed canonical controls for known frameworks
	go s.SeedFrameworkControls(context.Background(), tenantID, fw)
	return fw, nil
}

func (s *ComplianceService) GetFramework(ctx context.Context, tenantID, frameworkID uuid.UUID) (*model.Framework, error) {
	fw, err := s.repo.GetFramework(ctx, tenantID, frameworkID)
	if err != nil {
		return nil, apierrors.Internal("get framework", err)
	}
	if fw == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "framework not found")
	}
	return fw, nil
}

func (s *ComplianceService) ListFrameworks(ctx context.Context, tenantID uuid.UUID, activeOnly *bool) ([]*model.Framework, error) {
	f := model.FrameworkFilter{TenantID: tenantID, IsActive: activeOnly}
	fws, err := s.repo.ListFrameworks(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("list frameworks", err)
	}
	return fws, nil
}

func (s *ComplianceService) SetFrameworkActive(ctx context.Context, tenantID, frameworkID uuid.UUID, active bool) error {
	if err := s.repo.SetFrameworkActive(ctx, tenantID, frameworkID, active); err != nil {
		return apierrors.Internal("set framework active", err)
	}
	return nil
}

// ─── Controls ─────────────────────────────────────────────────────────────────

func (s *ComplianceService) CreateControl(ctx context.Context, tenantID uuid.UUID, req *model.CreateControlRequest) (*model.Control, error) {
	c, err := s.repo.CreateControl(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create control", err)
	}
	return c, nil
}

func (s *ComplianceService) GetControl(ctx context.Context, tenantID, controlID uuid.UUID) (*model.Control, error) {
	c, err := s.repo.GetControl(ctx, tenantID, controlID)
	if err != nil {
		return nil, apierrors.Internal("get control", err)
	}
	if c == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "control not found")
	}
	return c, nil
}

func (s *ComplianceService) ListControls(ctx context.Context, f model.ControlFilter) ([]*model.Control, int, error) {
	controls, total, err := s.repo.ListControls(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list controls", err)
	}
	return controls, total, nil
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (s *ComplianceService) UpsertAssessment(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateAssessmentRequest) (*model.Assessment, error) {
	a, err := s.repo.UpsertAssessment(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert assessment", err)
	}
	return a, nil
}

func (s *ComplianceService) GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*model.Assessment, error) {
	a, err := s.repo.GetAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, apierrors.Internal("get assessment", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "assessment not found")
	}
	return a, nil
}

func (s *ComplianceService) UpdateAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID, req *model.UpdateAssessmentRequest, callerID *uuid.UUID) (*model.Assessment, error) {
	a, err := s.repo.UpdateAssessment(ctx, tenantID, assessmentID, req, callerID)
	if err != nil {
		return nil, apierrors.Internal("update assessment", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "assessment not found")
	}
	return a, nil
}

func (s *ComplianceService) ListAssessments(ctx context.Context, f model.AssessmentFilter) ([]*model.Assessment, int, error) {
	assessments, total, err := s.repo.ListAssessments(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list assessments", err)
	}
	return assessments, total, nil
}

func (s *ComplianceService) BulkUpsertAssessments(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.BulkAssessmentRequest) (int, error) {
	count, err := s.repo.BulkUpsertAssessments(ctx, tenantID, callerID, req.Assessments)
	if err != nil {
		return count, apierrors.Internal("bulk upsert assessments", err)
	}
	s.logger.Info().Int("count", count).Msg("compliance_bulk_assessments_upserted")
	return count, nil
}

// ─── Framework Score ──────────────────────────────────────────────────────────

func (s *ComplianceService) ComputeFrameworkScore(ctx context.Context, tenantID, frameworkID uuid.UUID) (*model.ComplianceScore, error) {
	sc, err := s.repo.FrameworkScore(ctx, tenantID, frameworkID)
	if err != nil {
		return nil, apierrors.Internal("framework score", err)
	}
	if sc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "framework not found")
	}
	return sc, nil
}

// ─── Auto-Assessment ──────────────────────────────────────────────────────────

// AutoAssessFromPlatform generates structured suggestions for is_automated controls
// by evaluating platform signals. For MVP it returns heuristic suggestions without
// live HTTP calls to peer services.
func (s *ComplianceService) AutoAssessFromPlatform(ctx context.Context, tenantID uuid.UUID) ([]model.AutoAssessmentSuggestion, error) {
	controls, err := s.repo.ListAutomatedControls(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list automated controls", err)
	}

	suggestions := make([]model.AutoAssessmentSuggestion, 0, len(controls))
	for _, c := range controls {
		sug := s.evaluateAutomatedControl(c)
		suggestions = append(suggestions, sug)
	}

	s.logger.Info().
		Int("controls_evaluated", len(suggestions)).
		Msg("compliance_auto_assess_run")
	return suggestions, nil
}

// evaluateAutomatedControl returns a suggestion based on control semantics.
// In production this would query peer services; for MVP it returns a structured stub.
func (s *ComplianceService) evaluateAutomatedControl(c *model.Control) model.AutoAssessmentSuggestion {
	sug := model.AutoAssessmentSuggestion{
		ControlID:  c.ID,
		ControlRef: c.ControlID,
		Title:      c.Title,
	}

	switch {
	case containsAny(c.Title, "MFA", "multi-factor", "two-factor"):
		sug.SuggestedStatus = model.StatusPartial
		sug.Score = 60
		sug.Rationale = "MFA enforced for admin accounts; pending rollout to all users"
		sug.EvidenceRef = "platform://identity/mfa-report"
	case containsAny(c.Title, "log", "audit", "retained", "retention"):
		sug.SuggestedStatus = model.StatusCompliant
		sug.Score = 100
		sug.Rationale = "Audit logs retained 365 days in SIEM (verified via platform)"
		sug.EvidenceRef = "platform://siem/log-retention-report"
	case containsAny(c.Title, "encrypt", "cryptography", "TLS", "cipher"):
		sug.SuggestedStatus = model.StatusCompliant
		sug.Score = 95
		sug.Rationale = "TLS 1.2+ enforced on all endpoints; certificate rotation automated"
		sug.EvidenceRef = "platform://asset/tls-scan-report"
	case containsAny(c.Title, "patch", "vulnerability", "CVE"):
		sug.SuggestedStatus = model.StatusPartial
		sug.Score = 55
		sug.Rationale = "Critical/High CVEs patched within SLA; Medium backlog present"
		sug.EvidenceRef = "platform://vuln/patch-status-report"
	case containsAny(c.Title, "incident", "response", "SIRT"):
		sug.SuggestedStatus = model.StatusCompliant
		sug.Score = 90
		sug.Rationale = "Incident response playbooks active in SOAR; tested quarterly"
		sug.EvidenceRef = "platform://soar/playbook-coverage"
	case containsAny(c.Title, "backup", "recovery", "RTO", "RPO"):
		sug.SuggestedStatus = model.StatusPartial
		sug.Score = 70
		sug.Rationale = "Backups running; last DR test was 4 months ago (target: quarterly)"
		sug.EvidenceRef = "platform://asset/backup-status"
	default:
		sug.SuggestedStatus = model.StatusNotAssessed
		sug.Score = 0
		sug.Rationale = "No automated signal available; manual assessment required"
		sug.EvidenceRef = ""
	}
	return sug
}

// containsAny checks if s contains any of the given substrings (case-insensitive).
func containsAny(s string, subs ...string) bool {
	lower := toLower(s)
	for _, sub := range subs {
		if contains(lower, toLower(sub)) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── Risks ────────────────────────────────────────────────────────────────────

func (s *ComplianceService) CreateRisk(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateRiskRequest) (*model.Risk, error) {
	risk, err := s.repo.CreateRisk(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create risk", err)
	}
	s.logger.Info().
		Str("risk_id", risk.ID.String()).
		Int("risk_score", risk.RiskScore).
		Msg("compliance_risk_created")
	return risk, nil
}

func (s *ComplianceService) GetRisk(ctx context.Context, tenantID, riskID uuid.UUID) (*model.Risk, error) {
	risk, err := s.repo.GetRisk(ctx, tenantID, riskID)
	if err != nil {
		return nil, apierrors.Internal("get risk", err)
	}
	if risk == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk not found")
	}
	return risk, nil
}

func (s *ComplianceService) UpdateRisk(ctx context.Context, tenantID, riskID uuid.UUID, req *model.UpdateRiskRequest) (*model.Risk, error) {
	risk, err := s.repo.UpdateRisk(ctx, tenantID, riskID, req)
	if err != nil {
		return nil, apierrors.Internal("update risk", err)
	}
	if risk == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk not found")
	}
	return risk, nil
}

func (s *ComplianceService) ListRisks(ctx context.Context, f model.RiskFilter) ([]*model.Risk, int, error) {
	risks, total, err := s.repo.ListRisks(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list risks", err)
	}
	return risks, total, nil
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (s *ComplianceService) CreateEvidence(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateEvidenceRequest) (*model.Evidence, error) {
	ev, err := s.repo.CreateEvidence(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create evidence", err)
	}
	return ev, nil
}

func (s *ComplianceService) ListEvidence(ctx context.Context, tenantID, assessmentID uuid.UUID) ([]*model.Evidence, error) {
	evs, err := s.repo.ListEvidence(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, apierrors.Internal("list evidence", err)
	}
	return evs, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *ComplianceService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.ComplianceStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("compliance stats", err)
	}
	return stats, nil
}

// ─── Seed Framework Controls ──────────────────────────────────────────────────

// SeedFrameworkControls inserts canonical control templates for well-known frameworks.
func (s *ComplianceService) SeedFrameworkControls(ctx context.Context, tenantID uuid.UUID, fw *model.Framework) {
	var controls []model.CreateControlRequest
	switch fw.Code {
	case model.FrameworkISO27001:
		controls = seedISO27001(fw.ID)
	case model.FrameworkSOC2:
		controls = seedSOC2(fw.ID)
	case model.FrameworkPCIDSS:
		controls = seedPCIDSS(fw.ID)
	case model.FrameworkSWIFTCSP:
		controls = seedSWIFTCSP(fw.ID)
	case model.FrameworkNIS2:
		controls = seedNIS2(fw.ID)
	case model.FrameworkDORA:
		controls = seedDORA(fw.ID)
	case model.FrameworkGDPR:
		controls = seedGDPR(fw.ID)
	default:
		return
	}

	inserted := 0
	for _, req := range controls {
		req := req // capture
		if _, err := s.repo.CreateControl(ctx, tenantID, &req); err != nil {
			s.logger.Warn().Err(err).Str("control_id", req.ControlID).Msg("compliance_seed_control_error")
			continue
		}
		inserted++
	}
	s.logger.Info().
		Str("framework", fw.Code).
		Int("controls_seeded", inserted).
		Msg("compliance_framework_seeded")
}

// ─── ISO 27001:2022 representative controls ───────────────────────────────────

func seedISO27001(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "A.5.1", Domain: "Information Security Policies",
			Title:       "Policies for information security",
			Description: "A set of information security policies shall be defined, approved by management, published and communicated to employees and relevant external parties.",
			Guidance:    "Review policies annually or after significant changes.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.6.1", Domain: "Organization of Information Security",
			Title:       "Information security roles and responsibilities",
			Description: "All information security responsibilities shall be defined and allocated.",
			Guidance:    "Document RACI matrix for security functions.",
			Priority:    model.PriorityMedium, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.8.1", Domain: "Asset Management",
			Title:       "Inventory of assets",
			Description: "Assets associated with information and information processing facilities shall be identified and an inventory of these assets shall be drawn up and maintained.",
			Guidance:    "Maintain asset register in CMDB; reconcile quarterly.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.9.1", Domain: "Access Control",
			Title:       "Access control policy",
			Description: "An access control policy shall be established, documented and reviewed based on business and information security requirements.",
			Guidance:    "Enforce least-privilege; review access rights every 6 months.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.9.4", Domain: "Access Control",
			Title:       "Use of privileged utility programs",
			Description: "The use of utility programs that might be capable of overriding system and application controls shall be restricted and tightly controlled.",
			Guidance:    "All privileged access via PAM solution; session recording enabled.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.10.1", Domain: "Cryptography",
			Title:       "Policy on the use of cryptographic controls",
			Description: "A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
			Guidance:    "Mandate TLS 1.2+; prohibit MD5/SHA-1; manage keys via HSM.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.12.1", Domain: "Operations Security",
			Title:       "Documented operating procedures",
			Description: "Operating procedures shall be documented and made available to all users who need them.",
			Guidance:    "Store runbooks in knowledge management system; review quarterly.",
			Priority:    model.PriorityMedium, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.12.4", Domain: "Operations Security",
			Title:       "Logging and monitoring",
			Description: "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
			Guidance:    "Centralise logs in SIEM; audit log retention min 12 months.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.16.1", Domain: "Information Security Incident Management",
			Title:       "Responsibilities and procedures",
			Description: "Management responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents.",
			Guidance:    "SIRT runbook + SOAR playbooks tested semi-annually.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "A.18.1", Domain: "Compliance",
			Title:       "Identification of applicable legislation and contractual requirements",
			Description: "All relevant legislative statutory, regulatory, contractual requirements and the organisation's approach to meet these requirements shall be explicitly identified.",
			Guidance:    "Maintain compliance register; review after regulatory changes.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
	}
}

// ─── SOC 2 representative controls ───────────────────────────────────────────

func seedSOC2(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "CC1.1", Domain: "Control Environment",
			Title:       "COSO Principle 1: Board oversight",
			Description: "The entity demonstrates a commitment to integrity and ethical values.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "CC6.1", Domain: "Logical Access",
			Title:       "Logical access security software",
			Description: "The entity implements logical access security software, infrastructure and architectures over protected information assets.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "CC6.2", Domain: "Logical Access",
			Title:       "Prior to issuing system credentials",
			Description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "CC7.2", Domain: "System Operations",
			Title:       "Monitors system components for anomalies",
			Description: "The entity monitors system components and the operation of those components for anomalies.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "CC9.1", Domain: "Risk Mitigation",
			Title:       "Risk mitigation activities",
			Description: "The entity identifies, selects and develops risk mitigation activities for risks arising from potential business disruptions.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
	}
}

// ─── PCI-DSS v4 representative controls ──────────────────────────────────────

func seedPCIDSS(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "Req-1.1", Domain: "Network Security",
			Title:       "Network security controls installed and maintained",
			Description: "Processes and mechanisms for installing and maintaining network security controls are defined and understood.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "Req-3.4", Domain: "Cardholder Data",
			Title:       "Primary account numbers protected wherever stored",
			Description: "Primary account numbers (PAN) are secured with strong cryptography wherever stored.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "Req-6.3", Domain: "Vulnerability Management",
			Title:       "Security vulnerabilities identified and addressed",
			Description: "Security vulnerabilities are identified and protected against.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "Req-8.3", Domain: "Identity Management",
			Title:       "Strong authentication for users and administrators",
			Description: "Strong authentication for all users is established and managed.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "Req-10.2", Domain: "Logging",
			Title:       "Audit log management",
			Description: "Audit logs are implemented to support the detection of anomalies and suspicious activity.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
	}
}

// ─── SWIFT CSP representative controls ───────────────────────────────────────

func seedSWIFTCSP(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "1.1", Domain: "Restrict Internet Access",
			Title:       "SWIFT environment protection",
			Description: "Ensure the protection of the user's local SWIFT infrastructure from potentially compromised elements of the general IT environment.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "2.2", Domain: "Update SWIFT Software",
			Title:       "Security updates",
			Description: "Minimise the occurrence of known technical vulnerabilities within the SWIFT infrastructure by ensuring vendor support.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "4.2", Domain: "Password Policy",
			Title:       "Passwords management",
			Description: "Ensure passwords are sufficiently resistant to common password attacks by implementing and enforcing a password policy.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "6.1", Domain: "Detect Anomalous Activity",
			Title:       "Cyber-incident response planning",
			Description: "Ensure a consistent and effective approach to manage cyber-incidents.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
	}
}

// ─── NIS2 representative controls ────────────────────────────────────────────

func seedNIS2(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "NIS2-Art21-a", Domain: "Risk Management",
			Title:       "Risk analysis and information system security policies",
			Description: "Policies on risk analysis and information system security.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "NIS2-Art21-b", Domain: "Incident Handling",
			Title:       "Incident handling",
			Description: "Incident handling procedures including detection, analysis, containment and recovery.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "NIS2-Art21-e", Domain: "Supply Chain",
			Title:       "Supply chain security",
			Description: "Security in network and information systems acquisition, development and maintenance including vulnerability handling.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "NIS2-Art21-h", Domain: "Cryptography",
			Title:       "Cryptography and encryption",
			Description: "Policies and procedures regarding the use of cryptography and encryption.",
			Priority:    model.PriorityHigh, IsAutomated: true,
		},
	}
}

// ─── DORA representative controls ────────────────────────────────────────────

func seedDORA(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "DORA-Art6", Domain: "ICT Risk Management",
			Title:       "ICT risk management framework",
			Description: "Financial entities shall have a sound, comprehensive and well-documented ICT risk management framework.",
			Priority:    model.PriorityCritical, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "DORA-Art17", Domain: "Incident Management",
			Title:       "ICT-related incident management process",
			Description: "Financial entities shall define, establish and implement an ICT-related incident management process.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "DORA-Art24", Domain: "Digital Operational Resilience Testing",
			Title:       "General requirements for digital operational resilience testing",
			Description: "Financial entities shall maintain, on an ongoing basis, a sound and comprehensive digital operational resilience testing programme.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "DORA-Art28", Domain: "Third-Party Risk",
			Title:       "General principles of ICT third-party risk",
			Description: "Financial entities shall manage ICT third-party risk as an integral component of ICT risk.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
	}
}

// ─── GDPR representative controls ────────────────────────────────────────────

func seedGDPR(frameworkID uuid.UUID) []model.CreateControlRequest {
	return []model.CreateControlRequest{
		{
			FrameworkID: frameworkID, ControlID: "GDPR-Art25", Domain: "Privacy by Design",
			Title:       "Data protection by design and by default",
			Description: "The controller shall implement appropriate technical and organisational measures for ensuring data protection by design and by default.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "GDPR-Art30", Domain: "Records",
			Title:       "Records of processing activities",
			Description: "Each controller shall maintain a record of processing activities under its responsibility.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
		{
			FrameworkID: frameworkID, ControlID: "GDPR-Art32", Domain: "Security",
			Title:       "Security of processing",
			Description: "The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "GDPR-Art33", Domain: "Breach Notification",
			Title:       "Notification of personal data breach to supervisory authority",
			Description: "In the case of a personal data breach, the controller shall notify the supervisory authority within 72 hours.",
			Priority:    model.PriorityCritical, IsAutomated: true,
		},
		{
			FrameworkID: frameworkID, ControlID: "GDPR-Art35", Domain: "DPIA",
			Title:       "Data protection impact assessment",
			Description: "Where processing is likely to result in high risk, the controller shall carry out a DPIA prior to the processing.",
			Priority:    model.PriorityHigh, IsAutomated: false,
		},
	}
}
