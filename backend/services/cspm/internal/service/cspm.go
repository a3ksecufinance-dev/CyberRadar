package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/cspm/internal/model"
	"github.com/cyberradar/platform/services/cspm/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// CSPMService orchestrates Cloud Security Posture Management.
type CSPMService struct {
	repo     *repository.CSPMRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewCSPMService creates a CSPMService.
func NewCSPMService(repo *repository.CSPMRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *CSPMService {
	return &CSPMService{repo: repo, producer: producer, logger: logger}
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

func (s *CSPMService) RegisterAccount(ctx context.Context, tenantID uuid.UUID, req *model.RegisterAccountRequest) (*model.CSPMAccount, error) {
	a, err := s.repo.RegisterAccount(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("register account", err)
	}
	s.logger.Info().Str("account_id", a.ID.String()).Str("provider", a.Provider).Str("env", a.Environment).Msg("cspm_account_registered")
	// Auto-seed CIS rules for the provider
	go func() {
		ctx2 := context.Background()
		count, _ := s.repo.SeedCISRules(ctx2, tenantID, req.Provider)
		if count > 0 {
			s.logger.Info().Int("rules_seeded", count).Str("provider", req.Provider).Msg("cspm_cis_rules_seeded")
		}
	}()
	return a, nil
}

func (s *CSPMService) GetAccount(ctx context.Context, tenantID, accountID uuid.UUID) (*model.CSPMAccount, error) {
	a, err := s.repo.GetAccount(ctx, tenantID, accountID)
	if err != nil {
		return nil, apierrors.Internal("get account", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "account not found")
	}
	return a, nil
}

func (s *CSPMService) ListAccounts(ctx context.Context, tenantID uuid.UUID, provider, env string) ([]*model.CSPMAccount, error) {
	accounts, err := s.repo.ListAccounts(ctx, tenantID, provider, env)
	if err != nil {
		return nil, apierrors.Internal("list accounts", err)
	}
	return accounts, nil
}

func (s *CSPMService) UpdateAccount(ctx context.Context, tenantID, accountID uuid.UUID, req *model.UpdateAccountRequest) (*model.CSPMAccount, error) {
	a, err := s.repo.UpdateAccount(ctx, tenantID, accountID, req)
	if err != nil {
		return nil, apierrors.Internal("update account", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "account not found")
	}
	return a, nil
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (s *CSPMService) CreateRule(ctx context.Context, tenantID uuid.UUID, req *model.CreateRuleRequest) (*model.CSPMRule, error) {
	rule, err := s.repo.CreateRule(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create rule", err)
	}
	s.logger.Info().Str("rule_id", rule.RuleID).Str("framework", rule.Framework).Str("severity", rule.Severity).Msg("cspm_rule_created")
	return rule, nil
}

func (s *CSPMService) ListRules(ctx context.Context, tenantID uuid.UUID, provider, framework, severity string, page, pageSize int) ([]*model.CSPMRule, int, error) {
	rules, total, err := s.repo.ListRules(ctx, tenantID, provider, framework, severity, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list rules", err)
	}
	return rules, total, nil
}

func (s *CSPMService) SeedRules(ctx context.Context, tenantID uuid.UUID, provider string) (int, error) {
	count, err := s.repo.SeedCISRules(ctx, tenantID, provider)
	if err != nil {
		return 0, apierrors.Internal("seed rules", err)
	}
	s.logger.Info().Int("count", count).Str("provider", provider).Msg("cspm_rules_seeded")
	return count, nil
}

// ─── Resources ────────────────────────────────────────────────────────────────

func (s *CSPMService) UpsertResource(ctx context.Context, tenantID uuid.UUID, req *model.UpsertResourceRequest) (*model.CSPMResource, error) {
	res, err := s.repo.UpsertResource(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert resource", err)
	}
	return res, nil
}

func (s *CSPMService) GetResource(ctx context.Context, tenantID, resourceID uuid.UUID) (*model.CSPMResource, error) {
	res, err := s.repo.GetResource(ctx, tenantID, resourceID)
	if err != nil {
		return nil, apierrors.Internal("get resource", err)
	}
	if res == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "resource not found")
	}
	return res, nil
}

func (s *CSPMService) ListResources(ctx context.Context, tenantID uuid.UUID, f model.ListResourcesFilter) ([]*model.CSPMResource, int, error) {
	resources, total, err := s.repo.ListResources(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list resources", err)
	}
	return resources, total, nil
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (s *CSPMService) ReportFinding(ctx context.Context, tenantID uuid.UUID, req *model.ReportFindingRequest) (*model.CSPMFinding, error) {
	finding, err := s.repo.ReportFinding(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("report finding", err)
	}
	if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
		go s.publishFindingAlert(tenantID, finding)
	}
	return finding, nil
}

func (s *CSPMService) ListFindings(ctx context.Context, tenantID uuid.UUID, f model.ListFindingsFilter) ([]*model.CSPMFinding, int, error) {
	findings, total, err := s.repo.ListFindings(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list findings", err)
	}
	return findings, total, nil
}

func (s *CSPMService) UpdateFinding(ctx context.Context, tenantID, findingID, updatedBy uuid.UUID, req *model.UpdateFindingRequest) (*model.CSPMFinding, error) {
	finding, err := s.repo.UpdateFinding(ctx, tenantID, findingID, updatedBy, req)
	if err != nil {
		return nil, apierrors.Internal("update finding", err)
	}
	if finding == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "finding not found")
	}
	return finding, nil
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (s *CSPMService) TriggerScan(ctx context.Context, tenantID uuid.UUID, req *model.TriggerScanRequest, triggeredBy uuid.UUID) (*model.CSPMScan, error) {
	scan, err := s.repo.CreateScan(ctx, tenantID, req.AccountID, req.ScanType, triggeredBy)
	if err != nil {
		return nil, apierrors.Internal("trigger scan", err)
	}
	s.logger.Info().Str("scan_id", scan.ID.String()).Str("account_id", req.AccountID.String()).Msg("cspm_scan_triggered")
	go s.runScan(tenantID, scan)
	return scan, nil
}

func (s *CSPMService) GetScan(ctx context.Context, tenantID, scanID uuid.UUID) (*model.CSPMScan, error) {
	scan, err := s.repo.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, apierrors.Internal("get scan", err)
	}
	if scan == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "scan not found")
	}
	return scan, nil
}

func (s *CSPMService) ListScans(ctx context.Context, tenantID, accountID uuid.UUID, page, pageSize int) ([]*model.CSPMScan, int, error) {
	scans, total, err := s.repo.ListScans(ctx, tenantID, accountID, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list scans", err)
	}
	return scans, total, nil
}

func (s *CSPMService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.CSPMStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("cspm stats", err)
	}
	return stats, nil
}

// ─── Scan simulation ──────────────────────────────────────────────────────────

func (s *CSPMService) runScan(tenantID uuid.UUID, scan *model.CSPMScan) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error().Interface("panic", r).Str("scan_id", scan.ID.String()).Msg("cspm_scan_panic")
			s.repo.FailScan(context.Background(), scan.ID, fmt.Sprintf("panic: %v", r))
		}
	}()

	ctx := context.Background()

	// Simulate scan duration (3–8 seconds)
	duration := time.Duration(3+rand.Intn(6)) * time.Second
	time.Sleep(duration)

	// Fetch account details
	account, err := s.repo.GetAccount(ctx, tenantID, scan.AccountID)
	if err != nil || account == nil {
		s.repo.FailScan(ctx, scan.ID, "account not found")
		return
	}

	// Simulate resource discovery
	resourceTypes := providerResourceTypes(account.Provider)
	resourcesScanned := 10 + rand.Intn(40)
	for i := 0; i < resourcesScanned && i < len(resourceTypes)*3; i++ {
		rType := resourceTypes[rand.Intn(len(resourceTypes))]
		req := &model.UpsertResourceRequest{
			AccountID:    scan.AccountID,
			ResourceUID:  fmt.Sprintf("%s-%s-%d", rType, account.Provider, i),
			Name:         fmt.Sprintf("%s-%d", rType, i),
			ResourceType: rType,
			Service:      serviceForType(rType),
			Region:       firstRegion(account.Region),
			IsPublic:     rand.Intn(10) < 2, // 20% public
		}
		s.repo.UpsertResource(ctx, tenantID, req)
	}

	// Simulate findings — fetch active rules and create violations
	rules, _, _ := s.repo.ListRules(ctx, tenantID, account.Provider, "", "", 1, 100)
	findingsNew := 0
	for _, rule := range rules {
		if rand.Intn(4) == 0 { // 25% chance of violation per rule
			req := &model.ReportFindingRequest{
				AccountID:    scan.AccountID,
				ResourceUID:  fmt.Sprintf("%s-%s-0", rule.ResourceType, account.Provider),
				ResourceType: rule.ResourceType,
				RuleID:       rule.ID,
				Region:       firstRegion(account.Region),
				Evidence: map[string]any{
					"rule":    rule.RuleID,
					"details": "Non-compliant configuration detected during scan",
				},
				ScanID: &scan.ID,
			}
			if _, err := s.repo.ReportFinding(ctx, tenantID, req); err == nil {
				findingsNew++
			}
		}
	}

	// Update account posture
	s.repo.UpdateAccountPosture(ctx, tenantID, scan.AccountID)

	// Recompute posture score for scan record
	updatedAccount, _ := s.repo.GetAccount(ctx, tenantID, scan.AccountID)
	postureScore := 0
	if updatedAccount != nil {
		postureScore = updatedAccount.PostureScore
	}

	s.repo.CompleteScan(ctx, scan.ID, resourcesScanned, len(rules), findingsNew, 0, postureScore)

	s.logger.Info().
		Str("scan_id", scan.ID.String()).
		Int("resources_scanned", resourcesScanned).
		Int("findings_new", findingsNew).
		Int("posture_score", postureScore).
		Msg("cspm_scan_completed")

	// Publish scan completed event
	payload := map[string]any{
		"event_type":        "cspm.scan_completed",
		"tenant_id":         tenantID.String(),
		"scan_id":           scan.ID.String(),
		"account_id":        scan.AccountID.String(),
		"provider":          account.Provider,
		"posture_score":     postureScore,
		"findings_new":      findingsNew,
		"resources_scanned": resourcesScanned,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	_ = s.producer.Publish(ctx, scan.ID.String(), data)
}

func (s *CSPMService) publishFindingAlert(tenantID uuid.UUID, finding *model.CSPMFinding) {
	ctx := context.Background()
	payload := map[string]any{
		"event_type":    "cspm.finding_critical",
		"tenant_id":     tenantID.String(),
		"finding_id":    finding.ID.String(),
		"rule_ref":      finding.RuleRef,
		"title":         finding.Title,
		"severity":      finding.Severity,
		"resource_uid":  finding.ResourceUID,
		"resource_type": finding.ResourceType,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	_ = s.producer.Publish(ctx, finding.ID.String(), data)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func providerResourceTypes(provider string) []string {
	switch provider {
	case model.ProviderAWS:
		return []string{"s3_bucket", "ec2_instance", "security_group", "iam_user", "rds_instance", "cloudtrail", "vpc", "lambda_function", "eks_cluster"}
	case model.ProviderAzure:
		return []string{"virtual_machine", "storage_account", "sql_server", "aad_user", "app_gateway", "key_vault", "aks_cluster", "diagnostic_setting"}
	case model.ProviderGCP:
		return []string{"storage_bucket", "compute_instance", "firewall_rule", "iam_user", "cloudsql_instance", "audit_config", "gke_cluster"}
	}
	return []string{"resource"}
}

func serviceForType(resourceType string) string {
	m := map[string]string{
		"s3_bucket": "S3", "ec2_instance": "EC2", "security_group": "EC2",
		"iam_user": "IAM", "rds_instance": "RDS", "cloudtrail": "CloudTrail",
		"vpc": "VPC", "lambda_function": "Lambda", "eks_cluster": "EKS",
		"virtual_machine": "Compute", "storage_account": "Storage", "sql_server": "SQL",
		"aad_user": "AAD", "app_gateway": "Network", "key_vault": "KeyVault",
		"aks_cluster": "AKS", "diagnostic_setting": "Monitor",
		"storage_bucket": "GCS", "compute_instance": "Compute",
		"firewall_rule": "Compute", "cloudsql_instance": "CloudSQL",
		"audit_config": "Logging", "gke_cluster": "GKE",
	}
	if svc, ok := m[resourceType]; ok {
		return svc
	}
	return "Unknown"
}

func firstRegion(region string) string {
	if region != "" {
		return region
	}
	return "us-east-1"
}
