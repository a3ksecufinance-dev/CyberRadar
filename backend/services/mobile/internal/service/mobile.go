package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/mobile/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type Repository interface {
	// Devices
	CreateDevice(ctx context.Context, tenantID uuid.UUID, req model.CreateDeviceRequest) (*model.MobDevice, error)
	GetDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*model.MobDevice, error)
	ListDevices(ctx context.Context, tenantID uuid.UUID, f model.ListDevicesFilter) ([]model.MobDevice, int, error)
	UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req model.UpdateDeviceRequest) (*model.MobDevice, error)
	DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error

	// Apps
	CreateApp(ctx context.Context, tenantID uuid.UUID, req model.CreateAppRequest) (*model.MobApp, error)
	GetApp(ctx context.Context, tenantID, appID uuid.UUID) (*model.MobApp, error)
	ListApps(ctx context.Context, tenantID uuid.UUID, f model.ListAppsFilter) ([]model.MobApp, int, error)
	UpdateApp(ctx context.Context, tenantID, appID uuid.UUID, req model.UpdateAppRequest) (*model.MobApp, error)
	InstallApp(ctx context.Context, tenantID, deviceID, appID uuid.UUID) error
	ListDeviceApps(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobApp, error)

	// Policies
	CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.MobPolicy, error)
	GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.MobPolicy, error)
	ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.MobPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.MobPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error

	// Threats
	CreateThreat(ctx context.Context, tenantID uuid.UUID, req model.CreateThreatRequest) (*model.MobThreat, error)
	GetThreat(ctx context.Context, tenantID, threatID uuid.UUID) (*model.MobThreat, error)
	ListThreats(ctx context.Context, tenantID uuid.UUID, f model.ListThreatsFilter) ([]model.MobThreat, int, error)
	UpdateThreat(ctx context.Context, tenantID, threatID uuid.UUID, req model.UpdateThreatRequest) (*model.MobThreat, error)

	// Compliance
	RunComplianceCheck(ctx context.Context, tenantID uuid.UUID, req model.RunComplianceRequest) (*model.MobComplianceCheck, error)
	ListComplianceChecks(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]model.MobComplianceCheck, error)

	// Remote Actions
	CreateRemoteAction(ctx context.Context, tenantID uuid.UUID, req model.CreateRemoteActionRequest) (*model.MobRemoteAction, error)
	GetRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID) (*model.MobRemoteAction, error)
	ListRemoteActions(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobRemoteAction, error)
	UpdateRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID, req model.UpdateRemoteActionRequest) (*model.MobRemoteAction, error)

	// Stats
	GetStats(ctx context.Context, tenantID uuid.UUID) (*model.MobStats, error)
}

type Service struct {
	repo     Repository
	producer *kafka.Producer
	topic    string
	log      zerolog.Logger
}

func New(repo Repository, producer *kafka.Producer, topic string, log zerolog.Logger) *Service {
	return &Service{repo: repo, producer: producer, topic: topic, log: log}
}

func (s *Service) publish(event string, payload any) {
	go func() {
		data, err := json.Marshal(map[string]any{
			"event":     event,
			"payload":   payload,
			"timestamp": time.Now().UTC(),
		})
		if err != nil {
			s.log.Error().Err(err).Str("event", event).Msg("marshal kafka event")
			return
		}
		if err := s.producer.PublishRaw(context.Background(), "", data); err != nil {
			s.log.Error().Err(err).Str("event", event).Msg("publish kafka event")
		}
	}()
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (s *Service) CreateDevice(ctx context.Context, tenantID uuid.UUID, req model.CreateDeviceRequest) (*model.MobDevice, error) {
	device, err := s.repo.CreateDevice(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	// Publish for jailbroken or rooted devices
	if device.IsJailbroken || device.IsRooted {
		s.publish("mobile.device.compromised", map[string]any{
			"tenant_id":     tenantID,
			"device_id":     device.ID,
			"device_name":   device.DeviceName,
			"is_jailbroken": device.IsJailbroken,
			"is_rooted":     device.IsRooted,
			"risk_score":    device.RiskScore,
			"risk_level":    device.RiskLevel,
		})
	} else if device.RiskLevel == "high" || device.RiskLevel == "critical" {
		s.publish("mobile.device.high_risk", map[string]any{
			"tenant_id":   tenantID,
			"device_id":   device.ID,
			"device_name": device.DeviceName,
			"risk_score":  device.RiskScore,
			"risk_level":  device.RiskLevel,
		})
	}
	return device, nil
}

func (s *Service) GetDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*model.MobDevice, error) {
	return s.repo.GetDevice(ctx, tenantID, deviceID)
}

func (s *Service) ListDevices(ctx context.Context, tenantID uuid.UUID, f model.ListDevicesFilter) ([]model.MobDevice, int, error) {
	return s.repo.ListDevices(ctx, tenantID, f)
}

func (s *Service) UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req model.UpdateDeviceRequest) (*model.MobDevice, error) {
	device, err := s.repo.UpdateDevice(ctx, tenantID, deviceID, req)
	if err != nil {
		return nil, err
	}
	// Publish jailbreak/root detection
	if req.IsJailbroken != nil && *req.IsJailbroken {
		s.publish("mobile.device.jailbroken", map[string]any{
			"tenant_id":   tenantID,
			"device_id":   device.ID,
			"device_name": device.DeviceName,
			"platform":    device.Platform,
		})
	}
	if req.IsRooted != nil && *req.IsRooted {
		s.publish("mobile.device.rooted", map[string]any{
			"tenant_id":   tenantID,
			"device_id":   device.ID,
			"device_name": device.DeviceName,
			"platform":    device.Platform,
		})
	}
	// Non-compliant transition
	if req.IsCompliant != nil && !*req.IsCompliant {
		s.publish("mobile.device.non_compliant", map[string]any{
			"tenant_id":         tenantID,
			"device_id":         device.ID,
			"device_name":       device.DeviceName,
			"compliance_issues": device.ComplianceIssues,
		})
	}
	return device, nil
}

func (s *Service) DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	return s.repo.DeleteDevice(ctx, tenantID, deviceID)
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

func (s *Service) CreateApp(ctx context.Context, tenantID uuid.UUID, req model.CreateAppRequest) (*model.MobApp, error) {
	return s.repo.CreateApp(ctx, tenantID, req)
}

func (s *Service) GetApp(ctx context.Context, tenantID, appID uuid.UUID) (*model.MobApp, error) {
	return s.repo.GetApp(ctx, tenantID, appID)
}

func (s *Service) ListApps(ctx context.Context, tenantID uuid.UUID, f model.ListAppsFilter) ([]model.MobApp, int, error) {
	return s.repo.ListApps(ctx, tenantID, f)
}

func (s *Service) UpdateApp(ctx context.Context, tenantID, appID uuid.UUID, req model.UpdateAppRequest) (*model.MobApp, error) {
	app, err := s.repo.UpdateApp(ctx, tenantID, appID, req)
	if err != nil {
		return nil, err
	}
	// Publish blocklisting
	if req.IsBlocklisted != nil && *req.IsBlocklisted {
		reason := ""
		if req.BlocklistReason != nil {
			reason = *req.BlocklistReason
		}
		s.publish("mobile.app.blocklisted", map[string]any{
			"tenant_id":        tenantID,
			"app_id":           app.ID,
			"app_name":         app.AppName,
			"bundle_id":        app.BundleID,
			"platform":         app.Platform,
			"blocklist_reason": reason,
		})
	}
	// Publish vulnerable app
	if req.HasKnownVulns != nil && *req.HasKnownVulns {
		vulnCount := 0
		if req.VulnCount != nil {
			vulnCount = *req.VulnCount
		}
		s.publish("mobile.app.vulnerable", map[string]any{
			"tenant_id":  tenantID,
			"app_id":     app.ID,
			"app_name":   app.AppName,
			"bundle_id":  app.BundleID,
			"vuln_count": vulnCount,
		})
	}
	return app, nil
}

func (s *Service) InstallApp(ctx context.Context, tenantID, deviceID, appID uuid.UUID) error {
	return s.repo.InstallApp(ctx, tenantID, deviceID, appID)
}

func (s *Service) ListDeviceApps(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobApp, error) {
	return s.repo.ListDeviceApps(ctx, tenantID, deviceID)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *Service) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.MobPolicy, error) {
	return s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
}

func (s *Service) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.MobPolicy, error) {
	return s.repo.GetPolicy(ctx, tenantID, policyID)
}

func (s *Service) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.MobPolicy, error) {
	return s.repo.ListPolicies(ctx, tenantID)
}

func (s *Service) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.MobPolicy, error) {
	return s.repo.UpdatePolicy(ctx, tenantID, policyID, req)
}

func (s *Service) DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error {
	return s.repo.DeletePolicy(ctx, tenantID, policyID)
}

// ─── Threats ──────────────────────────────────────────────────────────────────

func (s *Service) CreateThreat(ctx context.Context, tenantID uuid.UUID, req model.CreateThreatRequest) (*model.MobThreat, error) {
	threat, err := s.repo.CreateThreat(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	// Publish critical or high threats
	if threat.Severity == "critical" || threat.Severity == "high" {
		s.publish("mobile.threat.detected", map[string]any{
			"tenant_id":    tenantID,
			"threat_id":    threat.ID,
			"device_id":    threat.DeviceID,
			"threat_type":  threat.ThreatType,
			"severity":     threat.Severity,
			"title":        threat.Title,
			"detected_at":  threat.DetectedAt,
		})
	}
	// Publish ransomware / malware immediately regardless of severity
	if threat.ThreatType == "ransomware" || threat.ThreatType == "malware" || threat.ThreatType == "spyware" {
		s.publish("mobile.threat.malware", map[string]any{
			"tenant_id":   tenantID,
			"threat_id":   threat.ID,
			"device_id":   threat.DeviceID,
			"threat_type": threat.ThreatType,
			"severity":    threat.Severity,
			"title":       threat.Title,
		})
	}
	return threat, nil
}

func (s *Service) GetThreat(ctx context.Context, tenantID, threatID uuid.UUID) (*model.MobThreat, error) {
	return s.repo.GetThreat(ctx, tenantID, threatID)
}

func (s *Service) ListThreats(ctx context.Context, tenantID uuid.UUID, f model.ListThreatsFilter) ([]model.MobThreat, int, error) {
	return s.repo.ListThreats(ctx, tenantID, f)
}

func (s *Service) UpdateThreat(ctx context.Context, tenantID, threatID uuid.UUID, req model.UpdateThreatRequest) (*model.MobThreat, error) {
	threat, err := s.repo.UpdateThreat(ctx, tenantID, threatID, req)
	if err != nil {
		return nil, err
	}
	if req.Status != nil && *req.Status == "resolved" {
		s.publish("mobile.threat.resolved", map[string]any{
			"tenant_id":   tenantID,
			"threat_id":   threat.ID,
			"device_id":   threat.DeviceID,
			"threat_type": threat.ThreatType,
			"resolved_by": threat.ResolvedBy,
		})
	}
	return threat, nil
}

// ─── Compliance ───────────────────────────────────────────────────────────────

func (s *Service) RunComplianceCheck(ctx context.Context, tenantID uuid.UUID, req model.RunComplianceRequest) (*model.MobComplianceCheck, error) {
	check, err := s.repo.RunComplianceCheck(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if !check.IsCompliant {
		s.publish("mobile.compliance.failed", map[string]any{
			"tenant_id":        tenantID,
			"device_id":        req.DeviceID,
			"policy_id":        req.PolicyID,
			"compliance_score": check.ComplianceScore,
			"violations":       check.Violations,
			"checked_at":       check.CheckedAt,
		})
	}
	return check, nil
}

func (s *Service) ListComplianceChecks(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]model.MobComplianceCheck, error) {
	return s.repo.ListComplianceChecks(ctx, tenantID, deviceID, limit)
}

// ─── Remote Actions ───────────────────────────────────────────────────────────

func (s *Service) CreateRemoteAction(ctx context.Context, tenantID uuid.UUID, req model.CreateRemoteActionRequest) (*model.MobRemoteAction, error) {
	action, err := s.repo.CreateRemoteAction(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	// Publish destructive actions
	if action.ActionType == "remote_wipe" || action.ActionType == "selective_wipe" || action.ActionType == "lock" {
		s.publish(fmt.Sprintf("mobile.action.%s", action.ActionType), map[string]any{
			"tenant_id":    tenantID,
			"action_id":    action.ID,
			"device_id":    action.DeviceID,
			"action_type":  action.ActionType,
			"requested_by": action.RequestedBy,
		})
	}
	return action, nil
}

func (s *Service) GetRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID) (*model.MobRemoteAction, error) {
	return s.repo.GetRemoteAction(ctx, tenantID, actionID)
}

func (s *Service) ListRemoteActions(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobRemoteAction, error) {
	return s.repo.ListRemoteActions(ctx, tenantID, deviceID)
}

func (s *Service) UpdateRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID, req model.UpdateRemoteActionRequest) (*model.MobRemoteAction, error) {
	action, err := s.repo.UpdateRemoteAction(ctx, tenantID, actionID, req)
	if err != nil {
		return nil, err
	}
	if req.Status != nil {
		s.publish("mobile.action.status_changed", map[string]any{
			"tenant_id":   tenantID,
			"action_id":   action.ID,
			"device_id":   action.DeviceID,
			"action_type": action.ActionType,
			"status":      *req.Status,
		})
	}
	return action, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *Service) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.MobStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}
