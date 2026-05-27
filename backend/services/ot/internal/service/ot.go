package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cyberradar/platform/services/ot/internal/model"
	"github.com/cyberradar/platform/services/ot/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

type OTService struct {
	repo   *repository.OTRepository
	kafka  *kafka.Writer
	logger zerolog.Logger
}

func NewOTService(repo *repository.OTRepository, kw *kafka.Writer, logger zerolog.Logger) *OTService {
	return &OTService{repo: repo, kafka: kw, logger: logger}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (s *OTService) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest, createdBy *uuid.UUID) (*model.OTAsset, error) {
	a, err := s.repo.CreateAsset(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, err
	}
	if a.RiskLevel == "critical" || a.IsInternetFacing {
		go s.publish("ot.asset_high_risk", map[string]any{
			"asset_id":   a.ID,
			"tenant_id":  a.TenantID,
			"asset_type": a.AssetType,
			"risk_level": a.RiskLevel,
			"site":       a.Site,
		})
	}
	return a, nil
}

func (s *OTService) GetAsset(ctx context.Context, tenantID, id uuid.UUID) (*model.OTAsset, error) {
	return s.repo.GetAsset(ctx, tenantID, id)
}

func (s *OTService) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]model.OTAsset, int, error) {
	return s.repo.ListAssets(ctx, tenantID, f)
}

func (s *OTService) UpdateAsset(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAssetRequest) (*model.OTAsset, error) {
	return s.repo.UpdateAsset(ctx, tenantID, id, req)
}

// ─── Zones ────────────────────────────────────────────────────────────────────

func (s *OTService) CreateZone(ctx context.Context, tenantID uuid.UUID, req *model.CreateZoneRequest, createdBy *uuid.UUID) (*model.OTZone, error) {
	return s.repo.CreateZone(ctx, tenantID, req, createdBy)
}

func (s *OTService) ListZones(ctx context.Context, tenantID uuid.UUID, site string) ([]model.OTZone, error) {
	return s.repo.ListZones(ctx, tenantID, site)
}

func (s *OTService) UpdateZone(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateZoneRequest) (*model.OTZone, error) {
	return s.repo.UpdateZone(ctx, tenantID, id, req)
}

// ─── Communications ───────────────────────────────────────────────────────────

func (s *OTService) CreateCommunication(ctx context.Context, tenantID uuid.UUID, req *model.CreateCommunicationRequest) (*model.OTCommunication, error) {
	c, err := s.repo.CreateCommunication(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if c.IsAnomalous || !c.IsAuthorized {
		go s.publish("ot.anomalous_communication", map[string]any{
			"comm_id":       c.ID,
			"tenant_id":     c.TenantID,
			"src_asset_id":  c.SrcAssetID,
			"dst_asset_id":  c.DstAssetID,
			"protocol":      c.Protocol,
			"is_authorized": c.IsAuthorized,
		})
	}
	return c, nil
}

func (s *OTService) ListCommunications(ctx context.Context, tenantID uuid.UUID, anomalousOnly bool) ([]model.OTCommunication, error) {
	return s.repo.ListCommunications(ctx, tenantID, anomalousOnly)
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

func (s *OTService) CreateVulnerability(ctx context.Context, tenantID uuid.UUID, req *model.CreateVulnerabilityRequest) (*model.OTVulnerability, error) {
	v, err := s.repo.CreateVulnerability(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if v.Severity == "critical" || v.AffectsSafety {
		go s.publish("ot.critical_vulnerability", map[string]any{
			"vuln_id":         v.ID,
			"tenant_id":       v.TenantID,
			"asset_id":        v.AssetID,
			"severity":        v.Severity,
			"affects_safety":  v.AffectsSafety,
			"cve_id":          v.CVEID,
			"ics_cert_id":     v.ICSCertID,
		})
	}
	return v, nil
}

func (s *OTService) ListVulnerabilities(ctx context.Context, tenantID uuid.UUID, f model.ListVulnsFilter) ([]model.OTVulnerability, int, error) {
	return s.repo.ListVulnerabilities(ctx, tenantID, f)
}

func (s *OTService) UpdateVulnerability(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateVulnerabilityRequest) (*model.OTVulnerability, error) {
	return s.repo.UpdateVulnerability(ctx, tenantID, id, req)
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (s *OTService) CreateEvent(ctx context.Context, tenantID uuid.UUID, req *model.CreateEventRequest) (*model.OTEvent, error) {
	e, err := s.repo.CreateEvent(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if e.Severity == "critical" || e.Severity == "high" {
		go s.publish("ot.security_event", map[string]any{
			"event_id":   e.ID,
			"tenant_id":  e.TenantID,
			"asset_id":   e.AssetID,
			"event_type": e.EventType,
			"severity":   e.Severity,
			"title":      e.Title,
		})
	}
	return e, nil
}

func (s *OTService) ListEvents(ctx context.Context, tenantID uuid.UUID, f model.ListEventsFilter) ([]model.OTEvent, int, error) {
	return s.repo.ListEvents(ctx, tenantID, f)
}

func (s *OTService) UpdateEvent(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateEventRequest) (*model.OTEvent, error) {
	return s.repo.UpdateEvent(ctx, tenantID, id, req)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *OTService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.OTPolicy, error) {
	return s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
}

func (s *OTService) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string) ([]model.OTPolicy, error) {
	return s.repo.ListPolicies(ctx, tenantID, policyType)
}

func (s *OTService) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePolicyRequest) (*model.OTPolicy, error) {
	return s.repo.UpdatePolicy(ctx, tenantID, id, req)
}

// ─── Patches ──────────────────────────────────────────────────────────────────

func (s *OTService) CreatePatch(ctx context.Context, tenantID uuid.UUID, req *model.CreatePatchRequest, createdBy *uuid.UUID) (*model.OTPatch, error) {
	return s.repo.CreatePatch(ctx, tenantID, req, createdBy)
}

func (s *OTService) ListPatches(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, status string) ([]model.OTPatch, error) {
	return s.repo.ListPatches(ctx, tenantID, assetID, status)
}

func (s *OTService) UpdatePatch(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePatchRequest) (*model.OTPatch, error) {
	p, err := s.repo.UpdatePatch(ctx, tenantID, id, req)
	if err != nil {
		return nil, err
	}
	// Mark asset as patched when patch applied
	if req.Status != nil && *req.Status == "applied" {
		go func() {
			isPatched := true
			_, _ = s.repo.UpdateAsset(context.Background(), tenantID, p.AssetID, &model.UpdateAssetRequest{
				IsPatched: &isPatched,
			})
		}()
	}
	return p, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *OTService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.OTStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}

// ─── Kafka ────────────────────────────────────────────────────────────────────

func (s *OTService) publish(eventType string, payload map[string]any) {
	payload["event_type"] = eventType
	payload["timestamp"] = time.Now().UTC()
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	tenantID, _ := payload["tenant_id"].(uuid.UUID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.kafka.WriteMessages(ctx, kafka.Message{
		Key:   []byte(tenantID.String()),
		Value: data,
	})
}
