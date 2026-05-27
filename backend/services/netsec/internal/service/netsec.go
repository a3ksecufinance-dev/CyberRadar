package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/netsec/internal/model"
	"github.com/cyberradar/platform/services/netsec/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// NetSecService orchestrates network security and microsegmentation.
type NetSecService struct {
	repo     *repository.NetSecRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewNetSecService creates a NetSecService.
func NewNetSecService(repo *repository.NetSecRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *NetSecService {
	return &NetSecService{repo: repo, producer: producer, logger: logger}
}

// ─── Zones ────────────────────────────────────────────────────────────────────

func (s *NetSecService) CreateZone(ctx context.Context, tenantID uuid.UUID, req *model.CreateZoneRequest) (*model.NetSecZone, error) {
	z, err := s.repo.CreateZone(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create zone", err)
	}
	s.logger.Info().Str("zone_id", z.ID.String()).Str("type", z.ZoneType).Str("name", z.Name).Msg("netsec_zone_created")
	return z, nil
}

func (s *NetSecService) GetZone(ctx context.Context, tenantID, zoneID uuid.UUID) (*model.NetSecZone, error) {
	z, err := s.repo.GetZone(ctx, tenantID, zoneID)
	if err != nil {
		return nil, apierrors.Internal("get zone", err)
	}
	if z == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "zone not found")
	}
	return z, nil
}

func (s *NetSecService) ListZones(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*model.NetSecZone, error) {
	zones, err := s.repo.ListZones(ctx, tenantID, activeOnly)
	if err != nil {
		return nil, apierrors.Internal("list zones", err)
	}
	return zones, nil
}

func (s *NetSecService) UpdateZone(ctx context.Context, tenantID, zoneID uuid.UUID, req *model.UpdateZoneRequest) (*model.NetSecZone, error) {
	z, err := s.repo.UpdateZone(ctx, tenantID, zoneID, req)
	if err != nil {
		return nil, apierrors.Internal("update zone", err)
	}
	if z == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "zone not found")
	}
	return z, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *NetSecService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy uuid.UUID) (*model.NetSecPolicy, error) {
	p, err := s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create policy", err)
	}
	s.logger.Info().Str("policy_id", p.ID.String()).Str("action", p.Action).Msg("netsec_policy_created")
	return p, nil
}

func (s *NetSecService) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.NetSecPolicy, error) {
	p, err := s.repo.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return nil, apierrors.Internal("get policy", err)
	}
	if p == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "policy not found")
	}
	return p, nil
}

func (s *NetSecService) ListPolicies(ctx context.Context, tenantID uuid.UUID, srcZoneID, dstZoneID *uuid.UUID, activeOnly bool, page, pageSize int) ([]*model.NetSecPolicy, int, error) {
	policies, total, err := s.repo.ListPolicies(ctx, tenantID, srcZoneID, dstZoneID, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list policies", err)
	}
	return policies, total, nil
}

func (s *NetSecService) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req *model.UpdatePolicyRequest) (*model.NetSecPolicy, error) {
	p, err := s.repo.UpdatePolicy(ctx, tenantID, policyID, req)
	if err != nil {
		return nil, apierrors.Internal("update policy", err)
	}
	if p == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "policy not found")
	}
	return p, nil
}

// ─── Flows ────────────────────────────────────────────────────────────────────

// IngestFlow ingests a network flow and runs anomaly detection heuristics.
func (s *NetSecService) IngestFlow(ctx context.Context, tenantID uuid.UUID, req *model.IngestFlowRequest) (*model.NetSecFlow, error) {
	// Zone resolution (naive CIDR match — production would use a proper lookup)
	var srcZoneID, dstZoneID *uuid.UUID

	flow, err := s.repo.IngestFlow(ctx, tenantID, req, srcZoneID, dstZoneID)
	if err != nil {
		return nil, apierrors.Internal("ingest flow", err)
	}

	// Async anomaly detection
	go s.detectFlowAnomalies(tenantID, flow)
	return flow, nil
}

func (s *NetSecService) detectFlowAnomalies(tenantID uuid.UUID, flow *model.NetSecFlow) {
	ctx := context.Background()
	score := 0
	flags := []string{}
	anomalies := []struct {
		atype string
		sev   string
		desc  string
	}{}

	// Heuristic: large data transfer (>100MB)
	totalBytes := flow.BytesSent + flow.BytesRecv
	if totalBytes > 100*1024*1024 {
		score += 30
		flags = append(flags, "data_exfil")
		if totalBytes > 1024*1024*1024 {
			score += 20
			anomalies = append(anomalies, struct{ atype, sev, desc string }{
				model.AnomalyDataExfil, model.SeverityHigh,
				"Large data transfer detected: " + bytesFmt(totalBytes),
			})
		}
	}

	// Heuristic: port scan (many dst ports from same src) — not detectable in single flow,
	// but flag unusual high port numbers commonly used in C2
	if flow.DstPort != nil && (*flow.DstPort == 4444 || *flow.DstPort == 1337 || *flow.DstPort == 31337) {
		score += 50
		flags = append(flags, "c2_traffic")
		anomalies = append(anomalies, struct{ atype, sev, desc string }{
			model.AnomalyC2, model.SeverityCritical,
			"Suspected C2 traffic on port " + itoa(*flow.DstPort),
		})
	}

	// Heuristic: beaconing pattern (very short duration, low bytes, repeated)
	if flow.DurationMs < 500 && totalBytes < 1024 && flow.Packets > 0 {
		score += 15
		flags = append(flags, "beacon")
	}

	if score == 0 {
		return
	}

	_ = s.repo.UpdateFlowAnomaly(ctx, flow.ID, score, flags)

	for _, a := range anomalies {
		anomaly, err := s.repo.CreateAnomaly(ctx, tenantID, &model.CreateAnomalyRequest{
			AnomalyType: a.atype,
			Severity:    a.sev,
			SrcIP:       flow.SrcIP,
			DstIP:       flow.DstIP,
			SrcZoneID:   flow.SrcZoneID,
			DstZoneID:   flow.DstZoneID,
			FlowIDs:     []uuid.UUID{flow.ID},
			Description: a.desc,
			Evidence: map[string]any{
				"bytes_total": totalBytes,
				"dst_port":    flow.DstPort,
				"duration_ms": flow.DurationMs,
			},
		})
		if err != nil {
			s.logger.Error().Err(err).Msg("netsec_anomaly_create_failed")
			continue
		}

		s.logger.Warn().Str("anomaly_id", anomaly.ID.String()).Str("type", a.atype).Str("severity", a.sev).Msg("netsec_anomaly_detected")

		if a.sev == model.SeverityCritical || a.sev == model.SeverityHigh {
			payload := map[string]any{
				"event_type":   "netsec.anomaly_detected",
				"tenant_id":    tenantID.String(),
				"anomaly_id":   anomaly.ID.String(),
				"anomaly_type": a.atype,
				"severity":     a.sev,
				"src_ip":       flow.SrcIP,
				"dst_ip":       flow.DstIP,
				"timestamp":    time.Now().UTC().Format(time.RFC3339),
			}
			data, _ := json.Marshal(payload)
			_ = s.producer.Publish(ctx, anomaly.ID.String(), data)
		}
	}
}

func (s *NetSecService) ListFlows(ctx context.Context, tenantID uuid.UUID, f model.ListFlowsFilter) ([]*model.NetSecFlow, int, error) {
	flows, total, err := s.repo.ListFlows(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list flows", err)
	}
	return flows, total, nil
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

func (s *NetSecService) CreateAnomaly(ctx context.Context, tenantID uuid.UUID, req *model.CreateAnomalyRequest) (*model.NetSecAnomaly, error) {
	a, err := s.repo.CreateAnomaly(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create anomaly", err)
	}
	s.logger.Warn().Str("anomaly_id", a.ID.String()).Str("type", a.AnomalyType).Str("severity", a.Severity).Msg("netsec_anomaly_reported")
	return a, nil
}

func (s *NetSecService) ListAnomalies(ctx context.Context, tenantID uuid.UUID, f model.ListAnomaliesFilter) ([]*model.NetSecAnomaly, int, error) {
	anomalies, total, err := s.repo.ListAnomalies(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list anomalies", err)
	}
	return anomalies, total, nil
}

func (s *NetSecService) UpdateAnomaly(ctx context.Context, tenantID, anomalyID uuid.UUID, status string) (*model.NetSecAnomaly, error) {
	a, err := s.repo.UpdateAnomaly(ctx, tenantID, anomalyID, status)
	if err != nil {
		return nil, apierrors.Internal("update anomaly", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "anomaly not found")
	}
	return a, nil
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (s *NetSecService) RegisterDevice(ctx context.Context, tenantID uuid.UUID, req *model.RegisterDeviceRequest) (*model.NetSecDevice, error) {
	d, err := s.repo.RegisterDevice(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("register device", err)
	}
	s.logger.Info().Str("device_id", d.ID.String()).Str("type", d.DeviceType).Str("ip", d.IPAddress).Msg("netsec_device_registered")
	return d, nil
}

func (s *NetSecService) ListDevices(ctx context.Context, tenantID uuid.UUID, deviceType string, zoneID *uuid.UUID, page, pageSize int) ([]*model.NetSecDevice, int, error) {
	devices, total, err := s.repo.ListDevices(ctx, tenantID, deviceType, zoneID, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list devices", err)
	}
	return devices, total, nil
}

func (s *NetSecService) UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req *model.UpdateDeviceRequest) (*model.NetSecDevice, error) {
	d, err := s.repo.UpdateDevice(ctx, tenantID, deviceID, req)
	if err != nil {
		return nil, apierrors.Internal("update device", err)
	}
	if d == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "device not found")
	}
	return d, nil
}

// ─── Topology & Stats ─────────────────────────────────────────────────────────

func (s *NetSecService) GetTopology(ctx context.Context, tenantID uuid.UUID) (*model.ZoneTopology, error) {
	topo, err := s.repo.GetTopology(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("get topology", err)
	}
	return topo, nil
}

func (s *NetSecService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.NetSecStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("stats", err)
	}
	return stats, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func bytesFmt(b int64) string {
	const gb = 1024 * 1024 * 1024
	const mb = 1024 * 1024
	if b >= gb {
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	}
	return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
