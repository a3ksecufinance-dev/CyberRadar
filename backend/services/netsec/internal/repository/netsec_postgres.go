package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/netsec/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetSecRepository handles all network security persistence.
type NetSecRepository struct {
	db *pgxpool.Pool
}

// NewNetSecRepository creates a NetSecRepository.
func NewNetSecRepository(db *pgxpool.Pool) *NetSecRepository {
	return &NetSecRepository{db: db}
}

// ─── Zones ────────────────────────────────────────────────────────────────────

func (r *NetSecRepository) CreateZone(ctx context.Context, tenantID uuid.UUID, req *model.CreateZoneRequest) (*model.NetSecZone, error) {
	if req.CIDRBlocks == nil { req.CIDRBlocks = []string{} }
	if req.Color == "" { req.Color = "#6B7280" }
	meta, _ := json.Marshal(req.Metadata)
	var z model.NetSecZone
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO netsec_zones (tenant_id, name, description, zone_type, trust_level, cidr_blocks, color, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id, name) DO UPDATE
		  SET zone_type=EXCLUDED.zone_type, trust_level=EXCLUDED.trust_level,
		      cidr_blocks=EXCLUDED.cidr_blocks, color=EXCLUDED.color, updated_at=NOW()
		RETURNING id, tenant_id, name, COALESCE(description,''), zone_type, trust_level,
		          COALESCE(cidr_blocks,'{}'), color, is_active, metadata, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.ZoneType, req.TrustLevel, req.CIDRBlocks, req.Color, meta,
	).Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.TrustLevel,
		&z.CIDRBlocks, &z.Color, &z.IsActive, &metaRaw, &z.CreatedAt, &z.UpdatedAt)
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &z.Metadata)
	return &z, nil
}

func (r *NetSecRepository) GetZone(ctx context.Context, tenantID, zoneID uuid.UUID) (*model.NetSecZone, error) {
	var z model.NetSecZone
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), zone_type, trust_level,
		       COALESCE(cidr_blocks,'{}'), color, is_active, metadata, created_at, updated_at
		FROM netsec_zones WHERE id=$1 AND tenant_id=$2`, zoneID, tenantID,
	).Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.TrustLevel,
		&z.CIDRBlocks, &z.Color, &z.IsActive, &metaRaw, &z.CreatedAt, &z.UpdatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &z.Metadata)
	return &z, nil
}

func (r *NetSecRepository) ListZones(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*model.NetSecZone, error) {
	where := "tenant_id=$1"
	if activeOnly { where += " AND is_active=TRUE" }
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), zone_type, trust_level,
		       COALESCE(cidr_blocks,'{}'), color, is_active, metadata, created_at, updated_at
		FROM netsec_zones WHERE `+where+` ORDER BY trust_level DESC, name`, tenantID)
	if err != nil { return nil, err }
	defer rows.Close()
	var zones []*model.NetSecZone
	for rows.Next() {
		var z model.NetSecZone
		var metaRaw []byte
		if err := rows.Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.TrustLevel,
			&z.CIDRBlocks, &z.Color, &z.IsActive, &metaRaw, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaRaw, &z.Metadata)
		zones = append(zones, &z)
	}
	return zones, nil
}

func (r *NetSecRepository) UpdateZone(ctx context.Context, tenantID, zoneID uuid.UUID, req *model.UpdateZoneRequest) (*model.NetSecZone, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Description != "" { sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++ }
	if req.TrustLevel != nil { sets = append(sets, fmt.Sprintf("trust_level=$%d", n)); args = append(args, *req.TrustLevel); n++ }
	if req.CIDRBlocks != nil { sets = append(sets, fmt.Sprintf("cidr_blocks=$%d", n)); args = append(args, req.CIDRBlocks); n++ }
	if req.Color != "" { sets = append(sets, fmt.Sprintf("color=$%d", n)); args = append(args, req.Color); n++ }
	if req.IsActive != nil { sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++ }
	if req.Metadata != nil { meta, _ := json.Marshal(req.Metadata); sets = append(sets, fmt.Sprintf("metadata=$%d", n)); args = append(args, meta); n++ }
	args = append(args, zoneID, tenantID)
	var z model.NetSecZone
	var metaRaw []byte
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE netsec_zones SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, name, COALESCE(description,''), zone_type, trust_level,
		          COALESCE(cidr_blocks,'{}'), color, is_active, metadata, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.TrustLevel,
		&z.CIDRBlocks, &z.Color, &z.IsActive, &metaRaw, &z.CreatedAt, &z.UpdatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &z.Metadata)
	return &z, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *NetSecRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy uuid.UUID) (*model.NetSecPolicy, error) {
	if req.Protocol == "" { req.Protocol = "any" }
	if req.Priority == 0 { req.Priority = 100 }
	if req.Ports == nil { req.Ports = []string{} }
	var p model.NetSecPolicy
	err := r.db.QueryRow(ctx, `
		INSERT INTO netsec_policies
		  (tenant_id, name, description, src_zone_id, dst_zone_id, src_cidr, dst_cidr, protocol, ports, action, priority, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, tenant_id, name, COALESCE(description,''), src_zone_id, NULL::TEXT,
		          dst_zone_id, NULL::TEXT, COALESCE(src_cidr,''), COALESCE(dst_cidr,''),
		          protocol, COALESCE(ports,'{}'), action, priority, is_active, hit_count, last_hit_at, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.SrcZoneID, req.DstZoneID,
		req.SrcCIDR, req.DstCIDR, req.Protocol, req.Ports, req.Action, req.Priority, createdBy,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description,
		&p.SrcZoneID, &p.SrcZoneName, &p.DstZoneID, &p.DstZoneName,
		&p.SrcCIDR, &p.DstCIDR, &p.Protocol, &p.Ports,
		&p.Action, &p.Priority, &p.IsActive, &p.HitCount, &p.LastHitAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return &p, err
}

func (r *NetSecRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID, srcZoneID, dstZoneID *uuid.UUID, activeOnly bool, page, pageSize int) ([]*model.NetSecPolicy, int, error) {
	if pageSize <= 0 { pageSize = 50 }
	if page <= 0 { page = 1 }
	conds := []string{"p.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if srcZoneID != nil { conds = append(conds, fmt.Sprintf("p.src_zone_id=$%d", n)); args = append(args, *srcZoneID); n++ }
	if dstZoneID != nil { conds = append(conds, fmt.Sprintf("p.dst_zone_id=$%d", n)); args = append(args, *dstZoneID); n++ }
	if activeOnly { conds = append(conds, "p.is_active=TRUE") }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_policies p WHERE "+where, args...).Scan(&total)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT p.id, p.tenant_id, p.name, COALESCE(p.description,''),
		       p.src_zone_id, COALESCE(sz.name,''), p.dst_zone_id, COALESCE(dz.name,''),
		       COALESCE(p.src_cidr,''), COALESCE(p.dst_cidr,''), p.protocol,
		       COALESCE(p.ports,'{}'), p.action, p.priority, p.is_active, p.hit_count, p.last_hit_at,
		       p.created_by, p.created_at, p.updated_at
		FROM netsec_policies p
		LEFT JOIN netsec_zones sz ON sz.id=p.src_zone_id
		LEFT JOIN netsec_zones dz ON dz.id=p.dst_zone_id
		WHERE %s ORDER BY p.priority ASC, p.hit_count DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var policies []*model.NetSecPolicy
	for rows.Next() {
		var p model.NetSecPolicy
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description,
			&p.SrcZoneID, &p.SrcZoneName, &p.DstZoneID, &p.DstZoneName,
			&p.SrcCIDR, &p.DstCIDR, &p.Protocol, &p.Ports,
			&p.Action, &p.Priority, &p.IsActive, &p.HitCount, &p.LastHitAt,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, 0, err
		}
		policies = append(policies, &p)
	}
	return policies, total, nil
}

func (r *NetSecRepository) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.NetSecPolicy, error) {
	var p model.NetSecPolicy
	err := r.db.QueryRow(ctx, `
		SELECT p.id, p.tenant_id, p.name, COALESCE(p.description,''),
		       p.src_zone_id, COALESCE(sz.name,''), p.dst_zone_id, COALESCE(dz.name,''),
		       COALESCE(p.src_cidr,''), COALESCE(p.dst_cidr,''), p.protocol,
		       COALESCE(p.ports,'{}'), p.action, p.priority, p.is_active, p.hit_count, p.last_hit_at,
		       p.created_by, p.created_at, p.updated_at
		FROM netsec_policies p
		LEFT JOIN netsec_zones sz ON sz.id=p.src_zone_id
		LEFT JOIN netsec_zones dz ON dz.id=p.dst_zone_id
		WHERE p.id=$1 AND p.tenant_id=$2`, policyID, tenantID,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description,
		&p.SrcZoneID, &p.SrcZoneName, &p.DstZoneID, &p.DstZoneName,
		&p.SrcCIDR, &p.DstCIDR, &p.Protocol, &p.Ports,
		&p.Action, &p.Priority, &p.IsActive, &p.HitCount, &p.LastHitAt,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	return &p, err
}

func (r *NetSecRepository) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req *model.UpdatePolicyRequest) (*model.NetSecPolicy, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Name != "" { sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, req.Name); n++ }
	if req.Description != "" { sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++ }
	if req.Protocol != "" { sets = append(sets, fmt.Sprintf("protocol=$%d", n)); args = append(args, req.Protocol); n++ }
	if req.Ports != nil { sets = append(sets, fmt.Sprintf("ports=$%d", n)); args = append(args, req.Ports); n++ }
	if req.Action != "" { sets = append(sets, fmt.Sprintf("action=$%d", n)); args = append(args, req.Action); n++ }
	if req.Priority != nil { sets = append(sets, fmt.Sprintf("priority=$%d", n)); args = append(args, *req.Priority); n++ }
	if req.IsActive != nil { sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++ }
	args = append(args, policyID, tenantID)
	_, err := r.db.Exec(ctx, fmt.Sprintf("UPDATE netsec_policies SET %s WHERE id=$%d AND tenant_id=$%d",
		strings.Join(sets, ","), n, n+1), args...)
	if err != nil { return nil, err }
	return r.GetPolicy(ctx, tenantID, policyID)
}

func (r *NetSecRepository) IncrementPolicyHit(ctx context.Context, policyID uuid.UUID) {
	_, _ = r.db.Exec(ctx,
		"UPDATE netsec_policies SET hit_count=hit_count+1, last_hit_at=NOW() WHERE id=$1", policyID)
}

// ─── Flows ────────────────────────────────────────────────────────────────────

func (r *NetSecRepository) IngestFlow(ctx context.Context, tenantID uuid.UUID, req *model.IngestFlowRequest, srcZoneID, dstZoneID *uuid.UUID) (*model.NetSecFlow, error) {
	action := req.Action
	if action == "" { action = "allowed" }
	var f model.NetSecFlow
	err := r.db.QueryRow(ctx, `
		INSERT INTO netsec_flows
		  (tenant_id, src_ip, dst_ip, src_port, dst_port, protocol,
		   bytes_sent, bytes_recv, packets, duration_ms,
		   src_zone_id, dst_zone_id, action, flow_start, flow_end)
		VALUES ($1,$2::INET,$3::INET,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING id, tenant_id, src_ip::TEXT, dst_ip::TEXT, src_port, dst_port,
		          COALESCE(protocol,''), bytes_sent, bytes_recv, packets, duration_ms,
		          src_zone_id, NULL::TEXT, dst_zone_id, NULL::TEXT,
		          action, anomaly_score, COALESCE(flags,'{}'), flow_start, flow_end, created_at`,
		tenantID, req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, req.Protocol,
		req.BytesSent, req.BytesRecv, req.Packets, req.DurationMs,
		srcZoneID, dstZoneID, action, req.FlowStart, req.FlowEnd,
	).Scan(&f.ID, &f.TenantID, &f.SrcIP, &f.DstIP, &f.SrcPort, &f.DstPort, &f.Protocol,
		&f.BytesSent, &f.BytesRecv, &f.Packets, &f.DurationMs,
		&f.SrcZoneID, &f.SrcZoneName, &f.DstZoneID, &f.DstZoneName,
		&f.Action, &f.AnomalyScore, &f.Flags, &f.FlowStart, &f.FlowEnd, &f.CreatedAt)
	return &f, err
}

func (r *NetSecRepository) ListFlows(ctx context.Context, tenantID uuid.UUID, f model.ListFlowsFilter) ([]*model.NetSecFlow, int, error) {
	if f.PageSize <= 0 { f.PageSize = 50 }
	if f.Page <= 0 { f.Page = 1 }
	conds := []string{"fl.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.SrcIP != "" { conds = append(conds, fmt.Sprintf("fl.src_ip::TEXT=$%d", n)); args = append(args, f.SrcIP); n++ }
	if f.DstIP != "" { conds = append(conds, fmt.Sprintf("fl.dst_ip::TEXT=$%d", n)); args = append(args, f.DstIP); n++ }
	if f.SrcZoneID != nil { conds = append(conds, fmt.Sprintf("fl.src_zone_id=$%d", n)); args = append(args, *f.SrcZoneID); n++ }
	if f.DstZoneID != nil { conds = append(conds, fmt.Sprintf("fl.dst_zone_id=$%d", n)); args = append(args, *f.DstZoneID); n++ }
	if f.Action != "" { conds = append(conds, fmt.Sprintf("fl.action=$%d", n)); args = append(args, f.Action); n++ }
	if f.MinScore != nil { conds = append(conds, fmt.Sprintf("fl.anomaly_score>=$%d", n)); args = append(args, *f.MinScore); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_flows fl WHERE "+where, args...).Scan(&total)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT fl.id, fl.tenant_id, fl.src_ip::TEXT, fl.dst_ip::TEXT, fl.src_port, fl.dst_port,
		       COALESCE(fl.protocol,''), fl.bytes_sent, fl.bytes_recv, fl.packets, fl.duration_ms,
		       fl.src_zone_id, COALESCE(sz.name,''), fl.dst_zone_id, COALESCE(dz.name,''),
		       fl.action, fl.anomaly_score, COALESCE(fl.flags,'{}'), fl.flow_start, fl.flow_end, fl.created_at
		FROM netsec_flows fl
		LEFT JOIN netsec_zones sz ON sz.id=fl.src_zone_id
		LEFT JOIN netsec_zones dz ON dz.id=fl.dst_zone_id
		WHERE %s ORDER BY fl.flow_start DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var flows []*model.NetSecFlow
	for rows.Next() {
		var fl model.NetSecFlow
		if err := rows.Scan(&fl.ID, &fl.TenantID, &fl.SrcIP, &fl.DstIP, &fl.SrcPort, &fl.DstPort,
			&fl.Protocol, &fl.BytesSent, &fl.BytesRecv, &fl.Packets, &fl.DurationMs,
			&fl.SrcZoneID, &fl.SrcZoneName, &fl.DstZoneID, &fl.DstZoneName,
			&fl.Action, &fl.AnomalyScore, &fl.Flags, &fl.FlowStart, &fl.FlowEnd, &fl.CreatedAt); err != nil {
			return nil, 0, err
		}
		flows = append(flows, &fl)
	}
	return flows, total, nil
}

func (r *NetSecRepository) UpdateFlowAnomaly(ctx context.Context, flowID uuid.UUID, score int, flags []string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE netsec_flows SET anomaly_score=$2, flags=$3 WHERE id=$1", flowID, score, flags)
	return err
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

func (r *NetSecRepository) CreateAnomaly(ctx context.Context, tenantID uuid.UUID, req *model.CreateAnomalyRequest) (*model.NetSecAnomaly, error) {
	ev, _ := json.Marshal(req.Evidence)
	if req.FlowIDs == nil { req.FlowIDs = []uuid.UUID{} }
	var a model.NetSecAnomaly
	var evRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO netsec_anomalies
		  (tenant_id, anomaly_type, severity, src_ip, dst_ip, src_zone_id, dst_zone_id, flow_ids, description, evidence)
		VALUES ($1,$2,$3,$4::INET,$5::INET,$6,$7,$8,$9,$10)
		RETURNING id, tenant_id, anomaly_type, severity,
		          src_ip::TEXT, dst_ip::TEXT, src_zone_id, dst_zone_id,
		          COALESCE(flow_ids,'{}'), description, evidence,
		          status, resolved_at, detected_at, created_at`,
		tenantID, req.AnomalyType, req.Severity, nullInet(req.SrcIP), nullInet(req.DstIP),
		req.SrcZoneID, req.DstZoneID, req.FlowIDs, req.Description, ev,
	).Scan(&a.ID, &a.TenantID, &a.AnomalyType, &a.Severity,
		&a.SrcIP, &a.DstIP, &a.SrcZoneID, &a.DstZoneID,
		&a.FlowIDs, &a.Description, &evRaw,
		&a.Status, &a.ResolvedAt, &a.DetectedAt, &a.CreatedAt)
	if err != nil { return nil, err }
	_ = json.Unmarshal(evRaw, &a.Evidence)
	return &a, nil
}

func (r *NetSecRepository) ListAnomalies(ctx context.Context, tenantID uuid.UUID, f model.ListAnomaliesFilter) ([]*model.NetSecAnomaly, int, error) {
	if f.PageSize <= 0 { f.PageSize = 20 }
	if f.Page <= 0 { f.Page = 1 }
	conds := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AnomalyType != "" { conds = append(conds, fmt.Sprintf("anomaly_type=$%d", n)); args = append(args, f.AnomalyType); n++ }
	if f.Severity != "" { conds = append(conds, fmt.Sprintf("severity=$%d", n)); args = append(args, f.Severity); n++ }
	if f.Status != "" { conds = append(conds, fmt.Sprintf("status=$%d", n)); args = append(args, f.Status); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_anomalies WHERE "+where, args...).Scan(&total)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, anomaly_type, severity,
		       COALESCE(src_ip::TEXT,''), COALESCE(dst_ip::TEXT,''), src_zone_id, dst_zone_id,
		       COALESCE(flow_ids,'{}'), description, evidence,
		       status, resolved_at, detected_at, created_at
		FROM netsec_anomalies WHERE %s ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var anomalies []*model.NetSecAnomaly
	for rows.Next() {
		var a model.NetSecAnomaly
		var evRaw []byte
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AnomalyType, &a.Severity,
			&a.SrcIP, &a.DstIP, &a.SrcZoneID, &a.DstZoneID,
			&a.FlowIDs, &a.Description, &evRaw,
			&a.Status, &a.ResolvedAt, &a.DetectedAt, &a.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(evRaw, &a.Evidence)
		anomalies = append(anomalies, &a)
	}
	return anomalies, total, nil
}

func (r *NetSecRepository) UpdateAnomaly(ctx context.Context, tenantID, anomalyID uuid.UUID, status string) (*model.NetSecAnomaly, error) {
	var resolvedAt *time.Time
	if status == "resolved" || status == "false_positive" {
		t := time.Now()
		resolvedAt = &t
	}
	var a model.NetSecAnomaly
	var evRaw []byte
	err := r.db.QueryRow(ctx, `
		UPDATE netsec_anomalies SET status=$3, resolved_at=$4
		WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, anomaly_type, severity,
		          COALESCE(src_ip::TEXT,''), COALESCE(dst_ip::TEXT,''), src_zone_id, dst_zone_id,
		          COALESCE(flow_ids,'{}'), description, evidence,
		          status, resolved_at, detected_at, created_at`,
		anomalyID, tenantID, status, resolvedAt,
	).Scan(&a.ID, &a.TenantID, &a.AnomalyType, &a.Severity,
		&a.SrcIP, &a.DstIP, &a.SrcZoneID, &a.DstZoneID,
		&a.FlowIDs, &a.Description, &evRaw,
		&a.Status, &a.ResolvedAt, &a.DetectedAt, &a.CreatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	_ = json.Unmarshal(evRaw, &a.Evidence)
	return &a, nil
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (r *NetSecRepository) RegisterDevice(ctx context.Context, tenantID uuid.UUID, req *model.RegisterDeviceRequest) (*model.NetSecDevice, error) {
	managed := true
	if req.IsManaged != nil { managed = *req.IsManaged }
	meta, _ := json.Marshal(req.Metadata)
	var d model.NetSecDevice
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO netsec_devices (tenant_id, name, device_type, ip_address, zone_id, vendor, model, firmware, is_managed, metadata)
		VALUES ($1,$2,$3,$4::INET,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant_id, ip_address) DO UPDATE
		  SET name=EXCLUDED.name, device_type=EXCLUDED.device_type, zone_id=EXCLUDED.zone_id,
		      vendor=EXCLUDED.vendor, model=EXCLUDED.model, firmware=EXCLUDED.firmware,
		      last_seen_at=NOW(), updated_at=NOW()
		RETURNING id, tenant_id, name, device_type, ip_address::TEXT, zone_id, NULL::TEXT,
		          COALESCE(vendor,''), COALESCE(model,''), COALESCE(firmware,''),
		          is_managed, last_seen_at, status, metadata, created_at, updated_at`,
		tenantID, req.Name, req.DeviceType, req.IPAddress, req.ZoneID,
		req.Vendor, req.Model, req.Firmware, managed, meta,
	).Scan(&d.ID, &d.TenantID, &d.Name, &d.DeviceType, &d.IPAddress, &d.ZoneID, &d.ZoneName,
		&d.Vendor, &d.Model, &d.Firmware, &d.IsManaged, &d.LastSeenAt, &d.Status, &metaRaw, &d.CreatedAt, &d.UpdatedAt)
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &d.Metadata)
	return &d, nil
}

func (r *NetSecRepository) ListDevices(ctx context.Context, tenantID uuid.UUID, deviceType string, zoneID *uuid.UUID, page, pageSize int) ([]*model.NetSecDevice, int, error) {
	if pageSize <= 0 { pageSize = 50 }
	if page <= 0 { page = 1 }
	conds := []string{"d.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if deviceType != "" { conds = append(conds, fmt.Sprintf("d.device_type=$%d", n)); args = append(args, deviceType); n++ }
	if zoneID != nil { conds = append(conds, fmt.Sprintf("d.zone_id=$%d", n)); args = append(args, *zoneID); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_devices d WHERE "+where, args...).Scan(&total)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT d.id, d.tenant_id, d.name, d.device_type, d.ip_address::TEXT, d.zone_id, COALESCE(z.name,''),
		       COALESCE(d.vendor,''), COALESCE(d.model,''), COALESCE(d.firmware,''),
		       d.is_managed, d.last_seen_at, d.status, d.metadata, d.created_at, d.updated_at
		FROM netsec_devices d
		LEFT JOIN netsec_zones z ON z.id=d.zone_id
		WHERE %s ORDER BY d.device_type, d.name LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var devices []*model.NetSecDevice
	for rows.Next() {
		var d model.NetSecDevice
		var metaRaw []byte
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.DeviceType, &d.IPAddress, &d.ZoneID, &d.ZoneName,
			&d.Vendor, &d.Model, &d.Firmware, &d.IsManaged, &d.LastSeenAt, &d.Status, &metaRaw, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(metaRaw, &d.Metadata)
		devices = append(devices, &d)
	}
	return devices, total, nil
}

func (r *NetSecRepository) UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req *model.UpdateDeviceRequest) (*model.NetSecDevice, error) {
	sets := []string{"updated_at=NOW()", "last_seen_at=NOW()"}
	args := []any{}
	n := 1
	if req.ZoneID != nil { sets = append(sets, fmt.Sprintf("zone_id=$%d", n)); args = append(args, *req.ZoneID); n++ }
	if req.Vendor != "" { sets = append(sets, fmt.Sprintf("vendor=$%d", n)); args = append(args, req.Vendor); n++ }
	if req.Model != "" { sets = append(sets, fmt.Sprintf("model=$%d", n)); args = append(args, req.Model); n++ }
	if req.Firmware != "" { sets = append(sets, fmt.Sprintf("firmware=$%d", n)); args = append(args, req.Firmware); n++ }
	if req.Status != "" { sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, req.Status); n++ }
	if req.Metadata != nil { meta, _ := json.Marshal(req.Metadata); sets = append(sets, fmt.Sprintf("metadata=$%d", n)); args = append(args, meta); n++ }
	args = append(args, deviceID, tenantID)
	var d model.NetSecDevice
	var metaRaw []byte
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE netsec_devices SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, name, device_type, ip_address::TEXT, zone_id, NULL::TEXT,
		          COALESCE(vendor,''), COALESCE(model,''), COALESCE(firmware,''),
		          is_managed, last_seen_at, status, metadata, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(&d.ID, &d.TenantID, &d.Name, &d.DeviceType, &d.IPAddress, &d.ZoneID, &d.ZoneName,
		&d.Vendor, &d.Model, &d.Firmware, &d.IsManaged, &d.LastSeenAt, &d.Status, &metaRaw, &d.CreatedAt, &d.UpdatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &d.Metadata)
	return &d, nil
}

// ─── Topology ─────────────────────────────────────────────────────────────────

func (r *NetSecRepository) GetTopology(ctx context.Context, tenantID uuid.UUID) (*model.ZoneTopology, error) {
	zones, err := r.ListZones(ctx, tenantID, true)
	if err != nil { return nil, err }
	devices, _, err := r.ListDevices(ctx, tenantID, "", nil, 1, 500)
	if err != nil { return nil, err }
	policies, _, err := r.ListPolicies(ctx, tenantID, nil, nil, true, 1, 500)
	if err != nil { return nil, err }
	return &model.ZoneTopology{Zones: zones, Devices: devices, Policies: policies}, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *NetSecRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.NetSecStats, error) {
	stats := &model.NetSecStats{
		AnomaliesBySev:  make(map[string]int),
		AnomaliesByType: make(map[string]int),
	}

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_zones WHERE tenant_id=$1 AND is_active=TRUE", tenantID).Scan(&stats.TotalZones)
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM netsec_policies WHERE tenant_id=$1", tenantID).Scan(&stats.TotalPolicies, &stats.ActivePolicies)
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*), COUNT(*) FILTER (WHERE status='offline') FROM netsec_devices WHERE tenant_id=$1", tenantID).Scan(&stats.TotalDevices, &stats.OfflineDevices)
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM netsec_anomalies WHERE tenant_id=$1 AND status='open'", tenantID).Scan(&stats.OpenAnomalies)
	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE action='blocked')
		FROM netsec_flows WHERE tenant_id=$1 AND flow_start > NOW()-INTERVAL '24 hours'`, tenantID,
	).Scan(&stats.FlowsLast24h, &stats.BlockedFlows24h)

	rows, _ := r.db.Query(ctx, "SELECT severity, COUNT(*) FROM netsec_anomalies WHERE tenant_id=$1 GROUP BY severity", tenantID)
	if rows != nil { defer rows.Close(); for rows.Next() { var s string; var c int; _ = rows.Scan(&s, &c); stats.AnomaliesBySev[s] = c } }

	rows2, _ := r.db.Query(ctx, "SELECT anomaly_type, COUNT(*) FROM netsec_anomalies WHERE tenant_id=$1 AND status='open' GROUP BY anomaly_type", tenantID)
	if rows2 != nil { defer rows2.Close(); for rows2.Next() { var s string; var c int; _ = rows2.Scan(&s, &c); stats.AnomaliesByType[s] = c } }

	rows3, _ := r.db.Query(ctx, `
		SELECT src_ip::TEXT, COUNT(*), SUM(bytes_sent)
		FROM netsec_flows WHERE tenant_id=$1 AND flow_start > NOW()-INTERVAL '24 hours'
		GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var ip model.IPStats
			_ = rows3.Scan(&ip.IP, &ip.FlowCount, &ip.BytesSent)
			stats.TopSrcIPs = append(stats.TopSrcIPs, &ip)
		}
	}

	rows4, _ := r.db.Query(ctx, `
		SELECT id, name, hit_count FROM netsec_policies
		WHERE tenant_id=$1 ORDER BY hit_count DESC LIMIT 5`, tenantID)
	if rows4 != nil {
		defer rows4.Close()
		for rows4.Next() {
			var ph model.PolicyHitStats
			_ = rows4.Scan(&ph.PolicyID, &ph.PolicyName, &ph.HitCount)
			stats.PolicyHits = append(stats.PolicyHits, &ph)
		}
	}

	return stats, nil
}

// nullInet returns nil if s is empty (to allow NULL in INET column)
func nullInet(s string) interface{} {
	if s == "" { return nil }
	return s
}
