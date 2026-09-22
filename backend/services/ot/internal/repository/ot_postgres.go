package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/ot/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OTRepository struct {
	db *pgxpool.Pool
}

func NewOTRepository(pool *pgxpool.Pool) *OTRepository {
	return &OTRepository{db: pool}
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

func assetRiskScore(criticality string, isInternetFacing bool, purdueLevel int, vulnCount int) int {
	score := 0
	switch criticality {
	case "critical":
		score += 40
	case "high":
		score += 25
	case "medium":
		score += 10
	}
	if isInternetFacing {
		score += 25
	}
	// Lower Purdue level = more OT exposure
	if purdueLevel <= 1 {
		score += 15
	} else if purdueLevel == 2 {
		score += 8
	}
	score += vulnCount * 3
	if score > 100 {
		score = 100
	}
	return score
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (r *OTRepository) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest, createdBy *uuid.UUID) (*model.OTAsset, error) {
	proto := req.Protocol
	if proto == nil {
		proto = []string{}
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	meta, _ := json.Marshal(req.Metadata)
	crit := req.Criticality
	if crit == "" {
		crit = "medium"
	}
	riskScore := assetRiskScore(crit, req.IsInternetFacing, req.PurdueLevel, 0)
	riskLevel := riskLevelFromScore(riskScore)

	var a model.OTAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_assets
		 (tenant_id,name,description,asset_type,vendor,model,firmware_version,serial_number,
		  ip_address,mac_address,protocol,site,zone,purdue_level,risk_score,risk_level,
		  is_internet_facing,criticality,install_date,end_of_life_date,tags,metadata,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		 RETURNING id,tenant_id,name,description,asset_type,vendor,model,firmware_version,serial_number,
		           ip_address,mac_address,protocol,site,zone,purdue_level,risk_score,risk_level,
		           is_internet_facing,is_patched,last_patched_at,is_active,criticality,
		           install_date,end_of_life_date,tags,metadata,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.AssetType,
		req.Vendor, req.Model, req.FirmwareVersion, req.SerialNumber,
		req.IPAddress, req.MACAddress, proto,
		req.Site, req.Zone, req.PurdueLevel, riskScore, riskLevel,
		req.IsInternetFacing, crit, req.InstallDate, req.EndOfLifeDate,
		tags, meta, createdBy,
	).Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType,
		&a.Vendor, &a.Model, &a.FirmwareVersion, &a.SerialNumber,
		&a.IPAddress, &a.MACAddress, &a.Protocol,
		&a.Site, &a.Zone, &a.PurdueLevel, &a.RiskScore, &a.RiskLevel,
		&a.IsInternetFacing, &a.IsPatched, &a.LastPatchedAt, &a.IsActive, &a.Criticality,
		&a.InstallDate, &a.EndOfLifeDate, &a.Tags, &metaRaw,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *OTRepository) GetAsset(ctx context.Context, tenantID, id uuid.UUID) (*model.OTAsset, error) {
	var a model.OTAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT a.id,a.tenant_id,a.name,a.description,a.asset_type,a.vendor,a.model,
		        a.firmware_version,a.serial_number,a.ip_address,a.mac_address,a.protocol,
		        a.site,a.zone,a.purdue_level,a.risk_score,a.risk_level,
		        a.is_internet_facing,a.is_patched,a.last_patched_at,a.is_active,a.criticality,
		        a.install_date,a.end_of_life_date,a.tags,a.metadata,a.created_by,a.created_at,a.updated_at,
		        COUNT(DISTINCT v.id) FILTER (WHERE v.id IS NOT NULL AND v.status='open') AS vuln_count,
		        COUNT(DISTINCT e.id) FILTER (WHERE e.id IS NOT NULL AND e.status='open') AS event_count
		 FROM ot_assets a
		 LEFT JOIN ot_vulnerabilities v ON v.asset_id=a.id
		 LEFT JOIN ot_events e ON e.asset_id=a.id
		 WHERE a.tenant_id=$1 AND a.id=$2
		 GROUP BY a.id`,
		tenantID, id,
	).Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType,
		&a.Vendor, &a.Model, &a.FirmwareVersion, &a.SerialNumber,
		&a.IPAddress, &a.MACAddress, &a.Protocol,
		&a.Site, &a.Zone, &a.PurdueLevel, &a.RiskScore, &a.RiskLevel,
		&a.IsInternetFacing, &a.IsPatched, &a.LastPatchedAt, &a.IsActive, &a.Criticality,
		&a.InstallDate, &a.EndOfLifeDate, &a.Tags, &metaRaw,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt,
		&a.VulnCount, &a.EventCount)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *OTRepository) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]model.OTAsset, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Site != "" {
		cond = append(cond, fmt.Sprintf("site=$%d", n))
		args = append(args, f.Site)
		n++
	}
	if f.AssetType != "" {
		cond = append(cond, fmt.Sprintf("asset_type=$%d", n))
		args = append(args, f.AssetType)
		n++
	}
	if f.RiskLevel != "" {
		cond = append(cond, fmt.Sprintf("risk_level=$%d", n))
		args = append(args, f.RiskLevel)
		n++
	}
	if f.PurdueLevel != 0 {
		cond = append(cond, fmt.Sprintf("purdue_level=$%d", n))
		args = append(args, f.PurdueLevel)
		n++
	}
	if f.IsActive != nil {
		cond = append(cond, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *f.IsActive)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ot_assets WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,asset_type,vendor,model,
		        firmware_version,serial_number,ip_address,mac_address,protocol,
		        site,zone,purdue_level,risk_score,risk_level,
		        is_internet_facing,is_patched,last_patched_at,is_active,criticality,
		        install_date,end_of_life_date,tags,metadata,created_by,created_at,updated_at
		 FROM ot_assets WHERE `+where+
			fmt.Sprintf(` ORDER BY risk_score DESC, criticality LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var assets []model.OTAsset
	for rows.Next() {
		var a model.OTAsset
		var metaRaw []byte
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType,
			&a.Vendor, &a.Model, &a.FirmwareVersion, &a.SerialNumber,
			&a.IPAddress, &a.MACAddress, &a.Protocol,
			&a.Site, &a.Zone, &a.PurdueLevel, &a.RiskScore, &a.RiskLevel,
			&a.IsInternetFacing, &a.IsPatched, &a.LastPatchedAt, &a.IsActive, &a.Criticality,
			&a.InstallDate, &a.EndOfLifeDate, &a.Tags, &metaRaw,
			&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(metaRaw, &a.Metadata)
		assets = append(assets, a)
	}
	return assets, total, nil
}

func (r *OTRepository) UpdateAsset(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAssetRequest) (*model.OTAsset, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, *req.Description)
		n++
	}
	if req.FirmwareVersion != nil {
		sets = append(sets, fmt.Sprintf("firmware_version=$%d", n))
		args = append(args, *req.FirmwareVersion)
		n++
	}
	if req.IPAddress != nil {
		sets = append(sets, fmt.Sprintf("ip_address=$%d", n))
		args = append(args, *req.IPAddress)
		n++
	}
	if req.Site != nil {
		sets = append(sets, fmt.Sprintf("site=$%d", n))
		args = append(args, *req.Site)
		n++
	}
	if req.Zone != nil {
		sets = append(sets, fmt.Sprintf("zone=$%d", n))
		args = append(args, *req.Zone)
		n++
	}
	if req.PurdueLevel != nil {
		sets = append(sets, fmt.Sprintf("purdue_level=$%d", n))
		args = append(args, *req.PurdueLevel)
		n++
	}
	if req.RiskScore != nil {
		sets = append(sets, fmt.Sprintf("risk_score=$%d", n))
		args = append(args, *req.RiskScore)
		n++
	}
	if req.RiskLevel != nil {
		sets = append(sets, fmt.Sprintf("risk_level=$%d", n))
		args = append(args, *req.RiskLevel)
		n++
	}
	if req.IsInternetFacing != nil {
		sets = append(sets, fmt.Sprintf("is_internet_facing=$%d", n))
		args = append(args, *req.IsInternetFacing)
		n++
	}
	if req.IsPatched != nil {
		sets = append(sets, fmt.Sprintf("is_patched=$%d", n))
		args = append(args, *req.IsPatched)
		n++
		if *req.IsPatched {
			sets = append(sets, fmt.Sprintf("last_patched_at=$%d", n))
			args = append(args, time.Now().UTC())
			n++
		}
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}
	if req.Criticality != nil {
		sets = append(sets, fmt.Sprintf("criticality=$%d", n))
		args = append(args, *req.Criticality)
		n++
	}
	if req.Protocol != nil {
		sets = append(sets, fmt.Sprintf("protocol=$%d", n))
		args = append(args, req.Protocol)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}
	if req.Metadata != nil {
		meta, _ := json.Marshal(req.Metadata)
		sets = append(sets, fmt.Sprintf("metadata=$%d", n))
		args = append(args, meta)
		n++
	}

	var a model.OTAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE ot_assets SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,asset_type,vendor,model,
		           firmware_version,serial_number,ip_address,mac_address,protocol,
		           site,zone,purdue_level,risk_score,risk_level,
		           is_internet_facing,is_patched,last_patched_at,is_active,criticality,
		           install_date,end_of_life_date,tags,metadata,created_by,created_at,updated_at`,
		args...,
	).Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType,
		&a.Vendor, &a.Model, &a.FirmwareVersion, &a.SerialNumber,
		&a.IPAddress, &a.MACAddress, &a.Protocol,
		&a.Site, &a.Zone, &a.PurdueLevel, &a.RiskScore, &a.RiskLevel,
		&a.IsInternetFacing, &a.IsPatched, &a.LastPatchedAt, &a.IsActive, &a.Criticality,
		&a.InstallDate, &a.EndOfLifeDate, &a.Tags, &metaRaw,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

// ─── Zones ────────────────────────────────────────────────────────────────────

func (r *OTRepository) CreateZone(ctx context.Context, tenantID uuid.UUID, req *model.CreateZoneRequest, createdBy *uuid.UUID) (*model.OTZone, error) {
	ranges := req.NetworkRanges
	if ranges == nil {
		ranges = []string{}
	}
	var z model.OTZone
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_zones
		 (tenant_id,name,description,zone_type,purdue_level,site,
		  is_air_gapped,firewall_present,ids_present,network_ranges,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id,tenant_id,name,description,zone_type,purdue_level,site,
		           is_air_gapped,firewall_present,ids_present,risk_score,asset_count,
		           network_ranges,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.ZoneType, req.PurdueLevel, req.Site,
		req.IsAirGapped, req.FirewallPresent, req.IDSPresent, ranges, createdBy,
	).Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.PurdueLevel, &z.Site,
		&z.IsAirGapped, &z.FirewallPresent, &z.IDSPresent, &z.RiskScore, &z.AssetCount,
		&z.NetworkRanges, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt)
	return &z, err
}

func (r *OTRepository) ListZones(ctx context.Context, tenantID uuid.UUID, site string) ([]model.OTZone, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if site != "" {
		cond = append(cond, fmt.Sprintf("site=$%d", n))
		args = append(args, site)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,zone_type,purdue_level,site,
		        is_air_gapped,firewall_present,ids_present,risk_score,asset_count,
		        network_ranges,created_by,created_at,updated_at
		 FROM ot_zones WHERE `+strings.Join(cond, " AND ")+
			` ORDER BY purdue_level ASC, name`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var zones []model.OTZone
	for rows.Next() {
		var z model.OTZone
		if err := rows.Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.PurdueLevel, &z.Site,
			&z.IsAirGapped, &z.FirewallPresent, &z.IDSPresent, &z.RiskScore, &z.AssetCount,
			&z.NetworkRanges, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt); err != nil {
			return nil, err
		}
		zones = append(zones, z)
	}
	return zones, nil
}

func (r *OTRepository) UpdateZone(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateZoneRequest) (*model.OTZone, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, *req.Description)
		n++
	}
	if req.IsAirGapped != nil {
		sets = append(sets, fmt.Sprintf("is_air_gapped=$%d", n))
		args = append(args, *req.IsAirGapped)
		n++
	}
	if req.FirewallPresent != nil {
		sets = append(sets, fmt.Sprintf("firewall_present=$%d", n))
		args = append(args, *req.FirewallPresent)
		n++
	}
	if req.IDSPresent != nil {
		sets = append(sets, fmt.Sprintf("ids_present=$%d", n))
		args = append(args, *req.IDSPresent)
		n++
	}
	if req.RiskScore != nil {
		sets = append(sets, fmt.Sprintf("risk_score=$%d", n))
		args = append(args, *req.RiskScore)
		n++
	}
	if req.NetworkRanges != nil {
		sets = append(sets, fmt.Sprintf("network_ranges=$%d", n))
		args = append(args, req.NetworkRanges)
		n++
	}

	var z model.OTZone
	err := r.db.QueryRow(ctx,
		`UPDATE ot_zones SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,zone_type,purdue_level,site,
		           is_air_gapped,firewall_present,ids_present,risk_score,asset_count,
		           network_ranges,created_by,created_at,updated_at`,
		args...,
	).Scan(&z.ID, &z.TenantID, &z.Name, &z.Description, &z.ZoneType, &z.PurdueLevel, &z.Site,
		&z.IsAirGapped, &z.FirewallPresent, &z.IDSPresent, &z.RiskScore, &z.AssetCount,
		&z.NetworkRanges, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt)
	return &z, err
}

// ─── Communications ───────────────────────────────────────────────────────────

func (r *OTRepository) CreateCommunication(ctx context.Context, tenantID uuid.UUID, req *model.CreateCommunicationRequest) (*model.OTCommunication, error) {
	dir := req.Direction
	if dir == "" {
		dir = "bidirectional"
	}
	var c model.OTCommunication
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_communications
		 (tenant_id,src_asset_id,dst_asset_id,src_zone_id,dst_zone_id,
		  protocol,port,direction,is_authorized,is_anomalous)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id,tenant_id,src_asset_id,dst_asset_id,src_zone_id,dst_zone_id,
		           protocol,port,direction,is_authorized,is_anomalous,
		           first_seen_at,last_seen_at,packet_count,created_at`,
		tenantID, req.SrcAssetID, req.DstAssetID, req.SrcZoneID, req.DstZoneID,
		req.Protocol, req.Port, dir, req.IsAuthorized, req.IsAnomalous,
	).Scan(&c.ID, &c.TenantID, &c.SrcAssetID, &c.DstAssetID, &c.SrcZoneID, &c.DstZoneID,
		&c.Protocol, &c.Port, &c.Direction, &c.IsAuthorized, &c.IsAnomalous,
		&c.FirstSeenAt, &c.LastSeenAt, &c.PacketCount, &c.CreatedAt)
	return &c, err
}

func (r *OTRepository) ListCommunications(ctx context.Context, tenantID uuid.UUID, anomalousOnly bool) ([]model.OTCommunication, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if anomalousOnly {
		cond = append(cond, fmt.Sprintf("is_anomalous=$%d", n))
		args = append(args, true)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,src_asset_id,dst_asset_id,src_zone_id,dst_zone_id,
		        protocol,port,direction,is_authorized,is_anomalous,
		        first_seen_at,last_seen_at,packet_count,created_at
		 FROM ot_communications WHERE `+strings.Join(cond, " AND ")+
			` ORDER BY last_seen_at DESC LIMIT 200`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var comms []model.OTCommunication
	for rows.Next() {
		var c model.OTCommunication
		if err := rows.Scan(&c.ID, &c.TenantID, &c.SrcAssetID, &c.DstAssetID, &c.SrcZoneID, &c.DstZoneID,
			&c.Protocol, &c.Port, &c.Direction, &c.IsAuthorized, &c.IsAnomalous,
			&c.FirstSeenAt, &c.LastSeenAt, &c.PacketCount, &c.CreatedAt); err != nil {
			return nil, err
		}
		comms = append(comms, c)
	}
	return comms, nil
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

func (r *OTRepository) CreateVulnerability(ctx context.Context, tenantID uuid.UUID, req *model.CreateVulnerabilityRequest) (*model.OTVulnerability, error) {
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	var v model.OTVulnerability
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_vulnerabilities
		 (tenant_id,asset_id,cve_id,ics_cert_id,title,description,severity,cvss_score,
		  affects_availability,affects_safety,potential_impact,
		  patch_available,patch_notes,workaround,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING id,tenant_id,asset_id,cve_id,ics_cert_id,title,description,severity,cvss_score,
		           affects_availability,affects_safety,potential_impact,status,
		           patch_available,patch_notes,workaround,discovered_at,remediated_at,tags,created_at,updated_at`,
		tenantID, req.AssetID, req.CVEID, req.ICSCertID, req.Title, req.Description,
		req.Severity, req.CVSSScore, req.AffectsAvailability, req.AffectsSafety,
		req.PotentialImpact, req.PatchAvailable, req.PatchNotes, req.Workaround, tags,
	).Scan(&v.ID, &v.TenantID, &v.AssetID, &v.CVEID, &v.ICSCertID, &v.Title, &v.Description,
		&v.Severity, &v.CVSSScore, &v.AffectsAvailability, &v.AffectsSafety, &v.PotentialImpact,
		&v.Status, &v.PatchAvailable, &v.PatchNotes, &v.Workaround,
		&v.DiscoveredAt, &v.RemediatedAt, &v.Tags, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return nil, err
	}
	// Update asset risk score
	go r.refreshAssetRisk(context.Background(), tenantID, req.AssetID)
	return &v, nil
}

func (r *OTRepository) ListVulnerabilities(ctx context.Context, tenantID uuid.UUID, f model.ListVulnsFilter) ([]model.OTVulnerability, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AssetID != nil {
		cond = append(cond, fmt.Sprintf("asset_id=$%d", n))
		args = append(args, *f.AssetID)
		n++
	}
	if f.Severity != "" {
		cond = append(cond, fmt.Sprintf("severity=$%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ot_vulnerabilities WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,asset_id,cve_id,ics_cert_id,title,description,severity,cvss_score,
		        affects_availability,affects_safety,potential_impact,status,
		        patch_available,patch_notes,workaround,discovered_at,remediated_at,tags,created_at,updated_at
		 FROM ot_vulnerabilities WHERE `+where+
			fmt.Sprintf(` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, discovered_at DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var vulns []model.OTVulnerability
	for rows.Next() {
		var v model.OTVulnerability
		if err := rows.Scan(&v.ID, &v.TenantID, &v.AssetID, &v.CVEID, &v.ICSCertID, &v.Title, &v.Description,
			&v.Severity, &v.CVSSScore, &v.AffectsAvailability, &v.AffectsSafety, &v.PotentialImpact,
			&v.Status, &v.PatchAvailable, &v.PatchNotes, &v.Workaround,
			&v.DiscoveredAt, &v.RemediatedAt, &v.Tags, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, 0, err
		}
		vulns = append(vulns, v)
	}
	return vulns, total, nil
}

func (r *OTRepository) UpdateVulnerability(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateVulnerabilityRequest) (*model.OTVulnerability, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "patched" || *req.Status == "mitigated" {
			sets = append(sets, fmt.Sprintf("remediated_at=COALESCE(remediated_at,$%d)", n))
			args = append(args, time.Now().UTC())
			n++
		}
	}
	if req.PatchAvailable != nil {
		sets = append(sets, fmt.Sprintf("patch_available=$%d", n))
		args = append(args, *req.PatchAvailable)
		n++
	}
	if req.PatchNotes != nil {
		sets = append(sets, fmt.Sprintf("patch_notes=$%d", n))
		args = append(args, *req.PatchNotes)
		n++
	}
	if req.Workaround != nil {
		sets = append(sets, fmt.Sprintf("workaround=$%d", n))
		args = append(args, *req.Workaround)
		n++
	}

	var v model.OTVulnerability
	err := r.db.QueryRow(ctx,
		`UPDATE ot_vulnerabilities SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,asset_id,cve_id,ics_cert_id,title,description,severity,cvss_score,
		           affects_availability,affects_safety,potential_impact,status,
		           patch_available,patch_notes,workaround,discovered_at,remediated_at,tags,created_at,updated_at`,
		args...,
	).Scan(&v.ID, &v.TenantID, &v.AssetID, &v.CVEID, &v.ICSCertID, &v.Title, &v.Description,
		&v.Severity, &v.CVSSScore, &v.AffectsAvailability, &v.AffectsSafety, &v.PotentialImpact,
		&v.Status, &v.PatchAvailable, &v.PatchNotes, &v.Workaround,
		&v.DiscoveredAt, &v.RemediatedAt, &v.Tags, &v.CreatedAt, &v.UpdatedAt)
	return &v, err
}

// refreshAssetRisk recomputes risk_score/risk_level for an asset based on open vuln count
func (r *OTRepository) refreshAssetRisk(ctx context.Context, tenantID, assetID uuid.UUID) {
	var criticality string
	var isInternetFacing bool
	var purdueLevel int
	var vulnCount int
	_ = r.db.QueryRow(ctx,
		`SELECT criticality, is_internet_facing, purdue_level FROM ot_assets WHERE tenant_id=$1 AND id=$2`,
		tenantID, assetID).Scan(&criticality, &isInternetFacing, &purdueLevel)
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1 AND asset_id=$2 AND status='open'`,
		tenantID, assetID).Scan(&vulnCount)
	score := assetRiskScore(criticality, isInternetFacing, purdueLevel, vulnCount)
	level := riskLevelFromScore(score)
	_, _ = r.db.Exec(ctx,
		`UPDATE ot_assets SET risk_score=$1, risk_level=$2, updated_at=NOW() WHERE tenant_id=$3 AND id=$4`,
		score, level, tenantID, assetID)
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (r *OTRepository) CreateEvent(ctx context.Context, tenantID uuid.UUID, req *model.CreateEventRequest) (*model.OTEvent, error) {
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	eventTime := time.Now().UTC()
	if req.EventTime != nil {
		eventTime = *req.EventTime
	}
	var e model.OTEvent
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_events
		 (tenant_id,asset_id,zone_id,event_type,severity,title,description,
		  source_ip,dest_ip,protocol,raw_payload,detected_by,detection_rule,event_time,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING id,tenant_id,asset_id,zone_id,event_type,severity,status,title,description,
		           source_ip,dest_ip,protocol,raw_payload,detected_by,detection_rule,
		           acknowledged_by,acknowledged_at,resolved_by,resolved_at,
		           event_time,tags,created_at,updated_at`,
		tenantID, req.AssetID, req.ZoneID, req.EventType, req.Severity,
		req.Title, req.Description, req.SourceIP, req.DestIP, req.Protocol,
		req.RawPayload, req.DetectedBy, req.DetectionRule, eventTime, tags,
	).Scan(&e.ID, &e.TenantID, &e.AssetID, &e.ZoneID, &e.EventType, &e.Severity, &e.Status,
		&e.Title, &e.Description, &e.SourceIP, &e.DestIP, &e.Protocol, &e.RawPayload,
		&e.DetectedBy, &e.DetectionRule, &e.AcknowledgedBy, &e.AcknowledgedAt,
		&e.ResolvedBy, &e.ResolvedAt, &e.EventTime, &e.Tags, &e.CreatedAt, &e.UpdatedAt)
	return &e, err
}

func (r *OTRepository) ListEvents(ctx context.Context, tenantID uuid.UUID, f model.ListEventsFilter) ([]model.OTEvent, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AssetID != nil {
		cond = append(cond, fmt.Sprintf("asset_id=$%d", n))
		args = append(args, *f.AssetID)
		n++
	}
	if f.EventType != "" {
		cond = append(cond, fmt.Sprintf("event_type=$%d", n))
		args = append(args, f.EventType)
		n++
	}
	if f.Severity != "" {
		cond = append(cond, fmt.Sprintf("severity=$%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ot_events WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,asset_id,zone_id,event_type,severity,status,title,description,
		        source_ip,dest_ip,protocol,raw_payload,detected_by,detection_rule,
		        acknowledged_by,acknowledged_at,resolved_by,resolved_at,
		        event_time,tags,created_at,updated_at
		 FROM ot_events WHERE `+where+
			fmt.Sprintf(` ORDER BY event_time DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var events []model.OTEvent
	for rows.Next() {
		var e model.OTEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AssetID, &e.ZoneID, &e.EventType, &e.Severity, &e.Status,
			&e.Title, &e.Description, &e.SourceIP, &e.DestIP, &e.Protocol, &e.RawPayload,
			&e.DetectedBy, &e.DetectionRule, &e.AcknowledgedBy, &e.AcknowledgedAt,
			&e.ResolvedBy, &e.ResolvedAt, &e.EventTime, &e.Tags, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, nil
}

func (r *OTRepository) UpdateEvent(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateEventRequest) (*model.OTEvent, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3
	now := time.Now().UTC()

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
	}
	if req.AcknowledgedBy != nil {
		sets = append(sets, fmt.Sprintf("acknowledged_by=$%d", n))
		args = append(args, *req.AcknowledgedBy)
		n++
		sets = append(sets, fmt.Sprintf("acknowledged_at=COALESCE(acknowledged_at,$%d)", n))
		args = append(args, now)
		n++
	}
	if req.ResolvedBy != nil {
		sets = append(sets, fmt.Sprintf("resolved_by=$%d", n))
		args = append(args, *req.ResolvedBy)
		n++
		sets = append(sets, fmt.Sprintf("resolved_at=COALESCE(resolved_at,$%d)", n))
		args = append(args, now)
		n++
	}

	var e model.OTEvent
	err := r.db.QueryRow(ctx,
		`UPDATE ot_events SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,asset_id,zone_id,event_type,severity,status,title,description,
		           source_ip,dest_ip,protocol,raw_payload,detected_by,detection_rule,
		           acknowledged_by,acknowledged_at,resolved_by,resolved_at,
		           event_time,tags,created_at,updated_at`,
		args...,
	).Scan(&e.ID, &e.TenantID, &e.AssetID, &e.ZoneID, &e.EventType, &e.Severity, &e.Status,
		&e.Title, &e.Description, &e.SourceIP, &e.DestIP, &e.Protocol, &e.RawPayload,
		&e.DetectedBy, &e.DetectionRule, &e.AcknowledgedBy, &e.AcknowledgedAt,
		&e.ResolvedBy, &e.ResolvedAt, &e.EventTime, &e.Tags, &e.CreatedAt, &e.UpdatedAt)
	return &e, err
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *OTRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.OTPolicy, error) {
	rule, _ := json.Marshal(req.Rule)
	scope := req.Scope
	if scope == "" {
		scope = "global"
	}
	action := req.Action
	if action == "" {
		action = "alert"
	}
	var p model.OTPolicy
	var ruleRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_policies
		 (tenant_id,name,description,policy_type,scope,scope_ref,rule,action,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING id,tenant_id,name,description,policy_type,scope,scope_ref,rule,action,is_active,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.PolicyType, scope, req.ScopeRef, rule, action, createdBy,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&p.Scope, &p.ScopeRef, &ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ruleRaw, &p.Rule)
	return &p, nil
}

func (r *OTRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string) ([]model.OTPolicy, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if policyType != "" {
		cond = append(cond, fmt.Sprintf("policy_type=$%d", n))
		args = append(args, policyType)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,policy_type,scope,scope_ref,rule,action,is_active,created_by,created_at,updated_at
		 FROM ot_policies WHERE `+strings.Join(cond, " AND ")+` ORDER BY policy_type,name`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []model.OTPolicy
	for rows.Next() {
		var p model.OTPolicy
		var ruleRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
			&p.Scope, &p.ScopeRef, &ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ruleRaw, &p.Rule)
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *OTRepository) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePolicyRequest) (*model.OTPolicy, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, *req.Description)
		n++
	}
	if req.Rule != nil {
		rule, _ := json.Marshal(req.Rule)
		sets = append(sets, fmt.Sprintf("rule=$%d", n))
		args = append(args, rule)
		n++
	}
	if req.Action != nil {
		sets = append(sets, fmt.Sprintf("action=$%d", n))
		args = append(args, *req.Action)
		n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}

	var p model.OTPolicy
	var ruleRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE ot_policies SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,policy_type,scope,scope_ref,rule,action,is_active,created_by,created_at,updated_at`,
		args...,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&p.Scope, &p.ScopeRef, &ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ruleRaw, &p.Rule)
	return &p, nil
}

// ─── Patches ──────────────────────────────────────────────────────────────────

func (r *OTRepository) CreatePatch(ctx context.Context, tenantID uuid.UUID, req *model.CreatePatchRequest, createdBy *uuid.UUID) (*model.OTPatch, error) {
	cveIDs := req.CVEIDs
	if cveIDs == nil {
		cveIDs = []string{}
	}
	patchType := req.PatchType
	if patchType == "" {
		patchType = "firmware"
	}
	riskLevel := req.RiskLevel
	if riskLevel == "" {
		riskLevel = "medium"
	}
	var p model.OTPatch
	err := r.db.QueryRow(ctx,
		`INSERT INTO ot_patches
		 (tenant_id,asset_id,patch_type,title,description,version_before,version_after,
		  cve_ids,risk_level,requires_downtime,scheduled_at,maintenance_window,rollback_plan,notes,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING id,tenant_id,asset_id,patch_type,title,description,version_before,version_after,
		           cve_ids,status,risk_level,requires_downtime,scheduled_at,maintenance_window,
		           applied_at,applied_by,rollback_plan,notes,created_by,created_at,updated_at`,
		tenantID, req.AssetID, patchType, req.Title, req.Description,
		req.VersionBefore, req.VersionAfter, cveIDs, riskLevel,
		req.RequiresDowntime, req.ScheduledAt, req.MaintenanceWindow,
		req.RollbackPlan, req.Notes, createdBy,
	).Scan(&p.ID, &p.TenantID, &p.AssetID, &p.PatchType, &p.Title, &p.Description,
		&p.VersionBefore, &p.VersionAfter, &p.CVEIDs, &p.Status, &p.RiskLevel,
		&p.RequiresDowntime, &p.ScheduledAt, &p.MaintenanceWindow,
		&p.AppliedAt, &p.AppliedBy, &p.RollbackPlan, &p.Notes, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return &p, err
}

func (r *OTRepository) ListPatches(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, status string) ([]model.OTPatch, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if assetID != nil {
		cond = append(cond, fmt.Sprintf("asset_id=$%d", n))
		args = append(args, *assetID)
		n++
	}
	if status != "" {
		cond = append(cond, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,asset_id,patch_type,title,description,version_before,version_after,
		        cve_ids,status,risk_level,requires_downtime,scheduled_at,maintenance_window,
		        applied_at,applied_by,rollback_plan,notes,created_by,created_at,updated_at
		 FROM ot_patches WHERE `+strings.Join(cond, " AND ")+
			` ORDER BY scheduled_at ASC NULLS LAST, created_at DESC`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var patches []model.OTPatch
	for rows.Next() {
		var p model.OTPatch
		if err := rows.Scan(&p.ID, &p.TenantID, &p.AssetID, &p.PatchType, &p.Title, &p.Description,
			&p.VersionBefore, &p.VersionAfter, &p.CVEIDs, &p.Status, &p.RiskLevel,
			&p.RequiresDowntime, &p.ScheduledAt, &p.MaintenanceWindow,
			&p.AppliedAt, &p.AppliedBy, &p.RollbackPlan, &p.Notes, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		patches = append(patches, p)
	}
	return patches, nil
}

func (r *OTRepository) UpdatePatch(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePatchRequest) (*model.OTPatch, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "applied" {
			sets = append(sets, fmt.Sprintf("applied_at=COALESCE(applied_at,$%d)", n))
			args = append(args, time.Now().UTC())
			n++
		}
	}
	if req.AppliedBy != nil {
		sets = append(sets, fmt.Sprintf("applied_by=$%d", n))
		args = append(args, *req.AppliedBy)
		n++
	}
	if req.AppliedAt != nil {
		sets = append(sets, fmt.Sprintf("applied_at=$%d", n))
		args = append(args, *req.AppliedAt)
		n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n))
		args = append(args, *req.Notes)
		n++
	}

	var p model.OTPatch
	err := r.db.QueryRow(ctx,
		`UPDATE ot_patches SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,asset_id,patch_type,title,description,version_before,version_after,
		           cve_ids,status,risk_level,requires_downtime,scheduled_at,maintenance_window,
		           applied_at,applied_by,rollback_plan,notes,created_by,created_at,updated_at`,
		args...,
	).Scan(&p.ID, &p.TenantID, &p.AssetID, &p.PatchType, &p.Title, &p.Description,
		&p.VersionBefore, &p.VersionAfter, &p.CVEIDs, &p.Status, &p.RiskLevel,
		&p.RequiresDowntime, &p.ScheduledAt, &p.MaintenanceWindow,
		&p.AppliedAt, &p.AppliedBy, &p.RollbackPlan, &p.Notes, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	return &p, err
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *OTRepository) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.OTStats, error) {
	stats := &model.OTStats{
		AssetsByType:     make(map[string]int),
		AssetsByPurdue:   make(map[string]int),
		EventsBySeverity: make(map[string]int),
		VulnsBySeverity:  make(map[string]int),
	}

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE is_active),
		        COUNT(*) FILTER (WHERE criticality='critical' AND is_active),
		        COUNT(*) FILTER (WHERE is_internet_facing AND is_active),
		        COUNT(*) FILTER (WHERE is_patched=false AND is_active)
		 FROM ot_assets WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalAssets, &stats.ActiveAssets, &stats.CriticalAssets,
		&stats.InternetFacingAssets, &stats.UnpatchedAssets)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ot_zones WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalZones)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE severity='critical' AND status='open'),
		        COUNT(*) FILTER (WHERE affects_safety AND status='open')
		 FROM ot_vulnerabilities WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalVulnerabilities, &stats.CriticalVulns, &stats.SafetyImpactVulns)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE severity='critical')
		 FROM ot_events WHERE tenant_id=$1 AND status='open'`, tenantID,
	).Scan(&stats.OpenEvents, &stats.CriticalEvents)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ot_communications WHERE tenant_id=$1 AND is_anomalous=true`, tenantID,
	).Scan(&stats.AnomalousCommunications)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ot_patches WHERE tenant_id=$1 AND status IN ('pending','approved','scheduled')`, tenantID,
	).Scan(&stats.PendingPatches)

	// Assets by type
	rows, _ := r.db.Query(ctx,
		`SELECT asset_type, COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND is_active=true GROUP BY asset_type`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.AssetsByType[k] = v
		}
	}

	// Assets by Purdue level
	rows2, _ := r.db.Query(ctx,
		`SELECT purdue_level::text, COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND is_active=true GROUP BY purdue_level`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var k string
			var v int
			_ = rows2.Scan(&k, &v)
			stats.AssetsByPurdue["level_"+k] = v
		}
	}

	// Events by severity
	rows3, _ := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM ot_events WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var k string
			var v int
			_ = rows3.Scan(&k, &v)
			stats.EventsBySeverity[k] = v
		}
	}

	// Vulns by severity
	rows4, _ := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if rows4 != nil {
		defer rows4.Close()
		for rows4.Next() {
			var k string
			var v int
			_ = rows4.Scan(&k, &v)
			stats.VulnsBySeverity[k] = v
		}
	}

	// Top risky assets
	rrows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,asset_type,vendor,model,
		        firmware_version,serial_number,ip_address,mac_address,protocol,
		        site,zone,purdue_level,risk_score,risk_level,
		        is_internet_facing,is_patched,last_patched_at,is_active,criticality,
		        install_date,end_of_life_date,tags,metadata,created_by,created_at,updated_at
		 FROM ot_assets WHERE tenant_id=$1 AND is_active=true
		 ORDER BY risk_score DESC LIMIT 5`, tenantID)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var a model.OTAsset
			var metaRaw []byte
			if err := rrows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType,
				&a.Vendor, &a.Model, &a.FirmwareVersion, &a.SerialNumber,
				&a.IPAddress, &a.MACAddress, &a.Protocol,
				&a.Site, &a.Zone, &a.PurdueLevel, &a.RiskScore, &a.RiskLevel,
				&a.IsInternetFacing, &a.IsPatched, &a.LastPatchedAt, &a.IsActive, &a.Criticality,
				&a.InstallDate, &a.EndOfLifeDate, &a.Tags, &metaRaw,
				&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err == nil {
				_ = json.Unmarshal(metaRaw, &a.Metadata)
				stats.TopRiskyAssets = append(stats.TopRiskyAssets, a)
			}
		}
	}

	// Recent critical events
	erows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,asset_id,zone_id,event_type,severity,status,title,description,
		        source_ip,dest_ip,protocol,raw_payload,detected_by,detection_rule,
		        acknowledged_by,acknowledged_at,resolved_by,resolved_at,
		        event_time,tags,created_at,updated_at
		 FROM ot_events WHERE tenant_id=$1 AND status='open'
		 ORDER BY event_time DESC LIMIT 5`, tenantID)
	if erows != nil {
		defer erows.Close()
		for erows.Next() {
			var e model.OTEvent
			if err := erows.Scan(&e.ID, &e.TenantID, &e.AssetID, &e.ZoneID, &e.EventType, &e.Severity, &e.Status,
				&e.Title, &e.Description, &e.SourceIP, &e.DestIP, &e.Protocol, &e.RawPayload,
				&e.DetectedBy, &e.DetectionRule, &e.AcknowledgedBy, &e.AcknowledgedAt,
				&e.ResolvedBy, &e.ResolvedAt, &e.EventTime, &e.Tags, &e.CreatedAt, &e.UpdatedAt); err == nil {
				stats.RecentEvents = append(stats.RecentEvents, e)
			}
		}
	}

	return stats, nil
}
