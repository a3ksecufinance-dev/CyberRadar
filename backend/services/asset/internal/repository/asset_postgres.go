package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/asset/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AssetRepository handles all asset DB operations.
type AssetRepository struct {
	db *pgxpool.Pool
}

// NewAssetRepository creates an AssetRepository.
func NewAssetRepository(db *pgxpool.Pool) *AssetRepository {
	return &AssetRepository{db: db}
}

// Create inserts a new asset and returns it with server-assigned fields.
func (r *AssetRepository) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.Asset, error) {
	id := uuid.New()
	env := req.Environment
	if env == "" {
		env = "production"
	}
	tags := req.IPAddresses
	if req.Tags != nil {
		tags = req.Tags
	}

	const q = `
		INSERT INTO assets (
			id, tenant_id, name, hostname, fqdn,
			ip_addresses, mac_addresses,
			asset_type, os, os_version,
			criticality, environment,
			owner_id, department, location, business_service,
			is_cbs_connected, is_swift_connected, is_pci_scope,
			tags, metadata, discovered_by
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
		)
		RETURNING id, created_at, updated_at, first_seen_at`

	row := r.db.QueryRow(ctx, q,
		id, tenantID, req.Name, nvlStr(req.Hostname), nvlStr(req.FQDN),
		req.IPAddresses, req.MACAddresses,
		req.AssetType, nvlStr(req.OS), nvlStr(req.OSVersion),
		req.Criticality, env,
		req.OwnerID, nvlStr(req.Department), nvlStr(req.Location), nvlStr(req.BusinessService),
		req.IsCBSConnected, req.IsSWIFTConnected, req.IsPCIScope,
		tags, req.Metadata, "manual",
	)

	var createdAt, updatedAt, firstSeen time.Time
	if err := row.Scan(&id, &createdAt, &updatedAt, &firstSeen); err != nil {
		return nil, fmt.Errorf("asset create: %w", err)
	}

	return r.GetByID(ctx, tenantID, id)
}

// GetByID fetches a single asset by ID, enforcing tenant isolation.
func (r *AssetRepository) GetByID(ctx context.Context, tenantID, assetID uuid.UUID) (*model.Asset, error) {
	const q = `
		SELECT id, tenant_id, name, hostname, fqdn,
		       ip_addresses, mac_addresses,
		       asset_type, os, os_version,
		       criticality, status, environment,
		       owner_id, department, location, business_service,
		       is_cbs_connected, is_swift_connected, is_pci_scope,
		       risk_score, vuln_critical, vuln_high, vuln_medium, vuln_low,
		       tags, metadata, discovered_by,
		       last_seen_at, first_seen_at, created_at, updated_at
		FROM assets
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	row := r.db.QueryRow(ctx, q, assetID, tenantID)
	a, err := scanAsset(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// List returns a paginated, filtered list of assets.
func (r *AssetRepository) List(ctx context.Context, f model.AssetFilter) (*model.AssetList, error) {
	where := []string{"tenant_id = $1", "deleted_at IS NULL"}
	args := []any{f.TenantID}
	n := 2

	if f.AssetType != "" {
		where = append(where, fmt.Sprintf("asset_type = $%d", n))
		args = append(args, f.AssetType)
		n++
	}
	if f.Criticality > 0 {
		where = append(where, fmt.Sprintf("criticality = $%d", n))
		args = append(args, f.Criticality)
		n++
	}
	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Environment != "" {
		where = append(where, fmt.Sprintf("environment = $%d", n))
		args = append(args, f.Environment)
		n++
	}
	if f.BusinessService != "" {
		where = append(where, fmt.Sprintf("business_service = $%d", n))
		args = append(args, f.BusinessService)
		n++
	}
	if f.Tag != "" {
		where = append(where, fmt.Sprintf("$%d = ANY(tags)", n))
		args = append(args, f.Tag)
		n++
	}
	if f.IsCBSConnected != nil {
		where = append(where, fmt.Sprintf("is_cbs_connected = $%d", n))
		args = append(args, *f.IsCBSConnected)
		n++
	}
	if f.IsPCIScope != nil {
		where = append(where, fmt.Sprintf("is_pci_scope = $%d", n))
		args = append(args, *f.IsPCIScope)
		n++
	}
	if f.Search != "" {
		where = append(where, fmt.Sprintf(
			"(name ILIKE $%d OR hostname ILIKE $%d OR $%d = ANY(ip_addresses))",
			n, n+1, n+2))
		pat := "%" + f.Search + "%"
		args = append(args, pat, pat, f.Search)
		n += 3
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset

	whereClause := strings.Join(where, " AND ")

	// Count query
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM assets WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("asset list count: %w", err)
	}

	// Data query
	dataQ := fmt.Sprintf(`
		SELECT id, tenant_id, name, hostname, fqdn,
		       ip_addresses, mac_addresses,
		       asset_type, os, os_version,
		       criticality, status, environment,
		       owner_id, department, location, business_service,
		       is_cbs_connected, is_swift_connected, is_pci_scope,
		       risk_score, vuln_critical, vuln_high, vuln_medium, vuln_low,
		       tags, metadata, discovered_by,
		       last_seen_at, first_seen_at, created_at, updated_at
		FROM assets WHERE %s
		ORDER BY risk_score DESC, criticality DESC, created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, n, n+1)
	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, fmt.Errorf("asset list: %w", err)
	}
	defer rows.Close()

	assets := make([]*model.Asset, 0)
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}

	return &model.AssetList{
		Assets: assets,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// Update applies a partial update to an asset.
func (r *AssetRepository) Update(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.Asset, error) {
	sets := []string{}
	args := []any{}
	n := 1

	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}

	if req.Name != nil {
		set("name", *req.Name)
	}
	if req.Hostname != nil {
		set("hostname", *req.Hostname)
	}
	if req.FQDN != nil {
		set("fqdn", *req.FQDN)
	}
	if req.IPAddresses != nil {
		set("ip_addresses", req.IPAddresses)
	}
	if req.OS != nil {
		set("os", *req.OS)
	}
	if req.OSVersion != nil {
		set("os_version", *req.OSVersion)
	}
	if req.Criticality != nil {
		set("criticality", *req.Criticality)
	}
	if req.Status != nil {
		set("status", *req.Status)
	}
	if req.Environment != nil {
		set("environment", *req.Environment)
	}
	if req.OwnerID != nil {
		set("owner_id", *req.OwnerID)
	}
	if req.Department != nil {
		set("department", *req.Department)
	}
	if req.Location != nil {
		set("location", *req.Location)
	}
	if req.BusinessService != nil {
		set("business_service", *req.BusinessService)
	}
	if req.IsCBSConnected != nil {
		set("is_cbs_connected", *req.IsCBSConnected)
	}
	if req.IsSWIFTConnected != nil {
		set("is_swift_connected", *req.IsSWIFTConnected)
	}
	if req.IsPCIScope != nil {
		set("is_pci_scope", *req.IsPCIScope)
	}
	if req.Tags != nil {
		set("tags", req.Tags)
	}
	if req.Metadata != nil {
		set("metadata", req.Metadata)
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, tenantID, assetID)
	}

	q := fmt.Sprintf(`UPDATE assets SET %s WHERE id = $%d AND tenant_id = $%d AND deleted_at IS NULL`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, assetID, tenantID)

	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("asset update: %w", err)
	}
	return r.GetByID(ctx, tenantID, assetID)
}

// SoftDelete marks an asset as deleted.
func (r *AssetRepository) SoftDelete(ctx context.Context, tenantID, assetID uuid.UUID) error {
	const q = `UPDATE assets SET deleted_at = NOW() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`
	tag, err := r.db.Exec(ctx, q, assetID, tenantID)
	if err != nil {
		return fmt.Errorf("asset delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// UpdateRiskScore refreshes the computed risk score of an asset.
func (r *AssetRepository) UpdateRiskScore(ctx context.Context, tenantID, assetID uuid.UUID, score float64) error {
	const q = `UPDATE assets SET risk_score = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.db.Exec(ctx, q, score, assetID, tenantID)
	return err
}

// UpdateLastSeen touches the last_seen_at timestamp.
func (r *AssetRepository) UpdateLastSeen(ctx context.Context, tenantID uuid.UUID, ip string) error {
	const q = `
		UPDATE assets SET last_seen_at = NOW()
		WHERE tenant_id = $1 AND $2 = ANY(ip_addresses) AND deleted_at IS NULL`
	_, err := r.db.Exec(ctx, q, tenantID, ip)
	return err
}

// UpsertDiscoveryCandidate records or increments a discovery candidate.
func (r *AssetRepository) UpsertDiscoveryCandidate(ctx context.Context, tenantID uuid.UUID, ip, hostname, sourceType, connectorID string) error {
	const q = `
		INSERT INTO asset_discovery_queue
			(id, tenant_id, hostname, ip_address, source_type, connector_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, ip_address) DO UPDATE
			SET event_count  = asset_discovery_queue.event_count + 1,
			    last_seen_at = NOW(),
			    hostname     = COALESCE(EXCLUDED.hostname, asset_discovery_queue.hostname)`
	_, err := r.db.Exec(ctx, q, uuid.New(), tenantID, nvlStr(hostname), ip, sourceType, connectorID)
	return err
}

// ListDiscoveryCandidates returns unresolved candidates.
func (r *AssetRepository) ListDiscoveryCandidates(ctx context.Context, tenantID uuid.UUID, limit int) ([]*model.DiscoveryCandidate, error) {
	const q = `
		SELECT id, tenant_id, hostname, ip_address, source_type, connector_id,
		       event_count, first_seen_at, last_seen_at
		FROM asset_discovery_queue
		WHERE tenant_id = $1 AND resolved = false
		ORDER BY event_count DESC, last_seen_at DESC
		LIMIT $2`

	rows, err := r.db.Query(ctx, q, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.DiscoveryCandidate
	for rows.Next() {
		c := &model.DiscoveryCandidate{}
		var hostname *string
		if err := rows.Scan(&c.ID, &c.TenantID, &hostname, &c.IPAddress,
			&c.SourceType, &c.ConnectorID, &c.EventCount, &c.FirstSeenAt, &c.LastSeenAt); err != nil {
			return nil, err
		}
		if hostname != nil {
			c.Hostname = *hostname
		}
		out = append(out, c)
	}
	return out, nil
}

// Stats returns aggregated statistics for a tenant.
func (r *AssetRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.AssetStats, error) {
	stats := &model.AssetStats{
		ByType:        make(map[string]int),
		ByCriticality: make(map[string]int),
		ByStatus:      make(map[string]int),
	}

	// Total + risk/flag counts
	const q1 = `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE risk_score >= 7),
		       COUNT(*) FILTER (WHERE is_cbs_connected),
		       COUNT(*) FILTER (WHERE is_swift_connected),
		       COUNT(*) FILTER (WHERE is_pci_scope),
		       COUNT(*) FILTER (WHERE last_seen_at IS NULL),
		       COUNT(*) FILTER (WHERE last_seen_at < NOW() - INTERVAL '30 days')
		FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`

	if err := r.db.QueryRow(ctx, q1, tenantID).Scan(
		&stats.Total, &stats.HighRisk, &stats.CBSConnected,
		&stats.SWIFTConnected, &stats.PCIScope, &stats.NeverSeen, &stats.Stale,
	); err != nil {
		return nil, err
	}

	// By type
	rows, err := r.db.Query(ctx,
		`SELECT asset_type, COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL GROUP BY asset_type`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var c int
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		stats.ByType[t] = c
	}

	// By criticality
	rows2, err := r.db.Query(ctx,
		`SELECT criticality, COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL GROUP BY criticality ORDER BY criticality`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	critMap := map[int]string{1: "low", 2: "medium", 3: "high", 4: "critical"}
	for rows2.Next() {
		var c, cnt int
		if err := rows2.Scan(&c, &cnt); err != nil {
			return nil, err
		}
		stats.ByCriticality[critMap[c]] = cnt
	}

	// By status
	rows3, err := r.db.Query(ctx,
		`SELECT status, COUNT(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL GROUP BY status`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var s string
		var cnt int
		if err := rows3.Scan(&s, &cnt); err != nil {
			return nil, err
		}
		stats.ByStatus[s] = cnt
	}

	// Discovery queue count
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM asset_discovery_queue WHERE tenant_id = $1 AND resolved = false`, tenantID,
	).Scan(&stats.DiscoveryQueue); err != nil {
		return nil, err
	}

	return stats, nil
}

// CreateRelationship links two assets.
func (r *AssetRepository) CreateRelationship(ctx context.Context, tenantID, sourceID uuid.UUID, req *model.CreateRelationshipRequest) (*model.AssetRelationship, error) {
	id := uuid.New()
	const q = `
		INSERT INTO asset_relationships (id, tenant_id, source_id, target_id, relationship_type, bidirectional, properties)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, source_id, target_id, relationship_type) DO UPDATE
			SET properties = EXCLUDED.properties
		RETURNING id, created_at`

	rel := &model.AssetRelationship{
		ID:               id,
		TenantID:         tenantID,
		SourceID:         sourceID,
		TargetID:         req.TargetID,
		RelationshipType: req.RelationshipType,
		Bidirectional:    req.Bidirectional,
		Properties:       req.Properties,
	}
	if err := r.db.QueryRow(ctx, q, id, tenantID, sourceID, req.TargetID,
		req.RelationshipType, req.Bidirectional, req.Properties,
	).Scan(&rel.ID, &rel.CreatedAt); err != nil {
		return nil, fmt.Errorf("create relationship: %w", err)
	}
	return rel, nil
}

// GetRelationships returns all edges for an asset (as source or target).
func (r *AssetRepository) GetRelationships(ctx context.Context, tenantID, assetID uuid.UUID) ([]*model.AssetRelationship, error) {
	const q = `
		SELECT id, tenant_id, source_id, target_id, relationship_type, bidirectional, properties, created_at
		FROM asset_relationships
		WHERE tenant_id = $1 AND (source_id = $2 OR target_id = $2)
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.AssetRelationship
	for rows.Next() {
		rel := &model.AssetRelationship{}
		if err := rows.Scan(&rel.ID, &rel.TenantID, &rel.SourceID, &rel.TargetID,
			&rel.RelationshipType, &rel.Bidirectional, &rel.Properties, &rel.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

// ─── Scanner helpers ──────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanAsset(row scannable) (*model.Asset, error) {
	a := &model.Asset{}
	var (
		hostname, fqdn, os, osVer       *string
		dept, loc, bizSvc, discoveredBy *string
		ownerID                         *uuid.UUID
		lastSeen                        *time.Time
		metadata                        map[string]any
	)
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &hostname, &fqdn,
		&a.IPAddresses, &a.MACAddresses,
		&a.AssetType, &os, &osVer,
		&a.Criticality, &a.Status, &a.Environment,
		&ownerID, &dept, &loc, &bizSvc,
		&a.IsCBSConnected, &a.IsSWIFTConnected, &a.IsPCIScope,
		&a.RiskScore, &a.VulnCritical, &a.VulnHigh, &a.VulnMedium, &a.VulnLow,
		&a.Tags, &metadata, &discoveredBy,
		&lastSeen, &a.FirstSeenAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan asset: %w", err)
	}

	derefStr(hostname, &a.Hostname)
	derefStr(fqdn, &a.FQDN)
	derefStr(os, &a.OS)
	derefStr(osVer, &a.OSVersion)
	derefStr(dept, &a.Department)
	derefStr(loc, &a.Location)
	derefStr(bizSvc, &a.BusinessService)
	derefStr(discoveredBy, &a.DiscoveredBy)
	a.OwnerID = ownerID
	a.LastSeenAt = lastSeen
	a.Metadata = metadata
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, nil
}

func derefStr(p *string, dst *string) {
	if p != nil {
		*dst = *p
	}
}

func nvlStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
