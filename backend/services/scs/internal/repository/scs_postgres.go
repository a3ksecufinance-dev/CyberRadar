package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/scs/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SCSRepository struct {
	db *pgxpool.Pool
}

func NewSCSRepository(pool *pgxpool.Pool) *SCSRepository {
	return &SCSRepository{db: pool}
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

func riskLevelFromTier(tier int) string {
	switch tier {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	default:
		return "low"
	}
}

func componentRiskScore(critVulns, highVulns, medVulns int, isEOL, isDeprecated bool) int {
	score := critVulns*25 + highVulns*12 + medVulns*5
	if isEOL {
		score += 20
	}
	if isDeprecated {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

func sbomRiskScore(critVulns, highVulns, eolCount, totalComponents int) int {
	if totalComponents == 0 {
		return 0
	}
	base := critVulns*30 + highVulns*15 + eolCount*5
	if base > 100 {
		base = 100
	}
	return base
}

// ─── Vendors ──────────────────────────────────────────────────────────────────

func (r *SCSRepository) CreateVendor(ctx context.Context, tenantID uuid.UUID, req *model.CreateVendorRequest, createdBy *uuid.UUID) (*model.SCSVendor, error) {
	tier := req.RiskTier
	if tier == 0 {
		tier = 2
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	riskLevel := riskLevelFromTier(tier)
	var v model.SCSVendor
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_vendors
		 (tenant_id,name,website,vendor_type,risk_tier,risk_level,
		  contact_name,contact_email,contact_phone,
		  has_soc2,has_iso27001,has_pci_dss,next_assessment_at,
		  tags,notes,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		 RETURNING id,tenant_id,name,website,vendor_type,risk_tier,risk_score,risk_level,
		           contact_name,contact_email,contact_phone,
		           has_soc2,has_iso27001,has_pci_dss,last_assessment_at,next_assessment_at,
		           status,tags,notes,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Website, req.VendorType, tier, riskLevel,
		req.ContactName, req.ContactEmail, req.ContactPhone,
		req.HasSOC2, req.HasISO27001, req.HasPCIDSS, req.NextAssessmentAt,
		tags, req.Notes, createdBy,
	).Scan(&v.ID, &v.TenantID, &v.Name, &v.Website, &v.VendorType, &v.RiskTier, &v.RiskScore, &v.RiskLevel,
		&v.ContactName, &v.ContactEmail, &v.ContactPhone,
		&v.HasSOC2, &v.HasISO27001, &v.HasPCIDSS, &v.LastAssessmentAt, &v.NextAssessmentAt,
		&v.Status, &v.Tags, &v.Notes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return &v, err
}

func (r *SCSRepository) GetVendor(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSVendor, error) {
	var v model.SCSVendor
	err := r.db.QueryRow(ctx,
		`SELECT v.id,v.tenant_id,v.name,v.website,v.vendor_type,v.risk_tier,v.risk_score,v.risk_level,
		        v.contact_name,v.contact_email,v.contact_phone,
		        v.has_soc2,v.has_iso27001,v.has_pci_dss,v.last_assessment_at,v.next_assessment_at,
		        v.status,v.tags,v.notes,v.created_by,v.created_at,v.updated_at,
		        COUNT(DISTINCT c.id) FILTER (WHERE c.id IS NOT NULL) AS component_count,
		        COUNT(DISTINCT a.id) FILTER (WHERE a.id IS NOT NULL) AS assessment_count,
		        COUNT(DISTINCT al.id) FILTER (WHERE al.id IS NOT NULL AND al.status='open') AS open_alert_count
		 FROM scs_vendors v
		 LEFT JOIN scs_components c ON c.vendor_id=v.id
		 LEFT JOIN scs_assessments a ON a.vendor_id=v.id
		 LEFT JOIN scs_alerts al ON al.vendor_id=v.id
		 WHERE v.tenant_id=$1 AND v.id=$2
		 GROUP BY v.id`,
		tenantID, id,
	).Scan(&v.ID, &v.TenantID, &v.Name, &v.Website, &v.VendorType, &v.RiskTier, &v.RiskScore, &v.RiskLevel,
		&v.ContactName, &v.ContactEmail, &v.ContactPhone,
		&v.HasSOC2, &v.HasISO27001, &v.HasPCIDSS, &v.LastAssessmentAt, &v.NextAssessmentAt,
		&v.Status, &v.Tags, &v.Notes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
		&v.ComponentCount, &v.AssessmentCount, &v.OpenAlertCount)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &v, err
}

func (r *SCSRepository) ListVendors(ctx context.Context, tenantID uuid.UUID, f model.ListVendorsFilter) ([]model.SCSVendor, int, error) {
	cond := []string{"v.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("v.status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.RiskTier != 0 {
		cond = append(cond, fmt.Sprintf("v.risk_tier=$%d", n))
		args = append(args, f.RiskTier)
		n++
	}
	if f.RiskLevel != "" {
		cond = append(cond, fmt.Sprintf("v.risk_level=$%d", n))
		args = append(args, f.RiskLevel)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scs_vendors v WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT v.id,v.tenant_id,v.name,v.website,v.vendor_type,v.risk_tier,v.risk_score,v.risk_level,
		        v.contact_name,v.contact_email,v.contact_phone,
		        v.has_soc2,v.has_iso27001,v.has_pci_dss,v.last_assessment_at,v.next_assessment_at,
		        v.status,v.tags,v.notes,v.created_by,v.created_at,v.updated_at,
		        0::bigint, 0::bigint, 0::bigint
		 FROM scs_vendors v WHERE `+where+
			fmt.Sprintf(` ORDER BY v.risk_tier ASC, v.risk_score DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var vendors []model.SCSVendor
	for rows.Next() {
		var v model.SCSVendor
		if err := rows.Scan(&v.ID, &v.TenantID, &v.Name, &v.Website, &v.VendorType, &v.RiskTier, &v.RiskScore, &v.RiskLevel,
			&v.ContactName, &v.ContactEmail, &v.ContactPhone,
			&v.HasSOC2, &v.HasISO27001, &v.HasPCIDSS, &v.LastAssessmentAt, &v.NextAssessmentAt,
			&v.Status, &v.Tags, &v.Notes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
			&v.ComponentCount, &v.AssessmentCount, &v.OpenAlertCount); err != nil {
			return nil, 0, err
		}
		vendors = append(vendors, v)
	}
	return vendors, total, nil
}

func (r *SCSRepository) UpdateVendor(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateVendorRequest) (*model.SCSVendor, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Website != nil {
		sets = append(sets, fmt.Sprintf("website=$%d", n))
		args = append(args, *req.Website)
		n++
	}
	if req.RiskTier != nil {
		sets = append(sets, fmt.Sprintf("risk_tier=$%d", n))
		args = append(args, *req.RiskTier)
		n++
		sets = append(sets, fmt.Sprintf("risk_level=$%d", n))
		args = append(args, riskLevelFromTier(*req.RiskTier))
		n++
	}
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
	}
	if req.ContactName != nil {
		sets = append(sets, fmt.Sprintf("contact_name=$%d", n))
		args = append(args, *req.ContactName)
		n++
	}
	if req.ContactEmail != nil {
		sets = append(sets, fmt.Sprintf("contact_email=$%d", n))
		args = append(args, *req.ContactEmail)
		n++
	}
	if req.HasSOC2 != nil {
		sets = append(sets, fmt.Sprintf("has_soc2=$%d", n))
		args = append(args, *req.HasSOC2)
		n++
	}
	if req.HasISO27001 != nil {
		sets = append(sets, fmt.Sprintf("has_iso27001=$%d", n))
		args = append(args, *req.HasISO27001)
		n++
	}
	if req.HasPCIDSS != nil {
		sets = append(sets, fmt.Sprintf("has_pci_dss=$%d", n))
		args = append(args, *req.HasPCIDSS)
		n++
	}
	if req.NextAssessmentAt != nil {
		sets = append(sets, fmt.Sprintf("next_assessment_at=$%d", n))
		args = append(args, *req.NextAssessmentAt)
		n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n))
		args = append(args, *req.Notes)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}

	var v model.SCSVendor
	err := r.db.QueryRow(ctx,
		`UPDATE scs_vendors SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,website,vendor_type,risk_tier,risk_score,risk_level,
		           contact_name,contact_email,contact_phone,
		           has_soc2,has_iso27001,has_pci_dss,last_assessment_at,next_assessment_at,
		           status,tags,notes,created_by,created_at,updated_at`,
		args...,
	).Scan(&v.ID, &v.TenantID, &v.Name, &v.Website, &v.VendorType, &v.RiskTier, &v.RiskScore, &v.RiskLevel,
		&v.ContactName, &v.ContactEmail, &v.ContactPhone,
		&v.HasSOC2, &v.HasISO27001, &v.HasPCIDSS, &v.LastAssessmentAt, &v.NextAssessmentAt,
		&v.Status, &v.Tags, &v.Notes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return &v, err
}

// ─── Components ───────────────────────────────────────────────────────────────

func (r *SCSRepository) CreateComponent(ctx context.Context, tenantID uuid.UUID, req *model.CreateComponentRequest) (*model.SCSComponent, error) {
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	usedIn := req.UsedIn
	if usedIn == nil {
		usedIn = []string{}
	}
	var c model.SCSComponent
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_components
		 (tenant_id,vendor_id,name,version,component_type,ecosystem,purl,license,
		  source_repo,source_hash,used_in,is_direct,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 RETURNING id,tenant_id,vendor_id,name,version,component_type,ecosystem,purl,license,
		           is_deprecated,is_end_of_life,has_known_vulns,vuln_count,critical_vuln_count,
		           risk_score,source_repo,source_hash,used_in,is_direct,tags,created_at,updated_at`,
		tenantID, req.VendorID, req.Name, req.Version, req.ComponentType,
		req.Ecosystem, req.PURL, req.License, req.SourceRepo, req.SourceHash,
		usedIn, req.IsDirect, tags,
	).Scan(&c.ID, &c.TenantID, &c.VendorID, &c.Name, &c.Version, &c.ComponentType, &c.Ecosystem,
		&c.PURL, &c.License, &c.IsDeprecated, &c.IsEndOfLife, &c.HasKnownVulns,
		&c.VulnCount, &c.CriticalVulnCount, &c.RiskScore,
		&c.SourceRepo, &c.SourceHash, &c.UsedIn, &c.IsDirect, &c.Tags,
		&c.CreatedAt, &c.UpdatedAt)
	return &c, err
}

func (r *SCSRepository) GetComponent(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSComponent, error) {
	var c model.SCSComponent
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,vendor_id,name,version,component_type,ecosystem,purl,license,
		        is_deprecated,is_end_of_life,has_known_vulns,vuln_count,critical_vuln_count,
		        risk_score,source_repo,source_hash,used_in,is_direct,tags,created_at,updated_at
		 FROM scs_components WHERE tenant_id=$1 AND id=$2`,
		tenantID, id,
	).Scan(&c.ID, &c.TenantID, &c.VendorID, &c.Name, &c.Version, &c.ComponentType, &c.Ecosystem,
		&c.PURL, &c.License, &c.IsDeprecated, &c.IsEndOfLife, &c.HasKnownVulns,
		&c.VulnCount, &c.CriticalVulnCount, &c.RiskScore,
		&c.SourceRepo, &c.SourceHash, &c.UsedIn, &c.IsDirect, &c.Tags,
		&c.CreatedAt, &c.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (r *SCSRepository) ListComponents(ctx context.Context, tenantID uuid.UUID, f model.ListComponentsFilter) ([]model.SCSComponent, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Ecosystem != "" {
		cond = append(cond, fmt.Sprintf("ecosystem=$%d", n))
		args = append(args, f.Ecosystem)
		n++
	}
	if f.HasVulns != nil {
		cond = append(cond, fmt.Sprintf("has_known_vulns=$%d", n))
		args = append(args, *f.HasVulns)
		n++
	}
	if f.IsEOL != nil {
		cond = append(cond, fmt.Sprintf("is_end_of_life=$%d", n))
		args = append(args, *f.IsEOL)
		n++
	}
	if f.IsDeprecated != nil {
		cond = append(cond, fmt.Sprintf("is_deprecated=$%d", n))
		args = append(args, *f.IsDeprecated)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scs_components WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,vendor_id,name,version,component_type,ecosystem,purl,license,
		        is_deprecated,is_end_of_life,has_known_vulns,vuln_count,critical_vuln_count,
		        risk_score,source_repo,source_hash,used_in,is_direct,tags,created_at,updated_at
		 FROM scs_components WHERE `+where+
			fmt.Sprintf(` ORDER BY risk_score DESC, critical_vuln_count DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var comps []model.SCSComponent
	for rows.Next() {
		var c model.SCSComponent
		if err := rows.Scan(&c.ID, &c.TenantID, &c.VendorID, &c.Name, &c.Version, &c.ComponentType, &c.Ecosystem,
			&c.PURL, &c.License, &c.IsDeprecated, &c.IsEndOfLife, &c.HasKnownVulns,
			&c.VulnCount, &c.CriticalVulnCount, &c.RiskScore,
			&c.SourceRepo, &c.SourceHash, &c.UsedIn, &c.IsDirect, &c.Tags,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		comps = append(comps, c)
	}
	return comps, total, nil
}

func (r *SCSRepository) UpdateComponent(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateComponentRequest) (*model.SCSComponent, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.IsDeprecated != nil {
		sets = append(sets, fmt.Sprintf("is_deprecated=$%d", n))
		args = append(args, *req.IsDeprecated)
		n++
	}
	if req.IsEndOfLife != nil {
		sets = append(sets, fmt.Sprintf("is_end_of_life=$%d", n))
		args = append(args, *req.IsEndOfLife)
		n++
	}
	if req.HasKnownVulns != nil {
		sets = append(sets, fmt.Sprintf("has_known_vulns=$%d", n))
		args = append(args, *req.HasKnownVulns)
		n++
	}
	if req.VulnCount != nil {
		sets = append(sets, fmt.Sprintf("vuln_count=$%d", n))
		args = append(args, *req.VulnCount)
		n++
	}
	if req.CriticalVulnCount != nil {
		sets = append(sets, fmt.Sprintf("critical_vuln_count=$%d", n))
		args = append(args, *req.CriticalVulnCount)
		n++
	}
	if req.License != nil {
		sets = append(sets, fmt.Sprintf("license=$%d", n))
		args = append(args, *req.License)
		n++
	}
	if req.UsedIn != nil {
		sets = append(sets, fmt.Sprintf("used_in=$%d", n))
		args = append(args, req.UsedIn)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}

	// Recompute risk score inline if vuln data changed
	if req.CriticalVulnCount != nil || req.VulnCount != nil || req.IsEndOfLife != nil || req.IsDeprecated != nil {
		// score computed as best-effort; actual value stored via trigger or explicit set
		_ = 0
	}

	var c model.SCSComponent
	err := r.db.QueryRow(ctx,
		`UPDATE scs_components SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,vendor_id,name,version,component_type,ecosystem,purl,license,
		           is_deprecated,is_end_of_life,has_known_vulns,vuln_count,critical_vuln_count,
		           risk_score,source_repo,source_hash,used_in,is_direct,tags,created_at,updated_at`,
		args...,
	).Scan(&c.ID, &c.TenantID, &c.VendorID, &c.Name, &c.Version, &c.ComponentType, &c.Ecosystem,
		&c.PURL, &c.License, &c.IsDeprecated, &c.IsEndOfLife, &c.HasKnownVulns,
		&c.VulnCount, &c.CriticalVulnCount, &c.RiskScore,
		&c.SourceRepo, &c.SourceHash, &c.UsedIn, &c.IsDirect, &c.Tags,
		&c.CreatedAt, &c.UpdatedAt)
	return &c, err
}

// ─── SBOMs ────────────────────────────────────────────────────────────────────

func (r *SCSRepository) CreateSBOM(ctx context.Context, tenantID uuid.UUID, req *model.CreateSBOMRequest, createdBy *uuid.UUID) (*model.SCSSBOM, error) {
	rawData, _ := json.Marshal(req.RawData)
	format := req.SBOMFormat
	if format == "" {
		format = "cyclonedx"
	}

	// Process components first
	var (
		totalComps      int
		directComps     int
		transitiveComps int
		critVulns       int
		highVulns       int
		medVulns        int
		lowVulns        int
		deprecatedCnt   int
		eolCnt          int
	)

	componentIDs := make([]uuid.UUID, 0, len(req.Components))
	for _, compReq := range req.Components {
		comp, err := r.CreateComponent(ctx, tenantID, &compReq)
		if err != nil {
			continue
		}
		componentIDs = append(componentIDs, comp.ID)
		totalComps++
		if compReq.IsDirect {
			directComps++
		} else {
			transitiveComps++
		}
		if comp.IsDeprecated {
			deprecatedCnt++
		}
		if comp.IsEndOfLife {
			eolCnt++
		}
		critVulns += comp.CriticalVulnCount
	}

	riskScore := sbomRiskScore(critVulns, highVulns, eolCnt, totalComps)

	var sbom model.SCSSBOM
	var rawOut []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_sboms
		 (tenant_id,name,version,sbom_format,total_components,direct_components,transitive_components,
		  critical_vulns,high_vulns,medium_vulns,low_vulns,deprecated_count,eol_count,risk_score,
		  raw_data,source,source_ref,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		 RETURNING id,tenant_id,name,version,sbom_format,total_components,direct_components,
		           transitive_components,critical_vulns,high_vulns,medium_vulns,low_vulns,
		           deprecated_count,eol_count,risk_score,raw_data,source,source_ref,
		           generated_at,created_by,created_at`,
		tenantID, req.Name, req.Version, format,
		totalComps, directComps, transitiveComps,
		critVulns, highVulns, medVulns, lowVulns,
		deprecatedCnt, eolCnt, riskScore,
		rawData, req.Source, req.SourceRef, createdBy,
	).Scan(&sbom.ID, &sbom.TenantID, &sbom.Name, &sbom.Version, &sbom.SBOMFormat,
		&sbom.TotalComponents, &sbom.DirectComponents, &sbom.TransitiveComponents,
		&sbom.CriticalVulns, &sbom.HighVulns, &sbom.MediumVulns, &sbom.LowVulns,
		&sbom.DeprecatedCount, &sbom.EOLCount, &sbom.RiskScore, &rawOut,
		&sbom.Source, &sbom.SourceRef, &sbom.GeneratedAt, &sbom.CreatedBy, &sbom.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawOut, &sbom.RawData)

	// Link components to SBOM
	for _, cid := range componentIDs {
		_, _ = r.db.Exec(ctx,
			`INSERT INTO scs_sbom_components (sbom_id, component_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			sbom.ID, cid)
	}

	return &sbom, nil
}

func (r *SCSRepository) ListSBOMs(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]model.SCSSBOM, int, error) {
	if limit == 0 {
		limit = 50
	}
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scs_sboms WHERE tenant_id=$1`, tenantID).Scan(&total)

	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,version,sbom_format,total_components,direct_components,
		        transitive_components,critical_vulns,high_vulns,medium_vulns,low_vulns,
		        deprecated_count,eol_count,risk_score,raw_data,source,source_ref,
		        generated_at,created_by,created_at
		 FROM scs_sboms WHERE tenant_id=$1
		 ORDER BY generated_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var sboms []model.SCSSBOM
	for rows.Next() {
		var s model.SCSSBOM
		var rawOut []byte
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.Version, &s.SBOMFormat,
			&s.TotalComponents, &s.DirectComponents, &s.TransitiveComponents,
			&s.CriticalVulns, &s.HighVulns, &s.MediumVulns, &s.LowVulns,
			&s.DeprecatedCount, &s.EOLCount, &s.RiskScore, &rawOut,
			&s.Source, &s.SourceRef, &s.GeneratedAt, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(rawOut, &s.RawData)
		sboms = append(sboms, s)
	}
	return sboms, total, nil
}

func (r *SCSRepository) GetSBOM(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSSBOM, error) {
	var s model.SCSSBOM
	var rawOut []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,name,version,sbom_format,total_components,direct_components,
		        transitive_components,critical_vulns,high_vulns,medium_vulns,low_vulns,
		        deprecated_count,eol_count,risk_score,raw_data,source,source_ref,
		        generated_at,created_by,created_at
		 FROM scs_sboms WHERE tenant_id=$1 AND id=$2`,
		tenantID, id,
	).Scan(&s.ID, &s.TenantID, &s.Name, &s.Version, &s.SBOMFormat,
		&s.TotalComponents, &s.DirectComponents, &s.TransitiveComponents,
		&s.CriticalVulns, &s.HighVulns, &s.MediumVulns, &s.LowVulns,
		&s.DeprecatedCount, &s.EOLCount, &s.RiskScore, &rawOut,
		&s.Source, &s.SourceRef, &s.GeneratedAt, &s.CreatedBy, &s.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	_ = json.Unmarshal(rawOut, &s.RawData)
	return &s, err
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (r *SCSRepository) CreateAssessment(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssessmentRequest, createdBy *uuid.UUID) (*model.SCSAssessment, error) {
	qJSON, _ := json.Marshal(map[string]any{})
	fJSON, _ := json.Marshal([]any{})
	var a model.SCSAssessment
	var qRaw, fRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_assessments
		 (tenant_id,vendor_id,assessment_type,assessor,assessor_id,due_at,planned_at,notes,
		  questionnaire,findings,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id,tenant_id,vendor_id,assessment_type,status,score,max_score,risk_rating,
		           findings_count,critical_findings,planned_at,started_at,completed_at,due_at,next_due_at,
		           assessor,assessor_id,questionnaire,findings,recommendations,notes,created_by,created_at,updated_at`,
		tenantID, req.VendorID, req.AssessmentType, req.Assessor, req.AssessorID,
		req.DueAt, req.PlannedAt, req.Notes, qJSON, fJSON, createdBy,
	).Scan(&a.ID, &a.TenantID, &a.VendorID, &a.AssessmentType, &a.Status,
		&a.Score, &a.MaxScore, &a.RiskRating,
		&a.FindingsCount, &a.CriticalFindings,
		&a.PlannedAt, &a.StartedAt, &a.CompletedAt, &a.DueAt, &a.NextDueAt,
		&a.Assessor, &a.AssessorID, &qRaw, &fRaw,
		&a.Recommendations, &a.Notes, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(qRaw, &a.Questionnaire)
	_ = json.Unmarshal(fRaw, &a.Findings)
	return &a, nil
}

func (r *SCSRepository) ListAssessments(ctx context.Context, tenantID, vendorID uuid.UUID, status string) ([]model.SCSAssessment, error) {
	cond := []string{"a.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if vendorID != uuid.Nil {
		cond = append(cond, fmt.Sprintf("a.vendor_id=$%d", n))
		args = append(args, vendorID)
		n++
	}
	if status != "" {
		cond = append(cond, fmt.Sprintf("a.status=$%d", n))
		args = append(args, status)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,vendor_id,assessment_type,status,score,max_score,risk_rating,
		        findings_count,critical_findings,planned_at,started_at,completed_at,due_at,next_due_at,
		        assessor,assessor_id,questionnaire,findings,recommendations,notes,created_by,created_at,updated_at
		 FROM scs_assessments a WHERE `+strings.Join(cond, " AND ")+
			` ORDER BY due_at ASC NULLS LAST, created_at DESC`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assessments []model.SCSAssessment
	for rows.Next() {
		var a model.SCSAssessment
		var qRaw, fRaw []byte
		if err := rows.Scan(&a.ID, &a.TenantID, &a.VendorID, &a.AssessmentType, &a.Status,
			&a.Score, &a.MaxScore, &a.RiskRating,
			&a.FindingsCount, &a.CriticalFindings,
			&a.PlannedAt, &a.StartedAt, &a.CompletedAt, &a.DueAt, &a.NextDueAt,
			&a.Assessor, &a.AssessorID, &qRaw, &fRaw,
			&a.Recommendations, &a.Notes, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(qRaw, &a.Questionnaire)
		_ = json.Unmarshal(fRaw, &a.Findings)
		assessments = append(assessments, a)
	}
	return assessments, nil
}

func (r *SCSRepository) UpdateAssessment(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAssessmentRequest) (*model.SCSAssessment, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		now := time.Now().UTC()
		switch *req.Status {
		case "in_progress":
			sets = append(sets, fmt.Sprintf("started_at=COALESCE(started_at,$%d)", n))
			args = append(args, now)
			n++
		case "completed":
			sets = append(sets, fmt.Sprintf("completed_at=COALESCE(completed_at,$%d)", n))
			args = append(args, now)
			n++
			sets = append(sets, fmt.Sprintf("last_assessment_at=$%d", n))
			args = append(args, now)
			n++
		}
	}
	if req.Score != nil {
		sets = append(sets, fmt.Sprintf("score=$%d", n))
		args = append(args, *req.Score)
		n++
	}
	if req.RiskRating != nil {
		sets = append(sets, fmt.Sprintf("risk_rating=$%d", n))
		args = append(args, *req.RiskRating)
		n++
	}
	if req.Questionnaire != nil {
		q, _ := json.Marshal(req.Questionnaire)
		sets = append(sets, fmt.Sprintf("questionnaire=$%d", n))
		args = append(args, q)
		n++
	}
	if req.Findings != nil {
		f, _ := json.Marshal(req.Findings)
		cnt := len(req.Findings)
		sets = append(sets, fmt.Sprintf("findings=$%d", n))
		args = append(args, f)
		n++
		sets = append(sets, fmt.Sprintf("findings_count=$%d", n))
		args = append(args, cnt)
		n++
	}
	if req.Recommendations != nil {
		sets = append(sets, fmt.Sprintf("recommendations=$%d", n))
		args = append(args, *req.Recommendations)
		n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n))
		args = append(args, *req.Notes)
		n++
	}
	if req.NextDueAt != nil {
		sets = append(sets, fmt.Sprintf("next_due_at=$%d", n))
		args = append(args, *req.NextDueAt)
		n++
	}

	var a model.SCSAssessment
	var qRaw, fRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE scs_assessments SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,vendor_id,assessment_type,status,score,max_score,risk_rating,
		           findings_count,critical_findings,planned_at,started_at,completed_at,due_at,next_due_at,
		           assessor,assessor_id,questionnaire,findings,recommendations,notes,created_by,created_at,updated_at`,
		args...,
	).Scan(&a.ID, &a.TenantID, &a.VendorID, &a.AssessmentType, &a.Status,
		&a.Score, &a.MaxScore, &a.RiskRating,
		&a.FindingsCount, &a.CriticalFindings,
		&a.PlannedAt, &a.StartedAt, &a.CompletedAt, &a.DueAt, &a.NextDueAt,
		&a.Assessor, &a.AssessorID, &qRaw, &fRaw,
		&a.Recommendations, &a.Notes, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(qRaw, &a.Questionnaire)
	_ = json.Unmarshal(fRaw, &a.Findings)
	return &a, nil
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (r *SCSRepository) CreateAlert(ctx context.Context, tenantID uuid.UUID, req *model.CreateAlertRequest) (*model.SCSAlert, error) {
	cveIDs := req.CVEIDs
	if cveIDs == nil {
		cveIDs = []string{}
	}
	affComps := req.AffectedComponents
	if affComps == nil {
		affComps = []string{}
	}
	affSys := req.AffectedSystems
	if affSys == nil {
		affSys = []string{}
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	var a model.SCSAlert
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_alerts
		 (tenant_id,vendor_id,component_id,alert_type,severity,title,description,
		  affected_components,affected_systems,cve_ids,advisory_url,remediation,
		  source,source_ref,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING id,tenant_id,vendor_id,component_id,alert_type,severity,status,title,description,
		           affected_components,affected_systems,cve_ids,advisory_url,remediation,
		           resolved_by,resolved_at,source,source_ref,detected_at,tags,created_at,updated_at`,
		tenantID, req.VendorID, req.ComponentID, req.AlertType, req.Severity,
		req.Title, req.Description, affComps, affSys, cveIDs,
		req.AdvisoryURL, req.Remediation, req.Source, req.SourceRef, tags,
	).Scan(&a.ID, &a.TenantID, &a.VendorID, &a.ComponentID, &a.AlertType, &a.Severity, &a.Status,
		&a.Title, &a.Description, &a.AffectedComponents, &a.AffectedSystems,
		&a.CVEIDs, &a.AdvisoryURL, &a.Remediation,
		&a.ResolvedBy, &a.ResolvedAt, &a.Source, &a.SourceRef, &a.DetectedAt, &a.Tags,
		&a.CreatedAt, &a.UpdatedAt)
	return &a, err
}

func (r *SCSRepository) ListAlerts(ctx context.Context, tenantID uuid.UUID, f model.ListAlertsFilter) ([]model.SCSAlert, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Severity != "" {
		cond = append(cond, fmt.Sprintf("severity=$%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.AlertType != "" {
		cond = append(cond, fmt.Sprintf("alert_type=$%d", n))
		args = append(args, f.AlertType)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM scs_alerts WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,vendor_id,component_id,alert_type,severity,status,title,description,
		        affected_components,affected_systems,cve_ids,advisory_url,remediation,
		        resolved_by,resolved_at,source,source_ref,detected_at,tags,created_at,updated_at
		 FROM scs_alerts WHERE `+where+
			fmt.Sprintf(` ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var alerts []model.SCSAlert
	for rows.Next() {
		var a model.SCSAlert
		if err := rows.Scan(&a.ID, &a.TenantID, &a.VendorID, &a.ComponentID, &a.AlertType, &a.Severity, &a.Status,
			&a.Title, &a.Description, &a.AffectedComponents, &a.AffectedSystems,
			&a.CVEIDs, &a.AdvisoryURL, &a.Remediation,
			&a.ResolvedBy, &a.ResolvedAt, &a.Source, &a.SourceRef, &a.DetectedAt, &a.Tags,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		alerts = append(alerts, a)
	}
	return alerts, total, nil
}

func (r *SCSRepository) UpdateAlert(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAlertRequest) (*model.SCSAlert, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "resolved" {
			sets = append(sets, fmt.Sprintf("resolved_at=$%d", n))
			args = append(args, time.Now().UTC())
			n++
		}
	}
	if req.Remediation != nil {
		sets = append(sets, fmt.Sprintf("remediation=$%d", n))
		args = append(args, *req.Remediation)
		n++
	}
	if req.ResolvedBy != nil {
		sets = append(sets, fmt.Sprintf("resolved_by=$%d", n))
		args = append(args, *req.ResolvedBy)
		n++
	}

	var a model.SCSAlert
	err := r.db.QueryRow(ctx,
		`UPDATE scs_alerts SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,vendor_id,component_id,alert_type,severity,status,title,description,
		           affected_components,affected_systems,cve_ids,advisory_url,remediation,
		           resolved_by,resolved_at,source,source_ref,detected_at,tags,created_at,updated_at`,
		args...,
	).Scan(&a.ID, &a.TenantID, &a.VendorID, &a.ComponentID, &a.AlertType, &a.Severity, &a.Status,
		&a.Title, &a.Description, &a.AffectedComponents, &a.AffectedSystems,
		&a.CVEIDs, &a.AdvisoryURL, &a.Remediation,
		&a.ResolvedBy, &a.ResolvedAt, &a.Source, &a.SourceRef, &a.DetectedAt, &a.Tags,
		&a.CreatedAt, &a.UpdatedAt)
	return &a, err
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *SCSRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.SCSPolicy, error) {
	rule, _ := json.Marshal(req.Rule)
	action := req.Action
	if action == "" {
		action = "alert"
	}
	var p model.SCSPolicy
	var ruleRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO scs_policies (tenant_id,name,description,policy_type,rule,action,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id,tenant_id,name,description,policy_type,rule,action,is_active,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.PolicyType, rule, action, createdBy,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ruleRaw, &p.Rule)
	return &p, nil
}

func (r *SCSRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string) ([]model.SCSPolicy, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if policyType != "" {
		cond = append(cond, fmt.Sprintf("policy_type=$%d", n))
		args = append(args, policyType)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,policy_type,rule,action,is_active,created_by,created_at,updated_at
		 FROM scs_policies WHERE `+strings.Join(cond, " AND ")+` ORDER BY policy_type,name`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []model.SCSPolicy
	for rows.Next() {
		var p model.SCSPolicy
		var ruleRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
			&ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ruleRaw, &p.Rule)
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *SCSRepository) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePolicyRequest) (*model.SCSPolicy, error) {
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

	var p model.SCSPolicy
	var ruleRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE scs_policies SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,policy_type,rule,action,is_active,created_by,created_at,updated_at`,
		args...,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&ruleRaw, &p.Action, &p.IsActive, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ruleRaw, &p.Rule)
	return &p, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *SCSRepository) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.SCSStats, error) {
	stats := &model.SCSStats{
		AlertsBySeverity: make(map[string]int),
		AlertsByType:     make(map[string]int),
		VendorsByTier:    make(map[string]int),
	}

	_ = r.db.QueryRow(ctx,
		`SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE risk_tier <= 2)
		 FROM scs_vendors WHERE tenant_id=$1 AND status='active'`, tenantID,
	).Scan(&stats.TotalVendors, &stats.HighRiskVendors)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE has_known_vulns), COUNT(*) FILTER (WHERE is_end_of_life)
		 FROM scs_components WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalComponents, &stats.VulnerableComponents, &stats.EOLComponents)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM scs_sboms WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalSBOMs)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE severity='critical')
		 FROM scs_alerts WHERE tenant_id=$1 AND status='open'`, tenantID,
	).Scan(&stats.OpenAlerts, &stats.CriticalAlerts)

	_ = r.db.QueryRow(ctx,
		`SELECT
		    COUNT(*) FILTER (WHERE status IN ('planned','in_progress')),
		    COUNT(*) FILTER (WHERE status NOT IN ('completed','cancelled') AND due_at < NOW())
		 FROM scs_assessments WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.PendingAssessments, &stats.OverdueAssessments)

	// Alerts by severity
	rows, _ := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM scs_alerts WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.AlertsBySeverity[k] = v
		}
	}

	// Alerts by type
	rows2, _ := r.db.Query(ctx,
		`SELECT alert_type, COUNT(*) FROM scs_alerts WHERE tenant_id=$1 AND status='open' GROUP BY alert_type`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var k string
			var v int
			_ = rows2.Scan(&k, &v)
			stats.AlertsByType[k] = v
		}
	}

	// Vendors by tier
	rows3, _ := r.db.Query(ctx,
		`SELECT risk_tier::text, COUNT(*) FROM scs_vendors WHERE tenant_id=$1 AND status='active' GROUP BY risk_tier`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var k string
			var v int
			_ = rows3.Scan(&k, &v)
			stats.VendorsByTier["tier_"+k] = v
		}
	}

	// Top risky vendors (tier 1-2, by risk_score DESC)
	rrows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,name,website,vendor_type,risk_tier,risk_score,risk_level,
		        contact_name,contact_email,contact_phone,
		        has_soc2,has_iso27001,has_pci_dss,last_assessment_at,next_assessment_at,
		        status,tags,notes,created_by,created_at,updated_at
		 FROM scs_vendors WHERE tenant_id=$1 AND risk_tier<=2 AND status='active'
		 ORDER BY risk_score DESC LIMIT 5`, tenantID)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var v model.SCSVendor
			if err := rrows.Scan(&v.ID, &v.TenantID, &v.Name, &v.Website, &v.VendorType,
				&v.RiskTier, &v.RiskScore, &v.RiskLevel,
				&v.ContactName, &v.ContactEmail, &v.ContactPhone,
				&v.HasSOC2, &v.HasISO27001, &v.HasPCIDSS,
				&v.LastAssessmentAt, &v.NextAssessmentAt,
				&v.Status, &v.Tags, &v.Notes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err == nil {
				stats.TopRiskyVendors = append(stats.TopRiskyVendors, v)
			}
		}
	}

	// Recent open alerts
	arows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,vendor_id,component_id,alert_type,severity,status,title,description,
		        affected_components,affected_systems,cve_ids,advisory_url,remediation,
		        resolved_by,resolved_at,source,source_ref,detected_at,tags,created_at,updated_at
		 FROM scs_alerts WHERE tenant_id=$1 AND status='open'
		 ORDER BY detected_at DESC LIMIT 5`, tenantID)
	if arows != nil {
		defer arows.Close()
		for arows.Next() {
			var a model.SCSAlert
			if err := arows.Scan(&a.ID, &a.TenantID, &a.VendorID, &a.ComponentID,
				&a.AlertType, &a.Severity, &a.Status, &a.Title, &a.Description,
				&a.AffectedComponents, &a.AffectedSystems,
				&a.CVEIDs, &a.AdvisoryURL, &a.Remediation,
				&a.ResolvedBy, &a.ResolvedAt, &a.Source, &a.SourceRef,
				&a.DetectedAt, &a.Tags, &a.CreatedAt, &a.UpdatedAt); err == nil {
				stats.RecentAlerts = append(stats.RecentAlerts, a)
			}
		}
	}

	return stats, nil
}
