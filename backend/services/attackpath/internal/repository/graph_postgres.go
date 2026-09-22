package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GraphRepository manages the attack graph in PostgreSQL.
type GraphRepository struct {
	db *pgxpool.Pool
}

// NewGraphRepository creates a GraphRepository.
func NewGraphRepository(db *pgxpool.Pool) *GraphRepository {
	return &GraphRepository{db: db}
}

// ─── Nodes ────────────────────────────────────────────────────────────────────

// UpsertNode inserts or updates an attack graph node.
func (r *GraphRepository) UpsertNode(ctx context.Context, tenantID uuid.UUID, req *model.CreateNodeRequest) (*model.AttackNode, error) {
	id := uuid.New()
	props, _ := json.Marshal(req.Properties)

	n := &model.AttackNode{
		ID: id, TenantID: tenantID, RefID: req.RefID,
		NodeType: req.NodeType, Label: req.Label,
		RiskScore: req.RiskScore, Criticality: req.Criticality,
		IsInternetFacing: req.IsInternetFacing, IsPrivileged: req.IsPrivileged,
		IsCriticalSystem: req.IsCriticalSystem, HasCriticalVuln: req.HasCriticalVuln,
		HasKnownExploit: req.HasKnownExploit, OpenVulnCount: req.OpenVulnCount,
		NetworkZone: req.NetworkZone, Hostname: req.Hostname,
	}

	if err := r.db.QueryRow(ctx, `
		INSERT INTO attack_nodes
			(id, tenant_id, ref_id, node_type, label, risk_score, criticality,
			 is_internet_facing, is_privileged, is_critical_system,
			 has_critical_vuln, has_known_exploit, open_vuln_count,
			 network_zone, hostname, properties)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (tenant_id, ref_id, node_type) DO UPDATE SET
			label             = EXCLUDED.label,
			risk_score        = EXCLUDED.risk_score,
			criticality       = EXCLUDED.criticality,
			is_internet_facing = EXCLUDED.is_internet_facing,
			is_privileged     = EXCLUDED.is_privileged,
			is_critical_system = EXCLUDED.is_critical_system,
			has_critical_vuln = EXCLUDED.has_critical_vuln,
			has_known_exploit = EXCLUDED.has_known_exploit,
			open_vuln_count   = EXCLUDED.open_vuln_count,
			network_zone      = EXCLUDED.network_zone,
			hostname          = EXCLUDED.hostname,
			properties        = EXCLUDED.properties,
			last_updated_at   = NOW()
		RETURNING id, is_compromised, last_updated_at, created_at`,
		id, tenantID, req.RefID, req.NodeType, req.Label,
		req.RiskScore, req.Criticality,
		req.IsInternetFacing, req.IsPrivileged, req.IsCriticalSystem,
		req.HasCriticalVuln, req.HasKnownExploit, req.OpenVulnCount,
		nvlS(req.NetworkZone), nvlS(req.Hostname), props,
	).Scan(&n.ID, &n.IsCompromised, &n.LastUpdatedAt, &n.CreatedAt); err != nil {
		return nil, fmt.Errorf("upsert node: %w", err)
	}
	if req.Properties != nil {
		n.Properties = req.Properties
	}
	return n, nil
}

// GetNode returns a node by ID.
func (r *GraphRepository) GetNode(ctx context.Context, tenantID, nodeID uuid.UUID) (*model.AttackNode, error) {
	row := r.db.QueryRow(ctx, nodeSelect+` WHERE id = $1 AND tenant_id = $2`, nodeID, tenantID)
	return scanNode(row)
}

// ListNodes returns nodes matching the filter.
func (r *GraphRepository) ListNodes(ctx context.Context, f model.NodeFilter) ([]*model.AttackNode, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.NodeType != "" {
		where = append(where, fmt.Sprintf("node_type = $%d", n))
		args = append(args, f.NodeType)
		n++
	}
	if f.NetworkZone != "" {
		where = append(where, fmt.Sprintf("network_zone = $%d", n))
		args = append(args, f.NetworkZone)
		n++
	}
	if f.IsInternetFacing != nil {
		where = append(where, fmt.Sprintf("is_internet_facing = $%d", n))
		args = append(args, *f.IsInternetFacing)
		n++
	}
	if f.IsCriticalSystem != nil {
		where = append(where, fmt.Sprintf("is_critical_system = $%d", n))
		args = append(args, *f.IsCriticalSystem)
		n++
	}
	if f.IsCompromised != nil {
		where = append(where, fmt.Sprintf("is_compromised = $%d", n))
		args = append(args, *f.IsCompromised)
		n++
	}
	if f.MinRisk > 0 {
		where = append(where, fmt.Sprintf("risk_score >= $%d", n))
		args = append(args, f.MinRisk)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := clamp(f.Limit, 50, 500)
	var total int
	r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM attack_nodes WHERE %s", wc), args...).Scan(&total) //nolint

	q := fmt.Sprintf(nodeSelect+` WHERE %s ORDER BY risk_score DESC LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.AttackNode
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, node)
	}
	return out, total, nil
}

// MarkCompromised flags a node as actively compromised (called by SIEM/UEBA integration).
func (r *GraphRepository) MarkCompromised(ctx context.Context, tenantID, nodeID uuid.UUID, compromised bool) error {
	_, err := r.db.Exec(ctx,
		`UPDATE attack_nodes SET is_compromised=$1, last_updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		compromised, nodeID, tenantID)
	return err
}

// GetNodeByRef finds a node by its referenced domain object ID.
func (r *GraphRepository) GetNodeByRef(ctx context.Context, tenantID, refID uuid.UUID, nodeType string) (*model.AttackNode, error) {
	row := r.db.QueryRow(ctx, nodeSelect+` WHERE tenant_id=$1 AND ref_id=$2 AND node_type=$3`,
		tenantID, refID, nodeType)
	return scanNode(row)
}

// ─── Edges ────────────────────────────────────────────────────────────────────

// UpsertEdge inserts or updates an attack graph edge with computed weight.
func (r *GraphRepository) UpsertEdge(ctx context.Context, tenantID uuid.UUID, req *model.CreateEdgeRequest) (*model.AttackEdge, error) {
	id := uuid.New()
	props, _ := json.Marshal(req.Properties)
	complexity := req.AttackComplexity
	if complexity == "" {
		complexity = "LOW"
	}
	privReq := req.PrivilegesRequired
	if privReq == "" {
		privReq = "NONE"
	}
	evSrc := req.EvidenceSource
	if evSrc == "" {
		evSrc = "computed"
	}
	weight := computeEdgeWeight(complexity, privReq)

	e := &model.AttackEdge{
		ID: id, TenantID: tenantID, SourceID: req.SourceID, TargetID: req.TargetID,
		EdgeType: req.EdgeType, AttackComplexity: complexity, PrivilegesRequired: privReq,
		VulnID: req.VulnID, CVEID: req.CVEID, MitreTechnique: req.MitreTechnique,
		Weight: weight, IsActive: true, EvidenceSource: evSrc,
	}

	if err := r.db.QueryRow(ctx, `
		INSERT INTO attack_edges
			(id, tenant_id, source_id, target_id, edge_type,
			 attack_complexity, privileges_required, vuln_id, cve_id,
			 mitre_technique, weight, evidence_source, properties)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (tenant_id, source_id, target_id, edge_type) DO UPDATE SET
			attack_complexity   = EXCLUDED.attack_complexity,
			privileges_required = EXCLUDED.privileges_required,
			vuln_id             = COALESCE(EXCLUDED.vuln_id, attack_edges.vuln_id),
			cve_id              = COALESCE(EXCLUDED.cve_id, attack_edges.cve_id),
			weight              = EXCLUDED.weight,
			is_active           = true,
			updated_at          = NOW()
		RETURNING id, is_active, created_at, updated_at`,
		id, tenantID, req.SourceID, req.TargetID, req.EdgeType,
		complexity, privReq, req.VulnID, nvlS(req.CVEID),
		nvlS(req.MitreTechnique), weight, evSrc, props,
	).Scan(&e.ID, &e.IsActive, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, fmt.Errorf("upsert edge: %w", err)
	}
	return e, nil
}

// ListEdges returns all active edges for a tenant (optionally filtered by source).
func (r *GraphRepository) ListEdges(ctx context.Context, tenantID uuid.UUID, sourceID *uuid.UUID, activeOnly bool) ([]*model.AttackEdge, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	n := 2
	if sourceID != nil {
		where = append(where, fmt.Sprintf("source_id = $%d", n))
		args = append(args, *sourceID)
		n++
	}
	if activeOnly {
		where = append(where, "is_active = true")
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, tenant_id, source_id, target_id, edge_type,
		        attack_complexity, privileges_required, vuln_id, cve_id,
		        mitre_technique, weight, is_active, evidence_source,
		        properties, created_at, updated_at
		 FROM attack_edges WHERE `+strings.Join(where, " AND ")+` ORDER BY weight`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AttackEdge
	for rows.Next() {
		e, err := scanEdge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// GetNodesByIDs fetches multiple nodes by their IDs.
func (r *GraphRepository) GetNodesByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*model.AttackNode, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*model.AttackNode{}, nil
	}
	rows, err := r.db.Query(ctx,
		nodeSelect+` WHERE tenant_id=$1 AND id = ANY($2)`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[uuid.UUID]*model.AttackNode, len(ids))
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out[n.ID] = n
	}
	return out, nil
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

func (r *GraphRepository) CreateScenario(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateScenarioRequest) (*model.AttackScenario, error) {
	id := uuid.New()
	maxHops := req.MaxHops
	if maxHops == 0 {
		maxHops = 10
	}
	includeTypes := req.IncludeTypes
	if includeTypes == nil {
		includeTypes = []string{}
	}
	s := &model.AttackScenario{
		ID: id, TenantID: tenantID, Name: req.Name, Description: req.Description,
		EntryNodeIDs: req.EntryNodeIDs, TargetNodeIDs: req.TargetNodeIDs,
		MaxHops: maxHops, IncludeTypes: includeTypes,
		Status: model.ScenarioStatusPending, CreatedBy: callerID,
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO attack_scenarios
			(id, tenant_id, name, description, entry_node_ids, target_node_ids,
			 max_hops, include_types, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING status, risk_score, path_count, created_at, updated_at`,
		id, tenantID, req.Name, nvlS(req.Description),
		req.EntryNodeIDs, req.TargetNodeIDs,
		maxHops, includeTypes, callerID,
	).Scan(&s.Status, &s.RiskScore, &s.PathCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create scenario: %w", err)
	}
	return s, nil
}

func (r *GraphRepository) GetScenario(ctx context.Context, tenantID, scenarioID uuid.UUID) (*model.AttackScenario, error) {
	row := r.db.QueryRow(ctx, scenarioSelect+` WHERE id=$1 AND tenant_id=$2`, scenarioID, tenantID)
	return scanScenario(row)
}

func (r *GraphRepository) ListScenarios(ctx context.Context, tenantID uuid.UUID) ([]*model.AttackScenario, error) {
	rows, err := r.db.Query(ctx, scenarioSelect+` WHERE tenant_id=$1 ORDER BY updated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AttackScenario
	for rows.Next() {
		s, err := scanScenario(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *GraphRepository) UpdateScenarioResult(ctx context.Context, scenarioID uuid.UUID, pathCount int, shortestPath, criticalPath *int, riskScore float64, durationMS int) error {
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, `
		UPDATE attack_scenarios SET
			status='completed', path_count=$1, shortest_path=$2, critical_path=$3,
			risk_score=$4, last_run_at=$5, last_run_ms=$6, updated_at=NOW()
		WHERE id=$7`,
		pathCount, shortestPath, criticalPath, riskScore, now, durationMS, scenarioID)
	return err
}

func (r *GraphRepository) SetScenarioStatus(ctx context.Context, scenarioID uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE attack_scenarios SET status=$1, updated_at=NOW() WHERE id=$2`, status, scenarioID)
	return err
}

// ─── Attack Paths ─────────────────────────────────────────────────────────────

func (r *GraphRepository) SavePaths(ctx context.Context, paths []*model.AttackPath) error {
	if len(paths) == 0 {
		return nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, p := range paths {
		if _, err := tx.Exec(ctx, `
			INSERT INTO attack_paths
				(id, tenant_id, scenario_id, entry_node_id, target_node_id,
				 node_sequence, edge_sequence, hop_count, path_score, likelihood, impact,
				 path_type, has_internet_entry, has_exploit_step, has_priv_esc,
				 mitre_tactics, choke_point_node_id, choke_point_edge_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
			ON CONFLICT DO NOTHING`,
			p.ID, p.TenantID, p.ScenarioID, p.EntryNodeID, p.TargetNodeID,
			p.NodeSequence, p.EdgeSequence, p.HopCount,
			p.PathScore, p.Likelihood, p.Impact,
			p.PathType, p.HasInternetEntry, p.HasExploitStep, p.HasPrivEsc,
			p.MitreTactics, p.ChokePointNodeID, p.ChokePointEdgeID,
		); err != nil {
			return fmt.Errorf("save path: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (r *GraphRepository) ListPaths(ctx context.Context, f model.PathFilter) ([]*model.AttackPath, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.ScenarioID != nil {
		where = append(where, fmt.Sprintf("scenario_id = $%d", n))
		args = append(args, *f.ScenarioID)
		n++
	}
	if f.TargetID != nil {
		where = append(where, fmt.Sprintf("target_node_id = $%d", n))
		args = append(args, *f.TargetID)
		n++
	}
	if f.PathType != "" {
		where = append(where, fmt.Sprintf("path_type = $%d", n))
		args = append(args, f.PathType)
		n++
	}
	if f.MinScore > 0 {
		where = append(where, fmt.Sprintf("path_score >= $%d", n))
		args = append(args, f.MinScore)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := clamp(f.Limit, 50, 500)
	var total int
	r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM attack_paths WHERE %s", wc), args...).Scan(&total) //nolint

	q := fmt.Sprintf(`
		SELECT id, tenant_id, scenario_id, entry_node_id, target_node_id,
		       node_sequence, edge_sequence, hop_count, path_score, likelihood, impact,
		       path_type, has_internet_entry, has_exploit_step, has_priv_esc,
		       mitre_tactics, choke_point_node_id, choke_point_edge_id, discovered_at
		FROM attack_paths WHERE %s
		ORDER BY path_score DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.AttackPath
	for rows.Next() {
		p, err := scanPath(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, nil
}

// ChokePoints returns the top N nodes that appear in the most attack paths.
func (r *GraphRepository) ChokePoints(ctx context.Context, tenantID uuid.UUID, scenarioID *uuid.UUID, limit int) ([]*model.ChokePoint, error) {
	where := "ap.tenant_id = $1"
	args := []any{tenantID}
	if scenarioID != nil {
		where += " AND ap.scenario_id = $2"
		args = append(args, *scenarioID)
	}
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT n.id, n.label, COUNT(ap.id) as paths_blocked,
		       AVG(ap.path_score) as risk_reduction
		FROM attack_paths ap
		JOIN attack_nodes n ON n.id = ap.choke_point_node_id
		WHERE %s AND ap.choke_point_node_id IS NOT NULL
		GROUP BY n.id, n.label
		ORDER BY paths_blocked DESC, risk_reduction DESC
		LIMIT $%d`, where, len(args)+1),
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ChokePoint
	for rows.Next() {
		cp := &model.ChokePoint{}
		if err := rows.Scan(&cp.NodeID, &cp.Label, &cp.PathsBlocked, &cp.RiskReduction); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *GraphRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.AttackGraphStats, error) {
	s := &model.AttackGraphStats{}
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_nodes WHERE tenant_id=$1`, tenantID).Scan(&s.TotalNodes)                                      //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_edges WHERE tenant_id=$1 AND is_active=true`, tenantID).Scan(&s.TotalEdges)                   //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_nodes WHERE tenant_id=$1 AND is_internet_facing=true`, tenantID).Scan(&s.InternetFacingNodes) //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_nodes WHERE tenant_id=$1 AND is_critical_system=true`, tenantID).Scan(&s.CriticalSystemNodes) //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_nodes WHERE tenant_id=$1 AND is_compromised=true`, tenantID).Scan(&s.CompromisedNodes)        //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_scenarios WHERE tenant_id=$1`, tenantID).Scan(&s.TotalScenarios)                              //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_paths WHERE tenant_id=$1`, tenantID).Scan(&s.TotalPaths)                                      //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_paths WHERE tenant_id=$1 AND path_score >= 7.0`, tenantID).Scan(&s.HighRiskPaths)             //nolint
	r.db.QueryRow(ctx, `SELECT COALESCE(MIN(hop_count),0) FROM attack_paths WHERE tenant_id=$1`, tenantID).Scan(&s.ShortestPath)                  //nolint
	r.db.QueryRow(ctx, `SELECT COALESCE(AVG(hop_count),0) FROM attack_paths WHERE tenant_id=$1`, tenantID).Scan(&s.AvgPathLength)                 //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_paths WHERE tenant_id=$1 AND has_exploit_step=true`, tenantID).Scan(&s.PathsWithExploit)      //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM attack_paths WHERE tenant_id=$1 AND has_priv_esc=true`, tenantID).Scan(&s.PathsWithPrivEsc)          //nolint
	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

const nodeSelect = `
	SELECT id, tenant_id, ref_id, node_type, label, risk_score, criticality,
	       is_internet_facing, is_privileged, is_critical_system, is_compromised,
	       has_critical_vuln, has_known_exploit, open_vuln_count,
	       network_zone, hostname, properties, last_updated_at, created_at
	FROM attack_nodes`

const scenarioSelect = `
	SELECT id, tenant_id, name, description, entry_node_ids, target_node_ids,
	       max_hops, include_types, status, path_count, shortest_path, critical_path,
	       last_run_at, last_run_ms, risk_score, created_by, created_at, updated_at
	FROM attack_scenarios`

func scanNode(row scannable) (*model.AttackNode, error) {
	n := &model.AttackNode{}
	var zone, hostname *string
	var propsRaw []byte
	err := row.Scan(
		&n.ID, &n.TenantID, &n.RefID, &n.NodeType, &n.Label,
		&n.RiskScore, &n.Criticality,
		&n.IsInternetFacing, &n.IsPrivileged, &n.IsCriticalSystem, &n.IsCompromised,
		&n.HasCriticalVuln, &n.HasKnownExploit, &n.OpenVulnCount,
		&zone, &hostname, &propsRaw, &n.LastUpdatedAt, &n.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan node: %w", err)
	}
	if zone != nil {
		n.NetworkZone = *zone
	}
	if hostname != nil {
		n.Hostname = *hostname
	}
	_ = json.Unmarshal(propsRaw, &n.Properties)
	return n, nil
}

func scanEdge(row scannable) (*model.AttackEdge, error) {
	e := &model.AttackEdge{}
	var cveID, mitre *string
	var propsRaw []byte
	err := row.Scan(
		&e.ID, &e.TenantID, &e.SourceID, &e.TargetID, &e.EdgeType,
		&e.AttackComplexity, &e.PrivilegesRequired, &e.VulnID, &cveID,
		&mitre, &e.Weight, &e.IsActive, &e.EvidenceSource,
		&propsRaw, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if cveID != nil {
		e.CVEID = *cveID
	}
	if mitre != nil {
		e.MitreTechnique = *mitre
	}
	_ = json.Unmarshal(propsRaw, &e.Properties)
	return e, nil
}

func scanScenario(row scannable) (*model.AttackScenario, error) {
	s := &model.AttackScenario{}
	var desc *string
	err := row.Scan(
		&s.ID, &s.TenantID, &s.Name, &desc, &s.EntryNodeIDs, &s.TargetNodeIDs,
		&s.MaxHops, &s.IncludeTypes, &s.Status, &s.PathCount,
		&s.ShortestPath, &s.CriticalPath, &s.LastRunAt, &s.LastRunMS,
		&s.RiskScore, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan scenario: %w", err)
	}
	if desc != nil {
		s.Description = *desc
	}
	if s.EntryNodeIDs == nil {
		s.EntryNodeIDs = []uuid.UUID{}
	}
	if s.TargetNodeIDs == nil {
		s.TargetNodeIDs = []uuid.UUID{}
	}
	if s.IncludeTypes == nil {
		s.IncludeTypes = []string{}
	}
	return s, nil
}

func scanPath(row scannable) (*model.AttackPath, error) {
	p := &model.AttackPath{}
	err := row.Scan(
		&p.ID, &p.TenantID, &p.ScenarioID, &p.EntryNodeID, &p.TargetNodeID,
		&p.NodeSequence, &p.EdgeSequence, &p.HopCount,
		&p.PathScore, &p.Likelihood, &p.Impact,
		&p.PathType, &p.HasInternetEntry, &p.HasExploitStep, &p.HasPrivEsc,
		&p.MitreTactics, &p.ChokePointNodeID, &p.ChokePointEdgeID, &p.DiscoveredAt,
	)
	if err != nil {
		return nil, err
	}
	if p.NodeSequence == nil {
		p.NodeSequence = []uuid.UUID{}
	}
	if p.EdgeSequence == nil {
		p.EdgeSequence = []uuid.UUID{}
	}
	if p.MitreTactics == nil {
		p.MitreTactics = []string{}
	}
	return p, nil
}

// computeEdgeWeight assigns a traversal cost to an edge.
// Lower weight = attacker prefers this path.
func computeEdgeWeight(complexity, privRequired string) float64 {
	w := 1.0
	switch complexity {
	case "MEDIUM":
		w += 0.5
	case "HIGH":
		w += 1.5
	}
	switch privRequired {
	case "LOW":
		w += 0.3
	case "HIGH":
		w += 1.0
	}
	return w
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
