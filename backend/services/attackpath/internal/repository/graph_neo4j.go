package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Neo4jGraphStore reads the attack graph from Neo4j.
//
// It embeds *GraphRepository rather than replacing it: the graph — nodes and
// edges — is what moves to Neo4j, while scenarios, discovered paths and their
// results stay in PostgreSQL, which remains the source of truth. So only
// LoadGraph is overridden; SetScenarioStatus, SavePaths and UpdateScenarioResult
// are the inherited PostgreSQL ones, and satisfy service.GraphStore unchanged.
//
// # Tenant isolation
//
// In PostgreSQL isolation is a column the schema puts in every WHERE. In Cypher
// it is a property with no such net, and a forgotten filter returns another
// bank's graph. Two things are done about it here:
//
//   - every read filters tenant_id on the relationship *and* on both endpoint
//     nodes, so an edge written across tenants by mistake still cannot be
//     traversed;
//   - no Cypher is built by string concatenation, and every statement in this
//     file takes $tenant.
//
// A database per tenant would remove the question entirely, but multi-database
// is a Neo4j Enterprise feature; on Community, which this deployment targets,
// there is one database and the property filter is the only option.
type Neo4jGraphStore struct {
	*GraphRepository
	driver   neo4j.DriverWithContext
	database string
}

// NewNeo4jGraphStore connects, verifies the connection and creates the schema.
//
// The driver settings — in particular the bounded transaction retry — live in
// internal/pkg/graphdb, so that the two services mirroring a graph cannot end
// up with different ones.
func NewNeo4jGraphStore(ctx context.Context, cfg graphdb.Config, pg *GraphRepository) (*Neo4jGraphStore, error) {
	driver, err := graphdb.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Neo4jGraphStore{GraphRepository: pg, driver: driver, database: cfg.DatabaseOrDefault()}
	if err := s.EnsureSchema(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, err
	}
	return s, nil
}

// Close releases the driver's connection pool.
func (s *Neo4jGraphStore) Close(ctx context.Context) error { return s.driver.Close(ctx) }

func (s *Neo4jGraphStore) query(ctx context.Context, cypher string, params map[string]any) (*neo4j.EagerResult, error) {
	return graphdb.Query(ctx, s.driver, s.database, cypher, params)
}

// ─── Schema ───────────────────────────────────────────────────────────────────

// schemaStatements are the constraints and indexes the graph needs.
//
// The two node constraints mirror the PostgreSQL keys exactly: (tenant_id, id)
// is the primary key, (tenant_id, ref_id, node_type) is the ON CONFLICT target
// of UpsertNode. Keeping them identical is what makes a divergence a bug rather
// than a difference between two schemas.
//
// There is deliberately no uniqueness constraint on the relationship: it is an
// Enterprise-only feature, and this deployment targets Community. MergeEdge
// keys on (tenant_id, source, target, edge_type) through MERGE instead, which
// holds as long as every write goes through it — which is why nothing in this
// package creates a relationship any other way.
var schemaStatements = []string{
	`CREATE CONSTRAINT attack_node_id IF NOT EXISTS
	 FOR (n:AttackNode) REQUIRE (n.tenant_id, n.id) IS UNIQUE`,
	`CREATE CONSTRAINT attack_node_ref IF NOT EXISTS
	 FOR (n:AttackNode) REQUIRE (n.tenant_id, n.ref_id, n.node_type) IS UNIQUE`,
	`CREATE INDEX attack_node_tenant IF NOT EXISTS
	 FOR (n:AttackNode) ON (n.tenant_id)`,
	`CREATE INDEX attack_edge_tenant IF NOT EXISTS
	 FOR ()-[e:ATTACKS]-() ON (e.tenant_id)`,
}

// EnsureSchema creates the constraints and indexes if they are absent.
func (s *Neo4jGraphStore) EnsureSchema(ctx context.Context) error {
	for _, stmt := range schemaStatements {
		if _, err := s.query(ctx, stmt, nil); err != nil {
			return fmt.Errorf("neo4j schema: %w", err)
		}
	}
	return nil
}

// ─── Reads ────────────────────────────────────────────────────────────────────

const nodeReturn = `
	RETURN n.id AS id, n.ref_id AS ref_id, n.node_type AS node_type, n.label AS label,
	       n.risk_score AS risk_score, n.criticality AS criticality,
	       n.is_internet_facing AS is_internet_facing, n.is_privileged AS is_privileged,
	       n.is_critical_system AS is_critical_system, n.is_compromised AS is_compromised,
	       n.has_critical_vuln AS has_critical_vuln, n.has_known_exploit AS has_known_exploit,
	       n.open_vuln_count AS open_vuln_count, n.network_zone AS network_zone,
	       n.ip_address AS ip_address, n.hostname AS hostname,
	       n.properties_json AS properties_json,
	       n.last_updated_at AS last_updated_at, n.created_at AS created_at`

const edgeReturn = `
	RETURN e.id AS id, e.source_id AS source_id, e.target_id AS target_id,
	       e.edge_type AS edge_type, e.attack_complexity AS attack_complexity,
	       e.privileges_required AS privileges_required, e.vuln_id AS vuln_id,
	       e.cve_id AS cve_id, e.mitre_technique AS mitre_technique,
	       e.weight AS weight, e.is_active AS is_active,
	       e.evidence_source AS evidence_source, e.properties_json AS properties_json,
	       e.created_at AS created_at, e.updated_at AS updated_at`

// LoadGraph returns every node and active edge for a tenant, read from Neo4j.
//
// It is the whole graph or an error, exactly like the PostgreSQL one: a
// traversal given part of a graph reports the paths it happened to find and
// says nothing about the ones it could not reach.
func (s *Neo4jGraphStore) LoadGraph(ctx context.Context, tenantID uuid.UUID) (*model.Graph, error) {
	nodes, err := s.loadNodes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	edges, err := s.loadActiveEdges(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return model.NewGraph(nodes, edges), nil
}

func (s *Neo4jGraphStore) loadNodes(ctx context.Context, tenantID uuid.UUID) ([]*model.AttackNode, error) {
	res, err := s.query(ctx,
		`MATCH (n:AttackNode {tenant_id: $tenant})`+nodeReturn,
		map[string]any{"tenant": tenantID.String()})
	if err != nil {
		return nil, fmt.Errorf("load graph nodes: %w", err)
	}
	nodes := make([]*model.AttackNode, 0, len(res.Records))
	for _, rec := range res.Records {
		n, err := nodeFromRecord(rec, tenantID)
		if err != nil {
			return nil, fmt.Errorf("read graph node: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (s *Neo4jGraphStore) loadActiveEdges(ctx context.Context, tenantID uuid.UUID) ([]*model.AttackEdge, error) {
	// The tenant is asserted on the relationship and on both endpoints. A
	// relationship that somehow joined two tenants is then unreachable from
	// either, rather than leaking one bank's topology into the other's
	// traversal.
	res, err := s.query(ctx, `
		MATCH (src:AttackNode {tenant_id: $tenant})
		      -[e:ATTACKS {tenant_id: $tenant}]->
		      (dst:AttackNode {tenant_id: $tenant})
		WHERE e.is_active`+edgeReturn+`
		ORDER BY e.weight`,
		map[string]any{"tenant": tenantID.String()})
	if err != nil {
		return nil, fmt.Errorf("load graph edges: %w", err)
	}
	edges := make([]*model.AttackEdge, 0, len(res.Records))
	for _, rec := range res.Records {
		e, err := edgeFromRecord(rec, tenantID)
		if err != nil {
			return nil, fmt.Errorf("read graph edge: %w", err)
		}
		edges = append(edges, e)
	}
	return edges, nil
}

// ─── Mirror writes ────────────────────────────────────────────────────────────

// MirrorNode copies a node PostgreSQL has just accepted into Neo4j.
//
// Every field is written, including the identifier: PostgreSQL decides what a
// node is, and a repeated mirror must converge on that rather than preserve
// whatever Neo4j happened to hold.
func (s *Neo4jGraphStore) MirrorNode(ctx context.Context, n *model.AttackNode) error {
	props, err := json.Marshal(n.Properties)
	if err != nil {
		return fmt.Errorf("mirror node %s: encode properties: %w", n.ID, err)
	}
	_, err = s.query(ctx, `
		MERGE (n:AttackNode {tenant_id: $tenant, ref_id: $ref_id, node_type: $node_type})
		ON CREATE SET n.created_at = $created_at
		SET n.id                 = $id,
		    n.label              = $label,
		    n.risk_score         = $risk_score,
		    n.criticality        = $criticality,
		    n.is_internet_facing = $is_internet_facing,
		    n.is_privileged      = $is_privileged,
		    n.is_critical_system = $is_critical_system,
		    n.is_compromised     = $is_compromised,
		    n.has_critical_vuln  = $has_critical_vuln,
		    n.has_known_exploit  = $has_known_exploit,
		    n.open_vuln_count    = $open_vuln_count,
		    n.network_zone       = $network_zone,
		    n.ip_address         = $ip_address,
		    n.hostname           = $hostname,
		    n.properties_json    = $properties_json,
		    n.last_updated_at    = $last_updated_at`,
		map[string]any{
			"tenant":             n.TenantID.String(),
			"ref_id":             n.RefID.String(),
			"node_type":          n.NodeType,
			"id":                 n.ID.String(),
			"label":              n.Label,
			"risk_score":         n.RiskScore,
			"criticality":        int64(n.Criticality),
			"is_internet_facing": n.IsInternetFacing,
			"is_privileged":      n.IsPrivileged,
			"is_critical_system": n.IsCriticalSystem,
			"is_compromised":     n.IsCompromised,
			"has_critical_vuln":  n.HasCriticalVuln,
			"has_known_exploit":  n.HasKnownExploit,
			"open_vuln_count":    int64(n.OpenVulnCount),
			"network_zone":       n.NetworkZone,
			"ip_address":         n.IPAddress,
			"hostname":           n.Hostname,
			"properties_json":    string(props),
			"created_at":         utc(n.CreatedAt),
			"last_updated_at":    utc(n.LastUpdatedAt),
		})
	if err != nil {
		return fmt.Errorf("mirror node %s: %w", n.ID, err)
	}
	return nil
}

// MirrorEdge copies an edge PostgreSQL has just accepted into Neo4j.
//
// It reports an error when either endpoint is missing from Neo4j. Without that
// check the MERGE matches nothing and reports success, which is how a mirror
// quietly loses an edge: PostgreSQL has it, Neo4j does not, and the traversal
// on the Neo4j side never sees the path it opens.
func (s *Neo4jGraphStore) MirrorEdge(ctx context.Context, e *model.AttackEdge) error {
	props, err := json.Marshal(e.Properties)
	if err != nil {
		return fmt.Errorf("mirror edge %s: encode properties: %w", e.ID, err)
	}
	var vulnID any
	if e.VulnID != nil {
		vulnID = e.VulnID.String()
	}
	res, err := s.query(ctx, `
		MATCH (src:AttackNode {tenant_id: $tenant, id: $source_id})
		MATCH (dst:AttackNode {tenant_id: $tenant, id: $target_id})
		MERGE (src)-[e:ATTACKS {tenant_id: $tenant, edge_type: $edge_type}]->(dst)
		ON CREATE SET e.created_at = $created_at
		SET e.id                  = $id,
		    e.source_id           = $source_id,
		    e.target_id           = $target_id,
		    e.attack_complexity   = $attack_complexity,
		    e.privileges_required = $privileges_required,
		    e.vuln_id             = $vuln_id,
		    e.cve_id              = $cve_id,
		    e.mitre_technique     = $mitre_technique,
		    e.weight              = $weight,
		    e.is_active           = $is_active,
		    e.evidence_source     = $evidence_source,
		    e.properties_json     = $properties_json,
		    e.updated_at          = $updated_at
		RETURN e.id AS id`,
		map[string]any{
			"tenant":              e.TenantID.String(),
			"id":                  e.ID.String(),
			"source_id":           e.SourceID.String(),
			"target_id":           e.TargetID.String(),
			"edge_type":           e.EdgeType,
			"attack_complexity":   e.AttackComplexity,
			"privileges_required": e.PrivilegesRequired,
			"vuln_id":             vulnID,
			"cve_id":              e.CVEID,
			"mitre_technique":     e.MitreTechnique,
			"weight":              e.Weight,
			"is_active":           e.IsActive,
			"evidence_source":     e.EvidenceSource,
			"properties_json":     string(props),
			"created_at":          utc(e.CreatedAt),
			"updated_at":          utc(e.UpdatedAt),
		})
	if err != nil {
		return fmt.Errorf("mirror edge %s: %w", e.ID, err)
	}
	if len(res.Records) == 0 {
		return fmt.Errorf("mirror edge %s: node %s or %s is not in neo4j", e.ID, e.SourceID, e.TargetID)
	}
	return nil
}

// MirrorCompromised copies a compromise flag into Neo4j. The flag is what makes
// a node an entry point, so a graph that has not received it is traversed from
// the wrong place.
func (s *Neo4jGraphStore) MirrorCompromised(ctx context.Context, tenantID, nodeID uuid.UUID, compromised bool) error {
	res, err := s.query(ctx, `
		MATCH (n:AttackNode {tenant_id: $tenant, id: $id})
		SET n.is_compromised = $compromised, n.last_updated_at = $now
		RETURN n.id AS id`,
		map[string]any{
			"tenant": tenantID.String(), "id": nodeID.String(),
			"compromised": compromised, "now": time.Now().UTC(),
		})
	if err != nil {
		return fmt.Errorf("mirror compromise %s: %w", nodeID, err)
	}
	if len(res.Records) == 0 {
		return fmt.Errorf("mirror compromise %s: node is not in neo4j", nodeID)
	}
	return nil
}

// DeleteTenantGraph removes a tenant's whole graph from Neo4j.
//
// Offboarding a tenant has to reach the mirror too: a graph left behind in a
// second store is the tenant's topology still on disk after the relational
// record says it is gone.
func (s *Neo4jGraphStore) DeleteTenantGraph(ctx context.Context, tenantID uuid.UUID) error {
	if _, err := s.query(ctx,
		`MATCH (n:AttackNode {tenant_id: $tenant}) DETACH DELETE n`,
		map[string]any{"tenant": tenantID.String()}); err != nil {
		return fmt.Errorf("delete tenant graph %s: %w", tenantID, err)
	}
	return nil
}

// ─── Reconciliation ───────────────────────────────────────────────────────────

// GraphDivergence is what the two stores disagree about for one tenant.
//
// It compares what each side returns from LoadGraph — every node, and the
// active edges — because that is exactly the input the traversal reads. Parity
// here is the precondition for pointing reads at Neo4j; anything else is a
// comparison of two schemas rather than of two answers.
type GraphDivergence struct {
	TenantID            uuid.UUID   `json:"tenant_id"`
	NodesInPostgres     int         `json:"nodes_in_postgres"`
	NodesInNeo4j        int         `json:"nodes_in_neo4j"`
	EdgesInPostgres     int         `json:"edges_in_postgres"`
	EdgesInNeo4j        int         `json:"edges_in_neo4j"`
	NodesOnlyInPostgres []uuid.UUID `json:"nodes_only_in_postgres,omitempty"`
	NodesOnlyInNeo4j    []uuid.UUID `json:"nodes_only_in_neo4j,omitempty"`
	NodesDiffering      []uuid.UUID `json:"nodes_differing,omitempty"`
	EdgesOnlyInPostgres []uuid.UUID `json:"edges_only_in_postgres,omitempty"`
	EdgesOnlyInNeo4j    []uuid.UUID `json:"edges_only_in_neo4j,omitempty"`
	EdgesDiffering      []uuid.UUID `json:"edges_differing,omitempty"`
}

// Count is the number of disagreements. Zero is parity.
func (d GraphDivergence) Count() int {
	return len(d.NodesOnlyInPostgres) + len(d.NodesOnlyInNeo4j) + len(d.NodesDiffering) +
		len(d.EdgesOnlyInPostgres) + len(d.EdgesOnlyInNeo4j) + len(d.EdgesDiffering)
}

// InParity reports whether the two stores would give the traversal the same graph.
func (d GraphDivergence) InParity() bool { return d.Count() == 0 }

// Reconcile compares PostgreSQL and Neo4j for one tenant.
func (s *Neo4jGraphStore) Reconcile(ctx context.Context, tenantID uuid.UUID) (*GraphDivergence, error) {
	pgGraph, err := s.GraphRepository.LoadGraph(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: postgres: %w", err)
	}
	n4jGraph, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: neo4j: %w", err)
	}

	d := &GraphDivergence{TenantID: tenantID}
	pgNodes, n4jNodes := nodeFingerprints(pgGraph), nodeFingerprints(n4jGraph)
	pgEdges, n4jEdges := edgeFingerprints(pgGraph), edgeFingerprints(n4jGraph)
	d.NodesInPostgres, d.NodesInNeo4j = len(pgNodes), len(n4jNodes)
	d.EdgesInPostgres, d.EdgesInNeo4j = len(pgEdges), len(n4jEdges)
	d.NodesOnlyInPostgres, d.NodesOnlyInNeo4j, d.NodesDiffering = diff(pgNodes, n4jNodes)
	d.EdgesOnlyInPostgres, d.EdgesOnlyInNeo4j, d.EdgesDiffering = diff(pgEdges, n4jEdges)
	return d, nil
}

// MirrorTenant copies a tenant's whole graph from PostgreSQL into Neo4j, and
// returns what it wrote. It is the backfill for a Neo4j that is empty or has
// fallen behind; nodes go first, because an edge whose endpoints are missing is
// refused rather than dropped.
func (s *Neo4jGraphStore) MirrorTenant(ctx context.Context, tenantID uuid.UUID) (nodes, edges int, err error) {
	g, err := s.GraphRepository.LoadGraph(ctx, tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("mirror tenant: postgres: %w", err)
	}
	for _, n := range g.Nodes {
		if err := s.MirrorNode(ctx, n); err != nil {
			return nodes, edges, err
		}
		nodes++
	}
	for _, out := range g.Out {
		for _, e := range out {
			if err := s.MirrorEdge(ctx, e); err != nil {
				return nodes, edges, err
			}
			edges++
		}
	}
	return nodes, edges, nil
}

// ─── Record decoding ──────────────────────────────────────────────────────────

func nodeFromRecord(rec *neo4j.Record, tenantID uuid.UUID) (*model.AttackNode, error) {
	id, err := recUUID(rec, "id")
	if err != nil {
		return nil, err
	}
	refID, err := recUUID(rec, "ref_id")
	if err != nil {
		return nil, err
	}
	n := &model.AttackNode{
		ID: id, TenantID: tenantID, RefID: refID,
		NodeType:         recString(rec, "node_type"),
		Label:            recString(rec, "label"),
		RiskScore:        recFloat(rec, "risk_score"),
		Criticality:      recInt(rec, "criticality"),
		IsInternetFacing: recBool(rec, "is_internet_facing"),
		IsPrivileged:     recBool(rec, "is_privileged"),
		IsCriticalSystem: recBool(rec, "is_critical_system"),
		IsCompromised:    recBool(rec, "is_compromised"),
		HasCriticalVuln:  recBool(rec, "has_critical_vuln"),
		HasKnownExploit:  recBool(rec, "has_known_exploit"),
		OpenVulnCount:    recInt(rec, "open_vuln_count"),
		NetworkZone:      recString(rec, "network_zone"),
		IPAddress:        recString(rec, "ip_address"),
		Hostname:         recString(rec, "hostname"),
		Properties:       recProps(rec),
		LastUpdatedAt:    recTime(rec, "last_updated_at"),
		CreatedAt:        recTime(rec, "created_at"),
	}
	return n, nil
}

func edgeFromRecord(rec *neo4j.Record, tenantID uuid.UUID) (*model.AttackEdge, error) {
	id, err := recUUID(rec, "id")
	if err != nil {
		return nil, err
	}
	sourceID, err := recUUID(rec, "source_id")
	if err != nil {
		return nil, err
	}
	targetID, err := recUUID(rec, "target_id")
	if err != nil {
		return nil, err
	}
	e := &model.AttackEdge{
		ID: id, TenantID: tenantID, SourceID: sourceID, TargetID: targetID,
		EdgeType:           recString(rec, "edge_type"),
		AttackComplexity:   recString(rec, "attack_complexity"),
		PrivilegesRequired: recString(rec, "privileges_required"),
		CVEID:              recString(rec, "cve_id"),
		MitreTechnique:     recString(rec, "mitre_technique"),
		Weight:             recFloat(rec, "weight"),
		IsActive:           recBool(rec, "is_active"),
		EvidenceSource:     recString(rec, "evidence_source"),
		Properties:         recProps(rec),
		CreatedAt:          recTime(rec, "created_at"),
		UpdatedAt:          recTime(rec, "updated_at"),
	}
	if raw := recString(rec, "vuln_id"); raw != "" {
		vulnID, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("edge %s: vuln_id %q: %w", id, raw, err)
		}
		e.VulnID = &vulnID
	}
	return e, nil
}

func recValue(rec *neo4j.Record, key string) any {
	v, found := rec.Get(key)
	if !found {
		return nil
	}
	return v
}

func recString(rec *neo4j.Record, key string) string {
	s, _ := recValue(rec, key).(string)
	return s
}

func recBool(rec *neo4j.Record, key string) bool {
	b, _ := recValue(rec, key).(bool)
	return b
}

func recInt(rec *neo4j.Record, key string) int {
	i, _ := recValue(rec, key).(int64)
	return int(i)
}

// recFloat accepts an integer too: Neo4j stores 7.0 as a long, so a risk score
// written as a whole number comes back as int64 and would otherwise read zero.
func recFloat(rec *neo4j.Record, key string) float64 {
	switch v := recValue(rec, key).(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	}
	return 0
}

func recTime(rec *neo4j.Record, key string) time.Time {
	t, _ := recValue(rec, key).(time.Time)
	return t.UTC()
}

func recUUID(rec *neo4j.Record, key string) (uuid.UUID, error) {
	raw := recString(rec, key)
	if raw == "" {
		return uuid.Nil, fmt.Errorf("%s is missing", key)
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s %q: %w", key, raw, err)
	}
	return id, nil
}

// recProps decodes the JSON that carries a node's or edge's free-form
// properties. Neo4j cannot store a nested map in a property, so the map travels
// as text; malformed text reads as no properties rather than failing the load,
// because a traversal does not use them.
func recProps(rec *neo4j.Record) map[string]any {
	raw := recString(rec, "properties_json")
	if raw == "" || raw == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

// ─── Fingerprints ─────────────────────────────────────────────────────────────

// nodeFingerprints reduces each node to the fields a traversal reads, so
// reconciliation reports a difference that changes an answer and ignores one
// that does not.
func nodeFingerprints(g *model.Graph) map[uuid.UUID]string {
	out := make(map[uuid.UUID]string, len(g.Nodes))
	for id, n := range g.Nodes {
		out[id] = fmt.Sprintf("%s|%s|%.4f|%d|%t|%t|%t|%t|%t|%t|%d|%s|%s",
			n.NodeType, n.Label, n.RiskScore, n.Criticality,
			n.IsInternetFacing, n.IsPrivileged, n.IsCriticalSystem, n.IsCompromised,
			n.HasCriticalVuln, n.HasKnownExploit, n.OpenVulnCount,
			n.NetworkZone, n.Hostname)
	}
	return out
}

func edgeFingerprints(g *model.Graph) map[uuid.UUID]string {
	out := make(map[uuid.UUID]string)
	for _, edges := range g.Out {
		for _, e := range edges {
			out[e.ID] = fmt.Sprintf("%s|%s|%s|%s|%s|%.4f|%t|%s",
				e.SourceID, e.TargetID, e.EdgeType, e.AttackComplexity,
				e.PrivilegesRequired, e.Weight, e.IsActive, e.CVEID)
		}
	}
	return out
}

func diff(left, right map[uuid.UUID]string) (onlyLeft, onlyRight, differing []uuid.UUID) {
	for id, lv := range left {
		rv, found := right[id]
		switch {
		case !found:
			onlyLeft = append(onlyLeft, id)
		case lv != rv:
			differing = append(differing, id)
		}
	}
	for id := range right {
		if _, found := left[id]; !found {
			onlyRight = append(onlyRight, id)
		}
	}
	sortIDs(onlyLeft)
	sortIDs(onlyRight)
	sortIDs(differing)
	return onlyLeft, onlyRight, differing
}

func sortIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}
