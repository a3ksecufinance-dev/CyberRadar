package service

import (
	"context"
	"math"
	"time"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// maxPathsPerScenario caps how many paths one scenario records. Reaching it is
// reported rather than silently returning a partial answer.
//
// It stays a constant while the weightings became configurable, because it is
// not the same kind of number: it bounds the work a run may do, the way a page
// size does. Nothing about an institution's view of risk is expressed by it.
const maxPathsPerScenario = 200

// PolicySource is where the weightings in force come from.
//
// Read once per run rather than cached: a scenario run enumerates a graph and
// writes hundreds of rows, so one more query is noise — and reading it fresh
// means a stance changed in the console applies to the very next run instead of
// whenever a refresh happens to land.
type PolicySource interface {
	AttackPolicy(ctx context.Context, tenantID uuid.UUID) (*model.AttackPolicy, error)
}

// Analyzer finds attack paths through a tenant's graph.
type Analyzer struct {
	store    GraphStore
	policies PolicySource
	logger   zerolog.Logger
}

// NewAnalyzer creates an Analyzer.
func NewAnalyzer(store GraphStore, policies PolicySource, logger zerolog.Logger) *Analyzer {
	return &Analyzer{store: store, policies: policies, logger: logger}
}

// RunScenario walks the graph from each entry node to each target and records
// what it found.
func (a *Analyzer) RunScenario(ctx context.Context, scenario *model.AttackScenario) error {
	start := time.Now()

	if err := a.store.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusRunning); err != nil {
		return err
	}

	// The stance this run is scored under. Resolved once, so every path in one
	// run is ranked against the same weightings even if someone saves a new
	// version while it is walking.
	policy := model.DefaultAttackPolicy()
	if a.policies != nil {
		if p, err := a.policies.AttackPolicy(ctx, scenario.TenantID); err == nil && p != nil {
			policy = p
		} else if err != nil {
			// Scoring on the standard stance beats refusing to score: a run
			// that failed because a configuration row was unreachable would be
			// a worse outage than one ranked under our weightings.
			a.logger.Error().Err(err).
				Str("tenant_id", scenario.TenantID.String()).
				Msg("attack_policy_unreadable_using_standard")
		}
	}

	// No graph is loaded. Every run used to pull the tenant's whole graph into
	// the process before the walk started — 462 ms from PostgreSQL and 5.8 s
	// from Neo4j on a twenty-thousand-node tenant, measured. The store
	// enumerates the routes instead, and stops at the budget.
	var allPaths []*model.AttackPath
	truncated := false
	for _, entryID := range scenario.EntryNodeIDs {
		budget := maxPathsPerScenario - len(allPaths)
		if budget <= 0 {
			truncated = true
			break
		}
		found, cut, err := a.store.FindPaths(ctx, scenario, entryID, budget)
		if err != nil {
			_ = a.store.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusFailed)
			return err
		}
		for _, dp := range found {
			allPaths = append(allPaths, a.buildPath(scenario, dp, policy))
		}
		truncated = truncated || cut
	}

	computeChokePoints(allPaths)

	if err := a.store.SavePaths(ctx, scenario.ID, allPaths); err != nil {
		a.logger.Error().Err(err).Str("scenario_id", scenario.ID.String()).Msg("save_paths_error")
	}

	durationMS := int(time.Since(start).Milliseconds())
	summary := summarise(allPaths)
	riskScore := scenarioRisk(allPaths, policy)

	if err := a.store.UpdateScenarioResult(ctx, scenario.ID, model.ScenarioOutcome{
		PathCount:        len(allPaths),
		ShortestPath:     summary.Shortest,
		CriticalPath:     summary.Critical,
		CheapestPathCost: summary.CheapestCost,
		RiskScore:        riskScore,
		DurationMS:       durationMS,
		PolicyCode:       policy.Code,
		PolicyVersion:    policy.Version,
	}); err != nil {
		return err
	}

	entry := a.logger.Info()
	if truncated {
		// An analyst reading "200 paths" must not take it for the whole
		// answer: the cap used to be hit and returned with no trace at all.
		entry = a.logger.Warn().Bool("truncated", true)
	}
	entry.
		Str("scenario_id", scenario.ID.String()).
		Str("tenant_id", scenario.TenantID.String()).
		Int("paths_found", len(allPaths)).
		Float64("risk_score", riskScore).
		Str("policy", policy.Code).
		Int("policy_version", policy.Version).
		Int("duration_ms", durationMS).
		Msg("scenario_analysis_completed")

	return nil
}

// walk enumerates paths from entryID to any target, depth first, and reports
// whether it stopped at the cap.
//
// Depth first with backtracking, not breadth first with copied state: the
// earlier breadth-first search deep-copied the visited set and both sequences
// at every edge it expanded, so memory grew with nodes × edges. Here one
// visited set and two slices are shared and unwound, so the working set is the
// depth of the walk — at most max_hops.
//
// It is a free function rather than a method because it is no longer the only
// way paths are found: both stores enumerate them now, and this is the
// reference the two are checked against.
func walk(
	g *model.Graph,
	scenario *model.AttackScenario,
	entryID uuid.UUID,
	targets map[uuid.UUID]bool,
	budget int,
) ([]model.DiscoveredPath, bool) {
	entryNode, ok := g.Nodes[entryID]
	if !ok {
		return nil, false // an entry node that is not in the graph reaches nothing
	}

	var found []model.DiscoveredPath
	truncated := false

	onPath := map[uuid.UUID]bool{entryID: true}
	nodesOnPath := []*model.AttackNode{entryNode}
	edgesOnPath := []*model.AttackEdge{}

	var step func(current uuid.UUID)
	step = func(current uuid.UUID) {
		if truncated || len(nodesOnPath) > scenario.MaxHops {
			return
		}
		for _, edge := range g.Out[current] {
			next := edge.TargetID
			if onPath[next] {
				continue // a cycle; the walk already holds this node
			}
			node, known := g.Nodes[next]
			if !known {
				continue // an edge to a node the graph does not have
			}
			isTarget := targets[next]
			if !isTarget && !typeIncluded(scenario, node) {
				continue
			}

			onPath[next] = true
			nodesOnPath = append(nodesOnPath, node)
			edgesOnPath = append(edgesOnPath, edge)

			if isTarget {
				// The sequences are reused across the walk, so each path keeps
				// its own copy.
				found = append(found, model.DiscoveredPath{
					Nodes: append([]*model.AttackNode(nil), nodesOnPath...),
					Edges: append([]*model.AttackEdge(nil), edgesOnPath...),
				})
				if len(found) >= budget {
					truncated = true
				}
			}
			if !truncated {
				step(next)
			}

			edgesOnPath = edgesOnPath[:len(edgesOnPath)-1]
			nodesOnPath = nodesOnPath[:len(nodesOnPath)-1]
			onPath[next] = false

			if truncated {
				return
			}
		}
	}
	step(entryID)

	return found, truncated
}

// typeIncluded applies a scenario's include_types to an intermediate node.
//
// The field was stored, returned by the API and never read by the traversal,
// so narrowing a scenario to "asset" nodes silently changed nothing.
func typeIncluded(scenario *model.AttackScenario, node *model.AttackNode) bool {
	if len(scenario.IncludeTypes) == 0 {
		return true
	}
	for _, t := range scenario.IncludeTypes {
		if t == node.NodeType {
			return true
		}
	}
	return false
}

// buildPath scores one discovered route and records what it says about the
// attack.
//
// It works from the path's own nodes and edges. It used to need the whole
// graph, to look up whether an intermediate node was privileged — which is one
// of the reasons the graph had to be in memory at all.
func (a *Analyzer) buildPath(
	scenario *model.AttackScenario,
	found model.DiscoveredPath,
	policy *model.AttackPolicy,
) *model.AttackPath {
	entry, target := found.Entry(), found.Target()
	hopCount := len(found.Edges)
	totalCost := policy.PathCost(found.Edges)

	nodeSeq := make([]uuid.UUID, 0, len(found.Nodes))
	for _, n := range found.Nodes {
		nodeSeq = append(nodeSeq, n.ID)
	}
	edgeSeq := make([]uuid.UUID, 0, len(found.Edges))
	for _, e := range found.Edges {
		edgeSeq = append(edgeSeq, e.ID)
	}

	path := &model.AttackPath{
		ID:               uuid.New(),
		TenantID:         scenario.TenantID,
		ScenarioID:       scenario.ID,
		EntryNodeID:      entry.ID,
		TargetNodeID:     target.ID,
		NodeSequence:     nodeSeq,
		EdgeSequence:     edgeSeq,
		HopCount:         hopCount,
		TotalCost:        totalCost,
		PathScore:        policy.PathScore(totalCost, hopCount),
		Likelihood:       math.Pow(policy.HopDecay, float64(hopCount)),
		Impact:           policy.Impact(target),
		HasInternetEntry: entry.IsInternetFacing,
		MitreTactics:     []string{},
		DiscoveredAt:     time.Now().UTC(),
	}

	// These three were declared, persisted and read back by the API, and never
	// computed: every path in the database recorded false for all of them.
	// They are exactly what an analyst filters on.
	for _, edge := range found.Edges {
		if edge.EdgeType == model.EdgeTypeExploit || edge.CVEID != "" || edge.VulnID != nil {
			path.HasExploitStep = true
			break
		}
	}
	for _, node := range found.Nodes[1:] {
		if node.IsPrivileged {
			path.HasPrivEsc = true
			break
		}
	}

	path.PathType = pathTypeOf(target, path)
	return path
}

// pathTypeOf classifies a path by what it achieved, rather than labelling
// every path lateral_movement as before.
func pathTypeOf(target *model.AttackNode, path *model.AttackPath) string {
	switch {
	case target.IsPrivileged || path.HasPrivEsc:
		return model.PathTypePrivEscalation
	case target.IsCriticalSystem:
		return model.PathTypeDataAccess
	default:
		return model.PathTypeLateralMovement
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// computeChokePoints identifies the most impactful node in each path to block.
func computeChokePoints(paths []*model.AttackPath) {
	// Count how often each intermediate node appears across all paths.
	nodeCounts := make(map[uuid.UUID]int)
	for _, p := range paths {
		if len(p.NodeSequence) <= 2 {
			continue // entry and target only; nothing in between to block
		}
		for _, nid := range p.NodeSequence[1 : len(p.NodeSequence)-1] {
			nodeCounts[nid]++
		}
	}

	for _, p := range paths {
		if len(p.NodeSequence) <= 2 {
			continue
		}
		best := uuid.Nil
		bestCount := 0
		for _, nid := range p.NodeSequence[1 : len(p.NodeSequence)-1] {
			if cnt := nodeCounts[nid]; cnt > bestCount {
				bestCount = cnt
				best = nid
			}
		}
		if best != uuid.Nil {
			p.ChokePointNodeID = &best
		}
	}
}

// scenarioResult is what a run recorded.
type scenarioResult struct {
	Shortest     *int     // fewest hops
	Critical     *int     // hops of the highest-scoring route
	CheapestCost *float64 // the weighted shortest route
}

// summarise reduces a run's routes to the numbers the scenario records.
//
// critical used to be the hop count of the LONGEST route, which is close to the
// opposite of what "most critical" means: the route an attacker takes is the
// one that scores highest, and length counts against a route rather than for
// it. And cheapest is the weighted shortest route — the accumulated edge weight
// the walk had always computed and nothing had ever kept.
func summarise(paths []*model.AttackPath) scenarioResult {
	if len(paths) == 0 {
		return scenarioResult{}
	}
	minHops, bestScore, cheapest := math.MaxInt, math.Inf(-1), math.Inf(1)
	criticalHops := 0
	for _, p := range paths {
		if p.HopCount < minHops {
			minHops = p.HopCount
		}
		if p.PathScore > bestScore {
			bestScore, criticalHops = p.PathScore, p.HopCount
		}
		if p.TotalCost < cheapest {
			cheapest = p.TotalCost
		}
	}
	return scenarioResult{Shortest: &minHops, Critical: &criticalHops, CheapestCost: &cheapest}
}

func scenarioRisk(paths []*model.AttackPath, policy *model.AttackPolicy) float64 {
	scores := make([]float64, 0, len(paths))
	for _, p := range paths {
		scores = append(scores, p.PathScore)
	}
	return policy.ScenarioRisk(scores)
}
