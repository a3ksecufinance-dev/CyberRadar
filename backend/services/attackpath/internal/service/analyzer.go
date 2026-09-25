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
const maxPathsPerScenario = 200

// hopDecay is how much each extra hop reduces a path's threat score. An attack
// that needs more steps is more work and more chance of being caught.
const hopDecay = 0.85

// Analyzer finds attack paths through a tenant's graph.
type Analyzer struct {
	store  GraphStore
	logger zerolog.Logger
}

// NewAnalyzer creates an Analyzer.
func NewAnalyzer(store GraphStore, logger zerolog.Logger) *Analyzer {
	return &Analyzer{store: store, logger: logger}
}

// RunScenario walks the graph from each entry node to each target and records
// what it found.
func (a *Analyzer) RunScenario(ctx context.Context, scenario *model.AttackScenario) error {
	start := time.Now()

	if err := a.store.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusRunning); err != nil {
		return err
	}

	graph, err := a.store.LoadGraph(ctx, scenario.TenantID)
	if err != nil {
		_ = a.store.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusFailed)
		return err
	}

	targets := make(map[uuid.UUID]bool, len(scenario.TargetNodeIDs))
	for _, tid := range scenario.TargetNodeIDs {
		targets[tid] = true
	}

	var allPaths []*model.AttackPath
	truncated := false
	for _, entryID := range scenario.EntryNodeIDs {
		if len(allPaths) >= maxPathsPerScenario {
			truncated = true
			break
		}
		paths, cut := a.walk(graph, scenario, entryID, targets, maxPathsPerScenario-len(allPaths))
		allPaths = append(allPaths, paths...)
		truncated = truncated || cut
	}

	computeChokePoints(allPaths)

	if err := a.store.SavePaths(ctx, allPaths); err != nil {
		a.logger.Error().Err(err).Str("scenario_id", scenario.ID.String()).Msg("save_paths_error")
	}

	durationMS := int(time.Since(start).Milliseconds())
	shortest, critical := pathStats(allPaths)
	riskScore := scenarioRisk(allPaths)

	if err := a.store.UpdateScenarioResult(ctx, scenario.ID, len(allPaths), shortest, critical, riskScore, durationMS); err != nil {
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
		Int("duration_ms", durationMS).
		Msg("scenario_analysis_completed")

	return nil
}

// walk enumerates paths from entryID to any target, depth first, and reports
// whether it stopped at the cap.
//
// Depth first with backtracking, not breadth first with copied state: the
// previous breadth-first search deep-copied the visited set and both sequences
// at every edge it expanded, so memory grew with nodes × edges. Here one
// visited set and two slices are shared and unwound, so the working set is the
// depth of the walk — at most max_hops.
func (a *Analyzer) walk(
	g *model.Graph,
	scenario *model.AttackScenario,
	entryID uuid.UUID,
	targets map[uuid.UUID]bool,
	budget int,
) ([]*model.AttackPath, bool) {
	entryNode, ok := g.Nodes[entryID]
	if !ok {
		return nil, false // an entry node that is not in the graph reaches nothing
	}

	var found []*model.AttackPath
	truncated := false

	onPath := map[uuid.UUID]bool{entryID: true}
	nodeSeq := []uuid.UUID{entryID}
	edgeSeq := []uuid.UUID{}
	// The edges themselves travel with the walk. Looking them up afterwards
	// would mean scanning the adjacency list, which is the size of the graph.
	edgesOnPath := []*model.AttackEdge{}
	cost := 0.0

	var step func(current uuid.UUID)
	step = func(current uuid.UUID) {
		if truncated || len(nodeSeq) > scenario.MaxHops {
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
			nodeSeq = append(nodeSeq, next)
			edgeSeq = append(edgeSeq, edge.ID)
			edgesOnPath = append(edgesOnPath, edge)
			cost += edge.Weight

			if isTarget {
				found = append(found, a.buildPath(g, scenario, entryNode, node, nodeSeq, edgeSeq, edgesOnPath, cost))
				if len(found) >= budget {
					truncated = true
				}
			}
			if !truncated {
				step(next)
			}

			cost -= edge.Weight
			edgesOnPath = edgesOnPath[:len(edgesOnPath)-1]
			edgeSeq = edgeSeq[:len(edgeSeq)-1]
			nodeSeq = nodeSeq[:len(nodeSeq)-1]
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

// buildPath records one path and what it says about the attack.
func (a *Analyzer) buildPath(
	g *model.Graph,
	scenario *model.AttackScenario,
	entry, target *model.AttackNode,
	nodeSeq, edgeSeq []uuid.UUID,
	edgesOnPath []*model.AttackEdge,
	totalCost float64,
) *model.AttackPath {
	hopCount := len(nodeSeq) - 1

	// The sequences are reused across the walk, so the path keeps its own copy.
	nodes := append([]uuid.UUID(nil), nodeSeq...)
	edges := append([]uuid.UUID(nil), edgeSeq...)

	path := &model.AttackPath{
		ID:               uuid.New(),
		TenantID:         scenario.TenantID,
		ScenarioID:       scenario.ID,
		EntryNodeID:      entry.ID,
		TargetNodeID:     target.ID,
		NodeSequence:     nodes,
		EdgeSequence:     edges,
		HopCount:         hopCount,
		PathScore:        pathScore(totalCost, hopCount),
		Likelihood:       math.Pow(hopDecay, float64(hopCount)),
		Impact:           impactOf(target),
		HasInternetEntry: entry.IsInternetFacing,
		MitreTactics:     []string{},
		DiscoveredAt:     time.Now().UTC(),
	}

	// These three were declared, persisted and read back by the API, and never
	// computed: every path in the database recorded false for all of them.
	// They are exactly what an analyst filters on.
	for _, edge := range edgesOnPath {
		if edge.EdgeType == model.EdgeTypeExploit || edge.CVEID != "" || edge.VulnID != nil {
			path.HasExploitStep = true
			break
		}
	}
	for _, nodeID := range nodes[1:] {
		if n, ok := g.Nodes[nodeID]; ok && n.IsPrivileged {
			path.HasPrivEsc = true
			break
		}
	}

	path.PathType = pathTypeOf(target, path)
	return path
}

// pathScore is how threatening a path is: higher means easier for an attacker.
//
// Both extra hops and heavier edges make an attack harder, so both lower it.
// The previous formula multiplied by hop count, so a five-hop path scored
// above a one-hop path of the same cost — it ranked the hardest attacks as the
// most dangerous, which is the wrong way round for a list an analyst works
// from the top of.
func pathScore(totalCost float64, hopCount int) float64 {
	if hopCount < 1 {
		hopCount = 1
	}
	avgCost := totalCost / float64(hopCount)
	score := 10.0 / (1.0 + avgCost) * math.Pow(hopDecay, float64(hopCount-1))
	return math.Min(10.0, math.Max(0, score))
}

// impactOf is what reaching this target would cost, from the target itself.
//
// Every path used to record a flat 7.0 regardless of what it reached, so
// impact carried no information and any ranking that used it was arbitrary.
func impactOf(target *model.AttackNode) float64 {
	// Criticality is 1–4 in the asset model. It maps onto 0–9 rather than
	// 0–10 so that is_critical_system still has somewhere to go: mapping it
	// straight onto 0–10 saturates at criticality 4 and the flag stops
	// distinguishing the targets it exists to distinguish.
	const ceiling = 9.0

	impact := 0.0
	switch {
	case target.Criticality > 0:
		impact = math.Min(ceiling, float64(target.Criticality)/4.0*ceiling)
	case target.RiskScore > 0:
		impact = math.Min(ceiling, target.RiskScore)
	default:
		impact = 4.5 // nothing recorded about the target; assume the middle
	}
	if target.IsCriticalSystem {
		impact += 1.0
	}
	return math.Min(10.0, impact)
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

func pathStats(paths []*model.AttackPath) (shortest, critical *int) {
	if len(paths) == 0 {
		return nil, nil
	}
	minHops := math.MaxInt
	maxHops := 0
	for _, p := range paths {
		if p.HopCount < minHops {
			minHops = p.HopCount
		}
		if p.HopCount > maxHops {
			maxHops = p.HopCount
		}
	}
	s := minHops
	c := maxHops
	return &s, &c
}

func scenarioRisk(paths []*model.AttackPath) float64 {
	if len(paths) == 0 {
		return 0
	}
	maxScore := 0.0
	for _, p := range paths {
		if p.PathScore > maxScore {
			maxScore = p.PathScore
		}
	}
	// More ways in is more risk, with diminishing return.
	boost := math.Log1p(float64(len(paths))) * 0.3
	return math.Min(10.0, maxScore+boost)
}
