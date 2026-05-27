package service

import (
	"context"
	"math"
	"time"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Analyzer runs attack path discovery on the stored graph.
type Analyzer struct {
	repo   *repository.GraphRepository
	logger zerolog.Logger
}

// NewAnalyzer creates an Analyzer.
func NewAnalyzer(repo *repository.GraphRepository, logger zerolog.Logger) *Analyzer {
	return &Analyzer{repo: repo, logger: logger}
}

// RunScenario executes BFS-based path discovery for a scenario and stores results.
func (a *Analyzer) RunScenario(ctx context.Context, scenario *model.AttackScenario) error {
	start := time.Now()

	if err := a.repo.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusRunning); err != nil {
		return err
	}

	// Load full adjacency list for this tenant
	graph, err := a.buildGraph(ctx, scenario.TenantID)
	if err != nil {
		_ = a.repo.SetScenarioStatus(ctx, scenario.ID, model.ScenarioStatusFailed)
		return err
	}

	targetSet := make(map[uuid.UUID]bool, len(scenario.TargetNodeIDs))
	for _, tid := range scenario.TargetNodeIDs {
		targetSet[tid] = true
	}

	var allPaths []*model.AttackPath
	for _, entryID := range scenario.EntryNodeIDs {
		paths := a.bfsFind(ctx, graph, scenario, entryID, targetSet)
		allPaths = append(allPaths, paths...)
	}

	// Compute choke points
	computeChokePoints(allPaths)

	// Persist paths
	if err := a.repo.SavePaths(ctx, allPaths); err != nil {
		a.logger.Error().Err(err).Str("scenario_id", scenario.ID.String()).Msg("save_paths_error")
	}

	// Update scenario results
	durationMS := int(time.Since(start).Milliseconds())
	shortest, critical := pathStats(allPaths)
	riskScore := scenarioRisk(allPaths)

	if err := a.repo.UpdateScenarioResult(ctx, scenario.ID, len(allPaths), shortest, critical, riskScore, durationMS); err != nil {
		return err
	}

	a.logger.Info().
		Str("scenario_id", scenario.ID.String()).
		Int("paths_found", len(allPaths)).
		Float64("risk_score", riskScore).
		Int("duration_ms", durationMS).
		Msg("scenario_analysis_completed")

	return nil
}

// bfsFind performs BFS from entryID to find all reachable target nodes within maxHops.
func (a *Analyzer) bfsFind(
	ctx context.Context,
	graph map[uuid.UUID][]*model.AttackEdge,
	scenario *model.AttackScenario,
	entryID uuid.UUID,
	targetSet map[uuid.UUID]bool,
) []*model.AttackPath {
	type state struct {
		nodeID    uuid.UUID
		nodeSeq   []uuid.UUID
		edgeSeq   []uuid.UUID
		visited   map[uuid.UUID]bool
		totalCost float64
	}

	var found []*model.AttackPath
	queue := []state{{
		nodeID:  entryID,
		nodeSeq: []uuid.UUID{entryID},
		edgeSeq: []uuid.UUID{},
		visited: map[uuid.UUID]bool{entryID: true},
	}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if len(cur.nodeSeq) > scenario.MaxHops+1 {
			continue
		}

		for _, edge := range graph[cur.nodeID] {
			if !edge.IsActive {
				continue
			}
			next := edge.TargetID
			if cur.visited[next] {
				continue
			}

			newSeqN := append(append([]uuid.UUID{}, cur.nodeSeq...), next)
			newSeqE := append(append([]uuid.UUID{}, cur.edgeSeq...), edge.ID)
			newCost := cur.totalCost + edge.Weight
			newVisited := make(map[uuid.UUID]bool, len(cur.visited)+1)
			for k, v := range cur.visited {
				newVisited[k] = v
			}
			newVisited[next] = true

			if targetSet[next] {
				path := a.buildPath(scenario, entryID, next, newSeqN, newSeqE, newCost)
				found = append(found, path)
				// Don't stop — continue to find all paths, but cap total results
				if len(found) >= 200 {
					return found
				}
			}

			queue = append(queue, state{
				nodeID:    next,
				nodeSeq:   newSeqN,
				edgeSeq:   newSeqE,
				visited:   newVisited,
				totalCost: newCost,
			})
		}
	}
	return found
}

func (a *Analyzer) buildPath(
	scenario *model.AttackScenario,
	entryID, targetID uuid.UUID,
	nodeSeq, edgeSeq []uuid.UUID,
	totalCost float64,
) *model.AttackPath {
	hopCount := len(nodeSeq) - 1

	// Normalize path score: lower cost → higher threat score
	pathScore := math.Min(10.0, 10.0/math.Max(totalCost, 1.0)*float64(hopCount))

	// Likelihood decreases with each hop (attacker detection risk)
	likelihood := math.Pow(0.85, float64(hopCount))

	// Impact based on target criticality (approximated from scenario)
	impact := 7.0 // default high-value target impact

	return &model.AttackPath{
		ID:           uuid.New(),
		TenantID:     scenario.TenantID,
		ScenarioID:   scenario.ID,
		EntryNodeID:  entryID,
		TargetNodeID: targetID,
		NodeSequence: nodeSeq,
		EdgeSequence: edgeSeq,
		HopCount:     hopCount,
		PathScore:    pathScore,
		Likelihood:   likelihood,
		Impact:       impact,
		PathType:     model.PathTypeLateralMovement,
		MitreTactics: []string{},
		DiscoveredAt: time.Now().UTC(),
	}
}

// buildGraph loads all active edges into an in-memory adjacency list.
func (a *Analyzer) buildGraph(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID][]*model.AttackEdge, error) {
	edges, err := a.repo.ListEdges(ctx, tenantID, nil, true)
	if err != nil {
		return nil, err
	}
	graph := make(map[uuid.UUID][]*model.AttackEdge)
	for _, e := range edges {
		graph[e.SourceID] = append(graph[e.SourceID], e)
	}
	return graph, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// computeChokePoints identifies the most impactful node in each path to block.
func computeChokePoints(paths []*model.AttackPath) {
	// Count how often each intermediate node appears across all paths
	nodeCounts := make(map[uuid.UUID]int)
	for _, p := range paths {
		// Skip first (entry) and last (target) — only intermediate nodes are choke points
		if len(p.NodeSequence) <= 2 {
			continue
		}
		for _, nid := range p.NodeSequence[1 : len(p.NodeSequence)-1] {
			nodeCounts[nid]++
		}
	}

	// For each path, pick the intermediate node with highest count as the choke point
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
	// Risk = max path score adjusted by number of paths (more paths = higher risk)
	maxScore := 0.0
	for _, p := range paths {
		if p.PathScore > maxScore {
			maxScore = p.PathScore
		}
	}
	// Boost for many paths: each additional path adds diminishing risk
	boost := math.Log1p(float64(len(paths))) * 0.3
	return math.Min(10.0, maxScore+boost)
}
