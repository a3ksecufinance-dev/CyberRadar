package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// AttackPathService orchestrates graph management and path analysis.
type AttackPathService struct {
	repo     *repository.GraphRepository
	analyzer *Analyzer
	logger   zerolog.Logger
}

// NewAttackPathService creates an AttackPathService.
func NewAttackPathService(repo *repository.GraphRepository, logger zerolog.Logger) *AttackPathService {
	return &AttackPathService{
		repo:     repo,
		analyzer: NewAnalyzer(repo, logger),
		logger:   logger,
	}
}

// ─── Nodes ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) UpsertNode(ctx context.Context, tenantID uuid.UUID, req *model.CreateNodeRequest) (*model.AttackNode, error) {
	n, err := s.repo.UpsertNode(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert node", err)
	}
	return n, nil
}

func (s *AttackPathService) GetNode(ctx context.Context, tenantID, nodeID uuid.UUID) (*model.AttackNode, error) {
	n, err := s.repo.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return nil, apierrors.Internal("get node", err)
	}
	if n == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "node not found")
	}
	return n, nil
}

func (s *AttackPathService) ListNodes(ctx context.Context, f model.NodeFilter) ([]*model.AttackNode, int, error) {
	nodes, total, err := s.repo.ListNodes(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list nodes", err)
	}
	return nodes, total, nil
}

func (s *AttackPathService) MarkCompromised(ctx context.Context, tenantID, nodeID uuid.UUID, compromised bool) error {
	if err := s.repo.MarkCompromised(ctx, tenantID, nodeID, compromised); err != nil {
		return apierrors.Internal("mark compromised", err)
	}
	return nil
}

// ─── Edges ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) UpsertEdge(ctx context.Context, tenantID uuid.UUID, req *model.CreateEdgeRequest) (*model.AttackEdge, error) {
	e, err := s.repo.UpsertEdge(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert edge", err)
	}
	return e, nil
}

func (s *AttackPathService) ListEdges(ctx context.Context, tenantID uuid.UUID, sourceID *uuid.UUID, activeOnly bool) ([]*model.AttackEdge, error) {
	edges, err := s.repo.ListEdges(ctx, tenantID, sourceID, activeOnly)
	if err != nil {
		return nil, apierrors.Internal("list edges", err)
	}
	return edges, nil
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

func (s *AttackPathService) CreateScenario(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateScenarioRequest) (*model.AttackScenario, error) {
	scenario, err := s.repo.CreateScenario(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create scenario", err)
	}
	s.logger.Info().Str("scenario_id", scenario.ID.String()).Str("name", scenario.Name).Msg("attack_scenario_created")
	return scenario, nil
}

func (s *AttackPathService) GetScenario(ctx context.Context, tenantID, scenarioID uuid.UUID) (*model.AttackScenario, error) {
	sc, err := s.repo.GetScenario(ctx, tenantID, scenarioID)
	if err != nil {
		return nil, apierrors.Internal("get scenario", err)
	}
	if sc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "scenario not found")
	}
	return sc, nil
}

func (s *AttackPathService) ListScenarios(ctx context.Context, tenantID uuid.UUID) ([]*model.AttackScenario, error) {
	scenarios, err := s.repo.ListScenarios(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list scenarios", err)
	}
	return scenarios, nil
}

// RunScenario triggers asynchronous path discovery for a scenario.
func (s *AttackPathService) RunScenario(ctx context.Context, tenantID, scenarioID uuid.UUID) error {
	sc, err := s.GetScenario(ctx, tenantID, scenarioID)
	if err != nil {
		return err
	}
	if sc.Status == model.ScenarioStatusRunning {
		return apierrors.New(apierrors.KindBadInput, "scenario is already running")
	}

	// Run asynchronously so the API returns immediately
	go func() {
		bgCtx := context.Background()
		if err := s.analyzer.RunScenario(bgCtx, sc); err != nil {
			s.logger.Error().Err(err).Str("scenario_id", sc.ID.String()).Msg("scenario_run_error")
			_ = s.repo.SetScenarioStatus(bgCtx, sc.ID, model.ScenarioStatusFailed)
		}
	}()
	return nil
}

// ─── Paths ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) ListPaths(ctx context.Context, f model.PathFilter) ([]*model.AttackPath, int, error) {
	paths, total, err := s.repo.ListPaths(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list paths", err)
	}
	return paths, total, nil
}

// GetPathWithGraph returns a path enriched with its node and edge objects.
func (s *AttackPathService) GetPathWithGraph(ctx context.Context, tenantID uuid.UUID, f model.PathFilter) ([]*model.AttackPath, int, error) {
	paths, total, err := s.repo.ListPaths(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list paths", err)
	}
	// Collect all node IDs referenced across paths
	nodeIDSet := make(map[uuid.UUID]bool)
	for _, p := range paths {
		for _, nid := range p.NodeSequence {
			nodeIDSet[nid] = true
		}
	}
	nodeIDs := make([]uuid.UUID, 0, len(nodeIDSet))
	for nid := range nodeIDSet {
		nodeIDs = append(nodeIDs, nid)
	}
	nodeMap, err := s.repo.GetNodesByIDs(ctx, tenantID, nodeIDs)
	if err != nil {
		s.logger.Warn().Err(err).Msg("node_enrichment_error")
	}
	for _, p := range paths {
		for _, nid := range p.NodeSequence {
			if n, ok := nodeMap[nid]; ok {
				p.Nodes = append(p.Nodes, *n)
			}
		}
	}
	return paths, total, nil
}

// ─── Choke Points ─────────────────────────────────────────────────────────────

func (s *AttackPathService) GetChokePoints(ctx context.Context, tenantID uuid.UUID, scenarioID *uuid.UUID, limit int) ([]*model.ChokePoint, error) {
	cps, err := s.repo.ChokePoints(ctx, tenantID, scenarioID, limit)
	if err != nil {
		return nil, apierrors.Internal("choke points", err)
	}
	return cps, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.AttackGraphStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("attack graph stats", err)
	}
	return stats, nil
}
