package service

import (
	"context"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

// GraphMirror receives a copy of every write that changes the attack graph.
//
// It exists so the graph can be kept in a second store — Neo4j — while
// PostgreSQL stays the source of truth. Only the graph is mirrored: scenarios
// and the paths a run discovers are records, not topology, and stay relational.
type GraphMirror interface {
	MirrorNode(ctx context.Context, n *model.AttackNode) error
	MirrorEdge(ctx context.Context, e *model.AttackEdge) error
	MirrorCompromised(ctx context.Context, tenantID, nodeID uuid.UUID, compromised bool) error
}

// mirrorFailures counts writes PostgreSQL accepted and the mirror did not.
//
// Any value above zero means the two stores have drifted, so it belongs on the
// dashboard next to the reconciliation the operator runs: the counter says that
// something diverged, Reconcile says what.
var mirrorFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "attackpath_graph_mirror_failures_total",
	Help: "Graph writes accepted by PostgreSQL that the mirrored graph store refused.",
}, []string{"kind"})

func init() { observe.MustRegister(mirrorFailures) }

// mirrorTimeout bounds one mirrored write. It is short on purpose: past it the
// write is recorded as a divergence for Reconcile to pick up, which is cheaper
// than holding the caller.
const mirrorTimeout = 5 * time.Second

// AttackPathService orchestrates graph management and path analysis.
type AttackPathService struct {
	repo *repository.GraphRepository
	// store is what the traversal reads. It defaults to repo, and is the
	// Neo4j store when a deployment has switched reads over.
	store    GraphStore
	mirror   GraphMirror
	analyzer *Analyzer
	logger   zerolog.Logger
}

// Option configures an AttackPathService.
type Option func(*AttackPathService)

// WithGraphStore points the traversal at a store other than PostgreSQL.
//
// This is the read switch of the Neo4j migration: it changes where the graph is
// read from and nothing else, which is what makes parity between the two stores
// the only thing that has to be established before flipping it.
func WithGraphStore(store GraphStore) Option {
	return func(s *AttackPathService) {
		if store != nil {
			s.store = store
		}
	}
}

// WithMirror copies every graph write to a second store.
func WithMirror(m GraphMirror) Option {
	return func(s *AttackPathService) { s.mirror = m }
}

// NewAttackPathService creates an AttackPathService.
func NewAttackPathService(repo *repository.GraphRepository, logger zerolog.Logger, opts ...Option) *AttackPathService {
	s := &AttackPathService{repo: repo, store: repo, logger: logger}
	for _, opt := range opts {
		opt(s)
	}
	s.analyzer = NewAnalyzer(s.store, logger)
	return s
}

// mirrorWrite copies to the secondary store a write PostgreSQL has accepted.
//
// A mirror failure does not fail the request. PostgreSQL is the source of
// truth, and making the write depend on the mirror would turn a secondary store
// into an availability dependency of the primary — a graph the platform could
// no longer record because a reporting database was down. The failure is
// logged and counted instead, and Reconcile turns that into the list of what
// actually diverged.
func (s *AttackPathService) mirrorWrite(ctx context.Context, kind string, write func(context.Context) error) {
	if s.mirror == nil {
		return
	}
	// The mirror gets its own short deadline, detached from the request's
	// cancellation. Detached, because a client that hangs up must not leave the
	// two stores in different states; short, because the write has already been
	// accepted and the caller is waiting on a copy that is allowed to fail.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mirrorTimeout)
	defer cancel()

	if err := write(ctx); err != nil {
		mirrorFailures.WithLabelValues(kind).Inc()
		s.logger.Error().Err(err).Str("kind", kind).Msg("graph_mirror_write_failed")
	}
}

// ─── Nodes ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) UpsertNode(ctx context.Context, tenantID uuid.UUID, req *model.CreateNodeRequest) (*model.AttackNode, error) {
	n, err := s.repo.UpsertNode(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert node", err)
	}
	s.mirrorWrite(ctx, "node", func(ctx context.Context) error { return s.mirror.MirrorNode(ctx, n) })
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
	s.mirrorWrite(ctx, "compromised", func(ctx context.Context) error {
		return s.mirror.MirrorCompromised(ctx, tenantID, nodeID, compromised)
	})
	return nil
}

// ─── Edges ────────────────────────────────────────────────────────────────────

func (s *AttackPathService) UpsertEdge(ctx context.Context, tenantID uuid.UUID, req *model.CreateEdgeRequest) (*model.AttackEdge, error) {
	e, err := s.repo.UpsertEdge(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert edge", err)
	}
	s.mirrorWrite(ctx, "edge", func(ctx context.Context) error { return s.mirror.MirrorEdge(ctx, e) })
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
