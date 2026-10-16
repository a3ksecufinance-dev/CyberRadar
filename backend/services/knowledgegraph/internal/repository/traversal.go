package repository

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
)

// This file holds the traversal itself, apart from any store.
//
// Both graph stores run this same walk and differ only in how they answer one
// question — "which live relationships touch these entities?". Keeping the
// algorithm in one place is what makes the two stores comparable: a difference
// between them can only come from the data or from that one query, never from
// two implementations of breadth-first search drifting apart.

// maxNeighbors bounds one traversal.
//
// A hub entity — a shared jump host, a corporate egress IP — can reach most of
// a tenant's graph within three hops. Returning it is neither useful to an
// analyst nor renderable by the graph view, so the traversal refuses instead of
// answering with an arbitrary subset: a silent partial answer to "what is this
// connected to" is the one answer that cannot be checked.
const maxNeighbors = 2000

// adjacencyFunc returns the live relationships touching any entity in the
// frontier, in the requested direction and of the requested types.
type adjacencyFunc func(ctx context.Context, frontier []uuid.UUID) ([]*model.KGRelationship, error)

// entityLoader fetches entities by identifier, scoped to one tenant.
type entityLoader func(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]*model.KGEntity, error)

// walk expands outward from one entity and returns everything it reaches, each
// at the fewest hops that reach it.
//
// It expands one hop at a time, keeping a set of entities already seen, rather
// than enumerating paths. The recursive CTE this replaces excluded repeats per
// path, not globally, so it enumerated every simple path: on a graph where an
// entity has a hundred neighbours, five hops is ten billion rows. Its "both"
// form — the default the handler and Enrich both use — also referenced the
// recursive term from a seed branch, so PostgreSQL rejected the query outright:
// every neighbour lookup made with the defaults failed, and Enrich turned that
// failure into a warning and an empty neighbour list.
func walk(ctx context.Context, q model.NeighborQuery,
	adjacent adjacencyFunc, load entityLoader) ([]model.KGNeighbor, error) {

	maxHops := clampHops(q.MaxHops)
	visited := map[uuid.UUID]bool{q.EntityID: true}
	pathTo := map[uuid.UUID][]uuid.UUID{q.EntityID: {q.EntityID}}
	frontier := []uuid.UUID{q.EntityID}

	var found []model.KGNeighbor
	for depth := 1; depth <= maxHops && len(frontier) > 0; depth++ {
		rels, err := adjacent(ctx, frontier)
		if err != nil {
			return nil, fmt.Errorf("neighbors hop %d: %w", depth, err)
		}
		inFrontier := make(map[uuid.UUID]bool, len(frontier))
		for _, id := range frontier {
			inFrontier[id] = true
		}

		var next []uuid.UUID
		for _, rel := range rels {
			for _, hop := range stepsFrom(rel, inFrontier, q.Direction) {
				if visited[hop.to] {
					continue
				}
				visited[hop.to] = true
				pathTo[hop.to] = append(append([]uuid.UUID{}, pathTo[hop.from]...), hop.to)
				found = append(found, model.KGNeighbor{
					Relationship: *rel,
					Depth:        depth,
					Path:         pathTo[hop.to],
				})
				next = append(next, hop.to)
				if len(found) > maxNeighbors {
					return nil, apierrors.New(apierrors.KindBadInput, fmt.Sprintf(
						"this entity reaches more than %d others within %d hop(s) — ask for fewer hops or filter by relationship type",
						maxNeighbors, maxHops))
				}
			}
		}
		frontier = next
	}

	return attachEntities(ctx, found, load)
}

// step is one hop: the frontier entity it left from, and the entity it reached.
type step struct{ from, to uuid.UUID }

// stepsFrom works out which way a relationship was traversed.
//
// Under "both" a relationship can be reached from either end, and both ends can
// be in the frontier at once — two entities one hop apart that are also joined
// to each other. Each direction is then its own step.
func stepsFrom(rel *model.KGRelationship, inFrontier map[uuid.UUID]bool, direction string) []step {
	var steps []step
	if direction != "inbound" && inFrontier[rel.SourceID] {
		steps = append(steps, step{from: rel.SourceID, to: rel.TargetID})
	}
	if direction != "outbound" && inFrontier[rel.TargetID] {
		steps = append(steps, step{from: rel.TargetID, to: rel.SourceID})
	}
	return steps
}

func clampHops(hops int) int {
	if hops <= 0 {
		return 2
	}
	if hops > 5 {
		return 5
	}
	return hops
}

// relTypeFilter normalises the requested relationship types.
//
// The API parsed rel_types, the service carried it and the traversal never read
// it: restricting a neighbour query to CONNECTS_TO returned the same answer as
// asking for everything. Empty means no restriction; blanks are dropped so
// "?rel_types=" does not filter everything out.
func relTypeFilter(relTypes []string) []string {
	out := make([]string, 0, len(relTypes))
	for _, t := range relTypes {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// attachEntities fills in the entity each neighbour record points at, and drops
// any whose entity is gone. The order is fixed — shallowest first, then by
// identifier — so a caller, a test, or a comparison between two graph stores
// sees the same list every time.
func attachEntities(ctx context.Context, found []model.KGNeighbor, load entityLoader) ([]model.KGNeighbor, error) {
	ids := make([]uuid.UUID, 0, len(found))
	for _, n := range found {
		ids = append(ids, n.Path[len(n.Path)-1])
	}
	entities, err := load(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("neighbors: load entities: %w", err)
	}

	out := make([]model.KGNeighbor, 0, len(found))
	for _, n := range found {
		e, ok := entities[n.Path[len(n.Path)-1]]
		if !ok {
			continue
		}
		n.Entity = *e
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].Entity.ID.String() < out[j].Entity.ID.String()
	})
	return out, nil
}
