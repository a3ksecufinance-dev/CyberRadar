package model

// DiscoveredPath is one route from an entry point to a target: the nodes it
// passes through and the edges it uses, in order.
//
// It carries the nodes and edges themselves rather than their identifiers so
// that scoring needs nothing else — no second lookup, and no graph held in
// memory to resolve them against.
//
// It lives in model rather than beside the traversal because both sides name
// it: the stores that enumerate routes and the analyzer that scores them.
// Scoring is deliberately not the store's business — the weightings are an
// institutional judgement that has to stay readable and arguable in one place.
type DiscoveredPath struct {
	Nodes []*AttackNode
	Edges []*AttackEdge
}

// Entry is the path's first node.
func (p DiscoveredPath) Entry() *AttackNode { return p.Nodes[0] }

// Target is the path's last node.
func (p DiscoveredPath) Target() *AttackNode { return p.Nodes[len(p.Nodes)-1] }

// StandardCost is the total traversal weight the stores recorded when the edges
// were created.
//
// It is NOT what an analysis uses. Scoring reads AttackPolicy.PathCost, which
// recomputes from each edge's own complexity and privilege requirement under
// the tenant's weightings — the stored weight is written once, at creation, so
// a stance that only applied to edges discovered afterwards would re-rank half
// a graph and leave the other half alone.
//
// Kept, and named apart from the policy's cost, because the parity tests
// compare two stores' enumerations and need a figure neither of them chose.
func (p DiscoveredPath) StandardCost() float64 {
	var total float64
	for _, e := range p.Edges {
		total += e.Weight
	}
	return total
}
