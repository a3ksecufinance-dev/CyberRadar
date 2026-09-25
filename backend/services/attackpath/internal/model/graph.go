package model

import "github.com/google/uuid"

// Graph is a tenant's attack graph, ready to traverse.
//
// It lives in model rather than beside the traversal so that both the store
// that loads it and the analyzer that walks it can name it without either
// importing the other.
type Graph struct {
	Nodes map[uuid.UUID]*AttackNode
	// Out is the adjacency list: node → the active edges leaving it.
	Out map[uuid.UUID][]*AttackEdge
}

// NewGraph builds the adjacency list from a flat node and edge set. Inactive
// edges are dropped here, so a traversal cannot forget to check.
func NewGraph(nodes []*AttackNode, edges []*AttackEdge) *Graph {
	g := &Graph{
		Nodes: make(map[uuid.UUID]*AttackNode, len(nodes)),
		Out:   make(map[uuid.UUID][]*AttackEdge),
	}
	for _, n := range nodes {
		g.Nodes[n.ID] = n
	}
	for _, e := range edges {
		if e.IsActive {
			g.Out[e.SourceID] = append(g.Out[e.SourceID], e)
		}
	}
	return g
}
