package entitygraph

import (
	"sort"
)

// Path represents an attack path: an ordered sequence of observed relationship edges.
type Path struct {
	Edges []*Edge
}

// Length returns the number of hops in the path.
func (p Path) Length() int {
	return len(p.Edges)
}

// Nodes returns the sequential list of nodes visited along this path.
func (p Path) Nodes() []Node {
	if len(p.Edges) == 0 {
		return nil
	}
	nodes := make([]Node, 0, len(p.Edges)+1)
	nodes = append(nodes, p.Edges[0].From)
	for _, e := range p.Edges {
		nodes = append(nodes, e.To)
	}
	return nodes
}

// FindPaths traverses the graph to discover all directed paths from source to target
// within a maximum hop limit (maxHops). Prevents cycles by tracking visited nodes.
func (g *Graph) FindPaths(source, target Node, maxHops int) []Path {
	if maxHops <= 0 {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []Path
	visited := map[Node]bool{source: true}
	var currentEdges []*Edge

	var dfs func(curr Node, hopsLeft int)
	dfs = func(curr Node, hopsLeft int) {
		if curr == target && len(currentEdges) > 0 {
			// Path found
			pathCopy := make([]*Edge, len(currentEdges))
			copy(pathCopy, currentEdges)
			results = append(results, Path{Edges: pathCopy})
			return
		}

		if hopsLeft <= 0 {
			return
		}

		outEdges := g.out[curr]
		if outEdges == nil {
			return
		}

		// Sort edges deterministically
		sortedEdges := make([]*Edge, 0, len(outEdges))
		for _, e := range outEdges {
			sortedEdges = append(sortedEdges, e)
		}
		sort.Slice(sortedEdges, func(i, j int) bool {
			if sortedEdges[i].To.Kind != sortedEdges[j].To.Kind {
				return sortedEdges[i].To.Kind < sortedEdges[j].To.Kind
			}
			return sortedEdges[i].To.ID < sortedEdges[j].To.ID
		})

		for _, edge := range sortedEdges {
			next := edge.To
			if !visited[next] {
				visited[next] = true
				currentEdges = append(currentEdges, edge)

				dfs(next, hopsLeft-1)

				currentEdges = currentEdges[:len(currentEdges)-1]
				visited[next] = false
			}
		}
	}

	dfs(source, maxHops)
	return results
}

// ScorePath calculates an anomaly/risk score for an attack path (0.0 to 1.0).
// Heuristic:
// - Shorter paths from entry to target are higher urgency.
// - Rare edges (low observation Count <= 3) significantly increase anomaly score.
// - High observation edges (benign/routine activity) dampen the risk score.
func ScorePath(p Path) float64 {
	if len(p.Edges) == 0 {
		return 0.0
	}

	rareEdges := 0
	totalCount := 0

	for _, e := range p.Edges {
		totalCount += e.Count
		if e.Count <= 3 {
			rareEdges++
		}
	}

	// Ratio of rare (anomalous) edges in the path
	rarityScore := float64(rareEdges) / float64(len(p.Edges))

	// Hop urgency factor (1-hop = 1.0, 2-hops = 0.85, 3-hops = 0.70, etc.)
	hopFactor := 1.0 / (1.0 + 0.15*float64(len(p.Edges)-1))

	score := (0.65 * rarityScore) + (0.35 * hopFactor)
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ChokePoint represents a critical entity node appearing across multiple attack paths.
type ChokePoint struct {
	Node      Node
	PathCount int
}

// IdentifyChokePoints identifies intermediate nodes that occur across multiple paths.
// Isolating or monitoring a choke point breaks the greatest number of potential attack paths.
func IdentifyChokePoints(paths []Path, excludeStart, excludeTarget Node) []ChokePoint {
	if len(paths) == 0 {
		return nil
	}

	counts := make(map[Node]int)
	for _, p := range paths {
		seenInPath := make(map[Node]bool)
		for _, node := range p.Nodes() {
			if node == excludeStart || node == excludeTarget {
				continue
			}
			if !seenInPath[node] {
				seenInPath[node] = true
				counts[node]++
			}
		}
	}

	var chokePoints []ChokePoint
	for node, count := range counts {
		if count > 0 {
			chokePoints = append(chokePoints, ChokePoint{
				Node:      node,
				PathCount: count,
			})
		}
	}

	sort.Slice(chokePoints, func(i, j int) bool {
		if chokePoints[i].PathCount != chokePoints[j].PathCount {
			return chokePoints[i].PathCount > chokePoints[j].PathCount
		}
		return chokePoints[i].Node.ID < chokePoints[j].Node.ID
	})

	return chokePoints
}
