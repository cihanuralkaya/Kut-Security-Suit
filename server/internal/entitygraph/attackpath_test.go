package entitygraph

import (
	"testing"
	"time"
)

func TestAttackPath_FindPaths(t *testing.T) {
	g := New()
	now := time.Now()

	// External IP -> Workstation -> Admin User -> Domain Controller
	extIP := Node{Kind: IP, ID: "198.51.100.20"}
	workstation := Node{Kind: Device, ID: "ws-accounting-01"}
	adminUser := Node{Kind: User, ID: "svc-domain-admin"}
	dc := Node{Kind: Device, ID: "dc-primary-01"}
	altGateway := Node{Kind: IP, ID: "10.0.0.1"}

	// Path 1: extIP -> workstation -> adminUser -> dc
	g.Observe(extIP, workstation, Connected, now)
	g.Observe(workstation, adminUser, LoggedIn, now)
	g.Observe(adminUser, dc, LoggedIn, now)

	// Path 2: extIP -> altGateway -> adminUser -> dc
	g.Observe(extIP, altGateway, Connected, now)
	g.Observe(altGateway, adminUser, Connected, now)

	// 1. Find paths with maxHops=3
	paths := g.FindPaths(extIP, dc, 3)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths from extIP to dc, found %d", len(paths))
	}

	for _, p := range paths {
		if p.Length() != 3 {
			t.Errorf("expected path length 3, got %d", p.Length())
		}
		nodes := p.Nodes()
		if len(nodes) != 4 {
			t.Errorf("expected 4 nodes in path, got %d", len(nodes))
		}
		if nodes[0] != extIP || nodes[len(nodes)-1] != dc {
			t.Errorf("path start/end mismatch: start=%v, end=%v", nodes[0], nodes[len(nodes)-1])
		}
	}

	// 2. Find paths with maxHops=2 (should find 0, min hops is 3)
	shortPaths := g.FindPaths(extIP, dc, 2)
	if len(shortPaths) != 0 {
		t.Fatalf("expected 0 paths with maxHops=2, got %d", len(shortPaths))
	}
}

func TestAttackPath_ScorePath(t *testing.T) {
	g := New()
	now := time.Now()

	n1 := Node{Kind: IP, ID: "1.1.1.1"}
	n2 := Node{Kind: Device, ID: "dev-1"}
	n3 := Node{Kind: Device, ID: "dev-2"}

	// Rare edges (count = 1)
	g.Observe(n1, n2, Connected, now)
	g.Observe(n2, n3, Connected, now)

	paths := g.FindPaths(n1, n3, 2)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}

	rareScore := ScorePath(paths[0])
	if rareScore <= 0.5 {
		t.Errorf("expected high risk score for rare path, got %f", rareScore)
	}

	// Now make edges common by observing them repeatedly
	for i := 0; i < 50; i++ {
		g.Observe(n1, n2, Connected, now)
		g.Observe(n2, n3, Connected, now)
	}

	commonPaths := g.FindPaths(n1, n3, 2)
	commonScore := ScorePath(commonPaths[0])
	if commonScore >= rareScore {
		t.Errorf("common path should have lower risk than rare path: common=%f, rare=%f", commonScore, rareScore)
	}
}

func TestAttackPath_IdentifyChokePoints(t *testing.T) {
	g := New()
	now := time.Now()

	src := Node{Kind: IP, ID: "attacker"}
	target := Node{Kind: Device, ID: "crown-jewels"}

	bridge := Node{Kind: User, ID: "compromised-admin"}
	alt1 := Node{Kind: Device, ID: "path1-step"}
	alt2 := Node{Kind: Device, ID: "path2-step"}

	// Both paths converge on 'bridge' before reaching target
	g.Observe(src, alt1, Connected, now)
	g.Observe(alt1, bridge, LoggedIn, now)

	g.Observe(src, alt2, Connected, now)
	g.Observe(alt2, bridge, LoggedIn, now)

	g.Observe(bridge, target, Connected, now)

	paths := g.FindPaths(src, target, 4)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	chokePoints := IdentifyChokePoints(paths, src, target)
	if len(chokePoints) == 0 {
		t.Fatal("expected choke points, found none")
	}

	// 'bridge' should be the top choke point with PathCount = 2
	if chokePoints[0].Node != bridge || chokePoints[0].PathCount != 2 {
		t.Errorf("expected top choke point to be 'bridge' with 2 paths, got %+v", chokePoints[0])
	}
}
