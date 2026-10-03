package coordinator

import (
	"testing"
	"time"
)

func TestRegisterAndHeartbeat(t *testing.T) {
	router := NewRegionalRouter()

	node := EdgeNode{
		ID:     "node-1",
		Region: "eu-central-1",
	}

	err := router.RegisterEdgeNode(node)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = router.Heartbeat("node-1", 15)
	if err != nil {
		t.Fatalf("expected no error on heartbeat, got %v", err)
	}

	router.mu.RLock()
	n := router.nodes["node-1"]
	router.mu.RUnlock()
	
	if n.LatencyMs != 15 {
		t.Errorf("expected latency 15, got %d", n.LatencyMs)
	}
	if n.Status != "healthy" {
		t.Errorf("expected status healthy, got %s", n.Status)
	}
}

func TestRouteTelemetry(t *testing.T) {
	router := NewRegionalRouter()
	router.SetTenantPrimaryRegion("tenant-1", "eu-central-1")

	// Add node in primary region (high latency)
	router.RegisterEdgeNode(EdgeNode{
		ID:        "node-eu-1",
		Region:    "eu-central-1",
		LatencyMs: 100,
		Status:    "healthy",
	})
	
	// Add node in primary region (low latency)
	router.RegisterEdgeNode(EdgeNode{
		ID:        "node-eu-2",
		Region:    "eu-central-1",
		LatencyMs: 20,
		Status:    "healthy",
	})

	// Add node in fallback region (very low latency, shouldn't be picked over primary)
	router.RegisterEdgeNode(EdgeNode{
		ID:        "node-us-1",
		Region:    "us-east-1",
		LatencyMs: 10,
		Status:    "healthy",
	})

	// Route should pick node-eu-2
	node, err := router.RouteTelemetry("tenant-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if node.ID != "node-eu-2" {
		t.Errorf("expected node-eu-2, got %s", node.ID)
	}
}

func TestRegionalFailover(t *testing.T) {
	router := NewRegionalRouter()
	router.SetTenantPrimaryRegion("tenant-1", "eu-central-1")

	// Node in primary region is offline
	router.RegisterEdgeNode(EdgeNode{
		ID:        "node-eu-1",
		Region:    "eu-central-1",
		LatencyMs: 20,
		Status:    "offline",
	})

	// Healthy node in fallback region
	router.RegisterEdgeNode(EdgeNode{
		ID:        "node-us-1",
		Region:    "us-east-1",
		LatencyMs: 50,
		Status:    "healthy",
	})

	// Route should fallback to node-us-1
	node, err := router.RouteTelemetry("tenant-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if node.ID != "node-us-1" {
		t.Errorf("expected node-us-1, got %s", node.ID)
	}
}

func TestPruneStaleNodes(t *testing.T) {
	router := NewRegionalRouter()

	router.RegisterEdgeNode(EdgeNode{
		ID:     "node-1",
		Region: "eu-central-1",
	})
	
	router.RegisterEdgeNode(EdgeNode{
		ID:     "node-2",
		Region: "eu-central-1",
	})

	// Simulate node-1 being old
	router.mu.Lock()
	router.nodes["node-1"].LastHeartbeat = time.Now().Add(-10 * time.Minute)
	router.mu.Unlock()

	pruned := router.PruneStaleNodes(5 * time.Minute)
	if pruned != 1 {
		t.Errorf("expected 1 pruned node, got %d", pruned)
	}

	router.mu.RLock()
	if _, exists := router.nodes["node-1"]; exists {
		t.Errorf("node-1 should have been pruned")
	}
	if _, exists := router.nodes["node-2"]; !exists {
		t.Errorf("node-2 should not have been pruned")
	}
	router.mu.RUnlock()
}
