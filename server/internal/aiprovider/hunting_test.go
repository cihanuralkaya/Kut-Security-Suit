package aiprovider

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/entitygraph"
)

// TestHuntingAgent_GenerateHypotheses tests hypothesis generation.
func TestHuntingAgent_GenerateHypotheses(t *testing.T) {
	agent := &HuntingAgent{}

	hypotheses, err := agent.GenerateHypotheses(context.Background(), "Execution")
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(hypotheses) == 0 {
		t.Fatal("en az bir hipotez üretilmeliydi")
	}
	if hypotheses[0].MITRETactic != "Execution" {
		t.Errorf("beklenen taktik 'Execution', alınan '%s'", hypotheses[0].MITRETactic)
	}
}

// TestHuntingAgent_ExecuteHunt tests graph hunt traversal and finding generation.
func TestHuntingAgent_ExecuteHunt(t *testing.T) {
	graph := entitygraph.New()

	agent := &HuntingAgent{
		Graph: graph,
	}

	hyp := HuntHypothesis{
		ID:         "hyp-1",
		TargetKind: entitygraph.Process,
	}

	// 1. Boş graf üzerinde bulgu olmamalıdır
	findings, err := agent.ExecuteHunt(context.Background(), hyp)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("beklenen bulgu sayısı 0, alınan %d", len(findings))
	}

	// 2. Graf üzerinde nadir bir süreç bağlantısı ekle
	pNode := entitygraph.Node{Kind: entitygraph.Process, ID: "proc-123"}
	ipNode := entitygraph.Node{Kind: entitygraph.IP, ID: "198.51.100.23"}
	graph.Observe(pNode, ipNode, entitygraph.Connected, time.Now())

	findings2, err := agent.ExecuteHunt(context.Background(), hyp)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(findings2) != 1 {
		t.Fatalf("beklenen bulgu sayısı 1, alınan %d", len(findings2))
	}
	if findings2[0].TargetNode.ID != "proc-123" {
		t.Errorf("beklenen hedef node proc-123, alınan %s", findings2[0].TargetNode.ID)
	}
	if len(findings2[0].SuspiciousEdges) != 1 {
		t.Errorf("beklenen şüpheli kenar sayısı 1, alınan %d", len(findings2[0].SuspiciousEdges))
	}
}
