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
	// TargetKind, grafın küçük-harf kind'iyle (entitygraph.Process) eşleşmeli — aksi halde
	// ExecuteHunt'ın NodesByKind'ı hiçbir düğüm bulamazdı (aktivasyon-bulgusu regresyon-guard'ı).
	if hypotheses[0].TargetKind != entitygraph.Process {
		t.Errorf("TargetKind entitygraph.Process olmalı, alınan %q", hypotheses[0].TargetKind)
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
	findings, err := agent.ExecuteHunt(context.Background(), hyp, HuntScope{AllTenants: true})
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

	findings2, err := agent.ExecuteHunt(context.Background(), hyp, HuntScope{AllTenants: true})
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

// Z5-03: av koşusu çağıranın kiracısıyla kısıtlıdır — başka kiracının süreç/IP düğümleri ve
// kenarları DÖNMEZ (negatif); sahibi kendi bulgusunu görür (pozitif); platform tümünü görür.
func TestHuntingAgent_ExecuteHuntTenantScoped(t *testing.T) {
	g := entitygraph.New()
	now := time.Now()
	g.Observe(entitygraph.Node{Kind: entitygraph.Process, ID: "proc-acme", Tenant: "acme"},
		entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.1", Tenant: "acme"}, entitygraph.Connected, now)
	g.Observe(entitygraph.Node{Kind: entitygraph.Process, ID: "proc-globex", Tenant: "globex"},
		entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.2", Tenant: "globex"}, entitygraph.Connected, now)
	agent := &HuntingAgent{Graph: g}
	hyp := HuntHypothesis{ID: "h", TargetKind: entitygraph.Process}
	ctx := context.Background()

	acme, err := agent.ExecuteHunt(ctx, hyp, HuntScope{Tenant: "acme"})
	if err != nil || len(acme) != 1 || acme[0].TargetNode.ID != "proc-acme" {
		t.Fatalf("acme yalnız kendi düğümünü görmeli: %+v %v", acme, err)
	}
	for _, f := range acme {
		for _, e := range f.SuspiciousEdges {
			if e.To.ID == "203.0.113.2" {
				t.Fatal("acme, globex'in uzak IP'sini görmemeli")
			}
		}
	}
	globex, _ := agent.ExecuteHunt(ctx, hyp, HuntScope{Tenant: "globex"})
	if len(globex) != 1 || globex[0].TargetNode.ID != "proc-globex" {
		t.Fatalf("globex yalnız kendi düğümünü görmeli: %+v", globex)
	}
	// Kiracı belirtilmeden (AllTenants=false) KAPSAM "hepsi" ANLAMINA GELMEZ (fail-closed).
	none, _ := agent.ExecuteHunt(ctx, hyp, HuntScope{})
	if len(none) != 0 {
		t.Fatalf("boş kapsam hiçbir kiracının düğümünü döndürmemeli: %+v", none)
	}
	// Platform: tümü.
	all, _ := agent.ExecuteHunt(ctx, hyp, HuntScope{AllTenants: true})
	if len(all) != 2 {
		t.Fatalf("platform iki kiracıyı da görmeli: %+v", all)
	}
}
