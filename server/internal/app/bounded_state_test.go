package app

import (
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/metrics"
)

// bakım döngüsünün çağırdığı süpürme eski kenar/kaynakları gerçekten atar ve sayaçlar
// /metrics'e yansır (Prune'un üretimde çağıranı yoktu).
func TestSweepBoundedStateAndMetrics(t *testing.T) {
	g := entitygraph.New()
	g.SetLimits(entitygraph.Limits{MaxEdgesPerTenant: 3})
	sm := aibrain.NewSeqModels()
	old := time.Now().Add(-90 * 24 * time.Hour)
	dev := entitygraph.Node{Kind: entitygraph.Device, ID: "d", Tenant: "a"}
	for _, id := range []string{"old1", "old2"} {
		g.Observe(dev, entitygraph.Node{Kind: entitygraph.Domain, ID: id, Tenant: "a"}, entitygraph.Resolved, old)
	}
	sm.Observe("a", []string{"p", "q"})
	// Tavan aşımı: 5 yeni kenar → tahliye sayacı artar.
	for i := 0; i < 5; i++ {
		g.Observe(dev, entitygraph.Node{Kind: entitygraph.Domain, ID: "n" + string(rune('a'+i)), Tenant: "a"}, entitygraph.Resolved, time.Now())
	}
	publishBoundedMetrics(g, sm)
	var sb strings.Builder
	metrics.Write(&sb, metrics.Snapshot{})
	if !strings.Contains(sb.String(), "kut_graph_evicted_total 4") {
		t.Fatalf("tahliye sayacı /metrics'e yansımalı:\n%s", sb.String())
	}

	// Süpürme: 30 günden eski olay-zamanlı kenarlar zaten tahliye edilmiş olabilir; kalanlardan
	// eski olanlar atılır, sekans kaynağı (taze) korunur.
	edges, srcs := sweepBoundedState(g, sm, time.Now().Add(40*24*time.Hour), 30*24*time.Hour)
	if edges == 0 || srcs != 1 {
		t.Fatal("TTL süpürmesi kenar atmalı")
	}
	if g.Size() != 0 {
		t.Fatalf("tüm kenarlar süpürülmeli (hepsi >30g sonrası): %d", g.Size())
	}
	if sm.Stats().Sources != 0 || sm.Stats().Pruned != 1 {
		t.Fatalf("sekans kaynağı da TTL ile atılmalı: %+v", sm.Stats())
	}
	publishBoundedMetrics(g, sm)
}

// KUT_GRAPH_TTL: ayarsız → varsayılan; "0" → süpürme KAPALI (0); geçersiz/negatif → varsayılan.
func TestGraphTTLFromEnv(t *testing.T) {
	def := 720 * time.Hour
	cases := map[string]time.Duration{"": def, "0": 0, "0s": 0, "48h": 48 * time.Hour, "-5h": def, "junk": def}
	for in, want := range cases {
		t.Setenv("KUT_GRAPH_TTL", in)
		if got := graphTTLFromEnv(def); got != want {
			t.Errorf("KUT_GRAPH_TTL=%q → %v, want %v", in, got, want)
		}
	}
}
