package app

// bounded_state.go — ajan/ingest kaynaklı bellek-içi durumun (varlık grafı + kiracı-bölümlü
// sekans modeli) SINIRLI tutulması: periyodik TTL süpürmesi ve /metrics için
// düşen/tahliye edilen sayaçların yayınlanması. Sert tavanlar ve LRU tahliyesi veri yapılarının
// kendisinde (entitygraph.Limits / aibrain.SeqLimits) uygulanır; burası yalnız zamanlayıcı bağıdır.

import (
	"context"
	"os"
	"strings"
	"time"

	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/metrics"
)

// sweepBoundedState, TTL'den eski graf kenarlarını ve sekans kaynaklarını atar; atılan sayıları döner.
func sweepBoundedState(g *entitygraph.Graph, sm *aibrain.SeqModels, now time.Time, ttl time.Duration) (edges, seqSources int) {
	cutoff := now.Add(-ttl)
	if g != nil {
		edges = g.Sweep(cutoff)
	}
	if sm != nil {
		seqSources = sm.Prune(cutoff)
	}
	return edges, seqSources
}

// publishBoundedMetrics, graf ve sekans modeli sayaçlarını /metrics'e eşitler (mutlak değerler).
func publishBoundedMetrics(g *entitygraph.Graph, sm *aibrain.SeqModels) {
	if g != nil {
		st := g.Stats()
		metrics.SetGraphStats(st.Dropped, st.Evicted, st.Pruned, int64(st.Edges), int64(st.Nodes))
		metrics.SetGraphDeviceDropped(st.DeviceDropped)
	}
	if sm != nil {
		st := sm.Stats()
		metrics.SetSeqModelStats(st.Dropped, st.Evicted, st.Pruned, int64(st.Sources))
	}
}

// graphTTLFromEnv, KUT_GRAPH_TTL'yi okur: ayarsız/geçersiz/negatif → def; açıkça "0" (ya da "0s")
// → 0 = TTL süpürmesi KAPALI (kenarlar yalnız tavan/LRU ile atılır).
func graphTTLFromEnv(def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv("KUT_GRAPH_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d == 0 {
			return 0
		}
	}
	return getdurEnv("KUT_GRAPH_TTL", def)
}

// runBoundedStateMaintenance, bakım döngüsünü başlatır: her sweepEvery'de TTL süpürmesi, her
// 15 sn'de metrik eşitleme. ctx iptalinde durur. ttl<=0 ise süpürme kapalıdır (yalnız metrik).
func runBoundedStateMaintenance(ctx context.Context, g *entitygraph.Graph, sm *aibrain.SeqModels, ttl, sweepEvery time.Duration) {
	go func() {
		metricsT := time.NewTicker(15 * time.Second)
		defer metricsT.Stop()
		sweepT := time.NewTicker(sweepEvery)
		defer sweepT.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-metricsT.C:
				publishBoundedMetrics(g, sm)
			case now := <-sweepT.C:
				if ttl > 0 {
					sweepBoundedState(g, sm, now, ttl)
				}
				publishBoundedMetrics(g, sm)
			}
		}
	}()
}
