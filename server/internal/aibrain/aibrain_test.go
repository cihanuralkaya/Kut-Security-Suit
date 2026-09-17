package aibrain

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/riskfusion"
)

func TestSequenceRarity(t *testing.T) {
	lp := NewLocalProvider()
	// Taban çizgisi: normal süreç zinciri defalarca gözlenir.
	normal := []string{"explorer.exe", "cmd.exe", "ipconfig.exe"}
	for i := 0; i < 10; i++ {
		lp.Learn(normal)
	}
	ctx := context.Background()

	// Sık görülen dizi → düşük nadirlik.
	common, _ := lp.ScoreSequence(ctx, SequenceInput{Tokens: normal, Kind: "process"})
	if common.Score > 20 {
		t.Fatalf("sık dizi düşük skorlanmalı, %v", common.Score)
	}
	// Hiç görülmemiş geçiş içeren dizi → yüksek nadirlik + açıklama.
	rare, _ := lp.ScoreSequence(ctx, SequenceInput{Tokens: []string{"winword.exe", "powershell.exe", "rundll32.exe"}, Kind: "process"})
	if rare.Score < 80 {
		t.Fatalf("görülmemiş dizi yüksek skorlanmalı, %v", rare.Score)
	}
	if rare.Rationale == "" {
		t.Fatal("nadir dizi açıklama içermeli")
	}
	// 2'den kısa dizi → 0.
	if s, _ := lp.ScoreSequence(ctx, SequenceInput{Tokens: []string{"tek"}}); s.Score != 0 {
		t.Fatalf("tek-token dizi 0 skorlanmalı, %v", s.Score)
	}
}

func TestBrainFailOpenWhenNoProvider(t *testing.T) {
	// nil sağlayıcı → tüm çağrılar ok=false (çekirdek "AI yokmuş gibi" devam eder).
	b := New(nil, 0)
	if b.Enabled() {
		t.Fatal("nil sağlayıcı Enabled()=false olmalı")
	}
	ctx := context.Background()
	if _, ok := b.ScoreSequence(ctx, SequenceInput{Tokens: []string{"a", "b"}}); ok {
		t.Fatal("nil sağlayıcıda ScoreSequence ok=false olmalı")
	}
	if _, ok := b.SuggestTriage(ctx, TriageInput{}); ok {
		t.Fatal("nil sağlayıcıda SuggestTriage ok=false olmalı")
	}
	if _, ok := b.SummarizeIncident(ctx, IncidentInput{}); ok {
		t.Fatal("nil sağlayıcıda SummarizeIncident ok=false olmalı")
	}
	// Bir nil Brain bile panik yapmamalı (savunmacı).
	var nb *Brain
	if _, ok := nb.ScoreSequence(ctx, SequenceInput{}); ok {
		t.Fatal("nil Brain ok=false olmalı")
	}
}

func TestBrainWithLocalProvider(t *testing.T) {
	b := New(NewLocalProvider(), 500*time.Millisecond)
	if !b.Enabled() {
		t.Fatal("yerel sağlayıcı Enabled()=true olmalı")
	}
	if _, ok := b.ScoreSequence(context.Background(), SequenceInput{Tokens: []string{"a", "b"}}); !ok {
		t.Fatal("yerel sağlayıcıda ScoreSequence ok=true olmalı")
	}
}

func TestSuggestTriageUsesRiskFusion(t *testing.T) {
	lp := NewLocalProvider()
	// Yüksek deterministik sinyaller → HIGH/CRITICAL öncelik, FP değil.
	hi, _ := lp.SuggestTriage(context.Background(), TriageInput{Signals: []riskfusion.Signal{
		{Name: "rule", Score: 95, Weight: 1}, {Name: "ioc", Score: 90, Weight: 1},
	}})
	if hi.LikelyFP {
		t.Fatalf("yüksek sinyalli triyaj FP olmamalı: %+v", hi)
	}
	if hi.Priority != "HIGH" && hi.Priority != "CRITICAL" {
		t.Fatalf("yüksek sinyalli triyaj HIGH/CRITICAL olmalı: %q", hi.Priority)
	}
	// Düşük sinyaller → olası FP.
	lo, _ := lp.SuggestTriage(context.Background(), TriageInput{Signals: []riskfusion.Signal{
		{Name: "rule", Score: 10, Weight: 1},
	}})
	if !lo.LikelyFP {
		t.Fatalf("düşük sinyalli triyaj olası-FP olmalı: %+v", lo)
	}
}

func TestScoreGraphAndExplainRisk(t *testing.T) {
	lp := NewLocalProvider()
	// Yüksek fan-out + nadir kenar → yüksek yapısal anomali.
	gs, _ := lp.ScoreGraph(context.Background(), GraphInput{Features: GraphFeatures{FanOut: 20, RareEdges: 10, NewNodeRatio: 1}})
	if gs.Score < 80 {
		t.Fatalf("yüksek fan-out/nadir kenar yüksek skorlanmalı: %v", gs.Score)
	}
	// ExplainRisk katkıları içermeli.
	res := riskfusion.Fuse([]riskfusion.Signal{{Name: "ioc", Score: 90, Weight: 2}, {Name: "rule", Score: 50, Weight: 1}})
	ex, _ := lp.ExplainRisk(context.Background(), res)
	if ex.Text == "" || ex.Source != "local" {
		t.Fatalf("açıklama boş olmamalı: %+v", ex)
	}
}
