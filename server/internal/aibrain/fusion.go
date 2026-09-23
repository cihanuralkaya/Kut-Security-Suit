package aibrain

// fusion.go — P4.4: aibrain skorlarını mevcut riskfusion motoruna AÇIKLANABİLİR birer sinyal
// olarak sokan çekirdek yapıştırıcı. İlke: AI yalnız var olan riske sinyal KATAR; hiçbir
// zaman tek başına karar vermez. Her AI çağrısı fail-open olduğundan (Brain), dış/yerel AI
// bir skor veremezse ilgili sinyal EKLENMEZ — deterministik taban çizgisi aynen korunur.
// Sinyal adları ("ai_sequence", "ai_graph") füzyon sonucunda ayrı katkı olarak görünür, yani
// AI'ın nihai skora etkisi denetlenebilir kalır.

import (
	"context"

	"kut.corp/suite/server/internal/riskfusion"
)

// AI-türevi sinyallerin füzyondaki göreli ağırlıkları. Deterministik çekirdek sinyallerine
// (genelde ağırlık ≥1) kıyasla ölçülü tutulur: AI DESTEKLEYİCİ, belirleyici değil.
const (
	aiSeqWeight   = 0.5
	aiGraphWeight = 0.5
)

// SignalNameSeq / SignalNameGraph, AI sinyallerinin kanonik adlarıdır (füzyon katkısında
// ve denetimde bunlarla görünür).
const (
	SignalNameSeq   = "ai_sequence"
	SignalNameGraph = "ai_graph"
)

// AugmentSignals, base sinyallere Brain'in sekans/graf anomali skorlarını (VARSA) ekler ve
// YENİ bir dilim döner (base MUTASYONA UĞRAMAZ). Her AI sorgusu fail-open'dır: ok=false ⇒ o
// sinyal atlanır. seq/graph nil ise ilgili sorgu hiç yapılmaz. Yalnız skoru >0 olan AI
// sinyalleri eklenir (taban-çizgisiyle tam uyumlu diziler risk katmaz). nil Brain güvenlidir.
func (b *Brain) AugmentSignals(ctx context.Context, base []riskfusion.Signal, seq *SequenceInput, graph *GraphInput) []riskfusion.Signal {
	out := append([]riskfusion.Signal(nil), base...)
	if seq != nil {
		if sc, ok := b.ScoreSequence(ctx, *seq); ok && sc.Score > 0 {
			out = append(out, riskfusion.Signal{Name: SignalNameSeq, Score: sc.Score, Weight: aiSeqWeight})
		}
	}
	if graph != nil {
		if sc, ok := b.ScoreGraph(ctx, *graph); ok && sc.Score > 0 {
			out = append(out, riskfusion.Signal{Name: SignalNameGraph, Score: sc.Score, Weight: aiGraphWeight})
		}
	}
	return out
}

// FuseWithAI, base sinyalleri AI ile zenginleştirip füzyon sonucunu döner (kısayol). AI
// yoksa/başarısızsa sonuç, base'in tek başına füzyonuyla AYNIDIR (fail-open).
func (b *Brain) FuseWithAI(ctx context.Context, base []riskfusion.Signal, seq *SequenceInput, graph *GraphInput) riskfusion.Result {
	return riskfusion.Fuse(b.AugmentSignals(ctx, base, seq, graph))
}
