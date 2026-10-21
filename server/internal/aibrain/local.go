package aibrain

import (
	"context"
	"fmt"
	"strings"

	"kut.corp/suite/server/internal/riskfusion"
)

// LocalProvider, sıfır-ağ, DETERMİNİSTİK varsayılan aibrain.Provider'dır. Dış AI
// yapılandırılmadığında çekirdek tam çalışır kalır. ScoreSequence gerçek n-gram
// nadirliğini kullanır; diğer metotlar deterministik şablon/ölçütlerle doldurulur.
type LocalProvider struct {
	seqs *SeqModels // kiracı-bölümlü taban çizgisi
}

// NewLocalProvider, boş bir yerel sağlayıcı oluşturur.
func NewLocalProvider() *LocalProvider { return &LocalProvider{seqs: NewSeqModels()} }

// NewLocalProviderWithSeq, MEVCUT (canlı) bir SeqModel'i PAYLAŞAN bir yerel sağlayıcı
// oluşturur. Böylece ajan PROCESS soyağacından pasif öğrenen taban çizgisi, hem
// /api/hunt/sequence-score hem de füzyon/triyaj (Brain) yolunda AYNI modeli kullanır —
// yerel deterministik AI, dış servis olmadan da gerçek verinden beslenir. seq nil ise
// boş bir model kullanılır (NewLocalProvider ile eşdeğer).
func NewLocalProviderWithSeq(seq *SeqModel) *LocalProvider {
	if seq == nil {
		seq = NewSeqModel()
	}
	return &LocalProvider{seqs: NewSeqModelsWith("", seq)}
}

// NewLocalProviderWithSeqs, CANLI kiracı-bölümlü modelleri paylaşan bir yerel sağlayıcı döner.
// ScoreSequence, SequenceInput.Tenant kiracısının taban çizgisini kullanır (SUNUCU-TARAFI atanır).
func NewLocalProviderWithSeqs(seqs *SeqModels) *LocalProvider {
	if seqs == nil {
		seqs = NewSeqModels()
	}
	return &LocalProvider{seqs: seqs}
}

// Derleme-zamanı güvence: LocalProvider, Provider arayüzünü karşılar.
var _ Provider = (*LocalProvider)(nil)

// Learn, sekans modeline bir taban-çizgisi dizisi ekler (çevrimiçi öğrenme).
func (l *LocalProvider) Learn(tokens []string) { l.seqs.Observe("", tokens) }

// ScoreSequence, dizinin n-gram nadirlik skorunu döner (açıklamalı).
func (l *LocalProvider) ScoreSequence(_ context.Context, in SequenceInput) (SequenceScore, error) {
	return l.seqs.Score(in.Tenant, in.Tokens), nil
}

// ScoreGraphFeatures, GraphFeatures üzerinden DETERMİNİSTİK yapısal anomali skoru
// üretir (durumsuz — sağlayıcı örneği gerektirmez): yüksek fan-out, çok sayıda nadir
// kenar ve yüksek yeni-düğüm oranı skoru artırır.
func ScoreGraphFeatures(f GraphFeatures) GraphScore {
	score := 0.0
	score += clamp(float64(f.FanOut)*4, 0, 40)    // dağılım
	score += clamp(float64(f.RareEdges)*8, 0, 40) // nadir kenarlar
	score += clamp(f.NewNodeRatio*20, 0, 20)      // yenilik
	return GraphScore{
		Score:     clamp(score, 0, 100),
		Rationale: fmt.Sprintf("fan-out=%d, nadir kenar=%d, yeni-düğüm oranı=%.2f", f.FanOut, f.RareEdges, f.NewNodeRatio),
		Source:    "local",
	}
}

// ScoreGraph, ScoreGraphFeatures'a delege eder (Provider arayüzü uyumu).
func (l *LocalProvider) ScoreGraph(_ context.Context, in GraphInput) (GraphScore, error) {
	return ScoreGraphFeatures(in.Features), nil
}

// SuggestTriage, mevcut deterministik sinyalleri riskfusion ile birleştirip bir
// triyaj ÖNERİSİ üretir (öncelik = füzyon seviyesi; düşük skor → olası FP). Karar
// yürütücü değildir; yalnız öneri.
func (l *LocalProvider) SuggestTriage(_ context.Context, in TriageInput) (Triage, error) {
	res := riskfusion.Fuse(in.Signals)
	steps := []string{"olayı doğrula", "etkilenen varlıkları grafta pivotla"}
	if res.Score >= 70 {
		steps = append(steps, "vaka aç ve içerme (containment) değerlendir")
	}
	return Triage{
		Priority:   res.Level,
		LikelyFP:   res.Score < 40,
		NextSteps:  steps,
		Confidence: 0.6, // yerel sezgisel; dış model daha yüksek güven verebilir
		Source:     "local",
	}, nil
}

// SummarizeIncident, incident bağlamından deterministik bir özet cümlesi üretir.
func (l *LocalProvider) SummarizeIncident(_ context.Context, in IncidentInput) (Summary, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Cihaz %s: %s", orNA(in.Device), orNA(in.Technique))
	if in.Severity != "" {
		fmt.Fprintf(&b, " (%s)", in.Severity)
	}
	fmt.Fprintf(&b, "; %d olay", len(in.Events))
	if len(in.Events) > 0 {
		fmt.Fprintf(&b, " — ilk: %s", in.Events[0])
	}
	return Summary{Text: b.String(), Confidence: 0.5, Source: "local"}, nil
}

// ExplainRisk, bir riskfusion sonucunu en yüksek katkılı sinyallerle düz metne çevirir.
func (l *LocalProvider) ExplainRisk(_ context.Context, res riskfusion.Result) (Explanation, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Risk %.0f (%s).", res.Score, res.Level)
	for i, c := range res.Contributions {
		if i >= 3 {
			break
		}
		fmt.Fprintf(&b, " %s: %.0f puan (%%%.0f).", c.Name, c.Points, c.Share*100)
	}
	return Explanation{Text: b.String(), Source: "local"}, nil
}

// Health, yerel sağlayıcı her zaman hazırdır.
func (l *LocalProvider) Health(_ context.Context) error { return nil }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "?"
	}
	return s
}
