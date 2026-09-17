package aibrain

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"kut.corp/suite/server/internal/riskfusion"
)

// SeqModel, deterministik bir n-gram (bigram/Markov) nadirlik modelidir. Gözlenen
// dizilerden ardışık token geçişlerinin sıklığını öğrenir; yeni bir diziyi bu taban
// çizgisine göre puanlar. Nadir/görülmemiş geçişler yüksek anomali skoru üretir —
// çıktı açıklanabilirdir (hangi geçişin nadir olduğu bildirilir). Eşzamanlı güvenli.
type SeqModel struct {
	mu    sync.RWMutex
	trans map[string]map[string]int // kaynak → hedef → sayı
	total map[string]int            // kaynak → toplam geçiş
}

// NewSeqModel, boş bir sekans modeli oluşturur.
func NewSeqModel() *SeqModel {
	return &SeqModel{trans: map[string]map[string]int{}, total: map[string]int{}}
}

// Observe, bir diziyi taban çizgisine ekler (bigram sayaçlarını artırır). Normal
// davranış ne kadar çok gözlenirse o kadar "sıradan" sayılır.
func (m *SeqModel) Observe(tokens []string) {
	if len(tokens) < 2 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i+1 < len(tokens); i++ {
		a, b := tokens[i], tokens[i+1]
		if m.trans[a] == nil {
			m.trans[a] = map[string]int{}
		}
		m.trans[a][b]++
		m.total[a]++
	}
}

// rarity, bir dizinin 0..100 nadirlik skorunu ve en nadir geçişin açıklamasını döner.
// Her geçişin nadirliği: görülmemiş (kaynak hiç gözlenmemiş VEYA bu hedefe hiç
// gidilmemiş) → 1.0; aksi halde 1 - P(hedef|kaynak). Skor, geçiş nadirliklerinin
// ortalamasıdır. 2'den kısa diziler için 0 (kıyaslanacak geçiş yok).
func (m *SeqModel) rarity(tokens []string) (float64, string) {
	if len(tokens) < 2 {
		return 0, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sum float64
	var n int
	worst := -1.0
	worstDesc := ""
	for i := 0; i+1 < len(tokens); i++ {
		a, b := tokens[i], tokens[i+1]
		var r float64
		tot := m.total[a]
		if tot == 0 || m.trans[a][b] == 0 {
			r = 1.0 // görülmemiş geçiş → azami nadirlik
		} else {
			r = 1.0 - float64(m.trans[a][b])/float64(tot)
		}
		sum += r
		n++
		if r > worst {
			worst = r
			worstDesc = a + "→" + b
		}
	}
	if n == 0 {
		return 0, ""
	}
	return (sum / float64(n)) * 100, worstDesc
}

// Score, bir dizinin nadirlik skorunu açıklamalı SequenceScore olarak döner
// (salt-okunur sorgu — taban çizgisini DEĞİŞTİRMEZ). Analist tehdit-avında bir
// süreç zincirini ortama göre puanlamak için kullanır.
func (m *SeqModel) Score(tokens []string) SequenceScore {
	score, worst := m.rarity(tokens)
	rationale := "tüm geçişler taban çizgisinde sık"
	if worst != "" && score > 0 {
		rationale = "en nadir geçiş: " + worst
	}
	return SequenceScore{Score: score, Rationale: rationale, Source: "local"}
}

// LocalProvider, sıfır-ağ, DETERMİNİSTİK varsayılan aibrain.Provider'dır. Dış AI
// yapılandırılmadığında çekirdek tam çalışır kalır. ScoreSequence gerçek n-gram
// nadirliğini kullanır; diğer metotlar deterministik şablon/ölçütlerle doldurulur.
type LocalProvider struct {
	seq *SeqModel
}

// NewLocalProvider, boş bir yerel sağlayıcı oluşturur.
func NewLocalProvider() *LocalProvider { return &LocalProvider{seq: NewSeqModel()} }

// Derleme-zamanı güvence: LocalProvider, Provider arayüzünü karşılar.
var _ Provider = (*LocalProvider)(nil)

// Learn, sekans modeline bir taban-çizgisi dizisi ekler (çevrimiçi öğrenme).
func (l *LocalProvider) Learn(tokens []string) { l.seq.Observe(tokens) }

// ScoreSequence, dizinin n-gram nadirlik skorunu döner (açıklamalı).
func (l *LocalProvider) ScoreSequence(_ context.Context, in SequenceInput) (SequenceScore, error) {
	return l.seq.Score(in.Tokens), nil
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
