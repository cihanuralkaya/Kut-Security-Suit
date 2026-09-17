// Package aibrain, KUT çekirdeğinin OPSİYONEL AI arka uçlarıyla konuştuğu TEK
// sınırdır (vNext P4). İlke: "güvenlik sistemi AI'ı yönetir." Buradaki her metot
// yalnız ÖNERİ/SİNYAL üretir — hiçbiri aksiyon yürütmez; yüksek-etkili her aksiyon
// yine authz gateway'in altında kalır. Ayrıca her çağrı FAIL-OPEN'dır: sağlayıcı
// yoksa, timeout olursa veya hata verirse çekirdek "AI yokmuş gibi" deterministik
// yoluna devam eder ve enforcement ASLA durmaz.
//
// aiassist'ten (§27, serbest-metin SOC asistanı) farkı: aibrain YAPISAL sinyaller
// (sekans nadirliği, graf anomalisi, risk açıklaması) üretir ve doğrudan riskfusion/
// correlate/entitygraph akışlarını besler. Varsayılan LocalProvider deterministik ve
// sıfır-ağdır; dış servis yalnız açıkça yapılandırılırsa devreye girer.
package aibrain

import (
	"context"
	"time"

	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/riskfusion"
)

// Provider, opsiyonel AI arka ucunu soyutlar. TÜM metotlar salt-öneri üretir.
// Her metot fail-open'dır: hata/timeout → boş sonuç + err; çağıran boş sonucu
// "AI yok" gibi ele alır.
type Provider interface {
	SummarizeIncident(ctx context.Context, in IncidentInput) (Summary, error)
	SuggestTriage(ctx context.Context, in TriageInput) (Triage, error)
	ScoreSequence(ctx context.Context, in SequenceInput) (SequenceScore, error)
	ScoreGraph(ctx context.Context, in GraphInput) (GraphScore, error)
	ExplainRisk(ctx context.Context, res riskfusion.Result) (Explanation, error)
	Health(ctx context.Context) error
}

// IncidentInput, bir incident'in özetlenecek bağlamıdır.
type IncidentInput struct {
	IncidentID string
	Device     string
	Technique  string // MITRE ATT&CK ör. T1059
	Severity   string
	Events     []string
	Context    map[string]string
}

// Summary, insan-okunur bir özettir (yalnız bilgilendirici).
type Summary struct {
	Text       string
	Confidence float64 // 0..1
	Source     string  // "local" | "llm:<model>" — denetlenebilirlik
}

// TriageInput, triyaj önerisi için mevcut deterministik sinyalleri taşır.
type TriageInput struct {
	IncidentID string
	Signals    []riskfusion.Signal
	Events     []string
}

// Triage, salt-öneri bir triyaj kararıdır (aksiyon değil).
type Triage struct {
	Priority   string // LOW|MEDIUM|HIGH|CRITICAL (öneri)
	LikelyFP   bool
	NextSteps  []string
	Confidence float64
	Source     string
}

// SequenceInput, sıralı bir olay dizisidir (süreç ağacı, komut geçmişi, auth).
type SequenceInput struct {
	Tokens []string
	Kind   string // "process" | "command" | "auth"
}

// SequenceScore, bir dizinin nadirlik/anomali skorudur (açıklamalı).
type SequenceScore struct {
	Score     float64 // 0..100
	Rationale string
	Source    string
}

// GraphInput, entitygraph üzerinde bir odak düğüm için çıkarılmış özelliklerdir.
// Ham graf dış servise sızdırılmaz; yalnız türetilmiş metrikler geçer (§5.4).
type GraphInput struct {
	Focus    entitygraph.Node
	MaxDepth int
	Features GraphFeatures
}

// GraphFeatures, bir düğümün deterministik yapısal özellikleridir.
type GraphFeatures struct {
	FanOut, FanIn int
	RareEdges     int
	NewNodeRatio  float64
}

// GraphScore, yapısal anomali skorudur.
type GraphScore struct {
	Score     float64 // 0..100
	Rationale string
	Source    string
}

// Explanation, bir riskfusion sonucunun doğal-dil açıklamasıdır.
type Explanation struct {
	Text   string
	Source string
}

// defaultTimeout, dış sağlayıcı çağrıları için makul üst sınırdır.
const defaultTimeout = 800 * time.Millisecond

// Brain, bir Provider'ı FAIL-OPEN semantiğiyle sarar. Provider nil ise (dış AI
// yapılandırılmamış) tüm çağrılar anında boş sonuç + ok=false döner — çekirdek
// akmaz. Böylece çağıran kod tek yol yazar: `if v, ok := brain.X(...); ok { kullan }`.
type Brain struct {
	p       Provider
	timeout time.Duration
}

// New, bir Brain oluşturur. p nil olabilir (fail-open). timeout <= 0 ise varsayılan.
func New(p Provider, timeout time.Duration) *Brain {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Brain{p: p, timeout: timeout}
}

// Enabled, gerçek bir sağlayıcının bağlı olup olmadığını bildirir.
func (b *Brain) Enabled() bool { return b != nil && b.p != nil }

// call, ortak fail-open sarmalayıcı: nil brain/provider, timeout ve hata → ok=false.
func call[T any](b *Brain, ctx context.Context, fn func(context.Context, Provider) (T, error)) (T, bool) {
	var zero T
	if b == nil || b.p == nil {
		return zero, false
	}
	cctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	v, err := fn(cctx, b.p)
	if err != nil {
		return zero, false // fail-open: sessizce yut (çağıran deterministik yola döner)
	}
	return v, true
}

// ScoreSequence, dizinin nadirlik skorunu döner; ok=false ⇒ sinyal EKLEME.
func (b *Brain) ScoreSequence(ctx context.Context, in SequenceInput) (SequenceScore, bool) {
	return call(b, ctx, func(c context.Context, p Provider) (SequenceScore, error) { return p.ScoreSequence(c, in) })
}

// ScoreGraph, yapısal anomali skorunu döner; ok=false ⇒ sinyal EKLEME.
func (b *Brain) ScoreGraph(ctx context.Context, in GraphInput) (GraphScore, bool) {
	return call(b, ctx, func(c context.Context, p Provider) (GraphScore, error) { return p.ScoreGraph(c, in) })
}

// SummarizeIncident, incident özetini döner; ok=false ⇒ özet gösterme.
func (b *Brain) SummarizeIncident(ctx context.Context, in IncidentInput) (Summary, bool) {
	return call(b, ctx, func(c context.Context, p Provider) (Summary, error) { return p.SummarizeIncident(c, in) })
}

// SuggestTriage, triyaj önerisini döner; ok=false ⇒ öneri gösterme.
func (b *Brain) SuggestTriage(ctx context.Context, in TriageInput) (Triage, bool) {
	return call(b, ctx, func(c context.Context, p Provider) (Triage, error) { return p.SuggestTriage(c, in) })
}

// ExplainRisk, risk açıklamasını döner; ok=false ⇒ açıklama gösterme.
func (b *Brain) ExplainRisk(ctx context.Context, res riskfusion.Result) (Explanation, bool) {
	return call(b, ctx, func(c context.Context, p Provider) (Explanation, error) { return p.ExplainRisk(c, res) })
}
