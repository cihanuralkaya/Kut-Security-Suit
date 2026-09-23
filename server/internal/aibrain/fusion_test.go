package aibrain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kut.corp/suite/server/internal/riskfusion"
)

// hasSignal, verilen adı taşıyan bir sinyal olup olmadığını ve skorunu döner.
func hasSignal(sigs []riskfusion.Signal, name string) (float64, bool) {
	for _, s := range sigs {
		if s.Name == name {
			return s.Score, true
		}
	}
	return 0, false
}

// TestAugmentAddsRareSequenceSignal, taban-çizgisine göre NADİR bir dizinin bir ai_sequence
// sinyali ürettiğini ve füzyon skorunu (base'e kıyasla) YÜKSELTTİĞİNİ doğrular — AI mevcut
// riske açıklanabilir bir katkı ekler.
func TestAugmentAddsRareSequenceSignal(t *testing.T) {
	lp := NewLocalProvider()
	// Taban çizgisi: "normal" süreç zinciri defalarca gözlenir.
	for i := 0; i < 10; i++ {
		lp.Learn([]string{"bash", "ls", "cat", "grep"})
	}
	b := New(lp, time.Second)
	base := []riskfusion.Signal{{Name: "ioc", Score: 50, Weight: 1}}

	// Görülmemiş geçişler içeren nadir bir dizi.
	rare := &SequenceInput{Tokens: []string{"bash", "curl", "powershell", "whoami"}, Kind: "process"}
	aug := b.AugmentSignals(context.Background(), base, rare, nil)

	sc, ok := hasSignal(aug, SignalNameSeq)
	if !ok {
		t.Fatal("nadir dizi ai_sequence sinyali üretmeliydi")
	}
	if sc <= 0 {
		t.Fatalf("ai_sequence skoru >0 olmalı: %v", sc)
	}
	// Füzyon: AI katkısı skoru base-only'nin üstüne çıkarmalı.
	baseOnly := riskfusion.Fuse(base)
	withAI := riskfusion.Fuse(aug)
	if withAI.Score <= baseOnly.Score {
		t.Errorf("AI sinyali füzyon skorunu yükseltmeliydi: base=%.2f withAI=%.2f", baseOnly.Score, withAI.Score)
	}
	// Katkı açıklanabilir olmalı (ai_sequence bir Contribution olarak görünür).
	res := b.FuseWithAI(context.Background(), base, rare, nil)
	if _, ok := hasContribution(res, SignalNameSeq); !ok {
		t.Error("FuseWithAI sonucunda ai_sequence katkısı görünmeli")
	}
}

func hasContribution(r riskfusion.Result, name string) (float64, bool) {
	for _, c := range r.Contributions {
		if c.Name == name {
			return c.Points, true
		}
	}
	return 0, false
}

// TestAugmentDoesNotMutateBase, dönen dilimin YENİ olduğunu ve base'in değişmediğini doğrular.
func TestAugmentDoesNotMutateBase(t *testing.T) {
	b := New(NewLocalProvider(), time.Second)
	base := []riskfusion.Signal{{Name: "ioc", Score: 50, Weight: 1}}
	rare := &SequenceInput{Tokens: []string{"x", "y", "z"}}
	_ = b.AugmentSignals(context.Background(), base, rare, nil)
	if len(base) != 1 || base[0].Name != "ioc" {
		t.Fatalf("base mutasyona uğramamalı: %+v", base)
	}
}

// TestAugmentFailOpen, AI mevcut değilken (nil Brain ve hata veren dış sağlayıcı) sinyal
// kümesinin base ile AYNI kaldığını doğrular — deterministik taban çizgisi korunur.
func TestAugmentFailOpen(t *testing.T) {
	base := []riskfusion.Signal{{Name: "ioc", Score: 50, Weight: 1}}
	seq := &SequenceInput{Tokens: []string{"a", "b", "c"}}

	// (1) nil Brain → panik yok, sinyal eklenmez.
	var nb *Brain
	if got := nb.AugmentSignals(context.Background(), base, seq, nil); len(got) != len(base) {
		t.Errorf("nil Brain sinyal eklememeli: %+v", got)
	}

	// (2) Dış sağlayıcı 5xx → fail-open, sinyal eklenmez.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer ts.Close()
	b := New(NewHTTPProvider(ts.URL, "", "m", time.Second), time.Second)
	got := b.AugmentSignals(context.Background(), base, seq, &GraphInput{Features: GraphFeatures{FanOut: 9}})
	if _, ok := hasSignal(got, SignalNameSeq); ok {
		t.Error("hata veren sağlayıcı ai_sequence eklememeli (fail-open)")
	}
	if _, ok := hasSignal(got, SignalNameGraph); ok {
		t.Error("hata veren sağlayıcı ai_graph eklememeli (fail-open)")
	}
	if len(got) != len(base) {
		t.Errorf("fail-open'da sinyal kümesi base ile aynı olmalı: %+v", got)
	}
}

// TestAugmentSkipsZeroScore, taban-çizgisiyle TAM UYUMLU bir dizinin (skor 0) sinyal
// eklemediğini doğrular — sıfır-skor guard'ı gürültüyü önler.
func TestAugmentSkipsZeroScore(t *testing.T) {
	lp := NewLocalProvider()
	for i := 0; i < 5; i++ {
		lp.Learn([]string{"a", "b"}) // yalnız a→b geçişi öğrenildi (P(b|a)=1 → nadirlik 0)
	}
	b := New(lp, time.Second)
	base := []riskfusion.Signal{{Name: "ioc", Score: 50, Weight: 1}}
	same := &SequenceInput{Tokens: []string{"a", "b"}}
	got := b.AugmentSignals(context.Background(), base, same, nil)
	if _, ok := hasSignal(got, SignalNameSeq); ok {
		t.Error("skoru 0 olan dizi (tam uyumlu) sinyal eklememeli")
	}
}
