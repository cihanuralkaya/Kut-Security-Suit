package aibrain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"kut.corp/suite/server/internal/riskfusion"
)

// Derleme-zamanı: HTTPProvider, Provider arayüzünü tam karşılar.
var _ Provider = (*HTTPProvider)(nil)

func TestHTTPProviderSuggestTriage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/triage" {
			http.Error(w, "yol", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer k1" {
			http.Error(w, "yetki", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"priority":"HIGH","likely_fp":false,"next_steps":["izole et"],"confidence":0.9}`))
	}))
	defer ts.Close()

	p := NewHTTPProvider(ts.URL, "k1", "test-model", time.Second)
	tr, err := p.SuggestTriage(context.Background(), TriageInput{IncidentID: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Priority != "HIGH" || tr.LikelyFP || len(tr.NextSteps) != 1 || tr.Confidence != 0.9 {
		t.Fatalf("triyaj eşlemesi hatalı: %+v", tr)
	}
	if tr.Source != "llm:test-model" {
		t.Fatalf("kaynak servis belirtmediyse llm:<model> olmalı: %q", tr.Source)
	}
}

// TestHTTPProviderFailOpen, non-2xx yanıtın hata döndürdüğünü (fail-open) ve Brain
// sarımının bunu ok=false'a çevirdiğini doğrular — çekirdek deterministik yola döner.
func TestHTTPProviderFailOpen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "patladı", http.StatusInternalServerError)
	}))
	defer ts.Close()

	p := NewHTTPProvider(ts.URL, "", "m", time.Second)
	if _, err := p.SuggestTriage(context.Background(), TriageInput{}); err == nil {
		t.Fatal("non-2xx hata dönmeliydi (fail-open)")
	}
	// Brain fail-open: hata → ok=false.
	b := New(p, time.Second)
	if _, ok := b.SuggestTriage(context.Background(), TriageInput{}); ok {
		t.Fatal("Brain hata durumunda ok=false dönmeliydi")
	}
}

// TestBrainResilienceMatrix, dış AI'ın KÖTÜ DAVRANDIĞI her senaryoda Brain'in ok=false +
// SIFIR değer döndüğünü ve güvenliğin BOZULMADIĞINI doğrular (P0-C güvenlik-sınırı). Hiçbir
// senaryo panik/kalıcı-bloklama/kısmi-veri üretmez; çağıran (riskfusion/correlate) AI'ı
// "yokmuş gibi" ele alıp deterministik yola döner. AI yalnız ÖNERİ üretir; bir arıza
// enforcement'ı ne durdurabilir ne de zayıflatabilir.
func TestBrainResilienceMatrix(t *testing.T) {
	slow := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"priority":"HIGH"}`))
	}
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		btimeout time.Duration
	}{
		{"5xx-internal", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "patladı", http.StatusInternalServerError)
		}, time.Second},
		{"429-ratelimit", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "yavaşla", http.StatusTooManyRequests) }, time.Second},
		{"503-unavailable", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "kapalı", http.StatusServiceUnavailable) }, time.Second},
		{"malformed-json-200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{bozuk`))
		}, time.Second},
		{"empty-body-200", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }, time.Second},
		{"timeout", slow, 40 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(c.handler)
			defer ts.Close()
			b := New(NewHTTPProvider(ts.URL, "", "m", time.Second), c.btimeout)
			tr, ok := b.SuggestTriage(context.Background(), TriageInput{IncidentID: "i1"})
			if ok {
				t.Fatalf("%s: kötü yanıt ok=false vermeli", c.name)
			}
			if !reflect.DeepEqual(tr, Triage{}) {
				t.Fatalf("%s: sıfır değer olmalı (kısmi veri sızmamalı): %+v", c.name, tr)
			}
		})
	}
}

// TestBrainAllMethodsFailOpenUniformly, arayüzün TAMAMININ tek tip fail-open olduğunu
// doğrular: dış servis 5xx verdiğinde beş öneri metodunun HİÇBİRİ ok=true dönmez. Böylece
// hiçbir sinyal/özet/açıklama, arıza anında sessizce eklenmez.
func TestBrainAllMethodsFailOpenUniformly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer ts.Close()
	b := New(NewHTTPProvider(ts.URL, "", "m", time.Second), time.Second)
	ctx := context.Background()

	if _, ok := b.ScoreSequence(ctx, SequenceInput{Tokens: []string{"x"}}); ok {
		t.Error("ScoreSequence fail-open olmalı")
	}
	if _, ok := b.ScoreGraph(ctx, GraphInput{}); ok {
		t.Error("ScoreGraph fail-open olmalı")
	}
	if _, ok := b.SummarizeIncident(ctx, IncidentInput{}); ok {
		t.Error("SummarizeIncident fail-open olmalı")
	}
	if _, ok := b.SuggestTriage(ctx, TriageInput{}); ok {
		t.Error("SuggestTriage fail-open olmalı")
	}
	if _, ok := b.ExplainRisk(ctx, riskfusion.Result{}); ok {
		t.Error("ExplainRisk fail-open olmalı")
	}
}

// TestBrainNetworkErrorFailOpen, servis HİÇ ulaşılamadığında (bağlantı reddi) çağrının
// ok=false döndüğünü doğrular — ağ katmanı hataları da fail-open'dır.
func TestBrainNetworkErrorFailOpen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close() // artık dinlemiyor → bağlantı reddi
	b := New(NewHTTPProvider(url, "", "m", 200*time.Millisecond), time.Second)
	if _, ok := b.SuggestTriage(context.Background(), TriageInput{}); ok {
		t.Fatal("ağ hatası → ok=false olmalı")
	}
}

// TestBrainNilAndNilProviderSafe, dış AI HİÇ yapılandırılmadığında (nil provider) ve hatta
// Brain'in kendisi nil olduğunda çağrıların panik etmeden ok=false döndüğünü doğrular —
// AI-yok yapılandırması varsayılan güvenli yoldur.
func TestBrainNilAndNilProviderSafe(t *testing.T) {
	b := New(nil, time.Second)
	if b.Enabled() {
		t.Error("nil provider'da Enabled=false olmalı")
	}
	if _, ok := b.SuggestTriage(context.Background(), TriageInput{}); ok {
		t.Error("nil provider → ok=false")
	}
	var nb *Brain // hiç kurulmamış Brain bile güvenli olmalı
	if nb.Enabled() {
		t.Error("nil Brain Enabled=false olmalı")
	}
	if _, ok := nb.SuggestTriage(context.Background(), TriageInput{}); ok {
		t.Error("nil Brain → ok=false (panik yok)")
	}
}

func TestHTTPProviderHealth(t *testing.T) {
	ok := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "sağlıksız", http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	p := NewHTTPProvider(ts.URL, "", "m", time.Second)
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("sağlıklı serviste Health nil dönmeli: %v", err)
	}
	ok = false
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("sağlıksız serviste Health hata dönmeli")
	}
}

// TestHTTPProviderScoreGraphSendsFeaturesOnly, ScoreGraph'in ham graf değil yalnız
// türetilmiş özellik/odak gönderdiğini doğrular (§5.4 veri-minimizasyonu).
func TestHTTPProviderScoreGraphSendsFeaturesOnly(t *testing.T) {
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":42,"rationale":"ok"}`))
	}))
	defer ts.Close()
	p := NewHTTPProvider(ts.URL, "", "m", time.Second)
	sc, err := p.ScoreGraph(context.Background(), GraphInput{Features: GraphFeatures{FanOut: 3}})
	if err != nil || sc.Score != 42 {
		t.Fatalf("graf skor eşlemesi hatalı: %+v err=%v", sc, err)
	}
	if gotBody == "" {
		t.Fatal("istek gövdesi okunmalıydı")
	}
}
