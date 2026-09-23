package aibrain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
