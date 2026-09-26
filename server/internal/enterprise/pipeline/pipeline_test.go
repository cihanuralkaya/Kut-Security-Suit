//go:build enterprise

package pipeline

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"kut.corp/suite/server/internal/casemgmt"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
)

// fakeDetector, "high" önem düzeyindeki olaylara tek bir tespit üretir.
type fakeDetector struct{}

func (fakeDetector) Evaluate(ev model.Event) []detect.Detection {
	if ev.Severity == "high" {
		return []detect.Detection{{RuleID: "R1", RuleName: "yüksek önem", Severity: "HIGH"}}
	}
	return nil
}

// fakeAlertSink, üretilen alarmları toplar.
type fakeAlertSink struct {
	mu     sync.Mutex
	alerts []Alert
}

func (f *fakeAlertSink) Emit(_ context.Context, a []Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a...)
	return nil
}

// --- sahte (fake) bağımlılıklar: gerçek backend'ler ayrıca konteynere karşı test edilir;
// burada pipeline MANTIĞI izole doğrulanır (konteynersiz, hızlı) ---

type fakeSource struct{ notices []eventbus.Notice }

func (f *fakeSource) Replay(fn func(eventbus.Notice) error) error {
	for _, n := range f.notices {
		if err := fn(n); err != nil {
			return err
		}
	}
	return nil
}

type fakeAnalytics struct {
	mu       sync.Mutex
	inserted []model.Event
}

func (f *fakeAnalytics) Insert(_ context.Context, evs []model.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inserted = append(f.inserted, evs...)
	return nil
}
func (f *fakeAnalytics) CountBySeverity(context.Context, string, time.Time) (map[string]uint64, error) {
	return nil, nil
}
func (f *fakeAnalytics) Close() error { return nil }

type fakeArchive struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeArchive() *fakeArchive { return &fakeArchive{objects: map[string][]byte{}} }
func (f *fakeArchive) Put(_ context.Context, key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
	return nil
}
func (f *fakeArchive) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[key], nil
}
func (f *fakeArchive) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		keys = append(keys, k)
	}
	return keys, nil
}
func (f *fakeArchive) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	return nil
}

func sampleNotices() []eventbus.Notice {
	return []eventbus.Notice{
		{Type: "event", DeviceID: "d1", Severity: "high", Message: "m1", At: time.Unix(1, 0).UTC()},
		{Type: "device", DeviceID: "d2", At: time.Unix(2, 0).UTC()},
		{Type: "event", DeviceID: "d3", Severity: "low", Message: "m3", At: time.Unix(3, 0).UTC()},
	}
}

// ProcessAll: normalize + iki sink'e yazım + doğru eşleme + EventID doldurma.
func TestProcessAll(t *testing.T) {
	src := &fakeSource{notices: sampleNotices()}
	an := &fakeAnalytics{}
	ar := newFakeArchive()
	p := New(src, an, ar)

	n, err := p.ProcessAll(context.Background())
	if err != nil {
		t.Fatalf("ProcessAll: %v", err)
	}
	if n != 3 {
		t.Fatalf("işlenen=%d, beklenen 3", n)
	}
	if len(an.inserted) != 3 {
		t.Fatalf("analitik ekleme=%d, beklenen 3", len(an.inserted))
	}
	// Eşleme + EventID doğrulama.
	e0 := an.inserted[0]
	if e0.DeviceID != "d1" || e0.Severity != "high" || e0.Message != "m1" ||
		e0.Category != "event" || e0.Source != "endpoint" || !e0.OccurredAt.Equal(time.Unix(1, 0).UTC()) {
		t.Fatalf("normalize eşleme hatalı: %+v", e0)
	}
	if e0.EventID == "" {
		t.Fatal("EventID doldurulmadı")
	}
	if len(ar.objects) != 3 {
		t.Fatalf("arşiv nesne=%d, beklenen 3", len(ar.objects))
	}
}

// Aynı bildirimlerin yeniden işlenmesi arşivde çift nesne üretmemeli (event_id anahtarlı idempotens).
func TestProcessAllIdempotentArchive(t *testing.T) {
	notices := sampleNotices()
	ar := newFakeArchive()
	p := New(&fakeSource{notices: notices}, nil, ar)

	if _, err := p.ProcessAll(context.Background()); err != nil {
		t.Fatalf("1. koşu: %v", err)
	}
	first := len(ar.objects)
	if _, err := p.ProcessAll(context.Background()); err != nil {
		t.Fatalf("2. koşu: %v", err)
	}
	if len(ar.objects) != first {
		t.Fatalf("yeniden işleme arşivde çift üretti: %d → %d", first, len(ar.objects))
	}
}

// Boş kaynak: yazım yok, hata yok.
func TestProcessAllEmpty(t *testing.T) {
	an := &fakeAnalytics{}
	ar := newFakeArchive()
	p := New(&fakeSource{}, an, ar)
	n, err := p.ProcessAll(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("boş kaynak: n=%d err=%v", n, err)
	}
	if len(an.inserted) != 0 || len(ar.objects) != 0 {
		t.Fatal("boş kaynakta yazım oldu")
	}
}

// nil sink'ler: panik yok, kayıtlar sayılır.
func TestProcessAllNilSinks(t *testing.T) {
	p := New(&fakeSource{notices: sampleNotices()}, nil, nil)
	n, err := p.ProcessAll(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("nil sink: n=%d err=%v", n, err)
	}
}

// WithTenant: tenant taşımayan olaylara sunucu-tarafı kiracı atanmalı (analitik satırı + arşiv anahtarı).
func TestProcessAllTenantBinding(t *testing.T) {
	an := &fakeAnalytics{}
	ar := newFakeArchive()
	p := New(&fakeSource{notices: sampleNotices()}, an, ar).WithTenant("acme")

	if _, err := p.ProcessAll(context.Background()); err != nil {
		t.Fatalf("ProcessAll: %v", err)
	}
	for i, e := range an.inserted {
		if e.TenantID != "acme" {
			t.Fatalf("analitik kayıt[%d] tenant=%q, beklenen acme", i, e.TenantID)
		}
	}
	for k := range ar.objects {
		if !strings.HasPrefix(k, "events/acme/") {
			t.Fatalf("arşiv anahtarı tenant prefix'i taşımıyor: %q", k)
		}
	}
}

// Per-event tenant (Notice.TenantID) WithTenant fallback'ine ÜSTÜN gelmeli (çok-tenant akış).
func TestProcessAllPerEventTenantOverridesFallback(t *testing.T) {
	an := &fakeAnalytics{}
	src := &fakeSource{notices: []eventbus.Notice{
		{Type: "event", DeviceID: "d1", TenantID: "acme", At: time.Unix(1, 0).UTC()}, // per-event kiracı
		{Type: "event", DeviceID: "d2", At: time.Unix(2, 0).UTC()},                   // kiracısız → fallback
	}}
	p := New(src, an, nil).WithTenant("fallback")
	if _, err := p.ProcessAll(context.Background()); err != nil {
		t.Fatalf("ProcessAll: %v", err)
	}
	if an.inserted[0].TenantID != "acme" {
		t.Fatalf("per-event kiracı korunmalı: %q", an.inserted[0].TenantID)
	}
	if an.inserted[1].TenantID != "fallback" {
		t.Fatalf("kiracısız olay fallback almalı: %q", an.inserted[1].TenantID)
	}
}

// Detection stage: yalnız eşleşen (high) olaylar alarm üretmeli; alarm tetikleyen olayı taşımalı.
func TestProcessAllDetection(t *testing.T) {
	sink := &fakeAlertSink{}
	p := New(&fakeSource{notices: sampleNotices()}, nil, nil).WithDetection(fakeDetector{}, sink)

	n, err := p.ProcessAll(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("ProcessAll: n=%d err=%v", n, err)
	}
	// sampleNotices'te bir tane "high" var (d1) → tam 1 alarm.
	if len(sink.alerts) != 1 {
		t.Fatalf("alarm sayısı=%d, beklenen 1", len(sink.alerts))
	}
	a := sink.alerts[0]
	if a.Detection.RuleID != "R1" || a.Event.DeviceID != "d1" || a.Event.EventID == "" {
		t.Fatalf("alarm içeriği hatalı: %+v", a)
	}
}

// Detector var ama sink nil ise (veya tersi) detection atlanır, panik olmaz.
func TestProcessAllDetectionNoSink(t *testing.T) {
	p := New(&fakeSource{notices: sampleNotices()}, nil, nil).WithDetection(fakeDetector{}, nil)
	if _, err := p.ProcessAll(context.Background()); err != nil {
		t.Fatalf("sink nil detection: %v", err)
	}
}

// CaseAlertSink: alarm → çekirdek casemgmt.Store'da vaka; alanlar doğru eşlenmeli.
func TestCaseAlertSink(t *testing.T) {
	store := casemgmt.NewMemStore()
	sink := NewCaseAlertSink(store)

	alerts := []Alert{{
		Event: model.Event{EventID: "evt_1", DeviceID: "d1", Severity: "high"},
		Detection: detect.Detection{
			RuleID: "R1", RuleName: "şüpheli komut", Severity: "HIGH",
			Technique: mitre.Technique{ID: "T1059"},
		},
	}}
	if err := sink.Emit(context.Background(), alerts); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// Tenant boştu → fallback "default" ile oluşturulmuş olmalı.
	cases, err := store.List(fallbackTenant)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("vaka sayısı=%d, beklenen 1", len(cases))
	}
	c := cases[0]
	if c.Severity != casemgmt.SeverityHigh {
		t.Fatalf("önem eşleme hatalı: %s", c.Severity)
	}
	if len(c.MITRE) != 1 || c.MITRE[0] != "T1059" {
		t.Fatalf("MITRE eşleme hatalı: %v", c.MITRE)
	}
	if len(c.EvidenceRefs) != 1 || c.EvidenceRefs[0] != "evt_1" {
		t.Fatalf("kanıt referansı hatalı: %v", c.EvidenceRefs)
	}
}

// CaseAlertSink idempotent: aynı alarmın yeniden işlenmesi çift vaka üretmemeli, hata dönmemeli.
func TestCaseAlertSinkIdempotent(t *testing.T) {
	store := casemgmt.NewMemStore()
	sink := NewCaseAlertSink(store)
	alerts := []Alert{{
		Event:     model.Event{EventID: "evt_9", DeviceID: "d9", Severity: "low"},
		Detection: detect.Detection{RuleID: "R2", RuleName: "x", Severity: "LOW"},
	}}
	for i := 0; i < 3; i++ {
		if err := sink.Emit(context.Background(), alerts); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	cases, _ := store.List(fallbackTenant)
	if len(cases) != 1 {
		t.Fatalf("idempotency kırık: %d vaka", len(cases))
	}
}
