//go:build enterprise

package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/model"
)

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
func (f *fakeAnalytics) CountBySeverity(context.Context, time.Time) (map[string]uint64, error) {
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
