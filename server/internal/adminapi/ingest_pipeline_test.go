package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kut.corp/suite/server/internal/model"
)

// recProc, EventProcessor'ı kaydeden bir sahtedir (hattın çağrıldığını doğrular).
type recProc struct {
	mu     sync.Mutex
	events []model.Event
	devs   []string
}

func (r *recProc) ProcessEvent(_ context.Context, deviceID string, e model.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devs = append(r.devs, deviceID)
	r.events = append(r.events, e)
}

// nopIngest, olayları kabul eden ama saklamayan bir EventIngestor sahtesidir.
type nopIngest struct{}

func (nopIngest) SaveEvents(context.Context, string, []model.Event) (uint64, error) { return 0, nil }

// TestIngestRunsDetectionPipeline, HTTP log-ingest (CEF) ile gelen olayların
// SAKLANMANIN YANI SIRA tespit+alarm hattına (EventProcessor) verildiğini doğrular.
// Bu, içe-aktarılan IDS kuralları dahil tüm tespit kurallarının log
// kaynaklarında da çalışmasını sağlayan kablolamanın regresyon kalkanıdır.
func TestIngestRunsDetectionPipeline(t *testing.T) {
	srv, _ := newServer(t)
	srv.SetIngest(nopIngest{}, "itok")
	proc := &recProc{}
	srv.SetEventProcessor(proc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Geçerli CEF satırı: Version|Vendor|Product|DevVer|SigID|Name|Severity|Ext
	cef := "CEF:0|Vendor|Product|1.0|100|mimikatz executed on host|9|src=10.0.0.5"
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(cef))
	req.Header.Set("Authorization", "Bearer itok")
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ingest durum kodu = %d, 200 beklendi", resp.StatusCode)
	}

	proc.mu.Lock()
	defer proc.mu.Unlock()
	if len(proc.events) == 0 {
		t.Fatal("log-ingest olayı tespit hattına VERİLMEDİ (ProcessEvent çağrılmadı)")
	}
	if strings.TrimSpace(proc.events[0].Message) == "" {
		t.Fatalf("tespit hattına boş mesajlı olay verildi: %+v", proc.events[0])
	}
	if strings.TrimSpace(proc.devs[0]) == "" {
		t.Fatal("tespit hattına boş device_id verildi")
	}
}

// TestIngestWithoutProcessorStillStores, EventProcessor bağlı değilken ingest'in
// yine de başarılı olduğunu (yalnız kaydettiğini — eski davranış) doğrular.
func TestIngestWithoutProcessorStillStores(t *testing.T) {
	srv, _ := newServer(t)
	srv.SetIngest(nopIngest{}, "itok") // eventProc AYARLANMADI
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cef := "CEF:0|Vendor|Product|1.0|100|benign event|3|src=10.0.0.9"
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(cef))
	req.Header.Set("Authorization", "Bearer itok")
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("processor'suz ingest durum kodu = %d, 200 beklendi", resp.StatusCode)
	}
}
