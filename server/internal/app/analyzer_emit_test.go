package app

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/memstore"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/notify"
)

type pubRec struct {
	mu   sync.Mutex
	pubs []struct{ tenant, dev string }
	alts []notify.Alert
}

func (p *pubRec) publish(tn, dev, _, _ string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pubs = append(p.pubs, struct{ tenant, dev string }{tn, dev})
}

func (p *pubRec) notify(a notify.Alert) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.alts = append(p.alts, a)
}

func enrollDev(t *testing.T, st *memstore.Store, mac, tenantID string) string {
	t.Helper()
	id, err := st.UpsertEnrollingDevice(context.Background(), enroll.DeviceEnrollment{
		MACBlindIndex: []byte(mac), HostnameEnc: []byte("h"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: tenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newEmitter(st *memstore.Store, deflt string, enforce bool) (*findingEmitter, *pubRec) {
	rec := &pubRec{}
	return &findingEmitter{
		save:    st.SaveEvents,
		tenants: analyzerTenants{lookup: st.TenantForDevice, deflt: deflt, enforce: enforce},
		publish: rec.publish,
		notify:  rec.notify,
	}, rec
}

func finding(msg string) (model.Event, notify.Alert) {
	return model.Event{Category: "SECURITY", Severity: "HIGH", Message: msg, OccurredAt: time.Now(),
			Details: findingDetails(map[string]any{"beacon": true})},
		notify.Alert{Category: "SECURITY", Severity: "HIGH", Message: msg, OccurredAt: time.Now()}
}

// bulgu cihazın kiracısıyla yazılır; SSE yayını ve uyarı da o kiracıya atfedilir;
// başka kiracı bu bulguyu OKUYAMAZ (negatif), sahibi okur (pozitif).
func TestAnalyzerFindingCarriesDeviceTenant(t *testing.T) {
	st := memstore.New()
	devA := enrollDev(t, st, "mac-a", "t1")
	devB := enrollDev(t, st, "mac-b", "t2")
	fe, rec := newEmitter(st, "deploy", true)

	ev, al := finding("beacon A")
	tn, ok := fe.emit(context.Background(), devA, "", ev, al, false)
	if !ok || tn != "t1" {
		t.Fatalf("t1 cihazı için bulgu t1 ile yazılmalı: %q %v", tn, ok)
	}
	ev, al = finding("beacon B")
	if tn, ok := fe.emit(context.Background(), devB, "", ev, al, false); !ok || tn != "t2" {
		t.Fatalf("t2: %q %v", tn, ok)
	}

	rowsT1, _ := st.QueryEvents(context.Background(), adminread.EventFilter{TenantID: "t1", Category: "SECURITY"})
	if len(rowsT1) != 1 || rowsT1[0].DeviceID != devA || rowsT1[0].TenantID != "t1" {
		t.Fatalf("t1 yalnız kendi bulgusunu görmeli: %+v", rowsT1)
	}
	rowsT2, _ := st.QueryEvents(context.Background(), adminread.EventFilter{TenantID: "t2", Category: "SECURITY"})
	if len(rowsT2) != 1 || rowsT2[0].DeviceID != devB {
		t.Fatalf("t2 yalnız kendi bulgusunu görmeli: %+v", rowsT2)
	}
	// SSE yayını + uyarı kiracı-atıflı.
	if len(rec.pubs) != 2 || rec.pubs[0].tenant != "t1" || rec.pubs[1].tenant != "t2" {
		t.Fatalf("SSE yayınları cihaz kiracısıyla atıflanmalı: %+v", rec.pubs)
	}
	if rec.alts[0].Tenant != "t1" || rec.alts[0].DeviceID != devA {
		t.Fatalf("uyarı kiracı + cihaz taşımalı: %+v", rec.alts[0])
	}
}

// Fail-closed: zorlama açıkken kiracısı çözülemeyen (kayıtsız, ipucusuz) cihazın bulgusu
// YAZILMAZ; zorlama kapalıyken dağıtım varsayılanına düşer; arama hatası bulguyu atlar.
func TestAnalyzerTenantResolutionFailClosed(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	fe, rec := newEmitter(st, "Deploy", true)
	ev, al := finding("orphan")
	if tn, ok := fe.emit(ctx, "11111111-1111-1111-1111-111111111111", "", ev, al, false); ok || tn != "" {
		t.Fatalf("enforce açıkken kiracısız cihaz atlanmalı: %q %v", tn, ok)
	}
	if rows, _ := st.QueryEvents(ctx, adminread.EventFilter{}); len(rows) != 0 || len(rec.pubs) != 0 || len(rec.alts) != 0 {
		t.Fatal("atlanan bulgu kaydedilmemeli, yayınlanmamalı, uyarılmamalı")
	}
	// Çakışan ipucu (aynı cihaz iki kiracıyla damgalı) → her zaman atla.
	if _, ok := fe.emit(ctx, "11111111-1111-1111-1111-111111111111", hintConflict, ev, al, false); ok {
		t.Fatal("çelişen kiracı ipucu atlanmalı")
	}
	// Zorlama kapalı → dağıtım varsayılanı (normalize).
	feOff, _ := newEmitter(st, "Deploy", false)
	if tn, ok := feOff.emit(ctx, "11111111-1111-1111-1111-111111111111", "", ev, al, false); !ok || tn != "deploy" {
		t.Fatalf("enforce kapalıyken varsayılan kiracı: %q %v", tn, ok)
	}
	// Kayıtsız kaynak (örn. HTTP-ingest "cihazı"): sunucu-damgalı olay ipucu kullanılır.
	feHint, _ := newEmitter(st, "deploy", true)
	if tn, ok := feHint.emit(ctx, "22222222-2222-2222-2222-222222222222", "acme", ev, al, false); !ok || tn != "acme" {
		t.Fatalf("olay ipucu kiracısı: %q %v", tn, ok)
	}
	// Kayıt arama hatası → atla (yanlış kiracıya yazma).
	feErr := &findingEmitter{
		save:    st.SaveEvents,
		tenants: analyzerTenants{lookup: func(context.Context, string) (string, error) { return "", errors.New("db") }, deflt: "deploy"},
	}
	if _, ok := feErr.emit(ctx, "33333333-3333-3333-3333-333333333333", "acme", ev, al, false); ok {
		t.Fatal("kayıt arama hatasında bulgu atlanmalı")
	}
	// Kayıt, ipucuna ÜSTÜNDÜR (otorite).
	devA := enrollDev(t, st, "mac-x", "t1")
	if tn, ok := feHint.emit(ctx, devA, "evil-hint", ev, al, false); !ok || tn != "t1" {
		t.Fatalf("cihaz kaydı ipucundan üstün olmalı: %q %v", tn, ok)
	}
}

// kayıt başarısızsa ok=false (çağıran "uyarıldı" bayrağını set ETMEZ), yayın/uyarı
// yok; notifyAlways (zincir) ise uyarı yine iletilir. Sonraki başarılı deneme ok=true.
func TestAnalyzerSaveFailureDoesNotMarkAlerted(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	dev := enrollDev(t, st, "mac-1", "t1")
	rec := &pubRec{}
	failing := true
	fe := &findingEmitter{
		save: func(c context.Context, d string, evs []model.Event) (uint64, error) {
			if failing {
				return 0, errors.New("transient db error")
			}
			return st.SaveEvents(c, d, evs)
		},
		tenants: analyzerTenants{lookup: st.TenantForDevice, deflt: "deploy"},
		publish: rec.publish,
		notify:  rec.notify,
	}
	alerted := map[string]bool{}
	run := func(key string) {
		if alerted[key] {
			return
		}
		ev, al := finding("beacon")
		if _, ok := fe.emit(ctx, dev, "", ev, al, false); ok {
			alerted[key] = true // çağıran deseni: bayrak YALNIZ başarıdan sonra
		}
	}
	run("k")
	if alerted["k"] || len(rec.pubs) != 0 || len(rec.alts) != 0 {
		t.Fatalf("başarısız kayıtta bayrak/yayın/uyarı olmamalı: %v %+v", alerted, rec)
	}
	failing = false
	run("k") // geçici hata geçti: bulgu yeniden denenir ve yazılır
	if !alerted["k"] || len(rec.pubs) != 1 {
		t.Fatalf("sonraki turda yeniden denenip yazılmalı: %v %+v", alerted, rec)
	}
	// Zincir: kayıt başarısız olsa da uyarı iletilir.
	failing = true
	rec2 := &pubRec{}
	fe.publish, fe.notify = rec2.publish, rec2.notify
	ev, al := finding("chain")
	if _, ok := fe.emit(ctx, dev, "", ev, al, true); ok || len(rec2.alts) != 1 || len(rec2.pubs) != 0 {
		t.Fatalf("notifyAlways: kayıt hatasında uyarı yine gitmeli, yayın gitmemeli: %+v", rec2)
	}
}

// Details HER ZAMAN geçerli JSON (kontrol karakteri, geçersiz UTF-8, NaN/Inf).
func TestFindingDetailsAlwaysValidJSON(t *testing.T) {
	hostile := "evil\x01\a\x1b.\xff\xfe\"quote\\back .example.com"
	for _, m := range []map[string]any{
		{"dns_tunnel": true, "parent": hostile, "distinct_subdomains": 25},
		{"brute_force": true, "top_source": hostile, "window_sec": 300},
		{"beacon": true, "cov": math.NaN(), "x": math.Inf(1), "remote_ip": hostile},
	} {
		got := findingDetails(m)
		if !json.Valid([]byte(got)) {
			t.Fatalf("Details geçerli JSON olmalı: %q", got)
		}
		var back map[string]any
		if err := json.Unmarshal([]byte(got), &back); err != nil {
			t.Fatal(err)
		}
	}
	// Eski %q yaklaşımı bu girdide GEÇERSİZ JSON üretirdi (regresyon kanıtı).
	if json.Valid([]byte(`{"parent":"evil\x01\a\xff"}`)) {
		t.Fatal("kanıt: eski quoted-string biçimi geçersiz JSON üretir")
	}
}

func TestTenantHintsFromEvents(t *testing.T) {
	evs := []adminread.EventDTO{
		{DeviceID: "d1", TenantID: "a"}, {DeviceID: "d1", TenantID: "a"},
		{DeviceID: "d2", TenantID: "a"}, {DeviceID: "d2", TenantID: "b"},
		{DeviceID: "d3"}, {TenantID: "z"},
	}
	h := tenantHints(evs)
	if h["d1"] != "a" || h["d2"] != hintConflict {
		t.Fatalf("ipuçları: %+v", h)
	}
	if _, ok := h["d3"]; ok {
		t.Fatal("kiracısız olay ipucu üretmemeli")
	}
}

// Kalıcı fail-closed cihaz her turda yeniden denenir: sayaç her atlamada artar ama günlük
// satırı cihaz başına skipLogEvery'de en fazla bir kez yazılır.
func TestAnalyzerSkipLogRateLimited(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fe := &findingEmitter{nowFn: func() time.Time { return now }}
	if !fe.shouldLogSkip("dev-a") {
		t.Fatal("ilk atlama günlüğe yazılmalı")
	}
	for i := 0; i < 100; i++ {
		now = now.Add(time.Second)
		if fe.shouldLogSkip("dev-a") {
			t.Fatal("aralık içinde tekrar günlüklenmemeli")
		}
	}
	if !fe.shouldLogSkip("dev-b") {
		t.Fatal("başka cihaz bağımsız günlüklenmeli")
	}
	now = now.Add(skipLogEvery)
	if !fe.shouldLogSkip("dev-a") {
		t.Fatal("aralık sonrası yeniden günlüklenmeli")
	}
}
