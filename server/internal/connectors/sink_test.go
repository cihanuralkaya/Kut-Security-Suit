package connectors

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/logingest"
	"kut.corp/suite/server/internal/model"
)

type recSave struct {
	saved map[string][]model.Event
	fail  bool
}

func (r *recSave) save(_ context.Context, dev string, evs []model.Event) (uint64, error) {
	if r.fail {
		return 0, errors.New("db down")
	}
	if r.saved == nil {
		r.saved = map[string][]model.Event{}
	}
	r.saved[dev] = append(r.saved[dev], evs...)
	return 0, nil
}

func mkEv(src string) model.Event {
	return model.Event{
		Category: "SECURITY", Severity: "HIGH", Message: "m", OccurredAt: time.Unix(1700000000, 0),
		DeviceID: logingest.SourceUUID(src),
		// Kaynak verisi kiracı SEÇMEYE çalışır: ezilmelidir.
		TenantID: "attacker-chosen",
	}
}

// Z3-02: her bağlayıcı yapılandırılmış kiracısıyla damgalanır (kaynak verisindeki değer ezilir)
// ve iki kiracının aynı kaynak adı ayrı cihaz kimliğine düşer.
func TestConnectorSinkStampsConfiguredTenant(t *testing.T) {
	var a, b recSave
	sinkA := NewTenantSink(context.Background(), "acme", nil, a.save, nil)
	sinkB := NewTenantSink(context.Background(), "globex", nil, b.save, nil)
	sinkA([]model.Event{mkEv("fw1")})
	sinkB([]model.Event{mkEv("fw1")})

	for dev, evs := range a.saved {
		for _, e := range evs {
			if e.TenantID != "acme" || e.DeviceID != dev {
				t.Fatalf("acme olayı acme damgalı olmalı: %+v (cihaz %s)", e, dev)
			}
		}
	}
	for dev, evs := range b.saved {
		for _, e := range evs {
			if e.TenantID != "globex" || e.DeviceID != dev {
				t.Fatalf("globex olayı globex damgalı olmalı: %+v", e)
			}
		}
	}
	var da, db string
	for d := range a.saved {
		da = d
	}
	for d := range b.saved {
		db = d
	}
	if da == "" || db == "" || da == db {
		t.Fatalf("aynı kaynak adı iki kiracıda AYRI cihaz olmalı: %q %q", da, db)
	}
}

// Varsayılan kiracı: cihaz kimliği değişmez (süreklilik), olay "default" damgalı (boş değil).
func TestConnectorSinkDefaultTenantKeepsDeviceID(t *testing.T) {
	var r recSave
	NewTenantSink(context.Background(), "default", nil, r.save, nil)([]model.Event{mkEv("fw1")})
	want := logingest.SourceUUID("fw1")
	evs := r.saved[want]
	if len(evs) != 1 || evs[0].TenantID != "default" {
		t.Fatalf("varsayılan kiracı kimliği korumalı ve damgalamalı: %+v", r.saved)
	}
}

// Yineleme tespiti kiracı damgasından SONRA çalışır; yazma hatası onErr'e bildirilir ve
// panik/kayıp sessiz olmaz.
func TestConnectorSinkDedupAndErrors(t *testing.T) {
	var r recSave
	seen := map[string]bool{}
	isDup := func(e *model.Event) bool {
		id := e.EnsureID()
		if seen[id] {
			return true
		}
		seen[id] = true
		return false
	}
	sink := NewTenantSink(context.Background(), "acme", isDup, r.save, nil)
	sink([]model.Event{mkEv("fw1")})
	sink([]model.Event{mkEv("fw1")}) // aynı olay → düşer
	total := 0
	for _, evs := range r.saved {
		total += len(evs)
	}
	if total != 1 {
		t.Fatalf("tekrar düşürülmeliydi, kaydedilen=%d", total)
	}

	var gotErr error
	bad := recSave{fail: true}
	NewTenantSink(context.Background(), "acme", nil, bad.save, func(_ string, err error) { gotErr = err })([]model.Event{mkEv("fw2")})
	if gotErr == nil {
		t.Fatal("yazma hatası onErr'e bildirilmeli")
	}
}

// SourceConfig kiracısı: boş → dağıtım varsayılanı; geçersiz biçim fail-closed (BuildAll hata).
func TestSourceConfigResolveTenant(t *testing.T) {
	c := SourceConfig{Name: "x"}
	if got, err := c.ResolveTenant("Deploy-1"); err != nil || got != "deploy-1" {
		t.Fatalf("boş kiracı dağıtım varsayılanına düşmeli: %q %v", got, err)
	}
	if got, err := c.ResolveTenant(""); err != nil || got != "default" {
		t.Fatalf("her ikisi boşsa default: %q %v", got, err)
	}
	c.Tenant = " ACME "
	if got, err := c.ResolveTenant("deploy"); err != nil || got != "acme" {
		t.Fatalf("yapılandırılmış kiracı normalize edilmeli: %q %v", got, err)
	}
	c.Tenant = "bad tenant!"
	if _, err := c.ResolveTenant("deploy"); err == nil {
		t.Fatal("geçersiz kiracı hata vermeli")
	}
	if _, err := BuildAll([]SourceConfig{{Name: "x", Format: "syslog", Source: "/nonexistent", Tenant: "bad tenant!"}}); err == nil {
		t.Fatal("BuildAll geçersiz kiracıyı fail-fast reddetmeli")
	}
}
