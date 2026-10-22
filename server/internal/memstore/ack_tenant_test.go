package memstore

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/model"
)

// eventIDFor, bir kiracı için olay kaydeder ve (kararlı) kimliğini döner.
func eventIDFor(t *testing.T, s *Store, deviceID, tenantID string) string {
	t.Helper()
	if _, err := s.SaveEvents(context.Background(), deviceID, []model.Event{{
		TenantID: tenantID, Category: "SYSTEM", Severity: "INFO", Message: "m", OccurredAt: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[len(s.events)-1].id
}

// (memstore, db ile aynı): event_ack kiracısı OLAYIN kiracısıdır (ack ve vaka yolları);
// eski boş kiracı 'default'a kanonikleşir; bilinmeyen olay 'default' alır ve mevcut satırın
// kiracısını bozmaz. Kiracı yalnız olaydan gelir: Store API'sinde çağıranın kiracı girdisi yoktur.
func TestEventAckWritesEventTenant(t *testing.T) {
	ctx := context.Background()
	s := New()
	evA := eventIDFor(t, s, "dev-a", "acme")
	evLegacy := eventIDFor(t, s, "dev-l", "")

	if err := s.SetEventAck(ctx, evA, "adm", "ACKNOWLEDGED"); err != nil {
		t.Fatal(err)
	}
	if got := s.eventAcks[evA].tenant; got != "acme" {
		t.Fatalf("ack kiracısı olayın kiracısı olmalı: %q", got)
	}
	if err := s.SetEventCase(ctx, evA, "adm", "analist", "not"); err != nil {
		t.Fatal(err)
	}
	if rec := s.eventAcks[evA]; rec.tenant != "acme" || rec.status != "ACKNOWLEDGED" {
		t.Fatalf("vaka güncellemesi kiracıyı ve durumu korumalı: %+v", rec)
	}
	evB := eventIDFor(t, s, "dev-a", "acme")
	if err := s.SetEventCase(ctx, evB, "adm", "a", "n"); err != nil {
		t.Fatal(err)
	}
	if got := s.eventAcks[evB].tenant; got != "acme" {
		t.Fatalf("SetEventCase olay kiracısını yazmalı: %q", got)
	}

	// Legacy boş kiracılı olay → kanonik 'default'.
	if err := s.SetEventAck(ctx, evLegacy, "adm", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if got := s.eventAcks[evLegacy].tenant; got != "default" {
		t.Fatalf("legacy olay 'default' olmalı: %q", got)
	}

	// NEGATIF: bilinmeyen olay 'default' alır; mevcut satırın kiracısı bozulmaz.
	if err := s.SetEventAck(ctx, "ghost", "adm", "ACKNOWLEDGED"); err != nil {
		t.Fatal(err)
	}
	if got := s.eventAcks["ghost"].tenant; got != "default" {
		t.Fatalf("bilinmeyen olay 'default' olmalı: %q", got)
	}
	rec := s.eventAcks["ghost"]
	rec.tenant = "acme"
	s.eventAcks["ghost"] = rec
	if err := s.SetEventAck(ctx, "ghost", "adm", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if got := s.eventAcks["ghost"].tenant; got != "acme" {
		t.Fatalf("olay bulunamayınca mevcut kiracı korunmalı: %q", got)
	}
}

// (memstore): incident kiracısı cihazın kiracısıdır; legacy boş kiracı, cihazsız ve
// bilinmeyen cihaz 'default'. Okuma yolu (device→tenant) kiracıyı doğru süzer.
func TestOpenIncidentWritesDeviceTenant(t *testing.T) {
	ctx := context.Background()
	s := New()
	devA, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("ia"), TenantID: "acme"})
	devL, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("il"), TenantID: ""})

	tenantOf := func(id string) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, r := range s.incidents {
			if r.id == id {
				return r.tenant
			}
		}
		t.Fatalf("incident bulunamadı: %s", id)
		return ""
	}
	open := func(dev string) string {
		id, err := s.OpenIncident(ctx, dev, "k-"+dev, "R1", "T1059", "HIGH", "msg", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if got := tenantOf(open(devA)); got != "acme" {
		t.Fatalf("incident cihazın kiracısını yazmalı: %q", got)
	}
	if got := tenantOf(open(devL)); got != "default" {
		t.Fatalf("legacy cihaz incident'i 'default' olmalı: %q", got)
	}
	if got := tenantOf(open("")); got != "default" {
		t.Fatalf("cihazsız incident 'default' olmalı: %q", got)
	}
	if got := tenantOf(open("bilinmeyen")); got != "default" {
		t.Fatalf("bilinmeyen cihaz incident'i 'default' olmalı: %q", got)
	}
	rows, _ := s.ListIncidents(ctx, 100, "acme")
	if len(rows) != 1 || rows[0].DeviceID != devA {
		t.Fatalf("acme yalnız kendi cihazının incident'ini görmeli: %+v", rows)
	}
}
