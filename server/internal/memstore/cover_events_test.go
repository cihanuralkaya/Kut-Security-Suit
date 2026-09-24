package memstore

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/model"
)

// SaveEvents: en yüksek Sequence'ı döner; olayları saklar (ListEvents ile görülür).
func TestSaveEventsReturnsMaxSequence(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)

	last, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 5, Category: "SECURITY", Severity: "HIGH", Message: "m1", OccurredAt: time.Now()},
		{Sequence: 12, Category: "SYSTEM", Severity: "INFO", Message: "m2", OccurredAt: time.Now()},
		{Sequence: 9, Category: "SYSTEM", Severity: "LOW", Message: "m3", OccurredAt: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if last != 12 {
		t.Fatalf("en yüksek sequence 12 dönmeliydi: %d", last)
	}

	// Boş girişte 0 döner.
	if l, _ := s.SaveEvents(ctx, id, nil); l != 0 {
		t.Fatalf("boş girişte 0 beklenirdi: %d", l)
	}

	evs, _ := s.ListEvents(ctx, id, "", "", 0)
	if len(evs) != 3 {
		t.Fatalf("3 olay saklanmalıydı: %d", len(evs))
	}
}

// ListEvents: en yeniden eskiye sıralı; deviceID/severity/category filtreleri;
// limit uygulanır.
func TestListEventsFiltersAndOrder(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	now := time.Now()

	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "SECURITY", Severity: "HIGH", Message: "first", OccurredAt: now},
		{Sequence: 2, Category: "SYSTEM", Severity: "INFO", Message: "second", OccurredAt: now},
		{Sequence: 3, Category: "SECURITY", Severity: "LOW", Message: "third", OccurredAt: now},
	}); err != nil {
		t.Fatal(err)
	}

	all, _ := s.ListEvents(ctx, id, "", "", 0)
	if len(all) != 3 {
		t.Fatalf("3 olay beklenirdi: %d", len(all))
	}
	// En yeniden eskiye: "third" ilk.
	if all[0].Message != "third" {
		t.Fatalf("en yeni olay ilk sırada olmalıydı: %q", all[0].Message)
	}

	// severity filtresi.
	high, _ := s.ListEvents(ctx, id, "HIGH", "", 0)
	if len(high) != 1 || high[0].Message != "first" {
		t.Fatalf("HIGH filtresi hatalı: %+v", high)
	}
	// category filtresi.
	sec, _ := s.ListEvents(ctx, id, "", "SECURITY", 0)
	if len(sec) != 2 {
		t.Fatalf("SECURITY kategorisi 2 olay dönmeliydi: %d", len(sec))
	}
	// limit.
	lim, _ := s.ListEvents(ctx, id, "", "", 1)
	if len(lim) != 1 {
		t.Fatalf("limit=1 uygulanmalıydı: %d", len(lim))
	}
	// Bilinmeyen cihaz.
	none, _ := s.ListEvents(ctx, "yok", "", "", 0)
	if len(none) != 0 {
		t.Fatalf("bilinmeyen cihazda olay olmamalıydı: %d", len(none))
	}
}

// QueryEvents: mesaj alt-dize (harf duyarsız), zaman penceresi ve limit filtreleri.
func TestQueryEventsFilters(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	base := time.Now()

	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "SECURITY", Severity: "HIGH", Message: "Malware detected", OccurredAt: base},
		{Sequence: 2, Category: "SYSTEM", Severity: "INFO", Message: "Login OK", OccurredAt: base},
	}); err != nil {
		t.Fatal(err)
	}

	// MessageContains harf duyarsız.
	mw, _ := s.QueryEvents(ctx, adminread.EventFilter{MessageContains: "malware"})
	if len(mw) != 1 || mw[0].Message != "Malware detected" {
		t.Fatalf("MessageContains harf-duyarsız eşleşmeliydi: %+v", mw)
	}

	// Since gelecekte → hiçbir olay.
	future, _ := s.QueryEvents(ctx, adminread.EventFilter{Since: base.Add(time.Hour)})
	if len(future) != 0 {
		t.Fatalf("Since gelecekte olduğunda olay dönmemeliydi: %d", len(future))
	}

	// Until geçmişte → hiçbir olay.
	past, _ := s.QueryEvents(ctx, adminread.EventFilter{Until: base.Add(-time.Hour)})
	if len(past) != 0 {
		t.Fatalf("Until geçmişte olduğunda olay dönmemeliydi: %d", len(past))
	}

	// Severity + limit.
	sev, _ := s.QueryEvents(ctx, adminread.EventFilter{Severity: "HIGH", Limit: 5})
	if len(sev) != 1 {
		t.Fatalf("Severity=HIGH 1 olay dönmeliydi: %d", len(sev))
	}

	// Geniş pencere: her iki olay.
	win, _ := s.QueryEvents(ctx, adminread.EventFilter{Since: base.Add(-time.Hour), Until: base.Add(time.Hour)})
	if len(win) != 2 {
		t.Fatalf("zaman penceresi 2 olay dönmeliydi: %d", len(win))
	}
}

// EventSeverityCounts / EventCategoryCounts: since'e göre gruplu sayım.
func TestEventSeverityAndCategoryCounts(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	now := time.Now()

	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "SECURITY", Severity: "HIGH", Message: "a", OccurredAt: now},
		{Sequence: 2, Category: "SECURITY", Severity: "HIGH", Message: "b", OccurredAt: now},
		{Sequence: 3, Category: "SYSTEM", Severity: "INFO", Message: "c", OccurredAt: now},
	}); err != nil {
		t.Fatal(err)
	}

	sev, _ := s.EventSeverityCounts(ctx, now.Add(-time.Hour))
	if sev["HIGH"] != 2 || sev["INFO"] != 1 {
		t.Fatalf("severity sayımı hatalı: %+v", sev)
	}
	cat, _ := s.EventCategoryCounts(ctx, now.Add(-time.Hour))
	if cat["SECURITY"] != 2 || cat["SYSTEM"] != 1 {
		t.Fatalf("category sayımı hatalı: %+v", cat)
	}

	// since gelecekte → boş.
	empty, _ := s.EventSeverityCounts(ctx, now.Add(time.Hour))
	if len(empty) != 0 {
		t.Fatalf("since gelecekte olduğunda sayım boş olmalıydı: %+v", empty)
	}
}

// DeviceStatusCounts: cihaz durumlarına göre sayım.
func TestDeviceStatusCounts(t *testing.T) {
	ctx := context.Background()
	s := New()
	a, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("sc-a")})
	b, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("sc-b")})
	c, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("sc-c")})

	if err := s.SetDeviceStatus(ctx, b, "OFFLINE"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceStatus(ctx, c, "QUARANTINED"); err != nil {
		t.Fatal(err)
	}
	_ = a // ACTIVE kalır

	counts, err := s.DeviceStatusCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["ACTIVE"] != 1 || counts["OFFLINE"] != 1 || counts["QUARANTINED"] != 1 {
		t.Fatalf("durum sayımı hatalı: %+v", counts)
	}
}

// SetEventAck / SetEventCase / EventAcks: ack durumu ve vaka alanları upsert edilir,
// adminID e-postaya çözülür; ayrı çağrılar birbirinin alanını korur.
func TestEventAckAndCase(t *testing.T) {
	ctx := context.Background()
	s := New()
	adminID := s.SeedAdmin("triage@x", "h", "OPERATOR")

	if err := s.SetEventAck(ctx, "evt-1", adminID, "ACKED"); err != nil {
		t.Fatal(err)
	}
	// SetEventCase status'u korumalı, assignee/note eklemeli.
	if err := s.SetEventCase(ctx, "evt-1", adminID, "analyst@x", "incele"); err != nil {
		t.Fatal(err)
	}

	acks, err := s.EventAcks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := acks["evt-1"]
	if !ok {
		t.Fatal("evt-1 ack kaydı bulunmalıydı")
	}
	if got.Status != "ACKED" {
		t.Fatalf("status korunmalıydı: %q", got.Status)
	}
	if got.Assignee != "analyst@x" || got.Note != "incele" {
		t.Fatalf("vaka alanları hatalı: %+v", got)
	}
	if got.AdminEmail != "triage@x" {
		t.Fatalf("adminID e-postaya çözülmeliydi: %q", got.AdminEmail)
	}

	// Sonradan ack güncellemesi assignee/note'u korumalı.
	if err := s.SetEventAck(ctx, "evt-1", adminID, "CLOSED"); err != nil {
		t.Fatal(err)
	}
	acks, _ = s.EventAcks(ctx)
	if acks["evt-1"].Status != "CLOSED" || acks["evt-1"].Assignee != "analyst@x" {
		t.Fatalf("ack güncellemesi vaka alanlarını korumalıydı: %+v", acks["evt-1"])
	}
}
