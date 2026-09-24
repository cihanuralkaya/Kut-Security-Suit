package memstore

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/model"
)

// LatestSoftwareByDevice: cihaz başına EN SON yazılım envanterini döner (yeni
// envanter eskisini gölgeler).
func TestLatestSoftwareByDevice(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	now := time.Now()

	// Eski envanter, sonra yeni envanter.
	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "INVENTORY", Message: "old", OccurredAt: now, Details: `{"software":["Old 1.0"]}`},
		{Sequence: 2, Category: "INVENTORY", Message: "new", OccurredAt: now, Details: `{"software":["Chrome 120","VLC 3.0"]}`},
	}); err != nil {
		t.Fatal(err)
	}

	m, err := s.LatestSoftwareByDevice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := m[id]
	if len(got) != 2 || got[0] != "Chrome 120" {
		t.Fatalf("en son envanter dönmeliydi: %+v", got)
	}
}

// SearchSoftware: harf-duyarsız alt-dize eşleşmesi; boş sorgu boş sonuç; cihaz
// başına yalnız en son envanter dikkate alınır.
func TestSearchSoftware(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	now := time.Now()

	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "INVENTORY", Message: "inv", OccurredAt: now, Details: `{"software":["Chrome 120","Firefox 100","VLC"]}`},
	}); err != nil {
		t.Fatal(err)
	}

	// Boş sorgu → boş harita.
	if r, _ := s.SearchSoftware(ctx, "   "); len(r) != 0 {
		t.Fatalf("boş sorgu boş dönmeliydi: %+v", r)
	}

	res, err := s.SearchSoftware(ctx, "fire")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, ok := res[id]
	if !ok || len(pkgs) != 1 || pkgs[0] != "Firefox 100" {
		t.Fatalf("harf-duyarsız eşleşme hatalı: %+v", res)
	}

	// Eşleşme yoksa cihaz haritada olmamalı.
	if r, _ := s.SearchSoftware(ctx, "zzz-yok"); len(r) != 0 {
		t.Fatalf("eşleşmesiz sorgu boş dönmeliydi: %+v", r)
	}
}

// LatestComplianceByDevice: cihaz başına EN SON disk_encryption/firewall durumu;
// uyum-olayı olmayan detaylar atlanır.
func TestLatestComplianceByDevice(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := enrollDevice(t, s)
	now := time.Now()

	if _, err := s.SaveEvents(ctx, id, []model.Event{
		{Sequence: 1, Category: "COMPLIANCE", Message: "old", OccurredAt: now, Details: `{"disk_encryption":"OFF","firewall":"OFF"}`},
		{Sequence: 2, Category: "OTHER", Message: "noise", OccurredAt: now, Details: `{"foo":"bar"}`},
		{Sequence: 3, Category: "COMPLIANCE", Message: "new", OccurredAt: now, Details: `{"disk_encryption":"ON","firewall":"ON"}`},
	}); err != nil {
		t.Fatal(err)
	}

	m, err := s.LatestComplianceByDevice(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Not: yeniden-eskiye gezilir; cihaz başına ilk görülen (en yeni) uyum-olayı.
	// Sıra: seq3 (uyum, ilk görülen) → kullanılır. seq2 uyum değil, atlanır.
	cs, ok := m[id]
	if !ok {
		t.Fatalf("cihaz uyum durumu bulunmalıydı: %+v", m)
	}
	if cs.Enc != "ON" || cs.Fw != "ON" {
		t.Fatalf("en son uyum durumu ON/ON olmalıydı: %+v", cs)
	}
}
