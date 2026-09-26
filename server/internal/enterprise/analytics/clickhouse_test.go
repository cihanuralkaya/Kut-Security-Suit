//go:build enterprise

package analytics

import (
	"context"
	"os"
	"testing"
	"time"

	"kut.corp/suite/server/internal/model"
)

// chTestDSN, entegrasyon testleri için ClickHouse DSN'ini döner; ayarlı değilse test atlanır
// (ClickHouse gömülemez → CI'da ClickHouse servis konteyneri sağlar).
func chTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KUT_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("KUT_CLICKHOUSE_DSN ayarlı değil; ClickHouse entegrasyon testi atlandı (CI konteyner sağlar)")
	}
	return dsn
}

// Insert + CountBySeverity uçtan uca: yazılan olaylar önem düzeyine göre doğru sayılmalı.
func TestClickHouseInsertAndCount(t *testing.T) {
	dsn := chTestDSN(t)
	s, err := NewClickHouseStore(dsn)
	if err != nil {
		t.Fatalf("NewClickHouseStore: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)
	events := []model.Event{
		{Sequence: 1, TenantID: "t1", DeviceID: "d1", Category: "detection", Severity: "high", Message: "m1", OccurredAt: base},
		{Sequence: 2, TenantID: "t1", DeviceID: "d2", Category: "detection", Severity: "high", Message: "m2", OccurredAt: base.Add(time.Second)},
		{Sequence: 3, TenantID: "t1", DeviceID: "d3", Category: "audit", Severity: "low", Message: "m3", OccurredAt: base.Add(2 * time.Second)},
	}
	if err := s.Insert(ctx, events); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	// EventID yazımdan sonra doldurulmuş olmalı (idempotens temeli).
	for i := range events {
		if events[i].EventID == "" {
			t.Fatalf("Insert EventID doldurmadı: kayıt[%d]", i)
		}
	}

	// ClickHouse yazımı asenkron birleştirebilir; kısa bir tutarlılık beklemesi.
	var counts map[string]uint64
	for attempt := 0; attempt < 20; attempt++ {
		counts, err = s.CountBySeverity(ctx, base.Add(-time.Minute))
		if err != nil {
			t.Fatalf("CountBySeverity: %v", err)
		}
		if counts["high"] == 2 && counts["low"] == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if counts["high"] != 2 || counts["low"] != 1 {
		t.Fatalf("beklenen {high:2, low:1}, alınan %v", counts)
	}
}

// Boş Insert no-op olmalı (hata yok).
func TestClickHouseInsertEmpty(t *testing.T) {
	dsn := chTestDSN(t)
	s, err := NewClickHouseStore(dsn)
	if err != nil {
		t.Fatalf("NewClickHouseStore: %v", err)
	}
	defer s.Close()
	if err := s.Insert(context.Background(), nil); err != nil {
		t.Fatalf("boş Insert hata döndü: %v", err)
	}
}
