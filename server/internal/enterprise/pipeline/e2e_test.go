//go:build enterprise

package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enterprise/analytics"
	"kut.corp/suite/server/internal/enterprise/archive"
	"kut.corp/suite/server/internal/enterprise/bus"
	"kut.corp/suite/server/internal/eventbus"
)

// TestPipelineE2E, hattı SAHTE değil GERÇEK backend'lere karşı doğrular: dosya DurableLog
// kaynağı → pipeline → gerçek ClickHouse + gerçek S3 (s3mock). Sahte-testler kompozisyonu
// kanıtlayamaz (gerçek şema/insert/anahtar davranışı); bu test onu kapatır. Her iki backend
// env'i ayarlı değilse atlanır (CI'da adanmış konteyner job'ı sağlar).
func TestPipelineE2E(t *testing.T) {
	dsn := os.Getenv("KUT_CLICKHOUSE_DSN")
	s3ep := os.Getenv("KUT_S3_ENDPOINT")
	if dsn == "" || s3ep == "" {
		t.Skip("KUT_CLICKHOUSE_DSN ve KUT_S3_ENDPOINT gerekli; pipeline e2e atlandı (CI konteyner sağlar)")
	}

	// Kaynak: dosya dayanıklı kaydı (üreticinin yazacağı yerin yerine test seed'i).
	src, err := bus.NewFileLog(filepath.Join(t.TempDir(), "bus.log"))
	if err != nil {
		t.Fatalf("NewFileLog: %v", err)
	}
	defer src.Close()

	base := time.Now().UTC().Truncate(time.Second)
	seed := []eventbus.Notice{
		{Type: "event", DeviceID: "d1", Severity: "high", Message: "m1", At: base},
		{Type: "event", DeviceID: "d2", Severity: "high", Message: "m2", At: base.Add(time.Second)},
		{Type: "event", DeviceID: "d3", Severity: "low", Message: "m3", At: base.Add(2 * time.Second)},
	}
	for _, n := range seed {
		if err := src.Append(n); err != nil {
			t.Fatalf("seed Append: %v", err)
		}
	}

	an, err := analytics.NewClickHouseStore(dsn)
	if err != nil {
		t.Fatalf("ClickHouse: %v", err)
	}
	defer an.Close()
	ar, err := archive.NewS3Archive(s3ep, os.Getenv("KUT_S3_ACCESS_KEY"), os.Getenv("KUT_S3_SECRET_KEY"),
		"kut-e2e", false)
	if err != nil {
		t.Fatalf("S3: %v", err)
	}

	p := New(src, an, ar)
	ctx := context.Background()
	n, err := p.ProcessAll(ctx)
	if err != nil {
		t.Fatalf("ProcessAll: %v", err)
	}
	if n != 3 {
		t.Fatalf("işlenen=%d, beklenen 3", n)
	}

	// Analitik: ClickHouse'a gerçekten indi mi (async birleştirmeye kısa retry).
	var counts map[string]uint64
	for attempt := 0; attempt < 20; attempt++ {
		counts, err = an.CountBySeverity(ctx, base.Add(-time.Minute))
		if err != nil {
			t.Fatalf("CountBySeverity: %v", err)
		}
		if counts["high"] == 2 && counts["low"] == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if counts["high"] != 2 || counts["low"] != 1 {
		t.Fatalf("ClickHouse'ta beklenen {high:2, low:1}, alınan %v", counts)
	}

	// Arşiv: S3'e gerçekten yazıldı mı.
	keys, err := ar.List(ctx, "events/")
	if err != nil {
		t.Fatalf("archive List: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("S3'te beklenen 3 nesne, alınan %d: %v", len(keys), keys)
	}
}
