//go:build enterprise

// Command ingest — KUT-Scale (Enterprise) VERİ DÜZLEMİ giriş noktası. YALNIZ `//go:build
// enterprise` ile derlenir. Rol: dayanıklı bus'ın TÜKETİCİSİ — bus'tan bildirimleri okur,
// kanonik model.Event'e normalize eder ve analitik deposu (ClickHouse) + soğuk arşiv (S3/MinIO)
// sink'lerine idempotent yazar (vendor deseni: control-plane config/query; data-plane telemetri
// hattı — bkz. docs/BUILD-TIERS.md ve araştırma raporu). Detection AYRI bir stage'de (sonraki
// faz) bus'tan sonra çalışacak; bu daemon üreticiyi bloklamaz.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kut.corp/suite/server/internal/enterprise"
	"kut.corp/suite/server/internal/enterprise/analytics"
	"kut.corp/suite/server/internal/enterprise/archive"
	"kut.corp/suite/server/internal/enterprise/bus"
	"kut.corp/suite/server/internal/enterprise/pipeline"
)

const defaultDrainInterval = 5 * time.Second

func main() {
	log.SetPrefix("[ingest] ")
	log.Printf("KUT Security Suite %s — veri düzlemi (tüketici)", enterprise.Edition)

	// Kaynak: dayanıklı bus (üreticiyle AYNI backend). KUT_BUS_BACKEND ile seçilir.
	src, desc, err := bus.OpenDurableLog()
	if err != nil {
		log.Fatalf("dayanıklı bus açılamadı: %v", err)
	}
	defer src.Close()
	log.Printf("kaynak: %s", desc)

	// Sink'ler (opsiyonel): yalnız yapılandırılmışsa açılır.
	var an analytics.AnalyticsStore
	if dsn := os.Getenv("KUT_CLICKHOUSE_DSN"); dsn != "" {
		ch, err := analytics.NewClickHouseStore(dsn)
		if err != nil {
			log.Fatalf("analitik deposu açılamadı: %v", err)
		}
		defer ch.Close()
		an = ch
		log.Println("sink: ClickHouse analitik")
	}
	var ar archive.Archive
	if ep := os.Getenv("KUT_S3_ENDPOINT"); ep != "" {
		s3, err := archive.NewS3Archive(ep, os.Getenv("KUT_S3_ACCESS_KEY"),
			os.Getenv("KUT_S3_SECRET_KEY"), envOr("KUT_S3_BUCKET", "kut-archive"),
			os.Getenv("KUT_S3_USE_SSL") == "1")
		if err != nil {
			log.Fatalf("arşiv açılamadı: %v", err)
		}
		ar = s3
		log.Println("sink: S3/MinIO arşiv")
	}
	if an == nil && ar == nil {
		log.Println("uyarı: hiçbir sink yapılandırılmadı (KUT_CLICKHOUSE_DSN / KUT_S3_ENDPOINT) — hat boşta drenaj yapar")
	}

	p := pipeline.New(src, an, ar)
	interval := envDuration("KUT_INGEST_INTERVAL", defaultDrainInterval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("veri düzlemi çalışıyor (drenaj aralığı %s); kapanış sinyali bekleniyor", interval)
	for {
		if n, err := p.ProcessAll(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("drenaj hatası: %v", err)
		} else if n > 0 {
			log.Printf("işlendi: %d olay", n)
		}
		select {
		case <-ctx.Done():
			log.Println("kapanış sinyali alındı; temiz kapanıyor")
			return
		case <-ticker.C:
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
