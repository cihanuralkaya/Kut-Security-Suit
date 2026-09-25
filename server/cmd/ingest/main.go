//go:build enterprise

// Command ingest — KUT-Scale (Enterprise) VERİ DÜZLEMİ giriş noktası (stateless ingest
// gateway/consumer). YALNIZ `//go:build enterprise` ile derlenir; çekirdek `internal/`
// (dedup/dlq/model/telemetryschema) + `internal/enterprise/*` (durable bus) yeniden kullanır.
// İSKELE: ajan/connector alımı → normalize (OCSF) → dayanıklı bus → analytics/object-store
// kablolaması sonraki fazda; şu an enterprise seam bağlanmasını kanıtlar (bkz. docs/BUILD-TIERS.md).
package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"kut.corp/suite/server/internal/enterprise"
	"kut.corp/suite/server/internal/eventbus"
)

func main() {
	log.SetPrefix("[ingest] ")
	log.Printf("KUT Security Suite %s — veri düzlemi (iskele)", enterprise.Edition)
	bus := eventbus.New()
	if err := enterprise.Enable(bus); err != nil {
		log.Fatalf("enterprise katmanı etkinleştirilemedi: %v", err)
	}
	defer func() {
		if err := enterprise.Shutdown(); err != nil {
			log.Printf("kapanışta enterprise shutdown hatası: %v", err)
		}
	}()

	// TODO(enterprise): ingest gateway (mTLS/gRPC) + normalize + durable-bus consumer'ı kabla.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Println("veri düzlemi iskelesi hazır (tam kablolama sonraki faz); kapanış sinyali bekleniyor")
	<-ctx.Done()
	log.Println("kapanış sinyali alındı; temiz kapanıyor")
}
