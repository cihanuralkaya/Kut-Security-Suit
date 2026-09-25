//go:build enterprise

// Command control — KUT-Scale (Enterprise) KONTROL DÜZLEMİ giriş noktası. YALNIZ
// `//go:build enterprise` ile derlenir ve çekirdek `internal/` paketlerini (Lite c2 ile
// AYNI) + `internal/enterprise/*` katmanını yeniden kullanır. İSKELE: tam kontrol-düzlemi
// (IAM/tenant/policy/case + admin API) kablolaması sonraki fazda buraya taşınır; şu an
// yalnız enterprise seam'lerinin bağlandığını kanıtlar (bkz. docs/BUILD-TIERS.md).
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
	log.SetPrefix("[control] ")
	log.Printf("KUT Security Suite %s — kontrol düzlemi (iskele)", enterprise.Edition)
	bus := eventbus.New()
	if err := enterprise.Enable(bus); err != nil {
		log.Fatalf("enterprise katmanı etkinleştirilemedi: %v", err)
	}
	defer func() {
		if err := enterprise.Shutdown(); err != nil {
			log.Printf("kapanışta enterprise shutdown hatası: %v", err)
		}
	}()

	// TODO(enterprise): control-plane servislerini (admin API, IAM, tenant, policy, case) kabla.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Println("kontrol düzlemi iskelesi hazır (tam kablolama sonraki faz); kapanış sinyali bekleniyor")
	<-ctx.Done()
	log.Println("kapanış sinyali alındı; temiz kapanıyor")
}
