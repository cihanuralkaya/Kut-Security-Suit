//go:build enterprise

// Command control — KUT-Scale (Enterprise) KONTROL DÜZLEMİ giriş noktası. YALNIZ
// `//go:build enterprise` ile derlenir. Lite `cmd/c2` ile AYNI paylaşılan sunucu
// bootstrap'ını (internal/app) çalıştırır; TEK fark app.Run'a enterprise.Enable hook'unu
// geçmesidir → canlı olay bus'ının sink'i dayanıklı bus'a yönlenir (ingest veri-düzlemi
// bunu tüketir). Böylece üretici (agent → C2 → bus) ile veri-düzlemi (bus → analitik/arşiv)
// uçtan uca bağlanır; sunucu kablolaması Lite ile tek kaynakta paylaşılır (drift yok).
package main

import (
	"log"
	"os"

	"kut.corp/suite/logx"
	"kut.corp/suite/server/internal/app"
	"kut.corp/suite/server/internal/enterprise"
)

func main() {
	logx.Setup(os.Getenv("KUT_LOG_FORMAT"), "[control] ")
	log.Printf("KUT Security Suite %s — kontrol düzlemi (tam sunucu + dayanıklı bus)", enterprise.Edition)

	// app.Run bloklar; kapanış sinyalinde döner. enterprise.Enable hook olarak geçilir →
	// canlı bus oluşturulunca dayanıklı bus sink'i bağlanır. Kapanışta dayanıklı kayıt kapatılır.
	runErr := app.Run(enterprise.Enable)
	if err := enterprise.Shutdown(); err != nil {
		log.Printf("kapanışta enterprise shutdown hatası: %v", err)
	}
	if runErr != nil {
		log.Fatalf("başlatma hatası: %v", runErr)
	}
}
