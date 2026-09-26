// Command c2, KUT Yönetim Sunucusunu (Command & Control) LITE katmanında başlatır.
// Tüm bootstrap paylaşılan `internal/app` paketindedir; bu main yalnız loglamayı kurar ve
// enterprise-hook'suz (nil) çağırır — Lite tek-binary, zero-heavy-dep. Enterprise katmanı
// için bkz. cmd/control (aynı app.Run'ı enterprise.Enable hook'uyla çağırır).
package main

import (
	"log"
	"os"

	"kut.corp/suite/logx"
	"kut.corp/suite/server/internal/app"
)

func main() {
	// Loglama biçimi: KUT_LOG_FORMAT=json ise yapısal JSON (SIEM/log toplama);
	// aksi halde "[c2] " prefix'li standart metin.
	logx.Setup(os.Getenv("KUT_LOG_FORMAT"), "[c2] ")

	if err := app.Run(nil); err != nil {
		log.Fatalf("başlatma hatası: %v", err)
	}
}
