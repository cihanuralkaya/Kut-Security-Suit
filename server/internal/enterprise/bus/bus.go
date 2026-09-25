//go:build enterprise

// Package bus (enterprise), dayanıklı telemetri bus'ını çekirdeğin eventbus seam'ine
// (SetSink) bağlar. Her bildirim önce dayanıklı kayda (DurableLog) yazılır, sonra yerel
// abonelere dağıtılır. Bu FAZ dosya-tabanlı DurableLog kullanır (dış bağımlılık YOK);
// gerçek Kafka/Redpanda producer'ı aynı DurableLog arayüzünü uygulayacak ve `//go:build
// enterprise` arkasında bu paketin yeni bir dosyasına gelecek (o an alt-ağaç nested-module'e
// taşınıp Lite go.mod'u tertemiz tutulur — bkz. docs/BUILD-TIERS.md).
package bus

import (
	"log"
	"os"
	"sync"

	"kut.corp/suite/server/internal/eventbus"
)

// defaultLogPath, KUT_BUS_LOG ayarlı değilse kullanılan yol. Süreç çalışma dizini
// (sunucu dağıtım dizini) kalıcıdır; operatörler kalıcı bir konum için KUT_BUS_LOG
// belirlemelidir.
const defaultLogPath = "kut-bus.log"

var (
	mu     sync.Mutex
	active DurableLog // Register tarafından set edilir; Close ile serbest bırakılır.
)

// Register, verilen Bus'ın sink'ini Enterprise dayanıklı-bus adaptörüne yönlendirir:
// bildirim önce DurableLog'a yazılır, sonra yerel dağıtılır.
func Register(b *eventbus.Bus) error {
	if b == nil {
		return nil
	}
	path := os.Getenv("KUT_BUS_LOG")
	if path == "" {
		path = defaultLogPath
	}
	dl, err := NewFileLog(path)
	if err != nil {
		return err
	}

	mu.Lock()
	if active != nil {
		_ = active.Close() // yeniden Register: önceki kaydı serbest bırak
	}
	active = dl
	mu.Unlock()

	b.SetSink(func(n eventbus.Notice) {
		// Dayanıklılık en iyi çabadır: kalıcı yazma başarısız olsa bile CANLI konsol
		// dağıtımını bloklamayız (mevcut "yavaş abone atla" kullanılabilirlik önyargısıyla
		// tutarlı). Hata fileLog.appendErr sayacında toplanır ve loglanır.
		if err := dl.Append(n); err != nil {
			log.Printf("KUT Enterprise bus: dayanıklı yazma başarısız (dağıtım sürüyor): %v", err)
		}
		b.Deliver(n) // Deliver sink'i ÇAĞIRMAZ (yerel fan-out) → recursion yok.
	})
	log.Printf("KUT Enterprise bus: seam bağlandı (dayanıklı kayıt %q)", path)
	return nil
}

// Close, aktif dayanıklı kaydı boşaltıp kapatır (süreç kapanışında çağrılır). Idempotenttir.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	if active == nil {
		return nil
	}
	err := active.Close()
	active = nil
	return err
}
