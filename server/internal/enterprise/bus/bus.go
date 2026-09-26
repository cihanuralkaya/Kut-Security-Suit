//go:build enterprise

// Package bus (enterprise), dayanıklı telemetri bus'ını çekirdeğin eventbus seam'ine
// (SetSink) bağlar. Her bildirim önce dayanıklı kayda (DurableLog) yazılır, sonra yerel
// abonelere dağıtılır. Bu FAZ dosya-tabanlı DurableLog kullanır (dış bağımlılık YOK);
// gerçek Kafka/Redpanda producer'ı aynı DurableLog arayüzünü uygulayacak ve `//go:build
// enterprise` arkasında bu paketin yeni bir dosyasına gelecek (o an alt-ağaç nested-module'e
// taşınıp Lite go.mod'u tertemiz tutulur — bkz. docs/BUILD-TIERS.md).
package bus

import (
	"fmt"
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
	dl, desc, err := openBackend()
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
	log.Printf("KUT Enterprise bus: seam bağlandı (%s)", desc)
	return nil
}

// openBackend, KUT_BUS_BACKEND'e göre dayanıklı kaydı açar: "file" (varsayılan) veya
// "jetstream". İkincil dönen değer, log için insan-okur backend açıklamasıdır.
func openBackend() (DurableLog, string, error) {
	switch os.Getenv("KUT_BUS_BACKEND") {
	case "jetstream", "nats":
		url := os.Getenv("KUT_NATS_URL") // boş → gömülü sunucu
		store := os.Getenv("KUT_NATS_STORE")
		dl, err := NewJetStreamLog(url, store)
		if err != nil {
			return nil, "", err
		}
		if url == "" {
			return dl, "jetstream backend: gömülü sunucu", nil
		}
		return dl, fmt.Sprintf("jetstream backend: %s", url), nil
	case "kafka", "redpanda":
		url := os.Getenv("KUT_KAFKA_URL")
		topic := os.Getenv("KUT_KAFKA_TOPIC")
		dl, err := NewKafkaLog(url, topic)
		if err != nil {
			return nil, "", err
		}
		return dl, fmt.Sprintf("kafka backend: %s", url), nil
	default: // "file" veya boş
		path := os.Getenv("KUT_BUS_LOG")
		if path == "" {
			path = defaultLogPath
		}
		dl, err := NewFileLog(path)
		if err != nil {
			return nil, "", err
		}
		return dl, fmt.Sprintf("dosya kaydı %q", path), nil
	}
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
