//go:build enterprise

// Package bus (enterprise), dayanıklı telemetri bus'ını çekirdeğin eventbus seam'ine
// (SetSink) bağlar. İSKELE: gerçek Kafka/Redpanda producer'ı BU dosyada, `//go:build
// enterprise` arkasında yer alacak (dış istemci ilk gerçek fazda eklenecek; o an bu alt-ağaç
// nested-module'e taşınıp Lite go.mod'u tertemiz tutulur — bkz. docs/BUILD-TIERS.md).
// Şimdilik yer-tutucu bir sink: yerel dağıtımı korur, bağlanma noktasını kanıtlar, dış
// bağımlılık EKLEMEZ.
package bus

import (
	"log"

	"kut.corp/suite/server/internal/eventbus"
)

// Register, verilen Bus'ın sink'ini Enterprise dayanıklı-bus adaptörüne yönlendirir.
func Register(b *eventbus.Bus) error {
	if b == nil {
		return nil
	}
	b.SetSink(func(n eventbus.Notice) {
		// TODO(enterprise): dayanıklı producer'a (franz-go/redpanda) yaz; sonra yerel dağıt.
		b.Deliver(n) // Deliver sink'i ÇAĞIRMAZ (yerel fan-out) → recursion yok.
	})
	log.Println("KUT Enterprise bus: seam bağlandı (yer-tutucu; durable producer sonraki fazda)")
	return nil
}
