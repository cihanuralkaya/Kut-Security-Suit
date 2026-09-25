//go:build enterprise

// Package enterprise, KUT-Scale (Enterprise) katmanının çekirdek seam'lerine bağlanma
// noktasıdır. YALNIZ `//go:build enterprise` ile derlenir. Bu paket ve altındakiler
// çekirdeği (eventbus/cluster/secrets/connector) YALNIZ arayüzler üzerinden genişletir;
// çekirdek bu paketi ASLA import etmez (bağımlılık yönü tek taraflı: enterprise → core).
// Ağır dış bağımlılıklar (Kafka/Redpanda, ClickHouse, object-store, KMS) buraya, bu build
// tag'i arkasına eklenir; Lite build (varsayılan) bunların hiçbirini görmez — böylece
// tek-binary/Postgres-only/zero-dep değişmezi korunur (bkz. docs/BUILD-TIERS.md).
package enterprise

import (
	"log"

	"kut.corp/suite/server/internal/enterprise/bus"
	"kut.corp/suite/server/internal/eventbus"
)

// Edition, çalışan sürümü etiketler (banner/telemetri/denetim).
const Edition = "Enterprise"

// Enable, Enterprise ölçek katmanını verilen çekirdek bileşenlerine bağlar. Şu an dayanıklı
// telemetri bus seam'ini kablolar; sonraki fazlarda analytics/object-store/secrets sağlayıcıları
// da buradan register edilir. İSKELE: gerçek altyapı istemcileri (henüz eklenmedi) bu tag'in
// arkasında yer alacak.
func Enable(b *eventbus.Bus) error {
	if err := bus.Register(b); err != nil {
		return err
	}
	log.Printf("KUT %s: ölçek katmanı etkin (seam'ler bağlandı)", Edition)
	return nil
}

// Shutdown, Enable ile bağlanan enterprise kaynaklarını temiz kapatır (dayanıklı bus
// kaydını boşaltıp kapatır). Enable'a simetriktir; süreç kapanışında çağrılmalıdır.
// Idempotenttir (tekrar çağrı no-op).
func Shutdown() error {
	if err := bus.Close(); err != nil {
		return err
	}
	log.Printf("KUT %s: ölçek katmanı temiz kapatıldı", Edition)
	return nil
}
