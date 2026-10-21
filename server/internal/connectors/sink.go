package connectors

import (
	"context"

	"kut.corp/suite/server/internal/logingest"
	"kut.corp/suite/server/internal/model"
)

// SaveFunc, bir cihaza ait olay grubunu kalıcılaştıran yoldur (backend.SaveEvents ile aynı imza).
type SaveFunc func(ctx context.Context, deviceID string, evs []model.Event) (uint64, error)

// StampTenant, bir bağlayıcının ürettiği olayları SUNUCU-TARAFI bilinen kiracıyla damgalar
// (Z3-02): TenantID ezilir (kaynak verisi kiracı seçemez) ve cihaz kimliği kiracıya
// ad-alanlanır (iki kiracının aynı kaynak adı çökmez; varsayılan kiracıda kimlik değişmez).
// Girdi dilimini yerinde değiştirir ve aynısını döner.
func StampTenant(evs []model.Event, tenantID string) []model.Event {
	for i := range evs {
		evs[i].TenantID = tenantID
		if evs[i].DeviceID != "" {
			evs[i].DeviceID = logingest.TenantDeviceID(tenantID, evs[i].DeviceID)
		}
	}
	return evs
}

// NewTenantSink, bir bağlayıcının sink'ini kurar: olayları kiracıyla damgalar (kaydetmeden
// ÖNCE; içerik-adresli EventID de kiracıyı kapsar), tekrarları isDup ile düşürür ve cihaz
// başına SaveEvents'e yazar. isDup nil ise yineleme-tespiti yoktur. Yazma hatası onErr'e
// bildirilir (nil olabilir) ve diğer cihazların yazımını kesmez.
//
// TODO(W3): bağlayıcı olayları henüz paylaşılan tespit hattından (ProcessEvent) GEÇMEZ —
// yalnız kaydedilir. Hatta bağlanması W3 dalgasının işidir; bu sink kiracıyı doğru
// damgalar ki o dalgada olaylar zaten kiracı-atıflı olsun.
func NewTenantSink(ctx context.Context, tenantID string, isDup func(*model.Event) bool, save SaveFunc, onErr func(deviceID string, err error)) func([]model.Event) {
	return func(evs []model.Event) {
		StampTenant(evs, tenantID)
		byDev := map[string][]model.Event{}
		for i := range evs {
			if isDup != nil && isDup(&evs[i]) {
				continue
			}
			byDev[evs[i].DeviceID] = append(byDev[evs[i].DeviceID], evs[i])
		}
		for dev, list := range byDev {
			if _, err := save(ctx, dev, list); err != nil && onErr != nil {
				onErr(dev, err)
			}
		}
	}
}
