package app

// analyzer_emit.go — sunucu-taraflı arka plan analizörlerinin (beacon, yanal hareket, DNS
// tüneli, kaba-kuvvet, zincir) bulgu yazma yolu. Önceden her analizör kendi
// model.Event'ini KİRACISIZ kuruyor (INV-044 ihlali), Details'i %q ile elle üretiyor
// (kontrol karakteri/geçersiz UTF-8 → geçersiz JSON → JSONB insert hatası → bulgu sessizce
// kayboluyor) ve "uyarıldı" bayrağını kaydın başarısına bakmadan set ediyordu (Z2-03/04).
//
// Bu dosya saf, test edilebilir yardımcıları toplar:
//   - analyzerTenants: bulgunun kiracısını SUNUCU-TARAFI çözer (cihaz kaydı → cihazın kendi
//     olaylarındaki sunucu-damgalı kiracı → dağıtım varsayılanı; KUT_TENANT_ENFORCE'ta
//     varsayılana DÜŞMEZ, bulgu atlanır).
//   - findingDetails: encoding/json ile HER ZAMAN geçerli JSON üretir.
//   - findingEmitter: kiracıyı damgalar, kaydeder; yalnız BAŞARILI kayıttan sonra yayın/uyarı
//     yapar ve başarıyı çağırana bildirir (çağıran "uyarıldı" bayrağını ancak o zaman set eder).
//
// NOT (W3'e bırakıldı — Z2-05): analizörler olayları hâlâ adminread.QueryEvents üzerinden
// okur ve bu yol sorgu başına 1000 satırla sınırlıdır; sayfalı/toplamalı bir tarama yolu
// W3 dalgasında ele alınacaktır.

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/notify"
	"kut.corp/suite/server/internal/tenant"
)

// hintConflict, aynı cihazın pencere içinde FARKLI kiracılarla damgalı olaylarının
// varlığını işaretler (kiracı belirsiz → bulgu atlanır, asla tahmin edilmez).
const hintConflict = "\x00conflict"

// analyzerTenants, bir analizör bulgusunun kiracısını çözer.
type analyzerTenants struct {
	lookup  func(ctx context.Context, deviceID string) (string, error) // cihaz kaydı (backend.TenantForDevice)
	deflt   string                                                     // dağıtımın varsayılan kiracısı (KUT_TENANT_ID)
	enforce bool                                                       // KUT_TENANT_ENFORCE (INV-044)
}

// resolve, cihaz için bulgu kiracısını döner; ok=false ise bulgu ATLANMALI (fail-closed).
// Sıra: (1) cihaz kaydındaki kiracı (otorite); (2) kayıtsız/kiracısız cihaz için olayların
// kendi sunucu-damgalı kiracısı (hint — örn. HTTP-ingest kaynak "cihazları" kayıtlı değildir);
// (3) dağıtım varsayılanı — YALNIZ zorlama kapalıyken. Kayıt aranırken hata → atla (geçici
// hata bulguyu yanlış kiracıya yazmasın; sonraki turda yeniden denenir).
func (a analyzerTenants) resolve(ctx context.Context, deviceID, hint string) (string, bool) {
	if deviceID == "" {
		return "", false
	}
	if a.lookup != nil {
		t, err := a.lookup(ctx, deviceID)
		if err != nil {
			return "", false
		}
		if t != "" {
			return t, true
		}
	}
	if hint == hintConflict {
		return "", false
	}
	if hint != "" {
		return hint, true
	}
	if a.enforce {
		return "", false
	}
	return tenant.Canonical(strings.ToLower(strings.TrimSpace(a.deflt))), true
}

// tenantHints, olay penceresinden cihaz → sunucu-damgalı kiracı eşlemesini çıkarır.
// Aynı cihaz için farklı kiracılar görülürse hintConflict işaretlenir.
func tenantHints(evs []adminread.EventDTO) map[string]string {
	hints := map[string]string{}
	for _, e := range evs {
		if e.DeviceID == "" || e.TenantID == "" {
			continue
		}
		switch prev, seen := hints[e.DeviceID]; {
		case !seen:
			hints[e.DeviceID] = e.TenantID
		case prev != e.TenantID:
			hints[e.DeviceID] = hintConflict
		}
	}
	return hints
}

// findingDetails, bulgu Details'ini encoding/json ile üretir: kontrol karakterleri kaçışlanır,
// geçersiz UTF-8 U+FFFD'ye çevrilir → çıktı HER ZAMAN geçerli JSON'dur (JSONB sütunu için).
// NaN/Inf gibi JSON'a çevrilemeyen sayılar 0'a indirilir; yine de hata olursa sabit geçerli
// bir JSON döner (bulgu asla "geçersiz JSON" yüzünden kaybolmaz).
func findingDetails(m map[string]any) string {
	for k, v := range m {
		if f, ok := v.(float64); ok && (math.IsNaN(f) || math.IsInf(f, 0)) {
			m[k] = 0.0
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return `{"details_encoding_error":true}`
	}
	return string(b)
}

// findingEmitter, bir analizör bulgusunu kiracıyla damgalayıp kaydeder ve yayınlar.
type findingEmitter struct {
	save    func(ctx context.Context, deviceID string, evs []model.Event) (uint64, error)
	tenants analyzerTenants
	publish func(tenantID, deviceID, severity, message string)
	notify  func(a notify.Alert)

	// Kiracı-çözülemedi günlüğünün hız sınırı (kalıcı fail-closed cihaz her tur aynı satırı
	// yazmasın): cihaz başına skipLogEvery'de en fazla bir satır. Sayaç (metrics) her atlamada artar.
	logMu   sync.Mutex
	logSeen map[string]time.Time
	nowFn   func() time.Time // test için; nil → time.Now
}

// skipLogEvery, aynı cihaz için "kiracı çözülemedi" günlüğünün asgari aralığıdır.
const skipLogEvery = 10 * time.Minute

// maxSkipLogDevices, hız-sınırı tablosunun üst sınırıdır (aşılırsa sıfırlanır → bellek sınırlı).
const maxSkipLogDevices = 4096

// shouldLogSkip, deviceID için atlama satırının şimdi yazılıp yazılmayacağını döner.
func (f *findingEmitter) shouldLogSkip(deviceID string) bool {
	now := time.Now()
	if f.nowFn != nil {
		now = f.nowFn()
	}
	f.logMu.Lock()
	defer f.logMu.Unlock()
	if last, ok := f.logSeen[deviceID]; ok && now.Sub(last) < skipLogEvery {
		return false
	}
	if f.logSeen == nil || len(f.logSeen) >= maxSkipLogDevices {
		f.logSeen = map[string]time.Time{}
	}
	f.logSeen[deviceID] = now
	return true
}

// emit, bulguyu kaydeder. Dönen tenantID, bulgunun yazıldığı kiracıdır; ok=true YALNIZ kayıt
// başarılıysa. Çağıran "uyarıldı" bayrağını / incident izlemeyi ancak ok ise yapmalıdır —
// geçici bir DB hatası bulguyu kalıcı olarak susturmaz (sonraki turda yeniden denenir).
// notifyAlways=true ise (zincir bulguları) uyarı kayıt sonucundan bağımsız iletilir.
// Kiracı çözülemezse bulgu YAZILMAZ ve sayılır (fail-closed).
func (f *findingEmitter) emit(ctx context.Context, deviceID, hint string, ev model.Event, alert notify.Alert, notifyAlways bool) (string, bool) {
	tn, ok := f.tenants.resolve(ctx, deviceID, hint)
	if !ok {
		metrics.IncAnalyzerSkipped()
		if f.shouldLogSkip(deviceID) {
			log.Printf("[analyzer] cihaz %s: kiracı çözülemedi — bulgu atlandı (fail-closed; günlük %s'de bir)", deviceID, skipLogEvery)
		}

		return "", false
	}
	ev.TenantID = tn
	alert.DeviceID = deviceID
	if tn != string(tenant.Default) {
		alert.Tenant = tn // "default" boş kalır (TenantStamper ile aynı sözleşme)
	}
	_, err := f.save(ctx, deviceID, []model.Event{ev})
	if err != nil {
		log.Printf("[analyzer] cihaz %s: bulgu kaydedilemedi: %v", deviceID, err)
		if notifyAlways && f.notify != nil {
			f.notify(alert)
		}
		return tn, false
	}
	if f.publish != nil {
		f.publish(tn, deviceID, ev.Severity, ev.Message)
	}
	if f.notify != nil {
		f.notify(alert)
	}
	return tn, true
}
