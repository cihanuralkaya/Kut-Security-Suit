//go:build enterprise

// Package pipeline (enterprise), veri-düzlemi tüketici hattıdır: dayanıklı bus'tan (Source)
// bildirimleri okur, kanonik model.Event'e normalize eder ve idempotent olarak analitik
// deposuna (AnalyticsStore) + soğuk arşive (Archive) yazar. Vendor deseni (Panther/Chronicle/
// Wazuh): normalize ingest'te, depodan önce; detection AYRI bir stage'de (burada değil) bus'tan
// sonra çalışır → üretici yolu bloklanmaz. Bu paket `//go:build enterprise` arkasındadır.
//
// Tasarım notu: Source, bus.DurableLog'un yalnız Replay alt-kümesidir (yapısal arayüz) → pipeline
// bus paketine bağımlı olmaz; bus.DurableLog bu arayüzü kendiliğinden karşılar.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"

	"kut.corp/suite/server/internal/enterprise/analytics"
	"kut.corp/suite/server/internal/enterprise/archive"
	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/model"
)

// Source, tüketilecek dayanıklı kayıttır (bus.DurableLog'un Replay alt-kümesi).
type Source interface {
	Replay(fn func(eventbus.Notice) error) error
}

// Normalizer, ham bildirimi kanonik olaya dönüştürür (kaynak→model.Event).
type Normalizer func(eventbus.Notice) model.Event

// DefaultNormalize, hafif eventbus.Notice'i kanonik model.Event'e eşler ve kararlı EventID'yi
// güvence altına alır (idempotens/dedup temeli). Üretici zenginleştikçe bu eşleme genişletilebilir.
func DefaultNormalize(n eventbus.Notice) model.Event {
	e := model.Event{
		DeviceID:   n.DeviceID,
		Severity:   n.Severity,
		Message:    n.Message,
		Category:   n.Type, // "event" | "device"
		Source:     "endpoint",
		OccurredAt: n.At,
	}
	e.EnsureID()
	return e
}

// Pipeline, bir Source'u iki sink'e (analytics + archive) bağlar. Sink'ler nil olabilir
// (yapılandırılmamışsa atlanır).
type Pipeline struct {
	source    Source
	analytics analytics.AnalyticsStore // nil olabilir
	archive   archive.Archive          // nil olabilir
	normalize Normalizer
}

// New, bir pipeline kurar. normalize nil ise DefaultNormalize kullanılır.
func New(source Source, an analytics.AnalyticsStore, ar archive.Archive) *Pipeline {
	return &Pipeline{source: source, analytics: an, archive: ar, normalize: DefaultNormalize}
}

// WithNormalizer, normalize fonksiyonunu değiştirir (test/özelleştirme).
func (p *Pipeline) WithNormalizer(n Normalizer) *Pipeline {
	if n != nil {
		p.normalize = n
	}
	return p
}

// ProcessAll, kaynaktaki tüm bildirimleri (en eskiden en yeniye) tüketir: her birini normalize
// eder, arşive idempotent yazar (event_id anahtarlı) ve toplu olarak analitik deposuna ekler.
// İşlenen kayıt sayısını döner. İdempotenttir: aynı olayların yeniden işlenmesi (dedup anahtarı
// event_id) güvenlidir — at-least-once + idempotent sink deseni.
func (p *Pipeline) ProcessAll(ctx context.Context) (int, error) {
	var batch []model.Event
	count := 0
	err := p.source.Replay(func(n eventbus.Notice) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := p.normalize(n)
		if p.archive != nil {
			data, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("pipeline: kodlama: %w", err)
			}
			if err := p.archive.Put(ctx, archiveKey(e), data); err != nil {
				return err
			}
		}
		batch = append(batch, e)
		count++
		return nil
	})
	if err != nil {
		return count, err
	}
	if p.analytics != nil && len(batch) > 0 {
		if err := p.analytics.Insert(ctx, batch); err != nil {
			return count, err
		}
	}
	return count, nil
}

// archiveKey, olayı tenant + tarih + event_id ile anahtarlar (S3 prefix izolasyonu; idempotent).
func archiveKey(e model.Event) string {
	tenant := e.TenantID
	if tenant == "" {
		tenant = "unknown"
	}
	d := e.OccurredAt.UTC()
	return fmt.Sprintf("events/%s/%s/%s.json", tenant, d.Format("2006/01/02"), e.EventID)
}
