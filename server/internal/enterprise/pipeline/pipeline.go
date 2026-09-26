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
	"errors"
	"fmt"
	"log"
	"strings"

	"kut.corp/suite/server/internal/casemgmt"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/enterprise/analytics"
	"kut.corp/suite/server/internal/enterprise/archive"
	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/model"
)

// fallbackTenant, olay tenant_id taşımadığında (henüz tüm üreticiler doldurmuyor) arşiv
// prefix'i ve vaka kiracısı için kullanılan yer-tutucudur. Multi-tenant sertleştirmesinde
// tenant_id ingest'te sunucu-tarafı bağlanınca gerçek değerler dolacak.
const fallbackTenant = "default"

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

// Detector, kanonik bir olayı değerlendirip tespitler döndürür. Çekirdek `detect.Engine`
// bu imzayı kendiliğinden karşılar (yeniden kullanım; sıfırdan tespit yazılmaz). Detection
// bus'tan SONRA, ayrı bir stage olarak çalışır — üretici yolu bloklanmaz (vendor deseni).
type Detector interface {
	Evaluate(ev model.Event) []detect.Detection
}

// Alert, tetikleyen olay + tespit çiftidir (case-mgmt/uyarı katmanına iletilir).
type Alert struct {
	Event     model.Event      `json:"event"`
	Detection detect.Detection `json:"detection"`
}

// AlertSink, üretilen alarmları hedefe (case-mgmt, webhook, control-plane deposu) iletir.
type AlertSink interface {
	Emit(ctx context.Context, alerts []Alert) error
}

// LogAlertSink, alarmları loglar — en basit sink (kalıcı vaka deposu yoksa geri düşüş).
type LogAlertSink struct{}

// Emit, her alarmı yapılandırılmış tek satır olarak loglar.
func (LogAlertSink) Emit(_ context.Context, alerts []Alert) error {
	for _, a := range alerts {
		log.Printf("ALARM rule=%s (%q) sev=%s device=%s event=%s technique=%s",
			a.Detection.RuleID, a.Detection.RuleName, a.Detection.Severity,
			a.Event.DeviceID, a.Event.EventID, a.Detection.Technique.ID)
	}
	return nil
}

// CaseAlertSink, alarmları çekirdek casemgmt.Store'a vaka (incident) olarak yazar — control-plane
// konsolunun okuduğu AYNI kalıcı depo. Vaka kimliği event_id+rule_id'den türetilir → aynı alarmın
// yeniden işlenmesi çift vaka üretmez (ErrCaseExists başarı sayılır; at-least-once + idempotent).
type CaseAlertSink struct {
	store casemgmt.Store
	owner string
}

// NewCaseAlertSink, verilen vaka deposuna yazan bir sink kurar.
func NewCaseAlertSink(store casemgmt.Store) *CaseAlertSink {
	return &CaseAlertSink{store: store, owner: "detection"}
}

// Emit, her alarm için bir vaka oluşturur (idempotent).
func (s *CaseAlertSink) Emit(_ context.Context, alerts []Alert) error {
	for _, a := range alerts {
		tenant := a.Event.TenantID
		if tenant == "" {
			tenant = fallbackTenant
		}
		c := casemgmt.Case{
			ID:           caseID(a),
			TenantID:     tenant,
			Title:        fmt.Sprintf("%s — %s", a.Detection.RuleName, a.Event.DeviceID),
			Severity:     mapCaseSeverity(a.Detection.Severity),
			Owner:        s.owner,
			MITRE:        mitreRefs(a.Detection),
			EvidenceRefs: []string{a.Event.EventID},
		}
		if _, err := s.store.Create(c); err != nil {
			if errors.Is(err, casemgmt.ErrCaseExists) {
				continue // aynı alarm yeniden işlendi → yeni vaka açma
			}
			return fmt.Errorf("pipeline: vaka oluşturma: %w", err)
		}
	}
	return nil
}

// caseID, alarmdan kararlı (idempotent) bir vaka kimliği türetir.
func caseID(a Alert) string { return "case_" + a.Event.EventID + "_" + a.Detection.RuleID }

// mapCaseSeverity, tespit önem düzeyini vaka önem düzeyine eşler (bilinmeyen → MEDIUM).
func mapCaseSeverity(s string) casemgmt.Severity {
	switch strings.ToUpper(s) {
	case "LOW":
		return casemgmt.SeverityLow
	case "MEDIUM":
		return casemgmt.SeverityMedium
	case "HIGH":
		return casemgmt.SeverityHigh
	case "CRITICAL":
		return casemgmt.SeverityCritical
	default:
		return casemgmt.SeverityMedium
	}
}

// mitreRefs, tespitin MITRE tekniğini (varsa) vaka referansı olarak döner.
func mitreRefs(d detect.Detection) []string {
	if d.Technique.ID != "" {
		return []string{d.Technique.ID}
	}
	return nil
}

// Pipeline, bir Source'u iki sink'e (analytics + archive) bağlar ve opsiyonel olarak tespit
// çalıştırıp alarmları AlertSink'e iletir. Tüm sink'ler/detector nil olabilir (atlanır).
type Pipeline struct {
	source    Source
	analytics analytics.AnalyticsStore // nil olabilir
	archive   archive.Archive          // nil olabilir
	detector  Detector                 // nil olabilir
	alerts    AlertSink                // nil olabilir
	normalize Normalizer
	tenant    string // sunucu-tarafı bağlanan kiracı (boşsa dokunulmaz)
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

// WithDetection, tespit stage'ini etkinleştirir: her olay detector ile değerlendirilir ve
// üretilen alarmlar sink'e iletilir. İkisi de gerekli; biri nil ise detection atlanır.
func (p *Pipeline) WithDetection(d Detector, sink AlertSink) *Pipeline {
	p.detector = d
	p.alerts = sink
	return p
}

// WithTenant, SUNUCU-TARAFI kiracıyı ayarlar: normalize edilmiş her olayın tenant_id'si boşsa
// bu değerle doldurulur (araştırma ilkesi: tenant ingest'te bağlanır, client'tan güvenilmez).
// Böylece tüm downstream tiers (ClickHouse satırı, S3 prefix'i, vaka kiracısı) tenant-atıflı olur.
func (p *Pipeline) WithTenant(tenant string) *Pipeline {
	p.tenant = tenant
	return p
}

// ProcessAll, kaynaktaki tüm bildirimleri (en eskiden en yeniye) tüketir: her birini normalize
// eder, arşive idempotent yazar (event_id anahtarlı) ve toplu olarak analitik deposuna ekler.
// İşlenen kayıt sayısını döner. İdempotenttir: aynı olayların yeniden işlenmesi (dedup anahtarı
// event_id) güvenlidir — at-least-once + idempotent sink deseni.
func (p *Pipeline) ProcessAll(ctx context.Context) (int, error) {
	var batch []model.Event
	var alertBatch []Alert
	count := 0
	err := p.source.Replay(func(n eventbus.Notice) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := p.normalize(n)
		// Sunucu-tarafı kiracı bağlama: olay tenant taşımıyorsa yapılandırılan kiracıyı ata.
		if e.TenantID == "" && p.tenant != "" {
			e.TenantID = p.tenant
		}
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
		// Tespit stage'i: bus'tan sonra, üreticiyi bloklamadan (tüketici içinde).
		if p.detector != nil {
			for _, d := range p.detector.Evaluate(e) {
				alertBatch = append(alertBatch, Alert{Event: e, Detection: d})
			}
		}
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
	if p.alerts != nil && len(alertBatch) > 0 {
		if err := p.alerts.Emit(ctx, alertBatch); err != nil {
			return count, err
		}
	}
	return count, nil
}

// archiveKey, olayı tenant + tarih + event_id ile anahtarlar (S3 prefix izolasyonu; idempotent).
func archiveKey(e model.Event) string {
	tenant := e.TenantID
	if tenant == "" {
		tenant = fallbackTenant
	}
	d := e.OccurredAt.UTC()
	return fmt.Sprintf("events/%s/%s/%s.json", tenant, d.Format("2006/01/02"), e.EventID)
}
