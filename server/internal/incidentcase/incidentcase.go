// Package incidentcase, korelasyon incident'lerini SOC vakalarına bağlayan ince bir
// yapıştırıcıdır (SOC otomasyonu: tespit → incident → VAKA). Bir correlate.IncidentSink
// dekoratörü olarak çalışır: sarmaladığı asıl sink'e delege eder ve YENİ bir incident
// açıldığında otomatik olarak bir casemgmt vakası da açar. Böylece aynı saldırının
// tespitleri tek bir incelenebilir vakada toplanır; vaka açılışı best-effort'tur ve
// ingest/korelasyon yolunu ASLA kesmez (vaka açılamazsa incident yine de açılır).
package incidentcase

import (
	"context"
	"log"
	"time"

	"kut.corp/suite/server/internal/casemgmt"
	"kut.corp/suite/server/internal/correlate"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/tenant"
)

// TenantResolver, bir cihazın kiracısını çözer (server-side; enrollment'ta bağlanan).
// Store'un TenantForDevice metodu bu imzayı doğrudan karşılar.
type TenantResolver func(ctx context.Context, deviceID string) (string, error)

// Sink, otomatik vaka açan bir correlate.IncidentSink dekoratörüdür.
type Sink struct {
	inner    correlate.IncidentSink
	cases    casemgmt.Store
	tenantOf TenantResolver
	enforce  bool // KUT_TENANT_ENFORCE: kiracısız (legacy) cihaz için vaka AÇILMAZ (INV-044)
}

// New, inner sink'i sararak otomatik vaka açan bir Sink döner. cases nil ise vaka
// açılmaz (yalnız delege). tenantOf, tetikleyen CİHAZIN kiracısını çözer → otomatik
// vaka, olayın/cihazın kiracısını taşır (dağıtım-geneli sabit değil).
//
// FAIL-CLOSED: kiracı çözümlemesi hata verirse (ya da çözümleyici yoksa) vaka
// AÇILMAZ ve sayılır — "default" kovasına düşülmez (aksi halde bir kiracının incident'i
// başka kiracının vaka kuyruğuna karışırdı). Boş dönen kiracı kiracı-öncesi (legacy) cihazdır
// ve tenant.Canonical ile "default" kiracısıdır; WithEnforce(true) iken o da atlanır.
func New(inner correlate.IncidentSink, cases casemgmt.Store, tenantOf TenantResolver) *Sink {
	return &Sink{inner: inner, cases: cases, tenantOf: tenantOf}
}

// WithEnforce, sıkı çok-kiracı zorlamasını (KUT_TENANT_ENFORCE) ayarlar: açıkken kiracıya
// bağlı olmayan cihaz için vaka açılmaz (INV-044: eksik kiracı → DENY).
func (s *Sink) WithEnforce(on bool) *Sink {
	s.enforce = on
	return s
}

// caseTenant, vakanın kiracısını çözer; ok=false ise vaka açılmamalıdır.
func (s *Sink) caseTenant(ctx context.Context, deviceID string) (string, bool) {
	if s.tenantOf == nil {
		return "", false
	}
	t, err := s.tenantOf(ctx, deviceID)
	if err != nil {
		return "", false
	}
	if t == "" {
		if s.enforce {
			return "", false
		}
		return tenant.Canonical(""), true
	}
	return t, true
}

// OpenIncident, asıl sink'e delege eder ve başarılıysa otomatik bir vaka açar
// (best-effort). Vaka id'si "case-<incidentID>" ile incident'e bağlanır ve incident
// referansı delil olarak eklenir; cihaz varlık, teknik MITRE olarak iliştirilir.
func (s *Sink) OpenIncident(ctx context.Context, deviceID, key, ruleID, technique, severity, message string, at time.Time) (string, error) {
	id, err := s.inner.OpenIncident(ctx, deviceID, key, ruleID, technique, severity, message, at)
	if err != nil || id == "" || s.cases == nil {
		return id, err
	}
	// Vaka, tetikleyen cihazın kiracısını taşır (server-side; çapraz-kiracı vaka sızıntısını
	// önler). Çözülemezse vaka AÇILMAZ (fail-closed) — incident yine açılmıştır, atlanma sayılır.
	caseTenant, ok := s.caseTenant(ctx, deviceID)
	if !ok {
		metrics.IncIncidentCaseSkipped()
		log.Printf("[incidentcase] cihaz %s: kiracı çözülemedi — otomatik vaka açılmadı (incident %s)", deviceID, id)
		return id, err
	}
	if _, cerr := s.cases.Create(casemgmt.Case{
		ID:           "case-" + id,
		TenantID:     caseTenant,
		Title:        message,
		Severity:     mapSeverity(severity),
		Owner:        "system", // otomatik açıldı; bir analist Assign ile devralır
		Assets:       nonEmpty(deviceID),
		MITRE:        nonEmpty(technique),
		EvidenceRefs: []string{"incident:" + id},
	}); cerr != nil {
		// Vaka yazım hatası sessizce yutulmaz (görünür metrik + log); incident yine açıktır.
		metrics.IncIncidentCaseError()
		log.Printf("[incidentcase] cihaz %s: vaka oluşturulamadı (incident %s): %v", deviceID, id, cerr)
	}
	return id, err
}

// BumpIncident, yalnız asıl sink'e delege eder (mevcut incident'in güncellenmesi
// yeni vaka açmaz — vaka zaten vardır).
func (s *Sink) BumpIncident(ctx context.Context, id string, at time.Time) error {
	return s.inner.BumpIncident(ctx, id, at)
}

// mapSeverity, incident önem-düzeyi metnini casemgmt.Severity'ye eşler (bilinmeyen
// → MEDIUM, güvenli varsayılan).
func mapSeverity(sev string) casemgmt.Severity {
	switch sev {
	case "CRITICAL", "critical":
		return casemgmt.SeverityCritical
	case "HIGH", "high":
		return casemgmt.SeverityHigh
	case "LOW", "low", "INFO", "info":
		return casemgmt.SeverityLow
	default:
		return casemgmt.SeverityMedium
	}
}

// nonEmpty, boş olmayan bir dizgeyi tek-elemanlı dilim yapar (boşsa nil).
func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
