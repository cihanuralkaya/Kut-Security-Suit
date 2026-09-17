// Package incidentcase, korelasyon incident'lerini SOC vakalarına bağlayan ince bir
// yapıştırıcıdır (SOC otomasyonu: tespit → incident → VAKA). Bir correlate.IncidentSink
// dekoratörü olarak çalışır: sarmaladığı asıl sink'e delege eder ve YENİ bir incident
// açıldığında otomatik olarak bir casemgmt vakası da açar. Böylece aynı saldırının
// tespitleri tek bir incelenebilir vakada toplanır; vaka açılışı best-effort'tur ve
// ingest/korelasyon yolunu ASLA kesmez (vaka açılamazsa incident yine de açılır).
package incidentcase

import (
	"context"
	"time"

	"kut.corp/suite/server/internal/casemgmt"
	"kut.corp/suite/server/internal/correlate"
)

// Sink, otomatik vaka açan bir correlate.IncidentSink dekoratörüdür.
type Sink struct {
	inner  correlate.IncidentSink
	cases  casemgmt.Store
	tenant string
}

// New, inner sink'i sararak otomatik vaka açan bir Sink döner. cases nil ise vaka
// açılmaz (yalnız delege). tenant, açılan vakaların kiracısıdır (boşsa "default").
func New(inner correlate.IncidentSink, cases casemgmt.Store, tenant string) *Sink {
	if tenant == "" {
		tenant = "default"
	}
	return &Sink{inner: inner, cases: cases, tenant: tenant}
}

// OpenIncident, asıl sink'e delege eder ve başarılıysa otomatik bir vaka açar
// (best-effort). Vaka id'si "case-<incidentID>" ile incident'e bağlanır ve incident
// referansı delil olarak eklenir; cihaz varlık, teknik MITRE olarak iliştirilir.
func (s *Sink) OpenIncident(ctx context.Context, deviceID, key, ruleID, technique, severity, message string, at time.Time) (string, error) {
	id, err := s.inner.OpenIncident(ctx, deviceID, key, ruleID, technique, severity, message, at)
	if err != nil || id == "" || s.cases == nil {
		return id, err
	}
	_, _ = s.cases.Create(casemgmt.Case{
		ID:           "case-" + id,
		TenantID:     s.tenant,
		Title:        message,
		Severity:     mapSeverity(severity),
		Owner:        "system", // otomatik açıldı; bir analist Assign ile devralır
		Assets:       nonEmpty(deviceID),
		MITRE:        nonEmpty(technique),
		EvidenceRefs: []string{"incident:" + id},
	})
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
