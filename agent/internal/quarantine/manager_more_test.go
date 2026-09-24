package quarantine

import (
	"errors"
	"testing"

	"kut.corp/suite/agent/internal/collector"
)

// flakyIso, Release'i (opsiyonel) başarısız kılabilen bir sahte izolatördür.
type flakyIso struct {
	isolateCalls int
	releaseCalls int
	failRelease  bool
}

func (f *flakyIso) Isolate(_ []string) error {
	f.isolateCalls++
	return nil
}

func (f *flakyIso) Release() error {
	f.releaseCalls++
	if f.failRelease {
		return errors.New("firewall kuralları silinemedi")
	}
	return nil
}

func TestReleaseAfterApplyEmitsHigh(t *testing.T) {
	iso := &flakyIso{}
	buf := collector.NewBuffer(100)
	m := NewManager(iso, buf, []string{"10.0.0.1"})

	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if !m.Active() {
		t.Fatal("Apply sonrası active olmalı")
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if m.Active() {
		t.Fatal("Release sonrası active olmamalı")
	}
	if iso.releaseCalls != 1 {
		t.Fatalf("Release bir kez çağrılmalıydı, %d", iso.releaseCalls)
	}

	// 2 olay: Apply (HIGH) + Release (HIGH).
	evs := buf.Pending(0)
	if len(evs) != 2 {
		t.Fatalf("2 olay beklenirdi, %d", len(evs))
	}
	rel := evs[1]
	if rel.Category != "SECURITY" || rel.Severity != "HIGH" {
		t.Fatalf("Release olayı SECURITY/HIGH olmalı: %+v", rel)
	}
	if rel.Message == "" {
		t.Fatal("Release olay mesajı boş olmamalı")
	}
}

func TestReleaseFailureEmitsCritical(t *testing.T) {
	iso := &flakyIso{failRelease: true}
	buf := collector.NewBuffer(100)
	m := NewManager(iso, buf, nil)

	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(); err == nil {
		t.Fatal("Release başarısızsa hata dönmeliydi")
	}
	// Başarısız Release'te active DEĞİŞMEMELİ (hâlâ karantinada).
	if !m.Active() {
		t.Fatal("başarısız Release sonrası hâlâ karantinada olmalı")
	}

	evs := buf.Pending(0)
	if len(evs) != 2 {
		t.Fatalf("2 olay beklenirdi (apply HIGH + release CRITICAL), %d", len(evs))
	}
	last := evs[1]
	if last.Severity != "CRITICAL" {
		t.Fatalf("başarısız Release CRITICAL olmalı, %s", last.Severity)
	}
}

func TestActiveInitiallyFalse(t *testing.T) {
	m := NewManager(&flakyIso{}, collector.NewBuffer(10), nil)
	if m.Active() {
		t.Fatal("yeni Manager başlangıçta karantinada olmamalı")
	}
}

func TestNoopIsolator(t *testing.T) {
	var iso NoopIsolator
	if err := iso.Isolate([]string{"10.0.0.1", ""}); err != nil {
		t.Fatalf("NoopIsolator.Isolate hata dönmemeli: %v", err)
	}
	if err := iso.Release(); err != nil {
		t.Fatalf("NoopIsolator.Release hata dönmemeli: %v", err)
	}

	// Noop ile uçtan uca akış: Manager çalışır, ağ gerçekten kesilmez.
	buf := collector.NewBuffer(10)
	m := NewManager(iso, buf, []string{"10.0.0.1"})
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if !m.Active() {
		t.Fatal("Noop ile de Apply active yapmalı")
	}
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 2 {
		t.Fatalf("Noop akışında 2 olay beklenirdi, %d", buf.Len())
	}
}
