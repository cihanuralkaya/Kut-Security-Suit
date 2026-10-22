package incidentcase

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/casemgmt"
)

// fakeSink, correlate.IncidentSink'i taklit eder ve çağrıları sayar.
type fakeSink struct {
	opened, bumped int
	id             string
	err            error
}

func (f *fakeSink) OpenIncident(_ context.Context, _, _, _, _, _, _ string, _ time.Time) (string, error) {
	f.opened++
	return f.id, f.err
}
func (f *fakeSink) BumpIncident(_ context.Context, _ string, _ time.Time) error {
	f.bumped++
	return nil
}

func TestOpenIncidentAlsoOpensCase(t *testing.T) {
	inner := &fakeSink{id: "inc-1"}
	cases := casemgmt.NewMemStore()
	s := New(inner, cases, func(context.Context, string) (string, error) { return "t1", nil })

	id, err := s.OpenIncident(context.Background(), "pc-1", "k", "R1", "T1059", "HIGH", "şüpheli powershell", time.Now())
	if err != nil || id != "inc-1" {
		t.Fatalf("asıl sink'e delege beklenirdi: %q %v", id, err)
	}
	c, err := cases.Get("t1", "case-inc-1")
	if err != nil {
		t.Fatalf("otomatik vaka açılmalı: %v", err)
	}
	if c.Severity != casemgmt.SeverityHigh {
		t.Fatalf("önem düzeyi eşlenmeli: %q", c.Severity)
	}
	if len(c.Assets) != 1 || c.Assets[0] != "pc-1" {
		t.Fatalf("cihaz varlık olarak eklenmeli: %+v", c.Assets)
	}
	if len(c.MITRE) != 1 || c.MITRE[0] != "T1059" {
		t.Fatalf("teknik MITRE olarak eklenmeli: %+v", c.MITRE)
	}
	if len(c.EvidenceRefs) != 1 || c.EvidenceRefs[0] != "incident:inc-1" {
		t.Fatalf("incident delil olarak bağlanmalı: %+v", c.EvidenceRefs)
	}
	if c.Owner != "system" {
		t.Fatalf("otomatik vaka sahibi 'system' olmalı: %q", c.Owner)
	}
}

func TestBumpDoesNotOpenCase(t *testing.T) {
	inner := &fakeSink{id: "inc-1"}
	cases := casemgmt.NewMemStore()
	s := New(inner, cases, func(context.Context, string) (string, error) { return "t1", nil })
	if err := s.BumpIncident(context.Background(), "inc-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if inner.bumped != 1 {
		t.Fatal("bump asıl sink'e delege edilmeli")
	}
	if list, _ := cases.List("t1"); len(list) != 0 {
		t.Fatalf("bump yeni vaka AÇMAMALI: %d", len(list))
	}
}

func TestOpenIncidentBestEffortOnInnerError(t *testing.T) {
	inner := &fakeSink{err: errors.New("db down")}
	cases := casemgmt.NewMemStore()
	s := New(inner, cases, func(context.Context, string) (string, error) { return "t1", nil })
	if _, err := s.OpenIncident(context.Background(), "pc-1", "k", "R1", "T1", "HIGH", "x", time.Now()); err == nil {
		t.Fatal("asıl sink hatası yayılmalı")
	}
	if list, _ := cases.List("t1"); len(list) != 0 {
		t.Fatal("asıl sink hatasında vaka açılmamalı (incident açılmadı)")
	}
}

// failCases, Create'i hata döndüren bir casemgmt.Store sarmalayıcısıdır.
type failCases struct {
	casemgmt.Store
	calls int
}

func (f *failCases) Create(c casemgmt.Case) (casemgmt.Case, error) {
	f.calls++
	return casemgmt.Case{}, errors.New("store down")
}

// kiracı çözümlemesi hata verirse vaka AÇILMAZ ("default" kovasına düşülmez); incident
// yine açılır. Pozitif: çözümlenen kiracıda vaka açılır ve yalnız o kiracıda görünür.
func TestOpenIncidentFailsClosedWhenTenantUnresolvable(t *testing.T) {
	inner := &fakeSink{id: "inc-9"}
	cases := casemgmt.NewMemStore()
	s := New(inner, cases, func(context.Context, string) (string, error) { return "", errors.New("db blip") })
	id, err := s.OpenIncident(context.Background(), "dev-1", "k", "R1", "T1059", "HIGH", "msg", time.Now())
	if err != nil || id != "inc-9" || inner.opened != 1 {
		t.Fatalf("incident yine açılmalı: %q %v %d", id, err, inner.opened)
	}
	if all, _ := cases.ListAll(); len(all) != 0 {
		t.Fatalf("çözümlenemeyen kiracıda vaka açılmamalı (default'a düşmemeli): %+v", all)
	}
	if d, _ := cases.List("default"); len(d) != 0 {
		t.Fatalf("default kovasında vaka olmamalı: %+v", d)
	}
	// Çözümleyici hiç yoksa da fail-closed.
	s2 := New(&fakeSink{id: "inc-10"}, cases, nil)
	_, _ = s2.OpenIncident(context.Background(), "dev-1", "k", "R1", "T1", "HIGH", "m", time.Now())
	if all, _ := cases.ListAll(); len(all) != 0 {
		t.Fatalf("çözümleyicisiz vaka açılmamalı: %+v", all)
	}
	// POZİTİF: çözümlenen kiracı.
	s3 := New(&fakeSink{id: "inc-11"}, cases, func(context.Context, string) (string, error) { return "acme", nil })
	_, _ = s3.OpenIncident(context.Background(), "dev-2", "k", "R1", "T1", "HIGH", "m", time.Now())
	if a, _ := cases.List("acme"); len(a) != 1 {
		t.Fatalf("acme vakası açılmalı: %+v", a)
	}
	if g, _ := cases.List("globex"); len(g) != 0 {
		t.Fatal("başka kiracıda vaka olmamalı")
	}
}

// Legacy (boş kiracı) cihaz: zorlama kapalıyken kanonik "default" kiracısı; zorlama AÇIKKEN atlanır.
func TestOpenIncidentLegacyTenantAndEnforce(t *testing.T) {
	blank := func(context.Context, string) (string, error) { return "", nil }
	cases := casemgmt.NewMemStore()
	s := New(&fakeSink{id: "inc-a"}, cases, blank)
	_, _ = s.OpenIncident(context.Background(), "dev-1", "k", "R", "T", "LOW", "m", time.Now())
	if d, _ := cases.List("default"); len(d) != 1 {
		t.Fatalf("legacy cihaz kanonik default kiracısında vaka açmalı: %+v", d)
	}
	cases2 := casemgmt.NewMemStore()
	se := New(&fakeSink{id: "inc-b"}, cases2, blank).WithEnforce(true)
	_, _ = se.OpenIncident(context.Background(), "dev-1", "k", "R", "T", "LOW", "m", time.Now())
	if all, _ := cases2.ListAll(); len(all) != 0 {
		t.Fatalf("enforce açıkken kiracısız cihaz için vaka açılmamalı: %+v", all)
	}
}

// Create hatası artık sessizce yutulmaz: incident döner ve hata çağrılmıştır (metrik+log).
func TestOpenIncidentCreateErrorSurfaced(t *testing.T) {
	fc := &failCases{Store: casemgmt.NewMemStore()}
	s := New(&fakeSink{id: "inc-c"}, fc, func(context.Context, string) (string, error) { return "acme", nil })
	id, err := s.OpenIncident(context.Background(), "dev-1", "k", "R", "T", "LOW", "m", time.Now())
	if err != nil || id != "inc-c" || fc.calls != 1 {
		t.Fatalf("incident etkilenmemeli, Create denenmeli: %q %v %d", id, err, fc.calls)
	}
}
