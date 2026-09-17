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
	s := New(inner, cases, "t1")

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
	s := New(inner, cases, "t1")
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
	s := New(inner, cases, "t1")
	if _, err := s.OpenIncident(context.Background(), "pc-1", "k", "R1", "T1", "HIGH", "x", time.Now()); err == nil {
		t.Fatal("asıl sink hatası yayılmalı")
	}
	if list, _ := cases.List("t1"); len(list) != 0 {
		t.Fatal("asıl sink hatasında vaka açılmamalı (incident açılmadı)")
	}
}
