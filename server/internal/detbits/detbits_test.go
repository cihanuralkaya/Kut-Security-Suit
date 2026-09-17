package detbits

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestSetIsSet(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(clk.now)
	if s.IsSet("dev1", "recon") {
		t.Fatal("kurulmamış bit set görünmemeli")
	}
	s.Set("dev1", "recon", 60*time.Second)
	if !s.IsSet("dev1", "recon") {
		t.Fatal("kurulan bit set olmalı")
	}
	// Kapsam izolasyonu: başka cihazda görünmemeli.
	if s.IsSet("dev2", "recon") {
		t.Fatal("bit yalnız kurulduğu kapsamda görünmeli")
	}
}

func TestExpiry(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(clk.now)
	s.Set("dev1", "recon", 60*time.Second)
	clk.t = clk.t.Add(61 * time.Second)
	if s.IsSet("dev1", "recon") {
		t.Fatal("süresi dolan bit set görünmemeli")
	}
	if s.TrackedCount() != 0 {
		t.Fatalf("süresi dolan bit tembel silinmeli, TrackedCount=%d", s.TrackedCount())
	}
}

func TestAllSet(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(clk.now)
	if !s.AllSet("dev1", nil) {
		t.Fatal("boş koşul true olmalı")
	}
	s.Set("dev1", "a", time.Minute)
	if s.AllSet("dev1", []string{"a", "b"}) {
		t.Fatal("b kurulu değilken AllSet false olmalı")
	}
	s.Set("dev1", "b", time.Minute)
	if !s.AllSet("dev1", []string{"a", "b"}) {
		t.Fatal("a ve b kuruluyken AllSet true olmalı")
	}
	// Boş bit adları atlanmalı.
	if !s.AllSet("dev1", []string{"a", ""}) {
		t.Fatal("boş bit adı atlanmalı")
	}
}

func TestNoneSet(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(clk.now)
	if !s.NoneSet("dev1", []string{"a", "b"}) {
		t.Fatal("hiçbiri kurulu değilken NoneSet true olmalı")
	}
	if !s.NoneSet("dev1", nil) {
		t.Fatal("boş liste NoneSet true olmalı")
	}
	s.Set("dev1", "a", time.Minute)
	if s.NoneSet("dev1", []string{"a", "b"}) {
		t.Fatal("a kuruluyken NoneSet false olmalı")
	}
	// Kapsam izolasyonu: başka cihazda hâlâ true.
	if !s.NoneSet("dev2", []string{"a"}) {
		t.Fatal("başka kapsamda NoneSet true olmalı")
	}
}

func TestDefaultTTL(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(clk.now)
	s.Set("dev1", "x", 0) // ttl<=0 → 1 saat
	clk.t = clk.t.Add(59 * time.Minute)
	if !s.IsSet("dev1", "x") {
		t.Fatal("varsayılan TTL 1 saat olmalı; 59 dk sonra hâlâ set")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if s.IsSet("dev1", "x") {
		t.Fatal("1 saat sonra bit dolmalı")
	}
}

func TestEmptyBitIgnored(t *testing.T) {
	s := New(nil)
	s.Set("dev1", "", time.Minute)
	if s.TrackedCount() != 0 {
		t.Fatal("boş bit adı kurulmamalı")
	}
	if s.IsSet("dev1", "") {
		t.Fatal("boş bit adı asla set olmamalı")
	}
}
