package aisec

import (
	"errors"
	"testing"
	"time"
)

// TestValidateMemoryWrite, INV-AG-006'yı doğrular: provenance (yazar + hash) zorunlu.
func TestValidateMemoryWrite(t *testing.T) {
	ok := MemoryRecord{Key: "k", ValueHash: "h1", AuthorPrincipal: "agent-A", SourceTrust: Trusted}
	if err := ValidateMemoryWrite(ok); err != nil {
		t.Fatalf("geçerli provenance kabul edilmeli: %v", err)
	}
	for _, bad := range []MemoryRecord{
		{Key: "k", ValueHash: "h1"},                       // yazar yok
		{Key: "k", AuthorPrincipal: "agent-A"},            // hash yok
		{Key: "k", ValueHash: "  ", AuthorPrincipal: " "}, // boşluk = yok
	} {
		if err := ValidateMemoryWrite(bad); !errors.Is(err, ErrNoProvenance) {
			t.Fatalf("provenance'sız yazım ErrNoProvenance dönmeli: %+v → %v", bad, err)
		}
	}
}

// TestMemoryReadPropagatesTaint, memory-poisoning zeminini doğrular: tainted bir hafıza
// girdisini okuyan güvenilir agent tainted olur (INV-AG-001), böylece downstream exfil
// guard tetiklenir.
func TestMemoryReadPropagatesTaint(t *testing.T) {
	poisoned := MemoryRecord{Key: "k", ValueHash: "h", AuthorPrincipal: "x", SourceTrust: Tainted}
	if got := poisoned.ReadTrust(Trusted); got != Tainted {
		t.Fatalf("zehirli hafıza okuyan agent tainted olmalı: %s", got)
	}
	clean := MemoryRecord{Key: "k", ValueHash: "h", AuthorPrincipal: "x", SourceTrust: Trusted}
	if got := clean.ReadTrust(Trusted); got != Trusted {
		t.Fatalf("temiz hafıza güveni düşürmemeli: %s", got)
	}
	// Uçtan-uca: zehirli hafıza → tainted agent + credential+external → DENY (AG-02).
	trust := poisoned.ReadTrust(Trusted)
	eff := CapSet{CapCredentialRead: true, CapExternalWrite: true}
	if got := EvaluateExfiltration(trust, eff); got != AGDeny {
		t.Fatalf("zehirli hafıza → exfil DENY bekleniyordu: %s", got)
	}
}

func TestMemoryExpiry(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	r := MemoryRecord{WrittenAt: now, TTL: time.Hour}
	if r.Expired(now.Add(30 * time.Minute)) {
		t.Fatal("TTL içinde expired olmamalı")
	}
	if !r.Expired(now.Add(2 * time.Hour)) {
		t.Fatal("TTL sonrası expired olmalı")
	}
	if (MemoryRecord{WrittenAt: now}).Expired(now.Add(999 * time.Hour)) {
		t.Fatal("TTL=0 (süresiz) expired sayılmamalı")
	}
}
