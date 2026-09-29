package verify

import (
	"testing"
	"time"
)

func TestMemStoreOpenGetResolve(t *testing.T) {
	s := NewMemStore()
	base := time.Now().UTC()
	s.now = func() time.Time { return base }

	c, err := s.Open(Check{ID: "chk-1", TenantID: "acme", RuleID: "rule-A", DeviceID: "d1", Kind: KindDetection, Baseline: 80})
	if err != nil {
		t.Fatal(err)
	}
	if c.Outcome != OutcomePending {
		t.Fatalf("açılışta Outcome PENDING olmalı, dönen: %q", c.Outcome)
	}
	if !c.OpenedAt.Equal(base) {
		t.Fatalf("OpenedAt enjekte saat olmalı")
	}

	// Get (doğru kiracı).
	got, err := s.Get("acme", "chk-1")
	if err != nil || got.RuleID != "rule-A" {
		t.Fatalf("Get başarısız: %+v err=%v", got, err)
	}

	// Resolve → VERIFIED + residual.
	rv, err := s.Resolve("acme", "chk-1", OutcomeVerified, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rv.Outcome != OutcomeVerified || rv.Residual != 10 || rv.VerifiedAt.IsZero() {
		t.Fatalf("Resolve sonucu hatalı: %+v", rv)
	}
	if rv.RiskReduced() != 70 { // 80 - 10
		t.Fatalf("RiskReduced 70 olmalı, dönen: %d", rv.RiskReduced())
	}
}

func TestMemStoreTenantIsolation(t *testing.T) {
	s := NewMemStore()
	_, _ = s.Open(Check{ID: "c", TenantID: "acme", Baseline: 50})
	_, _ = s.Open(Check{ID: "c", TenantID: "globex", Baseline: 60}) // aynı ham id, farklı kiracı

	// Çapraz-kiracı Get → bulunamadı (varlık sızmaz).
	if _, err := s.Get("globex", "c"); err != nil {
		t.Fatalf("globex kendi check'ini görmeli: %v", err)
	}
	acme, err := s.Get("acme", "c")
	if err != nil || acme.Baseline != 50 {
		t.Fatalf("acme kendi check'ini (baseline 50) görmeli: %+v err=%v", acme, err)
	}
	// List kiracı-kapsamlı.
	al, _ := s.List("acme")
	if len(al) != 1 || al[0].Baseline != 50 {
		t.Fatalf("acme List yalnız kendi check'ini dönmeli: %+v", al)
	}
	// Çapraz-kiracı Resolve → bulunamadı (yok kiracıya ait değil).
	if _, err := s.Resolve("acme", "nope", OutcomeVerified, 0); err != ErrCheckNotFound {
		t.Fatalf("bilinmeyen check ErrCheckNotFound dönmeli: %v", err)
	}
	// ListAll (platform) → ikisi de.
	all, _ := s.ListAll()
	if len(all) != 2 {
		t.Fatalf("ListAll her iki kiracıyı dönmeli: %d", len(all))
	}
}

func TestMemStoreValidationAndRestore(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Open(Check{ID: "x"}); err != ErrTenantRequired {
		t.Fatalf("kiracısız Open ErrTenantRequired dönmeli: %v", err)
	}
	if _, err := s.Open(Check{TenantID: "acme"}); err != ErrIDRequired {
		t.Fatalf("id'siz Open ErrIDRequired dönmeli: %v", err)
	}
	if _, err := s.List(""); err != ErrTenantRequired {
		t.Fatalf("kiracısız List ErrTenantRequired dönmeli: %v", err)
	}
	// Restore aynen yükler.
	s.Restore([]Check{{ID: "r1", TenantID: "acme", Outcome: OutcomeRegressed, Baseline: 90, Residual: 88}})
	got, err := s.Get("acme", "r1")
	if err != nil || got.Outcome != OutcomeRegressed {
		t.Fatalf("Restore edilen check okunmalı: %+v err=%v", got, err)
	}
	if got.RiskReduced() != 2 {
		t.Fatalf("REGRESSED RiskReduced ~düşük olmalı (90-88=2): %d", got.RiskReduced())
	}
}
