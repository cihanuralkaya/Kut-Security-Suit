package aisec

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// seedExfil, bir kiracı bölümüne untrusted→credential→external exfil zinciri işler.
func seedExfil(t *testing.T, s *Service, tenant string) {
	t.Helper()
	for _, err := range []error{
		s.ObserveNode(tenant, "web", KindContext, Untrusted),
		s.ObserveNode(tenant, "agent", KindAgent, Trusted),
		s.ObserveNode(tenant, "secret", KindCredential, Trusted),
		s.ObserveNode(tenant, "evil", KindExternal, Trusted),
		s.ObserveRead(tenant, "agent", "web"),
		s.ObserveRead(tenant, "agent", "secret"),
		s.ObserveWrite(tenant, "agent", "evil"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestServiceFindingsFromIngest, Service üzerinden ingest edilen bir exfil zincirinin
// Findings ile tespit edildiğini doğrular.
func TestServiceFindingsFromIngest(t *testing.T) {
	s := NewService()
	seedExfil(t, s, "")

	f := s.Findings("")
	if len(f) != 1 || f[0].AgentID != "agent" {
		t.Fatalf("ingest edilen exfil zinciri tespit edilmeliydi: %+v", f)
	}
}

// TestServiceConcurrentIngest, eşzamanlı ingest + Findings'in race-safe olduğunu doğrular
// (-race altında). CausalityGraph tek-thread varsayar; Service kilidi bunu güvence altına alır.
func TestServiceConcurrentIngest(t *testing.T) {
	s := NewService()
	_ = s.ObserveNode("", "agent", KindAgent, Untrusted)
	_ = s.ObserveNode("", "secret", KindCredential, Trusted)
	_ = s.ObserveNode("", "evil", KindExternal, Trusted)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.ObserveRead("", "agent", "secret")
			_ = s.ObserveWrite("", "agent", "evil")
			_ = s.Findings("")
		}()
	}
	wg.Wait()
	if f := s.Findings(""); len(f) != 1 {
		t.Fatalf("eşzamanlı ingest sonrası tam 1 bulgu (agent) bekleniyordu: %+v", f)
	}
}

// Z5-02: kiracılar birbirinin bulgusunu OKUYAMAZ ve düğüm güvenini ÜZERİNE YAZAMAZ.
func TestServiceTenantPartitionIsolation(t *testing.T) {
	s := NewService()
	seedExfil(t, s, "acme")

	// NEGATİF (okuma): globex ve platform bölümü acme'nin bulgusunu görmez.
	if f := s.Findings("globex"); len(f) != 0 {
		t.Fatalf("globex acme bulgusunu görmemeli: %+v", f)
	}
	if f := s.Findings(""); len(f) != 0 {
		t.Fatalf("platform bölümü acme bulgusunu görmemeli: %+v", f)
	}
	// POZİTİF (okuma): sahibi görür.
	if f := s.Findings("acme"); len(f) != 1 {
		t.Fatalf("acme kendi bulgusunu görmeli: %+v", f)
	}

	// NEGATİF (yazma): globex aynı kimlikli düğümlerin güvenini "Trusted" yaparak acme zincirini
	// BASTIRAMAZ — kendi bölümünde yazar, acme grafı dokunulmaz kalır.
	for _, err := range []error{
		s.ObserveNode("globex", "agent", KindAgent, Trusted),
		s.ObserveNode("globex", "web", KindContext, Trusted),
		s.ObserveNode("globex", "secret", KindCredential, Trusted),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f := s.Findings("acme"); len(f) != 1 {
		t.Fatalf("globex yazımı acme bulgusunu bastırmamalı: %+v", f)
	}

	// Platform görünümü: tüm bölümler kiracı etiketiyle.
	all := s.FindingsAll()
	if len(all) != 1 || all[0].Tenant != "acme" || all[0].AgentID != "agent" {
		t.Fatalf("FindingsAll kiracı etiketli olmalı: %+v", all)
	}
}

// Z5-02: bir kiracı düğüm tavanını doldurup başka kiracının düğümlerini tahliye EDEMEZ
// (FIFO tahliyesi bölüm başınadır).
func TestServiceNodeCapIsPerTenant(t *testing.T) {
	s := NewService()
	seedExfil(t, s, "acme")
	for i := 0; i < defaultMaxNodes+500; i++ {
		if err := s.ObserveNode("noisy", "n"+strconv.Itoa(i), KindContext, Untrusted); err != nil {
			t.Fatal(err)
		}
	}
	if f := s.Findings("acme"); len(f) != 1 {
		t.Fatalf("gürültücü kiracı acme düğümlerini tahliye etmemeli: %+v", f)
	}
}

// Sınırlar: aşırı uzun kimlik reddedilir (graf değişmez); bölüm sayısı tavanlıdır.
func TestServiceBoundsRejectOversizeAndTooManyTenants(t *testing.T) {
	s := NewService()
	long := strings.Repeat("a", MaxIDLen+1)
	if err := s.ObserveNode("acme", long, KindAgent, Trusted); !errors.Is(err, ErrIDTooLong) {
		t.Fatalf("uzun kimlik reddedilmeli: %v", err)
	}
	if err := s.ObserveRead("acme", "a", long); !errors.Is(err, ErrIDTooLong) {
		t.Fatalf("uzun kaynak kimliği reddedilmeli: %v", err)
	}
	if err := s.ObserveNode("acme", strings.Repeat("a", MaxIDLen), KindAgent, Trusted); err != nil {
		t.Fatalf("sınırdaki kimlik kabul edilmeli: %v", err)
	}
	for i := 0; i < maxPartitions-1; i++ { // "acme" zaten 1 bölüm
		if err := s.ObserveNode("t"+strconv.Itoa(i), "x", KindAgent, Trusted); err != nil {
			t.Fatalf("bölüm #%d açılabilmeli: %v", i, err)
		}
	}
	if err := s.ObserveNode("one-too-many", "x", KindAgent, Trusted); !errors.Is(err, ErrTooManyTenants) {
		t.Fatalf("bölüm tavanı aşılınca fail-closed: %v", err)
	}
	// Mevcut bölümlere yazmak sürer.
	if err := s.ObserveNode("t1", "y", KindAgent, Trusted); err != nil {
		t.Fatalf("mevcut bölüm yazılabilir kalmalı: %v", err)
	}
}
