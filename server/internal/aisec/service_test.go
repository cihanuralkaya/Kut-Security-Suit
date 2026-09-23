package aisec

import (
	"sync"
	"testing"
)

// TestServiceFindingsFromIngest, Service üzerinden ingest edilen bir exfil zincirinin
// Findings ile tespit edildiğini doğrular.
func TestServiceFindingsFromIngest(t *testing.T) {
	s := NewService()
	s.ObserveNode("web", KindContext, Untrusted)
	s.ObserveNode("agent", KindAgent, Trusted)
	s.ObserveNode("secret", KindCredential, Trusted)
	s.ObserveNode("evil", KindExternal, Trusted)
	s.ObserveRead("agent", "web")
	s.ObserveRead("agent", "secret")
	s.ObserveWrite("agent", "evil")

	f := s.Findings()
	if len(f) != 1 || f[0].AgentID != "agent" {
		t.Fatalf("ingest edilen exfil zinciri tespit edilmeliydi: %+v", f)
	}
}

// TestServiceConcurrentIngest, eşzamanlı ingest + Findings'in race-safe olduğunu doğrular
// (-race altında). CausalityGraph tek-thread varsayar; Service kilidi bunu güvence altına alır.
func TestServiceConcurrentIngest(t *testing.T) {
	s := NewService()
	s.ObserveNode("agent", KindAgent, Untrusted)
	s.ObserveNode("secret", KindCredential, Trusted)
	s.ObserveNode("evil", KindExternal, Trusted)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ObserveRead("agent", "secret")
			s.ObserveWrite("agent", "evil")
			_ = s.Findings()
		}()
	}
	wg.Wait()
	if f := s.Findings(); len(f) != 1 {
		t.Fatalf("eşzamanlı ingest sonrası tam 1 bulgu (agent) bekleniyordu: %+v", f)
	}
}
