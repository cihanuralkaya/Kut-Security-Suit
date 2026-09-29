package aisec

import (
	"strconv"
	"testing"
)

// TestCausalityGraphBounded, kaynak-tükenmesi savunmasını doğrular: (1) aynı kenar
// gözleminin tekrarı grafı BÜYÜTMEZ (dedupe → amplifikasyon yok); (2) düğüm ve kenar
// sayıları üst-sınırı AŞMAZ (FIFO eviction). HTTP'den beslenen graf sınırsız büyüyemez.
func TestCausalityGraphBounded(t *testing.T) {
	g := NewCausalityGraph()
	g.maxEdges = 5
	g.maxNodes = 4

	// Dedupe: aynı read 1000 kez → tek kenar.
	for i := 0; i < 1000; i++ {
		g.AddRead("agent", "web")
	}
	if len(g.taint) != 1 {
		t.Fatalf("tekrarlı aynı gözlem tekilleştirilmeliydi: len(taint)=%d (1 bekleniyordu)", len(g.taint))
	}

	// Kenar cap: çok sayıda DİSTİNCT kenar → maxEdges'i aşmaz.
	for i := 0; i < 100; i++ {
		g.AddInfluence("n"+strconv.Itoa(i), "n"+strconv.Itoa(i+1))
	}
	if len(g.taint) > g.maxEdges {
		t.Fatalf("taint kenar sayısı cap'i aşmamalı: %d > %d", len(g.taint), g.maxEdges)
	}

	// Write cap.
	for i := 0; i < 100; i++ {
		g.AddWrite("agent", "sink"+strconv.Itoa(i))
	}
	if len(g.writes) > g.maxEdges {
		t.Fatalf("writes kenar sayısı cap'i aşmamalı: %d > %d", len(g.writes), g.maxEdges)
	}
	// Write dedupe.
	before := len(g.writes)
	g.AddWrite("agent", "sink0-dup")
	g.AddWrite("agent", "sink0-dup")
	if len(g.writes)-before > 1 {
		t.Fatalf("tekrarlı write tekilleştirilmeliydi")
	}

	// Düğüm cap: çok sayıda distinct düğüm → maxNodes'u aşmaz.
	for i := 0; i < 100; i++ {
		g.AddNode("dev"+strconv.Itoa(i), KindAgent, Trusted)
	}
	if len(g.nodes) > g.maxNodes {
		t.Fatalf("düğüm sayısı cap'i aşmamalı: %d > %d", len(g.nodes), g.maxNodes)
	}
	if len(g.nodeOrder) != len(g.nodes) {
		t.Fatalf("nodeOrder ile nodes eşleşmeli: %d != %d", len(g.nodeOrder), len(g.nodes))
	}
}

// TestCausalityExfilChain, uçtan-uca AI-agent saldırı zincirini doğrular: untrusted
// context okuyan agent tainted olur; credential okuyup external'a yazınca exfil olarak
// işaretlenir (indirect prompt-injection → credential access → exfiltration).
func TestCausalityExfilChain(t *testing.T) {
	g := NewCausalityGraph()
	g.AddNode("web", KindContext, Untrusted)
	g.AddNode("agent", KindAgent, Trusted)
	g.AddNode("secret", KindCredential, Trusted)
	g.AddNode("evil.example", KindExternal, Trusted)

	g.AddRead("agent", "web")           // untrusted web okuma → agent tainted
	g.AddRead("agent", "secret")        // credential okuma
	g.AddWrite("agent", "evil.example") // external yazma

	if got := g.EffectiveTrust()["agent"]; got != Untrusted {
		t.Fatalf("untrusted web okuyan agent Untrusted olmalı: %s", got)
	}
	found := g.DetectExfiltration()
	if len(found) != 1 || found[0].AgentID != "agent" || found[0].Credential != "secret" || found[0].Sink != "evil.example" {
		t.Fatalf("exfil zinciri tespit edilmeliydi: %+v", found)
	}
}

// TestCausalityNoFindingForTrustedAgent, güvenilir bir agent'ın credential okuyup
// external'a yazmasının (meşru ops) exfil sayılmadığını doğrular — yalnız güveni
// DÜŞMÜŞ agent işaretlenir.
func TestCausalityNoFindingForTrustedAgent(t *testing.T) {
	g := NewCausalityGraph()
	g.AddNode("agent", KindAgent, Trusted)
	g.AddNode("secret", KindCredential, Trusted)
	g.AddNode("backup", KindExternal, Trusted)
	g.AddRead("agent", "secret")
	g.AddWrite("agent", "backup")
	if f := g.DetectExfiltration(); len(f) != 0 {
		t.Fatalf("güvenilir agent exfil sayılmamalı: %+v", f)
	}
}

// TestCausalityMissingLeg, credential veya external ayağı eksikse tespit olmadığını
// doğrular.
func TestCausalityMissingLeg(t *testing.T) {
	g := NewCausalityGraph()
	g.AddNode("web", KindContext, Untrusted)
	g.AddNode("agent", KindAgent, Trusted)
	g.AddNode("secret", KindCredential, Trusted)
	g.AddRead("agent", "web")
	g.AddRead("agent", "secret") // credential var ama external yazma YOK
	if f := g.DetectExfiltration(); len(f) != 0 {
		t.Fatalf("external ayağı olmadan tespit olmamalı: %+v", f)
	}
}

// TestCausalityDelegationTaint, delege edilen agent'ın delegatörünün taint'ini devraldığını
// doğrular (INV-AG-003 ruhu: delegatee delegatörden daha güvenilir olamaz).
func TestCausalityDelegationTaint(t *testing.T) {
	g := NewCausalityGraph()
	g.AddNode("a", KindAgent, Untrusted)
	g.AddNode("b", KindAgent, Trusted)
	g.AddDelegate("a", "b")
	if got := g.EffectiveTrust()["b"]; got != Untrusted {
		t.Fatalf("delege edilen agent delegatörün taint'ini almalı: %s", got)
	}
}

// TestCausalityCycleTerminates, döngülü grafın fixpoint gevşetmede sonsuz döngüye
// girmediğini ve taint'i doğru yaydığını doğrular.
func TestCausalityCycleTerminates(t *testing.T) {
	g := NewCausalityGraph()
	g.AddNode("a", KindAgent, Untrusted)
	g.AddNode("b", KindAgent, Trusted)
	g.AddInfluence("a", "b")
	g.AddInfluence("b", "a") // döngü
	eff := g.EffectiveTrust()
	if eff["a"] != Untrusted || eff["b"] != Untrusted {
		t.Fatalf("döngüde taint her iki düğüme yayılmalı ve sonlanmalı: %v", eff)
	}
}
