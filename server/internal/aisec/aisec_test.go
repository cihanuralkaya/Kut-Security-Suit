package aisec

import (
	"testing"
	"time"
)

// TestPropagateTrustMonotonicDown, INV-AG-001'i doğrular: birleşimde en kirli kazanır;
// untrusted/tainted içerik güveni ASLA yükseltmez.
func TestPropagateTrustMonotonicDown(t *testing.T) {
	cases := []struct{ a, b, want TrustLevel }{
		{Trusted, Trusted, Trusted},
		{Trusted, Untrusted, Untrusted}, // trusted agent untrusted okur → düşer
		{Trusted, Tainted, Tainted},
		{Untrusted, Tainted, Tainted},
		{Tainted, Trusted, Tainted}, // yükseltme YOK
		{Untrusted, Trusted, Untrusted},
	}
	for _, c := range cases {
		if got := PropagateTrust(c.a, c.b); got != c.want {
			t.Errorf("PropagateTrust(%s,%s)=%s want %s", c.a, c.b, got, c.want)
		}
	}
}

// TestChainTrust, etki zinciri boyunca en kirli düzeyin kazandığını doğrular.
func TestChainTrust(t *testing.T) {
	if got := ChainTrust(); got != Trusted {
		t.Errorf("boş zincir Trusted olmalı (nötr): %s", got)
	}
	if got := ChainTrust(Trusted, Trusted); got != Trusted {
		t.Errorf("hepsi trusted → Trusted: %s", got)
	}
	// indirect prompt-injection zinciri: iç agent + untrusted web + tainted araç → Tainted.
	if got := ChainTrust(Trusted, Untrusted, Tainted); got != Tainted {
		t.Errorf("zincirde tainted varsa Tainted olmalı: %s", got)
	}
}

// TestEffectiveCapabilitiesIntersection, INV-AG-003'ü doğrular: delegation etkin
// yeteneği ARTIRAMAZ; sonuç zincirin KESİŞİMİdir.
func TestEffectiveCapabilitiesIntersection(t *testing.T) {
	human := CapSet{"incident.read": true, "external.write": true}
	agentA := CapSet{"incident.read": true, "external.write": true, "credential.read": true}

	// agentA, human'da OLMAYAN credential.read'i kazanamaz.
	eff := EffectiveCapabilities(human, agentA)
	if !eff.Allows("incident.read") || !eff.Allows("external.write") {
		t.Fatalf("ortak yetenekler korunmalı: %v", eff)
	}
	if eff.Allows("credential.read") {
		t.Fatal("delegation credential.read'i ARTIRMAMALI (INV-AG-003)")
	}

	// Tenant politikası external.write'ı kısıtlarsa etkin kümeden düşer.
	tenant := CapSet{"incident.read": true}
	eff2 := EffectiveCapabilities(human, agentA, tenant)
	if eff2.Allows("external.write") || eff2.Allows("credential.read") {
		t.Fatalf("tenant kısıtı kesişimi daraltmalı: %v", eff2)
	}
	if !eff2.Allows("incident.read") {
		t.Fatalf("tüm katmanlarda ortak yetenek kalmalı: %v", eff2)
	}
}

// TestEffectiveCapabilitiesEdgeCases, boş/tekil küme davranışını doğrular.
func TestEffectiveCapabilitiesEdgeCases(t *testing.T) {
	if len(EffectiveCapabilities()) != 0 {
		t.Fatal("boş girdi boş küme dönmeli")
	}
	single := CapSet{"a": true, "b": true}
	if eff := EffectiveCapabilities(single); len(eff) != 2 {
		t.Fatalf("tek küme kendini dönmeli: %v", eff)
	}
}

func TestAgentExpiry(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	a := AgentPrincipal{ExpiresAt: now.Add(time.Minute)}
	if a.Expired(now) {
		t.Fatal("süre dolmadan expired olmamalı")
	}
	if !a.Expired(now.Add(2 * time.Minute)) {
		t.Fatal("süre sonrası expired olmalı")
	}
	if (AgentPrincipal{}).Expired(now) {
		t.Fatal("ExpiresAt sıfırsa (süre yok) expired sayılmamalı")
	}
}
