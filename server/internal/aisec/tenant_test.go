package aisec

import "testing"

// TestEnforceTenantBoundary, INV-AG-008'i doğrular: agent-üretimi kimlik/eylem tenant
// sınırını aşamaz; eksik tenant fail-closed DENY.
func TestEnforceTenantBoundary(t *testing.T) {
	issuer := AgentPrincipal{AgentID: "a1", TenantID: "acme"}
	if got := EnforceTenantBoundary(issuer, "acme"); got != AGAllow {
		t.Errorf("aynı tenant ALLOW olmalı: %s", got)
	}
	if got := EnforceTenantBoundary(issuer, "ACME "); got != AGAllow {
		t.Errorf("normalize edilmiş aynı tenant ALLOW olmalı: %s", got)
	}
	if got := EnforceTenantBoundary(issuer, "globex"); got != AGDeny {
		t.Errorf("çapraz-tenant DENY olmalı (INV-AG-008): %s", got)
	}
	if got := EnforceTenantBoundary(AgentPrincipal{AgentID: "a1"}, "acme"); got != AGDeny {
		t.Errorf("issuer tenant boş → fail-closed DENY: %s", got)
	}
	if got := EnforceTenantBoundary(issuer, ""); got != AGDeny {
		t.Errorf("hedef tenant boş → fail-closed DENY: %s", got)
	}
}

// TestContainmentIsDataNotExecution, INV-AG-010'u doğrular: containment önerisi DATA'dır,
// uygulanmamış gelir — aisec asla doğrudan uygulamaz (yürütme §0 zincirinden geçer).
func TestContainmentIsDataNotExecution(t *testing.T) {
	c := Recommend("a1", "suspend_agent", "tainted exfil attempt")
	if c.Applied {
		t.Fatal("containment önerisi uygulanmış gelmemeli (INV-AG-010)")
	}
	if c.AgentID != "a1" || c.Action != "suspend_agent" {
		t.Fatalf("öneri alanları hatalı: %+v", c)
	}
}
