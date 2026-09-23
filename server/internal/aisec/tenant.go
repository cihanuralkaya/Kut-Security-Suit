package aisec

// tenant.go — AG-05: agent kimlik-bilgisi tenant sınırı (INV-AG-008) + agent containment
// önerisinin DATA olması (INV-AG-010: containment normal authorization'ı bypass edemez;
// yalnız §0 zinciriyle ActionRequest'e dönüşür).

import "strings"

func normTenant(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// EnforceTenantBoundary, INV-AG-008'i uygular: bir agent'ın ÜRETTİĞİ kimlik-bilgisi veya
// eylem, agent'ın KENDİ tenant'ının dışına çıkamaz. Eksik tenant fail-closed DENY (boş
// tenant güvenlik nesnesinde implicit "default"a düşemez); hedef≠issuer tenant → DENY.
func EnforceTenantBoundary(issuer AgentPrincipal, targetTenant string) AGDecision {
	it, tt := normTenant(issuer.TenantID), normTenant(targetTenant)
	if it == "" || tt == "" {
		return AGDeny
	}
	if it != tt {
		return AGDeny
	}
	return AGAllow
}

// ContainmentAction, bir agent-containment ÖNERİSİDİR (KUT-AI-SEC-010) — DATA'dır, yürütme
// DEĞİL. INV-AG-010: containment normal KUT authorization'ını BYPASS EDEMEZ; bu öneri
// yalnız §0 zinciriyle (ActionRequest → Gateway → Grant → GuardedExecutor) uygulanabilir.
// Bu paket yürütme sınırına DOKUNMAZ; yalnız öneriyi ve gerekçesini üretir.
type ContainmentAction struct {
	AgentID string
	Action  string // önerilen kısıtlama (ör. "suspend_agent", "revoke_delegation")
	Reason  string
	// Applied DAİMA false — aisec uygulamaz; uygulama execution sınırında, gateway'den geçerek.
	Applied bool
}

// Recommend, bir containment önerisi üretir (uygulanmamış DATA). Çağıran bunu §0 zincirine
// sokmalıdır; aisec asla doğrudan uygulamaz (INV-AG-010).
func Recommend(agentID, action, reason string) ContainmentAction {
	return ContainmentAction{AgentID: agentID, Action: action, Reason: reason, Applied: false}
}
