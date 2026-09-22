package secgateway

import (
	"fmt"
	"testing"
	"time"

	"kut.corp/suite/server/internal/authz"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/seccontract"
)

// newTestGW, sabit saat + deterministik id üreteci + verilen politikayla bir köprü kurar.
func newTestGW(p authz.Policy) *Gateway {
	fixed := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	var n int
	genID := func() string { n++; return fmt.Sprintf("id-%d", n) }
	policy := seccontract.PolicyFunc(func(seccontract.ActionRequest) string { return "policy-v1" })
	return New(authz.NewGateway(p), policy, func() time.Time { return fixed }, genID, time.Minute)
}

func req(tenant string, pt seccontract.PrincipalType, act scope.Action, targets int, confirmed bool) seccontract.ActionRequest {
	ts := make([]string, targets)
	for i := range ts {
		ts[i] = fmt.Sprintf("dev-%d", i)
	}
	return seccontract.ActionRequest{
		RequestID: "req-1", TenantID: tenant,
		Principal: seccontract.Principal{Type: pt, ID: "p-1"},
		Action:    act, Targets: ts, Confirmed: confirmed,
	}
}

func hasReason(d seccontract.AuthorizationDecision, rc seccontract.ReasonCode) bool {
	for _, r := range d.ReasonCodes {
		if r == rc {
			return true
		}
	}
	return false
}

// assertValid, her kararın invariant tutarlılığını doğrular (ALLOW ⇔ Grant!=nil).
func assertValid(t *testing.T, d seccontract.AuthorizationDecision) {
	t.Helper()
	if !d.Valid() {
		t.Fatalf("karar invariant'ı bozdu: result=%s grant=%v", d.Result, d.Grant)
	}
}

func TestMissingTenant_Deny(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	d := gw.Authorize(req("", seccontract.PrincipalHuman, scope.ActionQuarantine, 1, false))
	assertValid(t, d)
	if d.Result != seccontract.ResultDeny || !hasReason(d, seccontract.ReasonTenantMismatch) {
		t.Fatalf("boş tenant DENY(TENANT_MISMATCH) bekleniyordu, alındı: %+v", d)
	}
}

func TestUnknownPrincipal_Deny(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	for _, pt := range []seccontract.PrincipalType{"", "bogus"} {
		d := gw.Authorize(req("t1", pt, scope.ActionQuarantine, 1, false))
		assertValid(t, d)
		if d.Result != seccontract.ResultDeny || !hasReason(d, seccontract.ReasonRBACDeny) {
			t.Fatalf("principal=%q için fail-closed DENY(RBAC_DENY) bekleniyordu: %+v", pt, d)
		}
	}
}

func TestLowImpact_AllowWithBoundGrant(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	r := req("t1", seccontract.PrincipalAI, scope.ActionActiveScan, 50, false) // düşük etki: AI + 50 hedef bile geçer
	d := gw.Authorize(r)
	assertValid(t, d)
	if d.Result != seccontract.ResultAllow || d.Grant == nil {
		t.Fatalf("düşük-etki ALLOW+grant bekleniyordu: %+v", d)
	}
	// Grant istek/tenant/action-bound olmalı (NewGrant).
	if d.Grant.RequestHash != r.RequestHash() || d.Grant.Action != r.Action || d.Grant.TenantID != r.TenantID {
		t.Fatalf("grant istek/tenant/action-bound değil: %+v", d.Grant)
	}
}

func TestHumanSoftExceed_NeedApproval(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	d := gw.Authorize(req("t1", seccontract.PrincipalHuman, scope.ActionQuarantine, 600, false))
	assertValid(t, d)
	if d.Result != seccontract.ResultNeedApproval {
		t.Fatalf("insan yumuşak-tavan aşımı NEED_APPROVAL bekliyordu: %+v", d)
	}
	if !hasReason(d, seccontract.ReasonDualControlRequired) || !hasReason(d, seccontract.ReasonBlastRadiusExceeded) {
		t.Fatalf("DUAL_CONTROL + BLAST_RADIUS reason bekleniyordu: %+v", d.ReasonCodes)
	}
}

func TestHumanSoftExceed_Confirmed_Allow(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	d := gw.Authorize(req("t1", seccontract.PrincipalHuman, scope.ActionQuarantine, 600, true))
	assertValid(t, d)
	if d.Result != seccontract.ResultAllow || d.Grant == nil {
		t.Fatalf("onaylı insan yumuşak-tavan aşımı ALLOW bekliyordu: %+v", d)
	}
}

func TestAutonomousHardExceed_Deny(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy()) // HardAutonomousRadius=3
	d := gw.Authorize(req("t1", seccontract.PrincipalAI, scope.ActionQuarantine, 5, true /* onay otonomu kurtarmaz */))
	assertValid(t, d)
	if d.Result != seccontract.ResultDeny || !hasReason(d, seccontract.ReasonBlastRadiusExceeded) {
		t.Fatalf("otonom sert-tavan aşımı DENY(BLAST_RADIUS) bekliyordu: %+v", d)
	}
}

func TestAutonomousWithinHard_Allow(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	d := gw.Authorize(req("t1", seccontract.PrincipalAI, scope.ActionQuarantine, 2, false))
	assertValid(t, d)
	if d.Result != seccontract.ResultAllow {
		t.Fatalf("otonom sert-tavan içi ALLOW bekliyordu: %+v", d)
	}
}

// TestAutoResponderIsAutonomous, autoresponder'ın Human'a düşmeyip otonom sert-tavana
// tabi olduğunu kanıtlar (fail-safe eşleme).
func TestAutoResponderIsAutonomous(t *testing.T) {
	gw := newTestGW(authz.DefaultPolicy())
	d := gw.Authorize(req("t1", seccontract.PrincipalAutoResponder, scope.ActionQuarantine, 5, true))
	assertValid(t, d)
	if d.Result != seccontract.ResultDeny || !hasReason(d, seccontract.ReasonBlastRadiusExceeded) {
		t.Fatalf("autoresponder otonom (sert-tavan DENY) olmalı: %+v", d)
	}
}

func TestRateLimit_Deny(t *testing.T) {
	p := authz.Policy{SoftBlastRadius: 500, HardAutonomousRadius: 3, HighImpactPerMin: 1}
	gw := newTestGW(p)
	r := req("t1", seccontract.PrincipalHuman, scope.ActionQuarantine, 1, false)
	if d := gw.Authorize(r); d.Result != seccontract.ResultAllow {
		t.Fatalf("ilk yüksek-etki op ALLOW olmalı: %+v", d)
	}
	d := gw.Authorize(r)
	assertValid(t, d)
	if d.Result != seccontract.ResultDeny || !hasReason(d, seccontract.ReasonRateLimited) {
		t.Fatalf("rate-limit aşımı DENY(RATE_LIMITED) bekliyordu: %+v", d)
	}
}
