package fabricauthz

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/aiprovider"
	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/coordinator"
	"kut.corp/suite/server/internal/scope"
)

// allowEngine, t1 kiracısını allow-scope'a alan ve WIPE'ı açıkça etkinleştiren bir
// scope motoru kurar (quarantine gibi HighImpact aksiyonlar scope içindeyken açık
// etkinleştirme gerektirmez; yalnız Destructive gerektirir).
func allowEngine() *scope.Engine {
	return scope.New(&scope.Policy{
		Allowed: scope.Selector{Tenants: []string{"t1"}},
		Actions: map[scope.Action]bool{scope.ActionWipe: true},
	})
}

func TestCommandAuthorizer_AllowedAndDenied(t *testing.T) {
	ca := NewCommandAuthorizer(allowEngine(), "t1")
	ctx := context.Background()

	// WIPE, kapsamdaki kiracı için açıkça etkin → izin.
	d, err := ca.Authorize(ctx, commandplane.ActionRequest{Subject: "admin", Action: "wipe", Object: "dev-1"})
	if err != nil || !d.Allowed {
		t.Fatalf("beklenen izin, alındı allowed=%v reason=%q err=%v", d.Allowed, d.Reason, err)
	}

	// Kapsam dışı kiracı → red (hedef izin verilen scope dışında).
	caOther := NewCommandAuthorizer(allowEngine(), "t2")
	d2, _ := caOther.Authorize(ctx, commandplane.ActionRequest{Subject: "admin", Action: "wipe", Object: "dev-1"})
	if d2.Allowed {
		t.Errorf("kapsam dışı kiracı için komut reddedilmeliydi")
	}
}

func TestCommandAuthorizer_NilEngineFailsClosed(t *testing.T) {
	ca := NewCommandAuthorizer(nil, "t1")
	d, _ := ca.Authorize(context.Background(), commandplane.ActionRequest{Action: "wipe", Object: "dev-1"})
	if d.Allowed {
		t.Errorf("motor yokken komut fail-closed reddedilmeli")
	}
}

func TestCommandAuthorizer_UnknownActionFailsClosed(t *testing.T) {
	// Bilinmeyen aksiyon adı scope.ImpactOf'ta Destructive'e düşer; WIPE dışında
	// açık etkinleştirme olmadığından yıkıcı olarak reddedilir.
	ca := NewCommandAuthorizer(allowEngine(), "t1")
	d, _ := ca.Authorize(context.Background(), commandplane.ActionRequest{Action: "selfdestruct", Object: "dev-1"})
	if d.Allowed {
		t.Errorf("bilinmeyen (→Destructive) aksiyon fail-closed reddedilmeli")
	}
}

func TestResponseAuthorizer_AllowedDeniedAndGuards(t *testing.T) {
	ra := NewResponseAuthorizer(allowEngine())
	ctx := context.Background()

	// IsolateEndpoint → quarantine (HighImpact); kapsamdaki kiracıda izin.
	err := ra.AuthorizeResponse(ctx, aiprovider.ResponseAction{
		Type: aiprovider.ActionIsolateEndpoint, Target: "dev-1", TenantID: "t1",
	}, "approver-1")
	if err != nil {
		t.Fatalf("beklenen izin, alındı hata: %v", err)
	}

	// Kapsam dışı kiracı → red.
	if err := ra.AuthorizeResponse(ctx, aiprovider.ResponseAction{
		Type: aiprovider.ActionIsolateEndpoint, Target: "dev-1", TenantID: "t2",
	}, "approver-1"); err == nil {
		t.Errorf("kapsam dışı kiracı için yanıt reddedilmeliydi")
	}

	// Boş onaylayan → red.
	if err := ra.AuthorizeResponse(ctx, aiprovider.ResponseAction{
		Type: aiprovider.ActionIsolateEndpoint, Target: "dev-1", TenantID: "t1",
	}, ""); err == nil {
		t.Errorf("boş onaylayan reddedilmeliydi")
	}

	// nil motor → fail-closed.
	if err := (&ResponseAuthorizer{}).AuthorizeResponse(ctx, aiprovider.ResponseAction{
		Type: aiprovider.ActionIsolateEndpoint, Target: "dev-1", TenantID: "t1",
	}, "approver-1"); err == nil {
		t.Errorf("motor yokken yanıt fail-closed reddedilmeli")
	}
}

func TestFaultAuthorizer_AllowListAndFailClosed(t *testing.T) {
	ctx := context.Background()

	fa := NewFaultAuthorizer("sre-1", " sre-2 ")
	if err := fa.AuthorizeFault(ctx, "sre-1", coordinator.RegionFailure, "us-east-1"); err != nil {
		t.Errorf("yetkili operatör izinli olmalı: %v", err)
	}
	if err := fa.AuthorizeFault(ctx, "sre-2", coordinator.BusSaturation, "bus"); err != nil {
		t.Errorf("boşlukları kırpılmış yetkili operatör izinli olmalı: %v", err)
	}
	if err := fa.AuthorizeFault(ctx, "intruder", coordinator.RegionFailure, "us-east-1"); err == nil {
		t.Errorf("yetkisiz aktör reddedilmeliydi")
	}

	// Boş allow-list → tüm enjeksiyonlar reddedilir.
	empty := NewFaultAuthorizer()
	if err := empty.AuthorizeFault(ctx, "sre-1", coordinator.RegionFailure, "us-east-1"); err == nil {
		t.Errorf("boş allow-list ile tüm enjeksiyonlar reddedilmeliydi")
	}
}
