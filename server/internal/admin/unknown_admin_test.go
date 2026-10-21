package admin

import (
	"context"
	"errors"
	"testing"
)

// Z4b-09 / S-5: bilinmeyen ya da PASİF yönetici için kiracı sorgusu "" (platform) DÖNMEZ;
// ErrUnknownAdmin (403) döner. Çağıranlar fail-closed reddeder, platform kapsamına düşmez.
func TestAdminTenantUnknownOrInactiveFailsClosed(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	seedTenantMaps(store)

	// NEGATIF: hiç var olmayan yönetici.
	if tn, err := svc.AdminTenant(ctx, "ghost"); !errors.Is(err, ErrUnknownAdmin) || tn != "" {
		t.Fatalf("bilinmeyen admin ErrUnknownAdmin olmalı: %q %v", tn, err)
	}
	if !errors.Is(ErrUnknownAdmin, ErrForbidden) {
		t.Fatal("ErrUnknownAdmin ErrForbidden'ı sarmalı (HTTP 403'e eşlensin)")
	}
	// NEGATIF: pasifleştirilmiş yönetici.
	store.admins["acme-op"].active = false
	if _, err := svc.AdminTenant(ctx, "acme-op"); !errors.Is(err, ErrUnknownAdmin) {
		t.Fatalf("pasif admin ErrUnknownAdmin olmalı: %v", err)
	}
	// POZITIF: etkin platform admini "" + nil (platform), etkin kiracılı admin kendi kiracısı.
	if tn, err := svc.AdminTenant(ctx, "plat"); err != nil || tn != "" {
		t.Fatalf("platform admini '' ve hatasız dönmeli: %q %v", tn, err)
	}
	if tn, err := svc.AdminTenant(ctx, "acme-adm"); err != nil || tn != "acme" {
		t.Fatalf("kiracılı admin kendi kiracısını almalı: %q %v", tn, err)
	}
}

// Z4b-09 / S-5: require() ile AdminTenant() arasında pasifleşen (TOCTOU) yönetici hiçbir
// kapıdan platform admini gibi geçemez ve hiçbir yazma/okuma yapılamaz.
func TestDeactivatedBetweenRequireAndTenantNeverBecomesPlatform(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	seedTenantMaps(store)
	store.deviceTenant["dev-globex"] = "globex"
	store.eventTenant["ev-globex"] = "globex"
	store.tokenTenants["tok-globex"] = "globex"
	// Rolü hâlâ OPERATOR/ADMIN görünen (m.roles) ama etkin olmayan yöneticiler: AdminRole
	// geçer, AdminTenant ErrUnknownAdmin döner.
	store.admins["acme-op"].active = false
	store.admins["acme-adm"].active = false

	auditBefore := len(store.audits)
	cmdBefore := len(store.commands)

	checks := map[string]error{
		"issue token":  func() error { _, e := svc.IssueEnrollmentToken(ctx, "acme-op", "globex"); return e }(),
		"revoke token": svc.RevokeEnrollmentToken(ctx, "acme-op", "tok-globex"),
		"set tags":     svc.SetDeviceTags(ctx, "acme-op", "dev-globex", []string{"x"}),
		"quarantine":   svc.QuarantineDevice(ctx, "acme-op", "dev-globex"),
		"ack event":    svc.AckEvent(ctx, "acme-op", "ev-globex", "ACKNOWLEDGED"),
		"list admins":  func() error { _, e := svc.ListAdmins(ctx, "acme-op"); return e }(),
		"set role":     svc.SetAdminRole(ctx, "acme-adm", "globex-adm", RoleViewer),
		"deactivate":   svc.DeactivateAdmin(ctx, "acme-adm", "globex-adm"),
		"create admin": func() error {
			_, e := svc.CreateAdmin(ctx, "acme-adm", "x@y", "longenoughpw", RoleViewer, "globex")
			return e
		}(),
	}
	for name, err := range checks {
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: pasif yönetici fail-closed reddedilmeli, dönen: %v", name, err)
		}
	}
	if store.revoked["tok-globex"] {
		t.Error("pasif yönetici başka kiracının token'ını iptal etmemeli")
	}
	if len(store.tags["dev-globex"]) != 0 {
		t.Error("pasif yönetici etiket yazmamalı")
	}
	if store.admins["globex-adm"].role != RoleAdmin || !store.admins["globex-adm"].active {
		t.Error("pasif yönetici başka kiracının yöneticisini değiştirmemeli")
	}
	if len(store.commands) != cmdBefore || len(store.audits) != auditBefore {
		t.Error("reddedilen çağrılar komut/denetim yan etkisi bırakmamalı")
	}
}

// S-4: kiracı predicate'i depo (SQL) katmanında da zorlanır — servis kapısı atlansa bile
// kiracıya bağlı çağıran başka kiracıya yazamaz; boş kiracı (platform) süzülmez.
func TestStoreWritesCarryTenantPredicate(t *testing.T) {
	ctx := context.Background()
	_, store := wallFixture(t)
	seedTenantMaps(store)
	store.deviceTenant["dev-acme"] = "acme"
	store.deviceTenant["dev-globex"] = "globex"
	store.tokenTenants["tok-globex"] = "globex"
	store.tokenTenants["tok-acme"] = "acme"

	// NEGATIF: acme kapsamıyla globex hedeflerine yazma reddedilir (doğrudan Store çağrısı).
	if err := store.RevokeEnrollmentToken(ctx, "tok-globex", "acme"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("token iptali kiracı predicate'ini taşımalı: %v", err)
	}
	if store.revoked["tok-globex"] {
		t.Fatal("yabancı token iptal edilmemeli")
	}
	if err := store.SetAdminRole(ctx, "globex-adm", RoleViewer, "acme"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("rol güncelleme kiracı predicate'ini taşımalı: %v", err)
	}
	if err := store.DeactivateAdmin(ctx, "globex-adm", "acme"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("pasifleştirme kiracı predicate'ini taşımalı: %v", err)
	}
	if err := store.SetDeviceTags(ctx, "dev-globex", []string{"x"}, "acme"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("etiket yazımı kiracı predicate'ini taşımalı: %v", err)
	}
	if store.admins["globex-adm"].role != RoleAdmin || !store.admins["globex-adm"].active || len(store.tags["dev-globex"]) != 0 {
		t.Fatal("reddedilen yazımlar durumu değiştirmemeli")
	}

	// POZITIF: kendi kiracısı ve platform kapsamı (boş) geçer.
	if err := store.RevokeEnrollmentToken(ctx, "tok-acme", "acme"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeEnrollmentToken(ctx, "tok-globex", ""); err != nil {
		t.Fatalf("platform kapsamı (süzme yok) geçmeli: %v", err)
	}
	if err := store.SetDeviceTags(ctx, "dev-acme", []string{"a"}, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAdminRole(ctx, "acme-viewer", RoleOperator, "acme"); err != nil {
		t.Fatal(err)
	}
}

// seedTenantMaps, wallFixture'ın tohumlamadığı kiracı haritalarını hazırlar.
func seedTenantMaps(m *memStore) {
	if m.deviceTenant == nil {
		m.deviceTenant = map[string]string{}
	}
	if m.eventTenant == nil {
		m.eventTenant = map[string]string{}
	}
	if m.tokenTenants == nil {
		m.tokenTenants = map[string]string{}
	}
}
