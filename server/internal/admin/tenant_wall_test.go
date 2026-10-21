package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/security"
)

// wallFixture: platform admini (plat), iki kiracı (acme, globex) ve her birinin yöneticileri.
func wallFixture(t *testing.T) (*Service, *memStore) {
	t.Helper()
	store := newMemStore()
	store.roles["plat"] = RoleAdmin
	store.admins["plat"] = &adminEntry{email: "plat@x", role: RoleAdmin, tenant: "", active: true}
	store.roles["acme-adm"] = RoleAdmin
	store.admins["acme-adm"] = &adminEntry{email: "acme-adm@x", role: RoleAdmin, tenant: "acme", active: true}
	store.roles["acme-viewer"] = RoleViewer
	store.admins["acme-viewer"] = &adminEntry{email: "acme-viewer@x", role: RoleViewer, tenant: "acme", active: true}
	store.roles["globex-adm"] = RoleAdmin
	store.admins["globex-adm"] = &adminEntry{email: "globex-adm@x", role: RoleAdmin, tenant: "globex", active: true}
	store.roles["acme-op"] = RoleOperator
	store.admins["acme-op"] = &adminEntry{email: "acme-op@x", role: RoleOperator, tenant: "acme", active: true}
	svc, _ := newService(t, store)
	return svc, store
}

// --- Z4a-01 / Z4b-05: yönetici-yönetimi IDOR ---

func TestAdminMgmtCrossTenantSetRoleDenied(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)

	// NEGATIF: acme ADMIN'i globex yöneticisinin rolünü değiştiremez.
	if err := svc.SetAdminRole(ctx, "acme-adm", "globex-adm", RoleViewer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı SetAdminRole reddedilmeli: %v", err)
	}
	if store.admins["globex-adm"].role != RoleAdmin {
		t.Fatal("reddedilen çağrı hedef rolü DEĞİŞTİRMEMELİ")
	}
	// NEGATIF: platform adminine dokunamaz (tenant '').
	if err := svc.SetAdminRole(ctx, "acme-adm", "plat", RoleViewer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kiracılı admin platform adminini değiştiremez: %v", err)
	}
	if store.admins["plat"].role != RoleAdmin {
		t.Fatal("platform admininin rolü değişmemeliydi")
	}
	// NEGATIF: bilinmeyen hedef de fail-closed.
	if err := svc.SetAdminRole(ctx, "acme-adm", "yok", RoleViewer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bilinmeyen hedef reddedilmeli: %v", err)
	}
	// POZITIF: kendi kiracısındaki yönetici.
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-viewer", RoleOperator); err != nil {
		t.Fatalf("kendi kiracısında rol değişimi geçmeli: %v", err)
	}
	if store.admins["acme-viewer"].role != RoleOperator {
		t.Fatal("rol güncellenmeliydi")
	}
	// POZITIF: platform admini kısıtsız.
	if err := svc.SetAdminRole(ctx, "plat", "globex-adm", RoleOperator); err != nil {
		t.Fatalf("platform admini her kiracıda rol değiştirebilmeli: %v", err)
	}
}

func TestAdminMgmtCrossTenantDeactivateDenied(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)

	if err := svc.DeactivateAdmin(ctx, "acme-adm", "globex-adm"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı Deactivate reddedilmeli: %v", err)
	}
	if !store.admins["globex-adm"].active {
		t.Fatal("hedef pasifleştirilmemeliydi")
	}
	if err := svc.DeactivateAdmin(ctx, "acme-adm", "plat"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kiracılı admin platform adminini pasifleştiremez: %v", err)
	}
	if !store.admins["plat"].active {
		t.Fatal("platform admini pasifleştirilmemeliydi")
	}
	// POZITIF.
	if err := svc.DeactivateAdmin(ctx, "acme-adm", "acme-viewer"); err != nil {
		t.Fatalf("kendi kiracısında pasifleştirme geçmeli: %v", err)
	}
	if store.admins["acme-viewer"].active {
		t.Fatal("kendi kiracısındaki hedef pasifleşmeliydi")
	}
	if !hasAudit(store.audits, "DEACTIVATE_ADMIN", "admin", "acme-viewer") {
		t.Fatal("DEACTIVATE_ADMIN audit yazılmalıydı")
	}
	if hasAudit(store.audits, "DEACTIVATE_ADMIN", "admin", "globex-adm") {
		t.Fatal("reddedilen eylem audit'te BAŞARILI görünmemeli")
	}
	if err := svc.DeactivateAdmin(ctx, "plat", "globex-adm"); err != nil {
		t.Fatalf("platform admini kısıtsız olmalı: %v", err)
	}
}

func TestListAdminsTenantScoped(t *testing.T) {
	ctx := context.Background()
	svc, _ := wallFixture(t)

	// acme OPERATOR: yalnız acme yöneticileri; platform/globex GÖRÜNMEZ.
	views, err := svc.ListAdmins(ctx, "acme-op")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 3 { // acme-adm, acme-viewer, acme-op
		t.Fatalf("yalnız acme yöneticileri beklenirdi: %+v", views)
	}
	for _, v := range views {
		if v.Email == "plat@x" || v.Email == "globex-adm@x" {
			t.Fatalf("başka kiracı/platform sızdı: %+v", v)
		}
	}
	// POZITIF: platform admini hepsini görür.
	all, err := svc.ListAdmins(ctx, "plat")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("platform admini 5 yönetici görmeliydi: %d", len(all))
	}
}

// S-1: ADMIN eşiği require() ile zaten kapalıdır (ADMIN en üst rütbe), bu yüzden eski
// "rol çağıranı aşamaz" kontrolü ölü koddu. Anlamlı korumalar: (a) kiracılı ADMIN, başka
// kiracıdaki/platformdaki hiç kimseye ADMIN veremez; (b) kapsamındaki SON etkin ADMIN
// kendini düşüremez/pasifleştiremez (kiracı yönetimsiz kalmasın).
func TestTenantAdminCannotGrantAdminOutsideOwnTenant(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	store.roles["globex-viewer"] = RoleViewer
	store.admins["globex-viewer"] = &adminEntry{email: "gv@x", role: RoleViewer, tenant: "globex", active: true}

	// NEGATIF: başka kiracıdaki kullanıcıya ADMIN verilemez.
	if err := svc.SetAdminRole(ctx, "acme-adm", "globex-viewer", RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı ADMIN verme reddedilmeli: %v", err)
	}
	if store.admins["globex-viewer"].role != RoleViewer {
		t.Fatal("reddedilen çağrı rolü DEĞİŞTİRMEMELİ")
	}
	// NEGATIF: platform admin satırına da dokunamaz (zaten ADMIN olsa bile).
	if err := svc.SetAdminRole(ctx, "acme-adm", "plat", RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kiracılı admin platform adminine rol veremez: %v", err)
	}
	// POZITIF: kendi kiracısında ADMIN verebilir.
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-op", RoleAdmin); err != nil {
		t.Fatalf("kendi kiracısında ADMIN verme geçmeli: %v", err)
	}
	if store.admins["acme-op"].role != RoleAdmin {
		t.Fatal("rol güncellenmeliydi")
	}
}

func TestLastAdminCannotSelfDemoteOrDeactivate(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	n := len(store.audits)

	// acme-adm, acme kiracısının TEK etkin ADMIN'i: kendini düşüremez.
	for _, r := range []Role{RoleOperator, RoleViewer} {
		if err := svc.SetAdminRole(ctx, "acme-adm", "acme-adm", r); !errors.Is(err, ErrLastAdmin) || !errors.Is(err, ErrForbidden) {
			t.Fatalf("son ADMIN kendini %s'e düşüremez (ErrLastAdmin/403): %v", r, err)
		}
	}
	if store.admins["acme-adm"].role != RoleAdmin || store.roles["acme-adm"] != RoleAdmin {
		t.Fatal("reddedilen düşürme rolü DEĞİŞTİRMEMELİ")
	}
	if err := svc.DeactivateAdmin(ctx, "acme-adm", "acme-adm"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("son ADMIN kendini pasifleştiremez: %v", err)
	}
	if !store.admins["acme-adm"].active {
		t.Fatal("reddedilen pasifleştirme durumu DEĞİŞTİRMEMELİ")
	}
	if len(store.audits) != n {
		t.Fatalf("reddedilen çağrılar audit yazmamalı: %+v", store.audits[n:])
	}
	// ADMIN → ADMIN (no-op) engellenmez.
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-adm", RoleAdmin); err != nil {
		t.Fatalf("rolü aynı bırakmak engellenmemeli: %v", err)
	}

	// Diğer kiracının ADMIN'i (globex-adm) ve platform adminleri acme için SAYILMAZ.
	// Etkin olmayan ikinci bir ADMIN de sayılmaz.
	store.roles["acme-old"] = RoleAdmin
	store.admins["acme-old"] = &adminEntry{email: "old@x", role: RoleAdmin, tenant: "acme", active: false}
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-adm", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("pasif ADMIN 'başka admin' sayılmamalı: %v", err)
	}

	// Başka bir etkin ADMIN varsa kendini düşürebilir.
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-op", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetAdminRole(ctx, "acme-adm", "acme-adm", RoleViewer); err != nil {
		t.Fatalf("ikinci etkin ADMIN varken kendini düşürmek geçmeli: %v", err)
	}
	if store.admins["acme-adm"].role != RoleViewer {
		t.Fatal("rol düşürülmeliydi")
	}
	// Artık acme-op tek etkin ADMIN: o da kendini pasifleştiremez.
	if err := svc.DeactivateAdmin(ctx, "acme-op", "acme-op"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("yeni son ADMIN kendini pasifleştiremez: %v", err)
	}
}

// Platform kapsamı: tek platform ADMIN'i, kiracılı ADMIN'ler var olsa da kendini düşüremez;
// ikinci bir platform ADMIN'i varsa düşürebilir.
func TestLastPlatformAdminCannotSelfDemote(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)

	if err := svc.SetAdminRole(ctx, "plat", "plat", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("tek platform ADMIN'i kendini düşüremez (kiracılı ADMIN'ler sayılmaz): %v", err)
	}
	if err := svc.DeactivateAdmin(ctx, "plat", "plat"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("tek platform ADMIN'i kendini pasifleştiremez: %v", err)
	}
	store.roles["plat2"] = RoleAdmin
	store.admins["plat2"] = &adminEntry{email: "plat2@x", role: RoleAdmin, tenant: "", active: true}
	if err := svc.SetAdminRole(ctx, "plat", "plat", RoleViewer); err != nil {
		t.Fatalf("ikinci platform ADMIN'i varken düşürmek geçmeli: %v", err)
	}
}

// --- Z4b-01 / Z4a-02 / Z4b-10: enrollment token ---

func TestIssueEnrollmentTokenTenantBinding(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)

	// NEGATIF: acme operatörü globex için token üretemez.
	store.lastTokenTenant = "SENTINEL"
	if _, err := svc.IssueEnrollmentToken(ctx, "acme-op", "globex"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı token reddedilmeli: %v", err)
	}
	if store.lastTokenTenant != "SENTINEL" {
		t.Fatal("reddedilen istek token KAYDETMEMELİ")
	}
	// POZITIF: boş istek = kendi kiracısı (asla dağıtım varsayılanı değil).
	if _, err := svc.IssueEnrollmentToken(ctx, "acme-op", ""); err != nil {
		t.Fatal(err)
	}
	if store.lastTokenTenant != "acme" {
		t.Fatalf("boş istek çağıranın kiracısına sabitlenmeli: %q", store.lastTokenTenant)
	}
	// POZITIF: kendi kiracısını açıkça vermek.
	if _, err := svc.IssueEnrollmentToken(ctx, "acme-op", "acme"); err != nil {
		t.Fatal(err)
	}
	if store.lastTokenTenant != "acme" {
		t.Fatalf("kendi kiracısı korunmalı: %q", store.lastTokenTenant)
	}
	// POZITIF: platform admini kiracı seçebilir.
	if _, err := svc.IssueEnrollmentToken(ctx, "plat", "globex"); err != nil {
		t.Fatal(err)
	}
	if store.lastTokenTenant != "globex" {
		t.Fatalf("platform admininin seçtiği kiracı korunmalı: %q", store.lastTokenTenant)
	}
}

func TestRevokeEnrollmentTokenTenantGate(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	store.tokenTenants = map[string]string{"tok-acme": "acme", "tok-globex": "globex"}

	// NEGATIF: acme operatörü globex token'ını iptal edemez.
	if err := svc.RevokeEnrollmentToken(ctx, "acme-op", "tok-globex"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı iptal reddedilmeli: %v", err)
	}
	if store.revoked["tok-globex"] {
		t.Fatal("yabancı token iptal EDİLMEMELİYDİ")
	}
	// NEGATIF: var olmayan token (kiracılı çağıran) fail-closed.
	if err := svc.RevokeEnrollmentToken(ctx, "acme-op", "tok-yok"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bilinmeyen token fail-closed olmalı: %v", err)
	}
	// POZITIF: kendi token'ı.
	if err := svc.RevokeEnrollmentToken(ctx, "acme-op", "tok-acme"); err != nil {
		t.Fatalf("kendi token iptali geçmeli: %v", err)
	}
	if !store.revoked["tok-acme"] {
		t.Fatal("kendi token iptal edilmeliydi")
	}
	// POZITIF: platform admini her token'ı iptal eder.
	if err := svc.RevokeEnrollmentToken(ctx, "plat", "tok-globex"); err != nil {
		t.Fatal(err)
	}
	if !store.revoked["tok-globex"] {
		t.Fatal("platform admini token iptal edebilmeli")
	}
}

// --- Z4a-09: cihaz etiketleri ---

func TestSetDeviceTagsTenantEnforcement(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	store.deviceTenant = map[string]string{"d-acme": "acme", "d-globex": "globex"}

	if err := svc.SetDeviceTags(ctx, "acme-op", "d-globex", []string{"x"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("çapraz-kiracı etiketleme reddedilmeli: %v", err)
	}
	if len(store.tags["d-globex"]) != 0 {
		t.Fatalf("yabancı cihaz etiketlenmemeliydi: %v", store.tags["d-globex"])
	}
	if err := svc.SetDeviceTags(ctx, "acme-op", "d-acme", []string{"x", "y"}); err != nil {
		t.Fatalf("kendi cihazı etiketlenebilmeli: %v", err)
	}
	if len(store.tags["d-acme"]) != 2 {
		t.Fatalf("etiketler yazılmalıydı: %v", store.tags["d-acme"])
	}
	if err := svc.SetDeviceTags(ctx, "plat", "d-globex", []string{"p"}); err != nil {
		t.Fatalf("platform admini her cihazı etiketleyebilmeli: %v", err)
	}
}

// --- Z4a-06: MFA yeniden kayıt ---

func totpFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := security.TOTPAt(secret, at)
	if err != nil {
		t.Fatalf("TOTP üretilemedi: %v", err)
	}
	return code
}

func TestMFAReenrollRequiresCurrentCode(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	now := time.Now()
	svc.now = func() time.Time { return now }

	// İlk kayıt: kod GEREKMEZ (mevcut akış korunur) + audit.
	secret, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", "")
	if err != nil || secret == "" {
		t.Fatalf("ilk kayıt kodsuz çalışmalı: %v", err)
	}
	if !hasAudit(store.audits, "MFA_ENROLL_BEGIN", "admin", "acme-op") {
		t.Fatal("MFA_ENROLL_BEGIN audit yazılmalıydı")
	}
	if err := svc.ActivateMFA(ctx, "acme-op", totpFor(t, secret, now)); err != nil {
		t.Fatal(err)
	}
	if !store.admins["acme-op"].mfaEnrolled {
		t.Fatal("MFA etkinleşmeliydi")
	}

	// NEGATIF: etkinken kodsuz yeniden kayıt reddedilir; MFA durumu/sır DEĞİŞMEZ.
	if _, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kodsuz yeniden kayıt reddedilmeli: %v", err)
	}
	if _, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", "000000"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("yanlış kodla yeniden kayıt reddedilmeli: %v", err)
	}
	if !store.admins["acme-op"].mfaEnrolled || store.admins["acme-op"].mfaSecret != secret {
		t.Fatal("reddedilen yeniden kayıt MFA'yı/sırrı değiştirmemeli (sessiz kapatma yok)")
	}
	if !hasAudit(store.audits, "MFA_REENROLL_DENIED", "admin", "acme-op") {
		t.Fatal("MFA_REENROLL_DENIED audit yazılmalıydı")
	}

	// POZITIF: geçerli GÜNCEL kod (ActivateMFA önceki adımı tüketmişti → sonraki adım).
	next := now.Add(61 * time.Second)
	svc.now = func() time.Time { return next }
	code := totpFor(t, secret, next)
	newSecret, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", code)
	if err != nil {
		t.Fatalf("geçerli kodla yeniden kayıt geçmeli: %v", err)
	}
	if newSecret == "" || newSecret == secret {
		t.Fatal("yeni sır üretilmeliydi")
	}
	if !hasAudit(store.audits, "MFA_REENROLL_BEGIN", "admin", "acme-op") {
		t.Fatal("MFA_REENROLL_BEGIN audit yazılmalıydı")
	}
}

// Yeniden kayıtta kullanılan kod tek-kullanımlıdır (anti-replay): sır değişmeden önce
// tüketilen adım ikinci kez kabul edilmez.
func TestMFAReenrollCodeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	now := time.Now()
	svc.now = func() time.Time { return now }
	store.admins["acme-op"].mfaSecret = "JBSWY3DPEHPK3PXP"
	store.admins["acme-op"].mfaEnrolled = true
	code := totpFor(t, "JBSWY3DPEHPK3PXP", now)

	if _, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", code); err != nil {
		t.Fatalf("geçerli kod kabul edilmeli: %v", err)
	}
	// Yeniden kayıt artık etkin sırrı DEĞİŞTİRMEZ (yeni sır bekleyen); saldırgan aynı kodu tekrar kullanmak
	// isterse adım tüketimi (anti-replay) yine reddeder:
	store.admins["acme-op"].mfaSecret = "JBSWY3DPEHPK3PXP"
	store.admins["acme-op"].mfaEnrolled = true
	if _, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", code); !errors.Is(err, ErrForbidden) {
		t.Fatalf("aynı kod ikinci kez kabul edilmemeli (replay): %v", err)
	}
}
