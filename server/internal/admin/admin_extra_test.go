package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/security"
)

// TestMFAEnrollmentLifecycle, MFA üçlüsünü (BeginMFAEnrollment/ActivateMFA/DisableMFA)
// uçtan uca doğrular: kayıt başlatma sırrı bekleyen yapar; geçerli kod etkinleştirir
// (audit MFA_ENABLED); geçersiz kod reddedilir; geçerli kod ile kapatma (audit
// MFA_DISABLED); kayıt başlatılmadan etkinleştirme reddedilir.
func TestMFAEnrollmentLifecycle(t *testing.T) {
	store := newMemStore()
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	fixed := time.Date(2026, 1, 2, 3, 4, 30, 0, time.UTC)
	svc.now = func() time.Time { return fixed }
	ctx := context.Background()

	// admin1 tarafından yeni bir OPERATOR yönetici oluştur (m.admins'e girsin).
	id, err := svc.CreateAdmin(ctx, "admin1", "u@x", "parola12", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}

	// Kayıt başlatılmadan ActivateMFA → ErrForbidden.
	if err := svc.ActivateMFA(ctx, id, "000000"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("kayıt yokken ActivateMFA reddedilmeli: %v", err)
	}

	// BeginMFAEnrollment: sır + otpauth URI döner, sır bekleyen (enrolled=false) olur.
	secret, uri, err := svc.BeginMFAEnrollment(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !strings.HasPrefix(uri, "otpauth://") {
		t.Fatalf("sır+otpauth URI dönmeliydi: secret=%q uri=%q", secret, uri)
	}
	if store.admins[id].mfaSecret != secret || store.admins[id].mfaEnrolled {
		t.Fatalf("sır bekleyen olarak saklanmalıydı: %+v", store.admins[id])
	}

	// Geçersiz kod ile etkinleştirme reddedilmeli.
	if err := svc.ActivateMFA(ctx, id, "123456"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("geçersiz kod etkinleştirmemeli: %v", err)
	}

	// Geçerli kod ile etkinleştir → enrolled=true + audit.
	code, err := security.TOTPAt(secret, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ActivateMFA(ctx, id, code); err != nil {
		t.Fatalf("geçerli kod etkinleştirmeli: %v", err)
	}
	if !store.admins[id].mfaEnrolled {
		t.Fatal("etkinleştirme sonrası mfaEnrolled true olmalı")
	}
	if !hasAudit(store.audits, "MFA_ENABLED", "admin", id) {
		t.Fatalf("MFA_ENABLED audit yazılmalıydı: %+v", store.audits)
	}

	// Etkinken geçersiz kod ile kapatma reddedilmeli.
	if err := svc.DisableMFA(ctx, id, "123456"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("etkinken geçersiz kod kapatmamalı: %v", err)
	}

	// Geçerli kod ile kapat → sır silinir + audit MFA_DISABLED. (Sonraki zaman-adımından
	// kod: aktivasyon adımı tek-kullanım kuralıyla tüketildi, aynı kod tekrar kabul edilmez.)
	code2, err := security.TOTPAt(secret, fixed.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableMFA(ctx, id, code2); err != nil {
		t.Fatalf("geçerli kod kapatmalı: %v", err)
	}
	if store.admins[id].mfaSecret != "" || store.admins[id].mfaEnrolled {
		t.Fatalf("kapatma sonrası sır temizlenmeliydi: %+v", store.admins[id])
	}
	if !hasAudit(store.audits, "MFA_DISABLED", "admin", id) {
		t.Fatalf("MFA_DISABLED audit yazılmalıydı: %+v", store.audits)
	}
}

// TestDisableMFAPendingOnly, yalnız bekleyen (etkinleşmemiş) sır varken DisableMFA'nın
// kod istemeden sırrı temizlediğini ve audit YAZMADIĞINI doğrular.
func TestDisableMFAPendingOnly(t *testing.T) {
	store := newMemStore()
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	ctx := context.Background()

	id, err := svc.CreateAdmin(ctx, "admin1", "u@x", "parola12", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.BeginMFAEnrollment(ctx, id); err != nil {
		t.Fatal(err)
	}
	// enrolled=false → kod gerekmeden kapatılır, MFA_DISABLED audit'i YAZILMAZ.
	if err := svc.DisableMFA(ctx, id, ""); err != nil {
		t.Fatalf("bekleyen sır kod olmadan temizlenmeli: %v", err)
	}
	if store.admins[id].mfaSecret != "" {
		t.Fatal("bekleyen sır temizlenmeliydi")
	}
	if hasAudit(store.audits, "MFA_DISABLED", "admin", id) {
		t.Fatal("etkinleşmemiş MFA kapatma audit yazmamalı")
	}
}

// TestCancelWipeRBACAndAudit, CancelWipe'ın ADMIN gerektirdiğini, bekleyen talebi
// sildiğini ve audit WIPE_CANCEL yazdığını doğrular.
func TestCancelWipeRBACAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["adminA"] = RoleAdmin
	store.roles["adminB"] = RoleAdmin
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.RequestWipe(ctx, "adminA", "dev-1", "kayıp"); err != nil {
		t.Fatal(err)
	}
	// OPERATOR iptal edememeli.
	if err := svc.CancelWipe(ctx, "op1", "dev-1"); err != ErrForbidden {
		t.Fatalf("OPERATOR CancelWipe reddedilmeli: %v", err)
	}
	if _, ok := store.pendWipes["dev-1"]; !ok {
		t.Fatal("reddedilen iptal bekleyen talebi silmemeli")
	}
	// ADMIN iptal edebilmeli → bekleyen silinir + audit.
	if err := svc.CancelWipe(ctx, "adminB", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.pendWipes["dev-1"]; ok {
		t.Fatal("iptal sonrası bekleyen talep silinmeliydi")
	}
	if !hasAudit(store.audits, "WIPE_CANCEL", "device", "dev-1") {
		t.Fatalf("WIPE_CANCEL audit yazılmalıydı: %+v", store.audits)
	}
	// İptal sonrası onay → bekleyen yok (ErrInvalidInput).
	if err := svc.ApproveWipe(ctx, "adminB", "dev-1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("iptal sonrası onay bekleyen yok dönmeli: %v", err)
	}
}

// TestRequestWipeInputValidation, RequestWipe girdi doğrulamasını (boş cihaz kimliği,
// aşırı uzun gerekçe) ve OPERATOR onayının reddini doğrular.
func TestRequestWipeInputValidation(t *testing.T) {
	store := newMemStore()
	store.roles["admin1"] = RoleAdmin
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.RequestWipe(ctx, "admin1", "  ", "sebep"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("boş cihaz kimliği reddedilmeli: %v", err)
	}
	if err := svc.RequestWipe(ctx, "admin1", "dev-1", strings.Repeat("x", 501)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("aşırı uzun gerekçe reddedilmeli: %v", err)
	}
	// OPERATOR onaylayamamalı (ADMIN gerekir).
	if err := svc.ApproveWipe(ctx, "op1", "dev-1"); err != ErrForbidden {
		t.Fatalf("OPERATOR ApproveWipe reddedilmeli: %v", err)
	}
}

// TestRevokeDeviceRBACAndAudit, RevokeDevice'ın OPERATOR+ gerektirdiğini, sertifikaları
// iptal ettiğini ve audit REVOKE_CERT yazdığını doğrular.
func TestRevokeDeviceRBACAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.RevokeDevice(ctx, "viewer1", "dev-1"); err != ErrForbidden {
		t.Fatalf("VIEWER cert iptal edememeli: %v", err)
	}
	if err := svc.RevokeDevice(ctx, "op1", "dev-1"); err != nil {
		t.Fatalf("OPERATOR cert iptal edebilmeli: %v", err)
	}
	var revoked bool
	for _, c := range store.commands {
		if c.cmdType == "REVOKE" && c.deviceID == "dev-1" {
			revoked = true
		}
	}
	if !revoked {
		t.Fatalf("RevokeDeviceCerts çağrılmalıydı: %+v", store.commands)
	}
	if !hasAudit(store.audits, "REVOKE_CERT", "device", "dev-1") {
		t.Fatalf("REVOKE_CERT audit yazılmalıydı: %+v", store.audits)
	}
}

// TestLockRestartQueueAndAudit, LOCK/RESTART komutlarının kuyruğa girip audit
// yazdığını (durum yansıtmadan) doğrular.
func TestLockRestartQueueAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.LockDevice(ctx, "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestartDevice(ctx, "op1", "dev-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 2 || store.commands[0].cmdType != "LOCK" || store.commands[1].cmdType != "RESTART" {
		t.Fatalf("LOCK+RESTART kuyruğa girmeliydi: %+v", store.commands)
	}
	if !hasAudit(store.audits, "LOCK", "device", "dev-1") || !hasAudit(store.audits, "RESTART", "device", "dev-1") {
		t.Fatalf("LOCK/RESTART audit yazılmalıydı: %+v", store.audits)
	}
	// Bu komutlar cihaz durum sütununu değiştirmez.
	if _, ok := store.statuses["dev-1"]; ok {
		t.Fatal("LOCK/RESTART durum değiştirmemeli")
	}
}

// TestSetAdminRoleRBACAndValidation, SetAdminRole'ün RBAC (OPERATOR reddi) ve rol
// doğrulamasını (geçersiz rol → ErrInvalidInput) ve başarılı yol + audit'i doğrular.
func TestSetAdminRoleRBACAndValidation(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	ctx := context.Background()

	// OPERATOR rol değiştirememeli.
	if err := svc.SetAdminRole(ctx, "op1", "adm-x", RoleViewer); err != ErrForbidden {
		t.Fatalf("OPERATOR SetAdminRole reddedilmeli: %v", err)
	}
	// Geçersiz rol reddedilmeli.
	if err := svc.SetAdminRole(ctx, "admin1", "adm-x", Role("BOGUS")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("geçersiz rol reddedilmeli: %v", err)
	}
	// ADMIN + geçerli rol → başarı + audit.
	if err := svc.SetAdminRole(ctx, "admin1", "adm-x", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if store.roles["adm-x"] != RoleAdmin {
		t.Fatalf("rol ayarlanmalıydı: %v", store.roles["adm-x"])
	}
	if !hasAudit(store.audits, "SET_ADMIN_ROLE", "admin", "adm-x") {
		t.Fatalf("SET_ADMIN_ROLE audit yazılmalıydı: %+v", store.audits)
	}
}

// TestDeactivateAdminRBACAndAudit, DeactivateAdmin'in OPERATOR reddini ve ADMIN
// başarı yolunu + audit'i doğrular.
func TestDeactivateAdminRBACAndAudit(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	store.roles["admin1"] = RoleAdmin
	svc, _ := newService(t, store)
	ctx := context.Background()

	id, err := svc.CreateAdmin(ctx, "admin1", "u@x", "parola12", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeactivateAdmin(ctx, "op1", id); err != ErrForbidden {
		t.Fatalf("OPERATOR DeactivateAdmin reddedilmeli: %v", err)
	}
	if err := svc.DeactivateAdmin(ctx, "admin1", id); err != nil {
		t.Fatal(err)
	}
	if store.admins[id].active {
		t.Fatal("yönetici pasifleştirilmiş olmalıydı")
	}
	if !hasAudit(store.audits, "DEACTIVATE_ADMIN", "admin", id) {
		t.Fatalf("DEACTIVATE_ADMIN audit yazılmalıydı: %+v", store.audits)
	}
}

// TestListPolicyRulesRBAC, ListPolicyRules'ün OPERATOR+ gerektirdiğini ve depodaki
// kuralları döndürdüğünü doğrular.
func TestListPolicyRulesRBAC(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	_ = store.AddPolicyRule(ctx, "pol-1", RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "oyun.exe"})

	if _, err := svc.ListPolicyRules(ctx, "viewer1", "pol-1"); err != ErrForbidden {
		t.Fatalf("VIEWER kural listeleyememeli: %v", err)
	}
	rules, err := svc.ListPolicyRules(ctx, "op1", "pol-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Type != "APP_BLOCK_ALWAYS" || rules[0].Target != "oyun.exe" {
		t.Fatalf("kurallar dönmeliydi: %+v", rules)
	}
}

// TestEnsureRole, EnsureRole'ün require ile aynı RBAC kararını verdiğini doğrular.
func TestEnsureRole(t *testing.T) {
	store := newMemStore()
	store.roles["viewer1"] = RoleViewer
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)
	ctx := context.Background()

	if err := svc.EnsureRole(ctx, "viewer1", RoleOperator); err != ErrForbidden {
		t.Fatalf("yetersiz rol ErrForbidden dönmeli: %v", err)
	}
	if err := svc.EnsureRole(ctx, "op1", RoleOperator); err != nil {
		t.Fatalf("yeterli rol geçmeli: %v", err)
	}
	if err := svc.EnsureRole(ctx, "op1", RoleViewer); err != nil {
		t.Fatalf("daha düşük eşik geçmeli: %v", err)
	}
}

// TestHelpers, saf yardımcıları (rank, validRuleType, validAdminRole, defaultGenToken)
// doğrular.
func TestHelpers(t *testing.T) {
	// rank: sıralama ve bilinmeyen rol → 0.
	if rank(RoleViewer) != 1 || rank(RoleOperator) != 2 || rank(RoleAdmin) != 3 {
		t.Fatal("rank sıralaması hatalı")
	}
	if rank(Role("BOGUS")) != 0 {
		t.Fatalf("bilinmeyen rol rank 0 olmalı, %d", rank(Role("BOGUS")))
	}

	// validRuleType.
	for _, ok := range []string{"APP_TIME_BLOCK", "APP_BLOCK_ALWAYS", "NETWORK_RULE"} {
		if !validRuleType(ok) {
			t.Fatalf("%q geçerli tip olmalı", ok)
		}
	}
	if validRuleType("BOGUS") || validRuleType("") {
		t.Fatal("geçersiz tip reddedilmeli")
	}

	// validAdminRole.
	for _, ok := range []Role{RoleViewer, RoleOperator, RoleAdmin} {
		if !validAdminRole(ok) {
			t.Fatalf("%q geçerli rol olmalı", ok)
		}
	}
	if validAdminRole(Role("BOGUS")) {
		t.Fatal("geçersiz rol reddedilmeli")
	}

	// defaultGenToken: boş olmayan, benzersiz, geçerli base32 (padding'siz) token.
	t1, err := defaultGenToken()
	if err != nil || t1 == "" {
		t.Fatalf("token üretilmeliydi: %v", err)
	}
	t2, _ := defaultGenToken()
	if t1 == t2 {
		t.Fatal("token'lar benzersiz olmalı")
	}
	if strings.ContainsAny(t1, "=") {
		t.Fatalf("token padding içermemeli: %q", t1)
	}
}
