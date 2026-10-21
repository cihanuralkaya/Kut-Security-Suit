package adminapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/authtoken"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/security"
)

// wallServer: dağıtım varsayılan kiracısı "deploy-default" olan bir sunucu + httptest.
func wallServer(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	srv, store := newServer(t)
	srv.SetTenantID("deploy-default")
	srv.SetDetector(detect.NewEngine([]detect.Rule{{
		ID: "R1", Name: "x", Category: "SECURITY", Contains: []string{"x"}, Severity: "HIGH",
	}}))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

// wallAdmin, bir yönetici ekler (tenant "" → platform) ve oturum token'ını döner.
func wallAdmin(t *testing.T, ts *httptest.Server, store *memStore, id string, role admin.Role, tenantID string) string {
	t.Helper()
	addAdmin(t, store, id, id+"@x", "secret", role)
	store.adminTen[id] = tenantID
	_, b := post(t, ts.URL+"/api/login", "", map[string]string{"email": id + "@x", "password": "secret"})
	if b["token"] == "" {
		t.Fatalf("%s için oturum alınamadı", id)
	}
	return b["token"]
}

func hasAuditRow(store *memStore, action string) bool {
	for _, a := range store.auditRows {
		if a.Action == action || strings.HasPrefix(a.Action, action+":") {
			return true
		}
	}
	return false
}

func doReq(t *testing.T, method, url, token string, body string) int {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// --- Z4b-01 / Z4a-02: enrollment token kiracısı ---

func TestIssueTokenTenantBoundCallerCannotChooseTenant(t *testing.T) {
	ts, store := wallServer(t)
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	// NEGATIF: yabancı kiracı → 403 ve token KAYDEDİLMEZ.
	before := store.tokenSeq
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "globex"}); code != http.StatusForbidden {
		t.Fatalf("yabancı kiracı için token 403 olmalı: %d", code)
	}
	if store.tokenSeq != before {
		t.Fatal("reddedilen istek token üretmemeli")
	}
	// NEGATIF: geçersiz biçimli kiracı da (kendi kiracısına eşit değil) 403.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "Bad_Tenant!"}); code != http.StatusForbidden {
		t.Fatalf("geçersiz kiracı 403 olmalı: %d", code)
	}

	// POZITIF: boş gövde {} → kendi kiracısı (ASLA dağıtım varsayılanı değil).
	if code, b := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{}); code != http.StatusOK || b["enrollment_token"] == "" {
		t.Fatalf("boş gövde meşru olmalı: %d %v", code, b)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "acme" {
		t.Fatalf("boş gövde çağıranın kiracısına sabitlenmeli, dönen: %q", got)
	}
	// POZITIF: tamamen gövdesiz istek de kendi kiracısı.
	if code := doReq(t, "POST", ts.URL+"/api/enrollment-tokens", acme, ""); code != http.StatusOK {
		t.Fatalf("gövdesiz istek meşru olmalı: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "acme" {
		t.Fatalf("gövdesiz istek kendi kiracısı olmalı: %q", got)
	}
	// POZITIF: kendi kiracısını (büyük harfle) açıkça vermek de geçer, normalize edilir.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "ACME"}); code != http.StatusOK {
		t.Fatalf("kendi kiracısı (normalize) kabul edilmeli: %d", code)
	}
}

func TestIssueTokenPlatformAdminChoosesValidatedTenant(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-op", admin.RoleOperator, "")

	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "Globex"}); code != http.StatusOK {
		t.Fatalf("platform admini kiracı seçebilmeli: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "globex" {
		t.Fatalf("seçilen kiracı tenant.Normalize ile normalize edilmeli: %q", got)
	}
	// NEGATIF: geçersiz biçim → 400 ve kayıt yok.
	before := store.tokenSeq
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "bad_tenant!"}); code != http.StatusBadRequest {
		t.Fatalf("geçersiz kiracı 400 olmalı: %d", code)
	}
	if store.tokenSeq != before {
		t.Fatal("geçersiz kiracı ile token üretilmemeli")
	}
	// POZITIF: boş gövde → dağıtım varsayılanı (yalnız platform için).
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform boş gövde: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "deploy-default" {
		t.Fatalf("platform boş gövde dağıtım varsayılanı olmalı: %q", got)
	}
}

// --- Z4b-10: token iptali kiracı kapısı ---

func TestRevokeTokenTenantGateHTTP(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-op", admin.RoleOperator, "")
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "globex"})
	globexTok := "etok-" + strconv.Itoa(store.tokenSeq)
	post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{})
	acmeTok := "etok-" + strconv.Itoa(store.tokenSeq)

	isUsed := func(id string) bool {
		for _, r := range store.tokenRows {
			if r.ID == id {
				return r.Used
			}
		}
		return false
	}
	// NEGATIF: acme, globex token'ını iptal edemez.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+globexTok+"/revoke", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("yabancı token iptali 403 olmalı: %d", code)
	}
	if isUsed(globexTok) {
		t.Fatal("yabancı token iptal EDİLMEMELİYDİ")
	}
	// POZITIF: kendi token'ı.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+acmeTok+"/revoke", acme, map[string]string{}); code != http.StatusOK {
		t.Fatalf("kendi token iptali geçmeli: %d", code)
	}
	if !isUsed(acmeTok) {
		t.Fatal("kendi token iptal edilmeliydi")
	}
	// POZITIF: platform admini her token'ı iptal eder.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+globexTok+"/revoke", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform admini iptal edebilmeli: %d", code)
	}
}

// --- Z4a-01 / Z4b-05: yönetici-yönetimi HTTP ---

func TestAdminManagementTenantScopeHTTP(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")
	_ = wallAdmin(t, ts, store, "globex-adm", admin.RoleAdmin, "globex")
	_ = plat

	// NEGATIF: acme, globex yöneticisinin rolünü / durumunu değiştiremez; platform adminine dokunamaz.
	for _, target := range []string{"globex-adm", "plat-adm"} {
		if code, _ := post(t, ts.URL+"/api/admins/"+target+"/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusForbidden {
			t.Fatalf("%s rol değişimi 403 olmalı: %d", target, code)
		}
		if code, _ := post(t, ts.URL+"/api/admins/"+target+"/deactivate", acme, map[string]string{}); code != http.StatusForbidden {
			t.Fatalf("%s pasifleştirme 403 olmalı: %d", target, code)
		}
		if !store.adminInfos[target].Active || store.adminInfos[target].Role != admin.RoleAdmin {
			t.Fatalf("%s DEĞİŞMEMELİYDİ: %+v", target, store.adminInfos[target])
		}
	}
	// NEGATIF: liste yalnız kendi kiracısı.
	resp, err := authedGET(t, ts.URL+"/api/admins", acme)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	body := buf.String()
	if strings.Contains(body, "globex-adm@x") || strings.Contains(body, "plat-adm@x") {
		t.Fatalf("liste başka kiracı/platform yöneticilerini SIZDIRMAMALI: %s", body)
	}
	if !strings.Contains(body, "acme-adm@x") {
		t.Fatalf("kendi kiracısı listede olmalı: %s", body)
	}

	// POZITIF: platform admini kısıtsız.
	if code, _ := post(t, ts.URL+"/api/admins/globex-adm/role", plat, map[string]string{"role": "VIEWER"}); code != http.StatusOK {
		t.Fatalf("platform admini rol değiştirebilmeli: %d", code)
	}
	if store.adminInfos["globex-adm"].Role != admin.RoleViewer {
		t.Fatal("rol güncellenmeliydi")
	}
	// POZITIF: kiracı admini kendi kiracısında (yeni yönetici oluşturup) değiştirebilir.
	code, nb := post(t, ts.URL+"/api/admins", acme, map[string]string{"email": "n@acme", "password": "parola12", "role": "VIEWER"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("kendi kiracısında admin oluşturma: %d %v", code, nb)
	}
	newID := nb["admin_id"]
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/role", acme, map[string]string{"role": "OPERATOR"}); code != http.StatusOK {
		t.Fatalf("kendi kiracısında rol değişimi geçmeli: %d", code)
	}
}

// --- Z4a-03: yönetilen API token'ları yalnız platform admini ---

func TestManagedAPITokensPlatformAdminOnly(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")

	// Platform admini bir token üretir (pozitif) + audit.
	code, cb := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "metrics"})
	if code != http.StatusCreated || cb["id"] == "" {
		t.Fatalf("platform admini token üretebilmeli: %d %v", code, cb)
	}
	if !hasAuditRow(store, "API_TOKEN_CREATE") {
		t.Fatal("API_TOKEN_CREATE audit satırı yazılmalıydı")
	}

	// NEGATIF: kiracılı ADMIN üretemez / listeleyemez / iptal edemez.
	if code, _ := post(t, ts.URL+"/api/tokens", acme, map[string]any{"scope": "ingest"}); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token üretememeli: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/tokens", acme, ""); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token listeleyememeli: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens/"+cb["id"]+"/revoke", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token iptal edememeli: %d", code)
	}
	if hasAuditRow(store, "API_TOKEN_REVOKE") {
		t.Fatal("reddedilen iptal audit'te başarılı görünmemeli")
	}

	// POZITIF: platform admini listeler ve iptal eder (+ audit).
	if code := doReq(t, "GET", ts.URL+"/api/tokens", plat, ""); code != http.StatusOK {
		t.Fatalf("platform admini listeleyebilmeli: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens/"+cb["id"]+"/revoke", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform admini iptal edebilmeli: %d", code)
	}
	if !hasAuditRow(store, "API_TOKEN_REVOKE") {
		t.Fatal("API_TOKEN_REVOKE audit satırı yazılmalıydı")
	}
}

// --- Z4a-09: cihaz etiketleri ---

func TestDeviceTagsCrossTenantDeniedHTTP(t *testing.T) {
	ts, store := wallServer(t)
	store.deviceTenant = map[string]string{"d-acme": "acme", "d-globex": "globex"}
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	if code, _ := post(t, ts.URL+"/api/devices/d-globex/tags", acme, map[string]any{"tags": []string{"x"}}); code != http.StatusForbidden {
		t.Fatalf("yabancı cihaz etiketleme 403 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/devices/d-acme/tags", acme, map[string]any{"tags": []string{"x"}}); code != http.StatusOK {
		t.Fatalf("kendi cihazını etiketleyebilmeli: %d", code)
	}
}

// --- Z4a (rol eşikleri): custody / artifact download / replay ---

func TestForensicsRoutesRequireOperator(t *testing.T) {
	ts, store := wallServer(t)
	viewer := wallAdmin(t, ts, store, "vw", admin.RoleViewer, "")
	op := wallAdmin(t, ts, store, "op", admin.RoleOperator, "")
	aid, _ := store.SaveArtifact(context.Background(), "dev-1", "cmd-1", "C:/logs/app.log", "abcd", []byte("icerik"))

	// NEGATIF: VIEWER 403.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/evidence/"+aid+"/custody", viewer, map[string]string{"action": "ACCESSED"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER custody 403 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/artifacts/"+aid+"/download", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("VIEWER artifact download 403 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/detections/replay", viewer, map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("VIEWER replay 403 olmalı: %d", code)
	}

	// POZITIF: OPERATOR geçer (403 değil; indirme 200, replay 200).
	if code := doReq(t, "GET", ts.URL+"/api/artifacts/"+aid+"/download", op, ""); code != http.StatusOK {
		t.Fatalf("OPERATOR artifact download 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/detections/replay", op, map[string]any{}); code != http.StatusOK {
		t.Fatalf("OPERATOR replay 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/evidence/"+aid+"/custody", op, map[string]string{"action": "ACCESSED"}); code == http.StatusForbidden {
		t.Fatalf("OPERATOR custody 403 almamalı: %d", code)
	}
}

// --- Z4a-06: MFA yeniden kayıt HTTP ---

func TestMFAReenrollNeedsCodeHTTP(t *testing.T) {
	ts, store := wallServer(t)
	tok := wallAdmin(t, ts, store, "op1", admin.RoleOperator, "")

	// İlk kayıt: {} ile kodsuz çalışır.
	code, eb := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{})
	if code != http.StatusOK || eb["secret"] == "" {
		t.Fatalf("ilk kayıt kodsuz çalışmalı: %d %v", code, eb)
	}
	secret := eb["secret"]
	otp, _ := security.TOTPAt(secret, time.Now())
	if c, _ := post(t, ts.URL+"/api/mfa/activate", tok, map[string]string{"code": otp}); c != http.StatusOK {
		t.Fatalf("activate: %d", c)
	}

	// NEGATIF: etkinken kodsuz yeniden kayıt 403 → MFA kapatılmaz, sır değişmez.
	if c, _ := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{}); c != http.StatusForbidden {
		t.Fatalf("kodsuz yeniden kayıt 403 olmalı: %d", c)
	}
	if c, _ := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{"code": "000000"}); c != http.StatusForbidden {
		t.Fatalf("yanlış kodlu yeniden kayıt 403 olmalı: %d", c)
	}
	if m := store.mfa["op1"]; m == nil || !m.enrolled || m.secret != secret {
		t.Fatalf("reddedilen yeniden kayıt MFA'yı değiştirmemeli: %+v", m)
	}
	if !hasAuditRow(store, "MFA_REENROLL_DENIED") {
		t.Fatal("MFA_REENROLL_DENIED audit satırı yazılmalıydı")
	}

	// POZITIF: geçerli (sonraki adım) kod ile yeniden kayıt.
	// Not: sunucu saati gerçek zaman olduğundan ±1 adım penceresi içindeki kod aranır; aktivasyonda
	// kullanılan adım tüketildiği için ONDAN BÜYÜK bir adım (sonraki pencere) kullanılır.
	next, _ := security.TOTPAt(secret, time.Now().Add(30*time.Second))
	if c, b := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{"code": next}); c != http.StatusOK || b["secret"] == "" || b["secret"] == secret {
		t.Fatalf("geçerli kodla yeniden kayıt geçmeli: %d %v", c, b)
	}
	if !hasAuditRow(store, "MFA_REENROLL_BEGIN") {
		t.Fatal("MFA_REENROLL_BEGIN audit satırı yazılmalıydı")
	}
}

// S-1 (HTTP): kiracının SON etkin ADMIN'i kendini düşüremez/pasifleştiremez (403); ikinci bir
// ADMIN varsa düşürebilir. Platform admini ve diğer kiracıların ADMIN'leri sayılmaz.
func TestLastTenantAdminSelfDemotionDeniedHTTP(t *testing.T) {
	ts, store := wallServer(t)
	_ = wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")
	_ = wallAdmin(t, ts, store, "globex-adm", admin.RoleAdmin, "globex")

	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusForbidden {
		t.Fatalf("son ADMIN kendini düşüremez (403): %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/deactivate", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("son ADMIN kendini pasifleştiremez (403): %d", code)
	}
	if info := store.adminInfos["acme-adm"]; !info.Active || info.Role != admin.RoleAdmin {
		t.Fatalf("reddedilen çağrılar DEĞİŞTİRMEMELİ: %+v", info)
	}

	// İkinci bir kiracı ADMIN'i eklenince kendini düşürebilir.
	code, nb := post(t, ts.URL+"/api/admins", acme, map[string]string{"email": "b@acme", "password": "parola12", "role": "ADMIN"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("ikinci ADMIN oluşturma: %d %v", code, nb)
	}
	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusOK {
		t.Fatalf("ikinci ADMIN varken düşürmek geçmeli: %d", code)
	}
}
