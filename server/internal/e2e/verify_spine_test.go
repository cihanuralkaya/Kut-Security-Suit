// Package e2e: DETECTION→RESPONSE→VERIFICATION→vaka-kapanışı omurgasının uçtan-uca kanıtı.
//
// Sahte runner YOK: gerçek memstore + gerçek adminapi.Server + GERÇEK detect.Engine
// (verify.DetectionVerifier'ın RuleRunner'ı) ile tüm halka koşturulur. Bir operatör
// vakayı CONTAINED'e getirir; kapanış-gate'i (KUT_VERIFY_REQUIRE_ON_CLOSE eşdeğeri)
// açıkken doğrulanmış check olmadan CONTAINED→CLOSED reddedilir (409); kaynak kural
// taze pencerede ARTIK tetiklemediği için verify/run VERIFIED üretir; check vakaya
// bağlanınca kapatma serbest kalır (200). Böylece "resolved ≠ fixed" boşluğunun
// kapandığı ÜRETİM yığınıyla kanıtlanır.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminapi"
	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/memstore"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/security"
	"kut.corp/suite/server/internal/verify"
)

func TestVerificationSpineEndToEnd(t *testing.T) {
	ctx := context.Background()

	// --- Gerçek güvenlik ilkelleri + üretim yığını ---
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	sessions := security.NewSessionSigner(security.DeriveKey(master, security.LabelSessionToken))

	backend := memstore.New()
	adminSvc := admin.NewService(backend, bidx, time.Hour)
	readSvc := adminread.NewService(backend, cipher)
	srv := adminapi.New(adminSvc, readSvc, backend, sessions, time.Hour)

	// GERÇEK tespit motoru = doğrulayıcının RuleRunner'ı (fake yok).
	const ruleID = "rule-mimikatz"
	engine := detect.NewEngine([]detect.Rule{{
		ID: ruleID, Name: "Kimlik-bilgisi boşaltma", Category: "SECURITY",
		Contains: []string{"mimikatz"}, Severity: "CRITICAL",
	}})
	// Akıl-sağlığı: kural GERÇEKTEN tehdit olayında tetiklemeli (VERIFIED'in
	// "yokluktan" geldiğini, bozuk/boş kuraldan gelmediğini garanti eder).
	if got := engine.Evaluate(model.Event{Category: "SECURITY", Message: "mimikatz sekurlsa"}); len(got) == 0 {
		t.Fatal("kural tehdit olayında tetiklemeliydi (test önkoşulu)")
	}

	// Kapanış-gate'i + doğrulama motoru bağlı (gerçek verifier, gerçek motor).
	srv.SetVerifyStore(verify.NewMemStore())
	srv.SetVerifier(verify.NewDetectionVerifier(engine))
	srv.SetRequireVerifyOnClose(true)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// --- Operatör (kiracı acme) + cihaz ---
	hash, err := security.HashPassword("parola12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.CreateAdmin(ctx, "op@x", hash, admin.RoleOperator, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		PreferredDeviceID: "d-acme", TenantID: "acme", OSPlatform: "windows",
	}); err != nil {
		t.Fatal(err)
	}

	// --- Oturum + yardımcılar ---
	login := func(email string) string {
		b, _ := json.Marshal(map[string]string{"email": email, "password": "parola12"})
		resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if out.Token == "" {
			t.Fatalf("%s giriş token alamadı (kod %d)", email, resp.StatusCode)
		}
		return out.Token
	}
	postJSON := func(token, path string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	tok := login("op@x")

	// --- Vakayı CONTAINED'e getir (OPEN→INVESTIGATING→CONTAINED) ---
	code, cbody := postJSON(tok, "/api/cases", map[string]any{"title": "Kimlik-bilgisi boşaltma", "severity": "CRITICAL"})
	if code != http.StatusOK {
		t.Fatalf("vaka oluşturma 200 dönmeliydi, %d", code)
	}
	caseID, _ := cbody["id"].(string)
	if caseID == "" {
		t.Fatalf("vaka id boş: %v", cbody)
	}
	for _, to := range []string{"INVESTIGATING", "CONTAINED"} {
		if c, _ := postJSON(tok, "/api/cases/"+caseID+"/transition", map[string]any{"to": to}); c != http.StatusOK {
			t.Fatalf("geçiş %s 200 dönmeliydi, %d", to, c)
		}
	}

	// --- Gate: doğrulanmış check YOK → CONTAINED→CLOSED reddedilir (409) ---
	if c, _ := postJSON(tok, "/api/cases/"+caseID+"/transition", map[string]any{"to": "CLOSED"}); c != http.StatusConflict {
		t.Fatalf("doğrulamasız CONTAINED→CLOSED 409 dönmeliydi, %d", c)
	}

	// --- verify/open (kaynak kural = gerçek motor kuralı) ---
	oc, obody := postJSON(tok, "/api/verify/open", map[string]any{
		"device_id": "d-acme", "rule_id": ruleID, "kind": "detection",
		"factors": map[string]any{"severity": "CRITICAL", "asset_criticality": 5, "exposure": 3, "confidence": 0.9, "exploitability": 0.8},
	})
	chk, _ := obody["id"].(string)
	if oc != http.StatusCreated || chk == "" {
		t.Fatalf("verify/open 201+id dönmeliydi: %d %v", oc, obody)
	}

	// --- Aksiyon-sonrası TAZE pencere: iyileşmiş (tehdit-yok) telemetri ---
	// Kaynak kural bunu ARTIK tetiklemez (mimikatz yok) → run VERIFIED üretmeli.
	if _, err := backend.SaveEvents(ctx, "d-acme", []model.Event{{
		TenantID: "acme", Category: "SECURITY", Severity: "INFO",
		Message: "endpoint healthy - no threats", OccurredAt: time.Now().Add(2 * time.Second),
	}}); err != nil {
		t.Fatal(err)
	}

	// --- verify/run → VERIFIED (gerçek detect.Engine taze pencerede tetiklemiyor) ---
	rc, rbody := postJSON(tok, "/api/verify/"+chk+"/run", map[string]any{})
	if rc != http.StatusOK || rbody["outcome"] != "VERIFIED" {
		t.Fatalf("verify/run VERIFIED dönmeliydi: %d %v", rc, rbody)
	}

	// --- Doğrulanmış check'i vakaya bağla ---
	if c, _ := postJSON(tok, "/api/cases/"+caseID+"/attach", map[string]any{"kind": "verification", "ref": chk}); c != http.StatusOK {
		t.Fatalf("doğrulama bağlama 200 dönmeliydi, %d", c)
	}

	// --- Artık VERIFIED kanıt bağlı → CONTAINED→CLOSED serbest (200) ---
	fc, fbody := postJSON(tok, "/api/cases/"+caseID+"/transition", map[string]any{"to": "CLOSED"})
	if fc != http.StatusOK || fbody["status"] != "CLOSED" {
		t.Fatalf("doğrulamalı CONTAINED→CLOSED 200+CLOSED dönmeliydi: %d %v", fc, fbody)
	}
}
