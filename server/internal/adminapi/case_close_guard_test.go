package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/verify"
)

// caseID, POST /api/cases yanıtından (tam Case JSON) id çeker.
func caseID(t *testing.T, ts, token, title string) string {
	t.Helper()
	code, body := postAny(t, ts+"/api/cases", token, map[string]any{"title": title, "severity": "HIGH"})
	if code != http.StatusOK {
		t.Fatalf("vaka oluşturma 200 dönmeliydi, %d", code)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("vaka id boş: %v", body)
	}
	return id
}

// TestCaseCloseVerifyGuard, opt-in CONTAINED→CLOSED doğrulama gate'ini uçtan uca sınar:
// gate açıkken doğrulanmış check olmadan kapatma 409; VERIFIED check bağlanınca 200.
// Ayrıca gate'in yalnızca CONTAINED kaynağını hedeflediğini (OPEN→CLOSED serbest) doğrular.
func TestCaseCloseVerifyGuard(t *testing.T) {
	srv, store := newServer(t)
	srv.SetVerifyStore(verify.NewMemStore())
	srv.SetVerifier(verify.NewDetectionVerifier(fakeRuleRunner{fireRuleID: "rule-A"}))
	srv.SetRequireVerifyOnClose(true) // gate ETKİN
	// Taze pencere olayları temiz → run VERIFIED üretir.
	store.evtRows = []adminread.EventRow{{ID: "e1", DeviceID: "d1", Category: "SYSTEM", Severity: "INFO", Message: "benign"}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := ob["token"]

	// (A) Kontrol: gate yalnızca CONTAINED'i hedefler → OPEN→CLOSED doğrulama istemez.
	openCase := caseID(t, ts.URL, tok, "Doğrudan kapatma")
	if c, _ := postAny(t, ts.URL+"/api/cases/"+openCase+"/transition", tok, map[string]any{"to": "CLOSED"}); c != http.StatusOK {
		t.Fatalf("OPEN→CLOSED gate'e takılmamalı (200), %d", c)
	}

	// (B) Vakayı CONTAINED'e getir (OPEN→INVESTIGATING→CONTAINED).
	id := caseID(t, ts.URL, tok, "Kimlik ele geçirme")
	for _, to := range []string{"INVESTIGATING", "CONTAINED"} {
		if c, _ := postAny(t, ts.URL+"/api/cases/"+id+"/transition", tok, map[string]any{"to": to}); c != http.StatusOK {
			t.Fatalf("geçiş %s 200 dönmeliydi, %d", to, c)
		}
	}

	// (C) Doğrulanmış check YOK → CONTAINED→CLOSED reddedilir (409, fail-closed).
	if c, _ := postAny(t, ts.URL+"/api/cases/"+id+"/transition", tok, map[string]any{"to": "CLOSED"}); c != http.StatusConflict {
		t.Fatalf("doğrulamasız CONTAINED→CLOSED 409 dönmeliydi, %d", c)
	}

	// (D) VERIFIED bir check üret (open → run) ve vakaya bağla.
	_, ob2 := postAny(t, ts.URL+"/api/verify/open", tok, map[string]any{"device_id": "d1", "rule_id": "rule-A"})
	chk, _ := ob2["id"].(string)
	if chk == "" {
		t.Fatalf("verify/open id dönmeliydi: %v", ob2)
	}
	if rc, rb := postAny(t, ts.URL+"/api/verify/"+chk+"/run", tok, map[string]any{}); rc != http.StatusOK || rb["outcome"] != "VERIFIED" {
		t.Fatalf("verify/run VERIFIED dönmeliydi: %d %v", rc, rb)
	}
	if c, _ := post(t, ts.URL+"/api/cases/"+id+"/attach", tok, map[string]string{"kind": "verification", "ref": chk}); c != http.StatusOK {
		t.Fatalf("doğrulama bağlama 200 dönmeliydi, %d", c)
	}

	// (E) Artık VERIFIED check bağlı → CONTAINED→CLOSED serbest (200).
	if c, body := postAny(t, ts.URL+"/api/cases/"+id+"/transition", tok, map[string]any{"to": "CLOSED"}); c != http.StatusOK {
		t.Fatalf("doğrulamalı CONTAINED→CLOSED 200 dönmeliydi, %d %v", c, body)
	} else if body["status"] != "CLOSED" {
		t.Fatalf("vaka CLOSED olmalı: %v", body["status"])
	}
}

// TestCaseCloseGuardDisabled, gate KAPALI (default) iken CONTAINED→CLOSED'ün doğrulama
// olmadan da çalıştığını (non-breaking) doğrular.
func TestCaseCloseGuardDisabled(t *testing.T) {
	srv, store := newServer(t)
	srv.SetVerifyStore(verify.NewMemStore()) // depo bağlı ama gate kapalı
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := ob["token"]

	id := caseID(t, ts.URL, tok, "Kapalı gate")
	for _, to := range []string{"INVESTIGATING", "CONTAINED", "CLOSED"} {
		c, body := postAny(t, ts.URL+"/api/cases/"+id+"/transition", tok, map[string]any{"to": to})
		if c != http.StatusOK {
			t.Fatalf("gate kapalıyken geçiş %s 200 dönmeliydi, %d %v", to, c, body)
		}
	}
	// son durumu doğrula.
	resp, err := authedGET(t, ts.URL+"/api/cases", tok)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var lst struct {
		Cases []struct {
			Status string `json:"status"`
		} `json:"cases"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&lst)
	if len(lst.Cases) != 1 || lst.Cases[0].Status != "CLOSED" {
		t.Fatalf("gate kapalıyken vaka CLOSED olmalı: %+v", lst)
	}
}
