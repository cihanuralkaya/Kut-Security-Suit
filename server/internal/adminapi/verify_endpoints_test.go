package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/verify"
	"kut.corp/suite/server/internal/vuln"
)

// fakeRuleRunner, verify.RuleRunner'ı test için gerçekler: mesajı "still" olan olaylar
// için verilen kuralı tetikler (sinyal sürüyor), aksi halde temiz.
type fakeRuleRunner struct{ fireRuleID string }

func (f fakeRuleRunner) Evaluate(ev model.Event) []detect.Detection {
	if ev.Message == "still" {
		return []detect.Detection{{RuleID: f.fireRuleID}}
	}
	return nil
}

// postAny, verify yanıtları (iç içe/tamsayı alanlar) için map[string]any decode eden
// yerel yardımcı (paket post() helper'ı map[string]string döner, uyumsuz).
func postAny(t *testing.T, url, token string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestVerifyEndpoints, remediation-doğrulama uçlarını uçtan uca doğrular: open → run
// (taze pencerede kural tetiklemiyor → VERIFIED) → list. Rol kapısı (Operator) da denenir.
func TestVerifyEndpoints(t *testing.T) {
	srv, store := newServer(t)
	srv.SetVerifyStore(verify.NewMemStore())
	srv.SetVerifier(verify.NewDetectionVerifier(fakeRuleRunner{fireRuleID: "rule-A"}))
	// Taze pencere olayları temiz (kural tetiklemez) → VERIFIED beklenir.
	store.evtRows = []adminread.EventRow{{ID: "e1", DeviceID: "d1", Category: "SYSTEM", Severity: "INFO", Message: "benign"}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})

	// VIEWER open → 403 (durum-değiştiren, Operator gerekir).
	if code, _ := postAny(t, ts.URL+"/api/verify/open", vb["token"], map[string]any{"device_id": "d1", "rule_id": "rule-A"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER verify/open 403 almalıydı, %d", code)
	}

	// OPERATOR open → 201 + id.
	code, body := postAny(t, ts.URL+"/api/verify/open", ob["token"], map[string]any{
		"device_id": "d1", "rule_id": "rule-A", "kind": "detection",
		"factors": map[string]any{"severity": "HIGH", "asset_criticality": 5, "exposure": 3, "confidence": 0.9, "exploitability": 0.8},
	})
	id, _ := body["id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("OPERATOR verify/open 201+id dönmeliydi: %d %v", code, body)
	}

	// run → VERIFIED (taze olaylar kuralı tetiklemiyor).
	rc, rb := postAny(t, ts.URL+"/api/verify/"+id+"/run", ob["token"], map[string]any{})
	if rc != http.StatusOK || rb["outcome"] != "VERIFIED" {
		t.Fatalf("verify/run VERIFIED dönmeliydi: %d %v", rc, rb)
	}

	// list → 1 check (Viewer okuyabilir).
	resp, err := authedGET(t, ts.URL+"/api/verify", vb["token"])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Count  int `json:"count"`
		Checks []struct {
			Outcome string `json:"outcome"`
		} `json:"checks"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Count != 1 || out.Checks[0].Outcome != "VERIFIED" {
		t.Fatalf("verify list 1 VERIFIED check dönmeliydi: %+v", out)
	}
}

// TestVerifyDeviceStatusRun, Kind=device_status doğrulama yolunu uçtan uca sınar: cihazın
// GÜNCEL efektif durumu beklenen duruma karşı ölçülür (olay değil). Beklenen=QUARANTINED
// ve cihaz QUARANTINED → VERIFIED; beklenen=ACTIVE iken cihaz QUARANTINED → REGRESSED.
func TestVerifyDeviceStatusRun(t *testing.T) {
	srv, store := newServer(t)
	srv.SetVerifyStore(verify.NewMemStore())
	srv.SetVerifier(verify.NewDetectionVerifier(fakeRuleRunner{fireRuleID: "rule-A"})) // nil-guard için (device_status kullanmaz)
	// Cihaz efektif durumu QUARANTINED (platform admini → check kiracısı "default").
	store.devRows = []adminread.DeviceRow{{ID: "dev-q", Status: "QUARANTINED", TenantID: "default"}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := ob["token"]

	// Beklenen QUARANTINED = cihazın durumu → VERIFIED.
	code, body := postAny(t, ts.URL+"/api/verify/open", tok, map[string]any{
		"device_id": "dev-q", "kind": "device_status", "expected": "QUARANTINED",
	})
	id, _ := body["id"].(string)
	if code != http.StatusCreated || id == "" {
		t.Fatalf("device_status open 201+id dönmeliydi: %d %v", code, body)
	}
	if rc, rb := postAny(t, ts.URL+"/api/verify/"+id+"/run", tok, map[string]any{}); rc != http.StatusOK || rb["outcome"] != "VERIFIED" {
		t.Fatalf("cihaz beklenen durumda → VERIFIED olmalı: %d %v", rc, rb)
	}

	// Beklenen ACTIVE iken cihaz QUARANTINED → REGRESSED (beklenen duruma ulaşmadı).
	_, b2 := postAny(t, ts.URL+"/api/verify/open", tok, map[string]any{
		"device_id": "dev-q", "kind": "device_status", "expected": "ACTIVE",
	})
	id2, _ := b2["id"].(string)
	if rc, rb := postAny(t, ts.URL+"/api/verify/"+id2+"/run", tok, map[string]any{}); rc != http.StatusOK || rb["outcome"] != "REGRESSED" {
		t.Fatalf("cihaz beklenen durumda değil → REGRESSED olmalı: %d %v", rc, rb)
	}
}

// TestVerifyVulnRun, Kind=vuln (CVE re-scan) yolunu uçtan uca sınar: beklenen CVE cihazın
// güncel envanterinde artık eşleşmiyorsa VERIFIED (yamalandı), hâlâ eşleşiyorsa REGRESSED.
func TestVerifyVulnRun(t *testing.T) {
	srv, store := newServer(t)
	srv.SetVerifyStore(verify.NewMemStore())
	srv.SetVerifier(verify.NewDetectionVerifier(fakeRuleRunner{fireRuleID: "rule-A"})) // nil-guard
	set, err := vuln.Load(bytes.NewReader([]byte(`[{"product":"log4j","cve":"CVE-2021-44228","severity":"CRITICAL"}]`)))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVulnSet(set)
	// dev-vuln hâlâ log4j taşır (CVE eşleşir); dev-clean yamalı (eşleşmez).
	store.softwareByDev = map[string][]string{
		"dev-vuln":  {"log4j 2.14.1", "openssl 3.0"},
		"dev-clean": {"log4j 2.17.1-patched-note", "openssl 3.0"}, // "log4j" alt-dizesi eşleşir → bilerek REGRESSED
		"dev-gone":  {"openssl 3.0"},                              // log4j yok → temizlenmiş
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := ob["token"]

	openRun := func(dev string) string {
		_, b := postAny(t, ts.URL+"/api/verify/open", tok, map[string]any{
			"device_id": dev, "kind": "vuln", "expected": "CVE-2021-44228",
		})
		id, _ := b["id"].(string)
		if id == "" {
			t.Fatalf("vuln open id dönmeliydi (%s): %v", dev, b)
		}
		rc, rb := postAny(t, ts.URL+"/api/verify/"+id+"/run", tok, map[string]any{})
		if rc != http.StatusOK {
			t.Fatalf("vuln run 200 dönmeliydi (%s): %d %v", dev, rc, rb)
		}
		o, _ := rb["outcome"].(string)
		return o
	}
	if o := openRun("dev-gone"); o != "VERIFIED" {
		t.Fatalf("CVE temizlenmiş cihaz VERIFIED olmalı, %s", o)
	}
	if o := openRun("dev-vuln"); o != "REGRESSED" {
		t.Fatalf("CVE hâlâ eşleşen cihaz REGRESSED olmalı, %s", o)
	}
}
