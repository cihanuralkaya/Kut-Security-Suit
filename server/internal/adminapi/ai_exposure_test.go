package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/aiprovider"
)

// TestAIExposureScanEndpoint, maruziyet/ASM ajanının canlı erişilebilirliğini doğrular:
// tehlikeli port + süresi dolmuş cert + bilinen-zafiyetli yazılım bulguları döner.
func TestAIExposureScanEndpoint(t *testing.T) {
	srv, store := newServer(t)
	srv.SetExposureAgent(aiprovider.NewExposureAgent(aiprovider.NewRAGStore(), nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})

	body, _ := json.Marshal(map[string]any{
		"asset_id": "srv-1", "open_ports": []int{3389, 8080}, "cert_expiry_days": -1,
		"software_versions": map[string]string{"log4j": "2.14.1"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/exposure/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lb["token"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 bekleniyordu, alındı %d", resp.StatusCode)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["available"] != true {
		t.Fatalf("available:true bekleniyordu: %v", out)
	}
	findings, _ := out["findings"].([]any)
	// RDP(3389) tehlikeli port + süresi-dolmuş cert + log4j CVE = en az 3 bulgu.
	if len(findings) < 3 {
		t.Fatalf("en az 3 bulgu bekleniyordu (RDP+cert+log4j), alındı %d: %v", len(findings), out)
	}
	kinds := map[string]bool{}
	for _, f := range findings {
		if m, ok := f.(map[string]any); ok {
			kinds[m["Kind"].(string)] = true
		}
	}
	for _, want := range []string{"OpenPort", "ExpiredCert", "KnownVulnerability"} {
		if !kinds[want] {
			t.Errorf("%s türünde bulgu bekleniyordu, bulgular: %v", want, kinds)
		}
	}
}

// TestAIExposureScanFailOpenWhenUnset, ajan bağlı değilken {available:false}.
func TestAIExposureScanFailOpenWhenUnset(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/exposure/scan",
		bytes.NewReader([]byte(`{"asset_id":"x","open_ports":[3389]}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lb["token"])
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["available"] != false {
		t.Errorf("ajan yokken available:false bekleniyordu: %v", out)
	}
}
