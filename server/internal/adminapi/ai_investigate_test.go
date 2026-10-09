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

// TestAIInvestigateEndpoint, otonom soruşturma ajanının CANLI ERİŞİLEBİLİRLİĞİNİ doğrular
// (G1 aktivasyon DoD): /api/ai/investigate uçtan uca çalışır, salt-okunur rapor döner.
func TestAIInvestigateEndpoint(t *testing.T) {
	srv, store := newServer(t)
	srv.SetInvestigator(aiprovider.NewInvestigationAgent(
		aiprovider.NewModelRouter(aiprovider.NewLocalInvestigationProvider(), nil, aiprovider.NewMockProvider()),
		aiprovider.NewRAGStore(), aiprovider.NewDataDLP()))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := lb["token"]
	if token == "" {
		t.Fatal("login token vermeliydi")
	}

	reqBody, _ := json.Marshal(map[string]string{
		"incident_id": "inc-9", "category": "SECURITY",
		"message": "ransom note dropped; vssadmin delete shadows /all /quiet",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/investigate", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 bekleniyordu, alındı %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("yanıt çözülemedi: %v", err)
	}
	if out["available"] != true {
		t.Fatalf("available:true bekleniyordu (canlı erişilebilirlik): %v", out)
	}
	rep, ok := out["report"].(map[string]any)
	if !ok {
		t.Fatalf("report nesnesi bekleniyordu: %v", out)
	}
	if rep["incident_id"] != "inc-9" {
		t.Errorf("incident_id inc-9 bekleniyordu, alındı %v", rep["incident_id"])
	}
	if rep["severity"] != "CRITICAL" {
		t.Errorf("fidye → CRITICAL bekleniyordu, alındı %v", rep["severity"])
	}
}

// TestAIInvestigateFailOpenWhenUnset, ajan bağlı değilken uç noktanın fail-open
// {available:false} döndüğünü (hata değil) doğrular.
func TestAIInvestigateFailOpenWhenUnset(t *testing.T) {
	srv, store := newServer(t) // investigator bağlanmadı
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/investigate",
		bytes.NewReader([]byte(`{"incident_id":"x","category":"SECURITY","message":"m"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lb["token"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fail-open 200 bekleniyordu, alındı %d", resp.StatusCode)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["available"] != false {
		t.Errorf("ajan yokken available:false bekleniyordu: %v", out)
	}
}
