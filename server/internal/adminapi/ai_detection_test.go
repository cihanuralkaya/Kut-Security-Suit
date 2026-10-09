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

// TestAIDetectionDraftEndpoint, tespit-mühendisliği ajanının canlı erişilebilirliğini
// doğrular: örnek sinyallerden geçerli bir TASLAK kural üretir (applied:false — motora
// uygulanmaz).
func TestAIDetectionDraftEndpoint(t *testing.T) {
	srv, store := newServer(t)
	srv.SetDetectionAgent(aiprovider.NewDetectionAgent(aiprovider.NewRAGStore(), nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})

	body, _ := json.Marshal(map[string]any{
		"hypothesis_id": "h-1", "title": "encoded ps", "mitre_tactic": "TA0002",
		"mitre_technique": "T1059", "description": "encoded powershell",
		"sample_signals": []string{"powershell.exe -enc AAAA", "powershell.exe -enc BBBB"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/detection/draft", bytes.NewReader(body))
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
	if out["applied"] != false {
		t.Errorf("taslak motora UYGULANMAMALI (applied:false): %v", out["applied"])
	}
	if out["valid"] != true {
		t.Errorf("TA0002/T1059 + türetilen regex ile geçerli taslak bekleniyordu: %v", out)
	}
	prop, _ := out["proposal"].(map[string]any)
	if prop["Pattern"] == nil || prop["Pattern"] == "" {
		t.Errorf("taslakta türetilmiş bir desen bekleniyordu: %v", prop)
	}

	// hypothesis_id boş → 400.
	b2, _ := json.Marshal(map[string]any{"hypothesis_id": ""})
	req2, _ := http.NewRequest("POST", ts.URL+"/api/ai/detection/draft", bytes.NewReader(b2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+lb["token"])
	resp2, _ := http.DefaultClient.Do(req2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("boş hypothesis_id 400 vermeli, alındı %d", resp2.StatusCode)
	}
}

// TestAIDetectionDraftFailOpenWhenUnset, ajan bağlı değilken {available:false}.
func TestAIDetectionDraftFailOpenWhenUnset(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/detection/draft",
		bytes.NewReader([]byte(`{"hypothesis_id":"h","sample_signals":["x"]}`)))
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
