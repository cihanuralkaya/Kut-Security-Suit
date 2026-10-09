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

func enrich(t *testing.T, url, token, ioc string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/ai/threatintel/enrich",
		bytes.NewReader([]byte(`{"ioc":"`+ioc+`"}`)))
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
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// TestAIThreatEnrichEndpoint, tehdit-istihbarat ajanının canlı erişilebilirliğini
// doğrular: yüklü gösterge malicious enrichment döner, bilinmeyen gösterge temiz döner.
func TestAIThreatEnrichEndpoint(t *testing.T) {
	srv, store := newServer(t)
	ti := aiprovider.NewThreatIntelAgent()
	_ = ti.IngestIndicator(aiprovider.ThreatIndicator{Value: "evil.example.com", MalwareFamily: "phishing", ConfidenceScore: 0.9})
	srv.SetThreatIntel(ti)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := lb["token"]

	known := enrich(t, ts.URL, token, "evil.example.com")
	if known["available"] != true {
		t.Fatalf("available:true bekleniyordu: %v", known)
	}
	en, _ := known["enrichment"].(map[string]any)
	if en["known_malicious"] != true {
		t.Errorf("bilinen-kötü gösterge known_malicious:true vermeli: %v", en)
	}
	if score, _ := en["reputation_score"].(float64); score < 0.8 {
		t.Errorf("itibar skoru ~0.9 bekleniyordu, alındı %v", en["reputation_score"])
	}

	unknown := enrich(t, ts.URL, token, "benign.example.org")
	enu, _ := unknown["enrichment"].(map[string]any)
	if enu["known_malicious"] != false {
		t.Errorf("bilinmeyen gösterge known_malicious:false vermeli: %v", enu)
	}
}

// TestAIThreatEnrichFailOpenWhenUnset, ajan bağlı değilken {available:false} (hata değil).
func TestAIThreatEnrichFailOpenWhenUnset(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	out := enrich(t, ts.URL, lb["token"], "x")
	if out["available"] != false {
		t.Errorf("ajan yokken available:false bekleniyordu: %v", out)
	}
}
