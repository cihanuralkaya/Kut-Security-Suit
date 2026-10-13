package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/aiprovider"
	"kut.corp/suite/server/internal/entitygraph"
)

// TestAIHuntEndpoint, tehdit-avı ajanının canlı erişilebilirliğini doğrular: tohumlanmış
// grafta nadir (Count<=2) kenarı olan bir süreç düğümü şüpheli bulgu üretmeli.
func TestAIHuntEndpoint(t *testing.T) {
	g := entitygraph.New()
	// Nadir bağlantı: tek gözlem → Count=1 (şüpheli).
	g.Observe(entitygraph.Node{Kind: entitygraph.Process, ID: "proc-evil"},
		entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.9"}, entitygraph.Connected, time.Now())

	srv, store := newServer(t)
	srv.SetHuntingAgent(&aiprovider.HuntingAgent{Graph: g})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})

	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/hunt",
		bytes.NewReader([]byte(`{"tactic":"Execution"}`)))
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
	hyps, _ := out["hypotheses"].([]any)
	if len(hyps) == 0 {
		t.Error("en az bir hipotez bekleniyordu")
	}
	findings, _ := out["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("nadir kenarlı süreç için en az bir bulgu bekleniyordu: %v", out)
	}

	// Boş taktik → 400.
	req2, _ := http.NewRequest("POST", ts.URL+"/api/ai/hunt", bytes.NewReader([]byte(`{"tactic":""}`)))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+lb["token"])
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("istek başarısız: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("boş taktik 400 vermeli, alındı %d", resp2.StatusCode)
	}
}

// TestAIHuntFailOpenWhenUnset, ajan bağlı değilken {available:false}.
func TestAIHuntFailOpenWhenUnset(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	req, _ := http.NewRequest("POST", ts.URL+"/api/ai/hunt", bytes.NewReader([]byte(`{"tactic":"Execution"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lb["token"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("istek başarısız: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["available"] != false {
		t.Errorf("ajan yokken available:false bekleniyordu: %v", out)
	}
}
