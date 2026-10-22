package adminapi

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/aiprovider"
	"kut.corp/suite/server/internal/aisec"
	"kut.corp/suite/server/internal/entitygraph"
)

func getJSON(t *testing.T, url, tok string) (int, map[string]any) {
	t.Helper()
	resp, err := authedGET(t, url, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

const exfilBody = `{"nodes":[{"id":"web","kind":"context","trust":"UNTRUSTED"},{"id":"agent","kind":"agent","trust":"TRUSTED"},{"id":"cred","kind":"credential","trust":"TRUSTED"},{"id":"evil","kind":"external","trust":"TRUSTED"}],"edges":[{"type":"read","from":"agent","to":"web"},{"type":"read","from":"agent","to":"cred"},{"type":"write","from":"agent","to":"evil"}]}`

// trustOverwriteBody, aynı kimlikli düğümleri "TRUSTED" yaparak başkasının zincirini bastırmaya çalışır.
const trustOverwriteBody = `{"nodes":[{"id":"web","kind":"context","trust":"TRUSTED"},{"id":"agent","kind":"agent","trust":"TRUSTED"}]}`

func agentSecServer(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	srv, store := newServer(t)
	srv.SetAgentSec(aisec.NewService())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

// agentsec grafı kiracı başına bölümlüdür — okuma ve yazma çapraz-kiracı
// geçmez; platform admini tümünü (etiketli) ya da açık filtreyle tek kiracıyı görür.
func TestAgentSecTenantPartitionHTTP(t *testing.T) {
	ts, store := agentSecServer(t)
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")
	globex := wallAdmin(t, ts, store, "globex-op", admin.RoleOperator, "globex")
	plat := wallAdmin(t, ts, store, "plat-op", admin.RoleOperator, "")

	// acme exfil zincirini kendi bölümüne işler.
	if code := doReq(t, "POST", ts.URL+"/api/agentsec/events", acme, exfilBody); code != http.StatusOK {
		t.Fatalf("acme ingest: %d", code)
	}

	// POZİTİF: acme kendi bulgusunu görür.
	if code, out := getJSON(t, ts.URL+"/api/agentsec/findings", acme); code != 200 || out["count"].(float64) != 1 {
		t.Fatalf("acme kendi bulgusunu görmeli: %d %v", code, out)
	}
	// NEGATİF: globex acme'nin bulgusunu görmez; ?tenant=acme ile seçemez (yok sayılır).
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings", globex); out["count"].(float64) != 0 {
		t.Fatalf("globex acme bulgusunu görmemeli: %v", out)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings?tenant=acme", globex); out["count"].(float64) != 0 {
		t.Fatalf("globex ?tenant=acme ile başka kiracıyı seçememeli: %v", out)
	}
	// NEGATİF (yazma): globex aynı kimlikli düğümleri TRUSTED yapar → acme zinciri bastırılmaz.
	if code := doReq(t, "POST", ts.URL+"/api/agentsec/events?tenant=acme", globex, trustOverwriteBody); code != http.StatusOK {
		t.Fatalf("globex kendi bölümüne yazabilir: %d", code)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings", acme); out["count"].(float64) != 1 {
		t.Fatalf("globex yazımı acme bulgusunu bastırmamalı: %v", out)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings", globex); out["count"].(float64) != 0 {
		t.Fatalf("globex'in kendi (zararsız) grafında bulgu olmamalı: %v", out)
	}

	// Platform: filtresiz tümü (kiracı etiketli), açık filtreyle tek kiracı, geçersiz filtre 400.
	_, all := getJSON(t, ts.URL+"/api/agentsec/findings", plat)
	rows, _ := all["findings"].([]any)
	if all["count"].(float64) != 1 || rows[0].(map[string]any)["tenant"] != "acme" {
		t.Fatalf("platform tümünü kiracı etiketiyle görmeli: %v", all)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings?tenant=globex", plat); out["count"].(float64) != 0 {
		t.Fatalf("platform ?tenant=globex yalnız globex bölümünü görmeli: %v", out)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings?tenant=ACME", plat); out["count"].(float64) != 1 {
		t.Fatalf("platform ?tenant=ACME normalize edilmeli: %v", out)
	}
	if code, _ := getJSON(t, ts.URL+"/api/agentsec/findings?tenant=Bad%20Tenant!", plat); code != http.StatusBadRequest {
		t.Fatalf("geçersiz tenant filtresi 400 olmalı: %d", code)
	}

	// Kanonik uç: acme kendi kiracı damgalı olayı alır; globex hiçbir olay almaz.
	_, can := getJSON(t, ts.URL+"/api/agentsec/canonical", acme)
	evs, _ := can["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["tenant_id"] != "acme" {
		t.Fatalf("acme kanonik olayı acme damgalı olmalı: %v", can)
	}
	if _, can := getJSON(t, ts.URL+"/api/agentsec/canonical?tenant=acme", globex); can["count"].(float64) != 0 {
		t.Fatalf("globex kanonik uçtan acme olayını alamaz: %v", can)
	}
	_, canAll := getJSON(t, ts.URL+"/api/agentsec/canonical", plat)
	if evs, _ := canAll["events"].([]any); len(evs) != 1 || evs[0].(map[string]any)["tenant_id"] != "acme" {
		t.Fatalf("platform kanonik görünümü bulguyu kendi bölüm kiracısıyla atıflamalı: %v", canAll)
	}
}

// Gözlem sınırları: istek başına düğüm tavanı 413, aşırı uzun kimlik 400 (hiçbiri uygulanmaz).
func TestAgentSecObservationBounds(t *testing.T) {
	ts, store := agentSecServer(t)
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	var nodes []string
	for i := 0; i < maxAgentSecNodesPerReq+1; i++ {
		nodes = append(nodes, `{"id":"n`+strings.Repeat("x", 3)+string(rune('a'+i%26))+`","kind":"agent","trust":"TRUSTED"}`)
	}
	big := `{"nodes":[` + strings.Join(nodes, ",") + `]}`
	if code := doReq(t, "POST", ts.URL+"/api/agentsec/events", acme, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("düğüm tavanı aşımı 413 olmalı: %d", code)
	}
	long := `{"nodes":[{"id":"` + strings.Repeat("a", aisec.MaxIDLen+1) + `","kind":"agent","trust":"TRUSTED"}]}`
	if code := doReq(t, "POST", ts.URL+"/api/agentsec/events", acme, long); code != http.StatusBadRequest {
		t.Fatalf("uzun kimlik 400 olmalı: %d", code)
	}
	// POZİTİF: normal gözlem kabul edilir.
	if code := doReq(t, "POST", ts.URL+"/api/agentsec/events", acme, exfilBody); code != http.StatusOK {
		t.Fatalf("normal gözlem 200 olmalı: %d", code)
	}
}

// İmzalı telemetri, anahtar kaydındaki kiracının bölümüne işlenir: o kiracının admini görür,
// başka kiracının admini görmez.
func TestAgentSecSignedTelemetryLandsInRegisteredTenantPartition(t *testing.T) {
	srv, store := newServer(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	reg := aisec.NewMemKeyRegistry()
	reg.Register("agent-1", pub, "acme")
	srv.SetAgentTrust(aisec.NewTrustVerifier(reg, nil, time.Minute))
	srv.SetAgentSec(aisec.NewService())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	payload := []byte(exfilBody)
	now := time.Now()
	obs := aisec.SignedObservation{AgentID: "agent-1", TenantID: "acme", Sequence: 1, Timestamp: now, Nonce: "n1", Payload: payload}
	obs.Signature = ed25519.Sign(priv, aisec.SigningBytes(obs))
	wire := map[string]any{
		"agent_id": "agent-1", "tenant_id": "acme", "sequence": 1,
		"timestamp": now, "nonce": "n1", "payload": payload, "signature": obs.Signature,
	}
	b, _ := json.Marshal(wire)
	req, _ := http.NewRequest("POST", ts.URL+"/api/agentsec/telemetry", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("geçerli imzalı telemetri 200 olmalı: %d", resp.StatusCode)
	}

	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleViewer, "acme")
	globex := wallAdmin(t, ts, store, "globex-op", admin.RoleViewer, "globex")
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings", acme); out["count"].(float64) != 1 {
		t.Fatalf("acme imzalı telemetri bulgusunu görmeli: %v", out)
	}
	if _, out := getJSON(t, ts.URL+"/api/agentsec/findings", globex); out["count"].(float64) != 0 {
		t.Fatalf("globex acme telemetrisini görmemeli: %v", out)
	}
}

// /api/ai/hunt kiracılı çağıranı kendi graf düğümleriyle sınırlar; platform admini hepsini
// görür ve açık tenant ile daraltır; kiracılı çağıranın body'deki tenant'ı yok sayılır.
func TestAIHuntTenantScopedHTTP(t *testing.T) {
	g := entitygraph.New()
	now := time.Now()
	g.Observe(entitygraph.Node{Kind: entitygraph.Process, ID: "proc-acme", Tenant: "acme"},
		entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.1", Tenant: "acme"}, entitygraph.Connected, now)
	g.Observe(entitygraph.Node{Kind: entitygraph.Process, ID: "proc-globex", Tenant: "globex"},
		entitygraph.Node{Kind: entitygraph.IP, ID: "203.0.113.2", Tenant: "globex"}, entitygraph.Connected, now)

	srv, store := newServer(t)
	srv.SetHuntingAgent(&aiprovider.HuntingAgent{Graph: g})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	acme := wallAdmin(t, ts, store, "acme-viewer", admin.RoleViewer, "acme")
	plat := wallAdmin(t, ts, store, "plat-viewer", admin.RoleViewer, "")

	hunt := func(tok, body string) (int, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/api/ai/hunt", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, e := resp.Body.Read(buf)
			sb.Write(buf[:n])
			if e != nil {
				break
			}
		}
		return resp.StatusCode, sb.String()
	}

	// POZİTİF: acme yalnız kendi düğümünü görür.
	code, body := hunt(acme, `{"tactic":"Execution"}`)
	if code != 200 || !strings.Contains(body, "proc-acme") {
		t.Fatalf("acme kendi düğümünü görmeli: %d %s", code, body)
	}
	// NEGATİF: globex'in düğümü/IP'si sızmaz; body'deki tenant=globex yok sayılır.
	for _, b := range []string{`{"tactic":"Execution"}`, `{"tactic":"Execution","tenant":"globex"}`} {
		_, body := hunt(acme, b)
		if strings.Contains(body, "proc-globex") || strings.Contains(body, "203.0.113.2") {
			t.Fatalf("acme globex düğümünü görmemeli (%s): %s", b, body)
		}
	}
	// Platform: filtresiz ikisini, tenant=globex ile yalnız globex'i görür; geçersiz tenant 400.
	if _, body := hunt(plat, `{"tactic":"Execution"}`); !strings.Contains(body, "proc-acme") || !strings.Contains(body, "proc-globex") {
		t.Fatalf("platform tüm kiracıları görmeli: %s", body)
	}
	if _, body := hunt(plat, `{"tactic":"Execution","tenant":"globex"}`); strings.Contains(body, "proc-acme") || !strings.Contains(body, "proc-globex") {
		t.Fatalf("platform tenant=globex yalnız globex'i görmeli: %s", body)
	}
	if code, _ := hunt(plat, `{"tactic":"Execution","tenant":"Bad Tenant!"}`); code != http.StatusBadRequest {
		t.Fatalf("geçersiz tenant 400 olmalı: %d", code)
	}
}

// kiracıya bağlı rapor ve /api/activity süreç-geneli sayaçları TAŞIMAZ; platform taşır.
func TestReportAndActivityOmitProcessCountersForTenant(t *testing.T) {
	srv, store := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	acme := wallAdmin(t, ts, store, "acme-viewer", admin.RoleViewer, "acme")
	plat := wallAdmin(t, ts, store, "plat-viewer", admin.RoleViewer, "")

	// Rapor (JSON): kiracılı → counters_omitted, platform → sayaçlar var.
	_, rep := getJSON(t, ts.URL+"/api/report?format=json", acme)
	if rep["counters_omitted"] != true {
		t.Fatalf("kiracılı rapor counters_omitted taşımalı: %v", rep)
	}
	_, repP := getJSON(t, ts.URL+"/api/report?format=json", plat)
	if repP["counters_omitted"] == true {
		t.Fatalf("platform raporu sayaçları taşımalı: %v", repP)
	}
	// HTML raporda "Tehdit etkinliği" bölümü kiracılıda YOK, platformda var.
	for tok, want := range map[string]bool{acme: false, plat: true} {
		resp, err := authedGET(t, ts.URL+"/api/report", tok)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, e := resp.Body.Read(buf)
			sb.Write(buf[:n])
			if e != nil {
				break
			}
		}
		resp.Body.Close()
		if got := strings.Contains(sb.String(), "Tehdit etkinliği"); got != want {
			t.Fatalf("HTML raporda 'Tehdit etkinliği' varlığı=%v beklenen=%v", got, want)
		}
	}
	// /api/activity.
	_, actT := getJSON(t, ts.URL+"/api/activity", acme)
	if c, _ := actT["counters"].(map[string]any); len(c) != 0 || actT["counters_omitted"] != true {
		t.Fatalf("kiracılı activity sayaç taşımamalı: %v", actT)
	}
	_, actP := getJSON(t, ts.URL+"/api/activity", plat)
	if c, _ := actP["counters"].(map[string]any); len(c) == 0 {
		t.Fatalf("platform activity sayaç taşımalı: %v", actP)
	}
}

// /api/hunt/sequence-score çağıranın KİRACI taban çizgisini kullanır; kiracılı çağıran
// başka kiracının taban çizgisini seçemez (?tenant= yok sayılır); platform admini seçebilir.
func TestSequenceScoreTenantBaselines(t *testing.T) {
	srv, store := newServer(t)
	m := aibrain.NewSeqModels()
	for i := 0; i < 10; i++ {
		m.Observe("acme", []string{"explorer.exe", "cmd.exe"})
	}
	srv.SetSeqModel(m)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	acme := wallAdmin(t, ts, store, "acme-v", admin.RoleViewer, "acme")
	globex := wallAdmin(t, ts, store, "globex-v", admin.RoleViewer, "globex")
	plat := wallAdmin(t, ts, store, "plat-v", admin.RoleViewer, "")

	score := func(tok, q string) float64 {
		code, out := getJSON(t, ts.URL+"/api/hunt/sequence-score?tokens=explorer.exe,cmd.exe"+q, tok)
		if code != 200 {
			t.Fatalf("sequence-score %d", code)
		}
		return out["score"].(float64)
	}
	if s := score(acme, ""); s != 0 {
		t.Fatalf("acme kendi taban çizgisinde sıradan: %v", s)
	}
	if s := score(globex, ""); s != 100 {
		t.Fatalf("globex acme taban çizgisini görmemeli: %v", s)
	}
	if s := score(globex, "&tenant=acme"); s != 100 {
		t.Fatalf("globex ?tenant=acme ile başka taban çizgisini seçememeli: %v", s)
	}
	if s := score(plat, "&tenant=acme"); s != 0 {
		t.Fatalf("platform açık kiracı seçebilmeli: %v", s)
	}
	if code, _ := getJSON(t, ts.URL+"/api/hunt/sequence-score?tokens=a,b&tenant=Bad%20T!", plat); code != http.StatusBadRequest {
		t.Fatalf("geçersiz tenant 400: %d", code)
	}
}
