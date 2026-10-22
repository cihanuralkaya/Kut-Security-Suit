package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/authtoken"
	"kut.corp/suite/server/internal/model"
)

// tenantIngest, kaydedilen olayları cihaz başına tutan sahte EventIngestor'dır.
type tenantIngest struct {
	mu    sync.Mutex
	saved map[string][]model.Event
}

func newTenantIngest() *tenantIngest { return &tenantIngest{saved: map[string][]model.Event{}} }

func (t *tenantIngest) SaveEvents(_ context.Context, dev string, evs []model.Event) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.saved[dev] = append(t.saved[dev], evs...)
	return 0, nil
}

func (t *tenantIngest) all() []model.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []model.Event
	for _, v := range t.saved {
		out = append(out, v...)
	}
	return out
}

func ingestPost(t *testing.T, url, token, ctype, body string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", ctype)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// mintIngest, platform admini olarak kiracıya bağlı ingest token'ı üretir.
func mintIngest(t *testing.T, ts *httptest.Server, plat, tenantID string) string {
	t.Helper()
	body := map[string]any{"scope": "ingest"}
	if tenantID != "" {
		body["tenant"] = tenantID
	}
	code, out := post(t, ts.URL+"/api/tokens", plat, body)
	if code != http.StatusCreated || out["secret"] == "" {
		t.Fatalf("ingest token üretilemedi (tenant=%q): %d %v", tenantID, code, out)
	}
	return out["secret"]
}

const cefLine = "CEF:0|Vendor|Product|1.0|100|firewall deny|5|src=10.0.0.5 rt=1700000000000"

// TestIngestTokenBindsTenant: kiracıya bağlı token ile gelen olaylar SaveEvents'ten
// ÖNCE o kiracıyla damgalanır; aynı kaynak adını kullanan iki kiracı AYRI cihaz kimliğine
// düşer; istemci başlık/gövde/query ile kiracı SEÇEMEZ.
func TestIngestTokenBindsTenant(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	sink := newTenantIngest()
	srv.SetIngest(sink, "")
	proc := &recProc{}
	srv.SetEventProcessor(proc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")

	acmeTok := mintIngest(t, ts, plat, "acme")
	globexTok := mintIngest(t, ts, plat, "Globex ") // normalize edilir
	if !hasAuditRow(store, "API_TOKEN_CREATE") {
		t.Fatal("token üretimi audit'e yazılmalı")
	}

	// İstemci kiracı SEÇMEYE çalışır (başlık + query + gövde alanı): hepsi YOK SAYILMALI.
	hdr := map[string]string{"X-Tenant-ID": "globex", "X-KUT-Tenant": "globex"}
	jsonBody := `[{"source":"fw1","category":"SECURITY","severity":"HIGH","message":"deny","tenant_id":"globex","tenant":"globex"}]`
	if c := ingestPost(t, ts.URL+"/api/ingest?tenant=globex", acmeTok, "application/json", jsonBody, hdr); c != http.StatusOK {
		t.Fatalf("acme ingest: %d", c)
	}
	acmeEvs := sink.all()
	if len(acmeEvs) != 1 || acmeEvs[0].TenantID != "acme" {
		t.Fatalf("acme token'ı olayı acme ile damgalamalı (istemci girdisi yok sayılır): %+v", acmeEvs)
	}
	acmeDev := ""
	for d := range sink.saved {
		acmeDev = d
	}

	// Aynı kaynak adı ("fw1") globex token'ıyla → globex damgası + AYRI cihaz kimliği.
	if c := ingestPost(t, ts.URL+"/api/ingest", globexTok, "application/json", jsonBody, nil); c != http.StatusOK {
		t.Fatalf("globex ingest: %d", c)
	}
	if len(sink.saved) != 2 {
		t.Fatalf("iki kiracının aynı kaynak adı AYRI cihaz olmalı, cihaz sayısı=%d", len(sink.saved))
	}
	for dev, evs := range sink.saved {
		want := "globex"
		if dev == acmeDev {
			want = "acme"
		}
		for _, e := range evs {
			if e.TenantID != want {
				t.Fatalf("cihaz %s olayı kiracı %q taşımalı, %q aldı", dev, want, e.TenantID)
			}
		}
	}

	// CEF (düz metin) yolu da damgalanır; tespit hattı (ProcessEvent) kiracı-damgalı olay alır.
	if c := ingestPost(t, ts.URL+"/api/ingest", acmeTok, "text/plain", cefLine, nil); c != http.StatusOK {
		t.Fatalf("acme cef ingest: %d", c)
	}
	proc.mu.Lock()
	defer proc.mu.Unlock()
	if len(proc.events) != 3 {
		t.Fatalf("3 olay işlenmeliydi: %d", len(proc.events))
	}
	for i, e := range proc.events {
		if e.TenantID == "" {
			t.Fatalf("ProcessEvent'e kiracısız olay verildi (#%d): %+v", i, e)
		}
	}
}

// TestIngestLegacyTokenFallsBackToDeploymentTenant: kiracısız (legacy) statik token,
// KUT_TENANT_ENFORCE kapalıyken dağıtımın varsayılan kiracısıyla damgalanır — boş değil.
func TestIngestLegacyTokenFallsBackToDeploymentTenant(t *testing.T) {
	srv, _ := newServer(t)
	srv.SetTenantID("Deploy-Default")
	sink := newTenantIngest()
	srv.SetIngest(sink, "legacy-tok")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if c := ingestPost(t, ts.URL+"/api/ingest", "legacy-tok", "text/plain", cefLine, nil); c != http.StatusOK {
		t.Fatalf("legacy ingest: %d", c)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].TenantID != "deploy-default" {
		t.Fatalf("legacy token dağıtım kiracısına düşmeli: %+v", evs)
	}
}

// TestIngestEnforceDeniesTenantlessToken (INV-044): KUT_TENANT_ENFORCE açıkken kiracısız
// (statik ya da yönetilen) token REDDEDİLİR, hiçbir olay kaydedilmez/işlenmez; kiracıya
// bağlı token geçer. Kiracısız ingest token'ı üretimi de reddedilir.
func TestIngestEnforceDeniesTenantlessToken(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	srv.SetTenantEnforce(true)
	sink := newTenantIngest()
	srv.SetIngest(sink, "legacy-tok")
	proc := &recProc{}
	srv.SetEventProcessor(proc)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")

	// NEGATIF: statik (kiracısız) token → 403.
	if c := ingestPost(t, ts.URL+"/api/ingest", "legacy-tok", "text/plain", cefLine, nil); c != http.StatusForbidden {
		t.Fatalf("enforce açıkken kiracısız token 403 olmalı: %d", c)
	}
	// NEGATIF: kiracısız ingest token'ı üretilemez.
	if code, _ := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "ingest"}); code != http.StatusBadRequest {
		t.Fatalf("enforce açıkken kiracısız ingest token üretimi 400 olmalı: %d", code)
	}
	if len(sink.all()) != 0 || len(proc.events) != 0 {
		t.Fatal("reddedilen istek hiçbir olay kaydetmemeli/işlememeli")
	}
	// NEGATİF: yanlış token → 401 (kimlik doğrulama kiracı kapısından önce).
	if c := ingestPost(t, ts.URL+"/api/ingest", "nope", "text/plain", cefLine, nil); c != http.StatusUnauthorized {
		t.Fatalf("geçersiz token 401 olmalı: %d", c)
	}
	// POZİTİF: kiracıya bağlı token geçer ve damgalanır.
	tok := mintIngest(t, ts, plat, "acme")
	if c := ingestPost(t, ts.URL+"/api/ingest", tok, "text/plain", cefLine, nil); c != http.StatusOK {
		t.Fatalf("kiracılı token geçmeli: %d", c)
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].TenantID != "acme" {
		t.Fatalf("acme damgası beklenir: %+v", evs)
	}
}

// TestIngestTokenMintingValidation: kiracı bağı yalnız ingest kapsamı ve geçerli biçim;
// kiracıya bağlı admin token üretemez (platform-yalnız); revoke sonrası token çalışmaz.
func TestIngestTokenMintingValidation(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	sink := newTenantIngest()
	srv.SetIngest(sink, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acmeAdm := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")

	if code, _ := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "metrics", "tenant": "acme"}); code != http.StatusBadRequest {
		t.Fatalf("metrics token'ı kiracıya bağlanamaz: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "ingest", "tenant": "Bad Tenant!"}); code != http.StatusBadRequest {
		t.Fatalf("geçersiz kiracı biçimi 400 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens", acmeAdm, map[string]any{"scope": "ingest", "tenant": "globex"}); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin ingest token'ı üretememeli: %d", code)
	}
	// Kiracı-kör Verify, kiracıya bağlı token'ı KABUL ETMEZ; VerifyTenant kiracıyı döndürür.
	st := authtoken.NewMemStore(nil)
	_, sec, err := st.CreateForTenant(authtoken.ScopeIngest, "acme", 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Verify(authtoken.ScopeIngest, sec) {
		t.Fatal("kiracı-kör Verify, kiracıya bağlı token'ı kabul etmemeli")
	}
	if tn, ok := st.VerifyTenant(authtoken.ScopeIngest, sec); !ok || tn != "acme" {
		t.Fatalf("VerifyTenant kiracıyı döndürmeli: %q %v", tn, ok)
	}
	if _, _, err := st.CreateForTenant(authtoken.ScopeMetrics, "acme", 0); err == nil {
		t.Fatal("metrics kapsamı kiracı bağı taşıyamaz")
	}

	// İptal sonrası token çalışmaz.
	code, out := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "ingest", "tenant": "acme"})
	if code != http.StatusCreated {
		t.Fatalf("üretim: %d", code)
	}
	if c := ingestPost(t, ts.URL+"/api/ingest", out["secret"], "text/plain", cefLine, nil); c != http.StatusOK {
		t.Fatalf("geçerli token: %d", c)
	}
	if code, _ := post(t, ts.URL+"/api/tokens/"+out["id"]+"/revoke", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("iptal: %d", code)
	}
	if c := ingestPost(t, ts.URL+"/api/ingest", out["secret"], "text/plain", cefLine, nil); c != http.StatusUnauthorized {
		t.Fatalf("iptal edilen token 401 olmalı: %d", c)
	}
}
