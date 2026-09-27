// Package e2e: çok-kiracılı OKUMA-YOLU izolasyonu uçtan-uca kanıtı.
//
// Gerçek memstore + gerçek adminapi.Server (gerçek admin.Service + adminread.Service
// + oturum imzalayıcı) ile: iki kiracıya (acme, globex) cihaz/olay/incident tohumlanır,
// her kiracının yöneticisi giriş yapar ve YALNIZ kendi kiracısının verisini gördüğü;
// platform yöneticisinin (kiracısız) TÜMÜNÜ gördüğü doğrulanır. Sahte yok — üretim
// okuma yığınının kendisi çalışır.
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
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/memstore"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/security"
)

func TestTenantReadIsolationEndToEnd(t *testing.T) {
	ctx := context.Background()

	// --- Gerçek güvenlik ilkelleri + üretim okuma yığını ---
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
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// --- Yöneticileri tohumla: iki kiracı-admini + bir platform admini (kiracısız) ---
	mkAdmin := func(email, tenant string) {
		hash, err := security.HashPassword("parola12")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := backend.CreateAdmin(ctx, email, hash, admin.RoleAdmin, tenant); err != nil {
			t.Fatal(err)
		}
	}
	mkAdmin("acme@x", "acme")
	mkAdmin("globex@x", "globex")
	mkAdmin("platform@x", "") // kiracısız → platform admini (tümünü görür)

	// --- Cihaz + olay + incident tohumla (kiracı başına) ---
	seed := func(deviceID, tenant, sev, msg string) {
		if _, err := backend.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
			PreferredDeviceID: deviceID, TenantID: tenant, OSPlatform: "windows",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.SaveEvents(ctx, deviceID, []model.Event{
			{TenantID: tenant, Category: "SECURITY", Severity: sev, Message: msg, OccurredAt: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.OpenIncident(ctx, deviceID, "key-"+deviceID, "rule-A", "T1059", sev, msg, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	seed("d-acme", "acme", "HIGH", "acme-only-event")
	seed("d-globex", "globex", "CRITICAL", "globex-only-event")

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

	getJSON := func(token, path string) map[string]any {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s beklenen 200, dönen %d", path, resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	countList := func(m map[string]any, key string) int {
		if arr, ok := m[key].([]any); ok {
			return len(arr)
		}
		return 0
	}

	// --- acme yöneticisi: YALNIZ acme verisi ---
	acme := login("acme@x")
	if n := countList(getJSON(acme, "/api/events"), "events"); n != 1 {
		t.Fatalf("acme /api/events yalnız kendi olayını görmeli, dönen: %d", n)
	}
	if n := countList(getJSON(acme, "/api/devices"), "devices"); n != 1 {
		t.Fatalf("acme /api/devices yalnız kendi cihazını görmeli, dönen: %d", n)
	}
	if n := countList(getJSON(acme, "/api/incidents"), "incidents"); n != 1 {
		t.Fatalf("acme /api/incidents yalnız kendi incident'ini görmeli, dönen: %d", n)
	}
	// Olay içeriği globex verisi sızdırmamalı.
	if evs, ok := getJSON(acme, "/api/events")["events"].([]any); ok {
		for _, e := range evs {
			if em, ok := e.(map[string]any); ok {
				if msg, _ := em["message"].(string); msg == "globex-only-event" {
					t.Fatal("acme başka kiracının olayını gördü (sızıntı)")
				}
			}
		}
	}
	// Özet: acme yalnız 1 cihaz.
	if sum, ok := getJSON(acme, "/api/summary")["summary"].(map[string]any); ok {
		if dt, _ := sum["devices_total"].(float64); dt != 1 {
			t.Fatalf("acme özeti 1 cihaz saymalı, dönen: %v", sum["devices_total"])
		}
	} else {
		t.Fatal("özet çözümlenemedi")
	}

	// --- globex yöneticisi: YALNIZ globex verisi ---
	globex := login("globex@x")
	if n := countList(getJSON(globex, "/api/devices"), "devices"); n != 1 {
		t.Fatalf("globex /api/devices yalnız kendi cihazını görmeli, dönen: %d", n)
	}

	// --- platform yöneticisi (kiracısız): TÜMÜNÜ görür ---
	plat := login("platform@x")
	if n := countList(getJSON(plat, "/api/devices"), "devices"); n != 2 {
		t.Fatalf("platform admini tüm cihazları görmeli, dönen: %d", n)
	}
	if n := countList(getJSON(plat, "/api/events"), "events"); n != 2 {
		t.Fatalf("platform admini tüm olayları görmeli, dönen: %d", n)
	}
	if n := countList(getJSON(plat, "/api/incidents"), "incidents"); n != 2 {
		t.Fatalf("platform admini tüm incident'leri görmeli, dönen: %d", n)
	}

	// --- SOC vakaları: çapraz-kiracı IDOR kapalı olmalı ---
	// acme admini bir vaka açar; globex admini ne listede görebilmeli ne de id ile alabilmeli.
	postJSON := func(token, path string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, created := postJSON(acme, "/api/cases", map[string]any{"title": "acme-only-case", "severity": "HIGH"})
	if code != http.StatusOK {
		t.Fatalf("acme vaka oluşturma beklenen 200, dönen %d", code)
	}
	caseID, _ := created["id"].(string)
	if caseID == "" {
		t.Fatalf("vaka id dönmeliydi: %+v", created)
	}

	if n := countList(getJSON(acme, "/api/cases"), "cases"); n != 1 {
		t.Fatalf("acme yalnız kendi vakasını görmeli, dönen: %d", n)
	}
	if n := countList(getJSON(globex, "/api/cases"), "cases"); n != 0 {
		t.Fatalf("globex acme'nin vakasını GÖRMEMELİ (IDOR), dönen: %d", n)
	}
	// globex, acme vakasını id ile de alamamalı → 404.
	greq, _ := http.NewRequest("GET", ts.URL+"/api/cases/"+caseID, nil)
	greq.Header.Set("Authorization", "Bearer "+globex)
	gresp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	gresp.Body.Close()
	if gresp.StatusCode != http.StatusNotFound {
		t.Fatalf("globex acme vakasını id ile alamamalı (404 beklendi), dönen: %d", gresp.StatusCode)
	}
	// Platform admini vakayı görebilmeli.
	if n := countList(getJSON(plat, "/api/cases"), "cases"); n != 1 {
		t.Fatalf("platform admini vakayı görmeli, dönen: %d", n)
	}
}
