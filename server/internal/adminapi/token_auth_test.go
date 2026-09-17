package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/authtoken"
)

// TestManagedTokenAuthOnMetrics, /metrics ucunun hem YÖNETİLEN token'ı hem de statik
// env token'ı (geriye uyumlu fallback) kabul ettiğini; iptal edilen yönetilen token'ı
// reddettiğini doğrular.
func TestManagedTokenAuthOnMetrics(t *testing.T) {
	srv, _ := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Yönetilen token deposu + bir token; statik env token da ayrı ayarlı.
	store := authtoken.NewMemStore(nil)
	srv.SetTokenStore(store)
	srv.SetMetricsToken("statik-token")
	id, secret, err := store.Create(authtoken.ScopeMetrics, 0)
	if err != nil {
		t.Fatal(err)
	}

	code := func(tok string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	if code(secret) != http.StatusOK {
		t.Fatal("yönetilen token /metrics'e erişebilmeli")
	}
	if code("statik-token") != http.StatusOK {
		t.Fatal("statik env token (fallback) hâlâ çalışmalı")
	}
	if code("yanlis") != http.StatusUnauthorized {
		t.Fatal("yanlış token 401 olmalı")
	}
	// İptal edilen yönetilen token reddedilmeli (statik token hâlâ geçerli).
	if err := store.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if code(secret) != http.StatusUnauthorized {
		t.Fatal("iptal edilen yönetilen token reddedilmeli")
	}
	// Yalnız yönetilen depo, statik token yok: yönetilen token yine çalışır, uç açık.
	srv2, _ := newServer(t)
	st2 := authtoken.NewMemStore(nil)
	srv2.SetTokenStore(st2)
	_, sec2, _ := st2.Create(authtoken.ScopeMetrics, 0)
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	req, _ := http.NewRequest("GET", ts2.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+sec2)
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("statik token olmadan yönetilen token /metrics'i açmalı, %d", r.StatusCode)
	}
}
