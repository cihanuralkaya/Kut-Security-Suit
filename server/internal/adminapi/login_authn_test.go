package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/controlplane"
	"kut.corp/suite/server/internal/security"
)

// TestLoginViaCanonicalAuthenticator, admin login'in controlplane.Authenticator'a
// devredildiğinde doğru kimlikle token verdiğini, yanlış parolada 401 döndüğünü
// doğrular (kanonik auth otoritesi yolu).
func TestLoginViaCanonicalAuthenticator(t *testing.T) {
	srv, store := newServer(t)
	addAdmin(t, store, "a1", "admin@x", "secret", admin.RoleAdmin)

	dummy, err := security.HashPassword("dummy-login")
	if err != nil {
		t.Fatal(err)
	}
	// MFA bu testte devre dışı (nil); MFA karar mantığı controlplane birim testlerinde.
	srv.SetAuthenticator(controlplane.NewAuthenticator(store, nil, dummy, time.Now))

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	if code != http.StatusOK || body["token"] == "" {
		t.Fatalf("kanonik authenticator ile doğru kimlik token vermeli: code=%d body=%v", code, body)
	}

	code2, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "wrong"})
	if code2 != http.StatusUnauthorized {
		t.Fatalf("yanlış parola 401 vermeli, alındı %d", code2)
	}

	code3, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "nobody@x", "password": "whatever"})
	if code3 != http.StatusUnauthorized {
		t.Fatalf("bilinmeyen hesap 401 vermeli, alındı %d", code3)
	}
}
