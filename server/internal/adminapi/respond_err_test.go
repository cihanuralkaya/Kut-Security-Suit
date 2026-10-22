package adminapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/admin"
)

// Scope/ROE guardrail reddi bir yetki sonucudur — 403, 500 değil.
func TestRespondErr_OutOfScopeIs403(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"out-of-scope", admin.ErrOutOfScope, http.StatusForbidden},
		{"out-of-scope wrapped", fmt.Errorf("%w (quarantine): kapsam dışı", admin.ErrOutOfScope), http.StatusForbidden},
		{"forbidden unchanged", admin.ErrForbidden, http.StatusForbidden},
		{"invalid input unchanged", admin.ErrInvalidInput, http.StatusBadRequest},
		{"unknown error stays 500", fmt.Errorf("beklenmeyen"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		if !respondErr(rec, c.err) {
			t.Errorf("%s: respondErr true dönmeliydi", c.name)
		}
		if rec.Code != c.want {
			t.Errorf("%s: HTTP %d, beklenen %d", c.name, rec.Code, c.want)
		}
	}
	if respondErr(httptest.NewRecorder(), nil) {
		t.Error("nil hata için respondErr true döndü")
	}
	// Gerekçe (ROE kapsamı) istemciye sızdırılmaz.
	rec := httptest.NewRecorder()
	respondErr(rec, fmt.Errorf("%w (wipe): cihaz dev-secret-7 dışlanmış", admin.ErrOutOfScope))
	if body := rec.Body.String(); len(body) == 0 || strings.Contains(body, "dev-secret-7") || strings.Contains(body, "dışlanmış") {
		t.Errorf("yanıt motor gerekçesini sızdırıyor: %q", body)
	}
}

// Uçtan uca: Scope/ROE motoru yapılandırılmamışken yüksek-etkili karantina fail-closed
// reddedilir (ErrOutOfScope) ve API bunu 403 olarak döner.
func TestQuarantine_ScopeUnconfiguredIs403(t *testing.T) {
	srv, store := newServer(t)
	srv.adminSvc.SetScopeAllowUnconfigured(false)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	code, _ := post(t, ts.URL+"/api/devices/quarantine", lb["token"], map[string]string{"device_id": "dev-1"})
	if code != http.StatusForbidden {
		t.Fatalf("scope yapılandırılmamış karantina: HTTP %d, beklenen 403", code)
	}
}
