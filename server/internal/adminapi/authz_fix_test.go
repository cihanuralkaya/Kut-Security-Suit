package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/iam"
	"kut.corp/suite/server/internal/msp"
)

// fakeProvisioner, iam.Provisioner'ı test için gerçekler (girdi kullanıcıyı geri döner).
type fakeProvisioner struct{}

func (fakeProvisioner) Create(_ string, u iam.User) (iam.User, error)     { return u, nil }
func (fakeProvisioner) Replace(_, _ string, u iam.User) (iam.User, error) { return u, nil }
func (fakeProvisioner) Deactivate(_, id string) (iam.User, error)         { return iam.User{ID: id}, nil }
func (fakeProvisioner) Get(_, id string) (iam.User, error)                { return iam.User{ID: id}, nil }

// fakeMSPStore, adminapi.MSPStore'u test için gerçekler.
type fakeMSPStore struct{}

func (fakeMSPStore) MSPAddCustomer(name, tenantID string) (msp.Customer, error) {
	return msp.Customer{Name: name, TenantID: tenantID}, nil
}
func (fakeMSPStore) MSPListCustomers() ([]msp.Customer, error) { return nil, nil }
func (fakeMSPStore) MSPGetCustomer(string) (msp.Customer, bool, error) {
	return msp.Customer{}, false, nil
}
func (fakeMSPStore) MSPDeactivateCustomer(string) (bool, error) { return true, nil }

// TestSCIMAndMSPRequireAdmin, kimlik/tenant yönetim uçlarının (SCIM + MSP) artık RoleAdmin
// gerektirdiğini doğrular: bir VIEWER 403 alır, bir ADMIN geçer. (Denetim bulgusu düzeltmesi:
// önceden bu uçlar yalnız s.authed ile korunuyordu → herhangi bir Viewer kimlik/müşteri
// oluşturabiliyordu.)
func TestSCIMAndMSPRequireAdmin(t *testing.T) {
	srv, store := newServer(t)
	srv.SetSCIMProvisioner(fakeProvisioner{})
	srv.SetMSPStore(fakeMSPStore{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "a1", "admin@x", "secret", admin.RoleAdmin)
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	viewerTok, adminTok := vb["token"], ab["token"]

	cases := []struct {
		name, path string
		body       any
	}{
		{"scim-create", "/scim/v2/Users", map[string]any{"userName": "u1", "active": true}},
		{"msp-create", "/api/msp/customers", map[string]string{"name": "acme", "tenant_id": "t1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _ := post(t, ts.URL+c.path, viewerTok, c.body); code != http.StatusForbidden {
				t.Fatalf("VIEWER %s 403 almalıydı, %d", c.path, code)
			}
			if code, _ := post(t, ts.URL+c.path, adminTok, c.body); code != http.StatusCreated {
				t.Fatalf("ADMIN %s 201 almalıydı, %d", c.path, code)
			}
		})
	}
}
