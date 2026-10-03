package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockEnrollmentHandler struct {
	resp EnrollResponse
	err  error
}

func (m *mockEnrollmentHandler) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	return m.resp, m.err
}

type mockPolicyProvider struct {
	bundle PolicyBundle
	err    error
}

func (m *mockPolicyProvider) GetPolicy(ctx context.Context, tenantID, deviceID string) (PolicyBundle, error) {
	return m.bundle, m.err
}

type mockAdminStore struct {
	user AdminUser
	err  error
}

func (m *mockAdminStore) AuthenticateAdmin(ctx context.Context, email, password string) (AdminUser, error) {
	return m.user, m.err
}

func TestControlPlane_Lifecycle(t *testing.T) {
	plane := New(&mockEnrollmentHandler{}, &mockPolicyProvider{}, &mockAdminStore{})
	ctx := context.Background()

	// Operations before Start should fail
	_, err := plane.EnrollDevice(ctx, EnrollRequest{})
	if err == nil {
		t.Fatal("expected error calling EnrollDevice before Start")
	}

	if err := plane.Start(ctx); err != nil {
		t.Fatalf("unexpected error starting plane: %v", err)
	}

	// Double start should fail
	if err := plane.Start(ctx); err == nil {
		t.Fatal("expected error starting already running plane")
	}

	if err := plane.Stop(); err != nil {
		t.Fatalf("unexpected error stopping plane: %v", err)
	}

	// Double stop should fail
	if err := plane.Stop(); err == nil {
		t.Fatal("expected error stopping already stopped plane")
	}
}

func TestControlPlane_Delegations(t *testing.T) {
	enrollHandler := &mockEnrollmentHandler{
		resp: EnrollResponse{DeviceID: "dev-123", NotAfter: time.Now().Add(24 * time.Hour)},
	}
	policyProvider := &mockPolicyProvider{
		bundle: PolicyBundle{PolicyVersion: "v1.0.0"},
	}
	adminStore := &mockAdminStore{
		user: AdminUser{ID: "adm-1", Email: "admin@kut.local", Role: "ADMIN"},
	}

	plane := New(enrollHandler, policyProvider, adminStore)
	ctx := context.Background()
	if err := plane.Start(ctx); err != nil {
		t.Fatalf("failed to start plane: %v", err)
	}
	defer plane.Stop()

	// Test EnrollDevice
	enrollResp, err := plane.EnrollDevice(ctx, EnrollRequest{Hostname: "host1"})
	if err != nil {
		t.Fatalf("unexpected error enrolling: %v", err)
	}
	if enrollResp.DeviceID != "dev-123" {
		t.Errorf("expected dev-123, got %s", enrollResp.DeviceID)
	}

	// Test FetchPolicyForDevice
	policy, err := plane.FetchPolicyForDevice(ctx, "tenant-a", "dev-123")
	if err != nil {
		t.Fatalf("unexpected error fetching policy: %v", err)
	}
	if policy.PolicyVersion != "v1.0.0" {
		t.Errorf("expected v1.0.0, got %s", policy.PolicyVersion)
	}

	// Test Authenticate
	user, err := plane.Authenticate(ctx, "admin@kut.local", "secret")
	if err != nil {
		t.Fatalf("unexpected error authenticating: %v", err)
	}
	if user.Email != "admin@kut.local" {
		t.Errorf("expected admin@kut.local, got %s", user.Email)
	}
}

func TestControlPlane_ErrorHandling(t *testing.T) {
	enrollHandler := &mockEnrollmentHandler{err: errors.New("invalid token")}
	plane := New(enrollHandler, nil, nil)
	ctx := context.Background()
	_ = plane.Start(ctx)
	defer plane.Stop()

	_, err := plane.EnrollDevice(ctx, EnrollRequest{})
	if err == nil || err.Error() != "invalid token" {
		t.Fatalf("expected 'invalid token' error, got %v", err)
	}

	_, err = plane.FetchPolicyForDevice(ctx, "tenant-a", "dev-1")
	if err == nil {
		t.Fatal("expected error with nil policy provider")
	}

	_, err = plane.Authenticate(ctx, "foo", "bar")
	if err == nil {
		t.Fatal("expected error with nil admin store")
	}
}
