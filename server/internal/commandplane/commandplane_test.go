package commandplane

import (
	"context"
	"errors"
	"testing"
)

// mockStore is a simple mock for CommandStore.
type mockStore struct {
	commands map[string]CommandRecord
	nextID   int
}

func newMockStore() *mockStore {
	return &mockStore{
		commands: make(map[string]CommandRecord),
		nextID:   1,
	}
}

func (m *mockStore) EnqueueCommand(ctx context.Context, deviceID string, cmdType CommandType, issuedBy string, params map[string]any) (string, error) {
	id := "cmd-123" // Test için
	return id, nil
}

func (m *mockStore) GetPendingCommands(ctx context.Context, deviceID string) ([]CommandRecord, error) {
	return nil, nil
}

func (m *mockStore) AckCommand(ctx context.Context, commandID string, status CommandState, detail string) error {
	if commandID == "" {
		return errors.New("empty command ID")
	}
	return nil
}

// mockAuthorizer is a simple mock for Authorizer.
type mockAuthorizer struct {
	allowAll bool
}

func (m *mockAuthorizer) Authorize(ctx context.Context, req ActionRequest) (AuthorizationDecision, error) {
	if m.allowAll {
		return AuthorizationDecision{Allowed: true}, nil
	}
	return AuthorizationDecision{Allowed: false, Reason: "unauthorized"}, nil
}

func TestLifecycle(t *testing.T) {
	p := NewPlane(newMockStore(), &mockAuthorizer{})
	
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("Expected error when starting already running plane")
	}
	
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if err := p.Stop(); err == nil {
		t.Fatal("Expected error when stopping already stopped plane")
	}
}

func TestDispatch_Authorization(t *testing.T) {
	req := CommandRequest{
		DeviceID: "dev1",
		Type:     TypeLock,
		IssuedBy: "admin",
	}

	// Test Allow
	pAllow := NewPlane(newMockStore(), &mockAuthorizer{allowAll: true})
	id, err := pAllow.Dispatch(context.Background(), req)
	if err != nil {
		t.Fatalf("Dispatch failed on allowed authz: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty command ID")
	}

	// Test Deny
	pDeny := NewPlane(newMockStore(), &mockAuthorizer{allowAll: false})
	_, err = pDeny.Dispatch(context.Background(), req)
	if err == nil {
		t.Fatal("Expected dispatch to fail due to authorization")
	}
}

func TestDispatch_Validation(t *testing.T) {
	p := NewPlane(newMockStore(), &mockAuthorizer{allowAll: true})
	
	req := CommandRequest{
		Type:     TypeLock,
		IssuedBy: "admin",
		// DeviceID eksik
	}
	
	_, err := p.Dispatch(context.Background(), req)
	if err == nil {
		t.Fatal("Expected validation to fail due to missing DeviceID")
	}
}

func TestHandleCommandResult(t *testing.T) {
	store := newMockStore()
	p := NewPlane(store, &mockAuthorizer{})
	
	err := p.HandleCommandResult(context.Background(), "dev1", "cmd-123", true, "locked")
	if err != nil {
		t.Fatalf("HandleCommandResult failed: %v", err)
	}
}
