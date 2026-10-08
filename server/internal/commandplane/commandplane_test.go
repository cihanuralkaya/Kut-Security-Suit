package commandplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// mockSink is a test double for GuardedCommandSink. It records the last signed
// envelope it received so tests can assert that Dispatch signed the command and
// routed it through the guarded sink (not a raw store mutation).
type mockSink struct {
	lastEnv    SignedCommandEnvelope
	dispatched int
}

func (m *mockSink) DispatchSigned(ctx context.Context, env SignedCommandEnvelope) (string, error) {
	m.lastEnv = env
	m.dispatched++
	return env.CommandID, nil
}

func (m *mockSink) AckResult(ctx context.Context, commandID string, status CommandState, detail string) error {
	if commandID == "" {
		return errors.New("empty command ID")
	}
	return nil
}

func (m *mockSink) GetPendingCommands(ctx context.Context, deviceID string) ([]CommandRecord, error) {
	return nil, nil
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

func newTestSigner(t *testing.T) *CommandSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return NewCommandSigner(priv, 5*time.Minute)
}

func TestLifecycle(t *testing.T) {
	p := NewPlane(&mockSink{}, &mockAuthorizer{}, newTestSigner(t))

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

	// Test Allow: command is signed and routed through the guarded sink.
	sink := &mockSink{}
	pAllow := NewPlane(sink, &mockAuthorizer{allowAll: true}, newTestSigner(t))
	id, err := pAllow.Dispatch(context.Background(), req)
	if err != nil {
		t.Fatalf("Dispatch failed on allowed authz: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty command ID")
	}
	if sink.dispatched != 1 {
		t.Fatalf("expected exactly 1 guarded dispatch, got %d", sink.dispatched)
	}
	if len(sink.lastEnv.Signature) == 0 || sink.lastEnv.Nonce == "" {
		t.Fatal("dispatched envelope must be cryptographically signed (signature+nonce)")
	}
	if sink.lastEnv.DeviceID != "dev1" || sink.lastEnv.Type != TypeLock {
		t.Fatal("signed envelope must bind the request fields")
	}

	// Test Deny: nothing is signed or dispatched.
	denySink := &mockSink{}
	pDeny := NewPlane(denySink, &mockAuthorizer{allowAll: false}, newTestSigner(t))
	if _, err = pDeny.Dispatch(context.Background(), req); err == nil {
		t.Fatal("Expected dispatch to fail due to authorization")
	}
	if denySink.dispatched != 0 {
		t.Fatal("denied command must not reach the guarded sink")
	}
}

func TestDispatch_Validation(t *testing.T) {
	p := NewPlane(&mockSink{}, &mockAuthorizer{allowAll: true}, newTestSigner(t))

	req := CommandRequest{
		Type:     TypeLock,
		IssuedBy: "admin",
		// DeviceID eksik
	}

	if _, err := p.Dispatch(context.Background(), req); err == nil {
		t.Fatal("Expected validation to fail due to missing DeviceID")
	}
}

// TestDispatch_RequiresSigner, imzalayıcı enjekte edilmemişse Dispatch'in
// fail-closed reddettiğini doğrular — imzasız komut korumalı sınıra gönderilemez.
func TestDispatch_RequiresSigner(t *testing.T) {
	sink := &mockSink{}
	p := NewPlane(sink, &mockAuthorizer{allowAll: true}, nil) // signer yok
	req := CommandRequest{DeviceID: "dev1", Type: TypeWipe, IssuedBy: "admin"}
	if _, err := p.Dispatch(context.Background(), req); err == nil {
		t.Fatal("Dispatch imzalayıcı olmadan başarısız olmalı (fail-closed)")
	}
	if sink.dispatched != 0 {
		t.Fatal("imzalayıcı yokken hiçbir komut sink'e gitmemeli")
	}
}

func TestHandleCommandResult(t *testing.T) {
	p := NewPlane(&mockSink{}, &mockAuthorizer{}, newTestSigner(t))

	err := p.HandleCommandResult(context.Background(), "dev1", "cmd-123", true, "locked")
	if err != nil {
		t.Fatalf("HandleCommandResult failed: %v", err)
	}
}
