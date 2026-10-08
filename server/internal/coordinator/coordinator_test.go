package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/controlplane"
	"kut.corp/suite/server/internal/telemetryplane"
)

type mockControlStore struct{}

func (m *mockControlStore) AuthenticateAdmin(ctx context.Context, email, password string) (controlplane.AdminUser, error) {
	return controlplane.AdminUser{}, nil
}

// mockCommandSink implements commandplane.GuardedCommandSink (the guarded boundary
// that would, in production, enqueue through privman/GuardedExecutor).
type mockCommandSink struct{}

func (m *mockCommandSink) DispatchSigned(ctx context.Context, env commandplane.SignedCommandEnvelope) (string, error) {
	return env.CommandID, nil
}

func (m *mockCommandSink) AckResult(ctx context.Context, commandID string, status commandplane.CommandState, detail string) error {
	return nil
}

func (m *mockCommandSink) GetPendingCommands(ctx context.Context, deviceID string) ([]commandplane.CommandRecord, error) {
	return nil, nil
}

type mockCommandAuthz struct{}

func (m *mockCommandAuthz) Authorize(ctx context.Context, req commandplane.ActionRequest) (commandplane.AuthorizationDecision, error) {
	return commandplane.AuthorizationDecision{Allowed: true}, nil
}

type mockDetector struct{}

func (m *mockDetector) Evaluate(ctx context.Context, evt any) (bool, error) {
	return false, nil
}

func TestFabricCoordinator_Lifecycle(t *testing.T) {
	control := controlplane.New(nil, nil, &mockControlStore{})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	signer := commandplane.NewCommandSigner(priv, 5*time.Minute)
	cmd := commandplane.NewPlane(&mockCommandSink{}, &mockCommandAuthz{}, signer)
	telem := telemetryplane.New(nil, nil, nil)

	coord := New(control, telem, cmd)
	ctx := context.Background()

	if coord.IsRunning() {
		t.Fatal("coordinator should not be running before start")
	}

	if err := coord.Start(ctx); err != nil {
		t.Fatalf("unexpected error starting coordinator: %v", err)
	}

	if !coord.IsRunning() {
		t.Fatal("coordinator should be running after start")
	}

	// Double start should fail
	if err := coord.Start(ctx); err == nil {
		t.Fatal("expected error starting already running coordinator")
	}

	if err := coord.Stop(); err != nil {
		t.Fatalf("unexpected error stopping coordinator: %v", err)
	}

	if coord.IsRunning() {
		t.Fatal("coordinator should not be running after stop")
	}

	// Double stop should fail
	if err := coord.Stop(); err == nil {
		t.Fatal("expected error stopping already stopped coordinator")
	}
}
