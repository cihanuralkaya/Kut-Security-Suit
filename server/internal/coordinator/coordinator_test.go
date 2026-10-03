package coordinator

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/controlplane"
	"kut.corp/suite/server/internal/telemetryplane"
)

type mockControlStore struct{}

func (m *mockControlStore) AuthenticateAdmin(ctx context.Context, email, password string) (controlplane.AdminUser, error) {
	return controlplane.AdminUser{}, nil
}

type mockCommandStore struct{}

func (m *mockCommandStore) EnqueueCommand(ctx context.Context, deviceID string, cmdType commandplane.CommandType, issuedBy string, params map[string]any) (string, error) {
	return "cmd-1", nil
}

func (m *mockCommandStore) GetPendingCommands(ctx context.Context, deviceID string) ([]commandplane.CommandRecord, error) {
	return nil, nil
}

func (m *mockCommandStore) AckCommand(ctx context.Context, commandID string, status commandplane.CommandState, detail string) error {
	return nil
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
	cmd := commandplane.NewPlane(&mockCommandStore{}, &mockCommandAuthz{})
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
