package admin

import (
	"context"
	"errors"
	"testing"

	"kut.corp/suite/server/internal/commandplane"
)

type fakeEnqueuer struct {
	deviceID, cmdType, issuedBy string
	params                      map[string]string
	err                         error
	calls                       int
}

func (f *fakeEnqueuer) EnqueueCommandParams(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error {
	f.calls++
	f.deviceID, f.cmdType, f.issuedBy, f.params = deviceID, cmdType, issuedBy, params
	return f.err
}

func TestCommandSink_DispatchSignedDelegates(t *testing.T) {
	fe := &fakeEnqueuer{}
	sink := NewCommandSink(fe)

	env := commandplane.SignedCommandEnvelope{
		CommandID: "cmd-1",
		DeviceID:  "dev-1",
		Type:      commandplane.TypeCollectFile,
		IssuedBy:  "admin-1",
		Params:    map[string]any{"path": "C:/evidence.bin", "retries": 3},
	}
	id, err := sink.DispatchSigned(context.Background(), env)
	if err != nil {
		t.Fatalf("beklenen başarı, hata: %v", err)
	}
	if id != "cmd-1" {
		t.Errorf("komut kimliği cmd-1 bekleniyordu, alındı %q", id)
	}
	if fe.calls != 1 || fe.deviceID != "dev-1" || fe.cmdType != "COLLECT_FILE" || fe.issuedBy != "admin-1" {
		t.Errorf("enqueue argümanları yanlış: %+v", fe)
	}
	if fe.params["path"] != "C:/evidence.bin" || fe.params["retries"] != "3" {
		t.Errorf("parametre dönüşümü yanlış: %v", fe.params)
	}
}

func TestCommandSink_DispatchSignedPropagatesStoreError(t *testing.T) {
	fe := &fakeEnqueuer{err: errors.New("db down")}
	sink := NewCommandSink(fe)
	if _, err := sink.DispatchSigned(context.Background(), commandplane.SignedCommandEnvelope{
		CommandID: "c", DeviceID: "d", Type: commandplane.TypeWipe, IssuedBy: "a",
	}); err == nil {
		t.Error("depo hatası yukarı taşınmalıydı")
	}
}

func TestCommandSink_NilStoreFailsClosed(t *testing.T) {
	sink := NewCommandSink(nil)
	if _, err := sink.DispatchSigned(context.Background(), commandplane.SignedCommandEnvelope{
		CommandID: "c", DeviceID: "d", Type: commandplane.TypeWipe, IssuedBy: "a",
	}); err == nil {
		t.Error("depo yokken dispatch reddedilmeliydi")
	}
}

func TestCommandSink_ReadPathMethodsUnsupported(t *testing.T) {
	sink := NewCommandSink(&fakeEnqueuer{})
	if err := sink.AckResult(context.Background(), "c", commandplane.StateSucceeded, ""); err == nil {
		t.Error("AckResult komut düzlemi üzerinden desteklenmemeli")
	}
	if _, err := sink.GetPendingCommands(context.Background(), "dev-1"); err == nil {
		t.Error("GetPendingCommands komut düzlemi üzerinden desteklenmemeli")
	}
}
