package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"kut.corp/suite/server/internal/commandplane"
)

type allowCmdAuthz struct{ calls int }

func (a *allowCmdAuthz) Authorize(ctx context.Context, req commandplane.ActionRequest) (commandplane.AuthorizationDecision, error) {
	a.calls++
	return commandplane.AuthorizationDecision{Allowed: true}, nil
}

type denyCmdAuthz struct{}

func (denyCmdAuthz) Authorize(ctx context.Context, req commandplane.ActionRequest) (commandplane.AuthorizationDecision, error) {
	return commandplane.AuthorizationDecision{Allowed: false, Reason: "yetki yok"}, nil
}

func newTestPlane(t *testing.T, store commandEnqueuer, authz commandplane.Authorizer) *commandplane.Plane {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return commandplane.NewPlane(NewCommandSink(store), authz, commandplane.NewCommandSigner(priv, time.Minute))
}

// TestCommandPlaneRouting_Allowed, komut düzlemi bağlıyken bir komutun düzlemden
// (authz+imza) geçip kanıtlanmış enqueue sınırına (store) ulaştığını doğrular.
func TestCommandPlaneRouting_Allowed(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	authz := &allowCmdAuthz{}
	svc.SetCommandPlane(newTestPlane(t, store, authz))

	if err := svc.QuarantineDevice(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatalf("beklenen başarı, hata: %v", err)
	}
	if authz.calls != 1 {
		t.Errorf("komut düzlemi authz'si tam 1 kez çağrılmalıydı, oldu %d", authz.calls)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "QUARANTINE" || store.commands[0].deviceID != "dev-1" {
		t.Fatalf("komut düzlem üzerinden kuyruğa ulaşmalıydı: %+v", store.commands)
	}
}

// TestCommandPlaneRouting_Denied, komut düzleminin authz'si reddederse komutun
// kuyruğa HİÇ ulaşmadığını (fail-closed) doğrular.
func TestCommandPlaneRouting_Denied(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	svc.SetCommandPlane(newTestPlane(t, store, denyCmdAuthz{}))

	if err := svc.QuarantineDevice(context.Background(), "op1", "dev-1"); err == nil {
		t.Fatal("komut düzlemi reddi dispatch'i başarısız yapmalıydı")
	}
	if len(store.commands) != 0 {
		t.Errorf("reddedilen komut kuyruğa ulaşmamalıydı: %+v", store.commands)
	}
}

// TestCommandPlaneRouting_NonRoutableBypasses, düzlem-uyumlu olmayan bir komutun
// (COLLECT_DIAGNOSTICS) düzlem bağlıyken bile doğrudan depo yolundan geçtiğini
// doğrular (davranış korunur, düzlem Validate'i tetiklenmez).
func TestCommandPlaneRouting_NonRoutableBypasses(t *testing.T) {
	store := newMemStore()
	store.roles["op1"] = RoleOperator
	svc, _ := newService(t, store)

	authz := &allowCmdAuthz{}
	svc.SetCommandPlane(newTestPlane(t, store, authz))

	if err := svc.CollectDiagnostics(context.Background(), "op1", "dev-1"); err != nil {
		t.Fatalf("beklenen başarı, hata: %v", err)
	}
	if authz.calls != 0 {
		t.Errorf("düzlem-dışı komut authz'yi çağırmamalıydı, oldu %d", authz.calls)
	}
	if len(store.commands) != 1 || store.commands[0].cmdType != "COLLECT_DIAGNOSTICS" {
		t.Fatalf("COLLECT_DIAGNOSTICS doğrudan depo yolundan geçmeliydi: %+v", store.commands)
	}
}
