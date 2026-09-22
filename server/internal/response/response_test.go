package response

import (
	"context"
	"errors"
	"testing"

	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/seccontract"
)

// stubAuthz, sabit bir kararla Authorizer'ı uygular (gate testleri için).
type stubAuthz struct{ result seccontract.DecisionResult }

func (s stubAuthz) Authorize(seccontract.ActionRequest) seccontract.AuthorizationDecision {
	if s.result == seccontract.ResultAllow {
		return seccontract.AuthorizationDecision{Result: seccontract.ResultAllow}
	}
	return seccontract.AuthorizationDecision{Result: s.result, ReasonCodes: []seccontract.ReasonCode{seccontract.ReasonBlastRadiusExceeded}}
}

// fakeStore, response.Store'u kaydederek uygular.
type fakeStore struct {
	cmds    []string // "deviceID:cmdType:issuedBy"
	status  map[string]string
	audits  []string // "action:targetID"
	failCmd bool
}

func newFake() *fakeStore { return &fakeStore{status: map[string]string{}} }

func (f *fakeStore) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	if f.failCmd {
		return errors.New("kuyruk hatası")
	}
	f.cmds = append(f.cmds, deviceID+":"+cmdType+":"+issuedBy)
	return nil
}
func (f *fakeStore) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	f.status[deviceID] = status
	return nil
}
func (f *fakeStore) WriteAudit(_ context.Context, adminID, action, _, targetID string) error {
	f.audits = append(f.audits, action+":"+targetID)
	return nil
}

func TestShouldTrigger(t *testing.T) {
	if _, ok := ShouldTrigger([]model.Event{{Severity: "INFO"}, {Severity: "HIGH"}}); ok {
		t.Fatal("KRİTİK olmadan tetiklenmemeliydi")
	}
	reason, ok := ShouldTrigger([]model.Event{{Severity: "LOW"}, {Severity: "CRITICAL", Message: "watchdog kurcalama"}})
	if !ok || reason != "watchdog kurcalama" {
		t.Fatalf("kritik olayda tetiklenmeliydi (reason=%q ok=%v)", reason, ok)
	}
	if _, ok := ShouldTrigger(nil); ok {
		t.Fatal("boş grup tetiklememeli")
	}
}

func TestAutoQuarantineEnqueuesAndAudits(t *testing.T) {
	f := newFake()
	a := New(f, nil, "")
	if err := a.AutoQuarantine(context.Background(), "dev-1", "kritik olay"); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "dev-1:QUARANTINE:" {
		t.Fatalf("karantina komutu kuyruğa alınmalıydı: %v", f.cmds)
	}
	if f.status["dev-1"] != "QUARANTINED" {
		t.Fatalf("durum QUARANTINED olmalıydı: %v", f.status)
	}
	if len(f.audits) != 1 || f.audits[0] != "AUTO_QUARANTINE:dev-1" {
		t.Fatalf("denetim izine yazılmalıydı: %v", f.audits)
	}
}

func TestAutoQuarantineReturnsErrOnEnqueueFailure(t *testing.T) {
	f := newFake()
	f.failCmd = true
	if err := New(f, nil, "").AutoQuarantine(context.Background(), "dev-1", "x"); err == nil {
		t.Fatal("komut kuyruğa alınamazsa hata dönmeliydi")
	}
}

// TestAutoQuarantineDeniedByGateway, gateway DENY verdiğinde HİÇBİR yan-etki
// üretilmediğini (komut/durum/denetim) ve hata döndüğünü doğrular (fail-closed, G-01).
func TestAutoQuarantineDeniedByGateway(t *testing.T) {
	f := newFake()
	a := New(f, stubAuthz{result: seccontract.ResultDeny}, "t1")
	if err := a.AutoQuarantine(context.Background(), "dev-1", "kritik"); err == nil {
		t.Fatal("gateway DENY iken hata dönmeliydi")
	}
	if len(f.cmds) != 0 || len(f.status) != 0 || len(f.audits) != 0 {
		t.Fatalf("DENY sonrası hiçbir yan-etki olmamalıydı: cmds=%v status=%v audits=%v", f.cmds, f.status, f.audits)
	}
}

// TestAutoQuarantineAllowedByGateway, gateway ALLOW verdiğinde karantinanın
// gerçekleştiğini doğrular (davranış-koruyan).
func TestAutoQuarantineAllowedByGateway(t *testing.T) {
	f := newFake()
	a := New(f, stubAuthz{result: seccontract.ResultAllow}, "t1")
	if err := a.AutoQuarantine(context.Background(), "dev-1", "kritik"); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.status["dev-1"] != "QUARANTINED" {
		t.Fatalf("ALLOW sonrası karantina uygulanmalıydı: cmds=%v status=%v", f.cmds, f.status)
	}
}
