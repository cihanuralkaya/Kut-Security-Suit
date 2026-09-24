package response

import (
	"context"
	"strings"
	"testing"
)

// TestNewGuardedSingleDeviceAllows, üretim varsayılanı NewGuarded'ın (gerçek
// secgateway; blast-radius + rate-limit) tek-cihaz otomatik karantinaya İZİN
// verdiğini ve komut/durum/denetim yan-etkilerini ürettiğini doğrular.
func TestNewGuardedSingleDeviceAllows(t *testing.T) {
	f := newFake()
	a := NewGuarded(f, "t1")
	if err := a.AutoQuarantine(context.Background(), "dev-1", "kritik olay"); err != nil {
		t.Fatalf("tek-cihaz otomatik karantina geçmeli: %v", err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "dev-1:QUARANTINE:" {
		t.Fatalf("karantina komutu kuyruğa alınmalıydı: %v", f.cmds)
	}
	if f.status["dev-1"] != "QUARANTINE_PENDING" {
		t.Fatalf("DESIRED durum QUARANTINE_PENDING olmalıydı: %v", f.status)
	}
	if len(f.audits) != 1 || f.audits[0] != "AUTO_QUARANTINE:dev-1" {
		t.Fatalf("denetim izine yazılmalıydı: %v", f.audits)
	}
}

// TestAutoQuarantineNilAuthzTransitional, authz==nil geçiş yolunun (gate atlanır)
// karantinayı doğrudan uyguladığını doğrular.
func TestAutoQuarantineNilAuthzTransitional(t *testing.T) {
	f := newFake()
	a := New(f, nil, "")
	if err := a.AutoQuarantine(context.Background(), "dev-9", "x"); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "dev-9:QUARANTINE:" {
		t.Fatalf("nil authz'de karantina uygulanmalıydı: %v", f.cmds)
	}
}

// TestRandGrantID, randGrantID'nin "g_" önekli, benzersiz kimlikler ürettiğini
// doğrular.
func TestRandGrantID(t *testing.T) {
	a := randGrantID()
	if !strings.HasPrefix(a, "g_") || len(a) <= len("g_") {
		t.Fatalf("grant kimliği g_ önekli ve dolu olmalı: %q", a)
	}
	if b := randGrantID(); a == b {
		t.Fatalf("grant kimlikleri benzersiz olmalı: %q == %q", a, b)
	}
}
