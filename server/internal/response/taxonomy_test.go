package response

import (
	"testing"

	"kut.corp/suite/cmdenvelope"
	"kut.corp/suite/server/internal/scope"
)

// Otomatik karantina, kapıya sorduğu aksiyon (scope.ActionQuarantine) ile kuyruğa aldığı komut
// tipinin (TypeQuarantine) paylaşılan tablodaki scope aksiyonunun AYNI olduğunu garanti eder;
// aksi halde yetki kararı başka bir şeyi, kuyruk başka bir şeyi yürütürdü.
func TestAutoQuarantineActionMatchesCommandTable(t *testing.T) {
	spec, ok := cmdenvelope.Lookup(cmdenvelope.TypeQuarantine)
	if !ok {
		t.Fatal("QUARANTINE tabloda yok")
	}
	if spec.ScopeExempt || spec.ScopeAction != string(scope.ActionQuarantine) {
		t.Fatalf("tablo scope aksiyonu %q (exempt=%v), kapı aksiyonu %q", spec.ScopeAction, spec.ScopeExempt, scope.ActionQuarantine)
	}
	if !spec.Protected {
		t.Error("otomatik karantina tipi korumalı olmalı")
	}
}
