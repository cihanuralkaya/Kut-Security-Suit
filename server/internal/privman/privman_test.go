package privman_test

import (
	"testing"

	"kut.corp/suite/server/internal/privman"
	"kut.corp/suite/server/internal/scope"
)

// Derleme-zamanı kanıtı: constructor'lar sealed arayüzü döndürür. privman DIŞINDA bir
// tip PrivilegedMutation'ı implemente EDEMEZ (unexported sealed() metodu) — bu yüzden
// privileged mutasyon yalnız buradan doğar.
var _ privman.PrivilegedMutation = privman.NewMetadataMutation("x")

func TestClassesAndGuardedBoundary(t *testing.T) {
	cases := []struct {
		name        string
		m           privman.PrivilegedMutation
		wantClass   privman.SideEffectClass
		wantGuarded bool
		wantDestr   bool
	}{
		{"wipe", privman.NewDeviceCommand(scope.ActionWipe, "d1"), privman.ClassDeviceCommand, true, true},
		{"quarantine", privman.NewDeviceCommand(scope.ActionQuarantine, "d1"), privman.ClassDeviceCommand, true, false},
		{"set_status", privman.NewSecurityStateMutation("set_device_status", "d1"), privman.ClassSecurityStateMutation, true, false},
		{"erase", privman.NewDestructiveServerMutation("erase_device_data", "d1"), privman.ClassDestructiveServer, true, true},
		{"cert_revoke", privman.NewIdentityCredentialMutation("revoke_device_certs", "d1"), privman.ClassIdentityCredential, true, false},
		{"policy", privman.NewPolicyMutation("assign_policy", "d1"), privman.ClassPolicyMutation, true, false},
		{"tags", privman.NewMetadataMutation("set_device_tags", "d1"), privman.ClassMetadataOnly, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.m.Class() != c.wantClass {
				t.Errorf("Class=%s want %s", c.m.Class(), c.wantClass)
			}
			if c.m.Class().RequiresGuardedBoundary() != c.wantGuarded {
				t.Errorf("RequiresGuardedBoundary=%v want %v", c.m.Class().RequiresGuardedBoundary(), c.wantGuarded)
			}
			if c.m.Destructive() != c.wantDestr {
				t.Errorf("Destructive=%v want %v", c.m.Destructive(), c.wantDestr)
			}
		})
	}
}

// TestTargetsDefensiveCopy, dönen Targets slice'ının iç durumu değiştiremeyeceğini
// doğrular (paylaşımlı-mutable state sızıntısı yok).
func TestTargetsDefensiveCopy(t *testing.T) {
	m := privman.NewDeviceCommand(scope.ActionLock, "d1", "d2")
	got := m.Targets()
	got[0] = "HACKED"
	if m.Targets()[0] != "d1" {
		t.Fatalf("Targets iç durumu dışarıdan değiştirilebildi: %v", m.Targets())
	}
}

// TestOnlyMetadataBypasses, yalnız METADATA_ONLY'nin guarded sınırı atlayabildiğini
// doğrular (audit §1).
func TestOnlyMetadataBypasses(t *testing.T) {
	for _, c := range []privman.SideEffectClass{
		privman.ClassDeviceCommand, privman.ClassSecurityStateMutation, privman.ClassDestructiveServer,
		privman.ClassIdentityCredential, privman.ClassPolicyMutation,
	} {
		if !c.RequiresGuardedBoundary() {
			t.Errorf("%s guarded sınır gerektirmeli", c)
		}
	}
	if privman.ClassMetadataOnly.RequiresGuardedBoundary() {
		t.Error("METADATA_ONLY guarded sınır gerektirmemeli")
	}
}
