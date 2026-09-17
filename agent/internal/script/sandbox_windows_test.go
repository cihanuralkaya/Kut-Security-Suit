//go:build windows

package script

import (
	"os/exec"
	"testing"
)

// TestSandboxWindowsRestrictedToken, varsayılan olarak kısıtlanmış bir erişim
// belirtecinin (ayrıcalıkları düşürülmüş) ayarlandığını doğrular.
func TestSandboxWindowsRestrictedToken(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "echo hi")
	cleanup, err := configureSandbox(cmd)
	if err != nil {
		t.Fatalf("configureSandbox: %v", err)
	}
	defer cleanup()
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token == 0 {
		t.Fatal("varsayılan: kısıtlanmış belirteç (Token) ayarlanmalı")
	}
}

// TestSandboxWindowsFullPrivilegesOptOut, KUT_SCRIPT_FULL_PRIVILEGES=1 ile
// ayrıcalık düşürmenin devre dışı kaldığını (Token ayarlanmadığını) doğrular.
func TestSandboxWindowsFullPrivilegesOptOut(t *testing.T) {
	t.Setenv("KUT_SCRIPT_FULL_PRIVILEGES", "1")
	cmd := exec.Command("cmd", "/c", "echo hi")
	cleanup, err := configureSandbox(cmd)
	if err != nil {
		t.Fatalf("configureSandbox: %v", err)
	}
	defer cleanup()
	if cmd.SysProcAttr.Token != 0 {
		t.Fatal("opt-out: kısıtlanmış belirteç ayarlanmamalı")
	}
}
