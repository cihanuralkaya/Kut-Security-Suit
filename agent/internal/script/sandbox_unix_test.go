//go:build !windows

package script

import (
	"os/exec"
	"testing"
)

// TestSandboxUnixProcessGroup, Unix sandbox'ının süreç-grubu izolasyonu ve grup
// öldürme (cmd.Cancel) ayarladığını doğrular — zaman aşımında torun süreçler de
// sonlanır.
func TestSandboxUnixProcessGroup(t *testing.T) {
	cmd := exec.Command("/bin/true")
	cleanup, err := configureSandbox(cmd)
	if err != nil {
		t.Fatalf("configureSandbox: %v", err)
	}
	defer cleanup()
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("Setpgid ayarlanmalı (süreç-grubu izolasyonu)")
	}
	if cmd.Cancel == nil {
		t.Fatal("cmd.Cancel ayarlanmalı (grup öldürme)")
	}
}

// TestSandboxUnixUIDDrop, KUT_SCRIPT_UID/GID ayrıcalık düşürmenin SysProcAttr.
// Credential'a doğru yansıdığını doğrular (varsayılan: kimlik-bilgisi ayarlanmaz).
func TestSandboxUnixUIDDrop(t *testing.T) {
	// Varsayılan: uid verilmez → Credential nil.
	cmd := exec.Command("/bin/true")
	cleanup, err := configureSandbox(cmd)
	if err != nil {
		t.Fatalf("configureSandbox: %v", err)
	}
	cleanup()
	if cmd.SysProcAttr.Credential != nil {
		t.Fatal("uid verilmeden Credential ayarlanmamalı (varsayılan davranış korunur)")
	}

	// Opt-in: uid + gid verilir → Credential yansır.
	t.Setenv("KUT_SCRIPT_UID", "12345")
	t.Setenv("KUT_SCRIPT_GID", "6789")
	cmd2 := exec.Command("/bin/true")
	cleanup2, err := configureSandbox(cmd2)
	if err != nil {
		t.Fatalf("configureSandbox (uid): %v", err)
	}
	defer cleanup2()
	cred := cmd2.SysProcAttr.Credential
	if cred == nil || cred.Uid != 12345 || cred.Gid != 6789 {
		t.Fatalf("KUT_SCRIPT_UID/GID Credential'a yansımalı: %+v", cred)
	}
}
