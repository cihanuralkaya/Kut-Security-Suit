//go:build windows

package script

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DISABLE_MAX_PRIVILEGE: CreateRestrictedToken bayrağı — yeni belirteçteki TÜM
// ayrıcalıkları (SeChangeNotify hariç) kaldırır.
const disableMaxPrivilege = 0x1

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
)

// createRestrictedToken, mevcut belirteçten ayrıcalıkları düşürülmüş bir birincil
// belirteç üretir. x/sys/windows bunu sarmalamadığından advapi32 doğrudan çağrılır.
// Kısıtlı belirteç ÇAĞIRANIN kendi belirtecinden türetildiği için özel ayrıcalık
// gerekmeden CreateProcessAsUser ile başlatılabilir (belgelenmiş istisna).
func createRestrictedToken(existing windows.Token) (windows.Token, error) {
	var newTok windows.Token
	r1, _, e1 := procCreateRestrictedToken.Call(
		uintptr(existing),            // ExistingTokenHandle
		uintptr(disableMaxPrivilege), // Flags
		0, 0,                         // DisableSidCount, SidsToDisable
		0, 0, // DeletePrivilegeCount, PrivilegesToDelete
		0, 0, // RestrictedSidCount, SidsToRestrict
		uintptr(unsafe.Pointer(&newTok)),
	)
	if r1 == 0 {
		return 0, e1
	}
	return newTok, nil
}

// configureSandbox, Windows'ta script sürecini KISITLANMIŞ bir erişim belirteci ile
// başlatır: ajan belirtecindeki TÜM ayrıcalıklar düşürülür (DISABLE_MAX_PRIVILEGE) —
// imzalı bir script çalışsa bile ajan/SYSTEM ayrıcalıklarını (ör. SeDebugPrivilege,
// SeTakeOwnership) DEVRALAMAZ. Süreç ayrıca kendi süreç grubunda başlatılır.
//
// Varsayılan AÇIK (güvenli). Operatör riski açıkça kabul ederse
// KUT_SCRIPT_FULL_PRIVILEGES=1 ile tam-ayrıcalıklı çalıştırmaya döner. Belirteç
// oluşturulamaz VE düşürme isteniyorsa fail-closed. Dönen cleanup, kısıtlanmış
// belirteç tanıtıcısını serbest bırakır.
func configureSandbox(cmd *exec.Cmd) (func(), error) {
	attr := &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	cmd.SysProcAttr = attr
	noop := func() {}

	if os.Getenv("KUT_SCRIPT_FULL_PRIVILEGES") == "1" {
		return noop, nil // ayrıcalık düşürme açıkça kapatıldı (riskli)
	}

	var procTok windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
		&procTok,
	)
	if err != nil {
		return nil, err
	}
	defer procTok.Close()

	restricted, err := createRestrictedToken(procTok)
	if err != nil {
		return nil, err
	}
	attr.Token = syscall.Token(restricted)
	return func() { _ = restricted.Close() }, nil
}
