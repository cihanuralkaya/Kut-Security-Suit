//go:build !windows

package script

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// configureSandbox, Unix'te script sürecini izole eder: kendi SÜREÇ GRUBUNDA
// başlatır (zaman aşımında yalnız doğrudan süreç değil tüm ağaç öldürülebilir) ve
// KUT_SCRIPT_UID (ops. KUT_SCRIPT_GID) ayarlıysa AYRICALIĞI DÜŞÜREREK belirtilen
// düşük-yetkili kullanıcıya iner (ajan root ise; imzalı script agent yetkisini
// devralamaz). Varsayılan davranış değişmez: uid verilmezse yalnız süreç-grubu
// izolasyonu uygulanır — bu yüzden CI/smoke etkilenmez. Dönen cleanup no-op'tur.
func configureSandbox(cmd *exec.Cmd) (func(), error) {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if uidStr := os.Getenv("KUT_SCRIPT_UID"); uidStr != "" {
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			return nil, err
		}
		gid := uid
		if g := os.Getenv("KUT_SCRIPT_GID"); g != "" {
			if gid, err = strconv.Atoi(g); err != nil {
				return nil, err
			}
		}
		attr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}
	}
	cmd.SysProcAttr = attr
	// Zaman aşımında (context iptali) TÜM süreç grubunu öldür — cmd'nin başlattığı
	// torun süreçler de sonlansın (negatif pid = süreç grubu).
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return func() {}, nil
}
