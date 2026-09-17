package script

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"kut.corp/suite/scriptwire"
)

// Result, sınırlı yürütmenin sonucudur.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// interpreterSpec, bir yorumlayıcının gövde-bayrağını ve GÜVENİLİR MUTLAK YOL
// adaylarını tutar. Yürütülebilir YALNIZ bu adaylardan çözülür; hiçbir zaman
// PATH üzerinden aranmaz — böylece PATH hijacking (saldırganın PATH'ine daha
// önce yerleştirdiği sahte powershell.exe/sh) yürütmeyi ele geçiremez.
type interpreterSpec struct {
	flag       string
	candidates []string
}

// winRoot, %SystemRoot%'u döner (yoksa güvenli varsayılan C:\Windows).
func winRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// progFiles, %ProgramFiles%'ı döner (yoksa güvenli varsayılan).
func progFiles() string {
	if p := os.Getenv("ProgramFiles"); p != "" {
		return p
	}
	return `C:\Program Files`
}

// interpreterSpecs, OS'e göre bilinen yorumlayıcıların mutlak-yol adaylarını döner.
// Adaylar yalnızca sistem/güvenilir kurulum dizinlerini kapsar.
func interpreterSpecs(name string) (interpreterSpec, bool) {
	if runtime.GOOS == "windows" {
		root := winRoot()
		switch name {
		case "powershell":
			return interpreterSpec{"-NoProfile -NonInteractive -Command", []string{
				root + `\System32\WindowsPowerShell\v1.0\powershell.exe`,
			}}, true
		case "cmd":
			cands := []string{root + `\System32\cmd.exe`}
			if c := os.Getenv("ComSpec"); filepath.IsAbs(c) {
				cands = append([]string{c}, cands...)
			}
			return interpreterSpec{"/c", cands}, true
		case "bash":
			return interpreterSpec{"-c", []string{
				root + `\System32\bash.exe`,       // WSL
				progFiles() + `\Git\bin\bash.exe`, // Git for Windows
			}}, true
		case "node":
			return interpreterSpec{"-e", []string{progFiles() + `\nodejs\node.exe`}}, true
		default:
			return interpreterSpec{}, false
		}
	}
	switch name {
	case "sh":
		return interpreterSpec{"-c", []string{"/bin/sh", "/usr/bin/sh"}}, true
	case "bash":
		return interpreterSpec{"-c", []string{"/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"}}, true
	case "node":
		return interpreterSpec{"-e", []string{"/usr/bin/node", "/usr/local/bin/node", "/opt/homebrew/bin/node"}}, true
	case "powershell":
		return interpreterSpec{"-NoProfile -NonInteractive -Command", []string{
			"/usr/bin/pwsh", "/usr/local/bin/pwsh", "/opt/microsoft/powershell/7/pwsh",
		}}, true
	default:
		return interpreterSpec{}, false
	}
}

// resolveInterpreter, yorumlayıcı adını güvenilir bir MUTLAK yola çözer. Adaylardan
// hiçbiri (düzenli dosya olarak) yoksa çözülemez döner — fail-closed, PATH'e düşmez.
func resolveInterpreter(name string) (exe, flag string, ok bool) {
	spec, known := interpreterSpecs(name)
	if !known {
		return "", "", false
	}
	for _, c := range spec.candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, spec.flag, true
		}
	}
	return "", "", false
}

// trustedPath, child sürecin PATH'ini yalnız sistem dizinlerine sabitler. Miras
// alınan (olası hijack'lenmiş) PATH geçirilmez; böylece scriptin başlattığı torun
// süreçler de güvenilir konumlardan çözülür.
func trustedPath() string {
	if runtime.GOOS == "windows" {
		root := winRoot()
		return root + `\System32;` + root
	}
	return "/usr/bin:/bin"
}

// minimalEnv, çalıştırma için kısıtlı bir ortam değişkeni kümesi döner (tam
// ortamı miras almaz). PATH, miras yerine güvenilir sistem yoluna SABİTLENİR.
func minimalEnv() []string {
	env := []string{"PATH=" + trustedPath()}
	if runtime.GOOS == "windows" {
		for _, k := range []string{"SystemRoot", "ComSpec", "PATHEXT", "TEMP", "TMP", "windir"} {
			if v, ok := os.LookupEnv(k); ok {
				env = append(env, k+"="+v)
			}
		}
	}
	return env
}

// cappedBuffer, en fazla max bayt biriktirir; fazlasını sessizce atar (çıktı
// bombalarına karşı).
type cappedBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil // her zaman "yazıldı" de ki süreç bloklanmasın
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

// Run, DOĞRULANMIŞ bir scripti sınırlı biçimde çalıştırır: timeout, çıktı
// sınırı (her akış için maxOutput), minimal env, stdin kapalı. Çağıran, Run'dan
// ÖNCE imzayı doğrulamış olmalıdır (bkz. Verifier).
func Run(ctx context.Context, s scriptwire.Script, timeout time.Duration, maxOutput int) (Result, error) {
	exe, flag, ok := resolveInterpreter(s.Interpreter)
	if !ok {
		return Result{}, errors.New("script: yorumlayıcı desteklenmiyor veya güvenilir mutlak yolda bulunamadı: " + s.Interpreter)
	}
	if maxOutput <= 0 {
		maxOutput = 1 << 20 // 1 MiB
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{flag, s.Body}, s.Args...)
	cmd := exec.CommandContext(runCtx, exe, args...)
	cmd.Env = minimalEnv()
	cmd.Stdin = nil
	// SANDBOX: OS'e özel ayrıcalık düşürme + süreç izolasyonu. Windows'ta kısıtlanmış
	// belirteç (ajan ayrıcalıkları düşürülür); Unix'te süreç-grubu + opsiyonel uid
	// düşürme. Düşürme istenir ama kurulamazsa fail-closed (script çalışmaz).
	cleanup, err := configureSandbox(cmd)
	if err != nil {
		return Result{}, fmt.Errorf("script: sandbox yapılandırılamadı: %w", err)
	}
	defer cleanup()
	// WaitDelay, timeout sonrası Run'ın G/Ç için sonsuz beklemesini sınırlar. Unix'te
	// context iptali TÜM süreç grubunu öldürür (bkz. sandbox_unix.go cmd.Cancel).
	cmd.WaitDelay = 3 * time.Second
	outBuf := &cappedBuffer{max: maxOutput}
	errBuf := &cappedBuffer{max: maxOutput}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err = cmd.Run()
	res := Result{Stdout: outBuf.String(), Stderr: errBuf.String()}
	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // script hata kodu döndürdü; yürütme başarılı
		}
		return res, err // yürütme başlatılamadı
	}
	res.ExitCode = 0
	return res, nil
}
