package logx

import (
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// saveGlobals, testin değiştirdiği süreç-genelindeki log/slog durumunu kaydeder ve
// geri yükleyen bir fonksiyon döner (t.Cleanup ile kullanılır).
func saveGlobals() func() {
	oldSlog := slog.Default()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	oldOut := log.Writer()
	oldStderr := os.Stderr
	return func() {
		slog.SetDefault(oldSlog)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
		log.SetOutput(oldOut)
		os.Stderr = oldStderr
	}
}

func TestSetupJSON(t *testing.T) {
	t.Cleanup(saveGlobals())

	// os.Stderr'i bir pipe'a yönlendir; Setup çağrı anında os.Stderr'i yakalar.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	Setup("json", "yok-sayılır")

	// JSON modunda std log bayrak/prefix temizlenir.
	if log.Flags() != 0 {
		t.Errorf("JSON modunda bayraklar 0 olmalı, %d", log.Flags())
	}
	if log.Prefix() != "" {
		t.Errorf("JSON modunda prefix boş olmalı, %q", log.Prefix())
	}
	// slog default JSON logger'a ayarlanmalı (çağrı hatasız info üretebilmeli).
	slog.Default().Info("slog-default-testi")

	// Standart log çıktısı slog üzerinden JSON'a yönlendirilmeli.
	log.Print("[c2] merhaba")
	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Son satırı (log.Print çıktısını) içeren bir JSON satırı bulunmalı.
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("std log satırı JSON olmalı: %v (%q)", err, line)
		}
		if m["msg"] == "[c2] merhaba" {
			found = true
		}
	}
	if !found {
		t.Fatalf("std log satırı JSON'a yönlendirilmeliydi, çıktı: %q", string(out))
	}
}

func TestSetupText(t *testing.T) {
	t.Cleanup(saveGlobals())

	Setup("text", "kutd: ")

	if log.Prefix() != "kutd: " {
		t.Errorf("text modunda prefix ayarlanmalı, %q", log.Prefix())
	}
	wantFlags := log.LstdFlags | log.Lmsgprefix
	if log.Flags() != wantFlags {
		t.Errorf("text modunda bayraklar %d olmalı, %d", wantFlags, log.Flags())
	}
}

// TestSetupTextIsDefaultOutput, text modunun std log yazıcısını slog'a
// SARMADIĞINI (yeniden yönlendirmediğini) doğrular.
func TestSetupTextKeepsWriter(t *testing.T) {
	t.Cleanup(saveGlobals())

	log.SetOutput(io.Discard)
	Setup("text", "x: ")
	if log.Writer() != io.Writer(io.Discard) {
		t.Fatal("text modu std log yazıcısını değiştirmemeli")
	}
}
