//go:build enterprise

package bus

import (
	"testing"
	"time"

	"kut.corp/suite/server/internal/eventbus"
)

func drainJS(t *testing.T, l *jetStreamLog) []eventbus.Notice {
	t.Helper()
	var got []eventbus.Notice
	if err := l.Replay(func(n eventbus.Notice) error {
		got = append(got, n)
		return nil
	}); err != nil {
		t.Fatalf("Replay hata: %v", err)
	}
	return got
}

// Gömülü JetStream: append edilen bildirimler en eskiden en yeniye, alanları korunarak oynatılmalı.
func TestJetStreamAppendReplay(t *testing.T) {
	l, err := NewJetStreamLog("", t.TempDir())
	if err != nil {
		t.Fatalf("NewJetStreamLog: %v", err)
	}
	defer l.Close()

	in := []eventbus.Notice{
		{Type: "event", DeviceID: "d1", Severity: "high", Message: "m1", At: time.Unix(1, 0).UTC()},
		{Type: "device", DeviceID: "d2", At: time.Unix(2, 0).UTC()},
		{Type: "event", DeviceID: "d3", Severity: "low", Message: "m3", At: time.Unix(3, 0).UTC()},
	}
	for _, n := range in {
		if err := l.Append(n); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	got := drainJS(t, l)
	if len(got) != len(in) {
		t.Fatalf("oynatma sayısı=%d, beklenen %d", len(got), len(in))
	}
	for i := range in {
		if got[i].DeviceID != in[i].DeviceID || got[i].Type != in[i].Type ||
			got[i].Severity != in[i].Severity || got[i].Message != in[i].Message ||
			!got[i].At.Equal(in[i].At) {
			t.Fatalf("kayıt[%d] sapma: got %+v, want %+v", i, got[i], in[i])
		}
	}
}

// Kapatıp aynı StoreDir ile yeniden açınca kayıtlar kalıcı olmalı (dosya-depolamalı stream kurtarma).
func TestJetStreamReopenRecovers(t *testing.T) {
	dir := t.TempDir()
	l, err := NewJetStreamLog("", dir)
	if err != nil {
		t.Fatalf("NewJetStreamLog: %v", err)
	}
	if err := l.Append(eventbus.Notice{Type: "event", DeviceID: "keep", At: time.Unix(5, 0).UTC()}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	l2, err := NewJetStreamLog("", dir) // aynı store → gömülü sunucu stream'i kurtarmalı
	if err != nil {
		t.Fatalf("yeniden aç: %v", err)
	}
	defer l2.Close()
	got := drainJS(t, l2)
	if len(got) != 1 || got[0].DeviceID != "keep" {
		t.Fatalf("yeniden açılışta kurtarma başarısız: %+v", got)
	}
}

// Register, KUT_BUS_BACKEND=jetstream ile JetStream backend'ini kullanmalı: hem canlı dağıtım
// hem dayanıklı yazma.
func TestRegisterJetStreamBackend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KUT_BUS_BACKEND", "jetstream")
	t.Setenv("KUT_NATS_URL", "") // gömülü
	t.Setenv("KUT_NATS_STORE", dir)

	b := eventbus.New()
	ch, cancel := b.Subscribe()
	defer cancel()

	if err := Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}

	b.PublishEvent("dev-x", "critical", "boom")

	select {
	case n := <-ch:
		if n.DeviceID != "dev-x" || n.Severity != "critical" {
			t.Fatalf("beklenmeyen bildirim: %+v", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("abone bildirimi almadı (canlı dağıtım kırık)")
	}

	// Aktif backend'i kapat, sonra aynı store'u bağımsızca açıp dayanıklı kaydı doğrula.
	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l, err := NewJetStreamLog("", dir)
	if err != nil {
		t.Fatalf("doğrulama açma: %v", err)
	}
	defer l.Close()
	got := drainJS(t, l)
	if len(got) != 1 || got[0].DeviceID != "dev-x" || got[0].Message != "boom" {
		t.Fatalf("dayanıklı kayıt eksik/yanlış: %+v", got)
	}
}
