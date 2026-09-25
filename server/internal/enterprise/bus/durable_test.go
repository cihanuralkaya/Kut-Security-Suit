//go:build enterprise

package bus

import (
	"path/filepath"
	"testing"
	"time"

	"kut.corp/suite/server/internal/eventbus"
)

func drain(t *testing.T, l *fileLog) []eventbus.Notice {
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

// Append edilen bildirimler en eskiden en yeniye, alanları korunarak oynatılmalı.
func TestFileLogAppendReplay(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bus.log")
	l, err := NewFileLog(p)
	if err != nil {
		t.Fatalf("NewFileLog: %v", err)
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
	got := drain(t, l)
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
	if l.AppendErrors() != 0 {
		t.Fatalf("beklenmeyen append hatası: %d", l.AppendErrors())
	}
}

// Kapatıp yeniden açtıktan sonra kayıtlar kalıcı olmalı (dayanıklılık kanıtı).
func TestFileLogReopenRecovers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bus.log")
	l, err := NewFileLog(p)
	if err != nil {
		t.Fatalf("NewFileLog: %v", err)
	}
	if err := l.Append(eventbus.Notice{Type: "event", DeviceID: "keep", At: time.Unix(5, 0).UTC()}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	l2, err := NewFileLog(p) // aynı yolu yeniden aç
	if err != nil {
		t.Fatalf("yeniden aç: %v", err)
	}
	defer l2.Close()
	got := drain(t, l2)
	if len(got) != 1 || got[0].DeviceID != "keep" {
		t.Fatalf("yeniden açılışta kurtarma başarısız: %+v", got)
	}
	// Yeni append eskisine EKLENMELİ (üzerine yazmamalı).
	if err := l2.Append(eventbus.Notice{Type: "device", DeviceID: "more", At: time.Unix(6, 0).UTC()}); err != nil {
		t.Fatalf("Append2: %v", err)
	}
	if got := drain(t, l2); len(got) != 2 {
		t.Fatalf("append eskiyi korumadı: %d kayıt", len(got))
	}
}

// Retention penceresi yeterince genişse rotasyon olsa bile HİÇBİR kayıt kaybolmamalı
// (tüm nesiller + aktif dosya en eski→en yeni sırayla oynatılır).
func TestFileLogRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bus.log")
	l, err := newFileLog(p, 200, 50) // küçük eşik → sık rotasyon; geniş nesil → düşme yok
	if err != nil {
		t.Fatalf("newFileLog: %v", err)
	}
	defer l.Close()

	const n = 25
	for i := 0; i < n; i++ {
		if err := l.Append(eventbus.Notice{Type: "event", DeviceID: "d", Message: "payload-to-grow", At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	got := drain(t, l)
	if len(got) != n {
		t.Fatalf("geniş pencerede kayıt kaybı: got %d, want %d", len(got), n)
	}
	for i := 0; i < n; i++ {
		if !got[i].At.Equal(time.Unix(int64(i), 0).UTC()) {
			t.Fatalf("rotasyon sonrası sıra bozuk: kayıt[%d].At=%v", i, got[i].At)
		}
	}
}

// Retention penceresi aşılınca YALNIZ en eski nesil düşmeli: kalanlar en-yeniye biten,
// sırası korunmuş bitişik bir alt-küme olmalı (en yeni kayıt her zaman durur).
func TestFileLogRotationDropsOldest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bus.log")
	l, err := newFileLog(p, 200, 2) // dar pencere (aktif + .1 + .2) → en eskiler düşer
	if err != nil {
		t.Fatalf("newFileLog: %v", err)
	}
	defer l.Close()

	const n = 40
	for i := 0; i < n; i++ {
		if err := l.Append(eventbus.Notice{Type: "event", DeviceID: "d", Message: "payload-to-grow", At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	got := drain(t, l)
	if len(got) == 0 || len(got) >= n {
		t.Fatalf("retention beklenen düşmeyi yapmadı: got %d (n=%d)", len(got), n)
	}
	// En yeni kayıt korunmalı; en eski düşmüş olmalı.
	if !got[len(got)-1].At.Equal(time.Unix(int64(n-1), 0).UTC()) {
		t.Fatalf("en yeni kayıt kayıp: son=%v", got[len(got)-1].At)
	}
	if got[0].At.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("en eski kayıt düşmeliydi ama duruyor")
	}
	// Kalanlar bitişik ve artan (en-yeniye biten kesintisiz bir kuyruk) olmalı.
	for i := 1; i < len(got); i++ {
		if got[i].At.Unix() != got[i-1].At.Unix()+1 {
			t.Fatalf("kalan küme bitişik değil: [%d]=%v [%d]=%v", i-1, got[i-1].At, i, got[i].At)
		}
	}
}

// Register hem dayanıklı yazmalı hem de canlı abonelere dağıtmalı.
func TestRegisterAppendsAndDelivers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bus.log")
	t.Setenv("KUT_BUS_LOG", p)

	b := eventbus.New()
	ch, cancel := b.Subscribe()
	defer cancel()

	if err := Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer Close()

	b.PublishEvent("dev-x", "critical", "boom")

	// Canlı dağıtım.
	select {
	case n := <-ch:
		if n.DeviceID != "dev-x" || n.Severity != "critical" {
			t.Fatalf("beklenmeyen bildirim: %+v", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abone bildirimi almadı (canlı dağıtım kırık)")
	}

	// Dayanıklı yazma: yolu bağımsızca oynatıp kaydı doğrula.
	l, err := NewFileLog(p)
	if err != nil {
		t.Fatalf("doğrulama açma: %v", err)
	}
	defer l.Close()
	got := drain(t, l)
	if len(got) != 1 || got[0].DeviceID != "dev-x" || got[0].Message != "boom" {
		t.Fatalf("dayanıklı kayıt eksik/yanlış: %+v", got)
	}
}
