//go:build enterprise

package bus

import (
	"fmt"
	"os"
	"testing"
	"time"

	"kut.corp/suite/server/internal/eventbus"
)

// kafkaTestURL, entegrasyon testleri için broker adresini döner; ayarlı değilse test atlanır
// (JetStream'in aksine Kafka gömülemez → CI'da Redpanda servis konteyneri sağlar).
func kafkaTestURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KUT_KAFKA_URL")
	if url == "" {
		t.Skip("KUT_KAFKA_URL ayarlı değil; Kafka entegrasyon testi atlandı (CI'da Redpanda konteyneri sağlar)")
	}
	return url
}

// uniqueTopic, testler arası çakışmayı önlemek için benzersiz bir topic adı üretir.
func uniqueTopic() string { return fmt.Sprintf("kut-bus-test-%d", time.Now().UnixNano()) }

func drainKafka(t *testing.T, l *kafkaLog) []eventbus.Notice {
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

// Kafka: append edilen bildirimler en eskiden en yeniye, alanları korunarak oynatılmalı.
func TestKafkaAppendReplay(t *testing.T) {
	url := kafkaTestURL(t)
	l, err := NewKafkaLog(url, uniqueTopic())
	if err != nil {
		t.Fatalf("NewKafkaLog: %v", err)
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
	got := drainKafka(t, l)
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

// Boş topic'te Replay hemen (kayıtsız) dönmeli.
func TestKafkaReplayEmpty(t *testing.T) {
	url := kafkaTestURL(t)
	l, err := NewKafkaLog(url, uniqueTopic())
	if err != nil {
		t.Fatalf("NewKafkaLog: %v", err)
	}
	defer l.Close()
	if got := drainKafka(t, l); len(got) != 0 {
		t.Fatalf("boş topic'te kayıt döndü: %+v", got)
	}
}

// Register, KUT_BUS_BACKEND=kafka ile Kafka backend'ini kullanmalı: canlı dağıtım + dayanıklı yazma.
func TestRegisterKafkaBackend(t *testing.T) {
	url := kafkaTestURL(t)
	topic := uniqueTopic()
	t.Setenv("KUT_BUS_BACKEND", "kafka")
	t.Setenv("KUT_KAFKA_URL", url)
	t.Setenv("KUT_KAFKA_TOPIC", topic)

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
	case <-time.After(10 * time.Second):
		t.Fatal("abone bildirimi almadı (canlı dağıtım kırık)")
	}

	if err := Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l, err := NewKafkaLog(url, topic)
	if err != nil {
		t.Fatalf("doğrulama açma: %v", err)
	}
	defer l.Close()
	got := drainKafka(t, l)
	if len(got) != 1 || got[0].DeviceID != "dev-x" || got[0].Message != "boom" {
		t.Fatalf("dayanıklı kayıt eksik/yanlış: %+v", got)
	}
}
