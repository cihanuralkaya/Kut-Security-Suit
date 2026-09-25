//go:build enterprise

package enterprise

import (
	"path/filepath"
	"testing"

	"kut.corp/suite/server/internal/eventbus"
)

// Enable dayanıklı bus'ı bağlamalı; Shutdown temiz kapatmalı ve idempotent olmalı.
func TestEnableShutdownLifecycle(t *testing.T) {
	t.Setenv("KUT_BUS_LOG", filepath.Join(t.TempDir(), "bus.log"))

	b := eventbus.New()
	if err := Enable(b); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// Bağlanma kanıtı: yayınlanan bildirim yerel aboneye ulaşmalı (sink kablolandı).
	ch, cancel := b.Subscribe()
	defer cancel()
	b.PublishDevice("d-lifecycle")
	select {
	case <-ch:
	default:
		t.Fatal("Enable sonrası sink bağlı değil (bildirim dağıtılmadı)")
	}

	if err := Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Idempotency: ikinci Shutdown no-op olmalı.
	if err := Shutdown(); err != nil {
		t.Fatalf("Shutdown (ikinci çağrı) no-op olmalı: %v", err)
	}
}
