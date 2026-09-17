package grpc

import (
	"testing"
	"time"

	"kut.corp/suite/server/internal/threshold"
)

// TestNewHandlerHasThresholdGate, constructor'ın eşik kapısını daima kurduğunu
// doğrular (eşik tanımlı kurallar yeniden-kablolama olmadan çalışsın).
func TestNewHandlerHasThresholdGate(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, nil)
	if h.threshold == nil {
		t.Fatal("NewAgentHandler eşik kapısını kurmalıydı")
	}
}

// TestThresholdScope, Track → sayaç kapsam anahtarı eşlemesini doğrular.
func TestThresholdScope(t *testing.T) {
	cases := []struct{ track, dev, tenant, want string }{
		{"", "d1", "t1", "device:d1"},
		{"device", "d1", "t1", "device:d1"},
		{"tenant", "d1", "t1", "tenant:t1"},
		{"global", "d1", "t1", "global"},
		{"  DEVICE  ", "d1", "t1", "device:d1"}, // trim + küçük harf
	}
	for _, c := range cases {
		if got := scopeKey(c.track, c.dev, c.tenant); got != c.want {
			t.Errorf("scopeKey(%q) = %q, want %q", c.track, got, c.want)
		}
	}
}

// TestHandlerGateSuppressesUntilThreshold, handler'a takılı kapının ilk N-1
// tespiti bastırıp N.'de geçirdiğini (ingest döngüsünün kullandığı tam mantık)
// doğrular. Kontrol edilebilir saatle enjekte edilir.
func TestHandlerGateSuppressesUntilThreshold(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, nil)
	clk := time.Unix(1_700_000_000, 0)
	h.SetThresholdGate(threshold.New(func() time.Time { return clk }))

	scope := scopeKey("device", "dev1", "")
	win := 60 * time.Second
	if h.threshold.Allow("BF-1", scope, 3, win) || h.threshold.Allow("BF-1", scope, 3, win) {
		t.Fatal("eşik (3) aşılmadan ilk iki tespit bastırılmalıydı")
	}
	if !h.threshold.Allow("BF-1", scope, 3, win) {
		t.Fatal("3. tespit eşiği aşıp alarma dönmeliydi")
	}
}
