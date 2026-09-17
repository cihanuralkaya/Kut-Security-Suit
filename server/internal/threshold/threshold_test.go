package threshold

import (
	"testing"
	"time"
)

// clock, kontrol edilebilir bir saat sağlar.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestAllow_FiresOnNthHit(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	g := New(clk.now)
	// count=3, window=60s: ilk iki vuruş bastırılmalı, üçüncü geçmeli.
	for i := 1; i <= 2; i++ {
		if g.Allow("R1", "dev1", 3, 60*time.Second) {
			t.Fatalf("vuruş %d geçmemeliydi (eşik 3)", i)
		}
	}
	if !g.Allow("R1", "dev1", 3, 60*time.Second) {
		t.Fatal("3. vuruş eşiği aşmalı ve geçmeliydi")
	}
	// Sıfırlandı: sonraki iki yine bastırılmalı.
	if g.Allow("R1", "dev1", 3, 60*time.Second) {
		t.Fatal("eşik sonrası sayaç sıfırlanmalıydı")
	}
}

func TestAllow_WindowExpiryResets(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	g := New(clk.now)
	g.Allow("R1", "dev1", 3, 60*time.Second) // hits=1
	g.Allow("R1", "dev1", 3, 60*time.Second) // hits=2
	clk.add(61 * time.Second)                // pencere doldu
	if g.Allow("R1", "dev1", 3, 60*time.Second) {
		t.Fatal("pencere dolunca sayaç sıfırlanmalı; bu vuruş hits=1 olmalı")
	}
}

func TestAllow_ScopeIsolation(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	g := New(clk.now)
	// Farklı kapsamlar (cihazlar) ayrı sayılmalı: tek cihaz tek başına eşiği aşmamalı.
	g.Allow("R1", "devA", 2, 60*time.Second) // A: hits=1
	if g.Allow("R1", "devB", 2, 60*time.Second) {
		t.Fatal("devB ilk vuruşta geçmemeli (devA'dan bağımsız)")
	}
	if !g.Allow("R1", "devA", 2, 60*time.Second) {
		t.Fatal("devA 2. vuruşta geçmeli")
	}
}

func TestAllow_CountOneAlwaysPasses(t *testing.T) {
	g := New(nil)
	for i := 0; i < 5; i++ {
		if !g.Allow("R1", "dev1", 1, time.Minute) {
			t.Fatal("count<=1 daima geçmeli (eşik anlamsız)")
		}
	}
	if g.TrackedCount() != 0 {
		t.Fatalf("count<=1 durum tutmamalı, TrackedCount=%d", g.TrackedCount())
	}
}

func TestAllow_RuleIsolation(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	g := New(clk.now)
	g.Allow("R1", "dev1", 2, 60*time.Second) // R1: hits=1
	if g.Allow("R2", "dev1", 2, 60*time.Second) {
		t.Fatal("R2 ilk vuruşta geçmemeli (R1'den bağımsız)")
	}
}
