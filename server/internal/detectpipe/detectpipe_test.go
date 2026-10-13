package detectpipe

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/correlate"
	"kut.corp/suite/server/internal/detbits"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/threshold"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestScopeKey(t *testing.T) {
	cases := []struct{ track, dev, tenant, want string }{
		{"device", "d1", "t1", "device:d1"},
		{"", "d1", "t1", "device:d1"},
		{"tenant", "d1", "t1", "tenant:t1"},
		{"global", "d1", "t1", "global"},
		{" TENANT ", "d1", "t1", "tenant:t1"}, // case/space-insensitive
	}
	for _, c := range cases {
		if got := ScopeKey(c.track, c.dev, c.tenant); got != c.want {
			t.Errorf("ScopeKey(%q) = %q, want %q", c.track, got, c.want)
		}
	}
}

// Gate'siz tespit (bit/eşik/korelatör yok) her zaman alarma geçer.
func TestGate_Admit_NoGates(t *testing.T) {
	g := NewGate(threshold.New(time.Now), detbits.New(time.Now), nil)
	if !g.Admit(context.Background(), "dev1", model.Event{}, detect.Detection{RuleID: "r1"}) {
		t.Fatal("gate'siz tespit alarma geçmeliydi")
	}
}

// Bits ön-koşulu (Require) kurulu değilken bastırılır; Set yan-etkisi uygulanır.
func TestGate_Admit_BitsPreconditionAndSideEffect(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	bits := detbits.New(fixedClock(now))
	g := NewGate(threshold.New(fixedClock(now)), bits, nil)
	ctx := context.Background()
	e := model.Event{}

	// Aşama-2: Require=["stage1"] kurulu değil → bastır.
	stage2 := detect.Detection{RuleID: "r2", Bits: &detect.BitSpec{Require: []string{"stage1"}}}
	if g.Admit(ctx, "dev1", e, stage2) {
		t.Fatal("ön-koşul kurulu değilken tespit bastırılmalıydı")
	}

	// Aşama-1: Set=["stage1"] → alarma geçer ve biti yazar.
	stage1 := detect.Detection{RuleID: "r1", Bits: &detect.BitSpec{Set: []string{"stage1"}, TTLSeconds: 3600}}
	if !g.Admit(ctx, "dev1", e, stage1) {
		t.Fatal("aşama-1 tespiti alarma geçmeliydi")
	}
	if !bits.AllSet(ScopeKey("", "dev1", ""), []string{"stage1"}) {
		t.Fatal("aşama-1 Set yan-etkisi biti kurmadı")
	}

	// Artık aşama-2 ön-koşulu sağlanır → alarma geçer.
	if !g.Admit(ctx, "dev1", e, stage2) {
		t.Fatal("ön-koşul sağlanınca aşama-2 alarma geçmeliydi")
	}
}

// Tekrar-eşiği: Count'a ulaşana dek bastırılır (brute-force/tarama).
func TestGate_Admit_ThresholdWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := NewGate(threshold.New(fixedClock(now)), detbits.New(fixedClock(now)), nil)
	ctx := context.Background()
	d := detect.Detection{RuleID: "bruteforce", Threshold: &detect.ThresholdSpec{Count: 3, Seconds: 60}}

	if g.Admit(ctx, "dev1", model.Event{}, d) {
		t.Fatal("1. vuruş eşiğin altında, bastırılmalıydı")
	}
	if g.Admit(ctx, "dev1", model.Event{}, d) {
		t.Fatal("2. vuruş eşiğin altında, bastırılmalıydı")
	}
	if !g.Admit(ctx, "dev1", model.Event{}, d) {
		t.Fatal("3. vuruş eşiğe ulaştı, alarma geçmeliydi")
	}
}

// stubSink, korelatör için minimal IncidentSink.
type stubSink struct{ opened int }

func (s *stubSink) OpenIncident(ctx context.Context, deviceID, key, ruleID, technique, severity, message string, at time.Time) (string, error) {
	s.opened++
	return "inc-1", nil
}
func (s *stubSink) BumpIncident(ctx context.Context, id string, at time.Time) error { return nil }

// Korelasyon: aynı cihaz+kural penceresindeki ikinci tespit yinelenen alarm
// olarak bastırılır.
func TestGate_Admit_CorrelationSuppression(t *testing.T) {
	corr := correlate.New(time.Hour, &stubSink{})
	g := NewGate(threshold.New(time.Now), detbits.New(time.Now), corr)
	ctx := context.Background()
	d := detect.Detection{RuleID: "r1"}

	if !g.Admit(ctx, "dev1", model.Event{}, d) {
		t.Fatal("pencerede ilk tespit alarma geçmeliydi")
	}
	if g.Admit(ctx, "dev1", model.Event{}, d) {
		t.Fatal("pencerede ikinci (yinelenen) tespit bastırılmalıydı")
	}
}
