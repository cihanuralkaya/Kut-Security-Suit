package verify

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

// fakeRunner, mesajı "still" içeren olaylar için verilen kuralı tetikleyen sahte bir
// RuleRunner'dır (gerçek detect.Engine yerine deterministik test ikizi).
type fakeRunner struct{ fireRuleID string }

func (f fakeRunner) Evaluate(ev model.Event) []detect.Detection {
	if ev.Message == "still" {
		return []detect.Detection{{RuleID: f.fireRuleID, RuleName: "x"}}
	}
	return nil
}

func TestDetectionVerifier(t *testing.T) {
	ctx := context.Background()
	v := NewDetectionVerifier(fakeRunner{fireRuleID: "rule-A"})
	c := Check{ID: "c1", TenantID: "acme", RuleID: "rule-A", Kind: KindDetection, Baseline: 80}

	// Telemetri yok → INCONCLUSIVE (fail-closed), residual=Baseline.
	if o, r, _ := v.Evaluate(ctx, c, nil); o != OutcomeInconclusive || r != 80 {
		t.Fatalf("boş pencere INCONCLUSIVE/Baseline olmalı: %s %d", o, r)
	}

	// Kaynak kural hâlâ tetikliyor → REGRESSED, residual=Baseline (azalma yok).
	still := []model.Event{{Message: "still"}}
	if o, r, _ := v.Evaluate(ctx, c, still); o != OutcomeRegressed || r != 80 {
		t.Fatalf("hâlâ tetikleyen kural REGRESSED/Baseline olmalı: %s %d", o, r)
	}

	// Taze pencerede kural artık tetiklemiyor → VERIFIED, residual=0.
	clean := []model.Event{{Message: "benign"}, {Message: "normal"}}
	if o, r, _ := v.Evaluate(ctx, c, clean); o != OutcomeVerified || r != 0 {
		t.Fatalf("tetiklemeyen kural VERIFIED/0 olmalı: %s %d", o, r)
	}

	// Farklı kural tetiklese bile kaynak kural (rule-A) tetiklemiyorsa VERIFIED.
	vOther := NewDetectionVerifier(fakeRunner{fireRuleID: "rule-B"})
	if o, _, _ := vOther.Evaluate(ctx, c, still); o != OutcomeVerified {
		t.Fatalf("başka kuralın tetiklemesi kaynak kuralı doğrular saymamalı: %s", o)
	}

	// nil runner → INCONCLUSIVE (fail-closed).
	if o, _, _ := (&DetectionVerifier{}).Evaluate(ctx, c, still); o != OutcomeInconclusive {
		t.Fatalf("nil runner INCONCLUSIVE olmalı: %s", o)
	}
}
