package verify

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/risk"
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

// TestDetectionVerifierRealizedRisk, Dilim 3 risk-azalması math'ini doğrular: Baseline
// açılışta Factors'tan türer; VERIFIED gerçekleşen azalma (>0) verir; REGRESSED azalma
// vermez (0). Kalan risk asla Baseline'ı aşmaz.
func TestDetectionVerifierRealizedRisk(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	f := risk.Factors{Severity: "HIGH", AssetCriticality: 5, Exposure: 3, Confidence: 0.9, Exploitability: 0.8}
	c, _ := s.Open(Check{ID: "c1", TenantID: "acme", RuleID: "rule-A", Kind: KindDetection, Factors: f})
	if c.Baseline != risk.Score(f) || c.Baseline == 0 {
		t.Fatalf("Open Baseline'ı Factors'tan türetmeli: %d (beklenen %d)", c.Baseline, risk.Score(f))
	}

	v := NewDetectionVerifier(fakeRunner{fireRuleID: "rule-A"})

	// VERIFIED: kural tetiklemiyor → residual < baseline, azalma > 0.
	clean := []model.Event{{Message: "benign"}}
	o, residual, _ := v.Evaluate(ctx, c, clean)
	if o != OutcomeVerified {
		t.Fatalf("VERIFIED beklenirdi: %s", o)
	}
	if residual >= c.Baseline || residual < 0 {
		t.Fatalf("VERIFIED residual baseline'dan küçük olmalı: residual=%d baseline=%d", residual, c.Baseline)
	}
	rv, _ := s.Resolve("acme", "c1", o, residual)
	if rv.RiskReduced() <= 0 {
		t.Fatalf("VERIFIED gerçekleşen risk-azalması pozitif olmalı: %d", rv.RiskReduced())
	}

	// REGRESSED: kural hâlâ tetikliyor → residual = baseline, azalma 0.
	still := []model.Event{{Message: "still"}}
	o2, residual2, _ := v.Evaluate(ctx, c, still)
	if o2 != OutcomeRegressed || residual2 != c.Baseline {
		t.Fatalf("REGRESSED residual=Baseline olmalı: %s %d", o2, residual2)
	}
}
