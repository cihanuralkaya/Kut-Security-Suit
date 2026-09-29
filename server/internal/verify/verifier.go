package verify

// verifier.go (Dilim 2) — tespit sinyalini AKSİYON-SONRASI pencerede yeniden ölçen
// deterministik doğrulayıcı. `adminread.ReplayDetections`'ın TERSİ: replay "bu kural
// geçmişte kaç olayı yakalardı?" derken, doğrulama "kural taze pencerede ARTIK
// tetikliyor mu?" der ve SIFIR eşleşme beklenir. Fail-closed: telemetri yoksa VERIFIED
// verilmez (INCONCLUSIVE).

import (
	"context"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

// RuleRunner, taze bir olayı tespit kurallarına karşı değerlendirir. `*detect.Engine`
// bunu doğrudan karşılar (`Evaluate(model.Event) []detect.Detection`); verify böylece
// motorun somut tipine değil bu dar arayüze bağlıdır (import döngüsü yok — detect,
// verify'ı import ETMEZ).
type RuleRunner interface {
	Evaluate(model.Event) []detect.Detection
}

// Verifier, bir Check'i taze telemetriye karşı değerlendirir ve sonucu + kalan riski döner.
type Verifier interface {
	Evaluate(ctx context.Context, c Check, fresh []model.Event) (Outcome, int, error)
}

// DetectionVerifier, Kind=detection için doğrulayıcı: Check'in kaynağı olan kuralı taze
// pencere olaylarına yeniden koşturur.
//   - SIFIR eşleşme  → VERIFIED (sinyal kayboldu)
//   - hâlâ tetikliyor → REGRESSED (düzelme yok)
//   - pencere boş    → INCONCLUSIVE (telemetri yok → karar verilemez, FAIL-CLOSED)
type DetectionVerifier struct {
	runner RuleRunner
}

// NewDetectionVerifier oluşturur.
func NewDetectionVerifier(r RuleRunner) *DetectionVerifier { return &DetectionVerifier{runner: r} }

var _ Verifier = (*DetectionVerifier)(nil)

// Evaluate, Verifier arayüzünü gerçekler. Döndürülen int, KALAN risktir (Dilim 3'te
// risk.Score ile inceltilir; burada: sinyal varsa/bilinmiyorsa Baseline korunur, yoksa 0).
func (v *DetectionVerifier) Evaluate(_ context.Context, c Check, fresh []model.Event) (Outcome, int, error) {
	// Fail-closed: değerlendirilecek taze telemetri yoksa "düzeldi" DENEMEYİZ.
	if len(fresh) == 0 {
		return OutcomeInconclusive, c.Baseline, nil
	}
	if v.runner == nil {
		return OutcomeInconclusive, c.Baseline, nil
	}
	for _, ev := range fresh {
		for _, d := range v.runner.Evaluate(ev) {
			// RuleID boşsa (kaynak kural bilinmiyor) herhangi bir tespit sinyalin
			// sürdüğünü gösterir; doluysa yalnız AYNI kural sayılır.
			if c.RuleID == "" || d.RuleID == c.RuleID {
				return OutcomeRegressed, c.Baseline, nil // sinyal hâlâ var → azalma yok
			}
		}
	}
	// Kaynak kural taze pencerede ARTIK tetiklemiyor → doğrulanmış düzelme.
	return OutcomeVerified, 0, nil
}
