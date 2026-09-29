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
	"kut.corp/suite/server/internal/risk"
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

// Evaluate, Verifier arayüzünü gerçekler. Döndürülen int, KALAN risktir:
//   - INCONCLUSIVE/REGRESSED → Baseline (azalma yok/ölçülemedi)
//   - VERIFIED → sinyal-bağımlı faktörler (Confidence, Exploitability) SIFIRLANMIŞ
//     risk.Score'u — yani bu tespit artık tetiklemediğinde kalan YAPISAL risk (varlık
//     kritikliği + maruziyet). Dürüst: bir cihaz bu tespit temizlense de hâlâ açık olabilir.
func (v *DetectionVerifier) Evaluate(_ context.Context, c Check, fresh []model.Event) (Outcome, int, error) {
	baseline := c.Baseline
	if baseline == 0 {
		baseline = risk.Score(c.Factors)
	}
	// Fail-closed: değerlendirilecek taze telemetri veya runner yoksa "düzeldi" DENEMEYİZ.
	if len(fresh) == 0 || v.runner == nil {
		return OutcomeInconclusive, baseline, nil
	}
	for _, ev := range fresh {
		for _, d := range v.runner.Evaluate(ev) {
			// RuleID boşsa (kaynak kural bilinmiyor) herhangi bir tespit sinyalin
			// sürdüğünü gösterir; doluysa yalnız AYNI kural sayılır.
			if c.RuleID == "" || d.RuleID == c.RuleID {
				return OutcomeRegressed, baseline, nil // sinyal hâlâ var → azalma yok
			}
		}
	}
	// Kaynak kural taze pencerede ARTIK tetiklemiyor → doğrulanmış düzelme; kalan risk =
	// sinyal-bağımlı faktörler asgariye indirilmiş skor. NOT: risk.Score, Confidence<=0'ı
	// "belirtilmemiş → tam güven" sayar; bu yüzden "sinyal yok"u temsil için 0 değil küçük
	// bir epsilon kullanılır (güveni asgariye indirir). Exploitability doğrudan eklenti
	// olduğundan 0 doğru (istismar sinyali kaldırılır).
	residualFactors := c.Factors
	residualFactors.Confidence = signalGoneConfidence
	residualFactors.Exploitability = 0
	residual := risk.Score(residualFactors)
	if residual > baseline {
		residual = baseline // güvenlik: kalan, başlangıcı asla aşmaz
	}
	return OutcomeVerified, residual, nil
}

// signalGoneConfidence, doğrulanmış-düzelme sonrası kalan-risk hesabında kullanılan
// asgari güven değeridir (risk.Score'un 0=tam-güven yorumundan kaçınmak için >0).
const signalGoneConfidence = 0.05
