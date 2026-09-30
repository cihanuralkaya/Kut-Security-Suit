package verify

// verifier.go (Dilim 2) — tespit sinyalini AKSİYON-SONRASI pencerede yeniden ölçen
// deterministik doğrulayıcı. `adminread.ReplayDetections`'ın TERSİ: replay "bu kural
// geçmişte kaç olayı yakalardı?" derken, doğrulama "kural taze pencerede ARTIK
// tetikliyor mu?" der ve SIFIR eşleşme beklenir. Fail-closed: telemetri yoksa VERIFIED
// verilmez (INCONCLUSIVE).

import (
	"context"
	"strings"

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
	// sinyal-bağımlı faktörler asgariye indirilmiş skor (verifiedResidual).
	return OutcomeVerified, verifiedResidual(c, baseline), nil
}

// signalGoneConfidence, doğrulanmış-düzelme sonrası kalan-risk hesabında kullanılan
// asgari güven değeridir (risk.Score'un 0=tam-güven yorumundan kaçınmak için >0).
const signalGoneConfidence = 0.05

// verifiedResidual, doğrulanmış-düzelme sonrası kalan (yapısal) riski hesaplar: sinyal-
// bağımlı faktörler asgariye indirilmiş skor. NOT: risk.Score, Confidence<=0'ı "belirtilmemiş
// → tam güven" sayar; bu yüzden "sinyal yok"u temsil için 0 değil küçük bir epsilon
// kullanılır. Exploitability doğrudan eklenti olduğundan 0 doğru. Kalan, baseline'ı aşmaz.
func verifiedResidual(c Check, baseline int) int {
	rf := c.Factors
	rf.Confidence = signalGoneConfidence
	rf.Exploitability = 0
	res := risk.Score(rf)
	if res > baseline {
		res = baseline // güvenlik: kalan, başlangıcı asla aşmaz
	}
	return res
}

// EvaluateDeviceStatus, Kind=device_status için doğrulayıcıdır: cihazın GÜNCEL efektif
// durumunu (current) beklenen duruma (c.Expected) karşı ölçer — DetectionVerifier'ın olay
// tabanlı yolundan farklı olarak sinyal cihazın DURUMUdur. Karşılaştırma büyük/küçük harf
// ve boşluk duyarsızdır. Fail-closed: durum ya da beklenti bilinmiyorsa (boş) INCONCLUSIVE
// (VERIFIED verilmez). Eşleşme → VERIFIED (yapısal kalan risk); aksi → REGRESSED (baseline).
func EvaluateDeviceStatus(c Check, current string) (Outcome, int) {
	baseline := c.Baseline
	if baseline == 0 {
		baseline = risk.Score(c.Factors)
	}
	cur := strings.ToUpper(strings.TrimSpace(current))
	exp := strings.ToUpper(strings.TrimSpace(c.Expected))
	if cur == "" || exp == "" {
		return OutcomeInconclusive, baseline
	}
	if cur == exp {
		return OutcomeVerified, verifiedResidual(c, baseline)
	}
	return OutcomeRegressed, baseline
}

// EvaluateVulnCleared, Kind=vuln için doğrulayıcıdır: bir CVE'nin (c.Expected) cihazın
// GÜNCEL yazılım envanterinde ARTIK eşleşmediğini ölçer. Çağıran katman cihazın güncel
// eşleşen CVE listesini (currentCVEs) ve envanter verisinin mevcut olup olmadığını
// (dataAvailable) hesaplar; bu saf fonksiyon karar verir. Fail-closed: envanter yoksa
// veya beklenen CVE boşsa INCONCLUSIVE (yamalandı DENMEZ). CVE hâlâ eşleşiyor → REGRESSED;
// eşleşmiyor → VERIFIED. Karşılaştırma büyük/küçük harf duyarsız.
func EvaluateVulnCleared(c Check, dataAvailable bool, currentCVEs []string) (Outcome, int) {
	baseline := c.Baseline
	if baseline == 0 {
		baseline = risk.Score(c.Factors)
	}
	exp := strings.ToUpper(strings.TrimSpace(c.Expected))
	if !dataAvailable || exp == "" {
		return OutcomeInconclusive, baseline
	}
	for _, cve := range currentCVEs {
		if strings.ToUpper(strings.TrimSpace(cve)) == exp {
			return OutcomeRegressed, baseline // CVE hâlâ var → yamalanmadı
		}
	}
	return OutcomeVerified, verifiedResidual(c, baseline)
}
