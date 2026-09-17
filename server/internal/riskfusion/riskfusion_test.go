package riskfusion

import (
	"math"
	"testing"
)

// almostEqual, kayan-nokta karşılaştırması için küçük tolerans kullanır.
func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestFuseWeightedScore(t *testing.T) {
	cases := []struct {
		name    string
		signals []Signal
		want    float64
		level   string
	}{
		{
			name:    "tek sinyal skorun kendisi",
			signals: []Signal{{Name: "a", Score: 60, Weight: 1}},
			want:    60,
			level:   "MEDIUM",
		},
		{
			name: "eşit ağırlık ortalama",
			signals: []Signal{
				{Name: "a", Score: 20, Weight: 1},
				{Name: "b", Score: 80, Weight: 1},
			},
			want:  50,
			level: "MEDIUM",
		},
		{
			name: "ağırlıklı ortalama yüksek sinyale kayar",
			signals: []Signal{
				{Name: "a", Score: 20, Weight: 1},
				{Name: "b", Score: 90, Weight: 3},
			},
			want:  (20*1 + 90*3) / 4.0, // 72.5
			level: "HIGH",
		},
		{
			name: "kritik seviye",
			signals: []Signal{
				{Name: "a", Score: 95, Weight: 2},
				{Name: "b", Score: 90, Weight: 2},
			},
			want:  92.5,
			level: "CRITICAL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Fuse(tc.signals)
			if !almostEqual(got.Score, tc.want) {
				t.Fatalf("skor = %v, beklenen %v", got.Score, tc.want)
			}
			if got.Level != tc.level {
				t.Fatalf("seviye = %q, beklenen %q", got.Level, tc.level)
			}
		})
	}
}

// TestContributionsSumToScore, açıklanabilirliğin çekirdek garantisidir:
// katkıların (Points) toplamı NİHAİ skora birebir eşit olmalı (additive
// attribution). Payların (Share) toplamı da 1 olmalı.
func TestContributionsSumToScore(t *testing.T) {
	signals := []Signal{
		{Name: "ioc", Score: 90, Weight: 3},
		{Name: "ueba", Score: 40, Weight: 1},
		{Name: "vuln", Score: 65, Weight: 2},
	}
	res := Fuse(signals)

	var sumPts, sumShare float64
	for _, c := range res.Contributions {
		sumPts += c.Points
		sumShare += c.Share
	}
	if !almostEqual(sumPts, res.Score) {
		t.Fatalf("katkı toplamı %v, skor %v — eşit olmalı", sumPts, res.Score)
	}
	if !almostEqual(sumShare, 1) {
		t.Fatalf("pay toplamı %v, 1 olmalı", sumShare)
	}
}

// TestContributionsSortedDescending, katkıların azalan sıralı olduğunu ve en
// ağır sinyalin başta geldiğini doğrular.
func TestContributionsSortedDescending(t *testing.T) {
	signals := []Signal{
		{Name: "low", Score: 30, Weight: 1},
		{Name: "high", Score: 95, Weight: 4},
		{Name: "mid", Score: 60, Weight: 2},
	}
	res := Fuse(signals)
	if len(res.Contributions) != 3 {
		t.Fatalf("3 katkı beklenirdi, %d", len(res.Contributions))
	}
	for i := 1; i < len(res.Contributions); i++ {
		if res.Contributions[i-1].Points < res.Contributions[i].Points {
			t.Fatalf("katkılar azalan sıralı değil: %+v", res.Contributions)
		}
	}
	if res.Contributions[0].Name != "high" {
		t.Fatalf("en yüksek katkı 'high' olmalı, %q", res.Contributions[0].Name)
	}
	if len(res.Top) == 0 || res.Top[0] != "high" {
		t.Fatalf("Top baskın sinyalle başlamalı, %v", res.Top)
	}
}

// TestCounterfactual, bir sinyal çıkarıldığında skorun renormalize olduğunu ve
// değerin KESİN yeniden-hesaplanmış ağırlıklı ortalama olduğunu doğrular.
func TestCounterfactual(t *testing.T) {
	signals := []Signal{
		{Name: "a", Score: 20, Weight: 1},
		{Name: "b", Score: 80, Weight: 1},
	}
	// b çıkarılırsa kalan yalnız a=20.
	if got := Counterfactual(signals, "b"); !almostEqual(got, 20) {
		t.Fatalf("counterfactual(b) = %v, beklenen 20", got)
	}
	// a çıkarılırsa kalan yalnız b=80.
	if got := Counterfactual(signals, "a"); !almostEqual(got, 80) {
		t.Fatalf("counterfactual(a) = %v, beklenen 80", got)
	}
	// Var olmayan sinyal → mevcut skor değişmez (50).
	if got := Counterfactual(signals, "yok"); !almostEqual(got, 50) {
		t.Fatalf("counterfactual(yok) = %v, beklenen 50", got)
	}
}

// TestCounterfactualRenormalizes, counterfactual'ın basit "skor − katkı"
// olmadığını; paydanın yeniden normalize olduğunu açıkça gösterir.
func TestCounterfactualRenormalizes(t *testing.T) {
	signals := []Signal{
		{Name: "a", Score: 20, Weight: 1},
		{Name: "b", Score: 90, Weight: 3},
	}
	full := Fuse(signals)              // 72.5
	cf := Counterfactual(signals, "b") // yalnız a → 20
	// Naif "skor − points(b)" yanlış olurdu; gerçek renormalize skor 20 olmalı.
	if !almostEqual(cf, 20) {
		t.Fatalf("renormalize counterfactual = %v, beklenen 20", cf)
	}
	naive := full.Score
	for _, c := range full.Contributions {
		if c.Name == "b" {
			naive -= c.Points
		}
	}
	if almostEqual(naive, cf) {
		t.Fatalf("naif çıkarma (%v) renormalize değerle (%v) çakışmamalı", naive, cf)
	}
}

// TestFailSafe, boş/negatif/aşırı girdilere dayanıklılığı doğrular.
func TestFailSafe(t *testing.T) {
	// Boş girdi.
	if r := Fuse(nil); r.Score != 0 || r.Level != "LOW" || len(r.Contributions) != 0 {
		t.Fatalf("boş girdi sıfır sonuç vermeli, %+v", r)
	}
	// Toplam ağırlık 0 (tüm ağırlıklar sıfır/negatif) → skor 0.
	zero := Fuse([]Signal{
		{Name: "a", Score: 100, Weight: 0},
		{Name: "b", Score: 100, Weight: -5},
	})
	if zero.Score != 0 {
		t.Fatalf("sıfır/negatif ağırlık → 0 skor, %v", zero.Score)
	}
	// Aralık dışı skorlar 0..100'e kırpılır: -50 → 0, 250 → 100.
	clamped := Fuse([]Signal{
		{Name: "neg", Score: -50, Weight: 1},
		{Name: "big", Score: 250, Weight: 1},
	})
	if !almostEqual(clamped.Score, 50) { // (0 + 100)/2
		t.Fatalf("kırpılmış ortalama 50 olmalı, %v", clamped.Score)
	}
	// Negatif ağırlıklı sinyal füzyona hiç girmemeli (katkı listesinde yok).
	mixed := Fuse([]Signal{
		{Name: "gecerli", Score: 80, Weight: 2},
		{Name: "gecersiz", Score: 90, Weight: -1},
	})
	if len(mixed.Contributions) != 1 || mixed.Contributions[0].Name != "gecerli" {
		t.Fatalf("negatif ağırlık yok sayılmalı, %+v", mixed.Contributions)
	}
	if !almostEqual(mixed.Score, 80) {
		t.Fatalf("skor yalnız geçerli sinyalden gelmeli (80), %v", mixed.Score)
	}
	// Counterfactual tüm ağırlığı yok ederse 0 döner.
	if got := Counterfactual([]Signal{{Name: "a", Score: 50, Weight: 1}}, "a"); got != 0 {
		t.Fatalf("tek sinyal çıkınca counterfactual 0 olmalı, %v", got)
	}
}
