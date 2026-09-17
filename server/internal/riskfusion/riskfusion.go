// Package riskfusion, AÇIKLANABİLİR (explainable) çok-sinyalli bir RİSK FÜZYON
// motorudur. Farklı tespit katmanlarından gelen bağımsız sinyaller (ör. UEBA
// sapması, IOC eşleşmesi, zafiyet maruziyeti, kimlik anomalisi) tek bir 0-100
// risk skoruna toplanır. Kritik fark şudur: skor bir "kara kutu" değildir —
// her sinyalin nihai skora KESİN katkısı hesaplanır (additive attribution).
//
// Model doğrusal ve ağırlıklı-ortalamadır:
//
//	Skor = Σ(wᵢ·sᵢ) / Σ(wᵢ)          // sᵢ∈[0,100], wᵢ≥0
//
// Doğrusal modelde her sinyalin katkısı belirsizlik olmadan ayrıştırılabilir;
// bu, SHAP değerlerinin doğrusal modeldeki özel (kapalı-form) hâlidir. Taban
// (baseline) 0 alınır — yani hiçbir sinyal yoksa skor 0'dır — ve her sinyalin
// katkısı Pointsᵢ = wᵢ·sᵢ/Σw olur. Bu katkıların TOPLAMI tam olarak nihai skora
// eşittir, dolayısıyla "skoru neyin oluşturduğu" kesin ve denetlenebilirdir.
//
// Paket SAF ve testlidir; ÇEKİRDEK dışında hiçbir bağımlılığı yoktur ve boş/
// negatif/aşırı girdilere karşı fail-safe davranır (ağırlık toplamı 0 ise 0
// döner, skorlar 0..100'e kırpılır).
package riskfusion

import "sort"

// Signal, füzyona giren tek bir bağımsız risk sinyalidir. Score sinyalin kendi
// 0..100 risk değeri, Weight ise bu sinyalin füzyondaki göreli önemidir (ör.
// yüksek-güvenli IOC eşleşmesi zayıf bir UEBA sapmasından ağır tartılır).
type Signal struct {
	Name   string  // sinyal adı (ör. "ioc", "ueba", "vuln")
	Score  float64 // 0..100 (aralık dışı değerler kırpılır)
	Weight float64 // ≥0 göreli önem (negatif → 0 sayılır, sinyal yok sayılır)
}

// Contribution, tek bir sinyalin nihai skora KESİN katkısıdır (açıklanabilirlik).
// Points sinyalin skora eklediği puandır; tüm Points'lerin toplamı nihai skora
// eşittir. Share ise bu katkının orandır (0..1); tüm Share'lerin toplamı 1'dir.
type Contribution struct {
	Name   string  // sinyal adı
	Points float64 // nihai skora katkı (puan); Σ Points = Score
	Share  float64 // 0..1 katkı oranı; Σ Share = 1 (skor > 0 iken)
}

// Result, bir füzyonun tam sonucudur: sayısal skor, insan-okunur seviye ve her
// sinyalin ayrıştırılmış katkısı ile baskın sürücü (driver) sinyallerin adları.
type Result struct {
	Score         float64        // 0..100 füzyon skoru
	Level         string         // LOW / MEDIUM / HIGH / CRITICAL
	Contributions []Contribution // katkıya göre AZALAN sıralı
	Top           []string       // en yüksek katkılı ("baskın") sinyal adları
}

// clampf, bir değeri [lo,hi] aralığına sıkıştırır (fail-safe).
func clampf(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// levelFor, sayısal skoru risk seviyesine eşler. Eşikler dokümantedir:
//
//	<40  → LOW
//	<70  → MEDIUM
//	<90  → HIGH
//	≥90  → CRITICAL
func levelFor(score float64) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// weightedScore, geçerli sinyaller üzerinden ağırlıklı-ortalama skoru ve toplam
// ağırlığı döner. Skorlar 0..100'e, ağırlıklar ≥0'a kırpılır. Toplam ağırlık 0
// ise (hiç geçerli sinyal yok) skor 0 ve toplam 0 döner — fail-safe.
func weightedScore(signals []Signal) (score, totalWeight float64) {
	for _, s := range signals {
		w := clampf(s.Weight, 0, s.Weight) // negatif ağırlık → 0
		if w <= 0 {
			continue
		}
		score += w * clampf(s.Score, 0, 100)
		totalWeight += w
	}
	if totalWeight <= 0 {
		return 0, 0
	}
	return clampf(score/totalWeight, 0, 100), totalWeight
}

// Fuse, verilen sinyalleri tek bir açıklanabilir risk sonucuna toplar. Nihai
// skor ağırlıklı ortalamadır ve her sinyalin katkısı KESİN olarak ayrıştırılır:
// Pointsᵢ = wᵢ·sᵢ/Σw olduğundan katkıların toplamı nihai skora birebir eşittir
// (baseline 0). Contributions katkıya göre azalan sıralıdır; Top, kümülatif
// katkısı skorun en az yarısını (%50) açıklayan baskın sinyallerin adlarıdır.
//
// Fail-safe: boş girdi veya toplam ağırlık 0 ise Score 0 ve Level LOW döner.
func Fuse(signals []Signal) Result {
	score, totalWeight := weightedScore(signals)
	res := Result{Score: score, Level: levelFor(score)}
	if totalWeight <= 0 {
		return res
	}

	res.Contributions = make([]Contribution, 0, len(signals))
	for _, s := range signals {
		w := clampf(s.Weight, 0, s.Weight)
		if w <= 0 {
			continue
		}
		pts := w * clampf(s.Score, 0, 100) / totalWeight
		share := 0.0
		if score > 0 {
			share = pts / score
		}
		res.Contributions = append(res.Contributions, Contribution{
			Name:   s.Name,
			Points: pts,
			Share:  share,
		})
	}

	// Katkıya göre azalan sırala; eşitlikte ada göre kararlı sırala.
	sort.SliceStable(res.Contributions, func(i, j int) bool {
		if res.Contributions[i].Points != res.Contributions[j].Points {
			return res.Contributions[i].Points > res.Contributions[j].Points
		}
		return res.Contributions[i].Name < res.Contributions[j].Name
	})

	// Top: kümülatif payı %50'ye ulaşan baskın sürücüler (en az bir sinyal).
	var cum float64
	for _, c := range res.Contributions {
		if score <= 0 {
			break
		}
		res.Top = append(res.Top, c.Name)
		cum += c.Share
		if cum >= 0.5 {
			break
		}
	}
	return res
}

// Counterfactual, "bu sinyal olmasaydı skor ne olurdu?" sorusunu yanıtlar:
// dropName adlı sinyal(ler) ÇIKARILDIĞINDA kalan sinyaller üzerinden yeniden
// hesaplanan ağırlıklı-ortalama skoru döner. Dikkat: bu değer basitçe
// Skor − Points(drop) DEĞİLDİR; sinyal çıkınca payda (Σw) yeniden normalize
// olur, dolayısıyla counterfactual bu renormalizasyonu yansıtan KESİN skordur.
//
// Fail-safe: dropName yoksa mevcut skor döner; çıkarma sonrası geçerli ağırlık
// kalmazsa 0 döner.
func Counterfactual(signals []Signal, dropName string) float64 {
	kept := make([]Signal, 0, len(signals))
	for _, s := range signals {
		if s.Name == dropName {
			continue
		}
		kept = append(kept, s)
	}
	score, _ := weightedScore(kept)
	return score
}
