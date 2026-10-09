package detect

import (
	"testing"

	"kut.corp/suite/server/internal/model"
)

// TestATTACKBreadthRules, ATT&CK genişlik kurallarının (KUT-0035..0039) doğru teknik+
// önem düzeyiyle tetiklendiğini doğrular. Odak: önceden BOŞ olan Collection taktiği
// (T1560/T1115) + Discovery/Cred-Access/C2 derinliği.
func TestATTACKBreadthRules(t *testing.T) {
	e := NewEngine(nil)
	cases := []struct {
		msg, rule, tech, sev string
	}{
		{`rar.exe a -hpSECRET loot.rar C:\Users\x\Documents`, "KUT-0035", "T1560", "MEDIUM"},
		{`powershell Get-Clipboard | Out-File c:\loot\clip.txt`, "KUT-0036", "T1115", "MEDIUM"},
		{`net group "Domain Admins" /domain`, "KUT-0037", "T1087", "MEDIUM"},
		{`findstr /si password *.config *.xml`, "KUT-0038", "T1552", "HIGH"},
		{`anydesk.exe --install --start-with-win`, "KUT-0039", "T1219", "HIGH"},
	}
	for _, c := range cases {
		dets := e.Evaluate(model.Event{Message: c.msg})
		d, ok := findDet(dets, c.rule)
		if !ok {
			t.Errorf("%q → %s tespiti bekleniyordu, dets=%+v", c.msg, c.rule, dets)
			continue
		}
		if d.Technique.ID != c.tech || d.Severity != c.sev {
			t.Errorf("%q → %s teknik=%s sev=%s (beklenen %s/%s)", c.msg, c.rule, d.Technique.ID, d.Severity, c.tech, c.sev)
		}
	}
}

// TestATTACKBreadthFalsePositiveGuards, benzer-ama-zararsız komutların genişlik
// kurallarını tetiklemediğini doğrular (FP koruması).
func TestATTACKBreadthFalsePositiveGuards(t *testing.T) {
	e := NewEngine(nil)
	negatives := []string{
		`net view \\fileserver01`,                  // 'view' net user|group|localgroup değil → KUT-0037 yok
		`kullanıcı parolasını panelden değiştirdi`, // 'parola' var ama 'password' literali yok → KUT-0038 yok
		`7zFM.exe arşiv görüntüleyici açıldı`,      // '7z a' deseni değil → KUT-0035 yok
		`haftalık takım toplantısı planlandı`,      // RMM aracı adı yok → KUT-0039 yok
	}
	for _, msg := range negatives {
		dets := e.Evaluate(model.Event{Message: msg})
		for _, id := range []string{"KUT-0035", "KUT-0036", "KUT-0037", "KUT-0038", "KUT-0039"} {
			if _, ok := findDet(dets, id); ok {
				t.Errorf("FP: %q %s tetiklememeliydi (dets=%+v)", msg, id, dets)
			}
		}
	}
}
