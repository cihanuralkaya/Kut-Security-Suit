package detect

import (
	"reflect"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/model"
)

// TestThresholdParsing, eşik alanının JSON'dan yüklenip doğrulandığını ve
// Evaluate tarafından tespide taşındığını doğrular.
func TestThresholdParsing(t *testing.T) {
	valid := `[{"id":"BF-1","name":"brute-force","severity":"HIGH",
	  "contains":["oturum başarısız"],"threshold":{"count":5,"seconds":60,"track":"device"}}]`
	rules, err := LoadRules(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("geçerli eşik yüklenemedi: %v", err)
	}
	if rules[0].Threshold == nil || rules[0].Threshold.Count != 5 || rules[0].Threshold.Track != "device" {
		t.Fatalf("eşik yanlış ayrıştırıldı: %+v", rules[0].Threshold)
	}
	// Evaluate, eşiği tespide taşımalı (alarm katmanı kapıyı buradan okur).
	e := NewEngine(rules)
	dets := e.Evaluate(model.Event{Category: "", Message: "oturum başarısız oldu", Severity: "HIGH"})
	if len(dets) != 1 || dets[0].Threshold == nil || dets[0].Threshold.Count != 5 {
		t.Fatalf("Evaluate eşiği taşımadı: %+v", dets)
	}

	// Geçersizler reddedilmeli (fail-closed doğrulama).
	bad := []string{
		`[{"id":"X","name":"n","severity":"HIGH","threshold":{"count":0,"seconds":60}}]`,
		`[{"id":"X","name":"n","severity":"HIGH","threshold":{"count":5,"seconds":0}}]`,
		`[{"id":"X","name":"n","severity":"HIGH","threshold":{"count":5,"seconds":60,"track":"planet"}}]`,
	}
	for i, b := range bad {
		if _, err := LoadRules(strings.NewReader(b)); err == nil {
			t.Errorf("geçersiz eşik[%d] kabul edildi", i)
		}
	}
}

// linearEval, ön-filtreyi BYPASS eden referans değerlendiricidir: her etkin kuralı
// doğrudan matches() ile sınar. Engine.Evaluate'in çıktısı bununla BİREBİR aynı
// olmalı — ön-filtre yalnız performans içindir, semantiği değiştiremez (soundness).
func linearEval(e *Engine, ev model.Event) []Detection {
	var out []Detection
	for _, c := range e.rules {
		if !c.rule.Active() {
			continue
		}
		if c.matches(ev) {
			r := c.rule
			out = append(out, Detection{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Technique: r.Technique, Threshold: r.Threshold, Bits: r.Bits})
		}
	}
	return out
}

// TestPrefilterEquivalence, çeşitli olaylar üzerinde ön-filtreli (Evaluate) ve
// doğrusal (linearEval) sonuçların özdeş olduğunu doğrular.
func TestPrefilterEquivalence(t *testing.T) {
	e := NewEngine(DefaultRules())
	events := []model.Event{
		{Category: "SECURITY", Message: "Ajan kurcalama girişimi tespit edildi", Severity: "CRITICAL"},
		{Category: "SECURITY", Message: "imzasız script reddedildi", Severity: "HIGH"},
		{Category: "SECURITY", Message: "sahte güncelleme paketi reddedildi", Severity: "HIGH"},
		{Category: "SECURITY", Message: "davranışsal anomali gözlendi", Severity: "HIGH"},
		{Category: "POLICY_VIOLATION", Message: "yasak süreç", Severity: "HIGH"},
		{Category: "NETWORK_DISCOVERY", Message: "port taraması", Severity: "LOW"},
		// Regex kuralı (KUT-0007, Contains yok → alwaysEval):
		{Category: "PROCESS", Message: "powershell -EncodedCommand ZQBjAGgAbwA=", Severity: "HIGH"},
		{Category: "PROCESS", Message: "C:\\tools\\mimikatz.exe sekurlsa::logonpasswords", Severity: "HIGH"},
		{Category: "POLICY_VIOLATION", Message: "kalıcılık autostart girdisi eklendi", Severity: "HIGH"},
		{Category: "SECURITY", Message: "dosya bütünlüğü değişikliği", Severity: "MEDIUM"},
		{Category: "SECURITY", Message: "hassas veri dışarı sızdırıldı", Severity: "HIGH"},
		{Category: "SECURITY", Message: "DGA-şüpheli alan adı sorgusu", Severity: "HIGH"},
		{Category: "SECURITY", Message: "içerik-tarama YARA eşleşmesi", Severity: "HIGH"},
		{Category: "SECURITY", Message: "yanal hareket denemesi", Severity: "HIGH"},
		{Category: "SECURITY", Message: "dns tünelleme tespiti", Severity: "HIGH"},
		// Hiçbir ankraja uymayan iyi-huylu olay: yalnız alwaysEval kuralları aday olur,
		// ama kategori/regex tutmadığından hiçbiri eşleşmemeli.
		{Category: "AUDIT", Message: "kullanıcı oturum açtı", Severity: "INFO"},
		// Kategori uyuşmazlığı: mesaj "kurcalama" içerir ama kural SECURITY ister.
		{Category: "AUDIT", Message: "kurcalama kelimesi geçen zararsız log", Severity: "INFO"},
		// Fields + MinSeverity yolu (özel kural aşağıda ayrı test edilir); burada boş.
		{Category: "SECURITY", Message: "hiçbir kurala uymayan metin", Severity: "LOW"},
	}
	for i, ev := range events {
		want := linearEval(e, ev)
		got := e.Evaluate(ev)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("olay[%d] %q: Evaluate=%v, linear=%v", i, ev.Message, got, want)
		}
	}
}

// TestPrefilterEquivalence_FieldsAndSeverity, Fields/MinSeverity taşıyan özel
// kurallarda da eşdeğerliği doğrular (ankraj yalnız Contains'ten seçilir; diğer
// koşullar 2. aşamada tam sınanır).
func TestPrefilterEquivalence_FieldsAndSeverity(t *testing.T) {
	rules := []Rule{
		{ID: "T-1", Name: "şifreleme kapalı", Category: "SECURITY", Contains: []string{"disk"},
			Fields: map[string]string{"disk_encryption": "off"}, MinSeverity: "MEDIUM", Severity: "HIGH"},
		{ID: "T-2", Name: "yalnız-alan (Contains yok)", Fields: map[string]string{"tamper": "true"}, Severity: "CRITICAL"},
	}
	e := NewEngine(rules)
	events := []model.Event{
		{Category: "SECURITY", Message: "disk durumu", Severity: "HIGH", Details: `{"disk_encryption":"off"}`},
		{Category: "SECURITY", Message: "disk durumu", Severity: "LOW", Details: `{"disk_encryption":"off"}`}, // MinSeverity elemeli
		{Category: "SECURITY", Message: "disk durumu", Severity: "HIGH", Details: `{"disk_encryption":"on"}`}, // Fields elemeli
		{Category: "SECURITY", Message: "ankraj yok", Severity: "HIGH", Details: `{"tamper":"true"}`},         // yalnız T-2 (alwaysEval)
		{Category: "SECURITY", Message: "disk ve tamper", Severity: "HIGH", Details: `{"disk_encryption":"off","tamper":"true"}`},
	}
	for i, ev := range events {
		want := linearEval(e, ev)
		got := e.Evaluate(ev)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("olay[%d] %q: Evaluate=%v, linear=%v", i, ev.Message, got, want)
		}
	}
}

// TestPrefilterStructure, ankraj seçiminin doğru sınıflandırdığını doğrular:
// Contains'i olmayan kurallar (regex/kategori-only) alwaysEval'e düşer; Contains'i
// olanlar ön-filtreye girer.
func TestPrefilterStructure(t *testing.T) {
	e := NewEngine(DefaultRules())
	always := map[int]bool{}
	for _, i := range e.alwaysEval {
		always[i] = true
	}
	for i, c := range e.rules {
		hasLiteral := selectAnchor(c.rule.Contains) != ""
		if hasLiteral && always[i] {
			t.Errorf("kural %s literal içeriyor ama alwaysEval'de", c.rule.ID)
		}
		if !hasLiteral && !always[i] {
			t.Errorf("kural %s literal içermiyor ama ön-filtrede", c.rule.ID)
		}
	}
	// patRule uzunluğu ön-filtreye giren kural sayısıyla tutarlı olmalı.
	if len(e.patRule)+len(e.alwaysEval) != len(e.rules) {
		t.Fatalf("patRule(%d)+alwaysEval(%d) != rules(%d)", len(e.patRule), len(e.alwaysEval), len(e.rules))
	}
}

// TestSelectAnchor, ankraj sezgiselini doğrudan sınar.
func TestSelectAnchor(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"  ", ""}, ""},
		{[]string{"nc", "encodedcommand", "cmd"}, "encodedcommand"}, // en uzun
		{[]string{"  padded  "}, "padded"},                          // trim
		{[]string{"eş", "eşit"}, "eşit"},
	}
	for _, c := range cases {
		if got := selectAnchor(c.in); got != c.want {
			t.Errorf("selectAnchor(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
