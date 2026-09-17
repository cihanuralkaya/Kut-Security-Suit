package detect

import (
	"testing"

	"kut.corp/suite/server/internal/model"
)

// TestAbsentExclusion, negatif içeriğin (Absent) eşleşmeyi dışladığını ve
// ön-filtreyle eşdeğerliğin korunduğunu doğrular.
func TestAbsentExclusion(t *testing.T) {
	rules := []Rule{
		// Pozitif ankraj (powershell) + dışlama (-signed): imzalı komut istisna.
		{ID: "PS-1", Name: "imzasız powershell", Category: "PROCESS",
			Contains: []string{"powershell"}, Absent: []string{"-signed"}, Severity: "HIGH"},
		// Yalnız-negatif kural: ankrajı yok → alwaysEval. "hata" içermeyen AUDIT olayları.
		{ID: "OK-1", Name: "temiz denetim", Category: "AUDIT",
			Absent: []string{"hata"}, Severity: "INFO"},
	}
	e := NewEngine(rules)

	// Yalnız-negatif kuralın ön-filtrelenemediğini (alwaysEval) doğrula.
	always := map[int]bool{}
	for _, i := range e.alwaysEval {
		always[i] = true
	}
	for i, c := range e.rules {
		if c.rule.ID == "OK-1" && !always[i] {
			t.Fatal("yalnız-negatif kural (OK-1) alwaysEval'de olmalı")
		}
	}

	events := []model.Event{
		{Category: "PROCESS", Message: "powershell -c whoami", Severity: "HIGH"},         // PS-1 eşleşir
		{Category: "PROCESS", Message: "powershell -Signed -c whoami", Severity: "HIGH"}, // PS-1 dışlanır
		{Category: "AUDIT", Message: "kullanıcı oturum açtı", Severity: "INFO"},          // OK-1 eşleşir
		{Category: "AUDIT", Message: "oturum açma hata verdi", Severity: "INFO"},         // OK-1 dışlanır
	}
	for i, ev := range events {
		want := linearEval(e, ev)
		got := e.Evaluate(ev)
		if len(want) != len(got) {
			t.Errorf("olay[%d] %q: Evaluate=%v linear=%v", i, ev.Message, got, want)
			continue
		}
		for j := range want {
			if want[j].RuleID != got[j].RuleID {
				t.Errorf("olay[%d] %q: Evaluate=%v linear=%v", i, ev.Message, got, want)
			}
		}
	}

	// Doğrudan davranış kontrolü: dışlama çalışıyor mu?
	if d := e.Evaluate(model.Event{Category: "PROCESS", Message: "powershell -Signed x", Severity: "HIGH"}); len(d) != 0 {
		t.Fatalf("imzalı powershell dışlanmalıydı, tespit: %v", d)
	}
	if d := e.Evaluate(model.Event{Category: "PROCESS", Message: "powershell x", Severity: "HIGH"}); len(d) != 1 || d[0].RuleID != "PS-1" {
		t.Fatalf("imzasız powershell PS-1 eşleşmeliydi: %v", d)
	}
}
