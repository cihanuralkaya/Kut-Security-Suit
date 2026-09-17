package detect

import (
	"strings"
	"testing"

	"kut.corp/suite/server/internal/model"
)

// TestBitsParsingAndCarry, bit alanının JSON'dan yüklenip doğrulandığını ve
// Evaluate tarafından tespide taşındığını doğrular.
func TestBitsParsingAndCarry(t *testing.T) {
	valid := `[
	  {"id":"S1","name":"keşif","severity":"LOW","contains":["port taraması"],
	   "bits":{"set":["recon_seen"],"ttl_seconds":3600,"track":"device"}},
	  {"id":"S2","name":"yatay hareket","severity":"HIGH","contains":["yanal hareket"],
	   "bits":{"require":["recon_seen"]}}
	]`
	rules, err := LoadRules(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("geçerli bits yüklenemedi: %v", err)
	}
	e := NewEngine(rules)
	dets := e.Evaluate(model.Event{Category: "", Message: "yanal hareket tespiti", Severity: "HIGH"})
	if len(dets) != 1 || dets[0].Bits == nil || len(dets[0].Bits.Require) != 1 || dets[0].Bits.Require[0] != "recon_seen" {
		t.Fatalf("Evaluate bits.require taşımadı: %+v", dets)
	}

	// require_not tek başına geçerli olmalı (en az bir koşul sağlanır).
	if _, err := LoadRules(strings.NewReader(`[{"id":"RN","name":"n","severity":"HIGH","contains":["x"],"bits":{"require_not":["handled"]}}]`)); err != nil {
		t.Fatalf("require_not-only bits reddedildi: %v", err)
	}

	bad := []string{
		`[{"id":"X","name":"n","severity":"HIGH","bits":{}}]`,                             // ne require ne require_not ne set
		`[{"id":"X","name":"n","severity":"HIGH","bits":{"set":["a"],"ttl_seconds":-1}}]`, // negatif ttl
		`[{"id":"X","name":"n","severity":"HIGH","bits":{"set":["a"],"track":"galaxy"}}]`, // geçersiz track
	}
	for i, b := range bad {
		if _, err := LoadRules(strings.NewReader(b)); err == nil {
			t.Errorf("geçersiz bits[%d] kabul edildi", i)
		}
	}
}
