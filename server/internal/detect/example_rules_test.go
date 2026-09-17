package detect

import (
	"path/filepath"
	"runtime"
	"testing"

	"kut.corp/suite/server/internal/model"
)

// exampleRulesPath, depo-köküne göre örnek kural dosyasının yolunu bu test
// dosyasının konumundan türetir (CWD'den bağımsız, sağlam).
func exampleRulesPath() string {
	_, thisFile, _, _ := runtime.Caller(0) // .../server/internal/detect/example_rules_test.go
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "docs", "examples", "detection-rules.sample.json")
}

// TestExampleRulesValid, operatöre sunulan örnek kural dosyasının HER ZAMAN geçerli
// yüklendiğini ve motorca derlenebildiğini doğrular — şema geliştikçe belge
// örnekleri de CI ile kanıtlanmış kalır (bit-çürümesi engellenir).
func TestExampleRulesValid(t *testing.T) {
	rules, err := LoadRulesFile(exampleRulesPath())
	if err != nil {
		t.Fatalf("örnek kural dosyası geçersiz: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("örnek kural dosyası boş")
	}

	// Her yeni özelliğin en az bir örnekle temsil edildiğini doğrula (belge kapsamı).
	var hasThreshold, hasSequence, hasWithin, hasAbsent, hasBitsSet, hasBitsRequire, hasBitsRequireNot bool
	for _, r := range rules {
		if r.Threshold != nil {
			hasThreshold = true
		}
		if len(r.Sequence) > 0 {
			hasSequence = true
		}
		if r.WithinBytes > 0 {
			hasWithin = true
		}
		if len(r.Absent) > 0 {
			hasAbsent = true
		}
		if r.Bits != nil && len(r.Bits.Set) > 0 {
			hasBitsSet = true
		}
		if r.Bits != nil && len(r.Bits.Require) > 0 {
			hasBitsRequire = true
		}
		if r.Bits != nil && len(r.Bits.RequireNot) > 0 {
			hasBitsRequireNot = true
		}
	}
	for name, ok := range map[string]bool{
		"threshold": hasThreshold, "sequence": hasSequence, "within_bytes": hasWithin,
		"absent": hasAbsent, "bits.set": hasBitsSet, "bits.require": hasBitsRequire,
		"bits.require_not": hasBitsRequireNot,
	} {
		if !ok {
			t.Errorf("örnek kurallar %q özelliğini temsil etmiyor", name)
		}
	}

	// Motorca derlenebilmeli (ön-filtre kurulumu dahil) ve örnek bir olayı
	// değerlendirebilmeli (panik/regresyon yok).
	e := NewEngine(rules)
	_ = e.Evaluate(model.Event{Category: "PROCESS", Message: "powershell IEX DownloadString Invoke", Severity: "HIGH"})
}
