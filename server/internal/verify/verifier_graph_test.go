package verify

import "testing"

// containedSet, verilen kimlikleri kontrol-altında sayan bir oracle üretir.
func containedSet(ids ...string) func(string) bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return func(d string) bool { return m[d] }
}

func TestEvaluateGraphContainment(t *testing.T) {
	base := Check{ID: "chk-1", TenantID: "t1", Kind: KindGraphContainment, Baseline: 100}

	// Graf verisi yok → INCONCLUSIVE (fail-closed), residual=baseline.
	if o, r := EvaluateGraphContainment(base, false, nil, containedSet()); o != OutcomeInconclusive || r != 100 {
		t.Errorf("veri yokken INCONCLUSIVE/100 bekleniyordu: %s/%d", o, r)
	}

	// Akran yok → tek-cihaz remediasyonu kapsamı tamamlar → VERIFIED.
	if o, r := EvaluateGraphContainment(base, true, nil, containedSet()); o != OutcomeVerified || r > 100 {
		t.Errorf("akran yokken VERIFIED bekleniyordu: %s/%d", o, r)
	}

	// Tüm akranlar kontrol-altında → VERIFIED.
	peers := []string{"dev-2", "dev-3"}
	if o, r := EvaluateGraphContainment(base, true, peers, containedSet("dev-2", "dev-3")); o != OutcomeVerified || r > 100 {
		t.Errorf("tüm akranlar kontrol-altındayken VERIFIED bekleniyordu: %s/%d", o, r)
	}

	// 4 akrandan 2'si açıkta → REGRESSED, residual = 100*2/4 = 50.
	four := []string{"dev-2", "dev-3", "dev-4", "dev-5"}
	if o, r := EvaluateGraphContainment(base, true, four, containedSet("dev-2", "dev-3")); o != OutcomeRegressed || r != 50 {
		t.Errorf("2/4 açıkta → REGRESSED/50 bekleniyordu: %s/%d", o, r)
	}

	// Tümü açıkta → REGRESSED, residual = baseline (100).
	if o, r := EvaluateGraphContainment(base, true, peers, containedSet()); o != OutcomeRegressed || r != 100 {
		t.Errorf("tümü açıkta → REGRESSED/100 bekleniyordu: %s/%d", o, r)
	}

	// Oracle nil → containment kanıtlanamaz → tümü açıkta sayılır → REGRESSED.
	if o, r := EvaluateGraphContainment(base, true, peers, nil); o != OutcomeRegressed || r != 100 {
		t.Errorf("oracle nil → REGRESSED/100 (fail-closed) bekleniyordu: %s/%d", o, r)
	}
}

// TestEvaluateGraphContainment_ResidualFloor, çok sayıda akrandan yalnız biri açıkta
// kaldığında residual'ın 0'a yuvarlanmayıp en az 1 kaldığını doğrular (sinyal kaybolmaz).
func TestEvaluateGraphContainment_ResidualFloor(t *testing.T) {
	base := Check{Kind: KindGraphContainment, Baseline: 10}
	peers := make([]string, 100)
	okIDs := make([]string, 0, 99)
	for i := 0; i < 100; i++ {
		id := "dev-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		peers[i] = id
		if i != 0 { // ilki açıkta, kalan 99 kontrol-altında
			okIDs = append(okIDs, id)
		}
	}
	o, r := EvaluateGraphContainment(base, true, peers, containedSet(okIDs...))
	// 10*1/100 = 0 → taban 1'e yükselir.
	if o != OutcomeRegressed || r != 1 {
		t.Errorf("1/100 açıkta → REGRESSED/1 (taban) bekleniyordu: %s/%d", o, r)
	}
}
