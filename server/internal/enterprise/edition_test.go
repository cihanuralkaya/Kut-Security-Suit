package enterprise

import "testing"

// TestEditionSet, her iki tier'da da (Lite stub: "Lite" / enterprise: "Enterprise") Edition
// sabitinin tanımlı olduğunu doğrular — build-tier deseninin iki dalının da derlendiğinin
// tier-nötr kanıtı.
func TestEditionSet(t *testing.T) {
	if Edition == "" {
		t.Fatal("Edition boş olmamalı")
	}
	if Edition != "Lite" && Edition != "Enterprise" {
		t.Fatalf("beklenmeyen Edition: %q", Edition)
	}
}
