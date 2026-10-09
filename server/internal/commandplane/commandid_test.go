package commandplane

import (
	"regexp"
	"testing"
)

// uuidV4Re, kanonik UUIDv4 biçimini doğrular: 8-4-4-4-12 hex, 3. grup '4' ile başlar
// (sürüm), 4. grup [89ab] ile başlar (varyant).
var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewCommandID_UUIDv4(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := newCommandID()
		if err != nil {
			t.Fatalf("newCommandID: %v", err)
		}
		if !uuidV4Re.MatchString(id) {
			t.Fatalf("geçerli UUIDv4 değil: %q", id)
		}
		if seen[id] {
			t.Fatalf("çakışma: %q iki kez üretildi", id)
		}
		seen[id] = true
	}
}
