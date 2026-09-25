package memstore

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/admin"
)

// TestConsumeTOTPStep, TOTP tek-kullanım (anti-replay) CAS davranışını doğrular: artan adım
// kabul edilir; aynı veya eski adım reddedilir; bilinmeyen admin reddedilir.
func TestConsumeTOTPStep(t *testing.T) {
	ctx := context.Background()
	s := New()
	id := s.SeedAdmin("op@x", "hash", admin.RoleOperator)

	if ok, _ := s.ConsumeTOTPStep(ctx, id, 100); !ok {
		t.Fatal("ilk (artan) adım kabul edilmeli")
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, id, 100); ok {
		t.Fatal("aynı adım tekrar reddedilmeli (replay)")
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, id, 99); ok {
		t.Fatal("eski adım reddedilmeli (rollback)")
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, id, 101); !ok {
		t.Fatal("daha büyük adım kabul edilmeli")
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, "unknown", 1); ok {
		t.Fatal("bilinmeyen admin reddedilmeli")
	}
}
