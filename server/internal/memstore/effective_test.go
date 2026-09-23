package memstore

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/model"
)

func deviceStatus(s *Store, dev string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[dev]; ok {
		return d.status
	}
	return ""
}

// TestApplyCommandResults_EffectiveState, F-D effective-state geçişini doğrular:
// başarılı QUARANTINE → QUARANTINED; başarısız sonuç durumu değiştirmez; başarılı
// UNQUARANTINE → ACTIVE.
func TestApplyCommandResults_EffectiveState(t *testing.T) {
	s := New()
	ctx := context.Background()
	dev := enrollDevice(t, s)

	if err := s.ApplyCommandResults(ctx, dev, []model.CommandOutcome{{CommandID: "c1", Type: "QUARANTINE", OK: true}}); err != nil {
		t.Fatal(err)
	}
	if st := deviceStatus(s, dev); st != "QUARANTINED" {
		t.Fatalf("başarılı QUARANTINE effective QUARANTINED olmalı: %q", st)
	}

	_ = s.ApplyCommandResults(ctx, dev, []model.CommandOutcome{{CommandID: "c2", Type: "UNQUARANTINE", OK: false}})
	if st := deviceStatus(s, dev); st != "QUARANTINED" {
		t.Fatalf("başarısız sonuç durumu değiştirmemeli: %q", st)
	}

	_ = s.ApplyCommandResults(ctx, dev, []model.CommandOutcome{{CommandID: "c3", Type: "UNQUARANTINE", OK: true}})
	if st := deviceStatus(s, dev); st != "ACTIVE" {
		t.Fatalf("başarılı UNQUARANTINE ACTIVE olmalı: %q", st)
	}
}
