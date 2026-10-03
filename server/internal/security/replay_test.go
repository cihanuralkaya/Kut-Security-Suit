package security

import (
	"testing"
	"time"
)

func TestReplayProtector(t *testing.T) {
	window := 5 * time.Minute
	skew := 1 * time.Minute

	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	rp := NewReplayProtector(window, skew)
	rp.nowFunc = func() time.Time { return now }

	t.Run("fresh unique nonce", func(t *testing.T) {
		err := rp.CheckAndRecord("tenant1", "device1", "nonce1", now)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("duplicate nonce", func(t *testing.T) {
		err := rp.CheckAndRecord("tenant1", "device1", "nonce1", now)
		if err != ErrReplayDetected {
			t.Errorf("expected ErrReplayDetected, got %v", err)
		}
	})

	t.Run("stale timestamp", func(t *testing.T) {
		staleTime := now.Add(-6 * time.Minute)
		err := rp.CheckAndRecord("tenant1", "device1", "nonce2", staleTime)
		if err != ErrMessageTooOld {
			t.Errorf("expected ErrMessageTooOld, got %v", err)
		}
	})

	t.Run("future timestamp", func(t *testing.T) {
		futureTime := now.Add(2 * time.Minute)
		err := rp.CheckAndRecord("tenant1", "device1", "nonce3", futureTime)
		if err != ErrMessageFromFuture {
			t.Errorf("expected ErrMessageFromFuture, got %v", err)
		}
	})

	t.Run("tenant and device isolation", func(t *testing.T) {
		// Same nonce, different device
		err := rp.CheckAndRecord("tenant1", "device2", "nonce1", now)
		if err != nil {
			t.Errorf("expected no error for different device, got %v", err)
		}

		// Same nonce, different tenant
		err = rp.CheckAndRecord("tenant2", "device1", "nonce1", now)
		if err != nil {
			t.Errorf("expected no error for different tenant, got %v", err)
		}
	})

	t.Run("nonce eviction", func(t *testing.T) {
		// Sweep with a time 6 minutes in the future
		futureNow := now.Add(6 * time.Minute)
		rp.Sweep(futureNow)

		// After sweeping, the original nonce1 should be accepted again, assuming the time is also valid.
		// Update mock time to futureNow so it's not rejected as too old
		rp.nowFunc = func() time.Time { return futureNow }
		err := rp.CheckAndRecord("tenant1", "device1", "nonce1", futureNow)
		if err != nil {
			t.Errorf("expected nonce to be evicted and accepted again, got error: %v", err)
		}
	})
}
