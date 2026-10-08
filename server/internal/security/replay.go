package security

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrMessageTooOld     = errors.New("message timestamp too old")
	ErrMessageFromFuture = errors.New("message timestamp too far in future")
	ErrReplayDetected    = errors.New("nonce replay detected")
)

// ReplayProtector provides sliding-window and nonce-based replay protection.
// It ensures that messages are within an acceptable time window and have not been seen before.
type ReplayProtector struct {
	mu      sync.RWMutex
	window  time.Duration
	skew    time.Duration
	seen    map[string]time.Time
	nowFunc func() time.Time
}

// NewReplayProtector creates a new ReplayProtector with the specified window and clock skew tolerance.
func NewReplayProtector(window, skew time.Duration) *ReplayProtector {
	return &ReplayProtector{
		window:  window,
		skew:    skew,
		seen:    make(map[string]time.Time),
		nowFunc: time.Now,
	}
}

// CheckAndRecord validates the timestamp and nonce.
// It returns an error if the timestamp is out of bounds or if the nonce is a duplicate.
func (rp *ReplayProtector) CheckAndRecord(tenantID, deviceID, nonce string, ts time.Time) error {
	now := rp.nowFunc()

	if now.Sub(ts) > rp.window {
		return ErrMessageTooOld
	}
	if ts.Sub(now) > rp.skew {
		return ErrMessageFromFuture
	}

	key := fmt.Sprintf("%s:%s:%s", tenantID, deviceID, nonce)

	rp.mu.Lock()
	defer rp.mu.Unlock()

	if _, exists := rp.seen[key]; exists {
		return ErrReplayDetected
	}

	rp.seen[key] = ts
	return nil
}

// Sweep removes expired nonces from the cache based on the provided time.
// This should be called periodically to free up memory.
func (rp *ReplayProtector) Sweep(now time.Time) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	for k, ts := range rp.seen {
		if now.Sub(ts) > rp.window {
			delete(rp.seen, k)
		}
	}
}
