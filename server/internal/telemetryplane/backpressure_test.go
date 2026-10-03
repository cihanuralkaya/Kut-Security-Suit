package telemetryplane

import (
	"context"
	"sync"
	"testing"
)

func TestNormalIngestion(t *testing.T) {
	cfg := Config{MaxQueueDepth: 10, HighWatermark: 0.8}
	c := NewBackpressureController(cfg)
	ctx := context.Background()

	// Should accept up to 7 without shedding (usage 7/10 = 0.7 < 0.8)
	for i := 0; i < 7; i++ {
		if !c.Acquire(ctx, "INFO") {
			t.Errorf("Expected to acquire, but failed at %d", i)
		}
	}

	stats := c.Stats()
	if stats.SheddingMode {
		t.Errorf("Expected SheddingMode to be false")
	}
	if stats.AcceptedEvents != 7 {
		t.Errorf("Expected 7 accepted events, got %d", stats.AcceptedEvents)
	}
}

func TestHighWatermarkShedding(t *testing.T) {
	cfg := Config{MaxQueueDepth: 10, HighWatermark: 0.8}
	c := NewBackpressureController(cfg)
	ctx := context.Background()

	// Fill queue to 80% (8/10)
	for i := 0; i < 8; i++ {
		c.Acquire(ctx, "INFO")
	}

	// Next low-priority event should be shed
	if c.Acquire(ctx, "INFO") {
		t.Errorf("Expected INFO to be shed")
	}

	// But high-priority event should be accepted
	if !c.Acquire(ctx, "HIGH") {
		t.Errorf("Expected HIGH to be accepted")
	}
	if !c.Acquire(ctx, "CRITICAL") {
		t.Errorf("Expected CRITICAL to be accepted")
	}

	stats := c.Stats()
	if !stats.SheddingMode {
		t.Errorf("Expected SheddingMode to be true")
	}
	// 8 initial + 2 high priority = 10 accepted
	if stats.AcceptedEvents != 10 {
		t.Errorf("Expected 10 accepted events, got %d", stats.AcceptedEvents)
	}
	if stats.DroppedEvents != 1 {
		t.Errorf("Expected 1 dropped event, got %d", stats.DroppedEvents)
	}
}

func TestSaturationHardDrop(t *testing.T) {
	cfg := Config{MaxQueueDepth: 10, HighWatermark: 0.8}
	c := NewBackpressureController(cfg)
	ctx := context.Background()

	// Fill queue completely (10/10)
	for i := 0; i < 10; i++ {
		c.Acquire(ctx, "CRITICAL")
	}

	// 100% full, even critical events should drop
	if c.Acquire(ctx, "CRITICAL") {
		t.Errorf("Expected CRITICAL to be dropped at 100%% capacity")
	}

	stats := c.Stats()
	if stats.DroppedEvents != 1 {
		t.Errorf("Expected 1 dropped event, got %d", stats.DroppedEvents)
	}
}

func TestThreadSafety(t *testing.T) {
	cfg := Config{MaxQueueDepth: 1000, HighWatermark: 0.8}
	c := NewBackpressureController(cfg)
	ctx := context.Background()
	var wg sync.WaitGroup

	// Run goroutines acquiring and releasing concurrently
	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func(priority string) {
			defer wg.Done()
			if c.Acquire(ctx, priority) {
				c.Release()
			}
		}("INFO")
	}

	wg.Wait()

	stats := c.Stats()
	if stats.CurrentDepth != 0 {
		t.Errorf("Expected depth 0, got %d", stats.CurrentDepth)
	}
}
