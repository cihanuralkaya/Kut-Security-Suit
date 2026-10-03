package telemetryplane

import (
	"context"
	"testing"
)

// BenchEvent represents a mocked security event for benchmark testing.
type BenchEvent struct {
	ID      string
	Payload []byte
}

// BenchTelemetryPlane is a mock telemetry plane for testing ingestion.
type BenchTelemetryPlane struct{}

func (tp *BenchTelemetryPlane) ProcessEvent(ctx context.Context, e *BenchEvent) error {
	// Simulate backpressure check and OCSF validation
	return nil
}

// BenchRuleEngine is a mock detection-as-code rule engine.
type BenchRuleEngine struct{}

func (re *BenchRuleEngine) Evaluate(e *BenchEvent) bool {
	// Simulate evaluation latency
	return false
}

// BenchEventBus is a mock pub/sub message bus with a bounded channel.
type BenchEventBus struct {
	ch chan *BenchEvent
}

func NewBenchEventBus(bufferSize int) *BenchEventBus {
	return &BenchEventBus{ch: make(chan *BenchEvent, bufferSize)}
}

func (eb *BenchEventBus) Publish(e *BenchEvent) {
	select {
	case eb.ch <- e:
	default: // Buffer shedding (drop if full)
	}
}

func BenchmarkTelemetryPlane_ProcessEvent(b *testing.B) {
	tp := &BenchTelemetryPlane{}
	ctx := context.Background()
	e := &BenchEvent{
		ID:      "evt-bench-001",
		Payload: []byte(`{"event_type": "authentication", "status": "success"}`),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tp.ProcessEvent(ctx, e)
	}
}

func BenchmarkRuleEngine_Evaluate(b *testing.B) {
	re := &BenchRuleEngine{}
	e := &BenchEvent{
		ID:      "evt-bench-001",
		Payload: []byte(`{"event_type": "network_traffic", "bytes_in": 1024}`),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = re.Evaluate(e)
	}
}

func BenchmarkEventBus_Publish(b *testing.B) {
	eb := NewBenchEventBus(10000)
	
	// Consumer goroutine to empty the channel
	go func() {
		for range eb.ch {
		}
	}()

	e := &BenchEvent{ID: "evt-bench-001"}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			eb.Publish(e)
		}
	})
}
