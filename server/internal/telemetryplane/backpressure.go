package telemetryplane

import (
	"context"
	"sync/atomic"
)

// Config represents configuration for BackpressureController.
type Config struct {
	MaxQueueDepth int
	HighWatermark float64
	MaxRPS        int
}

// BackpressureStats represents current metrics.
type BackpressureStats struct {
	DroppedEvents  uint64
	AcceptedEvents uint64
	SheddingMode   bool
	CurrentDepth   int
}

// BackpressureController manages high-throughput ingestion protection.
// Yüksek verimli veri alımını (ingestion) korumak için tasarlanmıştır.
type BackpressureController struct {
	config Config

	currentDepth   int64  // atomic
	droppedEvents  uint64 // atomic
	acceptedEvents uint64 // atomic
	sheddingMode   uint32 // atomic bool (0 or 1)
}

// NewBackpressureController creates a new BackpressureController instance.
func NewBackpressureController(cfg Config) *BackpressureController {
	if cfg.MaxQueueDepth <= 0 {
		cfg.MaxQueueDepth = 1000 // Varsayılan değer
	}
	if cfg.HighWatermark <= 0 || cfg.HighWatermark > 1 {
		cfg.HighWatermark = 0.8 // Varsayılan değer
	}
	return &BackpressureController{
		config: cfg,
	}
}

// Acquire attempts to allocate a slot for an event.
// Kuyruk doluluk oranına ve HighWatermark değerine göre shedding (atma) yapar.
func (c *BackpressureController) Acquire(ctx context.Context, priority string) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	for {
		depth := atomic.LoadInt64(&c.currentDepth)

		// Eğer kuyruk tamamen doluysa, tüm eventleri at (100% saturation hard drop)
		if depth >= int64(c.config.MaxQueueDepth) {
			atomic.AddUint64(&c.droppedEvents, 1)
			return false
		}

		usage := float64(depth) / float64(c.config.MaxQueueDepth)

		// High watermark aşıldıysa, düşük öncelikli eventleri at
		if usage >= c.config.HighWatermark {
			atomic.StoreUint32(&c.sheddingMode, 1)
			if priority != "HIGH" && priority != "CRITICAL" {
				atomic.AddUint64(&c.droppedEvents, 1)
				return false
			}
		} else {
			atomic.StoreUint32(&c.sheddingMode, 0)
		}

		// Yuvayı tahsis etmeyi dene (optimistic concurrency)
		if atomic.CompareAndSwapInt64(&c.currentDepth, depth, depth+1) {
			atomic.AddUint64(&c.acceptedEvents, 1)
			return true
		}
	}
}

// Release releases an allocated slot. It never drives the depth below zero: a
// single CAS loop decrements only when depth > 0, so concurrent releases (or an
// unbalanced release caused by misuse) cannot leave the counter negative. The
// previous form (unconditional AddInt64(-1) then a CompareAndSwap against the
// value it had just produced) was racy — a concurrent Acquire/Release between
// the add and the swap invalidated the clamp and could leave depth negative,
// which would make usage negative and silently disable shedding under load.
func (c *BackpressureController) Release() {
	for {
		depth := atomic.LoadInt64(&c.currentDepth)
		if depth <= 0 {
			return // zaten boş (veya dengesiz Release) — sıfırın altına inme
		}
		if atomic.CompareAndSwapInt64(&c.currentDepth, depth, depth-1) {
			return
		}
	}
}

// Stats returns the current metrics.
func (c *BackpressureController) Stats() BackpressureStats {
	return BackpressureStats{
		DroppedEvents:  atomic.LoadUint64(&c.droppedEvents),
		AcceptedEvents: atomic.LoadUint64(&c.acceptedEvents),
		SheddingMode:   atomic.LoadUint32(&c.sheddingMode) == 1,
		CurrentDepth:   int(atomic.LoadInt64(&c.currentDepth)),
	}
}
