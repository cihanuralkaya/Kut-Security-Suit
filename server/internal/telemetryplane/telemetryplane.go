// Package telemetryplane is the export boundary (a "tap") for already-processed
// telemetry. It does NOT detect or gate: the gRPC/HTTP ingest path
// (grpc.AgentHandler.ProcessEvent) remains the single owner of detection and the
// shared suppression gate, and hands this plane its OUTCOME — the canonical event
// plus the detections the gate admitted. The plane projects that to the sinks
// (OCSF export) under priority-aware backpressure. Keeping detection out of the
// plane is deliberate: a second path calling the stateful gate would double-count
// threshold/correlation windows and silently drop alerts (see ADR-0040).
package telemetryplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

// AlertSink receives an admitted alert: the canonical event plus the detections
// that fired AND passed the gate. The sink owns any projection (e.g. OCSF).
type AlertSink interface {
	EmitAlert(ctx context.Context, evt model.Event, dets []detect.Detection) error
}

// EventSink receives every normalized canonical event. The sink owns projection.
type EventSink interface {
	EmitEvent(ctx context.Context, evt model.Event) error
}

// TapConfig tunes the export tap. (Distinct from the backpressure Config.)
type TapConfig struct {
	QueueDepth int    // buffered records before shedding (default 10000)
	Mode       string // "all" (default: events + alerts) or "findings" (alerts only)
}

// Record is one processed event handed to the tap.
type Record struct {
	Event    model.Event
	Admitted []detect.Detection
}

// Stats is a snapshot of tap counters.
type Stats struct {
	Dropped    uint64
	Accepted   uint64
	SinkErrors uint64
	Depth      int
}

// Plane is the export tap: a bounded queue drained by a single worker so
// per-device order is preserved, with backpressure that sheds raw telemetry
// before findings. It never blocks the caller and never fails ingest.
type Plane struct {
	alert AlertSink
	event EventSink
	mode  string
	bp    *BackpressureController

	ch   chan Record
	done chan struct{} // Stop sinyali: worker drain-then-exit (ch ASLA kapatılmaz)
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu      sync.RWMutex
	running bool

	dropped    uint64 // atomic
	accepted   uint64 // atomic
	sinkErrors uint64 // atomic
}

// New builds an export tap over the given sinks. Either sink may be nil (that
// projection is skipped). Pass the server's product/queue config via cfg.
func New(alert AlertSink, event EventSink, cfg TapConfig) *Plane {
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = 10000
	}
	return &Plane{
		alert: alert,
		event: event,
		mode:  cfg.Mode,
		bp:    NewBackpressureController(Config{MaxQueueDepth: cfg.QueueDepth, HighWatermark: 0.8}),
		ch:    make(chan Record, cfg.QueueDepth),
	}
}

// Start launches the drain worker. The worker runs under a context derived from
// ctx with cancellation removed, so a shutdown signal that cancels ctx does not
// abort an in-flight drain; Stop ends the worker deterministically.
func (p *Plane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return errors.New("telemetry plane is already running")
	}
	p.ctx, p.stop = context.WithCancel(context.WithoutCancel(ctx))
	p.done = make(chan struct{})
	p.running = true
	p.wg.Add(1)
	go p.run()
	return nil
}

// Stop signals the worker to drain what is buffered, then waits for it to exit.
// The queue channel is NEVER closed by the sender side: a concurrent
// ObserveProcessed that already passed the running check must never panic on a
// send to a closed channel. Stop flips running=false under the write lock first,
// so every in-flight enqueue (held under the read lock) completes before Stop
// proceeds and no enqueue happens afterwards — the records the worker drains are
// therefore final, with no send-on-closed-channel window.
func (p *Plane) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return errors.New("telemetry plane is not running")
	}
	p.running = false
	p.mu.Unlock()

	close(p.done)
	p.wg.Wait()
	if p.stop != nil {
		p.stop()
	}
	return nil
}

func (p *Plane) run() {
	defer p.wg.Done()
	for {
		select {
		case rec := <-p.ch:
			p.emit(rec)
		case <-p.done:
			// Drain whatever is still buffered (no more sends arrive once Stop set
			// running=false), then exit deterministically.
			for {
				select {
				case rec := <-p.ch:
					p.emit(rec)
				default:
					return
				}
			}
		}
	}
}

// emit projects one record to the configured sinks under the worker's drain
// context (p.ctx is not cancelled until Stop finishes waiting).
func (p *Plane) emit(rec Record) {
	if p.event != nil && p.mode != "findings" {
		if err := p.event.EmitEvent(p.ctx, rec.Event); err != nil {
			atomic.AddUint64(&p.sinkErrors, 1)
		}
	}
	if len(rec.Admitted) > 0 && p.alert != nil {
		if err := p.alert.EmitAlert(p.ctx, rec.Event, rec.Admitted); err != nil {
			atomic.AddUint64(&p.sinkErrors, 1)
		}
	}
	p.bp.Release()
}

// ObserveProcessed is the tap entry: the ingest path calls it AFTER detection and
// gating with the server-bound deviceID, the canonical event, and the admitted
// detections. It stamps the device id, applies priority-aware backpressure
// (findings are HIGH, raw telemetry INFO so telemetry sheds first), and enqueues
// without blocking. Before Start or after Stop, or when shedding, the call is a
// counted drop — it never blocks ingest and never panics.
func (p *Plane) ObserveProcessed(ctx context.Context, deviceID string, e model.Event, admitted []detect.Detection) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()
	if !running {
		atomic.AddUint64(&p.dropped, 1)
		return
	}

	e.DeviceID = deviceID
	prio := "INFO"
	if len(admitted) > 0 {
		prio = "HIGH"
	}
	if !p.bp.Acquire(ctx, prio) {
		atomic.AddUint64(&p.dropped, 1)
		return
	}

	// Enqueue under the read lock and re-check running. Stop takes the write lock
	// to flip running=false before signalling drain, so this enqueue either
	// completes before Stop proceeds or is dropped here once running is false —
	// the channel is never closed under a live sender (no send-on-closed panic),
	// and every accepted record is drained. Acquire is non-blocking, and the send
	// below is non-blocking (select/default), so holding the read lock cannot
	// deadlock Stop.
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.running {
		p.bp.Release()
		atomic.AddUint64(&p.dropped, 1)
		return
	}
	select {
	case p.ch <- Record{Event: e, Admitted: admitted}:
		atomic.AddUint64(&p.accepted, 1)
	default:
		// Queue full despite the reservation (e.g. racing Stop): release and drop.
		p.bp.Release()
		atomic.AddUint64(&p.dropped, 1)
	}
}

// Stats returns a snapshot of the tap counters.
func (p *Plane) Stats() Stats {
	return Stats{
		Dropped:    atomic.LoadUint64(&p.dropped),
		Accepted:   atomic.LoadUint64(&p.accepted),
		SinkErrors: atomic.LoadUint64(&p.sinkErrors),
		Depth:      p.bp.Stats().CurrentDepth,
	}
}
