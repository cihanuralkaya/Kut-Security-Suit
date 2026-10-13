package telemetryplane

import (
	"context"
	"errors"
	"sync"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

// Detector evaluates a canonical event against detection rules. `*detect.Engine`
// satisfies this verbatim — the plane reuses the ONE live engine, never a copy.
type Detector interface {
	Evaluate(evt model.Event) []detect.Detection
}

// Gate decides whether a raw detection becomes an alert by running the shared
// server-side suppression gates (bits + repeat-threshold + correlation).
// `*detectpipe.Gate` satisfies this. The plane MUST route every detection
// through the same gate instance the gRPC/HTTP ingest paths use, so it can never
// become a second, ungated alert path (if the detection would be suppressed on
// the live path, it is suppressed here too). A nil gate means no suppression is
// configured (same semantics as a live server with no correlator/threshold),
// never "skip the gate when one exists".
type Gate interface {
	Admit(ctx context.Context, deviceID string, e model.Event, d detect.Detection) bool
}

// AlertSink receives the canonical event together with the detections that fired
// AND passed the gate. The sink owns any projection (e.g. OCSF) — the plane does
// not convert, so no detection context is lost before the boundary.
type AlertSink interface {
	EmitAlert(ctx context.Context, evt model.Event, dets []detect.Detection) error
}

// EventSink receives every normalized canonical event (whether or not it
// triggered a detection). The sink owns any projection to an export schema.
type EventSink interface {
	EmitEvent(ctx context.Context, evt model.Event) error
}

// Plane orchestrates event ingestion, detection, gating, and routing. It carries
// no detection logic of its own: detection is the live engine (Detector),
// suppression is the shared gate (Gate), and schema projection is the sink's job.
type Plane struct {
	detector  Detector
	gate      Gate
	alertSink AlertSink
	eventSink EventSink

	mu      sync.RWMutex
	running bool
}

// New creates a Telemetry Plane over the live detection engine, the shared
// suppression gate, and the configured sinks. Pass the server's single gate
// instance so the plane shares suppression state with the other ingest paths.
func New(detector Detector, gate Gate, alertSink AlertSink, eventSink EventSink) *Plane {
	return &Plane{
		detector:  detector,
		gate:      gate,
		alertSink: alertSink,
		eventSink: eventSink,
	}
}

// Start initializes and starts the telemetry plane lifecycle.
func (p *Plane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return errors.New("telemetry plane is already running")
	}
	p.running = true
	return nil
}

// Stop halts the telemetry plane lifecycle.
func (p *Plane) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return errors.New("telemetry plane is not running")
	}
	p.running = false
	return nil
}

// ProcessEvent runs one canonical event through the pipeline: emit it to the
// event sink, evaluate it with the live detection engine, pass each detection
// through the shared suppression gate, and emit an alert (with the admitted
// detections) only for detections the gate admits. It returns the event it
// processed. Emitting raw telemetry never fails the whole call on an alert-sink
// error, but a sink error is surfaced.
func (p *Plane) ProcessEvent(ctx context.Context, evt model.Event) (model.Event, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()

	if !running {
		return model.Event{}, errors.New("telemetry plane is not running")
	}

	// 1. Emit every normalized event to the event sink.
	if p.eventSink != nil {
		if err := p.eventSink.EmitEvent(ctx, evt); err != nil {
			return evt, err
		}
	}

	// 2. Evaluate with the LIVE detection engine.
	matched := p.detector.Evaluate(evt)

	// 3. Gate each detection through the SHARED suppression gate. A detection the
	// gate suppresses never becomes an alert — the plane cannot raise an alert the
	// live path would have gated. A nil gate means no suppression is configured.
	var admitted []detect.Detection
	for _, d := range matched {
		if p.gate == nil || p.gate.Admit(ctx, evt.DeviceID, evt, d) {
			admitted = append(admitted, d)
		}
	}

	// 4. Emit an alert (with the admitted detections) if any survived the gate.
	if len(admitted) > 0 && p.alertSink != nil {
		if err := p.alertSink.EmitAlert(ctx, evt, admitted); err != nil {
			return evt, err
		}
	}

	return evt, nil
}

// IngestBatch processes multiple events in a batch.
func (p *Plane) IngestBatch(ctx context.Context, events []model.Event) ([]model.Event, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()

	if !running {
		return nil, errors.New("telemetry plane is not running")
	}

	var results []model.Event
	var errs []error

	for _, evt := range events {
		res, err := p.ProcessEvent(ctx, evt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, res)
	}

	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}

	return results, nil
}
