package telemetryplane

import (
	"context"
	"errors"
	"sync"

	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/telemetryschema"
)

// Detector defines the interface for evaluating events against detection rules.
type Detector interface {
	Evaluate(evt model.Event) []Rule
}

// AlertSink is the interface for emitting events that triggered an alert.
type AlertSink interface {
	EmitAlert(ctx context.Context, evt telemetryschema.Event) error
}

// EventSink is the interface for emitting normalized events.
type EventSink interface {
	EmitEvent(ctx context.Context, evt telemetryschema.Event) error
}

// Plane orchestrates event ingestion, normalization, detection, and routing.
type Plane struct {
	detector  Detector
	alertSink AlertSink
	eventSink EventSink
	product   telemetryschema.Product

	mu      sync.RWMutex
	running bool
}

// New creates a new Telemetry Plane.
func New(detector Detector, alertSink AlertSink, eventSink EventSink) *Plane {
	return &Plane{
		detector:  detector,
		alertSink: alertSink,
		eventSink: eventSink,
		product: telemetryschema.Product{
			Name:       "KUT Security Suit",
			VendorName: "KUT",
			Version:    "1.0.0",
		},
	}
}

// SetProduct allows customizing the OCSF metadata product.
func (p *Plane) SetProduct(prod telemetryschema.Product) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.product = prod
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

// ProcessEvent takes a canonical model event, evaluates rules with detector,
// normalizes to OCSF, and emits to sinks.
func (p *Plane) ProcessEvent(ctx context.Context, evt model.Event) (telemetryschema.Event, error) {
	p.mu.RLock()
	running := p.running
	prod := p.product
	p.mu.RUnlock()

	if !running {
		return telemetryschema.Event{}, errors.New("telemetry plane is not running")
	}

	// 1. Evaluate with detector
	matchedRules := p.detector.Evaluate(evt)
	isAlert := len(matchedRules) > 0

	// 2. Normalize to OCSF
	ocsfEvent := telemetryschema.ToOCSF(evt, prod)
	// Assuming ToOCSF returns telemetryschema.Event and doesn't return an error.
	// If it returns (telemetryschema.Event, error), we might need to adjust this.
	// For now, assuming a simple conversion based on prompt: Normalizer to OCSF (`telemetryschema.ToOCSF`)

	// 3. Emit to Event Sink
	if p.eventSink != nil {
		if err := p.eventSink.EmitEvent(ctx, ocsfEvent); err != nil {
			return ocsfEvent, err
		}
	}

	// 4. Emit to Alert Sink if detection triggered
	if isAlert && p.alertSink != nil {
		if err := p.alertSink.EmitAlert(ctx, ocsfEvent); err != nil {
			return ocsfEvent, err
		}
	}

	return ocsfEvent, nil
}

// IngestBatch processes multiple events in a batch.
func (p *Plane) IngestBatch(ctx context.Context, events []model.Event) ([]telemetryschema.Event, error) {
	p.mu.RLock()
	running := p.running
	p.mu.RUnlock()

	if !running {
		return nil, errors.New("telemetry plane is not running")
	}

	var results []telemetryschema.Event
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
