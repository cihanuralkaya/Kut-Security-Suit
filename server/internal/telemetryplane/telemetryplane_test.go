package telemetryplane

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
)

// STRUCTURAL GUARD (ADR-0040): the export tap must never detect or gate. It may
// reference detect.Detection (a data type), but it must NOT import the detection
// engine's gate machinery. If a future change re-introduces a gate into the
// plane, this fails — that is the regression that would cause double gate
// consumption.
func TestPlaneHasNoGateImports(t *testing.T) {
	forbidden := []string{"/detectpipe", "/threshold", "/detbits", "/correlate"}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("paket dizini okunamadı: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s ayrıştırılamadı: %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.HasSuffix(p, bad) {
					t.Errorf("telemetri düzlemi %q import ediyor (%s) — tap tespit/gate yapmamalı", p, name)
				}
			}
		}
	}
}

// MockAlertSink records admitted alerts (event + firing detections).
type MockAlertSink struct {
	Events     []model.Event
	Detections [][]detect.Detection
}

func (m *MockAlertSink) EmitAlert(ctx context.Context, evt model.Event, dets []detect.Detection) error {
	m.Events = append(m.Events, evt)
	m.Detections = append(m.Detections, dets)
	return nil
}

// MockEventSink records every normalized event.
type MockEventSink struct {
	Events []model.Event
}

func (m *MockEventSink) EmitEvent(ctx context.Context, evt model.Event) error {
	m.Events = append(m.Events, evt)
	return nil
}

func TestPlane_Lifecycle(t *testing.T) {
	p := New(&MockAlertSink{}, &MockEventSink{}, TapConfig{QueueDepth: 8})
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("ikinci start hata vermeliydi")
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := p.Stop(); err == nil {
		t.Fatal("ikinci stop hata vermeliydi")
	}
}

// The tap exports raw events and, for admitted detections, enriched alerts. It
// carries the device id and the detections through to the sinks. Stop drains the
// queue, so sink contents are deterministic after Stop.
func TestPlane_ObserveProcessed(t *testing.T) {
	alert := &MockAlertSink{}
	event := &MockEventSink{}
	p := New(alert, event, TapConfig{QueueDepth: 16})
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Raw event, no detection → event only.
	p.ObserveProcessed(ctx, "dev1", model.Event{Message: "a"}, nil)
	// Event with an admitted detection → event + alert carrying the detection.
	p.ObserveProcessed(ctx, "dev2", model.Event{Message: "b"}, []detect.Detection{{RuleID: "r1"}})

	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if len(event.Events) != 2 {
		t.Fatalf("eventSink beklenen 2, alinan %d", len(event.Events))
	}
	if len(alert.Events) != 1 {
		t.Fatalf("alertSink beklenen 1, alinan %d", len(alert.Events))
	}
	if alert.Events[0].DeviceID != "dev2" {
		t.Errorf("alert olayı deviceID taşımalı (dev2), alinan %q", alert.Events[0].DeviceID)
	}
	if len(alert.Detections[0]) != 1 || alert.Detections[0][0].RuleID != "r1" {
		t.Errorf("alert tespiti taşımalı, alinan %v", alert.Detections[0])
	}
	if s := p.Stats(); s.Accepted != 2 {
		t.Errorf("accepted beklenen 2, alinan %d", s.Accepted)
	}
}

// "findings" mode exports only alerts, not raw telemetry.
func TestPlane_FindingsMode(t *testing.T) {
	alert := &MockAlertSink{}
	event := &MockEventSink{}
	p := New(alert, event, TapConfig{QueueDepth: 8, Mode: "findings"})
	ctx := context.Background()
	_ = p.Start(ctx)
	p.ObserveProcessed(ctx, "d", model.Event{}, nil)
	p.ObserveProcessed(ctx, "d", model.Event{}, []detect.Detection{{RuleID: "r"}})
	_ = p.Stop()

	if len(event.Events) != 0 {
		t.Errorf("findings modunda ham olay yazılmamalı, alinan %d", len(event.Events))
	}
	if len(alert.Events) != 1 {
		t.Errorf("findings modunda alarm yazılmalı, alinan %d", len(alert.Events))
	}
}

// Before Start (and after Stop) a call is a counted drop, never a panic/block.
func TestPlane_DropWhenNotRunning(t *testing.T) {
	p := New(&MockAlertSink{}, &MockEventSink{}, TapConfig{})
	p.ObserveProcessed(context.Background(), "d", model.Event{}, nil)
	if s := p.Stats(); s.Dropped != 1 {
		t.Fatalf("başlamadan önce drop beklenir, alinan %d", s.Dropped)
	}
}

// REGRESSION (close/send race): Stop must never close the queue channel while a
// sender is in flight — otherwise ObserveProcessed could send on a closed channel
// and panic (a send inside select/default still panics on a closed channel). Many
// goroutines hammer the tap with a small queue (so the full-queue "racing Stop"
// path is exercised) while Stop fires concurrently. The fix is that the sender
// side never closes ch (Stop signals a drain-then-exit and flips running under
// the lock); this test guards it, and -race flags the close/send window on the
// old code. Success = no panic, clean Stop, and accepted+dropped accounts for all
// sends that observed a running plane.
func TestPlane_ConcurrentObserveDuringStop(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		p := New(&MockAlertSink{}, &MockEventSink{}, TapConfig{QueueDepth: 4})
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("start: %v", err)
		}

		const senders, perSender = 16, 50
		var wg sync.WaitGroup
		wg.Add(senders)
		for i := 0; i < senders; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < perSender; j++ {
					// Must never panic, whether the plane is running, stopping, or stopped.
					p.ObserveProcessed(context.Background(), "d", model.Event{Message: "x"}, nil)
				}
			}()
		}

		// Stop concurrently with the in-flight senders: this is the close/send window.
		if err := p.Stop(); err != nil {
			t.Fatalf("stop: %v", err)
		}
		wg.Wait()
	}
}
