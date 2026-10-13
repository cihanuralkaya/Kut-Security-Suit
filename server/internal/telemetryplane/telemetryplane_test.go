package telemetryplane

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/detbits"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/detectpipe"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/threshold"
)

// Compile-time proof that the LIVE detection engine satisfies the plane's
// Detector seam and the SHARED suppression gate satisfies the Gate seam. This is
// the core of the convergence: the plane reuses the ONE live engine and the ONE
// shared gate, never duplicates. If either breaks, the fork has crept back in.
var (
	_ Detector = (*detect.Engine)(nil)
	_ Gate     = (*detectpipe.Gate)(nil)
)

// MockDetector implements Detector for testing.
type MockDetector struct {
	EvaluateFunc func(evt model.Event) []detect.Detection
}

func (m *MockDetector) Evaluate(evt model.Event) []detect.Detection {
	if m.EvaluateFunc != nil {
		return m.EvaluateFunc(evt)
	}
	return nil
}

// MockAlertSink implements AlertSink; it records the canonical event and the
// admitted detections for each alert.
type MockAlertSink struct {
	Events     []model.Event
	Detections [][]detect.Detection
	Err        error
}

func (m *MockAlertSink) EmitAlert(ctx context.Context, evt model.Event, dets []detect.Detection) error {
	if m.Err != nil {
		return m.Err
	}
	m.Events = append(m.Events, evt)
	m.Detections = append(m.Detections, dets)
	return nil
}

// MockEventSink implements EventSink.
type MockEventSink struct {
	Events []model.Event
	Err    error
}

func (m *MockEventSink) EmitEvent(ctx context.Context, evt model.Event) error {
	if m.Err != nil {
		return m.Err
	}
	m.Events = append(m.Events, evt)
	return nil
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestTelemetryPlane_Lifecycle(t *testing.T) {
	plane := New(&MockDetector{}, nil, &MockAlertSink{}, &MockEventSink{})
	ctx := context.Background()

	// Should not be able to process before start
	if _, err := plane.ProcessEvent(ctx, model.Event{}); err == nil {
		t.Fatal("beklenen hata alınmadı: process event without start")
	}
	if err := plane.Start(ctx); err != nil {
		t.Fatalf("beklenmeyen hata: start %v", err)
	}
	if err := plane.Start(ctx); err == nil {
		t.Fatal("beklenen hata alınmadı: start when already running")
	}
	if err := plane.Stop(); err != nil {
		t.Fatalf("beklenmeyen hata: stop %v", err)
	}
	if err := plane.Stop(); err == nil {
		t.Fatal("beklenen hata alınmadı: stop when not running")
	}
}

// With a nil gate (no suppression configured) a detection becomes an alert, and
// the alert carries the firing detections (nothing is dropped).
func TestTelemetryPlane_ProcessEvent(t *testing.T) {
	evalCount := 0
	detector := &MockDetector{
		EvaluateFunc: func(evt model.Event) []detect.Detection {
			evalCount++
			if evalCount == 2 { // sadece 2. event'te tespit üret
				return []detect.Detection{{RuleID: "r1", RuleName: "test"}}
			}
			return nil
		},
	}
	alertSink := &MockAlertSink{}
	eventSink := &MockEventSink{}

	plane := New(detector, nil, alertSink, eventSink)
	ctx := context.Background()
	_ = plane.Start(ctx)

	t.Run("Normal event without alert", func(t *testing.T) {
		if _, err := plane.ProcessEvent(ctx, model.Event{}); err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
		if len(eventSink.Events) != 1 {
			t.Errorf("eventSink beklenen 1, alinan %d", len(eventSink.Events))
		}
		if len(alertSink.Events) != 0 {
			t.Errorf("alertSink beklenen 0, alinan %d", len(alertSink.Events))
		}
	})

	t.Run("Event with alert carries the detection", func(t *testing.T) {
		if _, err := plane.ProcessEvent(ctx, model.Event{}); err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
		if len(eventSink.Events) != 2 {
			t.Errorf("eventSink beklenen 2, alinan %d", len(eventSink.Events))
		}
		if len(alertSink.Events) != 1 {
			t.Fatalf("alertSink beklenen 1, alinan %d", len(alertSink.Events))
		}
		if len(alertSink.Detections[0]) != 1 || alertSink.Detections[0][0].RuleID != "r1" {
			t.Errorf("alert tespiti taşımalıydı, alinan %v", alertSink.Detections[0])
		}
	})
}

func TestTelemetryPlane_IngestBatch(t *testing.T) {
	evalCount := 0
	detector := &MockDetector{
		EvaluateFunc: func(evt model.Event) []detect.Detection {
			evalCount++
			if evalCount == 2 {
				return []detect.Detection{{RuleID: "r1"}}
			}
			return nil
		},
	}
	alertSink := &MockAlertSink{}
	eventSink := &MockEventSink{}

	plane := New(detector, nil, alertSink, eventSink)
	ctx := context.Background()
	_ = plane.Start(ctx)

	results, err := plane.IngestBatch(ctx, []model.Event{{}, {}, {}})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("beklenen sonuc 3, alinan %d", len(results))
	}
	if len(eventSink.Events) != 3 {
		t.Errorf("beklenen eventSink 3, alinan %d", len(eventSink.Events))
	}
	if len(alertSink.Events) != 1 {
		t.Errorf("beklenen alertSink 1, alinan %d", len(alertSink.Events))
	}
}

// ACCEPTANCE (convergence slice 3b): the plane cannot raise an alert that the
// live path would have suppressed. Given the SHARED gate with a repeat-threshold
// rule (Count=3), the first two identical detections are gated and only the
// third raises an alert — identical to the gRPC/HTTP ingest paths, because it is
// the same gate.
func TestTelemetryPlane_GateSuppressesLikeLivePath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gate := detectpipe.NewGate(threshold.New(fixedClock(now)), detbits.New(fixedClock(now)), nil)
	detector := &MockDetector{
		EvaluateFunc: func(evt model.Event) []detect.Detection {
			return []detect.Detection{{RuleID: "bruteforce", Threshold: &detect.ThresholdSpec{Count: 3, Seconds: 60}}}
		},
	}
	alertSink := &MockAlertSink{}
	plane := New(detector, gate, alertSink, &MockEventSink{})
	ctx := context.Background()
	_ = plane.Start(ctx)

	ev := model.Event{DeviceID: "dev1"}
	_, _ = plane.ProcessEvent(ctx, ev)
	_, _ = plane.ProcessEvent(ctx, ev)
	if len(alertSink.Events) != 0 {
		t.Fatalf("eşiğin altındaki tespitler bastırılmalıydı, alarm sayisi %d", len(alertSink.Events))
	}
	_, _ = plane.ProcessEvent(ctx, ev)
	if len(alertSink.Events) != 1 {
		t.Fatalf("eşiğe ulaşınca tam 1 alarm bekleniyordu, alinan %d", len(alertSink.Events))
	}
}
