package telemetryplane

import (
	"context"
	"testing"

	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/telemetryschema"
)

// MockDetector implements Detector for testing.
type MockDetector struct {
	EvaluateFunc func(evt model.Event) []Rule
}

func (m *MockDetector) Evaluate(evt model.Event) []Rule {
	if m.EvaluateFunc != nil {
		return m.EvaluateFunc(evt)
	}
	return nil
}

// MockAlertSink implements AlertSink for testing.
type MockAlertSink struct {
	Alerts []telemetryschema.Event
	Err    error
}

func (m *MockAlertSink) EmitAlert(ctx context.Context, evt telemetryschema.Event) error {
	if m.Err != nil {
		return m.Err
	}
	m.Alerts = append(m.Alerts, evt)
	return nil
}

// MockEventSink implements EventSink for testing.
type MockEventSink struct {
	Events []telemetryschema.Event
	Err    error
}

func (m *MockEventSink) EmitEvent(ctx context.Context, evt telemetryschema.Event) error {
	if m.Err != nil {
		return m.Err
	}
	m.Events = append(m.Events, evt)
	return nil
}

func TestTelemetryPlane_Lifecycle(t *testing.T) {
	detector := &MockDetector{}
	alertSink := &MockAlertSink{}
	eventSink := &MockEventSink{}

	plane := New(detector, alertSink, eventSink)

	ctx := context.Background()

	// Should not be able to process before start
	_, err := plane.ProcessEvent(ctx, model.Event{})
	if err == nil {
		t.Fatal("beklenen hata alınmadı: process event without start")
	}

	// Start
	if err := plane.Start(ctx); err != nil {
		t.Fatalf("beklenmeyen hata: start %v", err)
	}

	// Start again should error
	if err := plane.Start(ctx); err == nil {
		t.Fatal("beklenen hata alınmadı: start when already running")
	}

	// Stop
	if err := plane.Stop(); err != nil {
		t.Fatalf("beklenmeyen hata: stop %v", err)
	}

	// Stop again should error
	if err := plane.Stop(); err == nil {
		t.Fatal("beklenen hata alınmadı: stop when not running")
	}
}

func TestTelemetryPlane_ProcessEvent(t *testing.T) {
	evalCount := 0
	detector := &MockDetector{
		EvaluateFunc: func(evt model.Event) []Rule {
			evalCount++
			// Sadece 2. event'te alert üret
			if evalCount == 2 {
				return []Rule{{}}
			}
			return nil
		},
	}
	alertSink := &MockAlertSink{}
	eventSink := &MockEventSink{}

	plane := New(detector, alertSink, eventSink)
	ctx := context.Background()
	_ = plane.Start(ctx)

	t.Run("Normal event without alert", func(t *testing.T) {
		_, err := plane.ProcessEvent(ctx, model.Event{})
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(eventSink.Events) != 1 {
			t.Errorf("eventSink beklenen event sayisi 1, alinan %d", len(eventSink.Events))
		}
		if len(alertSink.Alerts) != 0 {
			t.Errorf("alertSink beklenen alert sayisi 0, alinan %d", len(alertSink.Alerts))
		}
	})

	t.Run("Event with alert", func(t *testing.T) {
		_, err := plane.ProcessEvent(ctx, model.Event{})
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}

		if len(eventSink.Events) != 2 {
			t.Errorf("eventSink beklenen event sayisi 2, alinan %d", len(eventSink.Events))
		}
		if len(alertSink.Alerts) != 1 {
			t.Errorf("alertSink beklenen alert sayisi 1, alinan %d", len(alertSink.Alerts))
		}
	})

	t.Run("Detector error", func(t *testing.T) {
		t.Skip("Detector no longer returns error")
	})
}

func TestTelemetryPlane_IngestBatch(t *testing.T) {
	evalCount := 0
	detector := &MockDetector{
		EvaluateFunc: func(evt model.Event) []Rule {
			evalCount++
			if evalCount == 2 {
				return []Rule{{}}
			}
			return nil
		},
	}
	alertSink := &MockAlertSink{}
	eventSink := &MockEventSink{}

	plane := New(detector, alertSink, eventSink)
	ctx := context.Background()
	_ = plane.Start(ctx)

	events := []model.Event{
		{},
		{},
		{},
	}

	results, err := plane.IngestBatch(ctx, events)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("beklenen sonuc sayisi 3, alinan %d", len(results))
	}

	if len(eventSink.Events) != 3 {
		t.Errorf("beklenen eventSink sayisi 3, alinan %d", len(eventSink.Events))
	}

	if len(alertSink.Alerts) != 1 {
		t.Errorf("beklenen alertSink sayisi 1, alinan %d", len(alertSink.Alerts))
	}
}
