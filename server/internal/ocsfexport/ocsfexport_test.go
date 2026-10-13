package ocsfexport

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/telemetryplane"
	"kut.corp/suite/server/internal/telemetryschema"
)

// Compile-time proof that the OCSF Writer satisfies the telemetry plane's sink
// seams — the plane can emit directly to this export boundary.
var (
	_ telemetryplane.EventSink = (*Writer)(nil)
	_ telemetryplane.AlertSink = (*Writer)(nil)
)

var testProduct = telemetryschema.Product{Name: "KUT", VendorName: "KUT", Version: "1.0.0"}

func decodeLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("OCSF satırı çözümlenemedi: %v (%q)", err, buf.String())
	}
	return m
}

// EmitEvent, ham olayı etkinlik eşlemesiyle yazar (PROCESS → System Activity 1007),
// Detection Finding DEĞİL.
func TestWriter_EmitEvent_ActivityMapping(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, testProduct)
	if err := w.EmitEvent(context.Background(), model.Event{Category: "PROCESS", Message: "powershell"}); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	m := decodeLine(t, &buf)
	if m["class_uid"].(float64) != 1007 {
		t.Errorf("ham PROCESS olayı System Activity(1007) olmalı, alinan %v", m["class_uid"])
	}
}

// EmitAlert, bir Detection Finding yazar; en yüksek önemli tespit başlığı/önemi
// sürükler, teknikler types'a girer ve tüm tespitler unmapped.detections'da korunur.
func TestWriter_EmitAlert_DetectionFinding(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, testProduct)
	dets := []detect.Detection{
		{RuleID: "KUT-0001", RuleName: "High rule", Severity: "HIGH", Technique: mitre.Technique{ID: "T1059", Name: "Command", Tactic: "TA0002"}},
		{RuleID: "KUT-0002", RuleName: "Crit rule", Severity: "CRITICAL", Technique: mitre.Technique{ID: "T1486"}},
	}
	e := model.Event{Category: "PROCESS", Severity: "LOW", Message: "evt", DeviceID: "dev1"}
	if err := w.EmitAlert(context.Background(), e, dets); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	m := decodeLine(t, &buf)

	if m["class_uid"].(float64) != 2004 {
		t.Errorf("alarm Detection Finding(2004) olmalı, alinan %v", m["class_uid"])
	}
	// En yüksek önem (CRITICAL) başlığı ve önemi sürükler — ham olay LOW olsa bile.
	fi := m["finding_info"].(map[string]any)
	if fi["title"] != "Crit rule" {
		t.Errorf("başlık en yüksek önemli kuralın adı olmalı, alinan %v", fi["title"])
	}
	if m["severity"] != "Critical" {
		t.Errorf("önem tespitten gelmeli (Critical), alinan %v", m["severity"])
	}
	types := fi["types"].([]any)
	if len(types) != 2 {
		t.Errorf("iki teknik bekleniyordu, alinan %v", types)
	}
	// Lossless: her iki tespit de unmapped.detections'da.
	um := m["unmapped"].(map[string]any)
	recs := um["detections"].([]any)
	if len(recs) != 2 {
		t.Fatalf("iki tespit kaydı bekleniyordu, alinan %d", len(recs))
	}
}

func TestWriter_EmitAlert_NoDetections(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, testProduct)
	if err := w.EmitAlert(context.Background(), model.Event{Message: "x"}, nil); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	m := decodeLine(t, &buf)
	if m["class_uid"].(float64) != 2004 {
		t.Errorf("tespitsiz alarm bile Finding(2004) olmalı, alinan %v", m["class_uid"])
	}
}
