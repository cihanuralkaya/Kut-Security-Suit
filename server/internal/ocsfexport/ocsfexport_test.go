package ocsfexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestOpen_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ocsf.ndjson")
	w, c, err := Open("file:"+path, testProduct)
	if err != nil {
		t.Fatalf("Open file: %v", err)
	}
	if err := w.EmitEvent(context.Background(), model.Event{Category: "PROCESS", Message: "x"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	_ = c.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(b), `"class_uid"`) {
		t.Errorf("dosyaya OCSF JSON satırı yazılmalıydı, alinan %q", string(b))
	}
}

func TestOpen_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		got <- line
	}()

	w, c, err := Open("tcp://"+ln.Addr().String(), testProduct)
	if err != nil {
		t.Fatalf("Open tcp: %v", err)
	}
	defer c.Close()
	if err := w.EmitAlert(context.Background(), model.Event{Message: "a"}, []detect.Detection{{RuleID: "r"}}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	line := <-got
	if !strings.Contains(line, `"class_uid":2004`) {
		t.Errorf("tcp hedefine Detection Finding yazılmalıydı, alinan %q", line)
	}
}

func TestOpen_Stdout(t *testing.T) {
	w, c, err := Open("stdout", testProduct)
	if err != nil || w == nil {
		t.Fatalf("stdout Open hata vermemeli: %v", err)
	}
	if err := c.Close(); err != nil { // no-op, os.Stdout kapanmaz
		t.Errorf("stdout closer no-op olmalı: %v", err)
	}
}

func TestOpen_BadSpec(t *testing.T) {
	if _, _, err := Open("nope", testProduct); err == nil {
		t.Fatal("desteklenmeyen hedef hata vermeliydi")
	}
	if _, _, err := Open("file:", testProduct); err == nil {
		t.Fatal("boş dosya yolu hata vermeliydi")
	}
}
