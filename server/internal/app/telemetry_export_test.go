package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/detect"
	xgrpc "kut.corp/suite/server/internal/grpc"
	"kut.corp/suite/server/internal/model"
)

// End-to-end: the export tap wired from env projects the handler's gated outcome
// to an OCSF file. With a Count=3 rule in "findings" mode, the first two hits are
// gated (no finding) and the third produces exactly one Detection Finding that
// carries the server-bound device id.
func TestWireTelemetryExport_E2E(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ocsf.ndjson")
	t.Setenv("KUT_OCSF_EXPORT", "file:"+path)
	t.Setenv("KUT_OCSF_EXPORT_MODE", "findings")

	h := xgrpc.NewAgentHandler(nil, nil, nil, nil, nil)
	h.SetDetector(detect.NewEngine([]detect.Rule{{
		ID: "R-T", Name: "sprey", Category: "auth", Contains: []string{"fail"},
		Severity: "MEDIUM", Threshold: &detect.ThresholdSpec{Count: 3, Seconds: 3600},
	}}))

	stop, err := wireTelemetryExport(context.Background(), h, false)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}

	ev := model.Event{Category: "auth", Message: "login fail", Severity: "LOW"}
	h.ProcessEvent(context.Background(), "devX", ev)
	h.ProcessEvent(context.Background(), "devX", ev)
	h.ProcessEvent(context.Background(), "devX", ev) // Count=3 → fires
	stop()                                           // drains the queue and closes the file

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("findings modunda tam 1 finding bekleniyordu, alinan %d satır: %q", len(lines), string(b))
	}
	if !strings.Contains(lines[0], `"class_uid":2004`) {
		t.Errorf("Detection Finding (2004) bekleniyordu: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"uid":"devX"`) {
		t.Errorf("sunucu-bağlı device.uid (devX) bekleniyordu: %s", lines[0])
	}
}

// Fail-closed: strict multi-tenant mode refuses a mixed-tenant export stream
// unless explicitly allowed.
func TestWireTelemetryExport_MixedTenantFailsClosed(t *testing.T) {
	t.Setenv("KUT_OCSF_EXPORT", "stdout")
	h := xgrpc.NewAgentHandler(nil, nil, nil, nil, nil)
	if _, err := wireTelemetryExport(context.Background(), h, true); err == nil {
		t.Fatal("sıkı çok-kiracı modda onaysız export hata vermeliydi")
	}
	// Opt-in geçer.
	t.Setenv("KUT_OCSF_EXPORT_ALLOW_MIXED_TENANTS", "1")
	stop, err := wireTelemetryExport(context.Background(), h, true)
	if err != nil {
		t.Fatalf("onaylı mixed-tenant export başlamalıydı: %v", err)
	}
	stop()
}

// Off by default: no KUT_OCSF_EXPORT → no observer wired, no error.
func TestWireTelemetryExport_OffByDefault(t *testing.T) {
	h := xgrpc.NewAgentHandler(nil, nil, nil, nil, nil)
	stop, err := wireTelemetryExport(context.Background(), h, false)
	if err != nil {
		t.Fatalf("kapalıyken hata olmamalı: %v", err)
	}
	stop()
}
