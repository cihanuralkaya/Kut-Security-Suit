package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	xgrpc "kut.corp/suite/server/internal/grpc"
	"kut.corp/suite/server/internal/ocsfexport"
	"kut.corp/suite/server/internal/telemetryplane"
	"kut.corp/suite/server/internal/telemetryschema"
)

// wireTelemetryExport sets up the telemetry export tap (ADR-0040): the
// export-only plane that projects AgentHandler's detect+gate OUTCOME to OCSF.
// One code path serves both tiers (Lite c2 + Enterprise). It always returns a
// callable stop func (never nil); an error is returned only on operator
// misconfiguration (an unopenable destination, or a mixed-tenant stream in
// strict multi-tenant mode). When off (KUT_OCSF_EXPORT unset, or
// KUT_FABRIC_TELEMETRY_PLANE=0) it is a no-op and behaviour is unchanged.
//
// Flags: KUT_OCSF_EXPORT (stdout|file:…|tcp://…|udp://…), KUT_OCSF_EXPORT_MODE
// (all|findings), KUT_OCSF_EXPORT_QUEUE (int), KUT_OCSF_EXPORT_ALLOW_MIXED_TENANTS
// (1 to permit a single all-tenant stream under KUT_TENANT_ENFORCE),
// KUT_FABRIC_TELEMETRY_PLANE=0 (kill switch, mirrors KUT_FABRIC_COMMAND_PLANE).
func wireTelemetryExport(ctx context.Context, h *xgrpc.AgentHandler, tenantEnforce bool) (func(), error) {
	noop := func() {}
	if os.Getenv("KUT_FABRIC_TELEMETRY_PLANE") == "0" {
		return noop, nil
	}
	spec := os.Getenv("KUT_OCSF_EXPORT")
	if spec == "" {
		return noop, nil // export is opt-in; unset means unchanged behaviour
	}
	// Multi-tenant FAIL-CLOSED: in strict multi-tenant mode a single stream mixes
	// every tenant's events, so refuse to start unless the operator opts in.
	if tenantEnforce && os.Getenv("KUT_OCSF_EXPORT_ALLOW_MIXED_TENANTS") != "1" {
		return noop, fmt.Errorf("sıkı çok-kiracı modda OCSF export karışık-kiracı akışı oluşturur; onay için KUT_OCSF_EXPORT_ALLOW_MIXED_TENANTS=1 gerekir")
	}

	product := telemetryschema.Product{Name: "KUT Security Suite", VendorName: "KUT", Version: os.Getenv("KUT_BUILD_VERSION")}
	writer, closer, err := ocsfexport.Open(spec, product)
	if err != nil {
		return noop, err // fail loudly at boot (like the webhook/SIEM notifiers)
	}

	queue := 10000
	if n, perr := strconv.Atoi(os.Getenv("KUT_OCSF_EXPORT_QUEUE")); perr == nil && n > 0 {
		queue = n
	}
	mode := os.Getenv("KUT_OCSF_EXPORT_MODE") // "" (all) | "findings"

	plane := telemetryplane.New(writer, writer, telemetryplane.TapConfig{QueueDepth: queue, Mode: mode})
	if err := plane.Start(ctx); err != nil {
		_ = closer.Close()
		return noop, err
	}
	h.SetProcessedObserver(plane)

	modeLabel := mode
	if modeLabel == "" {
		modeLabel = "all"
	}
	log.Printf("telemetri dışa aktarımı ETKİN: OCSF → %s (mod=%s, kuyruk=%d)", spec, modeLabel, queue)

	return func() {
		_ = plane.Stop() // drain the queue
		_ = closer.Close()
	}, nil
}
