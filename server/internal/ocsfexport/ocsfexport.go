// Package ocsfexport projects canonical events and gated detections to OCSF and
// writes them, one JSON object per line, to an io.Writer (file, stdout, a syslog
// connection, an HTTP body). It is the telemetry plane's export boundary: raw
// telemetry is emitted via the activity mapping (telemetryschema.ToOCSF) and a
// gated alert is emitted as an enriched OCSF Detection Finding that carries the
// firing rule and its MITRE context.
//
// It is stdlib + in-repo only (core tier, safe for the zero-dep Lite binary); the
// heavy streaming sinks (Kafka/S3/ClickHouse) are an enterprise-tier concern. The
// Writer structurally satisfies telemetryplane.EventSink and telemetryplane.AlertSink.
package ocsfexport

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/telemetryschema"
)

// OCSF Detection Finding classification (Findings category). type_uid =
// class_uid*100 + activity_id; activity 1 = Create.
const (
	findingCategoryUID  = 2
	findingCategoryName = "Findings"
	findingClassUID     = 2004
	findingClassName    = "Detection Finding"
	findingActivityID   = 1
	findingActivityName = "Create"
	findingTypeUID      = findingClassUID*100 + findingActivityID
)

// Writer serializes OCSF events/findings as newline-delimited JSON to w. Writes
// are serialized so concurrent ingest paths do not interleave partial lines.
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	product telemetryschema.Product
}

// NewWriter returns a Writer that projects to OCSF with the given product
// metadata and appends each record as one JSON line to w.
func NewWriter(w io.Writer, product telemetryschema.Product) *Writer {
	return &Writer{w: w, product: product}
}

// EmitEvent projects a raw canonical event to its OCSF activity mapping and
// writes it. Satisfies telemetryplane.EventSink.
func (x *Writer) EmitEvent(ctx context.Context, e model.Event) error {
	return x.writeLine(telemetryschema.ToOCSF(e, x.product))
}

// EmitAlert projects a gated alert (the canonical event plus the detections that
// fired and passed the suppression gate) to an enriched OCSF Detection Finding
// and writes it. Satisfies telemetryplane.AlertSink.
func (x *Writer) EmitAlert(ctx context.Context, e model.Event, dets []detect.Detection) error {
	return x.writeLine(toFinding(e, dets, x.product))
}

func (x *Writer) writeLine(o telemetryschema.Event) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	x.mu.Lock()
	defer x.mu.Unlock()
	_, err = x.w.Write(b)
	return err
}

// toFinding builds an OCSF Detection Finding from a gated alert. It starts from
// the canonical event's base projection, forces the Findings class (an alert is a
// finding regardless of the raw event's category), and enriches finding_info and
// the severity from the detections. When several detections fire on one event,
// the highest-severity one drives the headline (title/severity) and every
// technique is listed; the full per-detection context is preserved losslessly
// under unmapped.detections so nothing the pipeline knew is dropped at the boundary.
func toFinding(e model.Event, dets []detect.Detection, product telemetryschema.Product) telemetryschema.Event {
	o := telemetryschema.ToOCSF(e, product)
	o.CategoryUID, o.CategoryName = findingCategoryUID, findingCategoryName
	o.ClassUID, o.ClassName = findingClassUID, findingClassName
	o.ActivityID, o.ActivityName = findingActivityID, findingActivityName
	o.TypeUID = findingTypeUID

	if len(dets) == 0 {
		return o
	}

	lead := dets[0]
	for _, d := range dets[1:] {
		if severityRank(d.Severity) > severityRank(lead.Severity) {
			lead = d
		}
	}

	if lead.RuleName != "" {
		o.FindingInfo.Title = lead.RuleName
	}
	if lead.Severity != "" {
		o.SeverityID, o.Severity = severityIDName(lead.Severity)
	}

	var types []string
	records := make([]map[string]any, 0, len(dets))
	for _, d := range dets {
		if d.Technique.ID != "" {
			types = append(types, d.Technique.ID)
		}
		rec := map[string]any{"rule_id": d.RuleID, "rule_name": d.RuleName, "severity": d.Severity}
		if d.Technique.ID != "" {
			rec["technique_id"] = d.Technique.ID
			rec["technique_name"] = d.Technique.Name
			rec["tactic"] = d.Technique.Tactic
		}
		records = append(records, rec)
	}
	if len(types) > 0 {
		o.FindingInfo.Types = types
	}
	if o.Unmapped == nil {
		o.Unmapped = map[string]any{}
	}
	o.Unmapped["detections"] = records
	return o
}

// severityRank orders KUT severities so the lead detection can be chosen.
func severityRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO", "INFORMATIONAL":
		return 1
	default:
		return 0
	}
}

// severityIDName maps a KUT severity to the OCSF severity_id/severity pair
// (mirrors telemetryschema's own mapping; kept here so the finding's severity can
// be driven by the detection rather than the raw event).
func severityIDName(sev string) (int, string) {
	switch sev {
	case "INFO", "INFORMATIONAL":
		return 1, "Informational"
	case "LOW":
		return 2, "Low"
	case "MEDIUM":
		return 3, "Medium"
	case "HIGH":
		return 4, "High"
	case "CRITICAL":
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}
