# ADR-0040: Telemetry Plane as an Export-Only Tap

## Status
Accepted (2026-10, telemetry-plane convergence slice 4)

## Context
The telemetry plane is being wired live in both the Lite (`cmd/c2`) and Enterprise
(`cmd/control`) tiers. The plane needs a runtime role that delivers value (OCSF
export + backpressure) without a second detection path.

Detection and the stateful suppression gate (bits + repeat-threshold +
correlation, `detectpipe.Gate`) live in exactly one place: `grpc.AgentHandler.
ProcessEvent`, shared by the gRPC agent stream and the HTTP log-ingest path. The
gate is stateful — `threshold.Allow` increments on every call and the correlator
records the first `(device, rule)` observation — so a second caller reaching the
same gate on the same event would double-count windows and, by call order,
silently drop an alert from either the operator path or the SIEM path.

A plane that owns detection would also (a) key the gate on `model.Event.DeviceID`,
which agent events do not carry (the device id is a separate `ProcessEvent`
argument from the mTLS identity), collapsing all devices into one scope; (b)
capture a stale `*detect.Engine`, defeating the atomic hot-reload; and (c) sit
in front of detection with a fail-open sink/backpressure ordering, letting a
broken SIEM pipe or load-shedding blind detection.

## Decision
The plane is an **export-only tap**. It does not detect and holds no gate or
detector. `AgentHandler.ProcessEvent` remains the single owner of detection and
gating and, after it finishes, hands the plane its outcome via
`ObserveProcessed(ctx, deviceID, event, admitted []detect.Detection)`. The plane
stamps the server-bound device id, applies priority-aware backpressure (findings
before raw telemetry), and projects to the sinks (OCSF export). It never blocks
ingest and never fails it; sink errors are counted, not propagated.

Because OCSF findings carry only the detections that survived suppression, the
SIEM, console, and webhook show the same alerts — avoiding the duplicate-alert
noise of exporting pre-suppression detections.

This supersedes the Phase-1 idea in ARCH-001 / ADR-0007 of moving the gRPC
handler into the plane. It does not touch CONTRACTS.md §0 (this is detection
ingest, not the command/auth runtime).

## Consequences
- One detection-and-gate path; double gate-consumption is impossible by
  construction (the plane package has no gate reference).
- The tap covers both ingest paths and both build tiers through one `app.Run`
  wiring; heavy streaming sinks stay enterprise-tier.
- A future regression that re-adds a gated path to the plane is caught by a
  structural guard test (one `detectpipe.Gate` call site).
