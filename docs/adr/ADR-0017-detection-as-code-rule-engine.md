# ADR 0017: Detection-as-Code and Telemetry Rule Engine

## Status
Superseded (2026-10, telemetry-plane convergence)

> **Superseded.** The separate `RuleEngine` in `server/internal/telemetryplane`
> described below was removed during the telemetry-plane convergence. It
> duplicated — and was strictly weaker than — the live detection engine
> (`server/internal/detect`): no rule-signature verification, no rule validation,
> per-event regex recompilation, and no tenant binding. Detection-as-code now
> builds on the ONE live engine and its signed rule type `detect.Rule` (the
> single content-pack substrate, used by `detectreg`/`ruleyaml`/`rulesimport`).
> The telemetry plane reuses that engine behind its `Detector` seam instead of
> owning a second rule stack. Historical record retained below.

## Context
Detection logic must be decoupled from binary releases to enable rapid rule updates and community-driven detection engineering (Roadmap §42, §108 `XDR-004`). The Telemetry Plane requires an extensible in-memory rule engine that evaluates incoming events at microsecond latency without external database lookups.

## Decision
We implemented `RuleEngine` in `server/internal/telemetryplane`:

1. **Declarative Rule Format:**
   - Rules specify `Category`, `Severity`, `MITRETactic`, `MITRETechnique`, and a list of atomic `RuleCondition` objects.
   - Operators supported: `equals`, `contains`, `regex`, `prefix`, `not_equals`.
   - Rules can be loaded dynamically from JSON/YAML via `LoadRulesFromJSON`.

2. **Integration with Telemetry Plane:**
   - `RuleEngine` fulfills the `telemetryplane.Detector` interface.
   - When events match enabled rules, alerts are dispatched directly to the `AlertSink`.

## Consequences

### Positive
- Detections are managed as code and dynamically reloadable.
- Explicit mapping to MITRE ATT&CK tactics and techniques.
- Evaluates rules in pure Go with zero latency overhead.

### Negative
- Regular expression compilation must be cached to prevent performance degradation on high-throughput event spikes.
