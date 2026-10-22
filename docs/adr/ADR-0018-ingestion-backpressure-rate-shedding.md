# ADR 0018: Telemetry Ingestion Backpressure and Load Shedding

## Status
Accepted (retained through the 2026-10 telemetry-plane convergence)

> **Note (convergence).** Unlike the duplicate rule/correlation/bus engines
> (ADR-0017/0026/0028, superseded), `BackpressureController` in
> `server/internal/telemetryplane` is retained — it has no live equivalent and is
> the sole priority-aware load-shedder. During convergence its `Release` was made
> race-safe: the counter now floors at zero via a single CAS loop, so a concurrent
> or unbalanced release can no longer leave the depth negative (which would make
> usage negative and silently disable shedding under load).

## Context
During distributed attacks, network scanning storms, or ransomware outbreaks, millions of endpoint telemetry events can surge simultaneously into the ingestion pipeline. Without backpressure protection, memory queues overflow, exhausting server RAM and leading to denial-of-service crashes.

## Decision
We implemented `BackpressureController` in `server/internal/telemetryplane`:

1. **High-Watermark Selective Shedding:**
   - Below `HighWatermark` (e.g., 80% queue capacity): 100% of telemetry events are accepted.
   - Between `HighWatermark` and 100%: Low-priority events (`INFO`, `DEBUG`) are shed, while high-severity telemetry (`HIGH`, `CRITICAL`, `SECURITY`) continues to be accepted.
   - At 100% saturation: Hard drop is enforced to prevent process memory exhaustion, incrementing `DroppedEvents`.

2. **Lock-Free Atomic Instrumentation:**
   - Queue depth, accepted, and dropped metrics are tracked via `sync/atomic` primitives, adding negligible latency to the hot ingestion loop.

## Consequences

### Positive
- Guarantees server stability and resilience during event storms.
- Ensures critical security alerts are never starved by low-priority noise during an active attack.
- Provides real-time metrics (`Stats()`) for autoscaling triggers.

### Negative
- Low-priority informational events may be discarded during severe overload conditions.
