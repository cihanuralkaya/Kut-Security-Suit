# ADR 0018: Telemetry Ingestion Backpressure and Load Shedding

## Status
Accepted

## Context
During distributed attacks, network scanning storms, or ransomware outbreaks, millions of endpoint telemetry events can surge simultaneously into the ingestion pipeline (Roadmap §39, §108 `SCALE-002`). Without backpressure protection, memory queues overflow, exhausting server RAM and leading to denial-of-service crashes.

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
