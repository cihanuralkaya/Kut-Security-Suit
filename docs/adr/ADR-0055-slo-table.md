# ADR-0055: Single SLO and Measurement Table

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner). The number 0055 is inside the reserved block 0041-0069 but is not named in D19; it is used here for D24.

## Context
The work-package tracks used different percentiles for the same targets. A target is only a claim until a benchmark backs it.

## Decision
One table applies to all tracks, and each value needs a benchmark before it counts.
- Command latency under telemetry saturation: pilot p95 under 1 s; GA p50 under 300 ms, p95 under 1 s, p99 under 2 s.
- Ingest: pilot 10k EPS multi-node; GA Lite 5k EPS sustained; Enterprise 50k EPS per node.
- Offline: pilot zero loss across kill -9; GA 72 h with zero P0 loss.
- Endpoint: exec capture 99% in lab; agent CPU 2% mean and 150 MB RSS.
- Hunting: pilot p95 under 3 s; GA 1 billion rows with a 24 h `stats count by` under 5 s.
- HA and DR: RPO 0 and RTO under 15 minutes.

## Consequences
- Track specs reference this ADR instead of restating numbers.
- Benchmarks become gate evidence for G14.
- Changing a value needs a new ADR revision.

## Alternatives
- Per-track tables: rejected, they conflicted.
- No numeric targets before pilot: rejected, nothing to test against.

## Source decision
D24 (roadmap section 3). Number assigned from the reserved block, see docs/adr/README.md.
