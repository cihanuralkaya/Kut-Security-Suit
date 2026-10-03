# ADR 0021: Forensics Timeline Reconstruction and Custody Verification

## Status
Accepted

## Context
During digital forensics and incident response (DFIR), investigators must synthesize disparate event streams (custodial evidence access, telemetry logs, and response commands) into a unified chronological sequence (Roadmap §23, §25, §108 `DFIR-003`). Any tampering with evidence logs must be clearly flagged on the reconstructed timeline.

## Decision
We implemented `ReconstructTimeline` in `server/internal/evidence`:

1. **Multi-Source Event Normalization:**
   - Unified `TimelineEvent` representing custody actions, telemetry events, and command dispatches.

2. **Cryptographic Integrity Verification:**
   - Evaluates the append-only SHA-256 hash chain via `Evidence.Verify()`.
   - Propagates a boolean `Verified` status to every timeline event; if a custody break occurs, all events at or after the tampering point are flagged as unverified.

3. **Temporal Filtering:**
   - Chronological sorting and range filtering (`FilterTimeRange`) allowing investigators to narrow investigations down to specific incident windows.

## Consequences

### Positive
- Produces court-ready, cryptographically verifiable forensic timelines.
- Immediate visual indicators of any compromised or altered custody records.

### Negative
- Clock discrepancies between endpoints and C2 can affect interleaving of unverified telemetry.
