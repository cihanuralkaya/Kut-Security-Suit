# ADR 0019: Cryptographic Anti-Replay Protection Engine

## Status
Accepted

## Context
In distributed C2 and endpoint telemetry streams, attackers intercepting signed messages over the wire could attempt replay attacks (re-transmitting previous telemetry or re-executing captured commands). Without replay protection, a stolen command could be executed repeatedly to cause disruption (Roadmap §19, §108 `SEC-003`).

## Decision
We implemented `ReplayProtector` in `server/internal/security`:

1. **Sliding-Window Time Validation:**
   - Rejects messages older than the freshness window (e.g. 5 minutes).
   - Rejects future-dated messages exceeding clock skew tolerance (e.g. 1 minute).

2. **Tenant and Device-Scoped Nonce Cache:**
   - Nonces are recorded per `(tenantID, deviceID, nonce)`.
   - The same nonce submitted for the same device within the freshness window is rejected immediately as a replay attempt.
   - Nonces expire and are reclaimed via `Sweep` once the sliding window passes.

## Consequences

### Positive
- Prevents captured commands and telemetry packets from being replayed.
- Zero external cache (Redis) required; thread-safe in-memory map with automatic TTL eviction.
- Isolated by tenant and device.

### Negative
- Endpoints with severe clock drift (> 1 minute) will have messages rejected until synchronized via NTP.
