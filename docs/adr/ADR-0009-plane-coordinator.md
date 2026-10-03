# ADR 0009: Fabric Coordinator and Plane Lifecycle Orchestration

## Status
Accepted

## Context
Following ARCH-001 (Plane Separation Architecture) and ADR-0007, the monolithic bootstrap in `app.go` is being decomposed into decoupled operational planes:
- Control Plane (`server/internal/controlplane`)
- Telemetry Plane (`server/internal/telemetryplane`)
- Command Plane (`server/internal/commandplane`)

To ensure predictable startup, error containment, and graceful shutdown, the lifecycle of these planes must be managed deterministically by an orchestrator rather than scattered throughout `app.go`.

## Decision
We introduced `FabricCoordinator` in `server/internal/coordinator` to manage the lifecycle and inter-plane boundary bindings:

1. **Startup Order (Dependency-First):**
   - **Step 1: Control Plane** boots first (Authentication, PKI, Enrollment, and Policy distribution must be ready).
   - **Step 2: Command Plane** boots second (Tasking, verification, and guarded execution must be online before agents connect).
   - **Step 3: Telemetry Plane** boots last (Data ingestion and rule evaluation begin once command and control channels are established).
   - *Rollback:* If any plane fails during boot, previously started planes are stopped in reverse order.

2. **Shutdown Order (Drain-First):**
   - **Step 1: Telemetry Plane** halts first (Stop incoming data streams to prevent queue overflow).
   - **Step 2: Command Plane** halts second (Drain and complete in-flight tasks).
   - **Step 3: Control Plane** halts last (Close management and administrative interfaces).

3. **Error Isolation & Failure Domains:**
   - Planes communicate strictly through interfaces.
   - Failure of the Telemetry Plane does not crash or invalidate the Control or Command planes.

## Consequences

### Positive
- **Deterministic Lifecycles:** Zero race conditions during startup and shutdown.
- **Clean Failure Containment:** An ingress storm taking down telemetry does not prevent administrators from issuing containment commands via the command plane.
- **Modular Testability:** The entire multi-plane fabric can be booted, verified, and torn down in unit and integration tests with minimal overhead.

### Negative
- Inter-plane state sharing requires explicit interface contracts rather than shared internal package pointers.
