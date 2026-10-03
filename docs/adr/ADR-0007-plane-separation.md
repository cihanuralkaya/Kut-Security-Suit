# ADR-0007: Plane Separation Architecture

## Status
Proposed

## Context
Currently, the KUT Security Suit backend is bootstrapped through a monolithic 1,693-line `app.go` file. This monolith initializes all subsystems including PKI, agent gRPC handlers, admin HTTP APIs, the detection engine, correlation, and external integrations in a single function. This design leads to tight coupling, making it difficult to test individual components, scale specific workloads (e.g., scaling ingestion independently from administration), and introduce new enterprise features (like AI Security Fabric) without risking system stability.

## Decision
We will refactor the system architecture into distinct, decoupled operational "planes" connected through well-defined Go interfaces. 

The defined planes are:
1. **Control Plane:** Manages configuration, policy distribution, administration (API/Web), PKI, and device enrollment.
2. **Telemetry Plane (Data Plane):** Handles high-volume event ingestion, OCSF normalization, stream processing, detection engine, and event forwarding (Kafka/S3/ClickHouse).
3. **Command Plane:** Manages the response bus, asynchronous agent dispatch, action verification, and remote shell capabilities.
4. **Intelligence Plane:** Manages IoC updates, threat intelligence lifecycle, entity graphing, and sequence anomaly models.
5. **AI Security Fabric / Decision Fabric:** Houses the model router, DLP, risk policies, guarded executor, and agent mesh logic.

The migration will follow an incremental path to maintain backward compatibility with existing Lite and Enterprise deployment modes.

## Consequences

**Positive:**
- **Isolation of Failure Domains:** High load or crashes in the Telemetry Plane will not impact the Control Plane's ability to issue commands or serve the admin UI.
- **Independent Scalability:** Telemetry ingestion can scale horizontally independently from the Control Plane.
- **Testability:** Clear Go interface contracts will enable robust unit testing via mock implementations.
- **Maintainability:** Reduces the complexity of `app.go`, transitioning it to a lightweight coordinator/wire file.

**Negative:**
- Increased initial architectural complexity.
- Refactoring effort will temporarily slow down new feature development.
- In-memory function calls will be replaced by channel-based or event-bus boundaries between certain planes, slightly increasing inter-plane latency.
