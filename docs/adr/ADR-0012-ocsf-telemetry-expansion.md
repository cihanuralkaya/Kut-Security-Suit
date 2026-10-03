# ADR 0012: OCSF Telemetry Schema Expansion (Process and Network Activity)

## Status
Accepted

## Context
Following the Roadmap vision (§17, §21, §108 `XDR-001`), KUT Security Fabric standardizes incoming endpoint telemetry using the Open Cybersecurity Schema Framework (OCSF v1.1.0). Previously, all canonical events were mapped exclusively to OCSF Detection Finding (`Class 2004`). 

While appropriate for alerts and detections, high-volume process execution (EDR visibility) and network connection telemetry require distinct first-class OCSF event classes so external data lakes, SIEMs, and downstream analytical pipelines can ingest, filter, and partition them efficiently without confusion.

## Decision
We expanded `telemetryschema.ToOCSF` to dynamically classify events based on their canonical `model.Event.Category`:

1. **Process Activity (`Class 1007`):**
   - Events with `Category == "PROCESS"` are mapped to OCSF System Activity category (`UID 1`), Process Activity class (`UID 1007`), type `100701` (Create).
2. **Network Activity (`Class 4001`):**
   - Events with `Category == "NETWORK_CONN"` or `"NETWORK_DISCOVERY"` are mapped to OCSF Network Activity category (`UID 4`), Network Activity class (`UID 4001`), type `400101` (Open).
3. **Detection Findings (`Class 2004`):**
   - Security alerts, malware, policy violations, and unclassified events default to OCSF Findings category (`UID 2`), Detection Finding class (`UID 2004`), preserving 100% backward compatibility.

## Consequences

### Positive
- Downstream ClickHouse, OpenSearch, and Snowflake data pipelines can ingest process, network, and detection telemetry into dedicated OCSF tables.
- Preserves lossless enrichment via `unmapped` attributes and canonical content-addressed `EnsureID()` identifiers.
- Zero breaking changes for existing detection consumers.

### Negative
- Consumers must be prepared to handle multi-class OCSF JSON streams rather than expecting only Detection Finding payloads.
