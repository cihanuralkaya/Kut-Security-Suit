# ADR-0048: Data Plane: Enterprise Bus and Hot Store

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12)

## Context
PostgreSQL is used as a lake and telemetry is processed event by event. The Enterprise tier needs a durable bus and an analytic hot store; Lite needs a lighter path (ADR-0049). Redpanda is BSL and cannot be bundled.

## Decision
- Enterprise bus: Apache Kafka 4.x in KRaft mode, Go client franz-go. Redpanda is not bundled and is supported only if a customer brings it. The CI image `redpandadata/redpanda:latest` is replaced with a pinned `apache/kafka` image, so what is tested is what ships.
- Enterprise hot store: ClickHouse with ReplacingMergeTree, row policies and the compiler-injected tenant predicate (ADR-0047).
- Lite hot store: DuckDB with Parquet. A transitional "Lite-Legacy PG" mode keeps existing installs working.
- The move from PostgreSQL to the new stores is a cutover under gate G13.

## Consequences
- Two storage backends must pass the same query vectors.
- License policy (ADR-0053) is respected: Kafka and ClickHouse are Apache-2.0.
- Migrations for ClickHouse live under `db/clickhouse/migrations/` (ADR-0060).

## Alternatives
- Redpanda: rejected, BSL.
- NATS JetStream in Enterprise: kept only as an optional adapter, not the default.
- PostgreSQL as the lake: rejected, does not scale to the target ingest.

## Source decision
D4, D5 (roadmap section 3). Reserved by D19 as 0048.
