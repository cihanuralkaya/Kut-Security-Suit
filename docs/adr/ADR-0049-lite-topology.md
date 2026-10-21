# ADR-0049: Lite Topology: Embedded WAL Bus and Command Outbox

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
Lite is a small single-site deployment that must stay simple and free of heavy dependencies. The CI zero-dependency guard for `server/cmd/c2` forbids NATS and similar clients.

## Decision
- The Lite bus is an embedded segment write-ahead log inside kut-dp. No NATS in Lite.
- Command fan-out uses a PostgreSQL `command_outbox` table with LISTEN/NOTIFY.
- Lite analytic storage is DuckDB plus Parquet (ADR-0048); the scheduler is a leader cron (ADR-0054).
- Lite and Enterprise share the same contracts, so a tenant can move between tiers.

## Consequences
- Lite keeps a small operational footprint, with one database and one binary set.
- The WAL needs crash and kill -9 tests (no event loss, P-M1 exit).
- The outbox adds a table with its own retention and RLS (ADR-0066 reserved).

## Alternatives
- Embedded NATS in Lite: rejected, violates the zero-dependency guard.
- Polling the database for commands: rejected, latency and load.

## Source decision
D3, with the Lite part of D5 (roadmap section 3). Reserved by D19 as 0048-0049.
