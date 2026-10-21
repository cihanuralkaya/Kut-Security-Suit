# ADR-0060: Migrations with goose and Database Roles

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12, migrations under G2)

## Context
Schema upgrades run as idempotent blocks in application start-up. Row-level security is not effective while the application connects as a role that bypasses it.

## Decision
- Migrations use goose v3 (MIT) with the paths `db/postgres/migrations/` and `db/clickhouse/migrations/`. The existing upgrade blocks become migrations 0001-0003 (WP-CP-001).
- The application role is NOSUPERUSER and NOBYPASSRLS; a separate migration role owns the schema. CI creates the application role and re-runs the `TestPG*` suite under it.
- Every migration ships up and down scripts, a lock estimate and an RLS test (gate G2).
- Atlas Community is not used because it does not support RLS.

## Consequences
- Start-up no longer changes schema; a migration step runs first.
- Rollbacks are rehearsed in CI.
- Two pools exist: application (tenant bound) and migration/admin.

## Alternatives
- Atlas: rejected, no RLS support.
- Hand-written start-up upgrades: rejected, no ordering, no down path.

## Source decision
D9 (roadmap section 3). Reserved by D19.
