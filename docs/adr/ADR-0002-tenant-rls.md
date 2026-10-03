# ADR 0002: Tenant Isolation using PostgreSQL Row-Level Security (RLS)

## Status
Accepted

## Context
The KUT Security Suit is a multi-tenant platform. Previously, tenant isolation relied entirely on application-layer `WHERE tenant_id = ?` clauses. This approach is fragile because a single missed predicate could lead to cross-tenant data leaks. We need a more robust, defense-in-depth approach to ensure tenant isolation at the database level.

## Decision
We have decided to implement PostgreSQL Row-Level Security (RLS) for all tenant-aware tables.

1.  **Enable RLS**: `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` are applied to tenant-aware tables (`event_logs`, `event_ack`, `scim_users`, `cases`, `verify_checks`, `msp_customers`, `devices`, `incidents`).
2.  **Policies**: A policy is created for each table that restricts access based on a custom configuration parameter (`app.tenant_id`).
3.  **Application Changes**: The application must set the tenant ID at the start of each transaction using `SET LOCAL app.tenant_id = '<tenant_id>'`.
4.  **Bypass**: A superuser bypass policy is created for the `kut_admin` role to allow migration and maintenance tasks without tenant restrictions.

## Consequences
*   **Positive**: Improved security and defense-in-depth against data leakage across tenants. A forgotten `WHERE` clause in the application will no longer expose other tenants' data.
*   **Negative**: Slight performance overhead due to RLS checks on every query. Application code must be updated to always set `app.tenant_id` at the beginning of each transaction; failure to do so will result in queries returning no rows or failing policy checks.
