# ADR 0004: Add tenant_id to the audit chain hash computation

## Context
The audit chain hash function `AuditChainHash` previously computed the hash using:
`SHA-256(prevHash || adminRef || action || targetType || targetID || atUnixNano)`
Because it did not include `tenant_id`, there was a risk that audit records could be maliciously moved between tenants without breaking the hash chain (cross-tenant log transplant).

## Decision
We updated the `AuditChainHash` signature to include `tenantID string` as the first field written after `prev`. The new computation is:
`SHA-256(prevHash || tenantID || adminRef || action || targetType || targetID || atUnixNano)`
This strictly binds each audit record to its respective tenant, preventing cross-tenant transplants.

We also updated all callers of `AuditChainHash` in the repository, primarily `server/internal/db/admin.go` and `server/internal/memstore/memstore.go`, to pass `tenant_id`. To ensure this works properly with `VerifyAuditChain`, `tenant_id` was added to `audit_log` in `db/schema.sql` and `auditRec` in `memstore`.

## Consequences
- Audit logs are now securely bound to their tenants.
- Any attempt to transplant an audit log across tenants will immediately break the hash chain and fail verification.
- The `AuditChainHash` API now explicitly requires `tenantID`, ensuring that future callers will not omit it.
