# Comprehensive Security Findings & Recommendations

## Finding ID: SEC-001
**Category:** Secret Management
**Severity:** MEDIUM
**Current State:** The `BlindIndexer` computes a keyed HMAC for searching encrypted fields using a global master key. 
**Evidence:** `server/internal/security/blindindex.go`
**Problem:** While HMAC is used, the key is global. If the master key is compromised, an attacker can offline brute-force the blind index for low-entropy data like MAC addresses (~48 bits).
**Impact:** Information disclosure of physical hardware addresses.
**Proposed Solution:** Introduce a tenant-specific salt or pepper to the blind index computation.
**Priority:** P2

## Finding ID: SEC-002
**Category:** Audit Logging
**Severity:** MEDIUM
**Current State:** `AuditChainHash` includes various fields and chains them securely using SHA-256.
**Evidence:** `server/internal/security/audithash.go`
**Problem:** The `tenant_id` is NOT included in the hash chain computation. 
**Impact:** A sophisticated attacker with DB access could potentially move audit logs between tenants without breaking the cryptographic chain.
**Proposed Solution:** Add `tenant_id` to the `writeField` series in `AuditChainHash`.
**Priority:** P2

## Finding ID: SEC-003
**Category:** Tenant Isolation
**Severity:** HIGH
**Current State:** `tenant_id` is passed as a Context value and verified via logical SQL clauses (`WHERE tenant_id = ?`).
**Evidence:** `server/internal/tenant/tenant.go` and `db/schema.sql`
**Problem:** Logical isolation relies entirely on developer discipline. Row Level Security (RLS) is not enabled.
**Impact:** Cross-tenant data leakage if a single SQL query omits the `tenant_id` predicate.
**Proposed Solution:** Enable PostgreSQL Row-Level Security (RLS) on all tenant-aware tables and force the application to set the `tenant.id` via `SET LOCAL` during transactions.
**Priority:** P1

## Finding ID: SEC-004
**Category:** Auth / Cryptography
**Severity:** LOW
**Current State:** Session tokens use a simple stateless HMAC signature.
**Evidence:** `server/internal/security/token.go`
**Problem:** Stateless tokens cannot be actively revoked before their expiration time.
**Impact:** Stolen admin session tokens remain valid until expiration.
**Proposed Solution:** Implement a fast-read blocklist (e.g., Redis) or keep session expiration times extremely short (e.g., 5-15 minutes).
**Priority:** P3

## Finding ID: SEC-005
**Category:** Agent Architecture
**Severity:** MEDIUM
**Current State:** Telemetry reporting signs data with `signingBytes`, wrapping a JSON payload.
**Evidence:** `clients/agentsec/sign.go`
**Problem:** JSON serialization is not inherently deterministic in Go without explicit canonicalization.
**Impact:** Potential false-positive signature rejections leading to loss of security telemetry.
**Proposed Solution:** Sign a deterministic canonical hash of the payload rather than the JSON representation itself.
**Priority:** P2

## Finding ID: SEC-006
**Category:** Operational Security
**Severity:** HIGH
**Current State:** The struct `Policy` includes `RateLimitRPS` but delegates enforcement to callers.
**Evidence:** `server/internal/scope/scope.go`
**Problem:** Missing centralized enforcement of rate limits.
**Impact:** A runaway SOAR playbook or compromised AI agent could flood the system with automated commands (e.g., quarantine storms).
**Proposed Solution:** Enforce the rate limiting centrally within the `secgateway` or `scope.Engine`.
**Priority:** P1

## Finding ID: SEC-007
**Category:** AI Security (Agentic Plane)
**Severity:** MEDIUM
**Current State:** `PropagateTrust` ensures trust levels monotonically decrease (`Tainted < Untrusted < Trusted`).
**Evidence:** `server/internal/aisec/aisec.go` (Lines 59-67)
**Problem:** There is no mechanism for an AI agent to explicitly "sanitize" or "cleanse" Tainted data. Once Tainted, always Tainted.
**Impact:** Operational deadlocks. Legitimate AI workflows that safely validate external input will remain permanently Tainted and blocked from executing trusted actions.
**Proposed Solution:** Introduce a formal `Sanitize()` capability that allows highly privileged principals to elevate a `Tainted` context to `Untrusted` after passing strict validation rules.
**Priority:** P2

## Finding ID: SEC-008
**Category:** Dual-Control Approvals
**Severity:** MEDIUM
**Current State:** `FinalizeAuthorization` re-validates the binding of the approval to the request.
**Evidence:** `server/internal/seccontract/approval.go` (Lines 81-119)
**Problem:** The `Nonce` and exact timestamp boundaries are not explicitly bound inside the `Approval` struct validation phase, relying entirely on the `ApprovalStore` for replay protection.
**Impact:** If the `MemApprovalStore` state is lost (e.g., a C2 restart), an attacker could theoretically replay a `FinalizeAuthorization` payload if the approval window hasn't expired.
**Proposed Solution:** Bind the approval explicitly to a nonce and ensure the `ApprovalStore` state is persisted or backed by a distributed lock (e.g., Redis).
**Priority:** P2

## Finding ID: SEC-009
**Category:** Evidence Integrity
**Severity:** LOW
**Current State:** `Verify()` checks the hash chain in memory.
**Evidence:** `server/internal/evidence/evidence.go` (Lines 183-201)
**Problem:** `Verify()` only checks the custody metadata chain. It does not automatically re-verify the payload hash against the actual physical file content.
**Impact:** An auditor might run `Verify()` and see a healthy chain, while the underlying physical file has been swapped out on disk.
**Proposed Solution:** Make `Verify()` explicitly call `VerifyContent()` if the raw evidence byte stream is available, or clearly document that it only verifies metadata custody.
**Priority:** P3

## Finding ID: SEC-010
**Category:** Configuration Management
**Severity:** HIGH
**Current State:** `config.go` reads highly sensitive variables (`KUT_MASTER_KEY`) via `secretEnv`.
**Evidence:** `server/internal/config/config.go` (Lines 163-179)
**Problem:** `os.Getenv` leaves the plaintext variable in the process's environment block. If the application crashes and dumps core, or if a subprocess is spawned, the master key is leaked.
**Impact:** Complete compromise of the database encryption.
**Proposed Solution:** After reading the key, immediately call `os.Unsetenv("KUT_MASTER_KEY")` and `os.Unsetenv("KUT_DATABASE_URL")` to clear them from memory.
**Priority:** P1

## Finding ID: SEC-011
**Category:** Configuration Management
**Severity:** MEDIUM
**Current State:** `KUT_TENANT_ENFORCE` defaults to `false` (disabled) if not explicitly set.
**Evidence:** `server/internal/config/config.go` (Line 157)
**Problem:** In a multi-tenant SaaS environment, forgetting to set this flag allows cross-tenant mingling where missing tenant IDs silently default to the "default" server tenant.
**Impact:** Catastrophic data spillage across tenants due to a simple configuration omission.
**Proposed Solution:** Default to a strict enforcement mode. Require an explicit `KUT_SINGLE_TENANT_MODE=1` flag to enable the relaxed backwards-compatible behavior.
**Priority:** P2

## Finding ID: SEC-012
**Category:** Evidence Integrity
**Severity:** MEDIUM
**Current State:** The genesis `CustodyEntry` has a blank `PrevHash`.
**Evidence:** `server/internal/evidence/evidence.go` (Line 144)
**Problem:** Without database-level immutability (like triggers or append-only tables), an attacker with DB access could completely delete an evidence record and insert a forged genesis entry.
**Impact:** Complete falsification of digital forensics evidence.
**Proposed Solution:** Implement PostgreSQL triggers to strictly reject `UPDATE` and `DELETE` operations on the `evidence_custody` table, enforcing append-only behavior at the engine level.
**Priority:** P2

## Finding ID: SEC-013
**Category:** AI Security (Agentic Plane)
**Severity:** LOW
**Current State:** `EffectiveCapabilities` calculates the intersection of capabilities.
**Evidence:** `server/internal/aisec/aisec.go` (Lines 106-128)
**Problem:** If `sets` is entirely empty, it returns an empty `CapSet`. However, if `sets[0]` is explicitly "all permissions" and the rest are empty, it might drop permissions unexpectedly based on array bounds checking. 
**Impact:** Potential capability calculation mismatch leading to fail-closed denials for valid AI workflows.
**Proposed Solution:** Add comprehensive unit tests covering empty array and edge-case intersection paths.
**Priority:** P3

## Finding ID: SEC-014
**Category:** File Permissions
**Severity:** MEDIUM
**Current State:** Private keys (`ServerKeyPath`, `CAKeyPath`) are read directly from disk.
**Evidence:** `server/internal/config/config.go`
**Problem:** The system does not verify that the private key files have strict permissions (e.g., `0600` or `0400`).
**Impact:** Local privilege escalation. Any user on the C2 host might read the CA key if the administrator made a mistake with `chmod`.
**Proposed Solution:** Before loading the keys, assert that the file mode restricts read access solely to the owner.
**Priority:** P2

## Finding ID: SEC-015
**Category:** Operational Security
**Severity:** MEDIUM
**Current State:** `MemApprovalStore` is memory-based.
**Evidence:** `server/internal/seccontract/approval.go` (Lines 58-79)
**Problem:** Since it is memory-based, if a C2 cluster has multiple nodes, an approval consumed on Node A might not be marked consumed on Node B.
**Impact:** Approvals could be finalized multiple times across different cluster nodes.
**Proposed Solution:** Replace `MemApprovalStore` with a distributed backend (like PostgreSQL row locking or Redis) for multi-node deployments.
**Priority:** P2
