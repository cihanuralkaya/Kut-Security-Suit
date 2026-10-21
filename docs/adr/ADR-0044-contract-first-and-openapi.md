# ADR-0044: Contract-First Interfaces, OpenAPI and Test Vectors

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
Wire and API formats are shared between Go, Rust, TypeScript and C code. Drift between implementations is a security risk, and 109 admin routes need to move to a described contract step by step.

## Decision
- Contract first (invariant 9): `proto/`, OpenAPI and test vectors are the single source; changes are gated by `buf breaking` and `oasdiff` (gate G1).
- OpenAPI is code-first with huma v2 (MIT). The generated spec is committed as `contracts/openapi/admin.v1.yaml`, with a drift test and `oasdiff` in CI. Route metadata (minimum role, tenant scope, audit) is mandatory.
- `proto/` stays at the repository root. `agent.proto` changes have one owner, WP-EP-032, so there are no parallel proto PRs.
- Test vectors live under `contracts/testvectors/<format>/` with a single Go and Rust runner (WP-EP-031).

## Consequences
- Routes are migrated incrementally to huma; routes not yet described are listed and shrink over time.
- Every wire format change carries a vector diff in the PR.
- Spec generation becomes part of the build; the committed spec is the reviewed artifact.

## Alternatives
- Spec-first with a generator: rejected, high friction while 109 routes already exist.
- No committed spec: rejected, breaking changes could not be diffed.

## Source decision
D10, D11, D12 (roadmap section 3). Reserved by D19.
