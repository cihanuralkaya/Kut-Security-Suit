# ADR-0047: KUT-QL Compiler in Go

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12)

## Context
KUT-QL is the search and query language of the platform. Every query must carry the caller's tenant and authorization context, and tenant predicates must not be bypassable by query text.

## Decision
- The KUT-QL compiler is written in Go and runs inside the Query API, where the authenticated principal is known.
- The compiler injects the tenant predicate and column permissions; user text cannot remove them.
- Grammar and golden vectors live in `contracts/kutql/` (ADR-0044), so other implementations can be checked against them.

## Consequences
- Query fuzzing for cross-tenant leaks is a release criterion for the data factory milestone (P-M4).
- Backends (ClickHouse, DuckDB) receive compiled, already scoped queries.
- A Rust port, if any, must pass the same vectors.

## Alternatives
- Compiler in the data store or in Rust: rejected, authorization context lives in the Go API.
- Pass-through SQL: rejected, tenant injection could not be guaranteed.

## Source decision
D6 (roadmap section 3). Reserved by D19.
