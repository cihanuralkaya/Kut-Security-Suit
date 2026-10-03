# ADR-0003: Centralized Rate Limiting Enforcement in Scope Engine

## Status
Accepted

## Context
Currently, `scope.Policy` has a `RateLimitRPS` field, but its enforcement was left to the caller (e.g., API layer or workers). However, in a fail-closed, defense-in-depth architecture, any caller forgetting to check rate limits could inadvertently allow AI or SOAR components to flood the system with high-impact operations.

While `authz.Gateway` handles per-principal rate limiting, we need a mechanism to enforce per-policy RPS limits directly at the engine level for each target/action to ensure consistent behavior across all paths (API, worker, agent, SOAR).

## Decision
1. We will enforce `RateLimitRPS` directly within the `scope.Engine.Authorize()` method.
2. We implement a simple token-bucket rate limiter natively in Go, avoiding any external dependencies, to adhere to the package's "pure Go" philosophy.
3. The rate limit state will be isolated per `tenant` and `action` to prevent cross-tenant starvation or action conflicts.
4. If a rate limit is exceeded, the `Authorize` method will return a `Decision` with `Allowed: false` and a clearly defined reason indicating the rate limit was breached.

## Consequences
- **Positive:** Centralized protection guarantees that no caller can bypass rate limiting, providing safety against misconfigured SOAR loops.
- **Positive:** No external dependencies are added to the critical path.
- **Negative:** Minor in-memory overhead for tracking rate limit states per tenant and action.
- **Negative:** Does not scale out-of-the-box in a distributed setup (each node will have its own rate limiter instance). We accept this for now as scope rate limits act as a local safety guardrail per node rather than a global strict quota.
