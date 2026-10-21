# ADR-0052: AI Gateway: Go Policy Point and Python Worker

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12, model enablement under G11)

## Context
AI features (triage, hunting, summaries) handle sensitive data and can suggest actions. The trust boundary must sit in one language and one place, while model and retrieval code is naturally Python.

## Decision
- The AI gateway is a Go policy enforcement point in `server/internal/aigw`: authorization, DLP and secret brokering, audit, tenant binding. It is the only egress for AI traffic.
- Model and RAG code runs in a Python worker (`ai/worker`, a hardened successor of `services/ai`). No Python on hot paths.
- Access uses the permission `ai.use` instead of a new role; it is temporarily mapped to OPERATOR because there is no ANALYST role yet.
- AI output never authorizes an action (invariant 6); a requester gets no action without approval.
- Enabling a provider or model is gate G11 (model-card license, eval report).

## Consequences
- The worker can be replaced without touching the trust boundary.
- RBAC and rate limits apply to every AI route (WP-AI-002) and DLP is mandatory (WP-AI-003).
- The mapping to OPERATOR is revisited when the role model of ADR-0067 (reserved) lands.

## Alternatives
- Python policy layer: rejected, splits the trust boundary across languages.
- A new ANALYST role: deferred, role redesign belongs to the RBAC work.

## Source decision
D8, D23 (roadmap section 3). Reserved by D19.
