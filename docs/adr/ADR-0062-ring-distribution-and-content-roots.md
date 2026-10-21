# ADR-0062: Ring Distribution and Content Signing Roots

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12, keys under G7)

## Context
Detection content and policies change often and a bad package can disable endpoints. A compromised server must not be able to push vendor content. Tenant authors still need to ship their own rules.

## Decision
- There are two signing roots. Vendor content is signed offline and delivered through TUF (ADR-0050). Tenant rules are signed by the C2 `kut-signer` after the promotion gate (invariant 12, gate G10).
- The agent trusts the two roots with separate scopes, so a server key cannot sign vendor content.
- Content ships in rings (staged groups of endpoints). A bad package in a small ring causes an automatic halt and a return to the last known good version (WP-SEC-025).
- Content is data evaluated in user mode (invariant 7); the kernel never interprets it.

## Consequences
- The server compromise case no longer bypasses the publisher signature.
- A ring chaos test is a P-M6 exit criterion.
- Key ceremonies are needed for both roots (gate G7).

## Alternatives
- One root: rejected, server compromise would sign vendor content.
- No rings: rejected, one bad package would reach every endpoint.

## Source decision
D21 (roadmap section 3). Reserved by D19.
