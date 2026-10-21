# ADR-0053: License Policy

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner, exceptions under G8)

## Context
Invariant 8 sets the license rules. Several planned components sit near the line (MPL-2.0 tools, AGPL servers, BSL brokers), and a scan result in `THIRD_PARTY_LICENSES.md` has been read as policy.

## Decision
- Allowed: MIT, BSD, Apache-2.0, ISC.
- MPL-2.0 is allowed when unmodified (examples: axe-core as a test dependency, OpenBao as a secrets manager, Vector as a component).
- LGPL only through dynamic linking, or through the permissive option of a dual license.
- Forbidden in shipped or embedded parts: GPL, AGPL, BUSL, SSPL, ELv2. Such products can be integrated by API only and are never bundled (examples: Redpanda, MinIO server, MISP, Velociraptor, Elastic EUI).
- `THIRD_PARTY_LICENSES.md` is a scan result, not policy. A new dependency or exception needs a row in `deps/allowlist.yaml` and license proof (gate G8).

## Consequences
- A CI license gate (WP-SEC-016) blocks forbidden licenses.
- Model weights are checked per checkpoint; Llama and Gemma 3 style licenses are not defaults.
- Choices in ADR-0048 and ADR-0063 follow from this policy.

## Alternatives
- Allow copyleft with isolation: rejected, too hard to audit for a small team.
- Ban MPL: rejected, would exclude useful unmodified tools.

## Source decision
D16 (roadmap section 3), invariant 8. Reserved by D19.
