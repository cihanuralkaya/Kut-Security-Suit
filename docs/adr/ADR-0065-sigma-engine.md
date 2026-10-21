# ADR-0065: Sigma Engine: One kut-sigma Crate

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
Detections are written in Sigma. The server data plane and the agent must give the same result for the same rule, otherwise shadow diffs and agent-side detection cannot be trusted.

## Decision
- One crate, `kut-sigma` (compiler, intermediate representation, evaluator), owned by the data plane. The agent uses a subset of the same crate.
- The inner parser is selected by a bake-off (WP-DP-060) between candidates, and the choice is recorded here.
- Agent-local detection starts in audit mode only (WP-EP-081). Moving a Go detection path to Rust needs a 7-day shadow diff (gate G13).

## Consequences
- Goal: SigmaHQ rules compile at 90% or better, and the shadow diff stays at or under 0.5% (P-M6).
- Because the crate is Rust, it depends on the spike in ADR-0045; until then the Go evaluator is the reference and the vectors define behaviour.
- Rule promotion stays behind the promotion gate (invariant 12).

## Alternatives
- Separate engines for agent and server: rejected, semantic drift.
- Engine in Go only: possible fallback if the Rust spike fails.

## Source decision
D7 (roadmap section 3). Reserved by D19.
