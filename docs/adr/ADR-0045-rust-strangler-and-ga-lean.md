# ADR-0045: Rust Strangler Path and GA-Lean Scope

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
A Rust agent core (kut-core) and data plane (kut-dp) are attractive for memory safety and throughput, but the plan carries seven toolchains for one maintainer and a large rewrite risk for GA.

## Decision
- GA-lean ships with the Go agent and Go services, plus C/WDK and eBPF-C sensors.
- Rust enters by the strangler pattern behind frozen wire contracts (ADR-0044) and test vectors, one component at a time.
- The month-4 spike (WP-PM-029) decides whether Rust kut-core and kut-dp enter GA. If the result is negative they move to v2.
- Any cutover from Go to Rust detection needs a 7-day shadow diff and a rollback rehearsal (gate G13).

## Consequences
- Scope and schedule of GA do not depend on the Rust rewrite.
- Wire formats must be language neutral from now on (DSSE, COSE, protobuf).
- Rust crates already planned in the workspace (ADR-0043) may exist as libraries without being on the GA path.

## Alternatives
- Rewrite in Rust before GA: rejected, schedule risk and review capacity.
- Never adopt Rust: rejected, keeps the option for the endpoint and data plane open.

## Source decision
D25 (roadmap section 3). Reserved by D19.
