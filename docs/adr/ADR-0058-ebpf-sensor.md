# ADR-0058: Linux eBPF Sensor Stack

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner, implementation under G4)

## Context
Linux event capture should be kernel assisted without kernel modules. The loader library affects license, language and review effort.

## Decision
- The GA-lean loader is cilium/ebpf (MIT) from the Go agent, using CO-RE objects.
- BPF object code carries the license string `Dual BSD/GPL`, as the kernel requires for GPL-only helpers; the objects are built from C in this repository.
- libbpf-rs (BSD-2 option) or aya are candidates only if the Rust agent core is adopted (ADR-0045).
- eBPF programs observe and report; they do not interpret content (invariant 7). Enforcement paths need a separate ADR and G4 evidence.

## Consequences
- Sensors need verifier and kernel-matrix tests in the lab.
- A new BPF program is a G4 change.
- The license of the loader and the object license are recorded in the dependency allowlist (G8).

## Alternatives
- aya or libbpf-rs now: deferred until the Rust decision.
- auditd and fanotify only: kept as a fallback, not sufficient for event-driven capture.

## Source decision
D25, with the technology table in roadmap section 4. Reserved by D19.
