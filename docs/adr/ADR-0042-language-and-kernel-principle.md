# ADR-0042: Language Set and Kernel Principle

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12)

## Context
The product spans a kernel driver, eBPF sensors, an agent, Go services, a data plane, a web console and AI workers. A single-language rule would be wrong for several layers, while seven toolchains are too many for one maintainer.

## Decision
- No single language is mandated. Each component takes the best fit by security, performance, maintenance cost and fabric integrity, and the choice is recorded in an ADR.
- GA language set: Go, TypeScript, C (WDK) and eBPF-C. Python only in the AI worker (ADR-0052). Rust for the agent core and data plane is outside the GA set until the month-4 spike (WP-PM-029, ADR-0045) says otherwise.
- Kernel principle (invariant 7): kernel code does not interpret content. Content (rules, signatures, policies) ships as signed data through rings (ADR-0062) and is evaluated in user mode.

## Consequences
- The toolchain count stays at four for GA, which a small team can maintain.
- Any new language needs an ADR and a gate G8 dependency review.
- Kernel code stays small, which reduces the crash and review surface.

## Alternatives
- Rust everywhere: rejected for GA, seven toolchains and a driver ecosystem that is still immature on Windows.
- Go only: rejected, kernel and eBPF need C, and the console needs TypeScript.

## Source decision
D25 (roadmap section 3), invariant 7. Reserved by D19.
