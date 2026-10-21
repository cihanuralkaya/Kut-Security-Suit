# ADR-0043: Monorepo Layout, Build System and Identifiers

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
The repository grows from a Go service tree into a polyglot product. Layout, build entry point and identifier schemes must be fixed before skeletons are added, so that parallel work packages do not collide.

## Decision
- Layout: `web/` (pnpm), `endpoint/`, `dataplane/`, `detections/{rules,regression}`, `packs/`, `playbooks/`, `compliance/packs/`, `ai/` and `ai/worker/`, `lab/`, `contracts/`, `roadmap/`. The Go module stays in place.
- One Cargo workspace at the repository root (`endpoint/core/crates/*`, `dataplane/crates/*`, `crates/{kut-wire,kut-proto,kut-sigma}`) so versions cannot drift.
- Build is a Taskfile plus each language's own tool (cargo, go, pnpm, msbuild, xcodebuild, clang). Bazel or Buck2 is revisited when CI p50 exceeds 25 minutes or with four or more contributors.
- Identifiers: `WP-<PREFIX>-NNN` work packages, `SF-0xx` security findings (replacing SEC-001..015), `RQ-` queue items, `P-M#` milestones.

## Consequences
- The older roadmap statement that moves Go packages is superseded; no mass move of existing code.
- The Taskfile is a protected path (gate G18) and is owned by the owner.
- Removes the SEC- and AI- identifier namespace clash.

## Alternatives
- Bazel or Buck2 now: rejected, WDK, Xcode and BPF toolchains and one maintainer make the cost too high.
- Several repositories: rejected, contract and vector parity is easier to gate in one place.

## Source decision
D13, D14, D15, D18 (roadmap section 3). Reserved by D19.
