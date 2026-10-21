# ADR-0054: Scheduler Interface and Temporal for Enterprise

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
Scheduled searches, SOAR playbooks and housekeeping need durable scheduling. A workflow engine is a heavy operational load for a single operator in Lite.

## Decision
- Scheduling sits behind an interface. Lite implements it with a leader-elected cron (WP-DP-073); Enterprise uses Temporal (SDK and server, MIT).
- SOAR is optional in Lite and first-class in Enterprise.
- Playbooks that run destructive actions stay dual-approved and signed (invariant 6).

## Consequences
- Both implementations pass one contract test suite.
- Temporal adds operational cost only for Enterprise customers.

## Alternatives
- Temporal in Lite: rejected, operations overhead.
- Cron only: rejected, no durable long-running workflows for Enterprise SOAR.

## Source decision
D22 (roadmap section 3). Reserved by D19 as 0054.
