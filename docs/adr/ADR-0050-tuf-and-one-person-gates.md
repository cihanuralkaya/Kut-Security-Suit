# ADR-0050: TUF Roots and the One-Person Gate Rule

## Status
Proposed (decision sprint WP-PM-025; acceptance under gate G12, key matters under G7)

## Context
Updates and content are distributed with TUF. Today the project has one maintainer, so a rule that needs several people on paper would simply not be followed.

## Decision
- One-person gate rule: the owner acts alone, waits 30 minutes between request and execution, and signs with a hardware key.
- TUF root threshold is 2-of-3: two keys held by the owner in separate safes and one with a custodian.
- When a second human joins, the root moves to 3-of-5 and two reviewers are required for gate-controlled changes.
- Key ceremonies are recorded (gate G7).

## Consequences
- The control is something the team can actually perform.
- Loss of two of three keys needs a documented recovery path, part of the ceremony record.
- Online keys (timestamp, snapshot) are separate from root keys.

## Alternatives
- 3-of-5 now: rejected, no second person to hold keys.
- Single root key: rejected, a lost or stolen key would break the update chain.

## Source decision
D20 (roadmap section 3). Reserved by D19 (TUF).
