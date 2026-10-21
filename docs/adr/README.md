# Architecture decision records

Numbers 0001-0040 are the existing records. Numbers 0041-0069 are reserved by
roadmap decision D19 for the decision sprint (WP-PM-025). The decision-sprint
records below have status `Accepted`: the owner accepted them under gate G12 on
2026-10-22 (`adrlint` green), and G0 evidence is the Accepted status and its date.

## Record layout

`# ADR-NNNN: Title`, then `## Status`, `## Context`, `## Decision`,
`## Consequences`, `## Alternatives`, `## Source decision` (the roadmap decision
id, Dn). The first four sections follow the existing records.

## Decision to ADR mapping (D19)

| Decision | ADR | Title |
|---|---|---|
| D1 | 0061 | Signed command envelope (DSSE) and local secure store (COSE) |
| D2 | 0061 | same record |
| D3 | 0049 | Lite topology: embedded WAL bus and command outbox |
| D4 | 0048 | Data plane: enterprise bus and hot store |
| D5 | 0048, 0049 | Hot store (Enterprise in 0048, Lite in 0049) |
| D6 | 0047 | KUT-QL compiler in Go |
| D7 | 0065 | Sigma engine: one kut-sigma crate |
| D8 | 0052 | AI gateway: Go policy point and Python worker |
| D9 | 0060 | Migrations with goose and database roles |
| D10 | 0044 | Contract-first interfaces, OpenAPI and test vectors |
| D11 | 0044 | same record |
| D12 | 0044 | same record |
| D13 | 0043 | Monorepo layout, build system and identifiers |
| D14 | 0043 | same record |
| D15 | 0043 | same record |
| D16 | 0053 | License policy |
| D17 | 0063 | Object storage behind an S3 API |
| D18 | 0043 | Monorepo layout, build system and identifiers |
| D19 | this file | ADR numbering and mapping |
| D20 | 0050 | TUF roots and the one-person gate rule |
| D21 | 0062 | Ring distribution and content signing roots |
| D22 | 0054 | Scheduler interface and Temporal for Enterprise |
| D23 | 0052 | AI gateway (permission `ai.use`) |
| D24 | 0055 | Single SLO and measurement table |
| D25 | 0042, 0045, 0058 | Language set; Rust strangler and GA-lean; eBPF sensor stack |
| D26 | 0041 | Lawful basis for endpoint telemetry |

## Numbering notes

- No number from 0041 on existed on `main` when these drafts were made, so there
  is no collision and D19 numbers are used as written.
- 0055 is inside the reserved block but is not named in D19. It holds D24 (SLO
  table) because the decision has no D19 number.
- D19 names these topics without a Dn in the decision list: 0046 (OCSF), 0051
  (web stack), 0066 (RLS, extends ADR-0002), 0067 (IdP), 0068 (Typst reports)
  and 0069 (data classification, extends ADR-0020). They stay reserved and are
  drafted when their work packages start.
- 0056, 0057, 0059 and 0064 are free inside the reserved block.
- Sprint 1 holds 0041-0050 (except 0046), sprint 2 holds 0052-0065.
