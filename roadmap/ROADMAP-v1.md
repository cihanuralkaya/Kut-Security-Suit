# KUT roadmap v1 (short)

Source of truth for state is `status.yaml`. The long form with acceptance
criteria is kept in the track specs. Dates are P50 for one maintainer; the plan
recommends two additional engineers from month 3. Work packages are referenced
by id (`WP-<PREFIX>-NNN`, see D18) and resolve to entries in `status.yaml`.

## Execution model

The owner runs an agent CLI on a local machine with a pinned model identifier
and a pinned CLI version. Code context goes to the model provider API, so real
customer data, secrets and personal data never enter the agent context. The
orchestrator plans, reviews and merges under the merge rule in `AGENTS.md`
section 4; implementers work one WP per worktree; verifiers are read-only. By
default one agent writes to the repository at a time. Gates G0-G18 stop the line
at human decisions (see `AGENTS.md`).

## Decisions (D1-D26)

Each decision becomes an ADR in `docs/adr/` (numbers 0041-0069, D19) and is
accepted by the owner under gate G12 (decision sprint: WP-PM-025).

| # | Decision |
|---|---|
| D1 | Command envelope v2 is DSSE: payloadType `application/vnd.kut.cmd.v2`, payload is the deterministic `signed_body` without `key_id`, multi-signature through the DSSE `signatures` list; signed `command_id` equals the DB id; verifier bound in production; command plane always on. TrustStatement is DSSE (`application/vnd.kut.trust.v2`). Rework: WP-CP-004, WP-EP-001 |
| D2 | Agent local store is COSE_Encrypt0 (RFC 9052); key wrapping per OS; no custom format (WP-EP-006) |
| D3 | Lite bus is an embedded segment WAL in kut-dp, no NATS; command fan-out through a PG outbox with LISTEN/NOTIFY |
| D4 | Enterprise bus is Apache Kafka 4.x (KRaft); Redpanda is not bundled; CI image is pinned |
| D5 | Hot store: ClickHouse (Enterprise), DuckDB with Parquet (Lite); transitional Lite-Legacy PG |
| D6 | KUT-QL compiler in Go inside the Query API; grammar and vectors in `contracts/kutql/` |
| D7 | One `kut-sigma` crate (compiler, IR, evaluator), owned by the data plane; agent uses a subset of it |
| D8 | AI gateway is a Go policy point (authz, DLP, audit, tenant) plus a Python worker; no Python on hot paths |
| D9 | Migrations use goose under `db/postgres/migrations/` and `db/clickhouse/migrations/` (WP-CP-001) |
| D10 | OpenAPI is code-first with huma v2; spec committed under `contracts/openapi/`; drift test and `oasdiff`; route metadata mandatory (WP-CP-016, WP-CP-017) |
| D11 | `proto/` stays at the root; `agent.proto` changes belong to WP-EP-032 |
| D12 | Test vectors under `contracts/testvectors/<format>/`; one Go-Rust runner (WP-EP-031) |
| D13 | One Cargo workspace at the repo root |
| D14 | Layout: web, endpoint, dataplane, detections, packs, playbooks, compliance/packs, ai, lab, contracts, roadmap; Go module stays in place |
| D15 | Build is a Taskfile plus each language's own tool; revisit Bazel when CI p50 exceeds 25 min or with 4 or more contributors |
| D16 | MPL-2.0 is allowed unmodified |
| D17 | Object storage is behind an S3 API abstraction; no AGPL server is bundled |
| D18 | Ids: `WP-<PREFIX>-NNN`, `SF-0xx` findings, `RQ-` queue items, `P-M#` milestones |
| D19 | ADR numbers 0041-0069 are reserved by topic; mapping in `docs/adr/README.md` |
| D20 | One-person gate rule: owner, 30 minute wait, hardware-key signature; TUF root 2-of-3 |
| D21 | Two content signing roots: vendor content via offline TUF; tenant rules via the C2 signer after the promotion gate |
| D22 | Scheduler interface: leader cron in Lite, Temporal in Enterprise |
| D23 | AI permission `ai.use`, temporarily mapped to OPERATOR |
| D24 | One SLO table (see below) |
| D25 | GA language set is Go, TypeScript, C/WDK and eBPF-C; Rust core depends on the month-4 spike (WP-PM-029) |
| D26 | Telemetry lawful basis is legitimate interest with notice and DPIA/LIA, not consent; consent only for BYOD and optional features |

## Milestones

| P-M | Name | P50 | Exit |
|---|---|---|---|
| P-M0 | Bootstrap, decision sprint, repo truth (WP-PM-001..010, WP-PM-025..028) | month 0-1 | validator green, hook tests, ADR numbers reserved |
| P-M1 | P0 security (WP-CP-001..010, WP-EP-000..011) | month 1-4 | no open Critical, cross-tenant test under NOBYPASSRLS, unsigned or stale command rejected e2e, no event loss after kill -9 |
| P-M2 | Contracts and skeleton (WP-PM-011..015, WP-EP-031) | month 4-6 | Go-Rust vector parity, contract-breaking checks in CI, signed releases verifiable |
| P-M2a | Friendly-customer alpha | about month 6 | owner and customer DPA |
| P-M3 | Pilot, NOW tier (WP-SEC-030..050) | month 6-11 | G14 pilot: 10k EPS, command p95 under 1 s, honest lab coverage report, counsel-approved DPIA |
| P-M4 | Data factory (WP-DP-050..058, WP-UX-010..025) | month 11-17 | cutover and rollback rehearsal, zero cross-tenant leaks in query fuzz |
| P-M5 | Event-driven endpoint (WP-EP-060..072) | month 14-22 | 99% exec capture in lab, zero P0 loss over 72 h offline |
| P-M6 | XDR core (WP-DP-060..078, WP-SEC-024..026) | month 20-27 | SigmaHQ 90% compiles, shadow diff 0.5% or less, ring chaos test |
| P-M7 | GA hardening (WP-CP-040..063, WP-SEC-027..051) | month 26-30 | RPO 0, RTO under 15 min, external pentest with no Critical |
| P-M8 | v2 | after GA | macOS, prevent, live query, SOAR, MSP, lake, copilot |
| P-M9 | Research | n/a | research items |

## Critical path

1. Decision sprint (D1, D2) then WP-CP-004 with WP-EP-001 and WP-EP-002, then
   WP-EP-006 securestore, then WP-EP-008 queue, then pilot.
2. WP-CP-001 goose, then WP-CP-002a/b/c RLS, then WP-CP-016/017 OpenAPI, then
   the React console P0.
3. Lab (WP-SEC-030), FP corpus (WP-SEC-033), signed content (WP-SEC-024), rings
   (WP-SEC-025), agent local detection (WP-EP-081).
4. Code-signing certificate, partner portal, then the driver chain
   (WP-EP-013, WP-EP-012/014, WP-EP-061, WP-EP-063).
5. Counsel, ADR-0041 and DPIA, then the pilot gate (G14).

## SLO targets (all need a benchmark before they count)

Command latency under telemetry saturation: pilot p95 under 1 s; GA p50 under
300 ms, p95 under 1 s, p99 under 2 s. Ingest: pilot 10k EPS multi-node; GA Lite
5k EPS sustained, Enterprise 50k EPS per node. Offline: pilot zero loss across
kill -9; GA 72 h with zero P0 loss. Exec capture 99% in lab. Agent CPU 2% mean,
150 MB RSS. Hunting: pilot p95 under 3 s; GA 1 billion rows, 24 h `stats count
by` under 5 s. HA/DR: RPO 0, RTO under 15 min.
