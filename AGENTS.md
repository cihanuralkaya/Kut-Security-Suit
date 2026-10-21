# AGENTS.md

Binding rules for every coding agent and every human contributor in this
repository. Owner-maintained: any change to this file needs the owner's explicit
approval (gate G17) and is never made by an agent.

## 1. Naming and attribution (hard rule)

- The product name of the coding-agent tool never appears, in any case or
  spelling, anywhere in this repository or its metadata: tracked files (code,
  comments, docs, test data, file names), commit messages, trailers, author and
  committer identity, branch and tag names, PR and issue titles and bodies,
  release notes, repository description and topics.
- No co-author trailers, no "generated with" lines, no session-id or other
  attribution trailers of any kind. Commits carry the owner's identity only.
- Refer to the tool neutrally: "coding agent", "agent CLI", "orchestrator",
  "implementer", "verifier".
- The deny pattern is held in the protected gate repository, not in this file.
  CI fails a PR that matches it in a path, a diff, a commit message or PR text.
- The local agent instruction file and the local agent-CLI configuration
  directory are never tracked and never named in the repository. They live on the
  developer machine, are excluded through `.git/info/exclude` (every clone and
  every worktree), and the instruction file only imports this file.

## 2. Invariants (14, binding)

1. Signature and verification are never weakened (command envelope, OTA wire,
   script wire, policy and rule bundles, TUF). A verification failure means
   reject plus a security event. No temporary bypass.
2. Secrets and keys never enter the repository, logs or agent context.
3. Tenant isolation: the application role is NOSUPERUSER and NOBYPASSRLS and
   every query runs under `SET LOCAL app.tenant_id`. The tenant is resolved on
   the server and never taken from a request. Write no code or migration that
   bypasses RLS.
4. A security fix needs a failing test first: test PR, then fix PR
   ("red-on-base").
5. Tests are never deleted or skipped. Test counts and coverage of security
   packages never go down.
6. Destructive actions (WIPE, UNINSTALL) stay dual-approved and signed. AI
   output never authorizes an action.
7. Kernel code does not interpret content. Content ships through rings.
8. License policy (ADR-0053). Allowed: MIT, BSD, Apache-2.0, ISC. MPL-2.0:
   only unmodified. LGPL: dynamic linking, or the permissive option of a dual
   license. Forbidden in shipped or embedded parts: GPL, AGPL, BUSL, SSPL,
   ELv2; such products are used by API only and are never bundled.
9. Contract first: proto, OpenAPI and test vectors are the single source.
   Changes are gated by `buf breaking` and `oasdiff`.
10. Unwired code is not "done". `roadmap/status.yaml` advances only with CI
    evidence.
11. No real customer data in development. Support bundles only with `--redact`.
12. Rules and model output reach production only through the promotion gate.
13. One WP = one worktree = one PR (about 500 changed lines at most). At most
    2 implementation streams and 1 critical WP at the same time.
14. When uncertain, stop and ask. Where a human gate applies, the agent reports
    and does not proceed.

## 3. Roles, one writer, WIP

- Roles: orchestrator (plans, dispatches, reviews, reports, merges under
  section 4; writes no code), implementer (one WP per fresh session in its own
  worktree), verifier (fresh context, read-only), owner (tags, keys, gates; may
  merge any PR).
- One writer: by default exactly one agent writes to the repository at a time.
  A second writer is allowed only in a separate git worktree and only with
  file sets that are disjoint from the first writer's (checked before the
  second session starts). Two writers in one worktree are never allowed.
  Reviewers and researchers are read-only.
- WIP caps (invariant 13): at most 2 implementation streams, at most 1 critical
  WP (the open critical-path item in `roadmap/ROADMAP-v1.md`). The review queue
  limit is 5 open PRs; at 5 or more, no new WP is claimed.
- A WP is claimed in `roadmap/status.yaml` before work starts and its
  dependencies must be `done`.

## 4. Merge authority and agent limits

- The orchestrator merges a PR when all three hold: CI is green, the verifier
  (QA) reports GO, and the orchestrator has reviewed the diff itself. The owner
  may still merge any PR at any time.
- Gate evidence must be present in the PR before merge: every gate that the
  change triggers (section 5, G1-G18) has its evidence listed in the PR body and
  reproducible from CI. A gate whose evidence is an owner action (G7, G9, G17,
  G18 and the like) needs that action recorded; without it the PR waits.
- Agents never: tag, trigger a release, touch keys or certificates, change
  protected paths, or read credential stores. Protected paths: `.github/`,
  `AGENTS.md`, `Taskfile.yml`, `taskfiles/`, `.gitleaks.toml`, `deny.toml`,
  baseline and golden files, CODEOWNERS, and the local agent files. Server-side
  rulesets enforce this; client hooks are a second layer.
- Stop immediately and report when: an invariant hook fires, the test count
  drops, a gate file is about to change, the daily budget is exceeded, the same
  WP failed twice, or the model or agent CLI version changed.

## 5. Human gate catalogue (short form)

| Gate | Trigger | Evidence |
|---|---|---|
| G0 | decision-sprint ADRs | ADR Accepted plus date |
| G1 | `proto/` or `contracts/**` change | `buf breaking` / `oasdiff` report, vector diff |
| G2 | DB migration | up and down, NOBYPASSRLS test, lock estimate |
| G3 | crypto or signature code | review note (SEC-006), vectors, mutation score |
| G4 | driver, kernel, eBPF | 24 h Driver Verifier stress, static analysis, VM artifact |
| G5 | destructive action, autonomy level | approval flow e2e, audit record |
| G6 | release (tag) | full gate matrix green, provenance, signature |
| G7 | key ceremony or certificate | ceremony record, hardware key |
| G8 | new dependency or license exception | `deps/allowlist.yaml` row plus license proof |
| G9 | privacy and legal (lawful basis, DPIA, transfers) | counsel approval record |
| G10 | detection content promotion | false-positive regression, two-eyes, signature |
| G11 | AI provider or model enablement | model-card license, eval report |
| G12 | ADR acceptance | `adrlint` green |
| G13 | cutover (PG to ClickHouse/DuckDB, Go to Rust detection) | 7-day shadow diff, rollback rehearsal |
| G14 | pilot or GA decision | exit checklist |
| G15 | customer data access | redaction proof, DPA |
| G16 | external communication (advisory, regulator notice) | PSIRT record |
| G17 | local agent configuration, instruction files, hooks, managed settings | owner edits by hand |
| G18 | gate definitions (CI workflows, scanner configs, baselines, CODEOWNERS) | owner edits by hand |

## 6. How to work

- Evidence comes from CI, not from the agent's statement. A PR body lists WP id,
  finding ids (`SF-`), invariants touched, gates and the commands run.
- Local gate before a PR (all must pass): gofmt clean on tracked `.go` files;
  `go vet ./...`; `go vet -tags enterprise ./server/...`; `go test ./...`
  (CI adds `-race`); `GOOS=linux` and `GOOS=windows` builds of `./...`;
  `go build -tags enterprise ./...`; zero-dependency guard (no clickhouse,
  nats, kafka, aws, minio, jetstream, segmentio in
  `go list -deps ./server/cmd/c2`); generated proto code is built with
  `make proto` and never committed.
- Server rules: the tenant of any request comes from the authenticated
  principal, never from a header, body or query. Unknown or inactive principals
  fail closed. Every new route declares its minimum role and tenant scope.
- Console rules (`server/internal/adminapi/console.html`): exactly one nonce
  script, no inline event handlers, all dynamic text through the escaper.
- Security-fix PRs carry the `security-fix` label and a failing test on base.
- Commit messages: imperative subject, English. No trailers.
- Language of docs: English by default; user-facing product text follows the
  product i18n files.
- Never put customer data, credentials or key material in prompts, fixtures or
  logs. Test keys are generated, public and labelled.
- Decisions that freeze a wire or storage format need an accepted ADR first.
  The command envelope is DSSE (ADR-0061, decision D1): payloadType
  `application/vnd.kut.cmd.v2`, payload is the deterministic `signed_body`
  without `key_id`, multiple signatures through the DSSE `signatures` list.
  The trust statement is DSSE too (`application/vnd.kut.trust.v2`).

## 7. Where things live

- `roadmap/ROADMAP-v1.md`: decisions D1-D26, milestones, critical path.
- `roadmap/status.yaml`: single source of truth for work-package state.
- `docs/adr/`: decisions; numbers 0041-0069 are reserved by the roadmap.
- `docs/MULTI-TENANCY.md`, `docs/CONTRACTS.md`: current isolation and contract
  documents.
