# roadmap/

Program plan and state for the KUT Security Suite.

| File | Purpose |
|---|---|
| `ROADMAP-v1.md` | Short roadmap: decisions D1-D26, milestones P-M0..P-M9, critical path |
| `status.yaml` | Single source of truth: one entry per work package (schema `kut-roadmap/v1`) |

## States

`planned` > `claimed` > `implemented` > `verified` > `done`; also `blocked` and
`dropped`.

- `claimed`: an implementer holds the WP. A claimed WP with `evidence` and a
  comment means a partial slice is merged.
- `implemented`: code merged, acceptance criteria not yet checked by a verifier.
- `verified`: a fresh, read-only verifier checked the acceptance criteria.
- `done`: verified and CI evidence recorded (invariant 10).

## Entry fields

`id`, `tier` (NOW, GA, V2, RES), `state`, `effort_ag` (nominal agent-days),
`title`, `depends_on` (WP ids), `gates` (G0-G18), `evidence` (`pr`, `ci_run`,
`tests`, `artifacts`). Dependencies marked "derived" in a comment come from
the critical path and are confirmed during the decision sprint (WP-PM-025).

## Rules

- Only the owner or the orchestrator changes `state`, and raising it needs CI
  evidence.
- A WP can be claimed only when all of its `depends_on` are `done`.
- Findings are tracked in `findings.yaml` (WP-SEC-002) with `SF-` ids and the
  fixing PR.
- Full detail (acceptance criteria, verification commands, delivery paths) lives
  in the track specs; when they are added they go under `roadmap/track-*.md`.
- This directory is part of the repository truth: a change to `status.yaml`
  that raises a state without evidence is rejected in review.

## Validation

Until `roadmapctl validate` exists (WP-PM-026), reviewers check: the file parses
as YAML, ids are unique, every `depends_on` id exists, the graph has no cycle,
the active nominal total is 784.0 agent-days over 348 active entries (350
entries including 2 dropped), and the file passes the repository naming rule
(AGENTS.md section 1).
