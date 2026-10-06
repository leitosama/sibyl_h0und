# CLAUDE.md

SOC investigation agents for the BlueSec competition (Positive Technologies).
Read `docs/competition.md` for rules and protocol, `docs/architecture.md`
for the design and `docs/adr/` for accepted decisions and their reasons
before changing agent logic.

## Commands

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

All three checks must pass before a commit. CI runs the same commands and has
no network or keys, so tests must not reach the runtime or an LLM.

## Rules

Each rule points to the ADR that explains it.

- Do not edit `src/bluesec1_client/` or `proto/`: they are a vendored copy
  from the organizers. Regenerate `src/bluesec1_client/proto/` only via
  `scripts/generate_remote_proto.py`. Put extra behavior in `src/sibyl_h0und/`.
  (ADR 0001)
- Build runtime tool calls from the task's `available_tools`, never from a
  hard-coded list: tools may differ on the competition day. (ADR 0003)
- Every runtime tool call costs score, but quality outweighs it. Do not add
  calls that repeat a known entity or relation lookup, and do not add a step
  budget to save calls. The only call limit is a safety ceiling in code below
  the runtime's 100 calls, counted in runtime calls, that leaves room for
  `finish_investigation`; the one other bound is a stall guard on locally
  answered turns in a row, which spends no calls. (ADR 0004, 0005, 0015)
- `finish_investigation` may cite only ids the runtime actually returned,
  and only entities that belong to the incident: extra report entities are
  penalized. (ADR 0005, 0013)
- Never use the per-call `reward` from the runtime in agent logic, prompts
  or model messages; it is for offline trace analysis only. (ADR 0006)
- Send the model only new evidence: the alert and tool catalog once, then
  each `last_tool_result` in full. (ADR 0007)
- A run against an arena must never wait for a human; interactive debug
  modes work only offline. Retry only transient LLM errors, with bounded
  delays. (ADR 0009)
- Flags are deterministic and advisory: no model, network, clock or extra
  runtime calls, every rule names its source, and the model decides the
  verdict. (ADR 0010, 0011)
- Knowledge comes from committed JSON packs built by
  `scripts/build_<name>_pack.py`, with provenance; agents and CI never
  fetch it at run time. Merge a rule
  change or a new source only after `scripts/replay_flags.py --compare`
  against `main`. (ADR 0010, 0012)
- Never commit `.env*` (except `.env.example`), task dumps or traces. Traces
  live outside the repository. Keep at most 1–2 anonymized tasks in
  `tests/fixtures/`. (ADR 0002, 0008)
- Code, comments and commit messages in English; docs in `docs/` in Russian.
- Work in a branch and open a PR to `main`.

## Decisions

- A change that makes or reverses an architectural decision adds an ADR in
  `docs/adr/` (template and index in `docs/adr/README.md`) in the same PR.
- Do not rewrite an accepted ADR; supersede it with a new one and mark the
  old one as replaced.
- Open hypotheses (roles, stack, models) stay in `docs/architecture.md`
  until a choice is made.
