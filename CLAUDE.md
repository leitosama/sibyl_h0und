# CLAUDE.md

SOC investigation agents for the BlueSec competition (Positive Technologies).
Read `docs/competition.md` for rules and protocol and `docs/architecture.md`
for the design before changing agent logic.

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

- Do not edit `src/bluesec1_client/` or `proto/`: they are a vendored copy
  from the organizers. Regenerate `src/bluesec1_client/proto/` only via
  `scripts/generate_remote_proto.py`. Put extra behavior in `src/sibyl_h0und/`.
- Build runtime tool calls from the task's `available_tools`, never from a
  hard-coded list: tools may differ on the competition day.
- Every runtime tool call costs score. Do not add calls that repeat a known
  entity or relation lookup, and do not add a fixed step budget.
- `finish_investigation` may cite only ids the runtime actually returned.
- `h0und1` must never wait for a human.
- Never commit `.env*` (except `.env.example`), task dumps or traces. Traces
  live outside the repository. Keep at most 1–2 anonymized tasks in
  `tests/fixtures/`.
- Code, comments and commit messages in English; docs in `docs/` in Russian.
- Work in a branch and open a PR to `main`.
