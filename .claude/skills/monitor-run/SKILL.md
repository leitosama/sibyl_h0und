---
name: monitor-run
description: Watch a live agent run's traces and report each finished task. Use when the user starts a run (h0und) and asks to monitor, watch or follow it.
---

# Monitor a run

## Start

1. Arm a Monitor with the maximum timeout:
   `uv run python -u .claude/skills/monitor-run/watch_run.py [RUN_DIR] --seen <N> 2>&1`,
   where `N` is the number of the last task you already reported (0 at first).
   - Run just started, or about to: omit `RUN_DIR`. The script waits for the
     first run directory created after it started (under `$TRACE_DIR`, default
     `~/.local/share/sibyl_h0und/traces`), so it never picks an older run.
   - Run already going, or the user named one: pass its directory.
2. The script prints `START` and one block per finished task, a totals line
   every 5 tasks, `STALL` after 5 quiet minutes while `h0und` still runs, and
   `RUN ENDED` (then exits) when the traces are quiet and `h0und` is gone.
3. When the Monitor expires, re-arm it with the same `RUN_DIR` and `--seen`
   set to the last reported task. Events already in the traces are replayed
   silently, so no task or `START` line is printed twice.

## Report each task

Copy the script's block, then add one sentence of opinion:

```
[007 e33a8dfd] Q=0.30 E=0.44 score=0.23 reward=6 calls=17 llm=20 llm_s=51 challenged=1 reporter=kept fallback=None rejected=0 refused=0 tool_errors=0 llm_errors=0 end=terminated error=None
Result=benign correct
<one sentence: your opinion>
```

- `score` is the leaderboard score, `Q × (0.6 + 0.4 × E)` (`docs/competition.md`).
- `correct` and `incorrect` are a guess: the runtime never says whether a
  verdict was right, so `incorrect` means `Q < 0.2`, the `--wrong-below`
  heuristic in `docs/development.md`. Say so whenever a verdict is `incorrect`
  or Q sits near the threshold.
- `reporter` compares the sent report with the head's draft: `kept`, `text`
  (same citations, kinds and fields), `+A/-Rids,Cchanged` (citations added,
  removed, and kept with a changed `kind` or property fields), `failed` (the
  reporter ran but the draft was sent; see `fallback`), or `none` (no reporter
  turn).
- `llm_errors` counts failed LLM calls (timeouts, provider errors), retried or not.
- To form the opinion, read the trace where the numbers point: the
  challenger's hypothesis on a challenged benign, the rejection feedback, the
  reporter's citation diff, or the calls spent against a low E. Name the
  concrete cause (an entity, a tool, a missed branch of the graph) rather
  than repeating the numbers.

After each totals line, add one sentence on the trend across those 5 tasks.

## Rules

- Per-call `reward` is for offline analysis only (ADR 0006): use it in
  reports to the user, never feed it into agent code or prompts.
- On `STALL` the agent still runs: look at the newest trace for a hung LLM or
  runtime call. Call the run finished only on `RUN ENDED`.
