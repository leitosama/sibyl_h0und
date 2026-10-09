---
name: monitor-run
description: Watch a live agent run's traces and report each finished task. Use when the user starts a run (h0und) and asks to monitor, watch or follow it.
---

# Monitor a run

## Start

1. Find the run directory: the newest one under `$TRACE_DIR`
   (default `~/.local/share/sibyl_h0und/traces`), or the one the user names.
2. Arm a Monitor with the maximum timeout:
   `python3 -u .claude/skills/monitor-run/watch_run.py <RUN_DIR> --seen <N> 2>&1`,
   where `N` is the number of the last task you already reported (0 at first).
   The script prints one block per finished task, a totals line every 5 tasks,
   and `STALL` after 5 quiet minutes.
3. When the Monitor expires, re-arm it with `--seen` set to the last reported
   task, so no task is reported twice.

## Report each task

Copy the script's block, then add one sentence of opinion:

```
[007 e33a8dfd] Q=0.30 E=0.44 score=0.23 reward=6 calls=17 llm=20 llm_s=51 challenged=1 reporter=kept fallback=None rejected=0 refused=0 tool_errors=0 llm_retries=0 end=terminated error=None
Result=benign correct
<one sentence: your opinion>
```

- `score` is the leaderboard score, `Q × (0.6 + 0.4 × E)` (`docs/competition.md`).
- `correct` and `incorrect` are a guess: the runtime never says whether a
  verdict was right, so `incorrect` means `Q < 0.2`, the `--wrong-below`
  heuristic in `docs/development.md`. Say so whenever a verdict is `incorrect`
  or Q sits near the threshold.
- `reporter` compares the sent report with the head's draft: `kept`, `text`
  (same ids and fields), `+A/-Rids,Ffields` (citations added, removed, and kept with changed property fields), or `none` (no reporter turn).
- To form the opinion, read the trace where the numbers point: the
  challenger's hypothesis on a challenged benign, the rejection feedback, the
  reporter's citation diff, or the calls spent against a low E. Name the
  concrete cause (an entity, a tool, a missed branch of the graph) rather
  than repeating the numbers.

After each totals line, add one sentence on the trend across those 5 tasks.

## Rules

- Per-call `reward` is for offline analysis only (ADR 0006): use it in
  reports to the user, never feed it into agent code or prompts.
- On `STALL`, check whether the `h0und` process still runs before calling the
  run finished.
