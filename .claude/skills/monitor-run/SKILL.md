---
name: monitor-run
description: Watch a live agent run's traces and report flagged tasks and totals. Use when the user starts a run (h0und) and asks to monitor, watch or follow it.
---

# Monitor a run

The watcher is quiet by design: it writes every finished task to
`monitor.log` in the run directory and prints only flagged tasks and totals,
so a routine task costs no model turn.

## Start

1. Arm a Monitor with the maximum timeout:
   `uv run python -u .claude/skills/monitor-run/watch_run.py [RUN_DIR] 2>&1`
   (add `--verbose` to print every task, `--seen <N>` to skip tasks up to N).
   - Run just started, or about to: omit `RUN_DIR`. The script waits for the
     first run directory created after it started (under `$TRACE_DIR`, default
     `~/.local/share/sibyl_h0und/traces`), so it never picks an older run.
   - Run already going, or the user named one: pass its directory.
2. The script prints `Watching`, one block per flagged task, a totals line
   every 5 finished tasks, `STALL` after 5 quiet minutes while `h0und` still
   runs, and `RUN ENDED` (then exits) when the traces are quiet and `h0und`
   is gone.
3. When the Monitor expires, re-arm it with the same `RUN_DIR`. Tasks already
   in `monitor.log` are not printed again.

## Flags

A task is printed when it has at least one flag:

| Flag | Meaning |
| --- | --- |
| `benign` | the verdict is benign: it overrules the detection, so it may be wrong |
| `challenged` | the benign challenger fired |
| `refused` | a report or answers were refused or a call was rejected |
| `fallback` | the reporter failed or the draft was sent |
| `tool_errors`, `llm_errors` | failed runtime or LLM calls |
| `not_terminated` | the task ended by anything but `terminated`, or with an error |
| `low_q` | `Q` below `--wrong-below` (only when scores are visible) |

## Report

Per flagged block: one sentence of opinion, not a copy of the block. Decide
the depth by cost:

- Obvious from the block (a tool error, an LLM timeout, a fallback): say the
  cause in your own words.
- A benign verdict, a challenge, or anything unclear: run the `analyze-task`
  skill (digest, then a cheap-model triage) instead of opening the trace.
  Do not `Read` a trace file here.

After each totals line, add one sentence on the trend across those 5 tasks.

## Scores

`score` is `Q × (0.6 + 0.4 × E)` (`docs/competition.md`). On the closed stage
the runtime does not give Q, E or reward: the block then shows `n/a` and
`Result=… (scores hidden)`. Do not invent a `correct`/`incorrect` then; judge
by flags, call counts (`calls`, `ktok`) and what the digest shows. When scores
are visible, `incorrect` is a guess (`Q < 0.2`, the `--wrong-below` heuristic
in `docs/development.md`): say so when a verdict is `incorrect` or Q sits
near the threshold.

`reporter` compares the sent report with the head's draft: `kept`, `text`
(same citations, kinds and fields), `+A/-Rids,Cchanged` (citations added,
removed, and kept with a changed `kind` or property fields), `failed` (the
reporter ran but the draft was sent; see `fallback`), or `none` (no reporter
turn). `llm_errors` counts failed LLM calls, retried or not.

## Rules

- Per-call `reward` is for offline analysis only (ADR 0006): use it in
  reports to the user, never feed it into agent code or prompts.
- On `STALL` the agent still runs: look at the newest trace for a hung LLM or
  runtime call (`digest_task.py latest <N>`). Call the run finished only on
  `RUN ENDED`.
