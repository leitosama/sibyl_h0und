---
name: monitor-run
description: Watch a live agent run's traces, triage flagged tasks with a cheap model and list the ones worth a deep read. Use when the user starts a run (h0und) and asks to monitor, watch or follow it.
model: haiku
---

# Monitor a run

Three tiers, so that expensive models touch only what is worth it:

| Tier | Model | Does |
| --- | --- | --- |
| Monitor | Haiku (this skill) | keeps the loop, relays blocks, never opines or reads traces |
| Triage | Sonnet (`run-triage` agent) | gets only a task's digest text, answers `DEEP` or `SKIP` |
| Deep read | Opus (`run-deep` agent) | only when the user asks, for tasks listed as DEEP |

Start the monitor in its own background session on Haiku, so the loop never
runs on an expensive model:
`claude --bg --model haiku "/monitor-run [RUN_DIR] [--mode graded|practice]"`.

## Modes

The mode comes from the run's `agent_name` (`h0und1` is graded, anything else
practice); the watcher prints `MODE ...` once and `MODE MISMATCH` if `--mode`
contradicts the traces.

| | practice (`.env.h0und2`, h0und2) | graded (`.env.h0und1`, h0und1, the final) |
| --- | --- | --- |
| Agent started as | `uv run --env-file .env.h0und2 h0und`; `--run-label`, `--agent-name` allowed for experiments | `uv run --env-file .env.h0und1 h0und`, nothing else |
| Run metadata | may change | never change: name, label, arena and model come only from `.env.h0und1` |
| Scores | shown when the runtime gives them | never shown, no `correct`/`incorrect` |
| Monitor | as below | read-only |

Graded rules: do not edit `.env.h0und1`, do not pass metadata flags, do not
start, stop or restart `h0und`, and propose changes to code and prompts only.

## Start

1. Arm a Monitor with the maximum timeout:
   `uv run python -u .claude/skills/monitor-run/watch_run.py [RUN_DIR] 2>&1`
   (`--verbose` prints every task, `--seen <N>` skips tasks up to N,
   `--mode` forces a mode).
   - Run just started, or about to: omit `RUN_DIR`. The script waits for the
     first run directory created after it started (under `$TRACE_DIR`, default
     `~/.local/share/sibyl_h0und/traces`), so it never picks an older run.
   - Run already going, or the user named one: pass its directory.
2. The script prints single lines, each starting with a fixed keyword or glyph:

   | Line | Meaning | You do |
   | --- | --- | --- |
   | `MODE …` | mode, agent, label, model (once); `MODE MISMATCH` when `--mode` contradicts the traces | relay; push on MISMATCH |
   | `⚠`/`✖ #NNN verdict · flags [gates] · calls · tok` + an indented reason | a flagged task | triage (below) |
   | `Σ N/40 · ✔ ⚠ ✖ · ⌀calls · tok · ETA · DEEP: …` | totals every 5 tasks | relay |
   | `DASHBOARD <RUN_DIR>` | every 10 tasks and at the end | refresh the dashboard (below) |
   | `STALL …` | 5 quiet minutes while `h0und` runs | relay; push |
   | `RUN ENDED …` | traces quiet and `h0und` gone (the script exits) | relay the `Σ` line; push |

3. When the Monitor expires, re-arm it with the same `RUN_DIR`. Tasks already
   in `monitor.log` and `monitor.jsonl` are not printed again.

## What the user sees

The user watches an interactive session, so each surface has one job and the
prose is kept out:

- **Status line** (no tokens): `statusline.py` shows progress, ✔/⚠/✖, ⌀calls,
  tokens, ETA, the running task and DEEP candidates, refreshed by a timer.
  Enable it once in `.claude/settings.local.json`:
  `{"statusLine": {"type": "command", "command": "python3 .claude/skills/monitor-run/statusline.py", "refreshInterval": 5}}`.
  `MONITOR_RUN_DIR` pins a run, otherwise the newest under `$TRACE_DIR`.
- **Event lines**: copy the script's line verbatim, add only the triage
  answer. No paths, no environment names, no prose around it.
- **Sub-agent panel**: each triage is a background agent whose `description`
  is `Triage #NNN flags`, all started in one turn.
- **Push**: `PushNotification` with the event line on `DEEP`, `STALL`,
  `RUN ENDED` and `MODE MISMATCH` only.
- **Dashboard**: on `DASHBOARD <RUN_DIR>` run
  `python3 .claude/skills/monitor-run/render_dashboard.py <RUN_DIR>` and publish
  the printed `dashboard.html` with the Artifact tool, the same path each time
  (icon `chart`; first publish only), so the URL stays one. The page holds
  counts, flags and ids only.

## For each flagged line

Mechanical, no opinion of your own:

1. Run `uv run python .claude/skills/analyze-task/digest_task.py <RUN_DIR> <N>`
   (RUN_DIR is in the `Watching` line); keep its output as text.
2. Spawn one `run-triage` agent (`model: sonnet`, description
   `Triage #NNN <flags>`) per task with only that text as the prompt. Several
   flagged lines at once: all agents in one turn. Never pass a trace path.
3. Record the answer exactly as given:
   `uv run python .claude/skills/analyze-task/digest_task.py <RUN_DIR> <N> --triage "<answer>"`
   (appends to `analysis.log`; the answer must start with `DEEP` or `SKIP`).
4. Tell the user the event line plus ` → <answer>`; on `DEEP` also push it.

Do not `Read` or `grep` a trace file. Do not start `run-deep`: the Opus read
happens only when the user asks (`/analyze-task`, or "разбери №N"). `STALL`,
`RUN ENDED`, `MODE` and totals lines get no triage.

## Flags

| Flag | Meaning |
| --- | --- |
| `benign` | the verdict is benign: it overrules the detection, so it may be wrong |
| `challenged` | the benign challenger fired |
| `refused` | a report or answers were refused or a call was rejected |
| `fallback` | the reporter failed or the draft was sent |
| `tool_errors`, `llm_errors` | failed runtime or LLM calls |
| `not_terminated` | the task ended by anything but `terminated`, or with an error |
| `low_q` | `Q` below `--wrong-below` (practice, scores visible) |
| `rework` | 5 or more calls after the first try to finish: the gates sent the agent back |
| `repeat` | 3 or more repeated lookups (`tool_cached` plus identical arguments) |
| `near_ceiling` | 90% or more of the runtime call ceiling spent |
| `slow`, `heavy` | duration or tokens above the p90 of earlier tasks of the run (after 5 tasks) |

The last four count trace events only. They do not look at what an entity or
a knowledge entry says (ADR 0017). Every task also lands in `monitor.jsonl`;
`digest_task.py RUN --summary` tables it and
`digest_task.py RUN_A --compare RUN_B` puts two runs side by side (it warns
when graded meets practice).

## Scores

`score` is `Q × (0.6 + 0.4 × E)` (`docs/competition.md`). The block shows
`n/a` and `Result=… (scores not shown, <mode>)` in graded mode and whenever
the runtime leaves Q, E and reward unfilled. Never invent `correct` or
`incorrect` then. In practice with scores visible, `incorrect` is a guess
(`Q < 0.2`, `--wrong-below` in `docs/development.md`).

`reporter` compares the sent report with the head's draft: `kept`, `text`
(same citations, kinds and fields), `+A/-Rids,Cchanged`, `failed` (the
reporter ran but the draft was sent; see `fallback`), or `none`.
`llm_errors` counts failed LLM calls, retried or not.

## Rules

- Per-call `reward` is for offline analysis only (ADR 0006): never feed it
  into agent code or prompts.
- On `STALL` the agent still runs: say so and give the newest task's
  digest command (`digest_task.py latest <N>`). Call the run finished only on
  `RUN ENDED`; then list `deep candidates:` for the user.
