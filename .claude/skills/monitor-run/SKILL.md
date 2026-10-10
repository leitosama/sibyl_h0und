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

1. Arm one Monitor per session with the maximum timeout:
   `uv run python -u .claude/skills/monitor-run/watch_run.py --follow 2>&1`
   It attaches to every `h0und` run that is alive and to every run directory
   created later (up to 2 active, 5 new per 30 minutes), so one Monitor covers
   graded and practice runs, also two at once. Options: `--verbose` prints
   every task, `--seen <N>` skips tasks up to N, `--mode` forces a mode,
   `--total <N>` overrides the queue size (graded 40, practice 30),
   `--register all` also records practice runs. Passing run directories
   instead of `--follow` watches exactly those.
   Arm it before the run starts, or right after; do not start a run without it.
2. Every run has a tag (`G1019` graded, `P1023` practice) that starts its
   lines. The script prints single lines, each starting with a keyword or glyph:

   | Line | Meaning | You do |
   | --- | --- | --- |
   | `Watching <tag> <RUN_DIR>` | a run attached (keep the tag → directory map) | nothing |
   | `MODE <tag> …` | mode, agent, label, model (once); `MODE MISMATCH` when `--mode` contradicts the traces | relay; push on MISMATCH |
   | `LIMIT active n/2 · new runs in 30m n/5` | a run would break a final rule | relay; push |
   | `⚠`/`✖ <tag> #NNN verdict · flags [gates] · calls · tok` + an indented reason | a flagged task | triage (below) |
   | `Σ <tag> N/40 · ✔ ⚠ ✖ · ⌀calls · tok · ETA · DEEP k: …` | totals every 5 tasks | relay |
   | `DASHBOARD <tag> <RUN_DIR>` | every 10 tasks and at the end | refresh that run's dashboard |
   | `STALL <tag> …` | quiet for 10 min (graded) or 5 min (practice) while its process runs | relay; push |
   | `RUN ENDED <tag> ended\|aborted …` | its `h0und` process is gone | relay the `Σ` line; push |

3. When the Monitor expires, re-arm it the same way. Tasks already in
   `monitor.log` and `monitor.jsonl` are not printed again, and runs that
   are still alive are re-attached.

## What the user sees

The user watches an interactive session, so each surface has one job and the
prose is kept out:

- **Status line** (no tokens): `statusline.py` shows a line per active run
  (tag, progress `N/40` or `N/30`, ✔/⚠/✖, ⌀calls, tokens, ETA, the running
  task, DEEP candidates) and a limits line `starts 30m n/5 · active n/2`,
  refreshed by a timer. Enable it once in `.claude/settings.local.json`:
  `{"statusLine": {"type": "command", "command": "python3 .claude/skills/monitor-run/statusline.py", "refreshInterval": 5}}`.
  `MONITOR_RUN_DIR` pins one run, otherwise the newest under `$TRACE_DIR`.
- **Event lines**: copy the script's line verbatim, add only the triage
  answer. No paths, no environment names, no prose around it.
- **Sub-agent panel**: each triage is a background agent whose `description`
  is `Triage #NNN flags`, all started in one turn.
- **Push**: `PushNotification` with the event line on `DEEP`, `STALL`,
  `RUN ENDED` and `MODE MISMATCH` only.
- **Dashboard**: on `DASHBOARD <tag> <RUN_DIR>` run
  `python3 .claude/skills/monitor-run/render_dashboard.py <RUN_DIR>` and publish
  the printed `dashboard.html` with the Artifact tool, the same path each time
  (icon `chart`; first publish only), so each run keeps one URL. The page holds
  counts, flags and ids only.
- **Registry**: graded runs are written to `final_runs.jsonl` by the watcher
  (full `run_id`, `task_id`, trace file, verdict, flags, triage) and their
  directory gets a `KEEP` file. When a graded run ends, save a memory pointer
  to the registry (path, tag, `run_id`, model) so a later session starts from
  it; `digest_task.py --runs [TAG]` reads it.

## For each flagged line

Mechanical, no opinion of your own:

1. Run `uv run python .claude/skills/analyze-task/digest_task.py <RUN_DIR> <N>`
   (RUN_DIR is the one in the tag's `Watching` line; the tag works as well:
   `... digest_task.py G1019 <N>`); keep its output as text.
2. Spawn one `run-triage` agent (`model: sonnet`, description
   `Triage <tag> #NNN <flags>`) per task with only that text as the prompt.
   Several flagged lines at once: all agents in one turn. Never pass a trace
   path.
3. Record the answer exactly as given:
   `uv run python .claude/skills/analyze-task/digest_task.py <tag|RUN_DIR> <N> --triage "<answer>"`
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
| `bad_id` | a call used an id the runtime does not know (`Unknown entity_id …`): the model corrupted or invented an id |
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
