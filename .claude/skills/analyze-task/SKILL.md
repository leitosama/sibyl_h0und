---
name: analyze-task
description: Analyze one task of a run from its trace: compact digest, cheap-model triage, then a targeted deep read only when it is worth it. Use when the user asks why a task was wrong, slow or expensive, or when monitor-run flags a task.
---

# Analyze one task of a run

A trace is megabytes of prompts and tool responses. Never `Read` or `grep` it
whole: use the digest, and pull single events by `seq`.

## 1. Digest

```bash
uv run python .claude/skills/analyze-task/digest_task.py <RUN_DIR|latest> <NUMBER>
```

It prints about 700 tokens: the alert, verdict, numbers, tools used, the
challenger's hypothesis and checks, the answer reviewer's refusals, the tool
errors, the reporter's change and the last `current_state`. Scores print as
`hidden by the runtime` when Q, E and reward are all zero (a wrong verdict
always has a negative reward, so zeros mean unfilled fields): then judge by
the verdict, the challenge, the call count and the errors, never by Q.

The digest ends its numbers with an economy block, all counted from the trace:

- `tokens by role` and `time`: where tokens and seconds went (the head grows
  from about 13k to 86k tokens per call on a long task, so a call count of 70
  costs millions of tokens), plus `slowest` calls with their `seq`;
- `ceiling`: runtime calls against the safety ceiling;
- `repeats`: `tool_cached`, identical arguments, the longest run of one tool,
  `search` pages beyond the first;
- `coverage`: ids opened against ids cited, and knowledge lookups;
- `finish attempts`: the chain of gates (`rejected`, `citations_refused`,
  `challenged`, `answers_refused`, `sent`) with the verdict of each try and
  the calls spent after the first one. A verdict that flips between tries
  (benign to malicious after a challenge) is shown.

For the whole run: `digest_task.py <RUN_DIR> --summary` (needs
`monitor.jsonl`, written by the watcher) or
`digest_task.py <RUN_A> --compare <RUN_B>` to compare two runs or models.

`RUN_DIR` is a run directory under `$TRACE_DIR` (default
`~/.local/share/sibyl_h0und/traces`).

## 2. Triage with a cheap model

Decide from the digest whether the task deserves a deep read. When the
digest alone is not conclusive, spawn one subagent with `model: "sonnet"`
(`"haiku"` for plain routine blocks), pass it only the digest text and ask:

```
This is the digest of one SOC investigation task done by an automated agent.
Answer in one line: `DEEP` or `SKIP`, then a dash and a reason of at most 25
words. DEEP when the digest shows a possible wrong verdict (a benign verdict
whose challenge hypothesis names an unanswered check or an attack stage), a
wasteful path (many calls with few citations), a refused answer that was
accepted anyway, or errors that changed the outcome. SKIP when the numbers,
the checks and the final state agree and nothing was left unexplained.
```

Rules for the triage:

- Pass the digest, not the trace path: the cheap model must not read files.
- `SKIP` ends the analysis: report the task in one line, quoting the reason.
- Several flagged tasks: one subagent per task, in the same turn.
- The triage is advice. A benign verdict that was challenged and then sent
  unchanged is still worth a look when `scores` are hidden.

## 3. Deep read (only after `DEEP`)

Read the event that the digest points at, not the file:

```bash
uv run python .claude/skills/analyze-task/digest_task.py <RUN_DIR> <NUMBER> --event <SEQ> --limit 3000
```

Useful `seq` values: the one in `errors`, `finish_seq` (the sent report), and
the neighbours of a challenge. Name the concrete cause: an entity, a relation
the agent never opened, a check answered with a different fact, a tool that
repeated an earlier lookup. Say what the change would be (prompt, vocabulary,
gate) and whether an ADR in `docs/adr/` already covers it.

## Rules

- Per-call `reward` and the scores are for offline analysis only (ADR 0006):
  quote them to the user, never into agent code or prompts.
- Without scores, do not call a verdict `correct` or `incorrect`; say what
  the evidence supports.
