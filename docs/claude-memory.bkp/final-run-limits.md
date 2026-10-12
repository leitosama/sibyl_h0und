---
name: final-run-limits
description: "Real run limits for the final stage - 2 concurrent runs, 5 new per 30 min, 15 min wait, scores invisible"
metadata:
  node_type: memory
  type: project
  originSessionId: c897561d-b783-474d-a6e7-90a887d1d17b
  modified: 2026-10-10T10:14:23.110Z
---

Limits for the final run (as of 2026-10-10, from the user):
- At most 2 runs active at once; at most 5 new runs per 30 minutes.
- A task is kept open while waiting for a reply for 15 minutes; after that, try launching again.
- Run scores are not visible, even in the user's cabinet, so per-task analyses (analyze-task, monitor-run) are the main way to judge quality.

**Why:** docs/competition.md used to say 10 and 10; the real limits are stricter, which changes the launch plan.
**How to apply:** plan at most 2 parallel runs and budget restarts against 5 per 30 minutes; invest in trace analysis. See [[ngfw-run-env]] for run environment.
