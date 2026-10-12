---
name: glm-5-3-not-usable
description: Z.AI/glm-5.3 was tried as the agent LLM on practice (2026-10-07) and rejected by the user as not usable
metadata:
  node_type: memory
  type: project
  originSessionId: 689df9b7-465d-4f23-895f-a30937a68420
  modified: 2026-10-06T19:30:25.885Z
---

Z.AI/glm-5.3 was tried as `LLM_DEFAULT_MODEL` on a `practice` run (run `cd918119`, 2026-10-07) and the user dropped it: "It's not usable".

**Why:** ~6–20 s per LLM step (DeepSeek-V4-Flash ≈2 s), so the first task ran over 8 minutes and 41 turns, past the ~6 min per task competition window; it also corrupted ids it copied (appended characters to a relation id, then propagated the bad id), which GraphLedger rejected locally.

**How to apply:** do not propose glm-5.3 again for runs; if a new model is tried, check seconds per step and id copying on the first task before running a full 30-task run. The default model at the time was DeepSeek-V4-Flash-0731.
