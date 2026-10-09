"""Stream a run's trace directory as one compact block per finished task.

Usage: python3 watch_run.py [RUN_DIR] [--seen N]

RUN_DIR defaults to the newest run under $TRACE_DIR or
~/.local/share/sibyl_h0und/traces. Tasks numbered N or below are read for the
running totals but not printed, so a re-armed watch does not repeat them.
"""

import glob
import json
import os
import sys
import time

WRONG_BELOW = 0.2  # docs/development.md: the runtime never says if a verdict was right
STALL_SECONDS = 300
TOTALS_EVERY = 5


def newest_run() -> str:
    root = os.path.expanduser(os.environ.get("TRACE_DIR", "~/.local/share/sibyl_h0und/traces"))
    return max(glob.glob(os.path.join(root, "*/")), key=os.path.getmtime).rstrip("/")


def citations(submission) -> dict:
    found = {}

    def walk(node):
        if isinstance(node, dict):
            key = node.get("entity_id") or node.get("relation_id")
            if key:
                found[key] = tuple(sorted(node.get("property_fields", [])))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(submission)
    return found


def submission_of(report) -> dict:
    report = report or {}
    return report.get("arguments", report).get("submission", {})


def reporter_change(payload) -> str:
    if payload.get("report") is None:
        return "none"
    draft, sent = submission_of(payload.get("draft")), submission_of(payload.get("report"))
    if draft == sent:
        return "kept"
    old, new = citations(draft), citations(sent)
    added, removed = len(new.keys() - old.keys()), len(old.keys() - new.keys())
    fields = sum(old[k] != new[k] for k in old.keys() & new.keys())
    if not (added or removed or fields):
        return "text"
    return f"+{added}/-{removed}ids,{fields}fields"


class Task:
    def __init__(self, number: int, task_id: str):
        self.number, self.id = number, task_id[:8]
        self.verdict = "?"
        self.challenged = self.rejected = self.refused = self.tool_errors = self.llm_retries = 0
        self.reporter = "none"
        self.fallback = None

    def feed(self, event) -> dict | None:
        kind, payload = event["kind"], event.get("payload") or {}
        if kind == "tool_call" and event.get("tool") == "finish_investigation":
            self.verdict = submission_of(payload).get("verdict", self.verdict)
        if kind == "tool_call" and (event.get("status") != "ok" or event.get("error")):
            self.tool_errors += 1
        elif kind == "llm_call" and event.get("attempt", 1) > 1:
            self.llm_retries += 1
        elif kind == "tool_rejected":
            self.rejected += 1
        elif kind == "report_refused":
            self.refused += 1
        elif kind == "benign_challenged":
            self.challenged += 1
        elif kind == "report_written":
            self.reporter, self.fallback = reporter_change(payload), event.get("fallback")
            sent = submission_of(payload.get("report") or payload.get("draft"))
            self.verdict = sent.get("verdict", self.verdict)
        elif kind == "task_end":
            return event
        return None


def task_line(task: Task, end: dict) -> tuple[str, dict]:
    q, e = end.get("quality_score") or 0.0, end.get("efficiency_score") or 0.0
    row = {
        "Q": q,
        "E": e,
        "score": q * (0.6 + 0.4 * e),
        "reward": end.get("total_reward") or 0.0,
        "calls": end.get("runtime_calls") or 0,
        "llm": end.get("llm_calls") or 0,
        "llm_s": (end.get("llm_ms") or 0) / 1000,
    }
    numbers = (
        f"Q={q:.2f} E={e:.2f} score={row['score']:.2f} reward={row['reward']:.0f} "
        f"calls={row['calls']} llm={row['llm']} llm_s={row['llm_s']:.0f} "
        f"challenged={task.challenged} reporter={task.reporter} fallback={task.fallback} "
        f"rejected={task.rejected} refused={task.refused} tool_errors={task.tool_errors} "
        f"llm_retries={task.llm_retries} end={end.get('completion_reason')} "
        f"error={end.get('error')}"
    )
    correct = "correct" if q >= WRONG_BELOW else "incorrect"
    return f"[{task.number:03d} {task.id}] {numbers}\nResult={task.verdict} {correct}", row


def totals_line(rows: list[dict], last: int) -> str:
    n = len(rows)
    mean = {k: sum(r[k] for r in rows) / n for k in rows[0]}
    wrong = sum(r["Q"] < WRONG_BELOW for r in rows)
    return (
        f"=== Tasks {last - n + 1:03d}-{last:03d}: mean Q={mean['Q']:.2f} E={mean['E']:.2f} "
        f"score={mean['score']:.2f} reward={mean['reward']:.0f} calls={mean['calls']:.1f} "
        f"llm={mean['llm']:.1f} llm_s={mean['llm_s']:.0f} incorrect={wrong}/{n}"
    )


def main() -> None:
    args = sys.argv[1:]
    seen = 0
    if "--seen" in args:
        i = args.index("--seen")
        seen = int(args[i + 1])
        del args[i : i + 2]
    run_dir = args[0] if args else newest_run()
    print(f"Watching {run_dir}", flush=True)

    offsets: dict[str, int] = {}
    tasks: dict[str, Task] = {}
    rows: list[dict] = []
    last_event, stalled = time.time(), False
    while True:
        for path in sorted(glob.glob(os.path.join(run_dir, "*.trace.jsonl"))):
            number = int(os.path.basename(path).split("_", 1)[0])
            with open(path, encoding="utf-8") as fh:
                fh.seek(offsets.get(path, 0))
                while (line := fh.readline()).endswith("\n"):
                    offsets[path] = fh.tell()
                    last_event, stalled = time.time(), False
                    event = json.loads(line)
                    task = tasks.setdefault(path, Task(number, event["task_id"]))
                    if event["kind"] == "task_start" and number > seen:
                        print(f"[{number:03d} {task.id}] START", flush=True)
                    end = task.feed(event)
                    if end is None:
                        continue
                    text, row = task_line(task, end)
                    rows.append(row)
                    if number > seen:
                        print(text, flush=True)
                    if len(rows) % TOTALS_EVERY == 0 and number > seen:
                        print(totals_line(rows[-TOTALS_EVERY:], number), flush=True)
        if not stalled and time.time() - last_event > STALL_SECONDS:
            minutes = STALL_SECONDS // 60
            print(f"STALL: no trace events for {minutes} min (run finished or hung?)", flush=True)
            stalled = True
        time.sleep(2)


if __name__ == "__main__":
    main()
