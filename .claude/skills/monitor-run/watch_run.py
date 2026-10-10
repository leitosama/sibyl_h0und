"""Stream one or several runs' trace directories as single-line events.

Usage: uv run python watch_run.py [RUN_DIR ...] [--follow] [--seen N] [--verbose]
       [--total N] [--mode graded|practice] [--register graded|all] [--idle SECONDS]

With no RUN_DIR the watcher follows: it attaches to every `h0und` run that is
alive and to every run directory created after it started, up to the limits of
the final (two active runs). Each run gets a tag (`G1019` graded, `P1023`
practice, from the directory name) that starts its lines.

Standard output is one line per event, each starting with a fixed keyword or
glyph: `Watching`, `MODE`, `LIMIT`, `⚠`/`✖` (a flagged task), `Σ` (totals),
`DASHBOARD`, `STALL`, `RUN ENDED`. Every finished task goes to `monitor.log`
and `monitor.jsonl` in its run directory; graded runs are also written to the
registry (`final_runs.jsonl`, see registry.py).

The mode comes from the run's `agent_name` (`h0und1` is graded) unless `--mode`
is given; it also fixes the queue size (graded 40, practice 30, `--total`
overrides). In graded mode scores are never shown and the watch is read-only: it
never starts or changes a run. A re-armed watch repeats nothing: tasks already
in `monitor.log` and tasks numbered `--seen` or below are skipped.
"""

import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze-task"))

import registry  # noqa: E402
from runview import (  # noqa: E402
    deep_candidates,
    event_line,
    expected_total,
    match_runs,
    read_rows,
    run_tag,
    run_ts,
    totals_event_line,
)
from taskdigest import (  # noqa: E402
    GRADED,
    PRACTICE,
    Task,
    clip,
    flags,
    metrics,
    mode_of_agent,
    percentile,
    structure_flags,
)
from taskdigest import hidden as scores_not_shown  # noqa: E402

from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW  # noqa: E402

STALL_SECONDS = {GRADED: 600, PRACTICE: 300}  # the runtime may hold a task up to 15 minutes
END_QUIET_SECONDS = 20
TOTALS_EVERY = 5
DASHBOARD_EVERY = 10
POLL_SECONDS = 2
LOG_NAME = "monitor.log"
JSONL_NAME = "monitor.jsonl"
MIN_HISTORY = 5  # finished tasks before a p90 flag means anything
MAX_ACTIVE = 2  # final rule: at most two runs active at once
MAX_STARTS = 5  # final rule: at most five new runs per 30 minutes
START_WINDOW_SECONDS = 1800
IDLE_SECONDS = 900


def task_line(task: Task, end: dict[str, Any]) -> str:
    """Format one finished task for `monitor.log`, with scores only when they may be shown."""
    hidden = scores_not_shown(task, end)
    q = None if hidden else end.get("quality_score") or 0.0
    e = None if hidden else end.get("efficiency_score") or 0.0
    score = None if q is None or e is None else q * (0.6 + 0.4 * e)
    reward = None if hidden else end.get("total_reward") or 0.0

    def fmt(value: float | None, spec: str) -> str:
        return "n/a" if value is None else format(value, spec)

    numbers = (
        f"Q={fmt(q, '.2f')} E={fmt(e, '.2f')} score={fmt(score, '.2f')} "
        f"reward={fmt(reward, '.0f')} calls={end.get('runtime_calls') or 0} "
        f"llm={end.get('llm_calls') or 0} llm_s={(end.get('llm_ms') or 0) / 1000:.0f} "
        f"ktok={(end.get('llm_tokens') or 0) / 1000:.0f} "
        f"challenged={task.challenged} reporter={task.reporter} fallback={task.fallback} "
        f"rejected={task.rejected} refused={task.refused} tool_errors={task.tool_errors} "
        f"llm_errors={task.llm_errors} end={end.get('completion_reason')} "
        f"error={end.get('error')}"
    )
    # Without scores `correct`/`incorrect` would be a guess from nothing.
    if q is None:
        result = f"Result={task.verdict} (scores not shown, {task.mode})"
    else:
        result = f"Result={task.verdict} {'correct' if q >= DEFAULT_WRONG_BELOW else 'incorrect'}"
    return f"[{task.number:03d} {task.id}] {numbers}\n{result}"


def why_lines(task: Task) -> str:
    """Return the reasons behind the flags, a few short lines for `monitor.log`."""
    lines = [f"alert: {task.alert}"]
    if task.hypotheses:
        lines.append(f"challenge: {task.hypotheses[0]}")
    if task.refusals:
        lines.append(f"refused: {task.refusals[0]}")
    if task.errors:
        lines.append(f"error: {task.errors[0]}")
    return "\n".join(lines)


def why_line(task: Task) -> str:
    """Return the single most telling reason behind the flags, clipped to one line."""
    for label, items in (
        ("challenge", task.hypotheses),
        ("refused", task.refusals),
        ("error", task.errors),
    ):
        if items:
            return f"{label}: {clip(items[0], 110)}"
    return f"alert: {clip(task.alert, 110)}"


def relative_flags(m: dict[str, Any], earlier: list[dict[str, Any]]) -> list[str]:
    """Flag a task whose time or tokens exceed the p90 of the tasks before it."""
    if len(earlier) < MIN_HISTORY:
        return []
    found = []
    for flag, key in (("slow", "duration_s"), ("heavy", "tokens")):
        limit = percentile([e[key] for e in earlier])
        if limit is not None and m[key] > limit:
            found.append(flag)
    return found


def peek_mode(run_dir: Path) -> str:
    """Return the run's mode from the agent name in its first trace line, else practice."""
    for path in sorted(run_dir.glob("*.trace.jsonl")):
        with path.open("rb") as fh:
            first = fh.readline()
        try:
            agent = json.loads(first)["payload"]["run"]["agent_name"]
        except (ValueError, KeyError, TypeError):
            continue
        return mode_of_agent(agent or "")
    return PRACTICE


def complete_lines(path: Path, offset: int) -> tuple[list[bytes], int]:
    """Read whole lines from `offset`; a partly written last line waits for the next poll."""
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    end = chunk.rfind(b"\n") + 1
    return chunk[:end].splitlines(), offset + end


class RunWatch:
    """Reads one run directory and turns its traces into event lines."""

    def __init__(
        self,
        run_dir: Path,
        mode: str | None,
        seen: int,
        total: int | None,
        register: str,
        verbose: bool,
    ):
        self.dir = run_dir
        self.forced_mode, self.seen = mode, seen
        self.total_override, self.register, self.verbose = total, register, verbose
        self.mode = mode or peek_mode(run_dir)
        self.tag = run_tag(run_dir.name, self.mode)
        self.offsets: dict[Path, int] = {}
        self.tasks: dict[Path, Task] = {}
        self.history: list[dict[str, Any]] = []
        self.records = read_rows(run_dir)
        log = run_dir / LOG_NAME
        self.logged = {
            line.split("]")[0] + "]"
            for line in (log.read_text().splitlines() if log.exists() else [])
            if line.startswith("[")
        }
        traces = list(run_dir.glob("*.trace.jsonl"))
        self.last_event = max((p.stat().st_mtime for p in traces), default=time.time())
        self.announced = self.stalled = self.ended = False
        self.run_id, self.info = "", {}

    @property
    def total(self) -> int | None:
        """Return the queue size this run counts to."""
        return expected_total(self.mode, self.total_override)

    def _write_registry(self, state: str) -> None:
        if not self.run_id or (self.register != "all" and self.mode != GRADED):
            return
        entry = registry.build_entry(
            self.dir, self.info, self.run_id, self.mode, self.records, state, self.total
        )
        registry.upsert(entry)
        if self.mode == GRADED:
            registry.mark_keep(self.dir)

    def poll(self) -> list[str]:
        """Read new trace lines and return the event lines they produce."""
        out: list[str] = []
        for path in sorted(self.dir.glob("*.trace.jsonl")):
            if path in self.tasks and self.tasks[path].ended:
                continue
            number = int(path.name.split("_", 1)[0])
            lines, self.offsets[path] = complete_lines(path, self.offsets.get(path, 0))
            for line in lines:
                self.last_event, self.stalled = time.time(), False
                event = json.loads(line)
                if path not in self.tasks:
                    self.tasks[path] = Task(number, event["task_id"], self.forced_mode)
                task = self.tasks[path]
                end = task.feed(event)
                if event["kind"] == "task_start" and not self.announced:
                    self.announced = True
                    self.mode, self.run_id, self.info = task.mode, task.run_id, task.run_info
                    self.tag = run_tag(self.dir.name, self.mode)
                    out.append(self._banner(task))
                if end is not None:
                    out.extend(self._finished(path, task, end))
        return out

    def _banner(self, task: Task) -> str:
        head = f"{task.mode} · {task.agent} · {task.label} · {task.model}"
        if task.mode_mismatch:
            return (
                f"MODE MISMATCH {self.tag} --mode {task.mode} but the traces say "
                f"agent={task.agent} · {head}"
            )
        note = " · read-only, metadata stays as .env.h0und1 sets it" if task.mode == GRADED else ""
        return f"MODE {self.tag} {head}{note}"

    def _finished(self, path: Path, task: Task, end: dict[str, Any]) -> list[str]:
        out: list[str] = []
        m = metrics(task, end)
        earlier, self.history = self.history, [*self.history, m]
        key = f"[{task.number:03d} {task.id}]"
        if task.number <= self.seen or key in self.logged:
            return out
        found = flags(task, end) + structure_flags(m) + relative_flags(m, earlier)
        block = f"{task_line(task, end)}\nflags={','.join(found) or '-'}"
        if found:
            block += f"\n{why_lines(task)}"
        with (self.dir / LOG_NAME).open("a") as log:
            log.write(block + "\n")
        record = {
            "number": task.number,
            "id": task.id,
            "task_id": task.full_id,
            "trace": path.name,
            "run_id": task.run_id,
            "tag": self.tag,
            "verdict": task.verdict,
            "flags": found,
            "model": task.model,
            "label": task.label,
            "mode": task.mode,
            "agent": task.agent,
            "total": self.total,
            "scores_hidden": scores_not_shown(task, end),
            **m,
        }
        with (self.dir / JSONL_NAME).open("a") as jsonl:
            jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.records.append(record)
        self._write_registry("running")
        if found or self.verbose:
            out.append(f"{event_line(record)}\n  {why_line(task)}")
        n = len(self.records)
        if n % TOTALS_EVERY == 0:
            totals = totals_event_line(
                self.records, deep_candidates(self.dir), self.total, self.tag
            )
            out.append(totals)
            if n % DASHBOARD_EVERY == 0:
                out.append(f"DASHBOARD {self.tag} {self.dir}")
        return out

    def liveness(self, alive: bool) -> list[str]:
        """Return STALL or RUN ENDED lines from the quiet time and the process state."""
        quiet = time.time() - self.last_event
        if self.ended or not self.tasks and not self.records:
            return []
        if not alive and quiet >= END_QUIET_SECONDS:
            self.ended = True
            unfinished = any(not t.ended for t in self.tasks.values())
            state = "aborted" if unfinished else "ended"
            self._write_registry(state)
            totals = totals_event_line(
                self.records, deep_candidates(self.dir), self.total, self.tag
            )
            return [
                f"RUN ENDED {self.tag} {state} {len(self.records)} tasks, no h0und process",
                totals,
                f"DASHBOARD {self.tag} {self.dir}",
            ]
        limit = STALL_SECONDS[self.mode]
        if alive and quiet >= limit and not self.stalled:
            self.stalled = True
            return [f"STALL {self.tag} {limit // 60}m without trace events, h0und still runs"]
        return []


def run_dirs(root: Path) -> list[Path]:
    """Return the run directories under `root`, newest first."""
    runs = [p for p in root.glob("*/") if p.is_dir() and run_ts(p.name) is not None]
    return sorted(runs, key=lambda p: run_ts(p.name) or 0.0, reverse=True)


def parse(argv: list[str]) -> dict[str, Any]:
    """Parse the command line into options."""
    options: dict[str, Any] = {
        "dirs": [],
        "follow": False,
        "seen": 0,
        "verbose": False,
        "total": None,
        "mode": None,
        "register": GRADED,
        "idle": IDLE_SECONDS,
    }
    values = {"--seen": ("seen", int), "--total": ("total", int), "--mode": ("mode", str)}
    values |= {"--register": ("register", str), "--idle": ("idle", int)}
    it = iter(argv)
    for arg in it:
        if arg in values:
            key, cast = values[arg]
            options[key] = cast(next(it))
        elif arg == "--verbose":
            options["verbose"] = True
        elif arg == "--follow":
            options["follow"] = True
        elif arg.startswith("--"):
            raise SystemExit(f"unknown option {arg}")
        else:
            options["dirs"].append(Path(arg))
    if options["mode"] not in (None, GRADED, PRACTICE):
        raise SystemExit("--mode must be graded or practice")
    if options["register"] not in (GRADED, "all"):
        raise SystemExit("--register must be graded or all")
    options["follow"] = options["follow"] or not options["dirs"]
    return options


def main() -> None:
    """Watch runs and print their events."""
    opts = parse(sys.argv[1:])
    started = time.time()
    watches: dict[Path, RunWatch] = {}
    warned: set[tuple[int, int]] = set()
    last_active = started

    def attach(directory: Path) -> None:
        watch = RunWatch(
            directory,
            opts["mode"],
            opts["seen"],
            opts["total"],
            opts["register"],
            opts["verbose"],
        )
        watches[directory] = watch
        print(f"Watching {watch.tag} {directory}", flush=True)

    for directory in opts["dirs"]:
        attach(directory)
    while True:
        recent = run_dirs(DEFAULT_TRACES) if opts["follow"] else []
        bound = match_runs(recent[:12] + list(watches)) if recent or watches else {}
        if opts["follow"]:
            for directory in recent:
                alive = bound.get(directory) is not None
                fresh = directory.stat().st_mtime >= started
                if directory not in watches and (alive or fresh):
                    attach(directory)
        for directory, watch in list(watches.items()):
            lines = watch.poll()
            alive = bound.get(directory) is not None
            lines += watch.liveness(alive)
            for line in lines:
                print(line, flush=True)
            if lines or alive:
                last_active = time.time()
        active = [w for w in watches.values() if not w.ended]
        starts = sum(
            1 for d in run_dirs(DEFAULT_TRACES) if (run_ts(d.name) or 0) >= time.time() - 1800
        )
        state = (len(active), starts)
        if (len(active) > MAX_ACTIVE or starts > MAX_STARTS) and state not in warned:
            warned.add(state)
            print(
                f"LIMIT active {len(active)}/{MAX_ACTIVE} · new runs in 30m {starts}/{MAX_STARTS}",
                flush=True,
            )
        done = watches and all(w.ended for w in watches.values())
        if done and (not opts["follow"] or time.time() - last_active > opts["idle"]):
            return
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
