"""Print a compact digest of one task of a run, or drill into one trace event.

Usage:
    uv run python digest_task.py RUN_DIR|latest NUMBER
    uv run python digest_task.py RUN_DIR|latest NUMBER --event SEQ [--limit CHARS]

`latest` is the newest run directory under `$TRACE_DIR` (default
`~/.local/share/sibyl_h0und/traces`). The first form prints the digest; the
second prints the payload of the event with that `seq`, clipped, so a deep
read never loads the whole multi-megabyte trace.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from taskdigest import build, find_trace, read_events, render  # noqa: E402

from sibyl_h0und.replay import DEFAULT_TRACES  # noqa: E402


def resolve_run(arg: str) -> Path:
    """Return the run directory named by `arg`, or the newest one for `latest`."""
    if arg != "latest":
        return Path(arg)
    runs = [p for p in DEFAULT_TRACES.glob("*/") if p.is_dir()]
    if not runs:
        raise SystemExit(f"no runs under {DEFAULT_TRACES}")
    return max(runs, key=lambda p: p.stat().st_mtime)


def main() -> None:
    """Parse arguments and print the digest or one event."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="run directory or `latest`")
    parser.add_argument("number", type=int, help="task number in the run")
    parser.add_argument("--event", type=int, help="print the event with this seq instead")
    parser.add_argument("--limit", type=int, default=2000, help="characters of the event payload")
    args = parser.parse_args()

    path = find_trace(resolve_run(args.run), args.number)
    if args.event is None:
        task, end = build(path)
        print(render(task, end))
        return
    for event in read_events(path):
        if event.get("seq") == args.event:
            meta = {k: v for k, v in event.items() if k not in ("payload", "run_id", "task_id")}
            print(json.dumps(meta, ensure_ascii=False))
            text = json.dumps(event.get("payload"), ensure_ascii=False)
            print(text[: args.limit] + (f"… [{len(text)} chars]" if len(text) > args.limit else ""))
            return
    raise SystemExit(f"no event seq={args.event} in {path.name}")


if __name__ == "__main__":
    main()
