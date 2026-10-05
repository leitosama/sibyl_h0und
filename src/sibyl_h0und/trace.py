"""JSONL traces of investigation runs, written outside the repository.

One directory per run holds one `<seq>_<task_id>.trace.jsonl` file per task.
Every line is one event with flat top-level fields for viewers and SQL, and
raw request/response data under `payload`. Tracing never breaks a run: a
failed write is logged and skipped.
"""

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger


def default_trace_dir() -> Path:
    """Return `$XDG_DATA_HOME/sibyl_h0und/traces` or its `~/.local/share` default."""
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "sibyl_h0und" / "traces"


def run_trace_dir(root: Path, run_id: str) -> Path:
    """Return the trace directory of a run, ordered by start time."""
    return root / f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}_{_safe_name(run_id)}"


def task_trace_path(run_dir: Path, seq: int, task_id: str) -> Path:
    """Return the trace file of the `seq`-th task leased in a run."""
    return run_dir / f"{seq:03d}_{_safe_name(task_id)}.trace.jsonl"


def elapsed_ms(started_at: float) -> int:
    """Return whole milliseconds elapsed since a `time.perf_counter()` value."""
    return int((time.perf_counter() - started_at) * 1000)


def _safe_name(value: str) -> str:
    """Make an identifier usable as a file name component."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "unknown"


class TaskTrace:
    """Event writer and counters for one task; `path=None` writes nothing."""

    def __init__(self, path: Path | None, *, run_id: str = "", task_id: str = "") -> None:
        """Store the target file and identifiers stamped on every event.

        Args:
            path: Target JSONL file, created with its directory on first write.
            run_id: Runtime run identifier.
            task_id: Runtime task identifier.
        """
        self.path = path
        self.run_id = run_id
        self.task_id = task_id
        self.step = 0
        self.llm_calls = 0
        self.llm_tokens = 0
        self.llm_ms = 0
        self.runtime_calls = 0
        self._seq = 0
        self._last_llm_request: list[dict[str, Any]] = []
        self._started_at = time.perf_counter()

    @property
    def wall_ms(self) -> int:
        """Milliseconds since the task trace was created."""
        return elapsed_ms(self._started_at)

    def event(self, kind: str, *, payload: dict[str, Any] | None = None, **fields: Any) -> None:
        """Append one event line.

        Args:
            kind: Event type, for example `llm_call` or `tool_call`.
            payload: Raw data kept under the nested `payload` key.
            **fields: Small flat fields shown next to the common ones.
        """
        if self.path is None:
            return
        self._seq += 1
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "seq": self._seq,
            "step": self.step,
            "kind": kind,
            **fields,
        }
        if payload is not None:
            record["payload"] = payload
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as error:
            logger.warning("Skipping trace event {} in {}: {}", kind, self.path, error)

    def llm_call(self, messages: list[dict[str, Any]], *, raw_content: str, **fields: Any) -> None:
        """Append an `llm_call` event that stores only the request's new messages.

        The payload keeps `prefix`, the number of leading messages shared with
        the previous `llm_call` of this task, and the messages after it, so the
        trace grows linearly with the history. `llm_requests` rebuilds the
        full requests.

        Args:
            messages: Exact message list sent to the LLM.
            raw_content: Model reply as received.
            **fields: Small flat fields shown next to the common ones.
        """
        if self.path is None:
            return
        previous = self._last_llm_request
        prefix = 0
        while prefix < min(len(previous), len(messages)) and previous[prefix] == messages[prefix]:
            prefix += 1
        self._last_llm_request = list(messages)
        self.event(
            "llm_call",
            payload={"prefix": prefix, "messages": messages[prefix:], "raw_content": raw_content},
            **fields,
        )


def llm_requests(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Rebuild the full message list of every `llm_call` event of one task.

    Args:
        events: Events of one task trace in file order.

    Returns:
        One full request per `llm_call` event, in order.
    """
    requests: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for event in events:
        if event.get("kind") != "llm_call":
            continue
        payload = event["payload"]
        current = current[: payload.get("prefix", 0)] + payload["messages"]
        requests.append(current)
    return requests
