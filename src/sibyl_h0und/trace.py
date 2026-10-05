"""JSONL traces of investigation runs, written outside the repository.

One directory per run holds `run.json` and one `<seq>_<task_id>.trace.jsonl`
file per task. Every line is one event with flat top-level fields for viewers
and SQL, and the raw request/response data under `payload`. Runtime responses
are stored in full so that a recorded task can later be replayed offline.

Tracing never breaks a run: a write failure is logged once and the trace for
that task is dropped.
"""

import contextlib
import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from loguru import logger

TRACE_SCHEMA_VERSION = 1

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def default_trace_dir() -> Path:
    """Return the per-user trace directory outside the repository.

    Returns:
        `$XDG_DATA_HOME/sibyl_h0und/traces`, or the `~/.local/share` equivalent.
    """
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "sibyl_h0und" / "traces"


def utc_now() -> str:
    """Return the current UTC time as an ISO 8601 string with milliseconds."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def elapsed_ms(started_at: float) -> int:
    """Return whole milliseconds elapsed since a `time.perf_counter()` value."""
    return int((time.perf_counter() - started_at) * 1000)


def git_revision() -> str | None:
    """Describe the checked-out source revision, marking uncommitted changes.

    Returns:
        Short commit hash with a `-dirty` suffix when the tree has changes,
        or `None` outside a git checkout.
    """
    repo_root = Path(__file__).resolve().parents[2]
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return f"{commit}-dirty" if status else commit


def _safe_name(value: str) -> str:
    """Make an identifier usable as a file name component."""
    return _UNSAFE_NAME_CHARS.sub("_", value).strip("._") or "unknown"


def _dump_line(record: dict[str, Any]) -> str:
    """Serialize one trace record as a single JSON line."""
    return json.dumps(record, ensure_ascii=False, default=str) + "\n"


class TaskTrace:
    """Event writer and counters for one investigated task.

    A trace without a path records counters only and writes nothing.
    """

    def __init__(self, path: Path | None, *, run_id: str, task_id: str) -> None:
        """Open the task trace file.

        Args:
            path: Target JSONL file, or `None` to disable writing.
            run_id: Runtime run identifier stamped on every event.
            task_id: Runtime task identifier stamped on every event.
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
        self._started_at = time.perf_counter()
        self._file: Any = None
        if path is not None:
            try:
                self._file = path.open("w", encoding="utf-8")
            except OSError as error:
                logger.warning("Cannot open trace file {}: {}", path, error)

    @classmethod
    def disabled(cls, task_id: str = "") -> Self:
        """Build a trace that keeps counters but writes nothing."""
        return cls(None, run_id="", task_id=task_id)

    @property
    def wall_ms(self) -> int:
        """Milliseconds since the task trace was opened."""
        return elapsed_ms(self._started_at)

    def event(
        self,
        kind: str,
        *,
        duration_ms: int | None = None,
        payload: dict[str, Any] | None = None,
        **fields: Any,
    ) -> None:
        """Append one event line.

        Args:
            kind: Event type, for example `llm_call` or `tool_call`.
            duration_ms: Wall time of the traced operation, when it has one.
            payload: Raw data kept under the nested `payload` key.
            **fields: Small flat fields shown next to the common ones.
        """
        if self._file is None:
            return
        self._seq += 1
        record: dict[str, Any] = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "seq": self._seq,
            "step": self.step,
            "kind": kind,
        }
        if duration_ms is not None:
            record["duration_ms"] = duration_ms
        record.update(fields)
        if payload is not None:
            record["payload"] = payload
        try:
            self._file.write(_dump_line(record))
            self._file.flush()
        except (OSError, TypeError, ValueError) as error:
            logger.warning("Dropping trace {} after a write error: {}", self.path, error)
            self.close()

    def record_llm_call(self, *, tokens: int, duration_ms: int, **fields: Any) -> None:
        """Count one LLM request and append its event.

        Args:
            tokens: Total tokens reported by the provider.
            duration_ms: Request latency.
            **fields: Remaining `llm_call` event fields.
        """
        self.llm_calls += 1
        self.llm_tokens += tokens
        self.llm_ms += duration_ms
        self.event("llm_call", tokens=tokens, duration_ms=duration_ms, **fields)

    def close(self) -> None:
        """Close the trace file; later events are ignored."""
        if self._file is not None:
            with contextlib.suppress(OSError):
                self._file.close()
            self._file = None


class RunTrace:
    """Trace directory for one runtime run."""

    def __init__(self, directory: Path | None, *, run_id: str) -> None:
        """Store the run directory.

        Args:
            directory: Existing run directory, or `None` when tracing is off.
            run_id: Runtime run identifier.
        """
        self.directory = directory
        self.run_id = run_id
        self._task_count = 0

    @classmethod
    def open(cls, root: Path | None, *, run_id: str, metadata: dict[str, Any]) -> Self:
        """Create the run directory and write `run.json`.

        Args:
            root: Trace root directory, or `None` to disable tracing.
            run_id: Runtime run identifier.
            metadata: Non-secret run settings stored in `run.json`.

        Returns:
            Run trace; disabled when the directory cannot be created.
        """
        if root is None:
            return cls(None, run_id=run_id)
        started_at = datetime.now(UTC)
        directory = root / f"{started_at:%Y%m%dT%H%M%SZ}_{_safe_name(run_id)}"
        run_info = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "run_id": run_id,
            "started_at": started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "git_revision": git_revision(),
            **metadata,
        }
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "run.json").write_text(
                json.dumps(run_info, ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            logger.warning("Tracing disabled, cannot write {}: {}", directory, error)
            return cls(None, run_id=run_id)
        logger.info("Writing traces to {}", directory)
        return cls(directory, run_id=run_id)

    def task(self, task_id: str) -> TaskTrace:
        """Open the trace of the next leased task.

        Args:
            task_id: Runtime task identifier.

        Returns:
            Task trace writing to `<seq>_<task_id>.trace.jsonl`.
        """
        self._task_count += 1
        path = None
        if self.directory is not None:
            path = self.directory / f"{self._task_count:03d}_{_safe_name(task_id)}.trace.jsonl"
        return TaskTrace(path, run_id=self.run_id, task_id=task_id)
