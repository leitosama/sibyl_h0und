"""Offline harness of the benign challenger over saved task traces (ADR 0022).

No runtime is involved: a trace already holds every tool response. For each
task the harness finds the first benign report, rebuilds the investigation
from the runtime calls made before it and runs only the challenger with the
configured LLM. It prints the challenger's hypothesis and checks per task.

Tasks are split into a dev half and a holdout half by a hash of the task id,
fixed before any prompt work: practice runs repeat task ids, so one task stays
in one half. Prompt work looks only at `dev`; `holdout` is a pass/fail check,
not a tuning loop. Traces stay where they are; nothing is copied.
"""

import argparse
import asyncio
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sibyl_h0und.agent import run_review
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.cli import llm_client, load_settings
from sibyl_h0und.investigation import Investigation, LocalAnswer, Review, Send, report_verdict
from sibyl_h0und.llm import StructuredStepClient
from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW, TRACE_GLOB
from sibyl_h0und.trace import RecordedTask, read_task

SPLITS = ("dev", "holdout")


@dataclass
class Case:
    """One task cut at its first benign report.

    Attributes:
        task: What the trace says about the task.
        split: `dev` or `holdout`.
        investigation: The investigation rebuilt up to the report.
        review: The challenger turn the report asks for.
    """

    task: RecordedTask
    split: str
    investigation: Investigation
    review: Review

    @property
    def final_verdict(self) -> str | None:
        """Verdict of the report the runtime finally received."""
        submission = self.task.submission
        return report_verdict(submission) if submission is not None else None

    def is_wrong(self, wrong_below: float) -> bool | None:
        """Whether the task ended benign with a low quality; `None` when it never ended."""
        if self.task.quality is None:
            return None
        return self.final_verdict == "benign" and self.task.quality < wrong_below


def split_of(task_id: str) -> str:
    """Put a task in `dev` or `holdout` by a hash of its id."""
    return SPLITS[hashlib.sha256(task_id.encode()).digest()[0] % 2]


def build_case(task: RecordedTask) -> Case | None:
    """Replay the task's reports in order until one goes to the challenger.

    One investigation sees the runtime calls and the reports as the live
    agent did, so a report refused earlier, or one made when only the report
    remained, is answered as it was live.

    Args:
        task: A recorded task.

    Returns:
        The case, or `None` when no report reaches the challenger.
    """
    if task.observation is None or task.task_id is None:
        return None
    investigation = Investigation(task.observation)
    replayed = 0
    for draft in task.drafts:
        for call in task.calls[replayed : draft.calls_before]:
            if call.tool != FINISH_TOOL and not call.outcome.terminal:
                investigation.after_call(call.tool, call.arguments, call.outcome)
        replayed = draft.calls_before
        decision = investigation.before_call(
            FINISH_TOOL, draft.arguments, finish_only=draft.finish_only
        )
        if isinstance(decision, Review):
            return Case(task, split_of(task.task_id), investigation, decision)
        if isinstance(decision, Send):
            return None
    return None


def load_cases(trace_dir: Path, run: str = "", split: str = "all") -> Iterator[Case]:
    """Yield the case of every trace of one split that has a benign report, in trace order."""
    for path in sorted(trace_dir.glob(TRACE_GLOB)):
        task = read_task(path)
        if run not in (task.run_id or "") or task.task_id is None:
            continue
        if split != "all" and split_of(task.task_id) != split:
            continue
        if (case := build_case(task)) is not None:
            yield case


async def challenge(case: Case, llm: StructuredStepClient) -> LocalAnswer:
    """Run the challenger on one case and return what the head would be told."""
    return await run_review(llm, case.investigation, case.review)


def render(case: Case, answer: LocalAnswer, wrong_below: float) -> str:
    """Show one task's challenge as text."""
    wrong = {True: " WRONG", False: "", None: " (unfinished)"}[case.is_wrong(wrong_below)]
    quality = "-" if case.task.quality is None else f"{case.task.quality:.2f}"
    lines = [
        f"== {case.split} {case.task.run_id}/{case.task.task_id} "
        f"final={case.final_verdict} q={quality}{wrong}"
    ]
    found = answer.feedback.get("challenge")
    if found is None:
        lines.append("  fallback: the general question of ADR 0020")
    else:
        lines.append(f"  hypothesis: {found['hypothesis']}")
        for check in found["checks"]:
            made = " [already made]" if check.get("already_made") else ""
            lines.append(f"  - {json.dumps(check['call'], ensure_ascii=False)}{made}")
            lines.append(f"    refuted if: {check['refuted_if']}")
    return "\n".join(lines)


async def run(args: argparse.Namespace, llm: StructuredStepClient) -> None:
    """Challenge the selected cases one by one and print each result."""
    cases = list(load_cases(args.traces, args.run, args.split))
    if args.wrong_only:
        cases = [case for case in cases if case.is_wrong(args.wrong_below)]
    cases = cases[: args.limit] if args.limit else cases
    print(f"{len(cases)} benign reports to challenge (split {args.split}).")
    out = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        for case in cases:
            answer = await challenge(case, llm)
            print(render(case, answer, args.wrong_below), flush=True)
            if out is not None:
                record: dict[str, Any] = {
                    "run_id": case.task.run_id,
                    "task_id": case.task.task_id,
                    "split": case.split,
                    "final_verdict": case.final_verdict,
                    "quality": case.task.quality,
                    "feedback": answer.feedback,
                }
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        if out is not None:
            out.close()


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and challenge the saved benign reports with the configured LLM."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--traces", type=Path, default=DEFAULT_TRACES)
    parser.add_argument("--run", default="", help="Only runs whose id contains this text.")
    parser.add_argument("--split", choices=[*SPLITS, "all"], default="dev")
    parser.add_argument("--wrong-below", type=float, default=DEFAULT_WRONG_BELOW)
    parser.add_argument("--wrong-only", action="store_true", help="Only tasks ended wrong.")
    parser.add_argument("--limit", type=int, default=0, help="At most this many tasks.")
    parser.add_argument("--out", type=Path, help="Also write one JSON line per task here.")
    args = parser.parse_args(argv)

    async def go() -> None:
        async with llm_client(load_settings()) as llm:
            await run(args, llm)

    asyncio.run(go())
