"""Offline harness of the finish gate's side turns over saved task traces (ADR 0022, 0023).

No runtime is involved: a trace already holds every tool response. For each
task the harness replays the runtime calls and reports as the live agent
made them, up to the report that reaches the chosen side turn: the first
benign report for the challenger, the report that was sent for the reporter.
It then runs only that side turn with the configured LLM and prints, per
task, the challenger's hypothesis and checks or how the reporter's report
differs from the draft.

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

from sibyl_h0und.agent import settle
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.cli import llm_client, load_settings
from sibyl_h0und.investigation import (
    CHALLENGER_ROLE,
    REPORTER_ROLE,
    Investigation,
    LocalAnswer,
    Review,
    Send,
    find_report,
    report_verdict,
)
from sibyl_h0und.llm import StructuredStepClient
from sibyl_h0und.models import Challenge
from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW, TRACE_GLOB
from sibyl_h0und.trace import RecordedTask, read_task

SPLITS = ("dev", "holdout")
ROLES = (CHALLENGER_ROLE, REPORTER_ROLE)
# Report keys whose value names a cited entity or relation.
CITATION_KEYS = ("entity_id", "relation_id")


@dataclass
class Case:
    """One task cut at the report that reaches a side turn.

    Attributes:
        task: What the trace says about the task.
        split: `dev` or `holdout`.
        investigation: The investigation rebuilt up to the report.
        review: The side turn the report asks for.
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
        """Whether the task ended with a low quality; `None` when it never ended.

        For the challenger only a benign ending counts: it is what the
        challenger is there to catch.
        """
        if self.task.quality is None:
            return None
        low = self.task.quality < wrong_below
        return low and (self.review.role != CHALLENGER_ROLE or self.final_verdict == "benign")


def split_of(task_id: str) -> str:
    """Put a task in `dev` or `holdout` by a hash of its id."""
    return SPLITS[hashlib.sha256(task_id.encode()).digest()[0] % 2]


def build_case(task: RecordedTask, role: str = CHALLENGER_ROLE) -> Case | None:
    """Replay the task's reports in order until one goes to the side turn of `role`.

    One investigation sees the runtime calls and the reports as the live
    agent did, so a report refused earlier, or one made when only the report
    remained, is answered as it was live. A challenger turn met on the way to
    the reporter gets the challenge the trace recorded, or the general
    question when the trace has none.

    Args:
        task: A recorded task.
        role: `challenger` or `reporter`.

    Returns:
        The case, or `None` when no report reaches that side turn.
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
        if isinstance(decision, Review) and decision.role == role:
            return Case(task, split_of(task.task_id), investigation, decision)
        if isinstance(decision, Review) and decision.role == CHALLENGER_ROLE:
            recorded = (draft.feedback or {}).get("challenge")
            challenge = Challenge.model_validate(recorded) if recorded else None
            missing = None if challenge else "no challenge in the trace"
            investigation.after_review(decision, challenge, missing)
        elif not isinstance(decision, LocalAnswer):
            # The report reached the runtime and ended the task.
            return None
    return None


def load_cases(
    trace_dir: Path, run: str = "", split: str = "all", role: str = CHALLENGER_ROLE
) -> Iterator[Case]:
    """Yield the case of every trace of one split that reaches the side turn, in trace order."""
    for path in sorted(trace_dir.glob(TRACE_GLOB)):
        task = read_task(path)
        if run not in (task.run_id or "") or task.task_id is None:
            continue
        if split != "all" and split_of(task.task_id) != split:
            continue
        if (case := build_case(task, role)) is not None:
            yield case


async def side_turn(case: Case, llm: StructuredStepClient) -> LocalAnswer | Send:
    """Run the case's side turn, with its repair turn if it asks for one, as the agent does."""
    return await settle(llm, case.investigation, case.review)


def cited_ids(node: Any) -> list[str]:
    """Ids a report cites, in order, at any depth."""
    if isinstance(node, list):
        return [item for value in node for item in cited_ids(value)]
    if not isinstance(node, dict):
        return []
    own = [node[key] for key in CITATION_KEYS if isinstance(node.get(key), str)]
    return own + [item for value in node.values() for item in cited_ids(value)]


def render(case: Case, answer: LocalAnswer | Send, wrong_below: float) -> str:
    """Show one task's side turn as text."""
    wrong = {True: " WRONG", False: "", None: " (unfinished)"}[case.is_wrong(wrong_below)]
    quality = "-" if case.task.quality is None else f"{case.task.quality:.2f}"
    lines = [
        f"== {case.split} {case.task.run_id}/{case.task.task_id} "
        f"final={case.final_verdict} q={quality}{wrong}"
    ]
    if isinstance(answer, Send):
        draft = case.review.arguments
        if case.investigation.report_fallback is not None:
            lines.append(f"  fallback, the draft is sent: {case.investigation.report_fallback}")
            return "\n".join(lines)
        before, after = cited_ids(draft), cited_ids(answer.arguments)
        lines.append(f"  cites {len(before)} -> {len(after)}")
        lines.extend(f"  + {item}" for item in after if item not in before)
        lines.extend(f"  - {item}" for item in before if item not in after)
        reasoning = (find_report(answer.arguments) or {}).get("reasoning")
        lines.append(f"  reasoning: {reasoning}")
        return "\n".join(lines)
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
    """Run the side turn of the selected cases one by one and print each result."""
    cases = list(load_cases(args.traces, args.run, args.split, args.role))
    if args.wrong_only:
        cases = [case for case in cases if case.is_wrong(args.wrong_below)]
    cases = cases[: args.limit] if args.limit else cases
    print(f"{len(cases)} reports for the {args.role} (split {args.split}).")
    out = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        for case in cases:
            answer = await side_turn(case, llm)
            print(render(case, answer, args.wrong_below), flush=True)
            if out is not None:
                record: dict[str, Any] = {
                    "run_id": case.task.run_id,
                    "task_id": case.task.task_id,
                    "split": case.split,
                    "final_verdict": case.final_verdict,
                    "quality": case.task.quality,
                    "role": args.role,
                }
                if isinstance(answer, Send):
                    record["draft"] = case.review.arguments
                    record["report"] = answer.arguments
                else:
                    record["feedback"] = answer.feedback
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        if out is not None:
            out.close()


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and run one side turn over the saved traces with the configured LLM."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--traces", type=Path, default=DEFAULT_TRACES)
    parser.add_argument("--run", default="", help="Only runs whose id contains this text.")
    parser.add_argument("--role", choices=ROLES, default=CHALLENGER_ROLE)
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
