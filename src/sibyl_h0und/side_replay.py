"""Offline harness of the finish gate's side turns over saved task traces (ADR 0022, 0023, 0028).

No runtime is involved: a trace already holds every tool response. For each
task the harness replays the runtime calls and reports as the live agent
made them, up to the report that reaches the chosen side turn: the first
benign report for the challenger, the first report after the challenge for
the challenger's ruling (`judge`), the report that was sent for the
reporter. It then runs only that side turn with the configured LLM and
prints, per task, the challenger's hypothesis and checks, its ruling, or how
the reporter's report differs from the draft.

Tasks are split into a dev half and a holdout half by a hash of the task id,
fixed before any prompt work: practice runs repeat task ids, so one task stays
in one half. Prompt work looks only at `dev`; `holdout` is a pass/fail check,
not a tuning loop. Traces stay where they are; nothing is copied.
"""

import argparse
import asyncio
import hashlib
import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sibyl_h0und.agent import run_review
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.cli import llm_client, load_settings
from sibyl_h0und.investigation import (
    CHALLENGER_ROLE,
    JUDGE_ROLE,
    REPORTER_ROLE,
    Investigation,
    LocalAnswer,
    Review,
    Send,
    find_report,
    report_verdict,
)
from sibyl_h0und.llm import StructuredStepClient
from sibyl_h0und.models import Challenge, Ruling
from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW, TRACE_GLOB
from sibyl_h0und.trace import RecordedTask, read_task

SPLITS = ("dev", "holdout")
ROLES = (CHALLENGER_ROLE, JUDGE_ROLE, REPORTER_ROLE)
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
        recorded: The local answer the live agent gave the report, if any.
    """

    task: RecordedTask
    split: str
    investigation: Investigation
    review: Review
    recorded: dict[str, Any] | None = None

    @property
    def final_verdict(self) -> str | None:
        """Verdict of the report the runtime finally received."""
        submission = self.task.submission
        return report_verdict(submission) if submission is not None else None

    def is_wrong(self, wrong_below: float) -> bool | None:
        """Whether the task ended with a low quality; `None` when it never ended.

        For the challenger only a benign ending counts: it is what the
        challenger is there to catch. Its ruling may end the task either way,
        so for it, as for the reporter, every low ending counts.
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
    question when the trace has none; a ruling turn met on the way gets the
    ruling the trace recorded, or none.

    Args:
        task: A recorded task.
        role: `challenger`, `judge` or `reporter`.

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
        while isinstance(decision, Review) and decision.role in (CHALLENGER_ROLE, JUDGE_ROLE):
            if decision.role == role:
                return Case(task, split_of(task.task_id), investigation, decision, draft.feedback)
            reply, missing = (
                recorded_challenge(draft.feedback)
                if decision.role == CHALLENGER_ROLE
                else recorded_ruling(draft.ruling)
            )
            # The trace holds the final reply, after any repair turn.
            decision = investigation.after_review(replace(decision, repaired=True), reply, missing)
        if isinstance(decision, Review) and decision.role == role:
            return Case(task, split_of(task.task_id), investigation, decision, draft.feedback)
        if not isinstance(decision, LocalAnswer):
            # The report reached the runtime and ended the task.
            return None
    return None


def recorded_challenge(feedback: dict[str, Any] | None) -> tuple[Challenge | None, str | None]:
    """Read the challenge a trace recorded, or say why there is none.

    Traces written before ADR 0026 hold checks of another shape; their
    challenge reads as missing.
    """
    recorded = (feedback or {}).get("challenge")
    if not recorded:
        return None, "no challenge in the trace"
    checks = []
    for check in recorded.get("checks", []):
        seen = check.get("seen")
        source = (
            {"seen": {"evidence_id": seen.get("evidence_id"), "property_fields": [*seen["values"]]}}
            if isinstance(seen, dict) and isinstance(seen.get("values"), dict)
            else {"call": check.get("call")}
        )
        checks.append({**check, "source": source})
    try:
        return Challenge.model_validate({**recorded, "checks": checks}), None
    except ValidationError:
        return None, "the trace's challenge predates ADR 0026"


def recorded_ruling(ruling: dict[str, Any] | None) -> tuple[Ruling | None, str | None]:
    """Read the ruling a trace recorded, or say why there is none."""
    if not ruling:
        return None, "no ruling in the trace"
    checks = [
        {
            **check,
            "observed": [
                {"evidence_id": fact["evidence_id"], "property_fields": [*fact["values"]]}
                for fact in check.get("observed", [])
            ],
        }
        for check in ruling.get("checks", [])
    ]
    try:
        return Ruling.model_validate({**ruling, "checks": checks}), None
    except ValidationError:
        return None, "the trace's ruling does not fit the ruling model"


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


async def side_turn(case: Case, llm: StructuredStepClient) -> LocalAnswer | Send | Review:
    """Run the case's side turn, with its repair turn if it asks for one, as the agent does.

    Returns:
        What the investigation does next; after a ruling, the reporter turn
        is returned, not run.
    """
    decision: LocalAnswer | Send | Review = case.review
    while isinstance(decision, Review) and decision.role == case.review.role:
        decision = await run_review(llm, case.investigation, decision)
    return decision


def cited_ids(node: Any) -> list[str]:
    """Ids a report cites, in order, at any depth."""
    if isinstance(node, list):
        return [item for value in node for item in cited_ids(value)]
    if not isinstance(node, dict):
        return []
    own = [node[key] for key in CITATION_KEYS if isinstance(node.get(key), str)]
    return own + [item for value in node.values() for item in cited_ids(value)]


def render(case: Case, answer: LocalAnswer | Send | Review, wrong_below: float) -> str:
    """Show one task's side turn as text."""
    wrong = {True: " WRONG", False: "", None: " (unfinished)"}[case.is_wrong(wrong_below)]
    quality = "-" if case.task.quality is None else f"{case.task.quality:.2f}"
    lines = [
        f"== {case.split} {case.task.run_id}/{case.task.task_id} "
        f"final={case.final_verdict} q={quality}{wrong}"
    ]
    if case.review.role == JUDGE_ROLE:
        ruling = case.investigation.ruling
        if ruling is None:
            lines.append(
                f"  fallback, the draft keeps its verdict: {case.investigation.ruling_fallback}"
            )
            return "\n".join(lines)
        lines.append(
            f"  draft {report_verdict(case.review.arguments)} -> ruled {ruling['verdict']}"
        )
        for check in ruling["checks"]:
            lines.append(f"  {check['n']}. {check['result']}: {check['look_for']}")
            for fact in check["observed"]:
                lines.append(f"     observed: {json.dumps(fact, ensure_ascii=False)}")
            lines.append(f"     why: {check['why']}")
        lines.append(f"  reasoning: {ruling['reasoning']}")
        return "\n".join(lines)
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
    if not isinstance(answer, LocalAnswer):
        return "\n".join(lines)
    if case.review.role == REPORTER_ROLE:
        lines.append(f"  handed back to the model: {answer.feedback['message']}")
        return "\n".join(lines)
    before, after = check_counts(case.recorded), check_counts(answer.feedback)
    lines.append(f"  checks recorded {before} -> replayed {after}")
    found = answer.feedback.get("challenge")
    if found is None:
        lines.append("  fallback: the general question of ADR 0020")
    else:
        lines.append(f"  hypothesis: {found['hypothesis']}")
        for check in found["checks"]:
            lines.append(f"  {check['n']}. look for: {check['look_for']}")
            if "seen" in check:
                lines.append(f"     seen: {json.dumps(check['seen'], ensure_ascii=False)}")
            else:
                made = " [already made]" if check.get("already_made") else ""
                lines.append(f"     call: {json.dumps(check['call'], ensure_ascii=False)}{made}")
            lines.append(f"     confirms if: {check['confirms_if']}")
            lines.append(f"     refuted if: {check['refuted_if']}")
    return "\n".join(lines)


def ruling_outcome(case: Case, wrong_below: float) -> str:
    """Name what a ruling did to the case's draft, for the totals of a run.

    Wrong and right endings are counted apart: a ruling that flips a wrong
    benign helps, one that flips a right benign hurts.
    """
    ruling = case.investigation.ruling
    if ruling is None:
        return "fallback"
    ending = {True: "wrong", False: "right", None: "unfinished"}[case.is_wrong(wrong_below)]
    draft = report_verdict(case.review.arguments)
    change = "kept" if str(ruling["verdict"]).lower() == draft else "flipped"
    return f"{ending} {case.final_verdict} ending, draft {draft} {change}"


def check_counts(feedback: dict[str, Any] | None) -> dict[str, int]:
    """Count a challenge's checks: all, repeated calls and facts already seen."""
    checks = ((feedback or {}).get("challenge") or {}).get("checks", [])
    return {
        "checks": len(checks),
        "already_made": sum(bool(check.get("already_made")) for check in checks),
        "seen": sum("seen" in check for check in checks),
    }


async def run(args: argparse.Namespace, llm: StructuredStepClient) -> None:
    """Run the side turn of the selected cases one by one and print each result."""
    cases = list(load_cases(args.traces, args.run, args.split, args.role))
    if args.wrong_only:
        cases = [case for case in cases if case.is_wrong(args.wrong_below)]
    cases = cases[: args.limit] if args.limit else cases
    print(f"{len(cases)} reports for the {args.role} (split {args.split}).")
    out = args.out.open("w", encoding="utf-8") if args.out else None
    totals = {"recorded": Counter[str](), "replayed": Counter[str](), "rulings": Counter[str]()}
    try:
        for case in cases:
            answer = await side_turn(case, llm)
            print(render(case, answer, args.wrong_below), flush=True)
            if args.role == JUDGE_ROLE:
                totals["rulings"][ruling_outcome(case, args.wrong_below)] += 1
            elif args.role == CHALLENGER_ROLE and isinstance(answer, LocalAnswer):
                totals["recorded"].update(check_counts(case.recorded))
                totals["replayed"].update(check_counts(answer.feedback))
            if out is not None:
                record: dict[str, Any] = {
                    "run_id": case.task.run_id,
                    "task_id": case.task.task_id,
                    "split": case.split,
                    "final_verdict": case.final_verdict,
                    "quality": case.task.quality,
                    "role": args.role,
                }
                if args.role == JUDGE_ROLE:
                    record["draft"] = case.review.arguments
                    record["ruling"] = case.investigation.ruling
                    record["fallback"] = case.investigation.ruling_fallback
                elif isinstance(answer, Send):
                    record["draft"] = case.review.arguments
                    record["report"] = answer.arguments
                elif isinstance(answer, LocalAnswer):
                    record["feedback"] = answer.feedback
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        if out is not None:
            out.close()
    if args.role == CHALLENGER_ROLE:
        for name in ("recorded", "replayed"):
            print(f"{name}: {dict(totals[name])}")
    elif args.role == JUDGE_ROLE:
        for outcome, count in sorted(totals["rulings"].items()):
            print(f"{outcome}: {count}")


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
