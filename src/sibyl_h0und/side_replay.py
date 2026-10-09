"""Offline harness of the finish gate's side turns over saved task traces (ADR 0022, 0023, 0028).

No runtime is involved: a trace already holds every tool response. For each
task the harness replays the runtime calls and reports as the live agent
made them, up to the report that reaches the chosen side turn: the first
benign report for the challenger, the benign report that answers the
challenge for the answer review, the report that was sent for the reporter.
It then runs only that side turn with the configured LLM and prints, per
task, the challenger's hypothesis and checks, how the answer review rates
each answer, or how the reporter's report differs from the draft.

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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sibyl_h0und.agent import settle
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.cli import llm_client, load_settings
from sibyl_h0und.investigation import (
    ANSWER_REVIEW_ROLE,
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
from sibyl_h0und.models import MAX_CHALLENGE_CHECKS, AnswerReview, Challenge, CheckOutcome
from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW, TRACE_GLOB
from sibyl_h0und.trace import RecordedTask, read_task

SPLITS = ("dev", "holdout")
ROLES = (CHALLENGER_ROLE, ANSWER_REVIEW_ROLE, REPORTER_ROLE)
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
        outcomes: The answer review's rating of each check, once it ran.
        review_error: Why the answer review failed, if it did.
    """

    task: RecordedTask
    split: str
    investigation: Investigation
    review: Review
    recorded: dict[str, Any] | None = None
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    review_error: str | None = None

    @property
    def final_verdict(self) -> str | None:
        """Verdict of the report the runtime finally received."""
        submission = self.task.submission
        return report_verdict(submission) if submission is not None else None

    def is_wrong(self, wrong_below: float) -> bool | None:
        """Whether the task ended with a low quality; `None` when it never ended.

        For the challenger and the answer review only a benign ending counts:
        it is what they are there to catch.
        """
        if self.task.quality is None:
            return None
        low = self.task.quality < wrong_below
        return low and (self.review.role == REPORTER_ROLE or self.final_verdict == "benign")


def split_of(task_id: str) -> str:
    """Put a task in `dev` or `holdout` by a hash of its id."""
    return SPLITS[hashlib.sha256(task_id.encode()).digest()[0] % 2]


def build_case(task: RecordedTask, role: str = CHALLENGER_ROLE) -> Case | None:
    """Replay the task's reports in order until one goes to the side turn of `role`.

    One investigation sees the runtime calls and the reports as the live
    agent did, so a report refused earlier, or one made when only the report
    remained, is answered as it was live. A challenger turn met on the way to
    the reporter gets the challenge the trace recorded, or the general
    question when the trace has none; an answer review met on the way refuses
    or settles the report as the trace says it did.

    Args:
        task: A recorded task.
        role: `challenger`, `answer_review` or `reporter`.

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
            FINISH_TOOL, draft.arguments, finish_only=draft.finish_only, state=draft.state
        )
        if (
            isinstance(decision, Review)
            and decision.role == ANSWER_REVIEW_ROLE
            and role != ANSWER_REVIEW_ROLE
        ):
            # The trace holds a refused report as a local answer, a settled one as sent.
            decision = investigation.after_review(decision, recorded_review(draft.feedback))
        if isinstance(decision, Review) and decision.role == role:
            return Case(task, split_of(task.task_id), investigation, decision, draft.feedback)
        if isinstance(decision, Review) and decision.role == CHALLENGER_ROLE:
            challenge, missing = recorded_challenge(draft.feedback)
            # The trace holds the final challenge, after any repair turn.
            investigation.after_review(replace(decision, repaired=True), challenge, missing)
        elif not isinstance(decision, LocalAnswer):
            # The report reached the runtime and ended the task.
            return None
    return None


def recorded_review(feedback: dict[str, Any] | None) -> AnswerReview:
    """An answer review that refuses or settles every check, as the trace recorded."""
    outcome = "not_shown" if feedback is not None else "refuted"
    return AnswerReview(
        checks=[
            CheckOutcome(n=n, outcome=outcome, why="As the trace recorded.")
            for n in range(1, MAX_CHALLENGE_CHECKS + 1)
        ]
    )


def recorded_challenge(feedback: dict[str, Any] | None) -> tuple[Challenge | None, str | None]:
    """Read the challenge a trace recorded, or say why there is none.

    Traces written before ADR 0026 hold checks of another shape; their
    challenge reads as missing. The technique ids come back from the
    recorded vocabulary entries, so the replay looks them up again (ADR 0028).
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
    techniques = [entry["id"] for entry in recorded.get("knowledge", []) if entry.get("id")]
    try:
        return Challenge.model_validate(
            {**recorded, "checks": checks, "techniques": techniques}
        ), None
    except ValidationError:
        return None, "the trace's challenge predates ADR 0026"


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

    The answer review is run alone: settled answers would go on to the
    reporter, and the reporter's turn is returned instead of being run.
    """
    review = case.review
    if review.role != ANSWER_REVIEW_ROLE:
        return await settle(llm, case.investigation, review)
    try:
        reply = await llm.structured(
            review.messages,
            response_format=review.response_format,
            model=review.model,
            role=review.role,
        )
    except Exception as exc:
        case.review_error = f"{type(exc).__name__}: {exc}"[:500]
        return case.investigation.after_review(review, None, case.review_error)
    if isinstance(reply, AnswerReview):
        case.outcomes = [item.model_dump() for item in reply.checks]
    return case.investigation.after_review(review, reply)


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
    if case.review.role == ANSWER_REVIEW_ROLE:
        request = json.loads(case.review.messages[-1]["content"])
        lines.append(f"  answers: {request.get('answers')}")
        lines.extend(f"  {item['n']}. {item['outcome']}: {item['why']}" for item in case.outcomes)
        if case.review_error is not None:
            lines.append(f"  review failed, the report goes to the reporter: {case.review_error}")
        elif isinstance(answer, LocalAnswer):
            lines.append(f"  REFUSED: {answer.feedback['message']}")
        else:
            lines.append("  settled: the report goes to the reporter")
        return "\n".join(lines)
    assert not isinstance(answer, Review)
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
    totals = {"recorded": Counter[str](), "replayed": Counter[str]()}
    # Answer review: refused or settled, by whether the task ended wrong.
    refusals = Counter[str]()
    try:
        for case in cases:
            answer = await side_turn(case, llm)
            print(render(case, answer, args.wrong_below), flush=True)
            if case.review.role == ANSWER_REVIEW_ROLE:
                ended = {True: "wrong", False: "not wrong", None: "unfinished"}[
                    case.is_wrong(args.wrong_below)
                ]
                outcome = (
                    "failed"
                    if case.review_error is not None
                    else "refused"
                    if isinstance(answer, LocalAnswer)
                    else "settled"
                )
                refusals[f"{ended}: {outcome}"] += 1
            elif isinstance(answer, LocalAnswer):
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
                if isinstance(answer, Send):
                    record["draft"] = case.review.arguments
                    record["report"] = answer.arguments
                elif isinstance(answer, LocalAnswer):
                    record["feedback"] = answer.feedback
                else:
                    record["settled"] = case.review_error is None
                    record["review_error"] = case.review_error
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        if out is not None:
            out.close()
    if args.role == CHALLENGER_ROLE:
        for name, total in totals.items():
            print(f"{name}: {dict(total)}")
    if args.role == ANSWER_REVIEW_ROLE:
        print(f"answer review: {dict(refusals)}")


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
