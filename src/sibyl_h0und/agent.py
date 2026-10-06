import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)
from sibyl_h0und.budget import DEFAULT_MAX_RUNTIME_CALLS, CallBudget
from sibyl_h0und.catalog import FINISH_TOOL, ToolCatalog
from sibyl_h0und.flags import FlagBoard, flag_feedback
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.llm import StructuredStepClient, render_json
from sibyl_h0und.rules import DEFAULT_RULES
from sibyl_h0und.trace import TaskTrace, elapsed_ms, run_trace_dir, task_trace_path

SYSTEM_PROMPT = """
You are a pragmatic senior SOC analyst investigating one security alert.

Return exactly one JSON object matching the supplied NextStep schema on every turn.
Do not emit prose, markdown, XML tags, or extra keys outside that object.

The task observation contains `available_tools`, the authoritative catalog of
enabled tool calls and their argument schemas. Follow that catalog exactly.

Investigation rules:
- Treat the alert as an initial hypothesis, not proof that the activity is malicious.
- Use only tools advertised in the current task observation.
- Execute exactly one tool per step and use its evidence before choosing the next step.
- Start from the entity ids named in the alert, then expand through their relations.
- Prefer following relations over searching again: an entity you already hold tells
  you where to go next.
- Search when you have a concrete string worth looking for and no edge leading to it.
- Do not repeat an identical unhelpful or failed call.
- Tool feedback may carry `still_open`: relations of visited entities and entities
  you know of but have not opened yet. Calls with an id the runtime never returned
  and repeated calls are answered locally and do not reach the runtime.
- Use only entity_id values actually returned by the alert or by a tool.
- Submit only response artifacts supported by evidence. Do not invent entity ids.
- Keep current_state evidence-focused and the remaining plan short.
- When told that only finish_investigation remains, submit the verdict at once
  from the evidence already gathered.
""".strip()


class AgentRunResult(BaseModel):
    """Aggregate results returned by one remote benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


class SimpleSGRAgent:
    """Run a typed one-action-per-turn LLM investigation loop."""

    def __init__(
        self,
        llm: StructuredStepClient,
        *,
        max_runtime_calls: int = DEFAULT_MAX_RUNTIME_CALLS,
        trace_dir: Path | None = None,
        trace_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store the LLM dependency and the per-task safety ceiling.

        Args:
            llm: Structured step generator used for every investigation turn.
            max_runtime_calls: Ceiling on runtime calls per task, the report
                included. It must stay below the runtime's own limit of 100.
            trace_dir: Root directory for run traces, or `None` to disable tracing.
            trace_metadata: Non-secret run settings stored in every `task_start` event.

        Raises:
            ValueError: If the ceiling leaves no room below the runtime's limit.
        """
        CallBudget(max_runtime_calls)
        self.llm = llm
        self.max_runtime_calls = max_runtime_calls
        self.trace_dir = trace_dir
        self.trace_metadata = dict(trace_metadata or {})

    async def run(self, client: RemoteBenchmarkClient) -> AgentRunResult:
        """Consume the remote queue and aggregate authoritative task results.

        Args:
            client: Open remote benchmark client that owns the current run.

        Returns:
            Aggregate result for the newly created remote run.

        Raises:
            RuntimeError: If the client is not open.
        """
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")

        run_dir = None
        if self.trace_dir is not None:
            run_dir = run_trace_dir(self.trace_dir, remote_run.run_id)
            logger.info("Writing traces to {}", run_dir)
        task_results: list[TaskResult] = []
        while (session := await client.start_task()) is not None:
            logger.info("Starting structured investigation for task {}.", session.task_id)
            trace_path = None
            if run_dir is not None:
                trace_path = task_trace_path(run_dir, len(task_results) + 1, session.task_id)
            trace = TaskTrace(
                trace_path,
                run_id=remote_run.run_id,
                task_id=session.task_id,
            )
            error_message: str | None = None
            try:
                task_result = await self._investigate(session, trace)
            except Exception as exc:
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                aborted_result = await session.abort_task(error_message=error_message)
                task_result = TaskResult.model_validate(aborted_result)
            self._trace_task_end(trace, task_result, error_message)
            task_results.append(task_result)

        successful_tasks = sum(
            result.completion_reason in {"terminated", "truncated"} for result in task_results
        )
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful_tasks,
            failed_tasks=len(task_results) - successful_tasks,
            task_results=task_results,
        )

    async def _investigate(
        self,
        session: RemoteBenchmarkSession,
        trace: TaskTrace | None = None,
    ) -> TaskResult:
        """Drive one leased task until its terminal investigation tool succeeds.

        Args:
            session: Active remote task session.
            trace: Task trace that receives every LLM and runtime exchange.

        Returns:
            Authoritative terminal task result returned by the server.

        Raises:
            ValueError: If the task observation has an invalid tool catalog.
            CallBudgetExhaustedError: If no report is accepted within the safety limits.
        """
        trace = trace or TaskTrace(None)
        observation = session.task.observation
        catalog = ToolCatalog.from_observation(observation)
        trace.event(
            "task_start",
            payload={
                "run": self.trace_metadata,
                "task": session.task.model_dump(mode="json"),
                "step_format": catalog.response_format(),
            },
        )

        initial_observation = {
            key: _decode_json(value)
            for key, value in observation.items()
            if key not in {"available_tools", "last_tool_result"}
        }
        ledger = GraphLedger()
        ledger.observe_alert(initial_observation)
        flag_board = FlagBoard(DEFAULT_RULES)
        budget = CallBudget(self.max_runtime_calls)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": render_json(
                    {
                        "instruction": "Investigate this alert and submit the correct response.",
                        "initial_observation": initial_observation,
                        "available_tools": catalog.specs,
                    }
                ),
            },
        ]

        while True:
            trace.step += 1
            finish_only = budget.start_turn()
            if finish_only and budget.finish_turns == 1:
                logger.warning("Only finish_investigation remains: {}.", budget.finish_reason)
                trace.event(
                    "finish_only",
                    payload={
                        "reason": budget.finish_reason,
                        "runtime_calls": budget.runtime_calls,
                    },
                )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"Only {FINISH_TOOL} remains: {budget.finish_reason}. "
                            "Submit the verdict now from the evidence already gathered."
                        ),
                    }
                )
            step = await self.llm.next_step(
                messages,
                response_format=catalog.response_format([FINISH_TOOL] if finish_only else None),
                trace=trace,
            )
            tool_name = step.function.tool
            arguments = step.function.arguments
            trace.event("step", tool=tool_name, payload={"step": step.model_dump(mode="json")})
            tool_call_id = f"step_{trace.step}"
            messages.append(
                {
                    "role": "assistant",
                    "content": step.plan_remaining_steps_brief[0],
                    "tool_calls": [
                        {
                            "type": "function",
                            "id": tool_call_id,
                            "function": {
                                "name": tool_name,
                                "arguments": render_json(arguments),
                            },
                        }
                    ],
                }
            )

            if tool_name not in catalog or (finish_only and tool_name != FINISH_TOOL):
                allowed = [FINISH_TOOL] if finish_only else catalog.names
                feedback: dict[str, Any] = {
                    "status": "error",
                    "message": (
                        f"Tool {tool_name!r} cannot be called now. Available tools: {allowed}"
                    ),
                }
                budget.record_local_answer()
                logger.warning("Rejected unavailable tool {} locally.", tool_name)
                trace.event("tool_rejected", tool=tool_name, payload={"arguments": arguments})
            elif (decision := ledger.check(tool_name, arguments)).feedback is not None:
                feedback = decision.feedback
                budget.record_local_answer()
                logger.warning("Answered {} locally: {}.", tool_name, decision.reason)
                trace.event(
                    f"tool_{decision.reason}",
                    tool=tool_name,
                    payload={"arguments": arguments, "feedback": feedback},
                )
            else:
                budget.record_runtime_call()
                response = await self._call_tool(session, trace, tool_name, arguments)
                feedback = self._tool_feedback(response)
                logger.info(
                    "Tool {} returned status {}.",
                    tool_name,
                    feedback.get("status", "unknown"),
                )
                if response.task_result is not None:
                    return TaskResult.model_validate(response.task_result)
                ledger.record(
                    tool_name,
                    arguments,
                    feedback["result"],
                    feedback,
                    failed=response.info.get("error") is not None,
                )
                if open_items := ledger.summary():
                    feedback = {**feedback, "still_open": open_items}
                if not feedback.get("error"):
                    fresh = flag_board.observe(feedback["result"])
                    if fresh:
                        trace.event(
                            "flags",
                            tool=tool_name,
                            payload={"findings": [asdict(finding) for finding in fresh]},
                        )
                    if shown := flag_feedback(fresh):
                        feedback = {**feedback, "flags": shown}

            messages.append(
                {
                    "role": "tool",
                    "content": render_json(feedback),
                    "tool_call_id": tool_call_id,
                }
            )

    @staticmethod
    async def _call_tool(
        session: RemoteBenchmarkSession,
        trace: TaskTrace,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """Invoke one runtime tool and trace the exact request and full response.

        Args:
            session: Active remote task session.
            trace: Task trace of this session.
            tool_name: Advertised tool name.
            arguments: Tool arguments sent to the runtime.

        Returns:
            Server tool-call response.
        """
        trace.runtime_calls += 1
        started_at = time.perf_counter()
        response = await session.call_tool(tool_name, arguments)
        trace.event(
            "tool_call",
            duration_ms=elapsed_ms(started_at),
            tool=tool_name,
            status=response.info.get("tool_status"),
            reward=response.reward,
            terminated=response.terminated,
            truncated=response.truncated,
            payload={"arguments": arguments, "response": response.model_dump(mode="json")},
        )
        return response

    @staticmethod
    def _trace_task_end(
        trace: TaskTrace,
        task_result: TaskResult,
        error_message: str | None,
    ) -> None:
        """Write the closing summary line of a task trace.

        Args:
            trace: Task trace to finish.
            task_result: Authoritative result returned by the runtime.
            error_message: Agent failure that aborted the task, if any.
        """
        trace.event(
            "task_end",
            duration_ms=trace.wall_ms,
            completion_reason=task_result.completion_reason,
            total_reward=task_result.total_reward,
            quality_score=task_result.quality_score,
            efficiency_score=task_result.efficiency_score,
            tool_calls=task_result.tool_calls,
            steps_taken=task_result.steps_taken,
            agent_steps=trace.step,
            runtime_calls=trace.runtime_calls,
            llm_calls=trace.llm_calls,
            llm_tokens=trace.llm_tokens,
            llm_ms=trace.llm_ms,
            error=error_message,
            payload={"task_result": task_result.model_dump(mode="json")},
        )

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        """Reduce a remote tool response to the new evidence it carries.

        The alert and the tool catalog repeat in every observation and are
        already in the first message. The step reward is never shown: it
        leaks the grader's ground truth.

        Args:
            response: Server tool-call response.

        Returns:
            Tool status, the complete tool result and the error, if any.
        """
        feedback = {
            "status": response.info.get("tool_status", "unknown"),
            "result": _decode_json(response.observation.get("last_tool_result")),
        }
        if response.info.get("error") is not None:
            feedback["error"] = response.info["error"]
        return feedback


def _decode_json(value: Any) -> Any:
    """Parse a JSON-encoded string so the LLM sees it without escaping."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
