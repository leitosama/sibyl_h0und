import time
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
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import Investigation, LocalAnswer
from sibyl_h0und.llm import StructuredStepClient, render_json
from sibyl_h0und.outcome import ToolOutcome
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
            trace.task_end(task_result.model_dump(mode="json"), error_message)
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
        investigation = Investigation(session.task.observation, trace)
        trace.task_start(
            self.trace_metadata,
            session.task.model_dump(mode="json"),
            investigation.catalog.response_format(),
        )
        budget = CallBudget(self.max_runtime_calls)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            investigation.opening_message(),
        ]

        while True:
            step_number = trace.next_step()
            finish_only = budget.start_turn()
            if finish_only and budget.finish_turns == 1:
                logger.warning("Only finish_investigation remains: {}.", budget.finish_reason)
                trace.finish_only(budget.finish_reason, budget.runtime_calls)
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
                response_format=investigation.catalog.response_format(
                    [FINISH_TOOL] if finish_only else None
                ),
                trace=trace,
            )
            tool_name = step.function.tool
            trace.step_chosen(tool_name, step.model_dump(mode="json"))
            tool_call_id = f"step_{step_number}"
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
                                "arguments": render_json(step.function.arguments),
                            },
                        }
                    ],
                }
            )

            decision = investigation.before_call(
                tool_name, step.function.arguments, finish_only=finish_only
            )
            if isinstance(decision, LocalAnswer):
                budget.record_local_answer()
                feedback = decision.feedback
            else:
                budget.record_runtime_call()
                response = await self._call_tool(session, trace, tool_name, decision.arguments)
                outcome = ToolOutcome.from_wire(
                    info=response.info,
                    observation=response.observation,
                    terminal=response.task_result is not None,
                )
                logger.info("Tool {} returned status {}.", tool_name, outcome.status)
                if response.task_result is not None:
                    return TaskResult.model_validate(response.task_result)
                feedback = investigation.after_call(tool_name, decision.arguments, outcome).feedback

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
        trace.count_runtime_call()
        started_at = time.perf_counter()
        response = await session.call_tool(tool_name, arguments)
        trace.tool_call(
            tool_name, arguments, response.model_dump(mode="json"), elapsed_ms(started_at)
        )
        return response
