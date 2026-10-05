import json
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
from sibyl_h0und.llm import StructuredStepClient, render_json
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
- Use only entity_id values actually returned by the alert or by a tool.
- Submit only response artifacts supported by evidence. Do not invent entity ids.
- Keep current_state evidence-focused and the remaining plan short.
- Finish before the investigation step budget is exhausted.
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
        max_steps: int = 100,
        trace_dir: Path | None = None,
        trace_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store the LLM dependency and per-task step limit.

        Args:
            llm: Structured step generator used for every investigation turn.
            max_steps: Maximum total tool calls allowed for one task.
            trace_dir: Root directory for run traces, or `None` to disable tracing.
            trace_metadata: Non-secret run settings stored in every `task_start` event.

        Raises:
            ValueError: If the configured limit is not positive.
        """
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        self.max_steps = max_steps
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
            RuntimeError: If the agent exhausts its step budget.
        """
        trace = trace or TaskTrace(None)
        observation = session.task.observation
        trace.event(
            "task_start",
            payload={"run": self.trace_metadata, "task": session.task.model_dump(mode="json")},
        )
        tool_specs = self._tool_specs(observation)
        available_tools = {
            specification["name"]
            for specification in tool_specs
            if isinstance(specification.get("name"), str)
        }
        if "finish_investigation" not in available_tools:
            raise ValueError("The runtime did not advertise finish_investigation.")

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": render_json(
                    {
                        "instruction": "Investigate this alert and submit the correct response.",
                        "initial_observation": observation,
                        "available_tools": tool_specs,
                    }
                ),
            },
        ]

        for step_index in range(1, self.max_steps + 1):
            trace.step = step_index
            step = await self.llm.next_step(messages, trace=trace)
            tool_name = step.function.tool
            arguments = step.function.model_dump(
                mode="json",
                by_alias=True,
                exclude={"tool"},
                exclude_none=True,
            )
            trace.event("step", tool=tool_name, payload={"step": step.model_dump(mode="json")})
            tool_call_id = f"step_{step_index}"
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

            if tool_name not in available_tools:
                feedback: dict[str, Any] = {
                    "status": "error",
                    "message": (
                        f"Tool {tool_name!r} is not advertised for this task. "
                        f"Available tools: {sorted(available_tools)}"
                    ),
                }
                logger.warning("Rejected unavailable tool {} locally.", tool_name)
                trace.event("tool_rejected", tool=tool_name, payload={"arguments": arguments})
            else:
                response = await self._call_tool(session, trace, tool_name, arguments)
                feedback = self._tool_feedback(response)
                logger.info(
                    "Tool {} returned status {}.",
                    tool_name,
                    feedback.get("status", "unknown"),
                )
                if response.task_result is not None:
                    return TaskResult.model_validate(response.task_result)

            messages.append(
                {
                    "role": "tool",
                    "content": render_json(feedback),
                    "tool_call_id": tool_call_id,
                }
            )

        raise RuntimeError(
            f"Agent hit the {self.max_steps}-step limit without finish_investigation."
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
    def _tool_specs(observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Decode the runtime tool catalog from the current observation.

        Args:
            observation: Current public task observation.

        Returns:
            Advertised tool specifications.

        Raises:
            ValueError: If `available_tools` is absent or malformed.
        """
        raw_tool_specs = observation.get("available_tools")
        if not isinstance(raw_tool_specs, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            tool_specs = json.loads(raw_tool_specs)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(tool_specs, list) or not all(
            isinstance(specification, dict) for specification in tool_specs
        ):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return [dict(specification) for specification in tool_specs]

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        """Reduce a remote tool response to evidence needed by the LLM.

        Args:
            response: Server tool-call response.

        Returns:
            Compact evidence and lifecycle flags.
        """
        return {
            "tool_name": response.tool_name,
            "status": response.info.get("tool_status", "unknown"),
            "result": response.info.get("tool_result", response.observation),
            "error": response.info.get("error"),
            "reward": response.reward,
            "terminated": response.terminated,
            "truncated": response.truncated,
        }
