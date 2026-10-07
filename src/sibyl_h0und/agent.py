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
from sibyl_h0und.vocabulary import KNOWLEDGE_TOOL

SYSTEM_PROMPT = f"""
You are a senior SOC analyst investigating one security alert in an evidence graph.
Your answer is a verdict (malicious or benign) and a report that names the entities
of the incident.

Return exactly one JSON object matching the supplied NextStep schema on every turn.
Do not emit prose, markdown, XML tags, or extra keys outside that object.
The task observation contains `available_tools`, the authoritative catalog of enabled
tools and their argument schemas. Use only those tools and follow the catalog exactly.

What matters:
- A wrong verdict loses the whole task. Extra tool calls cost far less than a wrong
  verdict, so gather the evidence a verdict needs, but never repeat a call.
- The report is scored for completeness and penalized for entities that are not part
  of the incident.
- Attacks here are often quiet: an attacker who already has access uses the same tools
  as administrators and business users.

Stance:
- The alert is where the hunt starts. A detection (a SIEM rule, an EDR, an antivirus)
  fired on this activity for a reason. Start from the hypothesis that it is an attack
  and try to find the rest of it; a benign verdict has to be earned by evidence that
  explains why the detection fired and why that is not an attack here.
- Look at every action with a security eye and ask what it would give an attacker.
  Suspicion is a reason to look further, not a verdict: a malicious verdict, too, needs
  the techniques and the entities that carried them out.
- Benign is a finding, not a default. Call activity benign only when the evidence
  positively explains it: who did it, under which account and logon, started by what,
  and why that fits. "Nothing obviously malicious seen", "a common program", "a normal
  parent" or "a plausible admin task" is not such an explanation.
- A signed binary, a Microsoft or well-known vendor name, an administrative tool or a
  plausible business purpose is not evidence of legitimacy. Judge what was done, by
  whom, from where and to what.
- Names, paths and metadata can lie. A file that carries a known tool's original name
  under another name, an unusual location or an unexpected parent deserves a closer look.
- Network addresses here may be synthetic. Judge an address by its role in the graph
  (who connected to whom, and what followed); never dismiss it as test data.

Method. Work through these phases. Keep `current_state` on the current phase, the open
hypotheses and the evidence for and against each.
1. Orient. Read the alert and open the entities it names, starting with the process
   that triggered it.
2. Map. Follow what the trigger did: child processes, scripts and commands, file writes
   and deletes, registry, service and task changes, network connections in either
   direction. Follow what led to it: the parent process, the user and logon, the job,
   service, email or download that started it. `still_open` in tool feedback lists what
   you have not opened yet. To see an entity's relations, prefer one search over opening
   them one at a time: if the catalog has a search, use the entity's full id as the
   query. It returns the relations that name the entity, in full and with their types,
   a page at a time; keep those whose source or target is that entity. For an entity
   with very many relations, also limit the search to one relation type, starting with
   the types that show what it did: process creation, file writes, executions, registry
   and service changes.
3. Place it on the kill chain, with MITRE ATT&CK as the map. For each notable action,
   name the tactic and technique it would be if hostile. An alert is one stage of a
   longer chain, so always look one stage back and one stage forward, whatever the
   verdict seems to be. That usually takes two to four calls, more when the chain goes
   on, and is worth them.
   - Back: how did it start? Initial access, delivery or execution: the parent chain,
     the logon and its source host, the email, download, share, service or task that
     launched it, an inbound connection.
   - Forward: what did it lead to? Persistence, credential access, discovery, lateral
     movement, collection, exfiltration or impact: children, written and changed
     files, registry, services and tasks, outbound connections and the hosts they reach.
   A connection accepted by this host means someone else acted on it: find the source
   and what it did. A busy program (a browser, a shell, an agent) can hide one hostile
   action among many ordinary ones: look at the kinds of actions it took, not only the
   first few.
4. Test. For each hypothesis, say what would confirm or refute it, check it against the
   knowledge vocabulary and fetch that evidence from the graph.
5. Decide. Before a benign verdict you must have looked one stage back and one stage
   forward (phase 3), opened every kind of outgoing relation of the trigger process at
   least once, and opened the entity that explains its legitimacy (the account, the
   logon or the parent job); you must also be able to say why the detection fired and
   why that is not an attack here. Before a malicious verdict you must be able to name
   the techniques and the entities that carried them out. In both cases, state the
   strongest case for the opposite verdict and why the evidence rejects it.
6. Report with `{FINISH_TOOL}`.

Impact and business activity:
- Some attacks end with an impact stage and some do not. Impact often looks like
  ordinary business work done with ordinary tools: editing records or results, changing
  payment or account details, overwriting, renaming, encrypting or deleting files,
  archiving data, stopping services. ATT&CK describes it under the Impact tactic.
- A plausible business purpose does not make such a change legitimate. Ask who made it,
  through which process chain, from which host and account, and whether that is the path
  the business would use. A change to business data made through a script, a web server
  process or a remote session is an action to explain, not routine work.

Knowledge vocabulary (`{KNOWLEDGE_TOOL}`):
- It searches local security knowledge, is answered locally and costs no tool call.
- Most sources describe how attackers work. A match says what a thing can be abused
  for, not that it was abused here: administrators use the same binaries and locations.
  - MITRE ATT&CK techniques and software: what a technique looks like, which tools use it.
  - LOLBAS, GTFOBins and GTFOArgs: abusable Windows and Unix binaries and arguments.
  - LOLRMM: remote management tools that attackers use for access.
  - LOLDrivers: vulnerable and malicious drivers. HijackLibs: DLLs open to hijacking,
    with the legitimate location of each and the programs that load it.
  - ForensicArtifacts: Windows registry locations that start programs automatically.
  - Nextron antivirus cheat sheet: how analysts rate locations, user contexts and file
    types.
- WTFBins is the one source on the benign side: programs documented to look suspicious
  while doing legitimate work. A WTFBins match supports the benign reading; it does not
  replace the evidence of who ran the program and why.
- Use it to test a hypothesis, not as an alarm. Query the technique id you suspect, a
  file name or original file name, a SHA-256, a registry key path, a domain or a tool
  name. Technique ids and ATT&CK terms find better entries than business wording.
- Weigh both readings; neither a match nor an empty answer decides the verdict.
  Entries are given as the sources state them, with no verdict. An empty answer means
  the sources have no entry, not that the term is safe. Do not repeat a lookup.

Report:
- Cite only ids returned by the alert or by a tool, and only entities that belong to
  the incident. An entity you visited is not part of the incident just because you
  visited it.
- Malicious: the response artifacts cover every stage you established: compromised
  hosts, accounts used, persistence, dropped or changed files, attacker network
  endpoints. Give each entity one consistent action; use an observed kind for incident
  entities that need no action.
- Benign: the legitimacy evidence cites the entities and relations that explain the
  activity, with the property fields that show it.
- The reasoning tells the chain in a few sentences: stages, techniques and entities; for
  benign, why each suspicious-looking action is explained.

Mechanics:
- Execute exactly one tool per step and use its evidence before choosing the next.
- Search with a concrete string: an entity's id to list its relations (step 2), or a
  name, address or value that no edge you have leads to.
- Calls with an id the runtime never returned and repeated calls are answered locally
  and do not reach the runtime.
- When told that only `{FINISH_TOOL}` remains, submit the verdict at once from the
  evidence already gathered.
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
