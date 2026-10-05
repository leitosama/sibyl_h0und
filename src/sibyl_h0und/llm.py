import json
import re
import time
from types import TracebackType
from typing import Any, Protocol, Self, cast

from loguru import logger
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared_params import ResponseFormatJSONSchema
from pydantic import ValidationError

from sibyl_h0und.models import (
    NEXT_STEP_RESPONSE_FORMAT,
    FinishInvestigationRequest,
    NextStep,
)
from sibyl_h0und.trace import TaskTrace, elapsed_ms

STRUCTURED_OUTPUT_INSTRUCTION = """
Every assistant reply must be exactly one JSON object with these top-level fields:
{
  "current_state": "short evidence-focused string",
  "plan_remaining_steps_brief": ["one to five short step strings"],
  "task_completed": false,
  "function": {
    "tool": "one advertised tool name",
    "...": "that tool's arguments placed directly in this function object"
  }
}

Never use top-level `action`, `parameters`, `tool_name`, or `arguments` fields.
Never wrap tool arguments in a nested `parameters` or `arguments` object.
For example, a call with one advertised argument is:
{"tool":"advertised_tool","argument_name":"value"}
Set task_completed=true only for a function whose tool is finish_investigation.
Return no prose, markdown, XML, comments, or keys outside the required object.
""".strip()

REPAIR_INSTRUCTION = (
    "Your previous reply violated the required NextStep contract. " + STRUCTURED_OUTPUT_INSTRUCTION
)


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid structured step."""


class StructuredStepClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_step(
        self,
        messages: list[dict[str, Any]],
        *,
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Generate and validate one investigation step."""
        ...


class OpenAIStructuredStepClient:
    """Portable structured-output client for OpenAI-compatible providers."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_completion_tokens: int,
        max_retries: int,
        client: AsyncOpenAI | None = None,
    ) -> None:
        """Initialize an OpenAI-compatible structured step generator.

        Args:
            base_url: OpenAI-compatible API root.
            api_key: Provider credential.
            model: Provider model identifier.
            timeout_seconds: Timeout applied to each provider request.
            max_completion_tokens: Maximum generated tokens per attempt.
            max_retries: Maximum schema-generation attempts per step.
            client: Optional injected SDK client used by tests.
        """
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.max_retries = max_retries
        self._owns_client = client is None
        self._client = client or AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=0,
        )

    async def __aenter__(self) -> Self:
        """Enter the async LLM client context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close an internally owned provider client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the provider transport created by this wrapper."""
        if self._owns_client:
            await self._client.close()

    async def next_step(
        self,
        messages: list[dict[str, Any]],
        *,
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Return one valid `NextStep`, repairing malformed replies when possible.

        Args:
            messages: Current investigation conversation.
            trace: Task trace that receives one `llm_call` event per attempt.

        Returns:
            A locally validated structured investigation step.

        Raises:
            NextStepRequestError: If every provider reply violates the schema.
        """
        request_messages = list(messages)
        if request_messages and request_messages[0].get("role") == "system":
            first_message = dict(request_messages[0])
            first_message["content"] = (
                f"{first_message.get('content', '')}\n\n{STRUCTURED_OUTPUT_INSTRUCTION}"
            )
            request_messages[0] = first_message
        else:
            request_messages.insert(
                0,
                {"role": "system", "content": STRUCTURED_OUTPUT_INSTRUCTION},
            )
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            started_at = time.perf_counter()
            response: Any = None
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=cast(list[ChatCompletionMessageParam], request_messages),
                    response_format=cast(ResponseFormatJSONSchema, NEXT_STEP_RESPONSE_FORMAT),
                    max_completion_tokens=self.max_completion_tokens,
                )
                raw_content = extract_raw_content(response)
            except Exception as exc:
                self._trace_attempt(
                    trace, attempt, request_messages, response, elapsed_ms(started_at), exc
                )
                raise
            latency_ms = elapsed_ms(started_at)
            total_tokens = response_total_tokens(response)

            try:
                step = parse_next_step_payload(raw_content)
            except ValueError as exc:
                last_error = exc
                self._trace_attempt(trace, attempt, request_messages, response, latency_ms, exc)
                logger.warning(
                    "Invalid structured LLM response on attempt {}/{}: {}",
                    attempt,
                    self.max_retries,
                    raw_content[:2000] or str(exc),
                )
                if attempt == self.max_retries:
                    break
                request_messages.extend(
                    [
                        {"role": "assistant", "content": raw_content or "<empty>"},
                        {"role": "user", "content": REPAIR_INSTRUCTION},
                    ]
                )
                continue

            self._trace_attempt(trace, attempt, request_messages, response, latency_ms, None)
            logger.info(
                "LLM selected {} in {} ms using {} tokens.",
                step.function.tool,
                latency_ms,
                total_tokens,
            )
            return step

        message = str(last_error or ValueError("Unable to parse model response."))
        raise NextStepRequestError(message) from last_error

    def _trace_attempt(
        self,
        trace: TaskTrace | None,
        attempt: int,
        request_messages: list[dict[str, Any]],
        response: Any,
        latency_ms: int,
        error: Exception | None,
    ) -> None:
        """Record one provider request with its raw reply.

        Args:
            trace: Task trace, or `None` when the caller does not trace.
            attempt: One-based attempt number within this step.
            request_messages: Exact messages sent to the provider.
            response: Provider response, or `None` when the request failed.
            latency_ms: Request latency.
            error: Request or validation failure of this attempt.
        """
        if trace is None:
            return
        raw_content = None
        if response is not None:
            try:
                raw_content = extract_raw_content(response)
            except ValueError:
                raw_content = None
        trace.record_llm_call(
            tokens=response_total_tokens(response),
            duration_ms=latency_ms,
            attempt=attempt,
            model=self.model,
            finish_reason=response_finish_reason(response),
            error=None if error is None else f"{type(error).__name__}: {error}",
            payload={
                "max_completion_tokens": self.max_completion_tokens,
                "messages": request_messages,
                "raw_content": raw_content,
                "usage": response_usage(response),
                "response": (
                    response.model_dump(mode="json") if hasattr(response, "model_dump") else None
                ),
            },
        )


def extract_message_text(message: Any) -> str:
    """Normalize string and multipart assistant content into plain text.

    Args:
        message: Provider-specific chat completion message.

    Returns:
        Concatenated textual message content.
    """
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    text_parts: list[str] = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            text_parts.append(str(part.get("text", "")))
        elif getattr(part, "type", None) == "text":
            text_parts.append(str(getattr(part, "text", "")))
    return "".join(text_parts)


def extract_raw_content(response: Any) -> str:
    """Extract the first assistant message from a completion response.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Raw assistant text.

    Raises:
        ValueError: If the provider response is missing a usable message.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        raise ValueError("Model response is missing choices.")

    message = getattr(choices[0], "message", None)
    if message is None:
        raise ValueError("Model response is missing a message.")

    refusal = getattr(message, "refusal", None)
    if refusal:
        raise ValueError(f"Model refused structured output: {refusal}")
    return extract_message_text(message)


def extract_json_object(raw_content: str) -> str:
    """Remove common provider wrappers around a JSON object.

    Args:
        raw_content: Untrusted assistant response text.

    Returns:
        Candidate JSON object text for local validation.
    """
    stripped = raw_content.strip()
    if not stripped:
        return ""
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped).strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    match = re.search(r"\{.*\}", stripped, re.DOTALL)
    return match.group(0) if match is not None else stripped


def parse_next_step_payload(raw_content: str) -> NextStep:
    """Validate one raw provider reply as a consistent `NextStep`.

    Args:
        raw_content: Assistant response containing a structured step.

    Returns:
        Parsed and validated step.

    Raises:
        ValueError: If JSON, schema, or completion semantics are invalid.
    """
    if not raw_content:
        raise ValueError("Model returned empty content for NextStep response.")

    normalized_content = extract_json_object(raw_content)
    try:
        step = NextStep.model_validate_json(normalized_content)
    except ValidationError as exc:
        raise ValueError("Model returned invalid NextStep JSON.") from exc

    is_finish = isinstance(step.function, FinishInvestigationRequest)
    if step.task_completed != is_finish:
        raise ValueError(
            "task_completed must be true exactly when finish_investigation is selected."
        )
    return step


def response_total_tokens(response: Any) -> int:
    """Read total token usage when the provider supplies it.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Non-negative total token count, or zero when unavailable.
    """
    usage = getattr(response, "usage", None)
    total_tokens = getattr(usage, "total_tokens", 0)
    return total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else 0


def response_finish_reason(response: Any) -> str | None:
    """Read why the provider stopped generating the first choice.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Finish reason such as `stop` or `length`, when present.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return None
    finish_reason = getattr(choices[0], "finish_reason", None)
    return finish_reason if isinstance(finish_reason, str) else None


def response_usage(response: Any) -> dict[str, Any] | None:
    """Return the provider usage block as plain JSON data.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Usage fields, including provider-specific extras, when present.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        return usage.model_dump(mode="json")
    return dict(vars(usage))


def render_json(value: Any) -> str:
    """Serialize participant-visible context for an LLM message.

    Args:
        value: Public JSON-compatible value.

    Returns:
        Stable readable JSON text.
    """
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
