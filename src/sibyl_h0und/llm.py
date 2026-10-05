import asyncio
import json
import re
import time
from types import TracebackType
from typing import Any, Protocol, Self, cast

from loguru import logger
from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AsyncOpenAI,
    BadRequestError,
    ConflictError,
    InternalServerError,
    RateLimitError,
)
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared_params import ResponseFormatJSONSchema
from pydantic import ValidationError

from sibyl_h0und.models import (
    NEXT_STEP_RESPONSE_FORMAT,
    NextStep,
)
from sibyl_h0und.trace import TaskTrace

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

# Seconds to wait before each repeated provider request after a transient
# error; the length bounds the extra requests, so a run never hangs.
TRANSPORT_RETRY_DELAYS = (2.0, 5.0, 10.0)
# A timeout already cost a full request timeout, so it is repeated only once.
MAX_TIMEOUT_RETRIES = 1

REPAIR_INSTRUCTION = (
    "Your previous reply violated the required NextStep contract. " + STRUCTURED_OUTPUT_INSTRUCTION
)


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid structured step."""


class StructuredStepClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_step(
        self, messages: list[dict[str, Any]], *, trace: TaskTrace | None = None
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
        self, messages: list[dict[str, Any]], *, trace: TaskTrace | None = None
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
        trace = trace or TaskTrace(None)
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            response, latency_ms = await self._create_completion(request_messages, trace)
            raw_content = extract_raw_content(response)
            total_tokens = response_total_tokens(response)
            trace.llm_calls += 1
            trace.llm_tokens += total_tokens
            trace.llm_ms += latency_ms
            trace.event(
                "llm_call",
                attempt=attempt,
                tokens=total_tokens,
                duration_ms=latency_ms,
                payload={"messages": request_messages, "raw_content": raw_content},
            )

            try:
                step = parse_next_step_payload(raw_content)
            except ValueError as exc:
                last_error = exc
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

            logger.info(
                "LLM selected {} in {} ms using {} tokens.",
                step.function.tool,
                latency_ms,
                total_tokens,
            )
            return step

        message = str(last_error or ValueError("Unable to parse model response."))
        raise NextStepRequestError(message) from last_error

    async def _create_completion(
        self, messages: list[dict[str, Any]], trace: TaskTrace
    ) -> tuple[Any, int]:
        """Request one completion, repeating it after transient provider errors.

        Which errors are repeated is decided by `is_transient_error`. Each
        failure is traced as an `llm_error` event.

        Args:
            messages: Request messages, including structured-output instructions.
            trace: Task trace that receives one `llm_error` event per failure.

        Returns:
            Raw chat completion response and the latency of the successful request.

        Raises:
            APIError: If the error is permanent or every retry failed.
        """
        delays = iter(TRANSPORT_RETRY_DELAYS)
        timeouts = 0
        while True:
            started_at = time.perf_counter()
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=cast(list[ChatCompletionMessageParam], messages),
                    response_format=cast(ResponseFormatJSONSchema, NEXT_STEP_RESPONSE_FORMAT),
                    max_completion_tokens=self.max_completion_tokens,
                )
            except APIError as exc:
                trace.event("llm_error", error=f"{type(exc).__name__}: {exc}"[:2_000])
                timeouts += isinstance(exc, APITimeoutError)
                delay = next(delays, None)
                if delay is None or timeouts > MAX_TIMEOUT_RETRIES or not is_transient_error(exc):
                    raise
                logger.warning("LLM request failed, retrying in {} s: {}", delay, exc)
                await asyncio.sleep(delay)
                continue
            return response, int((time.perf_counter() - started_at) * 1000)


def is_transient_error(error: APIError) -> bool:
    """Tell whether repeating the same provider request can succeed.

    Connection failures, timeouts, rate limits, conflicts and server errors are
    transient. A 400 is transient only when it reports a proxy connection
    failure: Open WebUI answers an upstream outage with
    `400 {'detail': 'Open WebUI: Server Connection Error'}`, while other 400s,
    such as an exceeded context length, fail the same way on every attempt.

    Args:
        error: Error raised by the OpenAI-compatible client.

    Returns:
        Whether the request is worth repeating.
    """
    if isinstance(error, BadRequestError):
        return "connection error" in str(error).lower()
    return isinstance(
        error, APIConnectionError | RateLimitError | ConflictError | InternalServerError
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
        ValueError: If the reply is not valid `NextStep` JSON.
    """
    if not raw_content:
        raise ValueError("Model returned empty content for NextStep response.")

    normalized_content = extract_json_object(raw_content)
    try:
        step = NextStep.model_validate_json(normalized_content)
    except ValidationError as exc:
        raise ValueError("Model returned invalid NextStep JSON.") from exc

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


def render_json(value: Any) -> str:
    """Serialize participant-visible context for an LLM message.

    Args:
        value: Public JSON-compatible value.

    Returns:
        Stable readable JSON text.
    """
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
