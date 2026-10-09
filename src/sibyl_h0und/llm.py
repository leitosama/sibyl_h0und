import asyncio
import json
import re
import time
from collections.abc import Callable, Mapping
from types import TracebackType
from typing import Any, Protocol, Self, TypeVar, cast

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
from pydantic import BaseModel, ValidationError

from sibyl_h0und.models import NextStep
from sibyl_h0und.trace import TaskTrace

STRUCTURED_OUTPUT_INSTRUCTION = """
Every assistant reply must be exactly one JSON object with these top-level fields:
{
  "current_state": "short evidence-focused string",
  "plan_remaining_steps_brief": ["one to five short step strings"],
  "function": {
    "tool": "one advertised tool name",
    "...": "that tool's arguments placed directly in this function object"
  }
}

Never use top-level `action`, `parameters`, `tool_name`, or `arguments` fields.
Never wrap tool arguments in a nested `parameters` or `arguments` object.
For example, a call with one advertised argument is:
{"tool":"advertised_tool","argument_name":"value"}
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
# Repair request of a side turn, whose schema is its own.
SIDE_REPAIR_INSTRUCTION = (
    "Your previous reply did not match the required JSON schema: {error}. Return exactly one "
    "JSON object that matches it, with no prose, markdown or extra keys."
)
# The role of the investigation's own turns in `llm_call` events.
HEAD_ROLE = "head"

ModelT = TypeVar("ModelT", bound=BaseModel)
ReplyT = TypeVar("ReplyT")


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid structured step."""


class StructuredStepClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_step(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any],
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Generate and validate one investigation step under the task's step schema."""
        ...

    async def structured(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any],
        model: type[ModelT],
        role: str,
        trace: TaskTrace | None = None,
    ) -> ModelT:
        """Generate and validate one side-turn reply, such as the challenger's."""
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
        role_models: Mapping[str, str] | None = None,
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
            role_models: Model of a side turn by its role; other turns use `model`.
            client: Optional injected SDK client used by tests.
        """
        self.model = model
        self.role_models = dict(role_models or {})
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
        response_format: dict[str, Any],
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Return one valid `NextStep`, repairing malformed replies when possible.

        Args:
            messages: Current investigation conversation.
            response_format: Step schema built from the task's tool catalog.
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
        step = await self._generate(
            request_messages,
            response_format,
            parse_next_step_payload,
            lambda _: REPAIR_INSTRUCTION,
            HEAD_ROLE,
            trace or TaskTrace(None),
        )
        logger.info("LLM selected {}.", step.function.tool)
        return step

    async def structured(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any],
        model: type[ModelT],
        role: str,
        trace: TaskTrace | None = None,
    ) -> ModelT:
        """Return one valid reply of a side turn, repairing malformed replies when possible.

        The messages carry their own instructions; nothing is added to them.

        Args:
            messages: The side turn's request.
            response_format: The side turn's schema.
            model: Model that validates the reply.
            role: Name of the side turn in `llm_call` events.
            trace: Task trace that receives one `llm_call` event per attempt.

        Returns:
            The validated reply.

        Raises:
            NextStepRequestError: If every provider reply violates the schema.
        """
        return await self._generate(
            list(messages),
            response_format,
            lambda raw: parse_model_payload(raw, model),
            lambda error: SIDE_REPAIR_INSTRUCTION.format(error=error),
            role,
            trace or TaskTrace(None),
        )

    async def _generate(
        self,
        request_messages: list[dict[str, Any]],
        response_format: dict[str, Any],
        parse: Callable[[str], ReplyT],
        repair: Callable[[ValueError], str],
        role: str,
        trace: TaskTrace,
    ) -> ReplyT:
        """Request replies until one parses, asking the model to repair each failure.

        Args:
            request_messages: Full request; repair turns are appended to it.
            response_format: Schema sent with the request.
            parse: Validation of one raw reply; raises `ValueError` on failure.
            repair: The repair instruction for a parse error.
            role: Name of the turn in `llm_call` events.
            trace: Task trace that receives one `llm_call` event per attempt.

        Returns:
            The first reply that parses.

        Raises:
            NextStepRequestError: If every provider reply violates the schema.
        """
        last_error: Exception | None = None
        model = self.role_models.get(role, self.model)

        for attempt in range(1, self.max_retries + 1):
            response, latency_ms = await self._create_completion(
                request_messages, response_format, model, trace
            )
            # A reply without a usable message, such as a refusal or empty
            # `choices`, is traced and repaired like a malformed one.
            try:
                raw_content = extract_raw_content(response)
            except ValueError as exc:
                raw_content, unusable = "", exc
            else:
                unusable = None
            total_tokens = response_total_tokens(response)
            trace.count_llm_attempt(tokens=total_tokens, ms=latency_ms)
            trace.llm_call(
                request_messages,
                raw_content=raw_content,
                role=role,
                model=model,
                attempt=attempt,
                tokens=total_tokens,
                duration_ms=latency_ms,
                **({"error": str(unusable)} if unusable is not None else {}),
            )

            try:
                if unusable is not None:
                    raise unusable
                reply = parse(raw_content)
            except ValueError as exc:
                last_error = exc
                logger.warning(
                    "Invalid structured {} response on attempt {}/{}: {}",
                    role,
                    attempt,
                    self.max_retries,
                    raw_content[:2000] or str(exc),
                )
                if attempt == self.max_retries:
                    break
                request_messages.extend(
                    [
                        {"role": "assistant", "content": raw_content or "<empty>"},
                        {"role": "user", "content": repair(exc)},
                    ]
                )
                continue

            logger.info(
                "LLM answered the {} turn in {} ms using {} tokens.", role, latency_ms, total_tokens
            )
            return reply

        message = str(last_error or ValueError("Unable to parse model response."))
        raise NextStepRequestError(message) from last_error

    async def _create_completion(
        self,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any],
        model: str,
        trace: TaskTrace,
    ) -> tuple[Any, int]:
        """Request one completion, repeating it after transient provider errors.

        Which errors are repeated is decided by `is_transient_error`. Each
        failure is traced as an `llm_error` event.

        Args:
            messages: Request messages, including structured-output instructions.
            response_format: Step schema sent with the request.
            model: Provider model identifier of this turn.
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
                    model=model,
                    messages=cast(list[ChatCompletionMessageParam], messages),
                    response_format=cast(ResponseFormatJSONSchema, response_format),
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


def parse_model_payload(raw_content: str, model: type[ModelT]) -> ModelT:
    """Validate one raw provider reply against a side turn's model.

    Args:
        raw_content: Assistant response containing one JSON object.
        model: Model of the reply.

    Returns:
        The validated reply.

    Raises:
        ValueError: If the reply is empty or does not match the model.
    """
    if not raw_content:
        raise ValueError(f"Model returned empty content for {model.__name__}.")
    try:
        return model.model_validate_json(extract_json_object(raw_content))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(map(str, error['loc'])) or 'reply'}: {error['msg']}"
            for error in exc.errors()[:3]
        )
        raise ValueError(f"Invalid {model.__name__} JSON: {problems}") from exc


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
