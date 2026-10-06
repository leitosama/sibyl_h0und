"""The task's tool catalog and the strict step schema built from it.

`available_tools` is the only source of truth about tools (ADR 0003). Each
task gets its own response format: the step envelope plus `function` as a
choice over the catalog tools, each with its name as an enum and its own
argument schema.
"""

import copy
import json
from collections.abc import Iterable
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, best_match
from jsonschema.validators import validator_for
from loguru import logger

from sibyl_h0und.models import PRACTICE_ARGUMENT_MODELS, StepEnvelope, normalize_time_windows

FINISH_TOOL = "finish_investigation"
RESPONSE_FORMAT_NAME = "bluesec1_next_step"
# Keys under which a catalog entry may carry the JSON Schema of its arguments.
ARGUMENT_SCHEMA_KEYS = (
    "parameters",
    "input_schema",
    "inputSchema",
    "arguments_schema",
    "args_schema",
    "schema",
    "arguments",
)
# Where JSON Schema keeps reusable definitions.
DEFINITION_KEYS = ("$defs", "definitions")
# Keywords whose value maps names to schemas, so the names are not keywords.
SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions"})
# Keywords whose value is data, not a schema.
LITERAL_KEYS = frozenset({"enum", "const", "required", "examples"})
# The step's own key for the tool name; an argument of that name cannot be sent.
TOOL_KEY = "tool"


class ToolCatalog:
    """Tools advertised by one task and the step schemas that allow calling them."""

    def __init__(self, specs: list[dict[str, Any]]) -> None:
        """Index the advertised tools and resolve each argument schema.

        Args:
            specs: Decoded `available_tools` entries.

        Raises:
            ValueError: If the catalog has no `finish_investigation`.
        """
        self.specs = specs
        self._schemas: dict[str, dict[str, Any] | None] = {}
        for spec in specs:
            name = _tool_name(spec)
            if name is not None and name not in self._schemas:
                self._schemas[name] = _argument_schema(name, spec)
        if FINISH_TOOL not in self._schemas:
            raise ValueError("The runtime did not advertise finish_investigation.")
        self._formats: dict[frozenset[str], dict[str, Any]] = {}
        self._validators = {
            name: _validator(name, schema)
            for name, schema in self._schemas.items()
            if schema is not None
        }

    @classmethod
    def from_observation(cls, observation: dict[str, Any]) -> "ToolCatalog":
        """Decode the catalog from a task observation.

        Args:
            observation: Public task observation with a JSON-encoded `available_tools`.

        Returns:
            The task's tool catalog.

        Raises:
            ValueError: If `available_tools` is absent, malformed or has no
                `finish_investigation`.
        """
        raw_specs = observation.get("available_tools")
        if not isinstance(raw_specs, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            specs = json.loads(raw_specs)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(specs, list) or not all(isinstance(spec, dict) for spec in specs):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return cls([dict(spec) for spec in specs])

    @property
    def names(self) -> list[str]:
        """Names of the advertised tools in catalog order."""
        return list(self._schemas)

    def __contains__(self, tool_name: object) -> bool:
        """Tell whether the task advertises a tool."""
        return tool_name in self._schemas

    def prepare(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Turn the model's arguments into the call the runtime receives.

        Calendar-day time windows become whole UTC days, omitted arguments
        take their schema defaults, so equal calls look equal to the ledger,
        and the result is checked against the tool's own argument schema.

        Args:
            tool_name: Advertised tool name.
            arguments: Arguments the model chose, without nulls.

        Returns:
            Arguments to send.

        Raises:
            ValueError: If the arguments break the tool's schema; the call is
                answered locally instead of costing a runtime call.
        """
        prepared = normalize_time_windows(arguments)
        schema = self._schemas.get(tool_name)
        if schema is None:
            return prepared
        defaults = {
            key: value["default"]
            for key, value in (schema.get("properties") or {}).items()
            if isinstance(value, dict) and value.get("default") is not None
        }
        prepared = {**copy.deepcopy(defaults), **prepared}
        validator = self._validators.get(tool_name)
        error = best_match(validator.iter_errors(prepared)) if validator is not None else None
        if error is not None:
            where = "/".join(str(part) for part in error.absolute_path) or "arguments"
            raise ValueError(f"Invalid {tool_name} arguments at {where}: {error.message}")
        return prepared

    def response_format(self, tools: Iterable[str] | None = None) -> dict[str, Any]:
        """Build the strict `json_schema` response format of one step.

        Args:
            tools: Catalog tools the step may call; all of them when `None`.

        Returns:
            OpenAI-compatible response format. It is strict unless an argument
            schema cannot be made strict, which leaves only local validation.
        """
        names = frozenset(self._schemas if tools is None else tools).intersection(self._schemas)
        if not names:
            raise ValueError("A step must allow at least one advertised tool.")
        if names not in self._formats:
            self._formats[names] = self._build_format(
                [name for name in self._schemas if name in names]
            )
        return self._formats[names]

    def _build_format(self, names: list[str]) -> dict[str, Any]:
        """Assemble the step schema over the given tools."""
        definitions: dict[str, Any] = {}
        branches = []
        strict = True
        for name in names:
            branch, branch_definitions, branch_strict = _function_branch(name, self._schemas[name])
            branches.append(branch)
            definitions.update(branch_definitions)
            strict = strict and branch_strict
        schema = StepEnvelope.model_json_schema()
        schema["properties"]["function"] = {
            "anyOf": branches,
            "description": "Execute the first remaining step.",
        }
        schema["required"] = list(schema["properties"])
        _strict_object(schema)
        if definitions:
            schema["$defs"] = definitions
        return {
            "type": "json_schema",
            "json_schema": {"name": RESPONSE_FORMAT_NAME, "strict": strict, "schema": schema},
        }


def _tool_name(spec: dict[str, Any]) -> str | None:
    """Read a tool's name, also from an OpenAI-style `function` wrapper."""
    name = spec.get("name")
    if not isinstance(name, str) and isinstance(spec.get("function"), dict):
        name = spec["function"].get("name")
    return name if isinstance(name, str) and name else None


def _argument_schema(name: str, spec: dict[str, Any]) -> dict[str, Any] | None:
    """Find a tool's argument schema, falling back to the practice tool of that name.

    Args:
        name: Tool name.
        spec: Catalog entry.

    Returns:
        An object schema with `properties` (empty for a tool without
        arguments), or `None` when the arguments are unknown and free.
    """
    holders = [spec]
    if isinstance(spec.get("function"), dict):
        holders.append(spec["function"])
    closed_without_properties = False
    for holder in holders:
        for key in ARGUMENT_SCHEMA_KEYS:
            schema = holder.get(key)
            if isinstance(schema, str):
                try:
                    schema = json.loads(schema)
                except json.JSONDecodeError:
                    continue
            if not isinstance(schema, dict):
                continue
            if isinstance(schema.get("properties"), dict):
                return copy.deepcopy(schema)
            if _is_object(schema) and not schema.get("additionalProperties"):
                closed_without_properties = True
    if name in PRACTICE_ARGUMENT_MODELS:
        logger.warning("Catalog entry of {} has no argument schema; using the practice one.", name)
        return PRACTICE_ARGUMENT_MODELS[name].model_json_schema(by_alias=True)
    if closed_without_properties:
        # An object schema that names no properties is read as a tool without
        # arguments, so the step schema stays strict for every other tool.
        return {"type": "object", "properties": {}}
    logger.warning("Catalog entry of {} has no argument schema; its arguments are free.", name)
    return None


def _validator(name: str, schema: dict[str, Any]) -> Any:
    """Build the validator of one tool's original argument schema, if it is valid."""
    validator_class = validator_for(schema, default=Draft202012Validator)
    try:
        validator_class.check_schema(schema)
    except SchemaError as exc:
        logger.warning("Argument schema of {} is invalid, arguments are not checked: {}", name, exc)
        return None
    return validator_class(schema)


def _function_branch(
    name: str, schema: dict[str, Any] | None
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Build the `function` alternative that calls one tool.

    Args:
        name: Tool name.
        schema: Argument object schema, or `None` for free arguments.

    Returns:
        The branch schema, the definitions it references under `#/$defs/`,
        and whether it is valid in strict mode.
    """
    tool = {"type": "string", "enum": [name]}
    if schema is None:
        return (
            {
                "type": "object",
                "properties": {TOOL_KEY: tool},
                "required": [TOOL_KEY],
                "additionalProperties": True,
            },
            {},
            False,
        )
    schema = copy.deepcopy(schema)
    prefix = f"{name}__"
    definitions: dict[str, Any] = {}
    for key in DEFINITION_KEYS:
        for definition_name, definition in (schema.pop(key, None) or {}).items():
            definitions[prefix + definition_name] = definition
    _rename_refs(schema, prefix)
    _rename_refs(definitions, prefix)
    properties = schema.get("properties") or {}
    if TOOL_KEY in properties:
        logger.warning("Tool {} has an argument named {!r}; it cannot be sent.", name, TOOL_KEY)
    branch = {
        key: value
        for key, value in schema.items()
        if key not in {"properties", "required", "title", "$schema", "$id"}
    }
    branch["type"] = "object"
    branch["properties"] = {
        TOOL_KEY: tool,
        **{key: value for key, value in properties.items() if key != TOOL_KEY},
    }
    branch["required"] = [TOOL_KEY, *(schema.get("required") or [])]
    strict = _make_strict([branch, *definitions.values()])
    return branch, definitions, strict


def _rename_refs(node: Any, prefix: str) -> None:
    """Point local `$ref`s at the definitions renamed with a tool prefix."""
    if isinstance(node, list):
        for item in node:
            _rename_refs(item, prefix)
        return
    if not isinstance(node, dict):
        return
    ref = node.get("$ref")
    if isinstance(ref, str):
        for key in DEFINITION_KEYS:
            if ref.startswith(f"#/{key}/"):
                node["$ref"] = f"#/$defs/{prefix}{ref.removeprefix(f'#/{key}/')}"
    for value in node.values():
        _rename_refs(value, prefix)


def _is_object(schema: dict[str, Any]) -> bool:
    """Tell whether a schema describes an object, whatever form its `type` takes."""
    kind = schema.get("type")
    if kind is None:
        return isinstance(schema.get("properties"), dict)
    return kind == "object" or (isinstance(kind, list) and "object" in kind)


def _nullable(schema: Any) -> Any:
    """Allow `null` for an optional property that strict mode makes required."""
    if not isinstance(schema, dict) or _allows_null(schema):
        return schema
    return {"anyOf": [schema, {"type": "null"}]}


def _allows_null(schema: dict[str, Any]) -> bool:
    """Tell whether a schema already accepts `null`."""
    kind = schema.get("type")
    if kind == "null" or (isinstance(kind, list) and "null" in kind):
        return True
    options = schema.get("anyOf") or schema.get("oneOf") or []
    return any(isinstance(option, dict) and _allows_null(option) for option in options)


def _make_strict(node: Any) -> bool:
    """Normalize a schema in place for strict OpenAI-compatible providers.

    Objects at every depth become closed, with optional properties made
    nullable and every property required; defaults and discriminators are
    dropped, and `oneOf` becomes `anyOf`.

    Returns:
        Whether the schema is valid in strict mode: an object without
        declared properties accepts free keys, which strict mode forbids.
    """
    if isinstance(node, list):
        return all([_make_strict(item) for item in node])
    if not isinstance(node, dict):
        return True
    node.pop("default", None)
    node.pop("discriminator", None)
    if "oneOf" in node:
        node["anyOf"] = node.pop("oneOf")
    strict = True
    if _is_object(node):
        if isinstance(node.get("properties"), dict):
            _strict_object(node)
        else:
            strict = False
    for key, value in node.items():
        if key in SCHEMA_MAPS and isinstance(value, dict):
            strict = _make_strict(list(value.values())) and strict
        elif key not in LITERAL_KEYS:
            strict = _make_strict(value) and strict
    return strict


def _strict_object(node: dict[str, Any]) -> None:
    """Close an object schema and require all its properties, optional ones as nullable."""
    required = set(node.get("required") or [])
    node["properties"] = {
        key: value if key in required else _nullable(value)
        for key, value in node["properties"].items()
    }
    node["additionalProperties"] = False
    node["required"] = list(node["properties"])
