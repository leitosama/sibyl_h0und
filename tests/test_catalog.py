import json
from typing import Any

import pytest

from sibyl_h0und.catalog import ToolCatalog

FINISH_PARAMETERS = {
    "type": "object",
    "properties": {
        "submission": {"$ref": "#/$defs/Submission"},
    },
    "required": ["submission"],
    "$defs": {
        "Submission": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["malicious", "benign"]},
                "reasoning": {"type": "string"},
            },
            "required": ["verdict", "reasoning"],
        }
    },
}
LOOKUP_PARAMETERS = {
    "type": "object",
    "properties": {
        "host_id": {"type": "string"},
        "page": {"type": "integer", "default": 1},
    },
    "required": ["host_id"],
}


def catalog_of(*specs: dict[str, Any]) -> ToolCatalog:
    """Decode a catalog the way a task observation carries it."""
    return ToolCatalog.from_observation({"available_tools": json.dumps(list(specs))})


def schema_of(response_format: dict[str, Any]) -> dict[str, Any]:
    """Return the JSON Schema inside a response format."""
    return response_format["json_schema"]["schema"]


def branches(response_format: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map each callable tool name to its `function` alternative."""
    options = schema_of(response_format)["properties"]["function"]["anyOf"]
    return {option["properties"]["tool"]["enum"][0]: option for option in options}


def refs(node: Any) -> list[str]:
    """Collect every `$ref` in a schema."""
    if isinstance(node, list):
        return [ref for item in node for ref in refs(item)]
    if not isinstance(node, dict):
        return []
    own = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
    return own + [ref for value in node.values() for ref in refs(value)]


@pytest.mark.parametrize(
    "lookup",
    [
        pytest.param({"name": "lookup_host", "parameters": LOOKUP_PARAMETERS}, id="parameters"),
        pytest.param({"name": "lookup_host", "input_schema": LOOKUP_PARAMETERS}, id="input-schema"),
        pytest.param(
            {
                "type": "function",
                "function": {"name": "lookup_host", "parameters": LOOKUP_PARAMETERS},
            },
            id="openai-function",
        ),
        pytest.param(
            {"name": "lookup_host", "parameters": json.dumps(LOOKUP_PARAMETERS)}, id="json-string"
        ),
    ],
)
def test_step_schema_offers_exactly_the_catalog_tools(lookup: dict[str, Any]) -> None:
    """A tool unknown to the code is callable, and a tool missing from the catalog is not."""
    catalog = catalog_of(lookup, {"name": "finish_investigation", "parameters": FINISH_PARAMETERS})

    response_format = catalog.response_format()

    assert response_format["json_schema"]["strict"] is True
    tools = branches(response_format)
    assert set(tools) == {"lookup_host", "finish_investigation"}
    assert "get_entity" not in catalog
    lookup_branch = tools["lookup_host"]
    assert lookup_branch["additionalProperties"] is False
    assert lookup_branch["required"] == ["tool", "host_id", "page"]
    assert lookup_branch["properties"]["host_id"] == {"type": "string"}
    # An optional argument is required by strict mode, so the model may send null.
    assert lookup_branch["properties"]["page"] == {"anyOf": [{"type": "integer"}, {"type": "null"}]}


def test_nested_objects_are_closed_and_their_optional_fields_nullable() -> None:
    """Strict mode needs every object closed, including ones written without `type: object`."""
    scope = {
        "properties": {"kind": {"type": "string"}, "attribute": {"type": "string"}},
        "required": ["kind"],
    }
    window = {"type": ["object", "null"], "properties": {"from": {"type": "string"}}}
    parameters = {
        "type": "object",
        "properties": {"query": {"type": "string"}, "scope": scope, "window": window},
        "required": ["query", "scope", "window"],
    }
    catalog = catalog_of(
        {"name": "search", "parameters": parameters}, {"name": "finish_investigation"}
    )

    response_format = catalog.response_format()

    assert response_format["json_schema"]["strict"] is True
    properties = branches(response_format)["search"]["properties"]
    for nested in (properties["scope"], properties["window"]):
        assert nested["additionalProperties"] is False
        assert nested["required"] == list(nested["properties"])
    assert properties["scope"]["properties"]["attribute"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}]
    }
    assert properties["scope"]["properties"]["kind"] == {"type": "string"}


def test_step_schema_keeps_tool_definitions_resolvable() -> None:
    """Definitions of each tool move to the root, and every reference still resolves."""
    catalog = catalog_of({"name": "finish_investigation", "parameters": FINISH_PARAMETERS})

    schema = schema_of(catalog.response_format())

    definitions = schema["$defs"]
    assert refs(schema) == ["#/$defs/finish_investigation__Submission"]
    submission = definitions["finish_investigation__Submission"]
    assert submission["additionalProperties"] is False
    assert submission["required"] == ["verdict", "reasoning"]
    assert schema["required"] == [
        "current_state",
        "plan_remaining_steps_brief",
        "function",
    ]


def test_tools_without_an_argument_schema() -> None:
    """A practice tool falls back to its known schema; an unknown one gets free arguments."""
    catalog = catalog_of(
        {"name": "get_entity", "parameters": {"type": "object"}},
        {"name": "list_hosts", "parameters": {"type": "object"}},
        {"name": "list_alerts"},
        {"name": "finish_investigation"},
    )

    response_format = catalog.response_format()

    tools = branches(response_format)
    assert set(tools["get_entity"]["properties"]) == {"tool", "entity_id", "reasoning"}
    assert "submission" in tools["finish_investigation"]["properties"]
    # An object schema naming no properties is a tool without arguments.
    assert tools["list_hosts"]["properties"] == {"tool": {"type": "string", "enum": ["list_hosts"]}}
    assert tools["list_alerts"]["additionalProperties"] is True
    # Strict mode cannot express free arguments, so the step schema is not strict.
    assert response_format["json_schema"]["strict"] is False
    strict_format = catalog.response_format(["get_entity", "list_hosts", "finish_investigation"])
    assert strict_format["json_schema"]["strict"] is True


def test_step_schema_can_allow_only_the_report() -> None:
    """Near the call limit the step schema offers finish_investigation alone."""
    catalog = catalog_of(
        {"name": "lookup_host", "parameters": LOOKUP_PARAMETERS},
        {"name": "finish_investigation", "parameters": FINISH_PARAMETERS},
    )

    assert set(branches(catalog.response_format(["finish_investigation"]))) == {
        "finish_investigation"
    }


def test_catalog_without_finish_investigation_is_rejected() -> None:
    """A task that cannot be finished is an error, not an endless investigation."""
    with pytest.raises(ValueError, match="finish_investigation"):
        catalog_of({"name": "lookup_host", "parameters": LOOKUP_PARAMETERS})


SEARCH_PARAMETERS = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "minLength": 5},
        "page_id": {"type": "integer", "minimum": 1, "default": 1},
        "time_window": {
            "type": "object",
            "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
        },
    },
    "required": ["query"],
}


def test_prepare_normalizes_arguments_so_equal_calls_look_equal() -> None:
    """Defaults fill omitted arguments and calendar days become whole UTC days."""
    catalog = catalog_of(
        {"name": "search", "parameters": SEARCH_PARAMETERS}, {"name": "finish_investigation"}
    )

    prepared = catalog.prepare(
        "search", {"query": "powershell", "time_window": {"from": "2026-09-01", "to": "2026-09-02"}}
    )

    assert prepared == {
        "query": "powershell",
        "page_id": 1,
        "time_window": {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T23:59:59.999999Z"},
    }
    assert catalog.prepare("search", {"query": "powershell", "page_id": 1}) == catalog.prepare(
        "search", {"query": "powershell"}
    )


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param({"query": "cmd"}, id="too-short"),
        pytest.param({"page_id": 2}, id="missing-required"),
        pytest.param({"query": "powershell", "page_id": 0}, id="below-minimum"),
        pytest.param(
            {"query": "powershell", "time_window": {"from": "2026-09-02", "to": "2026-09-01"}},
            id="inverted-window",
        ),
        pytest.param(
            {"query": "powershell", "time_window": {"from": "2026-09-01T10:00:00"}},
            id="naive-timestamp",
        ),
    ],
)
def test_prepare_rejects_arguments_that_break_the_tool_schema(arguments: dict[str, Any]) -> None:
    """A call the runtime would reject is caught before it costs a runtime call."""
    catalog = catalog_of(
        {"name": "search", "parameters": SEARCH_PARAMETERS}, {"name": "finish_investigation"}
    )

    with pytest.raises(ValueError):
        catalog.prepare("search", arguments)
