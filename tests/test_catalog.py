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
        "task_completed",
        "function",
    ]


def test_tools_without_an_argument_schema() -> None:
    """A practice tool falls back to its known schema; an unknown one gets free arguments."""
    catalog = catalog_of(
        {"name": "get_entity", "parameters": {"type": "object"}},
        {"name": "list_alerts"},
        {"name": "finish_investigation"},
    )

    response_format = catalog.response_format()

    tools = branches(response_format)
    assert set(tools["get_entity"]["properties"]) == {"tool", "entity_id", "reasoning"}
    assert "submission" in tools["finish_investigation"]["properties"]
    assert tools["list_alerts"]["additionalProperties"] is True
    # Strict mode cannot express free arguments, so the step schema is not strict.
    assert response_format["json_schema"]["strict"] is False
    strict_format = catalog.response_format(["get_entity", "finish_investigation"])
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
