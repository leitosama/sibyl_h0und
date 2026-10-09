import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
)


class StrictModel(BaseModel):
    """Base model that rejects fields outside the public structured contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


ToolReasoning = Annotated[str, Field(min_length=1, max_length=4096)]
PropertyFieldName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

EntitySearchType = Literal[
    "host",
    "network_connection",
    "thread",
    "memory_region",
    "email",
    "email_url",
    "email_click",
    "email_attachment",
    "archive_file",
    "mounted_volume",
    "vpn_session",
    "app_object",
    "windows_process",
    "windows_file",
    "windows_user",
    "windows_service",
    "windows_driver",
    "registry_key",
    "named_pipe",
    "smb_share",
    "scheduled_task",
    "powershell_script",
    "powershell_cmdlet_invocation",
    "wmi_event_filter",
    "wmi_event_consumer",
    "wmi_binding",
    "com_object",
    "certificate_template",
    "x509_certificate",
    "kerberos_ticket",
    "lnk_shortcut",
    "ad_object",
    "linux_process",
    "linux_file",
    "linux_user",
    "linux_group",
    "systemd_unit",
    "kernel_module",
    "unix_socket",
    "ebpf_program",
]

RelationSearchType = Literal[
    "wrote_file",
    "read_file",
    "deleted_file",
    "renamed_file",
    "timestomped",
    "executed_file",
    "changed_file_mode",
    "changed_file_owner",
    "created_directory",
    "created_link",
    "truncated_file",
    "resolved_file_handle",
    "opened_by_handle",
    "created_memfd",
    "created_memfd_secret",
    "connected_to",
    "listened_on",
    "accepted_connection_from",
    "served_request_for",
    "sent_data_to",
    "received_data_from",
    "loaded_image",
    "allocated_memory",
    "mapped_memory",
    "created_thread",
    "created_service",
    "modified_service",
    "started_service",
    "stopped_service",
    "logged_on_to",
    "logged_off_from",
    "runs_process",
    "hosts",
    "mounted",
    "parent_of",
    "win_process_create",
    "injected_into",
    "accessed_process",
    "debugged_process",
    "elevated_token",
    "opened_handle",
    "duplicated_handle",
    "created_pipe",
    "connected_to_pipe",
    "opened_share_session",
    "created_scheduled_task",
    "ran_scheduled_task",
    "payload_references",
    "created_registry_key",
    "set_registry_value",
    "deleted_registry_key",
    "deleted_registry_value",
    "renamed_registry_key",
    "created_wmi_filter",
    "created_wmi_consumer",
    "bound_wmi_filter_to_consumer",
    "executed_script",
    "invoked_cmdlet",
    "loaded_driver",
    "created_shadow_copy",
    "received_email",
    "contained_url",
    "contained_attachment",
    "materialized_as",
    "performed_click",
    "targeted_url",
    "archived_to",
    "extracted_to",
    "contains_file",
    "mounted_as",
    "resolves_to",
    "created_account",
    "added_to_group",
    "removed_from_group",
    "requested_certificate",
    "issued_by_template",
    "authenticated_with_certificate",
    "requested_service_ticket",
    "dcsync_replication",
    "opened_handle_on_ad_object",
    "cleared_event_log",
    "remote_wmi_exec",
    "tunneled_via",
    "established_vpn_session",
    "tunneled_through",
    "forked",
    "execve_transitioned",
    "linux_process_create",
    "signal_sent",
    "ptrace_attached",
    "privilege_changed",
    "capabilities_changed",
    "controlled_tty",
    "changed_system_time",
    "changed_password",
    "changed_selinux_context",
    "changed_xattr",
    "created_unix_socket",
    "connected_to_unix_socket",
    "passed_fd",
    "loaded_kernel_module",
    "loaded_ebpf",
    "modified_audit_rules",
    "modified_audit_params",
    "created_group",
    "modified_group",
]


class EntitySearchScope(StrictModel):
    """Restrict search to one graph entity type."""

    kind: Literal["entity"]
    type: EntitySearchType


class RelationSearchScope(StrictModel):
    """Restrict search to one graph relation type."""

    kind: Literal["relation"]
    type: RelationSearchType


SearchScope = Annotated[EntitySearchScope | RelationSearchScope, Field(discriminator="kind")]


class SearchTimeWindow(StrictModel):
    """Inclusive timestamp range for graph search."""

    from_: datetime = Field(alias="from")
    to: datetime


class SearchArguments(StrictModel):
    """Find entities and relations whose id or attributes contain a substring."""

    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=5)]
    reasoning: ToolReasoning
    page_id: int = Field(default=1, ge=1)
    scope: SearchScope | None = None
    time_window: SearchTimeWindow | None = None
    sort_order: Literal["ascending", "descending"] = "ascending"


class GetEntityArguments(StrictModel):
    """Read one entity and the ids of its incoming and outgoing relations."""

    entity_id: str
    reasoning: ToolReasoning


class GetRelationArguments(StrictModel):
    """Read one relation, including the entities it connects."""

    relation_id: str
    reasoning: ToolReasoning


class GetADObjectInfoArguments(StrictModel):
    """Read one Active Directory object and its navigation references."""

    ad_object_id: str
    reasoning: ToolReasoning


IRArtifactKind = Literal[
    "host_to_isolate",
    "identity_to_rotate",
    "persistence_to_remove",
    "cleanup_to_verify",
    "file_to_delete",
    "network_block",
    "mailbox_action",
    "other",
    "process_observed",
    "registry_observed",
    "file_observed",
    "mount_observed",
    "lnk_observed",
    "ticket_observed",
    "identity_observed",
    "artifact_observed",
]


class FinishInvestigationArtifact(StrictModel):
    """One discovered entity and its requested incident-response action."""

    entity_id: str
    kind: IRArtifactKind


class FinishInvestigationEntityEvidence(StrictModel):
    """Cite observable entity properties supporting a benign verdict."""

    anchor: Literal["entity"]
    entity_id: str
    property_fields: list[PropertyFieldName] = Field(min_length=1)


class FinishInvestigationRelationEvidence(StrictModel):
    """Cite a relation or its properties supporting a benign verdict."""

    anchor: Literal["relation"]
    relation_id: str
    property_fields: list[PropertyFieldName] = Field(default_factory=list)


FinishInvestigationLegitimacyEvidence = Annotated[
    FinishInvestigationEntityEvidence | FinishInvestigationRelationEvidence,
    Field(discriminator="anchor"),
]


class MaliciousFinishInvestigationSubmission(StrictModel):
    """Submit a malicious verdict with incident-response artifacts."""

    verdict: Literal["malicious"]
    ir_artifacts: list[FinishInvestigationArtifact]
    reasoning: str


class BenignFinishInvestigationSubmission(StrictModel):
    """Submit a benign verdict with observable legitimacy evidence."""

    verdict: Literal["benign"]
    legitimacy_evidence: list[FinishInvestigationLegitimacyEvidence]
    reasoning: str


FinishInvestigationSubmission = Annotated[
    MaliciousFinishInvestigationSubmission | BenignFinishInvestigationSubmission,
    Field(discriminator="verdict"),
]


class FinishInvestigationArguments(StrictModel):
    """Submit the final BlueSec1 verdict and discovered response artifacts."""

    submission: FinishInvestigationSubmission


# Argument schemas of the practice tools. The step schema uses one only when
# the catalog entry of a tool with this name carries no usable schema of its own.
PRACTICE_ARGUMENT_MODELS: dict[str, type[BaseModel]] = {
    "search": SearchArguments,
    "get_entity": GetEntityArguments,
    "get_relation": GetRelationArguments,
    "get_ad_object_info": GetADObjectInfoArguments,
    "finish_investigation": FinishInvestigationArguments,
}


class ToolCall(BaseModel):
    """One tool call: the tool name and its arguments as sibling keys."""

    model_config = ConfigDict(extra="allow")

    tool: str = Field(min_length=1)

    @property
    def arguments(self) -> dict[str, Any]:
        """Return the arguments without the null values of omitted optional fields."""
        return _drop_nulls(self.model_extra or {})


class StepEnvelope(StrictModel):
    """Reasoning fields of a step, shared by every tool catalog.

    Envelope keys the agent does not read, such as a `task_completed` left over
    from older contracts, are dropped instead of failing the step (ADR 0009);
    the step schema still closes the envelope.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    current_state: str
    plan_remaining_steps_brief: list[str] = Field(min_length=1, max_length=5)


class NextStep(StepEnvelope):
    """One validated reasoning-and-action turn produced by the LLM."""

    function: ToolCall = Field(description="Execute the first remaining step.")


class ChallengeCheck(BaseModel):
    """One call that would refute the challenger's attack hypothesis."""

    model_config = ConfigDict(extra="ignore")

    refuted_if: str = Field(min_length=1, description="The result that refutes the hypothesis.")
    call: ToolCall = Field(description="The tool call that checks it.")


class Challenge(BaseModel):
    """The challenger's case against a benign verdict (ADR 0022)."""

    model_config = ConfigDict(extra="ignore")

    hypothesis: str = Field(
        min_length=1, description="The strongest attack reading of the same evidence."
    )
    checks: list[ChallengeCheck] = Field(min_length=1, max_length=3)


def _drop_nulls(value: Any) -> Any:
    """Remove `None` values from dicts at every depth.

    Strict schemas make optional fields required and nullable, so the model
    sends `null` for every argument it leaves out.
    """
    if isinstance(value, dict):
        return {key: _drop_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_nulls(item) for item in value]
    return value


def normalize_time_windows(arguments: dict[str, Any]) -> dict[str, Any]:
    """Check and normalize every `time_window` argument at any depth.

    A calendar day becomes the whole UTC day: `from` its first and `to` its
    last microsecond. A timestamp must carry its timezone and is converted
    to UTC. The window must not be inverted.

    Args:
        arguments: Tool arguments without nulls.

    Returns:
        A copy with each `{"from": ..., "to": ...}` window normalized.

    Raises:
        ValueError: If a boundary is malformed or the window is inverted.
    """

    def walk(value: Any, key: str | None = None) -> Any:
        if isinstance(value, list):
            return [walk(item) for item in value]
        if not isinstance(value, dict):
            return value
        if key == "time_window":
            lower = value.get("from")
            upper = value.get("to")
            window = dict(value)
            if isinstance(lower, str):
                window["from"] = _parse_time_boundary(lower, upper=False)
            if isinstance(upper, str):
                window["to"] = _parse_time_boundary(upper, upper=True)
            if isinstance(lower, str) and isinstance(upper, str) and window["from"] > window["to"]:
                raise ValueError("time_window.from must be before or equal to time_window.to")
            return {
                name: _format_utc(item) if isinstance(item, datetime) else item
                for name, item in window.items()
            }
        return {name: walk(item, name) for name, item in value.items()}

    return walk(arguments)


def _parse_time_boundary(value: str, *, upper: bool) -> datetime:
    """Parse a timezone-aware search boundary or an inclusive UTC calendar day."""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        day = datetime.fromisoformat(value).replace(tzinfo=UTC)
        return day.replace(hour=23, minute=59, second=59, microsecond=999999) if upper else day
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ):
        raise ValueError(
            f"time_window boundary {value!r} must include a timezone or be a calendar day"
        )
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _format_utc(value: datetime) -> str:
    """Format a UTC datetime the way the practice runtime accepted it."""
    return value.isoformat().replace("+00:00", "Z")
