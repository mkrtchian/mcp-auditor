from datetime import date
from enum import StrEnum

from pydantic import BaseModel


class SoftwareKind(StrEnum):
    SERVER = "server"
    CLIENT = "client"
    HOST = "host"
    INSPECTOR = "inspector"
    REGISTRY = "registry"
    SDK = "sdk"
    OTHER = "other"


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"
    STDIO_AND_HTTP = "stdio_and_http"
    NONE = "none"


class Primitive(StrEnum):
    TOOLS = "tools"
    RESOURCES = "resources"
    PROMPTS = "prompts"
    SAMPLING = "sampling"
    ROOTS = "roots"
    ELICITATION = "elicitation"
    TRANSPORT_LAYER = "transport_layer"
    NONE = "none"


class Criterion(StrEnum):
    MCP_SERVER = "mcp_server"
    STDIO_TOOLS_CALL = "stdio_tools_call"
    EFFECT_IN_TOOL_RESPONSE = "effect_in_tool_response"
    GRAMMAR_CLASS = "grammar_class"
    PINNABLE = "pinnable"


GRAMMAR_CLASSES = ("read_outside_scope", "command_execution", "internal_fetch")


class Classification(BaseModel):
    flaw: str
    software_kind: SoftwareKind
    server_package: str
    affected_versions: str
    vulnerable_version: str | None
    first_patched_version: str | None
    pinnable: bool
    disclosure_date: date
    transport: Transport
    primitive: Primitive
    effect_in_tool_response: bool
    runs_in_container: bool
    effect_class: str
    first_failed_criterion: Criterion | None


def criteria_met(classification: Classification) -> dict[Criterion, bool]:
    # A server may still fail criterion 1 (no tools, no public package), so only the
    # classifier's verdict tells whether it is met.
    return _read_from_fields(classification) | {
        Criterion.MCP_SERVER: classification.first_failed_criterion != Criterion.MCP_SERVER
    }


def is_consistent(classification: Classification) -> bool:
    met = _read_from_fields(classification)
    failed = classification.first_failed_criterion
    if failed is None:
        return all(met.values())
    earlier = list(Criterion)[: list(Criterion).index(failed)]
    if not all(met[criterion] for criterion in earlier):
        return False
    return failed == Criterion.MCP_SERVER or not met[failed]


def normalized_class(name: str) -> str:
    return " ".join(name.split()).casefold()


def in_grammar(name: str) -> bool:
    return normalized_class(name) in GRAMMAR_CLASSES


def _read_from_fields(classification: Classification) -> dict[Criterion, bool]:
    return {
        Criterion.MCP_SERVER: classification.software_kind == SoftwareKind.SERVER,
        Criterion.STDIO_TOOLS_CALL: (
            classification.transport in (Transport.STDIO, Transport.STDIO_AND_HTTP)
            and classification.primitive == Primitive.TOOLS
        ),
        Criterion.EFFECT_IN_TOOL_RESPONSE: classification.effect_in_tool_response,
        Criterion.GRAMMAR_CLASS: in_grammar(classification.effect_class),
        Criterion.PINNABLE: classification.pinnable,
    }
