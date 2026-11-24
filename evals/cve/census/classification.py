from collections.abc import Iterable
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


# The census's grammar classes, as given to the classifiers (evals/census_method.md, reading 4)
# and recorded at the rule's commit (docs/detection-suite-log.md, 2026-10-07). Frozen with the
# census: a grammar change does not change them.
GRAMMAR_CLASSES = ("read_outside_scope", "command_execution", "internal_fetch")

# Written from the docstring of evals/cve/grammar.py, which stays untouched.
GRAMMAR_CLASS_DEFINITIONS = """\
- `read_outside_scope`: the server reads data outside the scope it declares, such as a file
  outside the directories it allows, and returns it.
- `command_execution`: the server executes a command of the caller's choice.
- `internal_fetch`: the server fetches an internal address of the caller's choice and returns
  what it got.
"""

CENSUS_GRAMMAR_CLASSES = f"""\
# The effect classes of the grammar

A class names the effect a client of the server can observe in a tool response, not a CWE.
An argument injection is filed under the effect it produces. A flaw whose effect falls in
none of these three classes gets a class name of your own.

{GRAMMAR_CLASS_DEFINITIONS}"""


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


def met_by_either_classifier(
    classifications: Iterable[Classification], criterion: Criterion
) -> bool:
    return any(criteria_met(classification)[criterion] for classification in classifications)


def criteria_met(classification: Classification) -> dict[Criterion, bool]:
    # A server may still fail criterion 1 (no tools, no public package), so only the
    # classifier's first failed criterion tells whether it is met.
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


def in_grammar(name: str) -> bool:
    return normalized_class(name) in GRAMMAR_CLASSES


def normalized_class(name: str) -> str:
    return " ".join(name.split()).casefold()
