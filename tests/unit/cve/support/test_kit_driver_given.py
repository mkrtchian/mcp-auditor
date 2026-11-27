from collections.abc import Mapping
from typing import Any

from evals.cve.kit.client import KitResponse, KitTool
from evals.cve.kit.driver import Exchange, PatchedExploits
from evals.cve.planting import RANDOM_NONCES, PlantingSpec
from tests.unit.support.fictional_planting import account_place, spec_of, unprivileged_host

_HOST = unprivileged_host(working_directory="/")


def a_spec() -> PlantingSpec:
    return spec_of([], _HOST, RANDOM_NONCES)


def a_spec_with_an_account() -> PlantingSpec:
    return spec_of([account_place()], _HOST, RANDOM_NONCES)


def options_running_as(*user_options: str) -> list[str]:
    return ["run", "-i", "--rm", "--cap-drop", "ALL", *user_options, "-e", "HOME=/tmp"]


def a_tool(name: str, required: list[str] | None = None) -> KitTool:
    schema: dict[str, object] = {"type": "object", "properties": {}}
    if required is not None:
        schema["required"] = required
    return KitTool(name=name, description=None, input_schema=schema)


# The SDKs' own argument-validation errors: the pydantic and TypeScript ones as the patched versions
# answered them on 2026-11-27, the low-level Python server's as mcp 1.30.0 words it.
PYTHON_REJECTION = KitResponse(
    "Error executing tool process_natural_language: 1 validation error for"
    " process_natural_languageArguments\nquery\n  Field required [type=missing]",
    is_error=True,
)
TYPESCRIPT_REJECTION = KitResponse(
    "MCP error -32602: Input validation error: Invalid arguments for tool git_clone: Invalid"
    " input: expected string, received undefined at url",
    is_error=True,
)
PYTHON_LOWLEVEL_REJECTION = KitResponse(
    "Input validation error: 'url' is a required property", is_error=True
)
REACHED = KitResponse("Command failed: kubectl get pods; id -n default", is_error=True)


def a_call(tool: str, arguments: dict[str, Any], response: KitResponse) -> Exchange:
    return (tool, arguments, response)


def patched(*exploits: list[Exchange], required: Mapping[str, frozenset[str]]) -> PatchedExploits:
    """The exploits played on a patched version whose tools/list requires `required`."""
    return PatchedExploits("patched", list(exploits), dict(required))
