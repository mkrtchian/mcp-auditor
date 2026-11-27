from collections.abc import Mapping

from evals.cve.kit.argument_validation import PatchedExploits
from evals.cve.kit.client import KitResponse, KitTool
from evals.cve.kit.driver import Exchange


def a_tool(name: str, required: list[str] | None = None) -> KitTool:
    schema: dict[str, object] = {"type": "object", "properties": {}}
    if required is not None:
        schema["required"] = required
    return KitTool(name=name, description=None, input_schema=schema)


# The SDKs' own argument-validation errors: the pydantic and TypeScript ones as the patched versions
# answered them on 2026-11-27, the low-level Python server's as mcp 1.30.0 words it, and the
# TypeScript SDK's up to 1.20.0, which carries no "Input validation error".
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
OLD_TYPESCRIPT_REJECTION = KitResponse(
    "MCP error -32602: Invalid arguments for tool git_clone: Required at url", is_error=True
)
PYTHON_LOWLEVEL_REJECTION = KitResponse(
    "Input validation error: 'url' is a required property", is_error=True
)
REACHED = KitResponse("Command failed: kubectl get pods; id -n default", is_error=True)


def patched(*exploits: list[Exchange], required: Mapping[str, frozenset[str]]) -> PatchedExploits:
    """The exploits played on a patched version whose tools/list requires `required`."""
    return PatchedExploits("patched", list(exploits), dict(required))
