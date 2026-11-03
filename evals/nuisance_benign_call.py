"""The benign call check of an admitted server on its patched image (rule v3, The benign call):
every counted tool and every prerequisite tool is in the server's `tools/list`, each prerequisite
call returns without error, and each counted tool's benign call returns without error and, when
the admission records an expected text, with that text in its response."""

from evals.nuisance_admission import AdmittedServer, BenignCall, ToolCall
from evals.nuisance_counting import counted_flaws, counted_tools
from mcp_auditor.domain.ports import MCPClientPort

_NOT_LISTED = "is not in the server's tools/list"


async def benign_call_failure(server: AdmittedServer, mcp_client: MCPClientPort) -> str | None:
    calls = benign_calls(server)
    failure = await _listing_failure(mcp_client, calls)
    if failure is not None:
        return failure
    for tool, call in calls.items():
        failure = await _chain_failure(mcp_client, tool, call)
        if failure is not None:
            return failure
    return None


def benign_calls(server: AdmittedServer) -> dict[str, BenignCall]:
    """One benign call per counted tool, the first in counted-flaw order (the load check refuses
    two different calls for one tool across the counted flaws)."""
    counted = counted_tools(server)
    calls: dict[str, BenignCall] = {}
    for flaw in counted_flaws(server):
        for call in flaw.benign_calls:
            if call.tool in counted:
                calls.setdefault(call.tool, call)
    return calls


async def _listing_failure(mcp_client: MCPClientPort, calls: dict[str, BenignCall]) -> str | None:
    try:
        listed = {tool.name for tool in await mcp_client.list_tools()}
    except Exception as exc:
        return f"listing the server's tools failed: {exc}"
    for tool, call in calls.items():
        if tool not in listed:
            return f"counted tool {tool!r} {_NOT_LISTED}"
        for prior in call.before or []:
            if prior.tool not in listed:
                return f"prerequisite tool {prior.tool!r} of {tool!r} {_NOT_LISTED}"
    return None


async def _chain_failure(mcp_client: MCPClientPort, tool: str, call: BenignCall) -> str | None:
    for prior in call.before or []:
        label = f"prerequisite call of {prior.tool!r} before {tool!r}"
        failure = await _call_failure(mcp_client, prior, label)
        if failure is not None:
            return failure
    try:
        response = await mcp_client.call_tool(tool, call.arguments)
    except Exception as exc:
        return f"benign call of {tool!r} failed: {exc}"
    if response.is_error:
        return f"benign call of {tool!r} returned an error: {response.content}"
    return _expectation_failure(call, response.content)


async def _call_failure(mcp_client: MCPClientPort, call: ToolCall, label: str) -> str | None:
    try:
        response = await mcp_client.call_tool(call.tool, call.arguments)
    except Exception as exc:
        return f"{label} failed: {exc}"
    if response.is_error:
        return f"{label} returned an error: {response.content}"
    return None


def _expectation_failure(call: BenignCall, content: str) -> str | None:
    if call.expect is None:
        return None
    if not content:
        return f"benign call of {call.tool!r} returned no text"
    if call.expect not in content:
        return f"benign call of {call.tool!r} did not return {call.expect!r}: {content}"
    return None
