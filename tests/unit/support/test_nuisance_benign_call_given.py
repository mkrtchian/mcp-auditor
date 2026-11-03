from typing import Any

from evals.cve_grammar import MechanismClass
from evals.nuisance_admission import AdmittedServer, ToolCall
from mcp_auditor.domain import ToolDefinition, ToolResponse
from tests.fakes.mcp_client import FakeMCPClient
from tests.unit.support.test_nuisance_admission_given import (
    FIRST_FLAW,
    SECOND_FLAW,
    a_flaw_record,
    a_server,
)

SERVER = a_server(
    [
        a_flaw_record(FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, "1.2.0"),
        a_flaw_record(SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, "1.2.0"),
    ]
)
FIRST_TOOL = f"{FIRST_FLAW}_read"
SECOND_TOOL = f"{SECOND_FLAW}_read"
PREREQUISITE_TOOL = "connect_to_database"


def expected_text(tool: str) -> str:
    return f"{tool} answered"


def a_listing_client(
    tools: list[str] | None = None, responses: dict[str, ToolResponse] | None = None
) -> FakeMCPClient:
    """Lists `tools` (both counted tools by default) and answers each counted tool with a text
    holding its expected text, unless `responses` says otherwise."""
    listed = [FIRST_TOOL, SECOND_TOOL] if tools is None else tools
    answers = {tool: ToolResponse(content=f"{expected_text(tool)}.") for tool in listed}
    return FakeMCPClient(_definitions(listed), answers | (responses or {}))


def with_first_call(server: AdmittedServer, **update: Any) -> AdmittedServer:
    first, *rest = server.flaws
    call = first.benign_calls[0].model_copy(update=update)
    moved = first.model_copy(update={"benign_calls": [call]})
    return server.model_copy(update={"flaws": [moved, *rest]})


def with_a_prerequisite(server: AdmittedServer) -> AdmittedServer:
    return with_first_call(server, before=[ToolCall(tool=PREREQUISITE_TOOL, arguments={})])


class RaisingClient(FakeMCPClient):
    def __init__(self, failing_tool: str) -> None:
        super().__init__(_definitions([FIRST_TOOL, SECOND_TOOL]))
        self._failing_tool = failing_tool

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if name == self._failing_tool:
            raise RuntimeError("connection closed")
        return ToolResponse(content=f"{expected_text(name)}.")


class ListingRaisingClient(FakeMCPClient):
    def __init__(self) -> None:
        super().__init__([])

    async def list_tools(self) -> list[ToolDefinition]:
        raise RuntimeError("listing timed out")


class ConnectingClient(FakeMCPClient):
    """A server whose first counted tool answers its expected text only once the prerequisite
    tool ran, and an error text without an error flag before, as awslabs-mysql does."""

    def __init__(self) -> None:
        super().__init__(_definitions([FIRST_TOOL, SECOND_TOOL, PREREQUISITE_TOOL]))
        self._connected = False

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        self.calls.append((name, args))
        if name == PREREQUISITE_TOOL:
            self._connected = True
            return ToolResponse(content="connected")
        if name == FIRST_TOOL and not self._connected:
            return ToolResponse(content='{"error": "No database connection available"}')
        return ToolResponse(content=f"{expected_text(name)}.")


def _definitions(names: list[str]) -> list[ToolDefinition]:
    return [ToolDefinition(name=name, input_schema={}) for name in names]
