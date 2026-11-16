from collections.abc import Mapping, Sequence
from typing import Any

from mcp_auditor.domain import ToolDefinition, ToolResponse


class FakeMCPClient:
    """Each tool answers its scripted responses in order, the last one repeated, and "ok" when
    it has none. The ping and the relaunch answer their scripted answers the same way."""

    def __init__(
        self,
        tools: list[ToolDefinition],
        responses: Mapping[str, ToolResponse | Sequence[ToolResponse]] | None = None,
        *,
        ping_answers: Sequence[bool] = (True,),
        relaunch_answers: Sequence[bool] = (True,),
    ):
        self._tools = tools
        self._responses = {
            name: [scripted] if isinstance(scripted, ToolResponse) else list(scripted)
            for name, scripted in (responses or {}).items()
        }
        self._ping_answers = list(ping_answers)
        self._relaunch_answers = list(relaunch_answers)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.pings = 0
        self.relaunches = 0

    async def list_tools(self) -> list[ToolDefinition]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        self.calls.append((name, args))
        if name in self._responses:
            return _next(self._responses[name])
        return ToolResponse(content="ok")

    async def ping(self) -> bool:
        self.pings += 1
        return _next(self._ping_answers)

    async def relaunch(self) -> bool:
        self.relaunches += 1
        return _next(self._relaunch_answers)


def a_timeout_response(tool_call_timeout: int = 60) -> ToolResponse:
    return ToolResponse(
        content=f"Tool call timed out after {tool_call_timeout}s",
        is_error=True,
        error_type="TimeoutError",
    )


def a_lost_connection_response() -> ToolResponse:
    return ToolResponse(content="Connection closed", is_error=True, error_type="McpError")


def _next[T](answers: list[T]) -> T:
    return answers.pop(0) if len(answers) > 1 else answers[0]
