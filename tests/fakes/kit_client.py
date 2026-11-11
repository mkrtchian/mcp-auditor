from collections.abc import Mapping, Sequence
from typing import Any

from evals.cve.kit.client import KitResponse, KitTool


class FakeKitClient:
    def __init__(
        self,
        tools: Sequence[KitTool] = (),
        responses: Mapping[str, KitResponse] | None = None,
    ):
        self._tools = list(tools)
        self._responses = dict(responses or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[KitTool]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append((name, args))
        return self._responses.get(name, KitResponse("", is_error=False))
