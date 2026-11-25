import pytest

from mcp_auditor.adapters.mcp_client import StdioMCPClient
from tests.integration.support.support_servers import a_paginated_server


class TestPagination:
    async def test_lists_the_tools_of_every_page(self) -> None:
        async with StdioMCPClient.connect(a_paginated_server()) as client:
            tools = await client.list_tools()

        assert [t.name for t in tools] == ["tool_1", "tool_2", "tool_3", "tool_4", "tool_5"]

    async def test_validates_structured_content_of_a_later_page(self) -> None:
        async with StdioMCPClient.connect(a_paginated_server()) as client:
            await client.list_tools()
            response = await client.call_tool("tool_5", {})

        assert response.is_error is True
        assert response.error_type == "RuntimeError"

    async def test_a_repeated_cursor_raises(self) -> None:
        async with StdioMCPClient.connect(a_paginated_server("--repeat-cursor")) as client:
            with pytest.raises(RuntimeError, match="already returned: 1"):
                await client.list_tools()
