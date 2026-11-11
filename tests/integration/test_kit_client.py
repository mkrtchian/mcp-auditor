import sys

import pytest

from evals.cve.kit.client import KitMCPClient
from tests.integration.support.test_mcp_client_given import PAGINATED_SERVER_PATH
from tests.integration.support.test_mcp_client_transport_given import READ_SERVER_PATH


async def test_a_server_logging_its_shutdown_to_stdout_is_left_cleanly() -> None:
    command = [str(READ_SERVER_PATH), "noisy_shutdown"]
    async with KitMCPClient.connect(sys.executable, command) as client:
        response = await client.call_tool("read", {"path": "/any"})

    assert response.content == "ok"


async def test_lists_the_tools_of_every_page() -> None:
    async with KitMCPClient.connect(sys.executable, [str(PAGINATED_SERVER_PATH)]) as client:
        tools = await client.list_tools()

    assert [tool.name for tool in tools] == ["tool_1", "tool_2", "tool_3", "tool_4", "tool_5"]


async def test_a_repeated_cursor_raises() -> None:
    arguments = [str(PAGINATED_SERVER_PATH), "--repeat-cursor"]
    async with KitMCPClient.connect(sys.executable, arguments) as client:
        with pytest.raises(RuntimeError, match="already returned: 1"):
            await client.list_tools()
