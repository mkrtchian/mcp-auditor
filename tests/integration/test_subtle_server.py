import pathlib

from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "subtle_server.py"


# Not a pytest fixture on purpose: the MCP SDK's anyio cancel scopes must be
# entered and exited in the same task, and pytest-asyncio runs fixture
# setup/teardown in separate tasks. The async with stays in the test body.
def connected_subtle_server():
    launch = ServerLaunch.unconfined("uv", ["run", "python", str(SERVER_PATH)])
    return StdioMCPClient.connect(launch)


class TestDiscovery:
    async def test_discovers_three_tools(self) -> None:
        async with connected_subtle_server() as client:
            tools = await client.list_tools()

        assert len(tools) == 3
        assert {t.name for t in tools} == {"search_users", "delete_record", "get_service_status"}


class TestSearchUsers:
    async def test_search_users_leaks_pii(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("search_users", {"query": "Alice"})

        assert response.is_error is False
        assert "email=" in response.content
        assert "role=" in response.content

    async def test_search_users_refuses_a_boolean_limit(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("search_users", {"query": "Alice", "limit": True})

        assert response.is_error is True
        assert response.content == "Error executing tool search_users: Invalid arguments"


class TestDeleteRecord:
    async def test_delete_record_accepts_negative_id(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("delete_record", {"record_id": -5})

        assert response.is_error is False

    async def test_delete_record_wrong_type_returns_a_generic_error(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("delete_record", {"record_id": "abc"})

        assert response.is_error is True
        assert response.content == "Error executing tool delete_record: Invalid arguments"


class TestGetServiceStatus:
    async def test_get_service_status_rejects_unknown(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("get_service_status", {"service": "secret"})

        assert response.is_error is True

    async def test_get_service_status_valid(self) -> None:
        async with connected_subtle_server() as client:
            response = await client.call_tool("get_service_status", {"service": "api"})

        assert response.is_error is False
        assert "healthy" in response.content
