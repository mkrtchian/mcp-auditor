import pathlib

from mcp_auditor.adapters.mcp_client import StdioMCPClient

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "subtle_server.py"
CONNECT_ARGS = ("uv", ["run", "python", str(SERVER_PATH)])


class TestDiscovery:
    async def test_discovers_three_tools(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            tools = await client.list_tools()

        assert len(tools) == 3
        assert {t.name for t in tools} == {"search_users", "delete_record", "get_service_status"}


class TestSearchUsers:
    async def test_search_users_leaks_pii(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool("search_users", {"query": "Alice"})

        assert response.is_error is False
        assert "email=" in response.content
        assert "role=" in response.content


class TestDeleteRecord:
    async def test_delete_record_accepts_negative_id(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool("delete_record", {"record_id": -5})

        assert response.is_error is False


class TestGetServiceStatus:
    async def test_get_service_status_rejects_unknown(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool("get_service_status", {"service": "secret"})

        assert response.is_error is True

    async def test_get_service_status_valid(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool("get_service_status", {"service": "api"})

        assert response.is_error is False
        assert "healthy" in response.content
