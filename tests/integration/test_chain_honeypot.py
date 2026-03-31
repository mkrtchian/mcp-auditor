import json
import pathlib

from mcp_auditor.adapters.mcp_client import StdioMCPClient

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "chain_honeypot_server.py"
CONNECT_ARGS = ("uv", ["run", "python", str(SERVER_PATH)])


class TestDiscovery:
    async def test_discovers_two_tools(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            tools = await client.list_tools()

        assert len(tools) == 2
        assert {t.name for t in tools} == {"project_manager", "user_directory"}


class TestProjectManagerChain:
    async def test_list_returns_project_ids_including_secret(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool("project_manager", {"action": "list"})

        assert response.is_error is False
        project_ids = json.loads(response.content)
        assert "proj_secret_admin" in project_ids

    async def test_details_for_secret_project_reveals_internal_path(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "project_manager",
                {"action": "details", "project_id": "proj_secret_admin"},
            )

        assert response.is_error is False
        details = json.loads(response.content)
        assert "internal_path" in details
        assert details["internal_path"] == "/data/admin/config.yaml"

    async def test_read_file_at_admin_path_returns_sensitive_config(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "project_manager",
                {"action": "read_file", "path": "/data/admin/config.yaml"},
            )

        assert response.is_error is False
        config = json.loads(response.content)
        assert "api_keys" in config
        assert "database" in config


class TestUserDirectoryChain:
    async def test_search_admin_returns_user_ids(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "user_directory", {"action": "search", "query": "admin"}
            )

        assert response.is_error is False
        user_ids = json.loads(response.content)
        assert "user_42" in user_ids

    async def test_profile_for_admin_reveals_role(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "user_directory", {"action": "profile", "user_id": "user_42"}
            )

        assert response.is_error is False
        profile = json.loads(response.content)
        assert profile["role"] == "admin"
        assert "auth_token_prefix" in profile

    async def test_get_field_auth_token_for_admin_returns_token(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "user_directory",
                {"action": "get_field", "user_id": "user_42", "field": "auth_token"},
            )

        assert response.is_error is False
        assert "sk-admin-7f3a9b2c" in response.content

    async def test_get_field_auth_token_for_non_admin_is_denied(self) -> None:
        async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
            response = await client.call_tool(
                "user_directory",
                {"action": "get_field", "user_id": "user_10", "field": "auth_token"},
            )

        assert response.is_error is True
