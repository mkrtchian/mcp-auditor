import pathlib
from typing import Any

import pytest

from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "honeypot_server.py"
LAUNCH = ServerLaunch.unconfined("uv", ["run", "python", str(SERVER_PATH)])


class TestDiscovery:
    async def test_discovers_three_tools(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            tools = await client.list_tools()

        assert len(tools) == 3
        assert {t.name for t in tools} == {"get_user", "execute_query", "list_items"}

    async def test_tool_schemas_have_required_fields(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            tools = await client.list_tools()

        for tool in tools:
            assert tool.name
            assert tool.description
            assert isinstance(tool.input_schema, dict)
            assert "properties" in tool.input_schema

    async def test_list_items_publishes_a_plain_integer_limit(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            tools = await client.list_tools()

        list_items = next(t for t in tools if t.name == "list_items")
        assert list_items.input_schema["properties"]["limit"] == {
            "default": 10,
            "title": "Limit",
            "type": "integer",
        }


class TestHappyPaths:
    async def test_get_user_valid_id(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {"user_id": 42})

        assert response.is_error is False
        assert "Alice" in response.content

    async def test_execute_query_simple(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("execute_query", {"query": "SELECT 1"})

        assert response.is_error is False

    async def test_list_items_valid_category(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("list_items", {"category": "books"})

        assert response.is_error is False
        assert "book" in response.content


class TestErrorPaths:
    async def test_get_user_negative_id_leaks_info(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {"user_id": -1})

        assert response.is_error is True
        assert "/opt/mcp-server/" in response.content

    async def test_execute_query_echoes_input(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("execute_query", {"query": "DROP TABLE users"})

        assert "DROP TABLE users" in response.content

    async def test_list_items_rejects_invalid_category(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("list_items", {"category": "weapons"})

        assert response.is_error is True
        assert "/opt/" not in response.content

    async def test_list_items_clamps_limit(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("list_items", {"category": "books", "limit": 9999})

        assert response.is_error is False
        assert "showing 100" in response.content

    async def test_get_user_unknown_id_raises_its_planted_error(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {"user_id": 0})

        assert response.is_error is True
        assert response.content == "Error executing tool get_user: 0"


class TestInvalidArguments:
    async def test_get_user_wrong_type_returns_a_generic_error(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {"user_id": "abc"})

        assert response.is_error is True
        assert response.content == "Error executing tool get_user: Invalid arguments"
        assert "validation error" not in response.content
        assert "pydantic" not in response.content

    async def test_get_user_missing_argument_returns_a_generic_error(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {})

        assert response.is_error is True
        assert response.content == "Error executing tool get_user: Invalid arguments"

    @pytest.mark.parametrize("limit", [True, "42"])
    async def test_list_items_refuses_a_non_integer_limit(self, limit: Any) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("list_items", {"category": "books", "limit": limit})

        assert response.is_error is True
        assert response.content == "Error executing tool list_items: Invalid arguments"
