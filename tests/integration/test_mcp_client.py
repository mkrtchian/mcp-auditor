import pathlib

from mcp_auditor.adapters.mcp_client import StdioMCPClient

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "dummy_server.py"
CONNECT_ARGS = ("uv", ["run", "python", str(SERVER_PATH)])


# -- Discovery --


async def test_discovers_three_tools() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        tools = await client.list_tools()

    assert len(tools) == 3
    assert {t.name for t in tools} == {"get_user", "execute_query", "list_items"}


async def test_tool_schemas_have_required_fields() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        tools = await client.list_tools()

    for tool in tools:
        assert tool.name
        assert tool.description
        assert isinstance(tool.input_schema, dict)
        assert "properties" in tool.input_schema


# -- Happy paths --


async def test_get_user_valid_id() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("get_user", {"user_id": 42})

    assert response.is_error is False
    assert "Alice" in response.content


async def test_execute_query_simple() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("execute_query", {"query": "SELECT 1"})

    assert response.is_error is False


async def test_list_items_valid_category() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("list_items", {"category": "books"})

    assert response.is_error is False
    assert "book" in response.content


# -- Error paths --


async def test_get_user_negative_id_leaks_info() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("get_user", {"user_id": -1})

    assert response.is_error is True
    assert "/opt/mcp-server/" in response.content


async def test_execute_query_echoes_input() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("execute_query", {"query": "DROP TABLE users"})

    assert "DROP TABLE users" in response.content


async def test_list_items_rejects_invalid_category() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("list_items", {"category": "weapons"})

    assert response.is_error is True
    assert "/opt/" not in response.content


async def test_list_items_clamps_limit() -> None:
    async with StdioMCPClient.connect(*CONNECT_ARGS) as client:
        response = await client.call_tool("list_items", {"category": "books", "limit": 9999})

    assert response.is_error is False
