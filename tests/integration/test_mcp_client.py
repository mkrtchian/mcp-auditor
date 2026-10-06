import pathlib
import time
from typing import Any

import pytest

from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent / "honeypot_server.py"
LAUNCH = ServerLaunch.unconfined("uv", ["run", "python", str(SERVER_PATH)])
CONFIG_PATH = "/opt/mcp-server/config/database.yml"
FORMED_ERROR = f"[db: {CONFIG_PATH}] Invalid query: the search did not run"
LONE_QUOTE = "'"
SEVERAL_STATEMENTS = "'; DROP TABLE products; --"
ENDLESS_RECURSION = (
    "' UNION SELECT 1, (WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) "
    "SELECT count(*) FROM r), 2 --"
)
HUGE_BLOB = "' UNION SELECT 1, zeroblob(100000000), 2 --"
CROSS_JOIN = (
    "' UNION SELECT a.id, b.name, c.price "
    "FROM products a, products b, products c, products d, products e --"
)


class TestDiscovery:
    async def test_discovers_three_tools(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            tools = await client.list_tools()

        assert len(tools) == 3
        assert {t.name for t in tools} == {"get_user", "search_products", "list_items"}

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

    async def test_search_products_publishes_a_catalog_search(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            tools = await client.list_tools()

        search_products = next(t for t in tools if t.name == "search_products")
        assert search_products.description == (
            "Search the product catalog: returns the listed products whose name contains the query."
        )
        assert search_products.input_schema["properties"]["query"]["type"] == "string"
        assert search_products.input_schema["required"] == ["query"]


class TestHappyPaths:
    async def test_get_user_valid_id(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("get_user", {"user_id": 42})

        assert response.is_error is False
        assert "Alice" in response.content

    async def test_search_products_finds_a_listed_product(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("search_products", {"query": "lamp"})

        assert response.is_error is False
        assert "1 rows" in response.content
        assert "Desk lamp" in response.content
        assert CONFIG_PATH in response.content

    async def test_search_products_searches_sql_as_a_name(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("search_products", {"query": "SELECT 1"})

        assert response.is_error is False
        assert "0 rows" in response.content

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


class TestSearchProductsInjection:
    async def test_a_tautology_returns_the_unlisted_products(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("search_products", {"query": "' OR 1=1 --"})

        assert response.is_error is False
        assert "5 rows" in response.content
        assert "Unreleased headset" in response.content

    async def test_a_union_returns_a_chosen_value(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool(
                "search_products", {"query": "' UNION SELECT 1,'mcp-auditor-probe',2 --"}
            )

        assert response.is_error is False
        assert "mcp-auditor-probe" in response.content

    async def test_a_cross_join_returns_a_bounded_response(self) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("search_products", {"query": CROSS_JOIN})

        assert response.is_error is False
        assert int(response.content.split(" rows:")[0].split()[-1]) <= 20
        assert len(response.content) < 2_100


class TestSearchProductsRefusals:
    @pytest.mark.parametrize("query", ["", "   "])
    async def test_refuses_an_empty_query(self, query: str) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            response = await client.call_tool("search_products", {"query": query})

        assert response.is_error is True
        assert response.content == "Error executing tool search_products: query must not be empty"

    @pytest.mark.parametrize(
        "query", [LONE_QUOTE, SEVERAL_STATEMENTS, ENDLESS_RECURSION, HUGE_BLOB]
    )
    async def test_a_statement_that_cannot_run_gets_one_formed_error(self, query: str) -> None:
        async with StdioMCPClient.connect(LAUNCH) as client:
            started = time.monotonic()
            response = await client.call_tool("search_products", {"query": query})
            elapsed = time.monotonic() - started

        assert response.is_error is True
        assert response.content == f"Error executing tool search_products: {FORMED_ERROR}"
        assert elapsed < 5


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
