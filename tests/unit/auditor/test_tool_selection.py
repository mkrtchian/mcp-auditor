import pytest

from mcp_auditor.domain.tool_selection import filter_tools, order_tools_for_audit
from tests.unit.auditor.support.graph_builders import a_tool


class TestFilterTools:
    def test_filters_tools_by_name(self):
        tools = [a_tool(name="a"), a_tool(name="b"), a_tool(name="c")]

        result = filter_tools(tools, frozenset({"a", "c"}))

        assert [t.name for t in result] == ["a", "c"]

    def test_raises_on_unknown_tool_name(self):
        tools = [a_tool(name="a"), a_tool(name="b")]

        with pytest.raises(ValueError, match="unknown"):
            filter_tools(tools, frozenset({"a", "unknown"}))

    def test_no_filter_returns_all(self):
        tools = [a_tool(name="a"), a_tool(name="b")]

        result = filter_tools(tools, None)

        assert [t.name for t in result] == ["a", "b"]

    def test_preserves_server_order(self):
        tools = [a_tool(name="c"), a_tool(name="a"), a_tool(name="b")]

        result = filter_tools(tools, frozenset({"b", "c"}))

        assert [t.name for t in result] == ["c", "b"]


class TestOrderToolsForAudit:
    def test_read_like_tools_sort_before_others(self):
        tools = [
            a_tool(name="delete_user"),
            a_tool(name="get_user"),
            a_tool(name="list_items"),
        ]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["get_user", "list_items", "delete_user"]

    def test_ties_broken_by_parameter_count(self):
        three_params = a_tool(
            name="get_details",
            input_schema={
                "type": "object",
                "properties": {"a": {}, "b": {}, "c": {}},
            },
        )
        one_param = a_tool(
            name="get_summary",
            input_schema={"type": "object", "properties": {"a": {}}},
        )

        result = order_tools_for_audit([three_params, one_param])

        assert [t.name for t in result] == ["get_summary", "get_details"]

    def test_stable_within_same_group(self):
        tools = [a_tool(name="create_x"), a_tool(name="update_y")]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["create_x", "update_y"]

    def test_empty_list(self):
        assert order_tools_for_audit([]) == []

    def test_all_read_prefixes_recognized(self):
        prefixes = [
            "get_",
            "list_",
            "read_",
            "search_",
            "find_",
            "fetch_",
            "show_",
            "describe_",
            "check_",
        ]
        # delete_thing goes first: a prefix that stopped being recognized would tie with it,
        # and the stable sort would keep it ahead, breaking the assertion.
        tools = [a_tool(name="delete_thing")]
        tools.extend(a_tool(name=f"{p}thing") for p in prefixes)

        result = order_tools_for_audit(tools)

        assert result[-1].name == "delete_thing"
