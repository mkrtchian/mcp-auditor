from typing import Any

from mcp_auditor.domain import ToolDefinition


def discovered_tools_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["discovered_tools"]) == expected


def current_tool_is(result: dict[str, Any], expected_tool: ToolDefinition) -> None:
    assert result["current_tool"] == expected_tool


def pending_cases_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["pending_cases"]) == expected


def current_case_has_response(result: dict[str, Any], expected_content: str) -> None:
    assert result["current_case"].response == expected_content


def current_case_has_error(result: dict[str, Any], expected_error: str) -> None:
    assert result["current_case"].error == expected_error
    assert result["current_case"].response is None


def judged_cases_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["judged_cases"]) == expected


def tool_report_has_cases(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["tool_reports"][0].cases) == expected_count


def discovered_tools_are(tools: list[ToolDefinition], expected_names: list[str]) -> None:
    assert [t.name for t in tools] == expected_names


def attack_context_has_db_engine(result: dict[str, Any], expected: str) -> None:
    assert result["attack_context"].db_engine == expected
