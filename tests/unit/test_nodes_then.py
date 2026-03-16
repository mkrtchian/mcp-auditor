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


def tool_results_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["tool_results"]) == expected


def tool_report_has_results(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["tool_reports"][0].results) == expected_count
