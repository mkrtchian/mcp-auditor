from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from mcp_auditor.domain.models import (
    AuditReport,
    TestCase,
    ToolDefinition,
    ToolReport,
)


class GraphState(TypedDict):
    target: str
    discovered_tools: list[ToolDefinition]
    test_budget: int
    current_tool: ToolDefinition | None
    judged_cases: list[TestCase]
    tool_reports: Annotated[list[ToolReport], operator.add]
    audit_report: AuditReport | None


class AuditToolState(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    pending_cases: list[TestCase]
    current_case: TestCase | None
    judged_cases: list[TestCase]


class AuditToolInput(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
