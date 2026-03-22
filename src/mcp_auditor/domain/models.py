from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditCategory(StrEnum):
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"
    INJECTION = "injection"
    INFO_LEAKAGE = "info_leakage"
    RESOURCE_ABUSE = "resource_abuse"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()

    def _rank(self) -> int:
        return list(Severity).index(self)


class EvalVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class ToolDefinition(BaseModel):
    """Decoupled from mcp.types.Tool."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any]


class ToolResponse(BaseModel):
    content: str
    is_error: bool = False
    error_type: str | None = None


class AuditPayload(BaseModel):
    tool_name: str
    category: AuditCategory
    description: str = Field(description="What this test case verifies")
    arguments: dict[str, Any]


class TestCaseBatch(BaseModel):
    """Wrapper: with_structured_output returns a single BaseModel, not a list."""

    cases: list[AuditPayload]


class EvalResult(BaseModel):
    tool_name: str
    category: AuditCategory
    payload: dict[str, Any]
    verdict: EvalVerdict
    justification: str
    severity: Severity


class TestCase(BaseModel):
    payload: AuditPayload
    response: str | dict[str, Any] | None = None
    error: str | None = None
    eval_result: EvalResult | None = None


class TokenUsage(BaseModel):
    """Cost is computed at report time, not here."""

    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


class ToolReport(BaseModel):
    tool: ToolDefinition
    cases: list[TestCase]


def filter_tools(
    tools: list[ToolDefinition], tools_filter: frozenset[str] | None
) -> list[ToolDefinition]:
    if tools_filter is None:
        return tools
    available_names = {t.name for t in tools}
    unknown = tools_filter - available_names
    if unknown:
        raise ValueError(f"unknown tool names: {', '.join(sorted(unknown))}")
    return [t for t in tools if t.name in tools_filter]


class AuditReport(BaseModel):
    target: str
    tool_reports: list[ToolReport]
    token_usage: TokenUsage

    @property
    def findings(self) -> list[EvalResult]:
        return [
            case.eval_result
            for tr in self.tool_reports
            for case in tr.cases
            if case.eval_result is not None and case.eval_result.verdict == EvalVerdict.FAIL
        ]

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)
