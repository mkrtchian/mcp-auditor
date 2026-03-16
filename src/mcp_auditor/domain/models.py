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


class EvalVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class ToolDefinition(BaseModel):
    """Domain representation of an MCP tool. Decoupled from mcp.types.Tool."""

    name: str
    description: str
    input_schema: dict[str, Any]


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
    """LLM token consumption tracker. Cost is computed at report time, not here."""

    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )
