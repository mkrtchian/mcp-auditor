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


class AttackContext(BaseModel):
    """Accumulated intelligence from previous tool audits."""

    db_engine: str | None = None
    framework: str | None = None
    language: str | None = None
    exposed_internals: list[str] = []
    effective_payloads: list[str] = []
    observations: str = ""

    @property
    def is_empty(self) -> bool:
        return self == AttackContext()


class AuditPayload(BaseModel):
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


class Judgment(BaseModel):
    """The judge's verdict, decoupled from the identity fields the code stamps itself."""

    verdict: EvalVerdict
    justification: str
    severity: Severity


class TestCase(BaseModel):
    payload: AuditPayload
    response: str | dict[str, Any] | None = None
    error: str | None = None
    eval_result: EvalResult | None = None


class StepObservation(BaseModel):
    """LLM output after observing a chain step's response."""

    observation: str
    should_continue: bool
    next_step_hint: str = ""


class ChainStep(BaseModel):
    payload: AuditPayload
    response: str | None = None
    error: str | None = None
    observation: str = ""

    @staticmethod
    def from_response(payload: AuditPayload, response: str) -> "ChainStep":
        return ChainStep(payload=payload, response=response)

    @staticmethod
    def from_error(payload: AuditPayload, error: str) -> "ChainStep":
        return ChainStep(payload=payload, error=error)

    def with_observation(self, observation: str) -> "ChainStep":
        return self.model_copy(update={"observation": observation})


class ChainGoal(BaseModel):
    """LLM-generated plan for one attack chain."""

    description: str
    category: AuditCategory
    first_step: AuditPayload


class ChainPlanBatch(BaseModel):
    """Wrapper for structured output (same pattern as TestCaseBatch)."""

    chains: list[ChainGoal]


class AttackChain(BaseModel):
    """A completed multi-step attack chain with a final verdict."""

    goal: ChainGoal
    steps: list[ChainStep]
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
    chains: list[AttackChain] = []

    @property
    def eval_results(self) -> list[EvalResult]:
        case_results = [c.eval_result for c in self.cases if c.eval_result]
        chain_results = [ch.eval_result for ch in self.chains if ch.eval_result]
        return case_results + chain_results


_READ_PREFIXES = (
    "get_",
    "list_",
    "read_",
    "search_",
    "find_",
    "fetch_",
    "show_",
    "describe_",
    "check_",
)


def order_tools_for_audit(tools: list[ToolDefinition]) -> list[ToolDefinition]:
    """Read-like tools first, then by parameter count ascending. Stable sort."""
    return sorted(tools, key=_audit_order_key)


def _audit_order_key(tool: ToolDefinition) -> tuple[int, int]:
    is_read = 0 if tool.name.startswith(_READ_PREFIXES) else 1
    param_count = len(tool.input_schema.get("properties", {}))
    return (is_read, param_count)


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
            result
            for tr in self.tool_reports
            for result in tr.eval_results
            if result.verdict == EvalVerdict.FAIL
        ]

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)
