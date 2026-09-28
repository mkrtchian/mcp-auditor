from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


@dataclass(frozen=True)
class OwaspMapping:
    code: str
    title: str

    @property
    def label(self) -> str:
        return f"{self.code}: {self.title}"


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


@dataclass(frozen=True)
class BlockedPayload:
    # No field is named like a ToolResponse field (content, is_error, error_type): the
    # non-overlap is what makes an unhandled refusal a type error, never a silent success.
    reason: str


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

    @computed_field
    @property
    def owasp(self) -> OwaspMapping | None:
        """Derived from category on every serialization, never stored (ADR 012)."""
        # Local import: domain.owasp imports this module for AuditCategory.
        from mcp_auditor.domain.owasp import owasp_mapping_for

        return owasp_mapping_for(self.category)


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
    blocked_reason: str | None = None


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
    blocked_reason: str | None = None


class ProviderUsage(BaseModel):
    """What the model provider billed and how often it throttled.

    Cost is computed at report time, not here.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0  # subset of input_tokens
    reasoning_tokens: int = 0  # subset of output_tokens
    throttled_requests: int = 0

    def add(self, other: "ProviderUsage") -> "ProviderUsage":
        return ProviderUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
            throttled_requests=self.throttled_requests + other.throttled_requests,
        )


class CoverageGap(BaseModel):
    requested_cases: int
    received_cases: int
    missing_categories: list[AuditCategory]


class ToolReport(BaseModel):
    tool: ToolDefinition
    cases: list[TestCase]
    chains: list[AttackChain] = []
    coverage_gap: CoverageGap | None = None

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


class ExecutionRegime(StrEnum):
    CONFINED = "confined"
    DECLARED_CONTAINER = "declared_container"
    UNCONFINED = "unconfined"


class ExecutionRecord(BaseModel):
    regime: ExecutionRegime
    image: str | None = None
    image_digest: str | None = None
    writable_paths: list[str] | None = None
    read_only_paths: list[str] | None = None
    oom_killed: bool | None = None
    """Read with the regime: under `confined`, `None` means the kill state could not be read.
    Under the other regimes it is always `None`, there being no container of the auditor's."""


class AuditStep(StrEnum):
    TEST_GENERATION = "test_generation"
    JUDGMENT = "judgment"
    CONTEXT_EXTRACTION = "context_extraction"
    CHAIN_PLANNING = "chain_planning"
    CHAIN_STEP_OBSERVATION = "chain_step_observation"
    CHAIN_STEP_PLANNING = "chain_step_planning"
    CHAIN_JUDGMENT = "chain_judgment"


class RefusedStep(BaseModel):
    tool_name: str
    step: AuditStep
    provider_message: str


class AuditReport(BaseModel):
    target: str
    tool_reports: list[ToolReport]
    provider_usage: ProviderUsage
    execution: ExecutionRecord | None = None
    refused_steps: list[RefusedStep] = []

    @property
    def is_complete(self) -> bool:
        return not self.refused_steps and all(tr.coverage_gap is None for tr in self.tool_reports)

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
