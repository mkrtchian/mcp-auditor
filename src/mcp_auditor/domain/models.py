from dataclasses import dataclass
from enum import StrEnum
from typing import Any, override

from pydantic import BaseModel, Field, computed_field

from mcp_auditor.domain.execution import ExecutionRecord
from mcp_auditor.domain.model_calls import MissedModelCall
from mcp_auditor.domain.server_liveness import Relaunch, UnsentCause
from mcp_auditor.domain.shown_response import is_cut, rendered_response


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

    @override
    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()

    @override
    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    @override
    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    @override
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
    # non-overlap is what makes an unhandled blocked payload a type error, never a silent success.
    reason: str


class AttackContext(BaseModel):
    """What tool audits show about the server."""

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


class JudgeResult(BaseModel):
    tool_name: str
    category: AuditCategory
    arguments: dict[str, Any]
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

    justification: str
    verdict: EvalVerdict
    severity: Severity

    def stamped(
        self, tool_name: str, category: AuditCategory, arguments: dict[str, Any]
    ) -> JudgeResult:
        return JudgeResult(
            tool_name=tool_name,
            category=category,
            arguments=arguments,
            verdict=self.verdict,
            justification=self.justification,
            severity=self.severity,
        )


class TestCase(BaseModel):
    payload: AuditPayload
    response: str | dict[str, Any] | None = None
    error: str | None = None
    judge_result: JudgeResult | None = None
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
    judge_result: JudgeResult | None = None
    blocked_reason: str | None = None
    cut_by_relaunch: bool = False


class ProviderUsage(BaseModel):
    """What the model provider billed and how often it throttled.

    Cost is computed at report time, not here.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0  # subset of input_tokens
    reasoning_tokens: int = 0  # subset of output_tokens
    throttled_requests: int = 0
    largest_input_tokens: int = 0  # of a single request, for vendors that bill by request size

    def add(self, other: "ProviderUsage") -> "ProviderUsage":
        return ProviderUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
            throttled_requests=self.throttled_requests + other.throttled_requests,
            largest_input_tokens=max(self.largest_input_tokens, other.largest_input_tokens),
        )

    def sub(self, other: "ProviderUsage") -> "ProviderUsage":
        return ProviderUsage(
            input_tokens=self.input_tokens - other.input_tokens,
            output_tokens=self.output_tokens - other.output_tokens,
            cached_input_tokens=self.cached_input_tokens - other.cached_input_tokens,
            reasoning_tokens=self.reasoning_tokens - other.reasoning_tokens,
            throttled_requests=self.throttled_requests - other.throttled_requests,
            largest_input_tokens=self.largest_input_tokens,  # a maximum does not subtract
        )


class CoverageGap(BaseModel):
    requested_cases: int
    received_cases: int
    missing_categories: list[AuditCategory]
    unsent_cases: int = 0
    unsent_chains: int = 0
    unsent_cause: UnsentCause | None = None


class ToolReport(BaseModel):
    tool: ToolDefinition
    cases: list[TestCase]
    chains: list[AttackChain] = []
    coverage_gap: CoverageGap | None = None

    @property
    def judge_results(self) -> list[JudgeResult]:
        case_results = [c.judge_result for c in self.cases if c.judge_result]
        chain_results = [ch.judge_result for ch in self.chains if ch.judge_result]
        return case_results + chain_results

    @computed_field
    @property
    def cut_responses(self) -> int:
        shown: list[str] = []
        for case in self.cases:
            if case.response is not None:
                shown.append(rendered_response(case.response))
            if case.error is not None:
                shown.append(case.error)
        for chain in self.chains:
            shown.extend(
                text for step in chain.steps for text in (step.response, step.error) if text
            )
        return sum(1 for text in shown if is_cut(text))


class AuditReport(BaseModel):
    server_command: str
    tool_reports: list[ToolReport]
    provider_usage: ProviderUsage
    judge_usage: ProviderUsage = ProviderUsage()
    chain_usage: ProviderUsage = ProviderUsage()  # the chain judgment counts here and as judge
    execution: ExecutionRecord | None = None
    missed_model_calls: list[MissedModelCall] = []
    relaunches: list[Relaunch] = []

    @property
    def generator_usage(self) -> ProviderUsage:
        return self.provider_usage.sub(self.judge_usage)

    @property
    def single_step_usage(self) -> ProviderUsage:
        return self.provider_usage.sub(self.chain_usage)

    @property
    def is_complete(self) -> bool:
        return not self.missed_model_calls and all(
            tr.coverage_gap is None for tr in self.tool_reports
        )

    @property
    def findings(self) -> list[JudgeResult]:
        return [
            result
            for tr in self.tool_reports
            for result in tr.judge_results
            if result.verdict == EvalVerdict.FAIL
        ]

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)
