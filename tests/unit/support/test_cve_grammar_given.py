import re
from dataclasses import dataclass
from typing import Any

from evals.cve_grammar import (
    CVEStatus,
    GradedTarget,
    MechanismClass,
    MissClass,
    RunGrade,
    grade_run,
)
from evals.cve_report_units import units_of
from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    EvalResult,
    EvalVerdict,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)

SENTINEL = "s3nt1nel_ab12cd34ef56"
AIMED_PATH = "/outside/flag"
UNAIMED_PATH = "/inside/file"
FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
INJECTION = AuditCategory.INJECTION
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
RESOURCE_ABUSE = AuditCategory.RESOURCE_ABUSE


@dataclass(frozen=True)
class FakeTarget:
    mechanism: MechanismClass
    sentinel: str
    aim: re.Pattern[str]


def a_read_target() -> FakeTarget:
    return FakeTarget(MechanismClass.READ_OUTSIDE_SCOPE, SENTINEL, re.compile(r"^/outside/"))


def a_command_target() -> FakeTarget:
    return FakeTarget(MechanismClass.COMMAND_EXECUTION, SENTINEL, re.compile(r"[;&|`]|\$\("))


def a_case(
    response: str | dict[str, Any] | None = None,
    error: str | None = None,
    verdict: EvalVerdict | None = FAIL,
    category: AuditCategory = INFO_LEAKAGE,
    arguments: dict[str, Any] | None = None,
) -> TestCase:
    return TestCase(
        payload=_a_payload(category, arguments or {"path": UNAIMED_PATH}),
        response=response,
        error=error,
        eval_result=_a_result(verdict, category) if verdict else None,
    )


def a_blocked_case(arguments: dict[str, Any]) -> TestCase:
    return TestCase(
        payload=_a_payload(INJECTION, arguments),
        blocked_reason="destructive payload",
    )


def a_step(
    arguments: dict[str, Any] | None = None,
    response: str | None = None,
    error: str | None = None,
    observation: str = "",
) -> ChainStep:
    return ChainStep(
        payload=_a_payload(INFO_LEAKAGE, arguments or {"path": UNAIMED_PATH}),
        response=response,
        error=error,
        observation=observation,
    )


def a_chain(
    steps: list[ChainStep],
    verdict: EvalVerdict = FAIL,
    blocked_reason: str | None = None,
) -> AttackChain:
    return AttackChain(
        goal=ChainGoal(
            description="test chain", category=INFO_LEAKAGE, first_step=steps[0].payload
        ),
        steps=steps,
        eval_result=_a_result(verdict, INFO_LEAKAGE),
        blocked_reason=blocked_reason,
    )


def a_chain_blocked_at_first_step(first_step_arguments: dict[str, Any]) -> AttackChain:
    return AttackChain(
        goal=ChainGoal(
            description="test chain",
            category=INJECTION,
            first_step=_a_payload(INJECTION, first_step_arguments),
        ),
        steps=[],
        blocked_reason="destructive payload",
    )


def a_report(
    cases: list[TestCase] | None = None,
    chains: list[AttackChain] | None = None,
    target: str = "test",
) -> AuditReport:
    tool_report = ToolReport(
        tool=ToolDefinition(name="read_file", description="test", input_schema={"type": "object"}),
        cases=cases or [],
        chains=chains or [],
    )
    return AuditReport(target=target, tool_reports=[tool_report], provider_usage=ProviderUsage())


def graded(target: GradedTarget, report: AuditReport) -> RunGrade:
    return grade_run(target, units_of(report))


def a_detected_run() -> RunGrade:
    return RunGrade(
        status=CVEStatus.DETECTED,
        surfaced=True,
        aimed=True,
        evidence=f"leaked {SENTINEL}",
        category=INFO_LEAKAGE,
    )


def a_missed_run(
    miss_class: MissClass, aimed: bool = True, fail_without_proof: bool = False
) -> RunGrade:
    return RunGrade(
        status=CVEStatus.MISSED,
        miss_class=miss_class,
        fail_without_proof=fail_without_proof,
        aimed=aimed,
    )


def a_reached_run() -> RunGrade:
    return RunGrade(
        status=CVEStatus.REACHED_BUT_JUDGED_PASS,
        surfaced=True,
        aimed=True,
        evidence=f"leaked {SENTINEL}",
        category=INFO_LEAKAGE,
    )


def _a_payload(category: AuditCategory, arguments: dict[str, Any]) -> AuditPayload:
    return AuditPayload(category=category, description="test", arguments=arguments)


def _a_result(verdict: EvalVerdict, category: AuditCategory) -> EvalResult:
    return EvalResult(
        tool_name="read_file",
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.HIGH,
    )
