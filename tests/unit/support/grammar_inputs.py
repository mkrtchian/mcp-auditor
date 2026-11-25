import re
from typing import Any

from evals.cve.grammar import FlawClass, MissKind, PlantedTarget, RunGrade, TargetStatus
from evals.cve.units import JudgeCategory
from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    EvalVerdict,
    JudgeResult,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)

NONCE = "s3nt1nel_ab12cd34ef56"
PLACE = "planted"
AIMED_PATH = "/outside/flag"
READ_AIM = re.compile(r"^/outside/")
_UNAIMED_PATH = "/inside/file"
FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
INJECTION = AuditCategory.INJECTION
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
RESOURCE_ABUSE = AuditCategory.RESOURCE_ABUSE
INPUT_VALIDATION = AuditCategory.INPUT_VALIDATION


def a_read_target() -> PlantedTarget:
    return a_target_under(FlawClass.READ_OUTSIDE_SCOPE)


def a_command_target() -> PlantedTarget:
    return PlantedTarget(
        classes=frozenset({FlawClass.COMMAND_EXECUTION}),
        aim=re.compile(r"[;&|`]|\$\("),
        nonces={PLACE: NONCE},
    )


def a_target_under(*classes: FlawClass) -> PlantedTarget:
    return PlantedTarget(classes=frozenset(classes), aim=READ_AIM, nonces={PLACE: NONCE})


def a_case(
    response: str | dict[str, Any] | None = None,
    error: str | None = None,
    verdict: EvalVerdict | None = FAIL,
    category: AuditCategory = INFO_LEAKAGE,
    arguments: dict[str, Any] | None = None,
) -> TestCase:
    return TestCase(
        payload=_a_payload(category, arguments or {"path": _UNAIMED_PATH}),
        response=response,
        error=error,
        judge_result=_a_result(verdict, category) if verdict else None,
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
        payload=_a_payload(INFO_LEAKAGE, arguments or {"path": _UNAIMED_PATH}),
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
        judge_result=_a_result(verdict, INFO_LEAKAGE),
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
    server_command: str = "test",
) -> AuditReport:
    report = a_report_of_tools(a_tool_report("read_file", cases, chains))
    return report.model_copy(update={"server_command": server_command})


def a_tool_report(
    name: str, cases: list[TestCase] | None = None, chains: list[AttackChain] | None = None
) -> ToolReport:
    return ToolReport(
        tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
        cases=cases or [],
        chains=chains or [],
    )


def a_report_of_tools(*tool_reports: ToolReport) -> AuditReport:
    return AuditReport(
        server_command="test", tool_reports=list(tool_reports), provider_usage=ProviderUsage()
    )


def a_detected_run() -> RunGrade:
    return RunGrade(
        status=TargetStatus.DETECTED,
        surfaced_places=frozenset({PLACE}),
        aimed=True,
        evidence=f"leaked {NONCE}",
        category=JudgeCategory(INFO_LEAKAGE.value),
    )


def a_missed_run(
    miss_kind: MissKind, aimed: bool = True, fail_without_proof: bool = False
) -> RunGrade:
    return RunGrade(
        status=TargetStatus.MISSED,
        miss_kind=miss_kind,
        fail_without_proof=fail_without_proof,
        aimed=aimed,
    )


def a_reached_run() -> RunGrade:
    return RunGrade(
        status=TargetStatus.REACHED_BUT_JUDGED_PASS,
        surfaced_places=frozenset({PLACE}),
        aimed=True,
        evidence=f"leaked {NONCE}",
        category=JudgeCategory(INFO_LEAKAGE.value),
    )


def _a_payload(category: AuditCategory, arguments: dict[str, Any]) -> AuditPayload:
    return AuditPayload(category=category, description="test", arguments=arguments)


def _a_result(verdict: EvalVerdict, category: AuditCategory) -> JudgeResult:
    return JudgeResult(
        tool_name="read_file",
        category=category,
        arguments={},
        verdict=verdict,
        justification="test",
        severity=Severity.HIGH,
    )
