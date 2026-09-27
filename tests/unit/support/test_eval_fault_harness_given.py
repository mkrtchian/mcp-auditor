from dataclasses import dataclass

from evals.baseline import Baseline
from evals.gate import Cell, cell_key
from evals.honeypots import HoneypotConfig
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    AuditStep,
    ChainGoal,
    ChainPlanBatch,
    EvalResult,
    EvalVerdict,
    Judgment,
    RefusedStep,
    Severity,
    StepObservation,
    TestCase,
    TestCaseBatch,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.ports import LLMPort
from tests.fakes.fixture_judge import CHAIN_ONLY_FLAWS
from tests.unit.support.test_eval_fault_injection_given import the_fault_injection_baseline

__all__ = ["CHAIN_ONLY_FLAWS", "the_fault_injection_baseline"]


def the_fixture_missing(cell: Cell) -> Baseline:
    fixture = the_fault_injection_baseline()
    runs = [
        {key: seen for key, seen in run.items() if key != cell_key(cell)} for run in fixture.runs
    ]
    return fixture.model_copy(update={"runs": runs})


def many_detections_and_a_pass_and_an_uncovered_cell() -> VerdictMap:
    detections: VerdictMap = {
        (f"tool_{index}", category): EvalVerdict.FAIL
        for index in range(20)
        for category in AuditCategory
    }
    return {
        **detections,
        ("passing_tool", AuditCategory.INJECTION): EvalVerdict.PASS,
        ("uncovered_tool", AuditCategory.INJECTION): None,
    }


def a_test_case_batch(*categories: AuditCategory) -> TestCaseBatch:
    return TestCaseBatch(cases=[_a_payload(category) for category in categories])


def a_chain_plan(*categories: AuditCategory) -> ChainPlanBatch:
    return ChainPlanBatch(
        chains=[
            ChainGoal(description="a goal", category=category, first_step=_a_payload(category))
            for category in categories
        ]
    )


def a_step_observation() -> StepObservation:
    return StepObservation(observation="nothing", should_continue=False)


def _a_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="a case", arguments={})


@dataclass(frozen=True)
class HoneypotReports:
    """One fixed report per honeypot, as the audit of each would return it."""

    by_honeypot: dict[str, AuditReport]

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        return self.by_honeypot[honeypot.name]


def a_report_per_honeypot() -> HoneypotReports:
    return HoneypotReports(
        {
            "honeypot": _a_report(
                "get_user", EvalVerdict.FAIL, TokenUsage(input_tokens=100, output_tokens=10)
            ).model_copy(update={"refused_steps": [_a_refused_step("get_user")]}),
            "subtle": _a_report(
                "list_items", EvalVerdict.PASS, TokenUsage(input_tokens=200, output_tokens=20)
            ),
            "chain_honeypot": _a_report(
                "project_manager", EvalVerdict.FAIL, TokenUsage(input_tokens=300, output_tokens=30)
            ),
        }
    )


def _a_report(tool: str, verdict: EvalVerdict, usage: TokenUsage) -> AuditReport:
    result = EvalResult(
        tool_name=tool,
        category=AuditCategory.INFO_LEAKAGE,
        payload={},
        verdict=verdict,
        justification="judged",
        severity=Severity.LOW,
    )
    tool_report = ToolReport(
        tool=ToolDefinition(name=tool, input_schema={"type": "object"}),
        cases=[TestCase(payload=_a_payload(AuditCategory.INFO_LEAKAGE), eval_result=result)],
    )
    return AuditReport(target=tool, tool_reports=[tool_report], token_usage=usage)


def _a_refused_step(tool: str) -> RefusedStep:
    return RefusedStep(tool_name=tool, step=AuditStep.JUDGMENT, provider_message="refused")


async def verdicts_of(judge: LLMPort, calls: int) -> list[EvalVerdict]:
    return [
        (await judge.generate_structured("a prompt", Judgment))[0].verdict for _ in range(calls)
    ]
