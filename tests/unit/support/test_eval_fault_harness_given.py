import asyncio
from dataclasses import dataclass, field
from typing import Any

from evals.baseline import Baseline
from evals.fault_catalog import FAULTS
from evals.fault_harness import FaultedAudit
from evals.fault_injection import FailingJudge
from evals.gate import Cell, cell_key
from evals.honeypots import HONEYPOTS, AuditModels, ConnectedHoneypot, HoneypotConfig
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
    ProviderUsage,
    RefusedStep,
    Severity,
    StepObservation,
    TestCase,
    TestCaseBatch,
    ToolDefinition,
    ToolReport,
    ToolResponse,
)
from mcp_auditor.domain.ports import LLMPort
from tests.fakes.fixture_judge import CHAIN_ONLY_FLAWS
from tests.fakes.scripted_audit_model import ScriptedAuditModel
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


@dataclass(frozen=True)
class ReverseFinishingReports:
    """Each honeypot's audit ends only once the next honeypot's has, the last one first."""

    reports: HoneypotReports
    finished: dict[str, asyncio.Event] = field(
        default_factory=lambda: {honeypot.name: asyncio.Event() for honeypot in HONEYPOTS}
    )

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        position = HONEYPOTS.index(honeypot)
        if position + 1 < len(HONEYPOTS):
            async with asyncio.timeout(_NEVER_IN_SEQUENCE):
                await self.finished[HONEYPOTS[position + 1].name].wait()
        self.finished[honeypot.name].set()
        return await self.reports.audit(honeypot)


_NEVER_IN_SEQUENCE = 1.0  # seconds: awaited one after the other, these audits would wait forever


class SubtleHoneypotCrashed(Exception):
    pass


@dataclass(frozen=True)
class OneFailingHoneypot:
    """The subtle honeypot's audit fails at once, the others wait until they are cancelled."""

    cancelled: list[str] = field(default_factory=list[str])

    async def audit(self, honeypot: HoneypotConfig) -> AuditReport:
        if honeypot.name == "subtle":
            raise SubtleHoneypotCrashed
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(honeypot.name)
            raise
        raise AssertionError("unreachable: the event is never set")


def a_report_per_honeypot_finishing_in_reverse() -> ReverseFinishingReports:
    return ReverseFinishingReports(a_report_per_honeypot())


def a_report_per_honeypot() -> HoneypotReports:
    return HoneypotReports(
        {
            "honeypot": _a_report(
                "get_user", EvalVerdict.FAIL, ProviderUsage(input_tokens=100, output_tokens=10)
            ).model_copy(update={"refused_steps": [_a_refused_step("get_user")]}),
            "subtle": _a_report(
                "list_items", EvalVerdict.PASS, ProviderUsage(input_tokens=200, output_tokens=20)
            ),
            "chain_honeypot": _a_report(
                "project_manager",
                EvalVerdict.FAIL,
                ProviderUsage(input_tokens=300, output_tokens=30),
            ),
        }
    )


def _a_report(tool: str, verdict: EvalVerdict, usage: ProviderUsage) -> AuditReport:
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
    return AuditReport(target=tool, tool_reports=[tool_report], provider_usage=usage)


def _a_refused_step(tool: str) -> RefusedStep:
    return RefusedStep(tool_name=tool, step=AuditStep.JUDGMENT, provider_message="refused")


async def verdicts_of(judge: LLMPort, calls: int) -> list[EvalVerdict]:
    return [
        (await judge.generate_structured("a prompt", Judgment))[0].verdict for _ in range(calls)
    ]


FAULT_INJECTION_BUDGET = 5  # One case per category, as in the fault injection integration test.
MANY_TOOLS = [
    ToolDefinition(name=f"tool_{index}", input_schema={"type": "object"}) for index in range(20)
]
SINGLE_STEP_HONEYPOTS = [honeypot for honeypot in HONEYPOTS if honeypot.chain_budget == 0]


class GatedClient:
    """A server that lists its tools only once its gate opens."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()

    async def list_tools(self) -> list[ToolDefinition]:
        await self.gate.wait()
        return MANY_TOOLS

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        return ToolResponse(content="ok")


def a_faulted_audit_losing_detections(clients: dict[str, GatedClient]) -> FaultedAudit:
    """Every case is judged a detection, so the loss drawn at each audit index shows."""
    fault = next(fault for fault in FAULTS if fault.loses_detections)
    models = AuditModels(llm=ScriptedAuditModel(), judge_llm=FailingJudge())
    servers = {
        honeypot.name: ConnectedHoneypot(honeypot, clients[honeypot.name])
        for honeypot in HONEYPOTS
        if honeypot.name in clients
    }
    return FaultedAudit(fault, models, FAULT_INJECTION_BUDGET, servers)
