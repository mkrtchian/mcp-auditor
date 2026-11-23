import asyncio
from typing import Any

from evals.honeypot.fault_catalog import FAULTS
from evals.honeypot.fault_harness import FaultedAudit
from evals.honeypot.fault_injection import FailingJudge
from evals.honeypots import HONEYPOTS, AuditModels, ConnectedHoneypot
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    StepObservation,
    TestCaseBatch,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.ports import LLMPort
from tests.fakes.scripted_audit_model import ScriptedAuditModel


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


async def verdicts_of(judge: LLMPort, calls: int) -> list[EvalVerdict]:
    return [
        (await judge.generate_structured("a prompt", Judgment))[0].verdict for _ in range(calls)
    ]


# One case per category, as in the fault injection integration test.
FAULT_INJECTION_TEST_BUDGET = 5
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

    async def ping(self) -> bool:
        return True

    async def relaunch(self) -> bool:
        return False


def a_faulted_audit_losing_detections(clients: dict[str, GatedClient]) -> FaultedAudit:
    """Every case is judged a detection, so the loss drawn at each audit index shows."""
    fault = next(fault for fault in FAULTS if fault.loses_detections)
    models = AuditModels(llm=ScriptedAuditModel(), judge_llm=FailingJudge())
    servers = {
        honeypot.name: ConnectedHoneypot(honeypot, clients[honeypot.name])
        for honeypot in HONEYPOTS
        if honeypot.name in clients
    }
    return FaultedAudit(fault, models, FAULT_INJECTION_TEST_BUDGET, servers)
