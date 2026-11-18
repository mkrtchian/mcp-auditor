from typing import Any

from mcp_auditor.domain import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    TestCase,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH

NEEDLE = "NEEDLE-FROM-THE-CUT-MIDDLE"
OVER_THE_BOUND = "x" * (MAX_SHOWN_LENGTH + 1)


def a_long_text(label: str = "text", length: int = 50_000) -> str:
    """Its head and tail name the label, so a prompt shows which text it kept, and its middle
    holds NEEDLE, so a prompt shows whether the middle was cut."""
    head = f"{label}-head-"
    tail = f"-{label}-tail"
    filler = length - len(head) - len(tail) - len(NEEDLE)
    return head + "h" * (filler // 2) + NEEDLE + "t" * (filler - filler // 2) + tail


def a_dict_response_rendering_over_the_bound() -> dict[str, Any]:
    """Its one value is under the bound, its JSON rendering is over it."""
    return {"rows": "x" * (MAX_SHOWN_LENGTH - 5)}


def a_tool_report(
    cases: list[TestCase] | None = None, steps: list[ChainStep] | None = None
) -> ToolReport:
    chains = [_a_chain(steps)] if steps is not None else []
    return ToolReport(tool=_a_tool(), cases=cases or [], chains=chains)


def a_case(response: str | dict[str, Any] | None = "ok", error: str | None = None) -> TestCase:
    return TestCase(payload=_a_payload(), response=response, error=error)


def a_blocked_case() -> TestCase:
    return TestCase(payload=_a_payload(), blocked_reason="destructive filesystem command: rm -rf")


def a_step(response: str | None = "ok", error: str | None = None) -> ChainStep:
    return ChainStep(payload=_a_payload(), response=response, error=error)


def _a_chain(steps: list[ChainStep]) -> AttackChain:
    goal = ChainGoal(
        description="probe then read", category=AuditCategory.INJECTION, first_step=_a_payload()
    )
    return AttackChain(goal=goal, steps=steps)


def _a_payload() -> AuditPayload:
    return AuditPayload(
        category=AuditCategory.INJECTION, description="probe", arguments={"id": "1"}
    )


def _a_tool() -> ToolDefinition:
    return ToolDefinition(name="query", description="Run a query", input_schema={})
