from typing import Any

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    TestCaseBatch,
    TokenUsage,
    ToolDefinition,
)
from mcp_auditor.domain.ports import ProviderRefusal


def a_payload(category: AuditCategory = AuditCategory.INJECTION) -> AuditPayload:
    return AuditPayload(category=category, description="test payload", arguments={"input": "x"})


def a_batch_of(num_cases: int, categories: list[AuditCategory] | None = None) -> TestCaseBatch:
    cycled = list(AuditCategory) if categories is None else categories
    return TestCaseBatch(cases=[a_payload(cycled[i % len(cycled)]) for i in range(num_cases)])


def a_generation_state(test_budget: int) -> dict[str, Any]:
    tool = ToolDefinition(
        name="test_tool", description="A test tool", input_schema={"type": "object"}
    )
    return {"current_tool": tool, "test_budget": test_budget, "attack_context": AttackContext()}


def a_provider_refusal() -> ProviderRefusal:
    return ProviderRefusal("flagged by policy", TokenUsage(input_tokens=7, output_tokens=0))
