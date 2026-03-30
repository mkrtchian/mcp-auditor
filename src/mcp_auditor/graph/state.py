from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from mcp_auditor.domain.models import (
    AttackChain,
    AttackContext,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    StepObservation,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)


class GraphState(TypedDict):
    target: str
    discovered_tools: list[ToolDefinition]
    test_budget: int
    current_tool: ToolDefinition | None
    judged_cases: list[TestCase]
    tool_reports: Annotated[list[ToolReport], operator.add]
    token_usage: Annotated[list[TokenUsage], operator.add]
    audit_report: AuditReport | None
    attack_context: AttackContext
    chain_budget: int
    max_chain_steps: int
    completed_chains: list[AttackChain]


class AuditToolState(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    pending_cases: list[TestCase]
    current_case: TestCase | None
    judged_cases: Annotated[list[TestCase], operator.add]
    token_usage: Annotated[list[TokenUsage], operator.add]
    attack_context: AttackContext


class AuditToolInput(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    attack_context: AttackContext


class ChainAuditState(TypedDict):
    current_tool: ToolDefinition
    judged_cases: list[TestCase]
    attack_context: AttackContext
    chain_budget: int
    max_chain_steps: int
    pending_chains: list[ChainGoal]
    current_chain_goal: ChainGoal | None
    current_chain_steps: list[ChainStep]
    current_step_payload: AuditPayload | None
    current_observation: StepObservation | None
    completed_chains: Annotated[list[AttackChain], operator.add]
    token_usage: Annotated[list[TokenUsage], operator.add]


class ChainAuditInput(TypedDict):
    current_tool: ToolDefinition
    judged_cases: list[TestCase]
    attack_context: AttackContext
    chain_budget: int
    max_chain_steps: int
