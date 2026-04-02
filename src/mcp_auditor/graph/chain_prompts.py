import json

from mcp_auditor.domain.models import (
    AttackChain,
    AttackContext,
    ChainGoal,
    ChainStep,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.graph.prompts import build_context_section, format_tool_header


def build_chain_planning_prompt(
    tool: ToolDefinition,
    single_step_cases: list[TestCase],
    attack_context: AttackContext,
    chain_budget: int,
) -> str:
    tool_header = format_tool_header(tool)
    summary = _format_single_step_summary(single_step_cases)
    context_section = build_context_section(attack_context)
    summary_text = summary or "No single-step results available."

    return (
        "You are a security auditor planning multi-step"
        f' attack chains for the MCP tool "{tool.name}".'
        f"""

{tool_header}

Single-step test results summary:
{summary_text}
{context_section}
Your task: plan up to {chain_budget} multi-step attack chains. \
Each chain should exploit a vulnerability that requires multiple \
interactions — probing to discover internal state, then using \
that knowledge to escalate.

For each chain, provide:
- description: what the chain aims to demonstrate
- category: the attack category being targeted
- first_step: the initial AuditPayload to send

Do not plan chains for things that can be tested with a single \
request. Focus on vulnerabilities where reconnaissance enables \
exploitation. Only plan chains for info_leakage and injection \
— other categories (input_validation, error_handling, \
resource_abuse) are thoroughly covered by single-step tests.

For info_leakage chains specifically: enumerate entities, \
inspect their metadata, then use discovered field names or \
IDs to extract sensitive data through different actions or \
parameters."""
    )


def build_step_planning_prompt(
    tool: ToolDefinition,
    goal: ChainGoal,
    chain_history: list[ChainStep],
    observation_hint: str,
) -> str:
    tool_header = format_tool_header(tool)
    history_section = _format_chain_history(chain_history)
    hint_section = (
        f"\nHint from previous observation: {observation_hint}\n" if observation_hint else ""
    )
    history_text = history_section or "No steps executed yet."

    return (
        "You are executing a multi-step attack chain"
        f' against the MCP tool "{tool.name}".'
        f"""

{tool_header}

Chain goal: {goal.description}

Chain history so far:
{history_text}
{hint_section}
Based on what has been observed so far, plan the next step. \
Provide an AuditPayload with the arguments for the next tool \
call and a description of why this step advances the attack."""
    )


def build_step_observation_prompt(
    tool: ToolDefinition,
    goal: ChainGoal,
    chain_steps: list[ChainStep],
) -> str:
    description = tool.description or "No description provided"
    latest = chain_steps[-1]
    history_section = _format_chain_history(chain_steps[:-1])
    outcome = _format_latest_outcome(latest.response, latest.error)
    history_text = history_section or "No previous steps."

    return (
        "You are analyzing the result of a step in a multi-step"
        f' attack chain against the MCP tool "{tool.name}".'
        f"""

Tool description: {description}

Chain goal: {goal.description}

Chain history:
{history_text}

Latest step result:
{outcome}

Analyze this result:
1. What did this response reveal about the tool or server?
2. Is there a promising next step to advance the attack, \
or is this a dead end?

Provide your observation, whether to continue, \
and optionally a hint for the next step."""
    )


def build_chain_judge_prompt(
    tool: ToolDefinition,
    chain: AttackChain,
) -> str:
    description = tool.description or "No description provided"
    steps_section = _format_chain_history(chain.steps)
    category = chain.goal.category

    return (
        "You are a security evaluator for MCP tool servers."
        f"""

Your task: evaluate whether the multi-step attack chain \
against "{tool.name}" demonstrated a vulnerability.

Tool description: {description}

Chain goal: {chain.goal.description}
Target category: {category}

Full chain of interactions:
{steps_section}

Judge the chain as a whole. Individual steps may appear \
benign — the vulnerability is in the progression.

Decide:
- FAIL: the chain demonstrated a **{category}** vulnerability \
through the sequence of interactions
- PASS: no vulnerability was demonstrated despite the \
multi-step attempt

Consider the tool's stated purpose. A tool designed to \
execute queries or access files is expected to do those \
things. The vulnerability must come from the multi-step \
escalation — information from early steps enabling \
exploitation in later steps.

Provide a justification and severity (low, medium, high, \
critical). For the payload field, use the arguments from \
the most significant step in the chain."""
    )


def _format_single_step_summary(cases: list[TestCase]) -> str:
    if not cases:
        return ""
    lines: list[str] = []
    for i, case in enumerate(cases, 1):
        parts = [f"Case {i} [{case.payload.category}]"]
        if case.response is not None:
            response_text = (
                json.dumps(case.response) if isinstance(case.response, dict) else str(case.response)
            )
            snippet = response_text[:200] + "..." if len(response_text) > 200 else response_text
            parts.append(f"  Response: {snippet}")
        if case.error is not None:
            parts.append(f"  Error: {case.error}")
        if case.eval_result is not None:
            parts.append(f"  Verdict: {case.eval_result.verdict}")
        lines.append("\n".join(parts))
    return "\n".join(lines)


def _format_chain_history(steps: list[ChainStep]) -> str:
    if not steps:
        return ""
    lines: list[str] = []
    for i, step in enumerate(steps, 1):
        parts = [f"Step {i}: {step.payload.description}"]
        args_json = json.dumps(step.payload.arguments)
        parts.append(f"  Arguments: {args_json}")
        if step.response is not None:
            parts.append(f"  Response: {step.response}")
        if step.error is not None:
            parts.append(f"  Error: {step.error}")
        if step.observation:
            parts.append(f"  Observation: {step.observation}")
        lines.append("\n".join(parts))
    return "\n\n".join(lines)


def _format_latest_outcome(response: str | None, error: str | None) -> str:
    parts: list[str] = []
    if response is not None:
        parts.append(f"Response: {response}")
    if error is not None:
        parts.append(f"Error: {error}")
    if not parts:
        return "No response and no error."
    return "\n".join(parts)
