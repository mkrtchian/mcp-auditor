from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.models import (
    AttackChain,
    AuditPayload,
    ChainPlanBatch,
    ChainStep,
    EvalResult,
    StepObservation,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.chain_prompts import (
    build_chain_judge_prompt,
    build_chain_planning_prompt,
    build_step_observation_prompt,
    build_step_planning_prompt,
)


def make_plan_chains(llm: LLMPort):
    async def plan_chains(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        cases = state["judged_cases"]
        context = state["attack_context"]
        budget = state["chain_budget"]
        prompt = build_chain_planning_prompt(
            tool=tool,
            single_step_cases=cases,
            attack_context=context,
            chain_budget=budget,
        )
        batch, usage = await llm.generate_structured(prompt, ChainPlanBatch)
        return {"pending_chains": batch.chains, "token_usage": [usage]}

    return plan_chains


def prepare_chain(state: dict[str, Any]) -> dict[str, Any]:
    goal = state["pending_chains"][0]
    return {
        "pending_chains": state["pending_chains"][1:],
        "current_chain_goal": goal,
        "current_chain_steps": [],
        "current_step_payload": goal.first_step,
    }


def make_execute_step(mcp_client: MCPClientPort):
    async def execute_step(state: dict[str, Any]) -> dict[str, Any]:
        payload: AuditPayload = state["current_step_payload"]
        tool = state["current_tool"]
        if payload.tool_name != tool.name:
            payload = payload.model_copy(update={"tool_name": tool.name})
        response = await mcp_client.call_tool(payload.tool_name, payload.arguments)
        if response.is_error:
            step = ChainStep.from_error(payload, response.content)
        else:
            step = ChainStep.from_response(payload, response.content)
        steps = [*list(state["current_chain_steps"]), step]
        return {"current_chain_steps": steps}

    return execute_step


def make_observe_step(llm: LLMPort):
    async def observe_step(state: dict[str, Any]) -> dict[str, Any]:
        steps = list(state["current_chain_steps"])
        latest = steps[-1]
        goal = state["current_chain_goal"]
        tool = state["current_tool"]
        prompt = build_step_observation_prompt(
            tool=tool,
            goal=goal,
            chain_history=steps[:-1],
            latest_response=latest.response,
            latest_error=latest.error,
        )
        obs, usage = await llm.generate_structured(prompt, StepObservation)
        updated_step = latest.with_observation(obs.observation)
        steps[-1] = updated_step
        return {
            "current_chain_steps": steps,
            "current_observation": obs,
            "token_usage": [usage],
        }

    return observe_step


def make_plan_step(llm: LLMPort):
    async def plan_step(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        goal = state["current_chain_goal"]
        steps = state["current_chain_steps"]
        obs = state["current_observation"]
        hint = obs.next_step_hint if obs else ""
        prompt = build_step_planning_prompt(
            tool=tool,
            goal=goal,
            chain_history=steps,
            observation_hint=hint,
        )
        payload, usage = await llm.generate_structured(prompt, AuditPayload)
        return {"current_step_payload": payload, "token_usage": [usage]}

    return plan_step


def make_judge_chain(llm: LLMPort):
    async def judge_chain(state: dict[str, Any]) -> dict[str, Any]:
        goal = state["current_chain_goal"]
        steps = state["current_chain_steps"]
        tool = state["current_tool"]
        chain = AttackChain(goal=goal, steps=steps)
        prompt = build_chain_judge_prompt(tool=tool, chain=chain)
        eval_result, usage = await llm.generate_structured(prompt, EvalResult)
        judged_chain = chain.model_copy(update={"eval_result": eval_result})
        return {
            "completed_chains": [judged_chain],
            "current_chain_goal": None,
            "current_chain_steps": [],
            "token_usage": [usage],
        }

    return judge_chain


def route_after_planning(state: dict[str, Any]) -> str:
    if state["pending_chains"]:
        return "prepare_chain"
    return END


def route_after_observe(state: dict[str, Any]) -> str:
    obs = state["current_observation"]
    steps = state["current_chain_steps"]
    max_steps = state["max_chain_steps"]
    if obs.should_continue and len(steps) < max_steps:
        return "plan_step"
    return "judge_chain"


def route_after_judge(state: dict[str, Any]) -> str:
    if state["pending_chains"]:
        return "prepare_chain"
    return END


def route_to_chains_or_report(state: dict[str, Any]) -> str:
    if state.get("chain_budget", 0) > 0:
        return "chain_audit_tool"
    return "build_tool_report"
