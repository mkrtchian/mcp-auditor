from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import (
    AttackChain,
    AuditPayload,
    AuditStep,
    BlockedPayload,
    ChainPlanBatch,
    ChainStep,
    EvalResult,
    Judgment,
    StepObservation,
)
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.chain_prompts import (
    build_chain_judge_prompt,
    build_chain_planning_prompt,
    build_step_observation_prompt,
    build_step_planning_prompt,
)
from mcp_auditor.graph.refusals import ModelCall, Refused, call_model


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
        call = ModelCall(tool.name, AuditStep.CHAIN_PLANNING, prompt, ChainPlanBatch)
        outcome = await call_model(llm, call)
        if isinstance(outcome, Refused):
            return {"pending_chains": [], **outcome.state_update()}
        batch, usage = outcome
        return {"pending_chains": batch.chains, "token_usage": [usage]}

    return plan_chains


def prepare_chain(state: dict[str, Any]) -> dict[str, Any]:
    goal = state["pending_chains"][0]
    return {
        "pending_chains": state["pending_chains"][1:],
        "current_chain_goal": goal,
        "current_chain_steps": [],
        "current_step_payload": goal.first_step,
        "blocked_step_reason": None,
        "chain_step_refused": False,
    }


def make_execute_step(server: AuditedServer):
    async def execute_step(state: dict[str, Any]) -> dict[str, Any]:
        payload: AuditPayload = state["current_step_payload"]
        tool = state["current_tool"]
        outcome = await server.attempt(tool, payload)
        if isinstance(outcome, BlockedPayload):
            return {"blocked_step_reason": outcome.reason}
        if outcome.is_error:
            step = ChainStep.from_error(payload, outcome.content)
        else:
            step = ChainStep.from_response(payload, outcome.content)
        steps = [*state["current_chain_steps"], step]
        return {"current_chain_steps": steps}

    return execute_step


def make_observe_step(llm: LLMPort):
    async def observe_step(state: dict[str, Any]) -> dict[str, Any]:
        steps = list(state["current_chain_steps"])
        goal = state["current_chain_goal"]
        tool = state["current_tool"]
        prompt = build_step_observation_prompt(
            tool=tool,
            goal=goal,
            chain_steps=steps,
        )
        call = ModelCall(tool.name, AuditStep.CHAIN_STEP_OBSERVATION, prompt, StepObservation)
        outcome = await call_model(llm, call)
        if isinstance(outcome, Refused):
            return {"chain_step_refused": True, **outcome.state_update()}
        obs, usage = outcome
        updated_step = steps[-1].with_observation(obs.observation)
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
        call = ModelCall(tool.name, AuditStep.CHAIN_STEP_PLANNING, prompt, AuditPayload)
        outcome = await call_model(llm, call)
        if isinstance(outcome, Refused):
            return {"chain_step_refused": True, **outcome.state_update()}
        payload, usage = outcome
        return {"current_step_payload": payload, "token_usage": [usage]}

    return plan_step


def make_judge_chain(llm: LLMPort):
    async def judge_chain(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        chain = AttackChain(
            goal=state["current_chain_goal"],
            steps=state["current_chain_steps"],
            blocked_reason=state["blocked_step_reason"],
        )
        prompt = build_chain_judge_prompt(tool=tool, chain=chain)
        outcome = await call_model(
            llm, ModelCall(tool.name, AuditStep.CHAIN_JUDGMENT, prompt, Judgment)
        )
        if isinstance(outcome, Refused):
            return {**_completion(chain), **outcome.state_update()}
        judgment, usage = outcome
        eval_result = _chain_eval_result(tool.name, chain, judgment)
        judged_chain = chain.model_copy(update={"eval_result": eval_result})
        return {**_completion(judged_chain), "token_usage": [usage]}

    return judge_chain


def _chain_eval_result(tool_name: str, chain: AttackChain, judgment: Judgment) -> EvalResult:
    last_payload = chain.steps[-1].payload if chain.steps else chain.goal.first_step
    return EvalResult(
        tool_name=tool_name,
        category=chain.goal.category,
        payload=last_payload.arguments,
        verdict=judgment.verdict,
        justification=judgment.justification,
        severity=judgment.severity,
    )


def abandon_chain(state: dict[str, Any]) -> dict[str, Any]:
    chain = AttackChain(
        goal=state["current_chain_goal"],
        steps=[],
        blocked_reason=state["blocked_step_reason"],
    )
    return _completion(chain)


def _completion(chain: AttackChain) -> dict[str, Any]:
    return {
        "completed_chains": [chain],
        "current_chain_goal": None,
        "current_chain_steps": [],
        "blocked_step_reason": None,
        "chain_step_refused": False,
    }


def _route_to_next_chain_or_end(state: dict[str, Any]) -> str:
    if state["pending_chains"]:
        return "prepare_chain"
    return END


route_after_planning = _route_to_next_chain_or_end
route_after_judge = _route_to_next_chain_or_end


def route_after_execute_step(state: dict[str, Any]) -> str:
    if state["blocked_step_reason"] is None:
        return "observe_step"
    if state["current_chain_steps"]:
        return "judge_chain"
    return "abandon_chain"


def route_after_observe(state: dict[str, Any]) -> str:
    if state["chain_step_refused"]:
        return "judge_chain"
    obs = state["current_observation"]
    steps = state["current_chain_steps"]
    max_steps = state["max_chain_steps"]
    if obs.should_continue and len(steps) < max_steps:
        return "plan_step"
    return "judge_chain"


def route_after_plan_step(state: dict[str, Any]) -> str:
    if state["chain_step_refused"]:
        return "judge_chain"
    return "execute_step"


def route_to_chains_or_report(state: dict[str, Any]) -> str:
    if state.get("chain_budget", 0) > 0:
        return "chain_audit_tool"
    return "build_tool_report"
