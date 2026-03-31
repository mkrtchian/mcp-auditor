from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditReport,
    EvalResult,
    TestCase,
    TestCaseBatch,
    TokenUsage,
    ToolReport,
    filter_tools,
    order_tools_for_audit,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_context_extraction_prompt,
    build_judge_prompt,
)


def make_discover_tools(mcp_client: MCPClientPort, tools_filter: frozenset[str] | None = None):
    async def discover_tools(_state: dict[str, Any]) -> dict[str, Any]:
        tools = await mcp_client.list_tools()
        filtered = filter_tools(tools, tools_filter)
        ordered = order_tools_for_audit(filtered)
        return {"discovered_tools": ordered}

    return discover_tools


async def prepare_tool(state: dict[str, Any]) -> dict[str, Any]:
    index = len(state.get("tool_reports", []))
    current = state["discovered_tools"][index]
    return {"current_tool": current}


def make_generate_test_cases(llm: LLMPort):
    async def generate_test_cases(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        budget = state["test_budget"]
        attack_context = state["attack_context"]
        categories = list(AuditCategory)
        prompt = build_attack_generation_prompt(
            tool=tool, budget=budget, categories=categories, attack_context=attack_context
        )
        batch, usage = await llm.generate_structured(prompt, TestCaseBatch)
        cases = [TestCase(payload=p) for p in batch.cases]
        return {"pending_cases": cases, "judged_cases": [], "token_usage": [usage]}

    return generate_test_cases


def make_execute_tool(mcp_client: MCPClientPort):
    async def execute_tool(state: dict[str, Any]) -> dict[str, Any]:
        pending = list(state["pending_cases"])
        case = pending.pop(0)
        response = await mcp_client.call_tool(case.payload.tool_name, case.payload.arguments)
        if response.is_error:
            case = case.model_copy(update={"error": response.content, "response": None})
        else:
            case = case.model_copy(update={"response": response.content})
        return {"current_case": case, "pending_cases": pending}

    return execute_tool


def make_judge_response(llm: LLMPort):
    async def judge_response(state: dict[str, Any]) -> dict[str, Any]:
        case = state["current_case"]
        tool = state["current_tool"]
        prompt = build_judge_prompt(tool=tool, test_case=case)
        eval_result, usage = await llm.generate_structured(prompt, EvalResult)
        judged_case = case.model_copy(update={"eval_result": eval_result})
        return {"judged_cases": [judged_case], "current_case": None, "token_usage": [usage]}

    return judge_response


async def collect_generated_cases(state: dict[str, Any]) -> dict[str, Any]:
    return {"judged_cases": state["pending_cases"], "pending_cases": []}


async def build_tool_report(state: dict[str, Any]) -> dict[str, Any]:
    tool = state["current_tool"]
    cases = state["judged_cases"]
    chains = state.get("completed_chains", [])
    report = ToolReport(tool=tool, cases=cases, chains=chains)
    return {"tool_reports": [report]}


def make_extract_attack_context(llm: LLMPort):
    async def extract_attack_context(state: dict[str, Any]) -> dict[str, Any]:
        tool_report = state["tool_reports"][-1]
        existing_context = state["attack_context"]
        prompt = build_context_extraction_prompt(tool_report, existing_context)
        new_context, usage = await llm.generate_structured(prompt, AttackContext)
        return {"attack_context": new_context, "token_usage": [usage]}

    return extract_attack_context


async def generate_report(state: dict[str, Any]) -> dict[str, Any]:
    target = state["target"]
    reports = state.get("tool_reports", [])
    usage = _sum_token_usage(state.get("token_usage", []))
    return {"audit_report": AuditReport(target=target, tool_reports=reports, token_usage=usage)}


def _sum_token_usage(usages: list[TokenUsage]) -> TokenUsage:
    total = TokenUsage()
    for u in usages:
        total = total.add(u)
    return total


def route_after_discovery(state: dict[str, Any]) -> str:
    if state["discovered_tools"]:
        return "prepare_tool"
    return "generate_report"


def route_test_cases(state: dict[str, Any]) -> str:
    if state["pending_cases"]:
        return "execute_tool"
    return END


def route_tools(state: dict[str, Any]) -> str:
    if len(state["tool_reports"]) < len(state["discovered_tools"]):
        return "prepare_tool"
    return "generate_report"
