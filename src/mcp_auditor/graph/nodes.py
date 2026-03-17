from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.models import (
    AuditCategory,
    AuditReport,
    EvalResult,
    TestCase,
    TestCaseBatch,
    ToolReport,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.prompts import build_attack_generation_prompt, build_judge_prompt


def make_discover_tools(mcp_client: MCPClientPort):
    async def discover_tools(_state: dict[str, Any]) -> dict[str, Any]:
        tools = await mcp_client.list_tools()
        return {"discovered_tools": tools}

    return discover_tools


def make_prepare_tool():
    async def prepare_tool(state: dict[str, Any]) -> dict[str, Any]:
        index = len(state.get("tool_reports", []))
        current = state["discovered_tools"][index]
        return {"current_tool": current}

    return prepare_tool


def make_generate_test_cases(llm: LLMPort):
    async def generate_test_cases(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        budget = state["test_budget"]
        categories = list(AuditCategory)
        prompt = build_attack_generation_prompt(
            tool_name=tool.name,
            tool_description=tool.description,
            input_schema=tool.input_schema,
            budget=budget,
            categories=categories,
        )
        batch = await llm.generate_structured(prompt, TestCaseBatch)
        cases = [TestCase(payload=p) for p in batch.cases]
        return {"pending_cases": cases, "tool_results": []}

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
        prompt = build_judge_prompt(
            tool_name=tool.name,
            tool_description=tool.description,
            test_case=case,
        )
        eval_result = await llm.generate_structured(prompt, EvalResult)
        existing = list(state.get("tool_results", []))
        existing.append(eval_result)
        return {"tool_results": existing, "current_case": None}

    return judge_response


def make_finalize_tool_audit():
    async def finalize_tool_audit(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        results = state["tool_results"]
        report = ToolReport(tool=tool, results=results)
        return {"tool_reports": [report]}

    return finalize_tool_audit


def make_generate_report(llm: LLMPort):
    async def generate_report(state: dict[str, Any]) -> dict[str, Any]:
        target = state["target"]
        reports = state.get("tool_reports", [])
        usage = llm.usage_stats
        return {"audit_report": AuditReport(target=target, tool_reports=reports, token_usage=usage)}

    return generate_report


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
