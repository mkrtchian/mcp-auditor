# pyright: reportUnknownMemberType=false, reportArgumentType=false
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver  # type: ignore[import-untyped]
from langgraph.graph import END, START, StateGraph  # type: ignore[import-untyped]
from langgraph.graph.state import CompiledStateGraph  # type: ignore[import-untyped]

from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.nodes import (
    make_build_tool_report,
    make_collect_generated_cases,
    make_discover_tools,
    make_execute_tool,
    make_extract_attack_context,
    make_generate_report,
    make_generate_test_cases,
    make_judge_response,
    make_prepare_tool,
    route_after_discovery,
    route_test_cases,
    route_tools,
)
from mcp_auditor.graph.state import AuditToolInput, AuditToolState, GraphState


def build_graph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    judge_llm: LLMPort | None = None,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
    tools_filter: frozenset[str] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    effective_judge = judge_llm or llm
    audit_subgraph = _build_audit_tool_subgraph(llm, mcp_client, effective_judge)

    builder: StateGraph[Any, Any, Any, Any] = StateGraph(GraphState)
    builder.add_node("discover_tools", make_discover_tools(mcp_client, tools_filter=tools_filter))
    builder.add_node("prepare_tool", make_prepare_tool())
    builder.add_node("audit_tool", audit_subgraph)
    builder.add_node("build_tool_report", make_build_tool_report())
    builder.add_node("extract_attack_context", make_extract_attack_context(llm))
    builder.add_node("generate_report", make_generate_report())
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", route_after_discovery)
    builder.add_edge("prepare_tool", "audit_tool")
    builder.add_edge("audit_tool", "build_tool_report")
    builder.add_edge("build_tool_report", "extract_attack_context")
    builder.add_conditional_edges("extract_attack_context", route_tools)
    return builder.compile(checkpointer=checkpointer)


def _build_audit_tool_subgraph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    judge_llm: LLMPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(
        AuditToolState, input_schema=AuditToolInput
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("execute_tool", make_execute_tool(mcp_client))
    builder.add_node("judge_response", make_judge_response(judge_llm))
    builder.add_edge(START, "generate_test_cases")
    builder.add_edge("generate_test_cases", "execute_tool")
    builder.add_edge("execute_tool", "judge_response")
    builder.add_conditional_edges("judge_response", route_test_cases)
    return builder.compile()


def build_dry_run_graph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    tools_filter: frozenset[str] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    subgraph = _build_generate_only_subgraph(llm)

    builder: StateGraph[Any, Any, Any, Any] = StateGraph(GraphState)
    builder.add_node("discover_tools", make_discover_tools(mcp_client, tools_filter=tools_filter))
    builder.add_node("prepare_tool", make_prepare_tool())
    builder.add_node("generate_cases", subgraph)
    builder.add_node("build_tool_report", make_build_tool_report())
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", _route_to_tools_or_end)
    builder.add_edge("prepare_tool", "generate_cases")
    builder.add_edge("generate_cases", "build_tool_report")
    builder.add_conditional_edges("build_tool_report", _route_to_next_tool_or_end)
    return builder.compile()


def _build_generate_only_subgraph(
    llm: LLMPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(
        AuditToolState, input_schema=AuditToolInput
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("collect_cases", make_collect_generated_cases())
    builder.add_edge(START, "generate_test_cases")
    builder.add_edge("generate_test_cases", "collect_cases")
    return builder.compile()


def _route_to_tools_or_end(state: dict[str, Any]) -> str:
    if state["discovered_tools"]:
        return "prepare_tool"
    return END


def _route_to_next_tool_or_end(state: dict[str, Any]) -> str:
    if len(state["tool_reports"]) < len(state["discovered_tools"]):
        return "prepare_tool"
    return END
