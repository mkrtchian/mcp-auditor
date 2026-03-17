# pyright: reportUnknownMemberType=false, reportArgumentType=false
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver  # type: ignore[import-untyped]
from langgraph.graph import START, StateGraph  # type: ignore[import-untyped]
from langgraph.graph.state import CompiledStateGraph  # type: ignore[import-untyped]

from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.nodes import (
    make_discover_tools,
    make_execute_tool,
    make_finalize_tool_audit,
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
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    audit_subgraph = _build_audit_tool_subgraph(llm, mcp_client)

    builder: StateGraph[Any, Any, Any, Any] = StateGraph(GraphState)
    builder.add_node("discover_tools", make_discover_tools(mcp_client))
    builder.add_node("prepare_tool", make_prepare_tool())
    builder.add_node("audit_tool", audit_subgraph)
    builder.add_node("finalize_tool_audit", make_finalize_tool_audit())
    builder.add_node("generate_report", make_generate_report(llm))
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", route_after_discovery)
    builder.add_edge("prepare_tool", "audit_tool")
    builder.add_edge("audit_tool", "finalize_tool_audit")
    builder.add_conditional_edges("finalize_tool_audit", route_tools)
    return builder.compile(checkpointer=checkpointer)


def _build_audit_tool_subgraph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(
        AuditToolState, input_schema=AuditToolInput
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("execute_tool", make_execute_tool(mcp_client))
    builder.add_node("judge_response", make_judge_response(llm))
    builder.add_edge(START, "generate_test_cases")
    builder.add_edge("generate_test_cases", "execute_tool")
    builder.add_edge("execute_tool", "judge_response")
    builder.add_conditional_edges("judge_response", route_test_cases)
    return builder.compile()
