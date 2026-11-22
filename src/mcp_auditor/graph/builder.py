from dataclasses import dataclass
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.chain_nodes import (
    abandon_chain,
    make_execute_step,
    make_judge_chain,
    make_observe_step,
    make_plan_chains,
    make_plan_step,
    make_route_to_chains_or_report,
    prepare_chain,
    route_after_execute_step,
    route_after_judge,
    route_after_observe,
    route_after_plan_step,
    route_after_planning,
)
from mcp_auditor.graph.nodes import (
    build_tool_report,
    collect_generated_cases,
    generate_report,
    make_discover_tools,
    make_execute_tool,
    make_extract_attack_context,
    make_generate_test_cases,
    make_judge_response,
    make_route_tools,
    prepare_tool,
    route_after_discovery,
    route_after_execute,
    route_test_cases,
)
from mcp_auditor.graph.prompts import with_redaction_notice
from mcp_auditor.graph.state import (
    AuditInput,
    AuditToolInput,
    AuditToolState,
    ChainAuditInput,
    ChainAuditState,
    DryRunInput,
    GraphState,
)
from mcp_auditor.graph.unsent_calls import (
    count_unsent_chain,
    make_count_chains_not_planned,
    report_tools_left,
)


def build_graph(
    llm: LLMPort,
    server: AuditedServer,
    judge_llm: LLMPort | None = None,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
    tools_filter: frozenset[str] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    effective_judge = _with_notice_if_redacting(judge_llm or llm, server)
    llm = _with_notice_if_redacting(llm, server)
    audit_subgraph = _build_audit_tool_subgraph(llm, server, effective_judge)
    chain_subgraph = _build_chain_audit_subgraph(llm, server, effective_judge)

    builder: StateGraph[Any, Any, Any, Any] = StateGraph(  # pyrefly: ignore[bad-specialization]
        GraphState,
        input_schema=AuditInput,  # pyrefly: ignore[bad-argument-type]
    )
    builder.add_node("discover_tools", make_discover_tools(server, tools_filter=tools_filter))  # pyrefly: ignore[bad-argument-type]
    builder.add_node("prepare_tool", prepare_tool)
    builder.add_node("audit_tool", audit_subgraph)
    builder.add_node("chain_audit_tool", chain_subgraph)
    builder.add_node("count_chains_not_planned", make_count_chains_not_planned(server))
    builder.add_node("build_tool_report", build_tool_report)
    builder.add_node("extract_attack_context", make_extract_attack_context(llm))
    builder.add_node("report_tools_left", report_tools_left)
    builder.add_node("generate_report", generate_report)
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", route_after_discovery)
    builder.add_edge("prepare_tool", "audit_tool")
    builder.add_conditional_edges(
        "audit_tool",
        make_route_to_chains_or_report(server),
        {
            "chain_audit_tool": "chain_audit_tool",
            "count_chains_not_planned": "count_chains_not_planned",
            "build_tool_report": "build_tool_report",
        },
    )
    builder.add_edge("chain_audit_tool", "build_tool_report")
    builder.add_edge("count_chains_not_planned", "build_tool_report")
    builder.add_edge("build_tool_report", "extract_attack_context")
    builder.add_conditional_edges("extract_attack_context", make_route_tools(server))
    builder.add_edge("report_tools_left", "generate_report")
    return builder.compile(checkpointer=checkpointer)


def _with_notice_if_redacting(llm: LLMPort, server: AuditedServer) -> LLMPort:
    return _RedactionNoticeLLM(llm) if server.redacting else llm


@dataclass(frozen=True)
class _RedactionNoticeLLM:
    llm: LLMPort

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        return await self.llm.generate_structured(with_redaction_notice(prompt), output_schema)


def _build_audit_tool_subgraph(
    llm: LLMPort,
    server: AuditedServer,
    judge_llm: LLMPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(  # pyrefly: ignore[bad-specialization]
        AuditToolState,
        input_schema=AuditToolInput,  # pyrefly: ignore[bad-argument-type]
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("execute_tool", make_execute_tool(server))
    builder.add_node("judge_response", make_judge_response(judge_llm))
    builder.add_edge(START, "generate_test_cases")
    builder.add_conditional_edges(
        "generate_test_cases", route_test_cases, {"execute_tool": "execute_tool", END: END}
    )
    builder.add_conditional_edges(
        "execute_tool",
        route_after_execute,
        {"judge_response": "judge_response", "execute_tool": "execute_tool", END: END},
    )
    builder.add_conditional_edges("judge_response", route_test_cases)
    return builder.compile()


def _build_chain_audit_subgraph(
    llm: LLMPort,
    server: AuditedServer,
    judge_llm: LLMPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(  # pyrefly: ignore[bad-specialization]
        ChainAuditState,
        input_schema=ChainAuditInput,  # pyrefly: ignore[bad-argument-type]
    )
    builder.add_node("plan_chains", make_plan_chains(llm))
    builder.add_node("prepare_chain", prepare_chain)
    builder.add_node("execute_step", make_execute_step(server))
    builder.add_node("observe_step", make_observe_step(llm))
    builder.add_node("plan_step", make_plan_step(llm))
    builder.add_node("judge_chain", make_judge_chain(judge_llm))
    builder.add_node("abandon_chain", abandon_chain)
    builder.add_node("count_unsent_chain", count_unsent_chain)
    builder.add_edge(START, "plan_chains")
    builder.add_conditional_edges("plan_chains", route_after_planning)
    builder.add_edge("prepare_chain", "execute_step")
    builder.add_conditional_edges(
        "execute_step",
        route_after_execute_step,
        {
            "observe_step": "observe_step",
            "judge_chain": "judge_chain",
            "abandon_chain": "abandon_chain",
            "count_unsent_chain": "count_unsent_chain",
        },
    )
    builder.add_conditional_edges("observe_step", route_after_observe)
    builder.add_conditional_edges(
        "plan_step",
        route_after_plan_step,
        {"execute_step": "execute_step", "judge_chain": "judge_chain"},
    )
    builder.add_conditional_edges("judge_chain", route_after_judge)
    builder.add_conditional_edges("abandon_chain", route_after_judge)
    builder.add_conditional_edges("count_unsent_chain", route_after_judge)
    return builder.compile()


def build_dry_run_graph(
    llm: LLMPort,
    server: AuditedServer,
    tools_filter: frozenset[str] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    subgraph = _build_generate_only_subgraph(_with_notice_if_redacting(llm, server))

    builder: StateGraph[Any, Any, Any, Any] = StateGraph(  # pyrefly: ignore[bad-specialization]
        GraphState,
        input_schema=DryRunInput,  # pyrefly: ignore[bad-argument-type]
    )
    builder.add_node("discover_tools", make_discover_tools(server, tools_filter=tools_filter))  # pyrefly: ignore[bad-argument-type]
    builder.add_node("prepare_tool", prepare_tool)
    builder.add_node("generate_cases", subgraph)
    builder.add_node("build_tool_report", build_tool_report)
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", _route_to_tools_or_end)
    builder.add_edge("prepare_tool", "generate_cases")
    builder.add_edge("generate_cases", "build_tool_report")
    builder.add_conditional_edges("build_tool_report", _route_to_next_tool_or_end)
    return builder.compile()


def _build_generate_only_subgraph(llm: LLMPort) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(  # pyrefly: ignore[bad-specialization]
        AuditToolState,
        input_schema=AuditToolInput,  # pyrefly: ignore[bad-argument-type]
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("collect_cases", collect_generated_cases)
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
