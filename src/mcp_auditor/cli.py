# pyright: reportUnknownMemberType=false, reportMissingTypeStubs=false, reportArgumentType=false, reportUnknownArgumentType=false
import asyncio
import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.config import load_settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditReport,
    TestCaseBatch,
    ToolDefinition,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.domain.rendering import render_json, render_markdown
from mcp_auditor.graph.builder import build_graph
from mcp_auditor.graph.prompts import build_attack_generation_prompt


@dataclass(frozen=True)
class ReportPaths:
    json: str | None = None
    markdown: str | None = None


@click.group()
@click.version_option()
def cli() -> None:
    """Agentic QA & fuzzing for MCP servers."""


@cli.command()
@click.argument("target", nargs=-1, required=True)
@click.option("--budget", default=10, type=click.IntRange(min=1), help="Test cases per tool.")
@click.option("--output", "-o", type=str, default=None, help="JSON output path.")
@click.option("--markdown", "-m", type=str, default=None, help="Markdown output path.")
@click.option("--resume", is_flag=True, default=False, help="Resume from last checkpoint.")
@click.option("--dry-run", is_flag=True, default=False, help="Generate test cases without running.")
def run(
    target: tuple[str, ...],
    budget: int,
    output: str | None,
    markdown: str | None,
    resume: bool,
    dry_run: bool,
) -> None:
    """Audit an MCP server.

    TARGET is the command to start the MCP server.

    \b
    Examples:
        mcp-auditor run -- python my_server.py
        mcp-auditor run --budget 5 -- npx some-mcp-server
    """
    report_paths = ReportPaths(json=output, markdown=markdown)
    asyncio.run(_run_audit(target, budget, report_paths, resume, dry_run))


async def _run_audit(
    target: tuple[str, ...],
    budget: int,
    report_paths: ReportPaths,
    resume: bool,
    dry_run: bool,
) -> None:
    command, args = target[0], list(target[1:])
    target_str = " ".join(target)
    display = AuditDisplay()
    display.print_header(target_str)

    try:
        settings = load_settings()
        llm = create_llm(settings)
        judge_llm = create_judge_llm(settings)
    except (KeyError, ValueError) as exc:
        click.echo(f"Error: could not initialize LLM: {exc}", err=True)
        raise SystemExit(1) from exc

    checkpoint_dir = Path.home() / ".mcp-auditor"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(checkpoint_dir / "checkpoints.db")

    try:
        async with (
            AsyncSqliteSaver.from_conn_string(db_path) as checkpointer,
            StdioMCPClient.connect(command, args) as mcp_client,
        ):
            if dry_run:
                await _run_dry_run(llm, mcp_client, budget, display)
                return

            graph = build_graph(llm, mcp_client, judge_llm=judge_llm, checkpointer=checkpointer)
            thread_id = _compute_thread_id(command, args) if resume else uuid.uuid4().hex[:16]
            initial_state = None if resume else {"target": target_str, "test_budget": budget}
            config: dict[str, Any] = {
                "configurable": {"thread_id": thread_id},
                "metadata": {
                    "target": target_str,
                    "budget": budget,
                    "provider": settings.provider,
                    "model": settings.resolve_model(),
                },
            }

            await _run_full_audit(graph, config, initial_state, display, report_paths)
    except ConnectionError as exc:
        click.echo(f"Error: could not connect to MCP server: {exc}", err=True)
        raise SystemExit(1) from exc
    except OSError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


async def _run_full_audit(
    graph: Any,
    config: dict[str, Any],
    initial_state: dict[str, Any] | None,
    display: AuditDisplay,
    report_paths: ReportPaths,
) -> None:
    tracker: dict[str, Any] = {"tool_index": 0, "tool_count": 0, "case_indices": {}}
    async for event in graph.astream(initial_state, config, stream_mode="updates", subgraphs=True):
        _handle_stream_event(event, display, tracker)

    final_state = await graph.aget_state(config)
    report: AuditReport | None = final_state.values.get("audit_report")
    if report is None:
        click.echo("Error: audit did not produce a report", err=True)
        raise SystemExit(1)

    display.print_summary_table(report)
    display.print_cost(report.token_usage)
    _write_reports(report, report_paths, display)


async def _run_dry_run(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    budget: int,
    display: AuditDisplay,
) -> None:
    tools = await mcp_client.list_tools()
    display.print_discovery(len(tools), [t.name for t in tools])
    categories = list(AuditCategory)
    for tool in tools:
        prompt = build_attack_generation_prompt(tool=tool, budget=budget, categories=categories)
        batch = await llm.generate_structured(prompt, TestCaseBatch)
        display.print_dry_run_payloads(tool.name, batch.cases)


def _compute_thread_id(command: str, args: list[str]) -> str:
    full = " ".join([command, *args])
    return hashlib.sha256(full.encode()).hexdigest()[:16]


def _handle_stream_event(
    event: tuple[tuple[str, ...], dict[str, Any]],
    display: AuditDisplay,
    tracker: dict[str, Any],
) -> None:
    namespace, updates = event
    for node_name, state_update in updates.items():
        if not isinstance(state_update, dict):
            continue
        if namespace == ():
            _handle_parent_event(node_name, state_update, display, tracker)
        else:
            _handle_subgraph_event(node_name, state_update, display, tracker)


def _handle_parent_event(
    node_name: str,
    state_update: dict[str, Any],
    display: AuditDisplay,
    tracker: dict[str, Any],
) -> None:
    if node_name == "discover_tools":
        tools: list[ToolDefinition] = state_update.get("discovered_tools", [])
        tracker["tool_count"] = len(tools)
        display.print_discovery(len(tools), [t.name for t in tools])
    elif node_name == "prepare_tool":
        tool: ToolDefinition | None = state_update.get("current_tool")
        if tool:
            tracker["tool_index"] += 1
            tracker["case_indices"][tool.name] = 0
    elif node_name == "finalize_tool_audit":
        tool_reports: list[Any] = state_update.get("tool_reports", [])
        if tool_reports:
            tool_report = tool_reports[-1]
            pass_count = sum(
                1
                for c in tool_report.cases
                if c.eval_result and c.eval_result.verdict.value == "pass"
            )
            fail_count = sum(
                1
                for c in tool_report.cases
                if c.eval_result and c.eval_result.verdict.value != "pass"
            )
            display.print_tool_done(tool_report.tool.name, pass_count, fail_count)


def _handle_subgraph_event(
    node_name: str,
    state_update: dict[str, Any],
    display: AuditDisplay,
    tracker: dict[str, Any],
) -> None:
    if node_name == "generate_test_cases":
        pending = state_update.get("pending_cases", [])
        case_count = len(pending)
        tool_index = tracker["tool_index"]
        tool_count = tracker["tool_count"]
        if pending:
            tool_name = pending[0].payload.tool_name
            display.print_tool_start(tool_index, tool_count, tool_name, case_count)
    elif node_name == "judge_response":
        judged = state_update.get("judged_cases", [])
        if judged:
            last_case = judged[-1]
            if last_case.eval_result is not None:
                result = last_case.eval_result
                tool_name = result.tool_name
                tracker["case_indices"].setdefault(tool_name, 0)
                tracker["case_indices"][tool_name] += 1
                case_index = tracker["case_indices"][tool_name]
                case_count = case_index  # approximate, updated as we go
                display.print_verdict(case_index, case_count, result)


def _write_reports(
    report: AuditReport,
    paths: ReportPaths,
    display: AuditDisplay,
) -> None:
    if paths.json:
        Path(paths.json).write_text(render_json(report))
        display.print_report_path(paths.json)
    if paths.markdown:
        Path(paths.markdown).write_text(render_markdown(report))
        display.print_report_path(paths.markdown)


def main() -> None:
    cli()
