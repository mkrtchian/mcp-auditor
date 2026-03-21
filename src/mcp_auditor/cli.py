# pyright: reportUnknownMemberType=false, reportMissingTypeStubs=false, reportArgumentType=false, reportUnknownArgumentType=false
import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1", category=UserWarning)

import asyncio
import hashlib
import logging
import tempfile
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
    Severity,
    TestCaseBatch,
    ToolDefinition,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.domain.rendering import render_json, render_markdown
from mcp_auditor.graph.builder import build_graph
from mcp_auditor.graph.nodes import filter_tools
from mcp_auditor.graph.prompts import build_attack_generation_prompt


@dataclass(frozen=True)
class ReportPaths:
    json: str | None = None
    markdown: str | None = None


@dataclass(frozen=True)
class CIOptions:
    enabled: bool = False
    severity_threshold: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class AuditOptions:
    budget: int
    report_paths: ReportPaths
    resume: bool
    dry_run: bool
    ci: CIOptions = CIOptions()
    tools_filter: frozenset[str] | None = None


@dataclass
class StreamTracker:
    tool_index: int = 0
    tool_count: int = 0
    active_progress: Any = None


def parse_tools_filter(raw: str | None) -> frozenset[str] | None:
    if raw is None or raw.strip() == "":
        return None
    return frozenset(name.strip() for name in raw.split(","))


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
@click.option("--tools", type=str, default=None, help="Comma-separated tool names to audit.")
@click.option("--dry-run", is_flag=True, default=False, help="Generate test cases without running.")
@click.option("--ci", is_flag=True, default=False, help="CI mode: plain output, exit 1.")
@click.option(
    "--severity-threshold",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=Severity.MEDIUM.value,
    help="Minimum severity to trigger CI failure.",
)
def run(
    target: tuple[str, ...],
    budget: int,
    output: str | None,
    markdown: str | None,
    tools: str | None,
    resume: bool,
    dry_run: bool,
    ci: bool,
    severity_threshold: str,
) -> None:
    """Audit an MCP server.

    TARGET is the command to start the MCP server.

    \b
    Examples:
        mcp-auditor run -- python my_server.py
        mcp-auditor run --budget 5 -- npx some-mcp-server
        mcp-auditor run --ci -- python my_server.py
    """
    options = AuditOptions(
        budget=budget,
        report_paths=ReportPaths(json=output, markdown=markdown),
        resume=resume,
        dry_run=dry_run,
        ci=CIOptions(enabled=ci, severity_threshold=Severity(severity_threshold)),
        tools_filter=parse_tools_filter(tools),
    )
    asyncio.run(_run_audit(target, options))


async def _run_audit(target: tuple[str, ...], options: AuditOptions) -> None:
    logging.getLogger("langgraph.checkpoint.serde.jsonplus").setLevel(logging.ERROR)
    command, args = target[0], list(target[1:])
    target_str = " ".join(target)
    display = AuditDisplay(ci_mode=options.ci.enabled)
    display.print_header(target_str)

    try:
        settings = load_settings()
        llm = create_llm(settings)
        judge_llm = create_judge_llm(settings)
    except (KeyError, ValueError) as exc:
        display.print_error(f"could not initialize LLM: {exc}")
        raise SystemExit(1) from exc

    checkpoint_dir = Path.home() / ".mcp-auditor"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(checkpoint_dir / "checkpoints.db")

    server_stderr = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+")  # noqa: SIM115
    try:
        async with (
            AsyncSqliteSaver.from_conn_string(db_path) as checkpointer,
            StdioMCPClient.connect(command, args, errlog=server_stderr) as mcp_client,
        ):
            if options.dry_run:
                await _run_dry_run(llm, mcp_client, options.budget, display, options.tools_filter)
                return

            graph = build_graph(
                llm,
                mcp_client,
                judge_llm=judge_llm,
                checkpointer=checkpointer,
                tools_filter=options.tools_filter,
            )
            thread_id = (
                _compute_thread_id(command, args) if options.resume else uuid.uuid4().hex[:16]
            )
            initial_state = (
                None if options.resume else {"target": target_str, "test_budget": options.budget}
            )
            config: dict[str, Any] = {
                "configurable": {"thread_id": thread_id},
                "metadata": {
                    "target": target_str,
                    "budget": options.budget,
                    "provider": settings.provider,
                    "model": settings.resolve_model(),
                },
            }

            await _run_full_audit(
                graph, config, initial_state, display, options.report_paths, options.ci
            )
    except ConnectionError as exc:
        display.print_error(f"could not connect to MCP server: {exc}")
        _show_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc
    except OSError as exc:
        display.print_error(str(exc))
        _show_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc
    except BaseExceptionGroup as exc:
        display.print_error(f"MCP server failed: {_summarize_exception_group(exc)}")
        _show_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc


async def _run_full_audit(
    graph: Any,
    config: dict[str, Any],
    initial_state: dict[str, Any] | None,
    display: AuditDisplay,
    report_paths: ReportPaths,
    ci: CIOptions = CIOptions(),  # noqa: B008
) -> None:
    tracker = StreamTracker()
    async for event in graph.astream(initial_state, config, stream_mode="updates", subgraphs=True):
        _handle_stream_event(event, display, tracker)

    final_state = await graph.aget_state(config)
    report: AuditReport | None = final_state.values.get("audit_report")
    if report is None:
        display.print_error("audit did not produce a report")
        raise SystemExit(1)

    display.print_summary(report)
    _write_reports(report, report_paths, display)

    if ci.enabled and report.has_findings_at_or_above(ci.severity_threshold):
        raise SystemExit(1)


async def _run_dry_run(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    budget: int,
    display: AuditDisplay,
    tools_filter: frozenset[str] | None = None,
) -> None:
    with display.status("Discovering tools..."):
        tools = await mcp_client.list_tools()
        tools = filter_tools(tools, tools_filter)
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
    tracker: StreamTracker,
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
    tracker: StreamTracker,
) -> None:
    if node_name == "discover_tools":
        tools: list[ToolDefinition] = state_update.get("discovered_tools", [])
        tracker.tool_count = len(tools)
        display.print_discovery(len(tools), [t.name for t in tools])
    elif node_name == "prepare_tool":
        tool: ToolDefinition | None = state_update.get("current_tool")
        if tool:
            tracker.tool_index += 1
    elif node_name == "finalize_tool_audit":
        if tracker.active_progress:
            tracker.active_progress.__exit__(None, None, None)
            tracker.active_progress = None


def _handle_subgraph_event(
    node_name: str,
    state_update: dict[str, Any],
    display: AuditDisplay,
    tracker: StreamTracker,
) -> None:
    if node_name == "generate_test_cases":
        pending = state_update.get("pending_cases", [])
        if pending:
            tool_name = pending[0].payload.tool_name
            progress = display.create_tool_progress(
                tracker.tool_index, tracker.tool_count, tool_name, len(pending)
            )
            progress.__enter__()
            tracker.active_progress = progress
    elif node_name == "judge_response":
        judged = state_update.get("judged_cases", [])
        if judged:
            last_case = judged[-1]
            if last_case.eval_result is not None and tracker.active_progress:
                tracker.active_progress.advance(last_case.eval_result)


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


def _show_server_stderr(
    server_stderr: tempfile.SpooledTemporaryFile[str], display: AuditDisplay
) -> None:
    server_stderr.seek(0)
    output = server_stderr.read().strip()
    if output:
        display.print_error(f"server stderr:\n{output}")


def _summarize_exception_group(group: BaseExceptionGroup[BaseException]) -> str:
    for exc in group.exceptions:
        if isinstance(exc, BaseExceptionGroup):
            return _summarize_exception_group(exc)
        return str(exc)
    return str(group)


def main() -> None:
    cli()
