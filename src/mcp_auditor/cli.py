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
from mcp_auditor.config_file import load_config_file, merge_defaults
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import (
    AttackContext,
    AuditReport,
    Severity,
)
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.domain.rendering import render_json, render_markdown
from mcp_auditor.graph.builder import build_dry_run_graph, build_graph
from mcp_auditor.stream_handler import AuditProgressReporter


@dataclass(frozen=True)
class ReportPaths:
    json: str | None = None
    markdown: str | None = None


@dataclass(frozen=True)
class CIOptions:
    enabled: bool = False
    severity_threshold: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class ExecutionConfig:
    budget: int
    resume: bool
    dry_run: bool


@dataclass(frozen=True)
class AuditConfig:
    execution: ExecutionConfig
    report_paths: ReportPaths
    ci: CIOptions
    tools_filter: frozenset[str] | None = None


def parse_tools_filter(raw: str | None) -> frozenset[str] | None:
    if raw is None or raw.strip() == "":
        return None
    return frozenset(name.strip() for name in raw.split(","))


CONFIG_FILE_NAME = ".mcp-auditor.yml"


@click.group()
@click.version_option()
def cli() -> None:
    """Agentic security testing for MCP servers."""


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
@click.pass_context
def run(
    ctx: click.Context,
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
    params = _merge_with_config_file(ctx)
    config = AuditConfig(
        execution=ExecutionConfig(
            budget=params["budget"],
            resume=params["resume"],
            dry_run=params["dry_run"],
        ),
        report_paths=ReportPaths(json=params["output"], markdown=params["markdown"]),
        ci=CIOptions(
            enabled=params["ci"],
            severity_threshold=Severity(params["severity_threshold"]),
        ),
        tools_filter=parse_tools_filter(params["tools"]),
    )
    asyncio.run(_run_audit(target, config))


def _merge_with_config_file(ctx: click.Context) -> dict[str, Any]:
    file_defaults = load_config_file(Path.cwd() / CONFIG_FILE_NAME)
    explicit_keys = {
        key for key in ctx.params if ctx.get_parameter_source(key) != click.core.ParameterSource.DEFAULT
    }
    return merge_defaults(dict(ctx.params), file_defaults, explicit_keys)


async def _run_audit(target: tuple[str, ...], config: AuditConfig) -> None:
    logging.getLogger("langgraph.checkpoint.serde.jsonplus").setLevel(logging.ERROR)
    command, args = target[0], list(target[1:])
    target_str = " ".join(target)
    display = AuditDisplay(ci_mode=config.ci.enabled)
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
            StdioMCPClient.connect(
                command, args, errlog=server_stderr, tool_call_timeout=settings.tool_call_timeout
            ) as mcp_client,
        ):
            if config.execution.dry_run:
                await _run_dry_run(
                    llm, mcp_client, config.execution.budget, display, config.tools_filter
                )
                return

            graph = build_graph(
                llm,
                mcp_client,
                judge_llm=judge_llm,
                checkpointer=checkpointer,
                tools_filter=config.tools_filter,
            )
            thread_id = (
                _compute_thread_id(command, args)
                if config.execution.resume
                else uuid.uuid4().hex[:16]
            )
            initial_state = (
                None
                if config.execution.resume
                else {
                    "target": target_str,
                    "test_budget": config.execution.budget,
                    "attack_context": AttackContext(),
                }
            )
            graph_config: dict[str, Any] = {
                "configurable": {"thread_id": thread_id},
                "metadata": {
                    "target": target_str,
                    "budget": config.execution.budget,
                    "provider": settings.provider,
                    "model": settings.resolve_model(),
                },
            }

            await _run_full_audit(
                graph, graph_config, initial_state, display, config.report_paths, config.ci
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
    reporter = AuditProgressReporter(display)
    async for event in graph.astream(initial_state, config, stream_mode="updates", subgraphs=True):
        reporter.on_stream_event(event)

    final_state = await graph.aget_state(config)
    report: AuditReport | None = final_state.values.get("audit_report")
    if report is None:
        display.print_error("audit did not produce a report")
        raise SystemExit(1)

    display.print_summary(report)
    display.print_findings_recap(report)
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
    graph = build_dry_run_graph(llm, mcp_client, tools_filter=tools_filter)
    result = await graph.ainvoke(
        {"target": "", "test_budget": budget, "attack_context": AttackContext()}
    )
    tools = result.get("discovered_tools", [])
    display.print_discovery(len(tools), [t.name for t in tools])
    for report in result.get("tool_reports", []):
        display.print_dry_run_payloads(report.tool.name, [c.payload for c in report.cases])


def _compute_thread_id(command: str, args: list[str]) -> str:
    full = " ".join([command, *args])
    return hashlib.sha256(full.encode()).hexdigest()[:16]


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


def _summarize_exception_group(exc_group: BaseExceptionGroup[BaseException]) -> str:
    for exc in exc_group.exceptions:
        if isinstance(exc, BaseExceptionGroup):
            return _summarize_exception_group(exc)
        return str(exc)
    return str(exc_group)


def main() -> None:
    cli()
