# pyright: reportUnknownMemberType=false, reportMissingTypeStubs=false, reportArgumentType=false, reportUnknownArgumentType=false
import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1", category=UserWarning)

import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import click
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

from mcp_auditor.adapters.docker import DockerRuntime, docker_client_env
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.checkpointing import checkpoint_db_path, compute_thread_id, resume_or_reset
from mcp_auditor.config import load_settings
from mcp_auditor.config_file import load_config_file, merge_defaults
from mcp_auditor.console import AuditDisplay, print_server_stderr, summarize_exception_group
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import (
    AttackContext,
    AuditReport,
    Severity,
)
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.builder import build_dry_run_graph, build_graph
from mcp_auditor.report_files import ReportPaths, write_reports
from mcp_auditor.stream_handler import AuditProgressReporter
from mcp_auditor.target_execution import (
    Host,
    LaunchContext,
    LaunchOptions,
    LaunchRefused,
    TargetExecution,
    decide_launch,
)


@dataclass(frozen=True)
class CIOptions:
    enabled: bool = False
    severity_threshold: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class ExecutionConfig:
    budget: int
    chains: int
    resume: bool
    dry_run: bool


@dataclass(frozen=True)
class AuditConfig:
    execution: ExecutionConfig
    report_paths: ReportPaths
    ci: CIOptions
    launch: LaunchOptions
    tools_filter: frozenset[str] | None = None


def parse_tools_filter(raw: str | None) -> frozenset[str] | None:
    if raw is None or raw.strip() == "":
        return None
    return frozenset(name.strip() for name in raw.split(","))


CONFIG_FILE_NAME = ".mcp-auditor.yml"
DEFAULT_MAX_CHAIN_STEPS = 3


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
@click.option(
    "--chains",
    default=0,
    type=click.IntRange(min=0),
    help="Attack chains per tool (0 = disabled). Each chain adds several LLM calls.",
)
@click.option("--ci", is_flag=True, default=False, help="CI mode: plain output, exit 1.")
@click.option(
    "--severity-threshold",
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    default=Severity.MEDIUM.value,
    help="Minimum severity to trigger CI failure.",
)
@click.option(
    "--unconfined",
    is_flag=True,
    default=False,
    help="Launch the server on this host with your privileges, outside any container.",
)
@click.option(
    "--image",
    type=str,
    default=None,
    help="Container image to run the server in, for a launcher the default table does not cover.",
)
@click.option(
    "--mount",
    type=str,
    multiple=True,
    help="Host path to mount into the container, PATH or PATH:rw, read-only by default.",
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
    chains: int,
    ci: bool,
    severity_threshold: str,
    unconfined: bool,
    image: str | None,
    mount: tuple[str, ...],
) -> None:
    """Audit an MCP server.

    TARGET is the command to start the MCP server.

    \b
    Examples:
        mcp-auditor run --unconfined -- python my_server.py
        mcp-auditor run --budget 5 -- npx some-mcp-server
        mcp-auditor run --ci --unconfined -- python my_server.py
    """
    params = _merge_with_config_file(ctx)
    config = AuditConfig(
        execution=ExecutionConfig(
            budget=params["budget"],
            chains=params.get("chains", 0),
            resume=params["resume"],
            dry_run=params["dry_run"],
        ),
        report_paths=ReportPaths(json=params["output"], markdown=params["markdown"]),
        ci=CIOptions(
            enabled=params["ci"],
            severity_threshold=Severity(params["severity_threshold"]),
        ),
        launch=LaunchOptions(
            unconfined=params["unconfined"],
            image=params["image"],
            mounts=tuple(params["mount"]),
        ),
        tools_filter=parse_tools_filter(params["tools"]),
    )
    asyncio.run(_run_audit(target, config))


def _merge_with_config_file(ctx: click.Context) -> dict[str, Any]:
    file_defaults = load_config_file(Path.cwd() / CONFIG_FILE_NAME)
    explicit_keys = {
        key
        for key in ctx.params
        if ctx.get_parameter_source(key) != click.core.ParameterSource.DEFAULT
    }
    return merge_defaults(dict(ctx.params), file_defaults, explicit_keys)


async def _run_audit(target: tuple[str, ...], config: AuditConfig) -> None:
    logging.getLogger("langgraph.checkpoint.serde.jsonplus").setLevel(logging.ERROR)
    display = AuditDisplay(ci_mode=config.ci.enabled)
    context = _launch_context(config)

    try:
        decision = decide_launch(target[0], list(target[1:]), context)
    except LaunchRefused as refusal:
        display.print_error(str(refusal))
        raise SystemExit(1) from refusal
    for warning in decision.warnings:
        display.print_warning(warning)
    launch = decision.launch
    target_str = " ".join([launch.command, *launch.args])
    display.print_header(target_str, launch.regime)

    try:
        settings = load_settings()
        llm = create_llm(settings)
        judge_llm = create_judge_llm(settings)
    except (KeyError, ValueError) as exc:
        display.print_error(f"could not initialize LLM: {exc}")
        raise SystemExit(1) from exc

    execution = TargetExecution(launch, context.runtime)
    server_stderr = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+")  # noqa: SIM115
    try:
        async with (
            execution,
            AsyncSqliteSaver.from_conn_string(checkpoint_db_path()) as checkpointer,
            StdioMCPClient.connect(
                launch,
                errlog=server_stderr,
                tool_call_timeout=settings.tool_call_timeout,
            ) as mcp_client,
        ):
            server = AuditedServer(mcp_client)
            if config.execution.dry_run:
                await _run_dry_run(
                    llm, server, config.execution.budget, display, config.tools_filter
                )
                return

            graph = build_graph(
                llm,
                server,
                judge_llm=judge_llm,
                checkpointer=checkpointer,
                tools_filter=config.tools_filter,
            )
            thread_id = compute_thread_id(launch)
            resuming = await resume_or_reset(graph, thread_id, config.execution.resume)
            if config.execution.resume and not resuming:
                display.print_info("nothing to resume for this target, starting a fresh audit")
            initial_state = (
                None
                if resuming
                else {
                    "target": target_str,
                    "test_budget": config.execution.budget,
                    "chain_budget": config.execution.chains,
                    "max_chain_steps": DEFAULT_MAX_CHAIN_STEPS,
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

            report = await _run_full_audit(graph, graph_config, initial_state, display)
    except ConnectionError as exc:
        display.print_error(f"could not connect to MCP server: {exc}")
        print_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc
    except OSError as exc:
        display.print_error(str(exc))
        print_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc
    except BaseExceptionGroup as exc:
        display.print_error(f"MCP server failed: {summarize_exception_group(exc)}")
        print_server_stderr(server_stderr, display)
        raise SystemExit(1) from exc

    report = report.model_copy(update={"execution": execution.record})
    display.print_summary(report)
    display.print_findings_recap(report)
    write_reports(report, config.report_paths, display)
    if config.ci.enabled and report.has_findings_at_or_above(config.ci.severity_threshold):
        raise SystemExit(1)


def _launch_context(config: AuditConfig) -> LaunchContext:
    return LaunchContext(
        options=config.launch,
        runtime=DockerRuntime(),
        host=Host(
            uid=os.getuid(),
            gid=os.getgid(),
            home=Path.home(),
            docker_env=docker_client_env(os.environ),
        ),
        container_name=f"mcp-auditor-{uuid4().hex[:12]}",
    )


async def _run_full_audit(
    graph: Any,
    config: dict[str, Any],
    initial_state: dict[str, Any] | None,
    display: AuditDisplay,
) -> AuditReport:
    reporter = AuditProgressReporter(display)
    async for event in graph.astream(initial_state, config, stream_mode="updates", subgraphs=True):
        reporter.on_stream_event(event)

    final_state = await graph.aget_state(config)
    report: AuditReport | None = final_state.values.get("audit_report")
    if report is None:
        display.print_error("audit did not produce a report")
        raise SystemExit(1)
    return report


async def _run_dry_run(
    llm: LLMPort,
    server: AuditedServer,
    budget: int,
    display: AuditDisplay,
    tools_filter: frozenset[str] | None,
) -> None:
    graph = build_dry_run_graph(llm, server, tools_filter=tools_filter)
    result = await graph.ainvoke(
        {"target": "", "test_budget": budget, "attack_context": AttackContext()}
    )
    tools = result.get("discovered_tools", [])
    display.print_discovery(len(tools), [t.name for t in tools])
    for report in result.get("tool_reports", []):
        display.print_dry_run_payloads(report.tool.name, [c.payload for c in report.cases])


def main() -> None:
    cli()
