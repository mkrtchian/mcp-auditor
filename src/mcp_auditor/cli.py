import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1", category=UserWarning)

import asyncio
import logging
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import click

from mcp_auditor.adapters.docker import DockerRuntime, docker_client_env
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import (
    Analysts,
    Audit,
    AuditConfig,
    CIOptions,
    ExecutionConfig,
)
from mcp_auditor.config_file import load_config_file, merge_defaults
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import AuditReport, Severity
from mcp_auditor.report_files import ReportPaths, write_reports
from mcp_auditor.target_execution import (
    Host,
    LaunchContext,
    LaunchOptions,
    LaunchRefused,
    TargetExecution,
    decide_launch,
)

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
@click.option(
    "--chains",
    default=0,
    type=click.IntRange(min=0),
    help="Attack chains per tool (0 = disabled). Each chain adds several LLM calls.",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="CI mode: plain output, exit 1 on findings, 3 on an incomplete audit.",
)
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


def parse_tools_filter(raw: str | None) -> frozenset[str] | None:
    if raw is None or raw.strip() == "":
        return None
    return frozenset(name.strip() for name in raw.split(","))


async def _run_audit(target: tuple[str, ...], config: AuditConfig) -> None:
    logging.getLogger("langgraph.checkpoint.serde.jsonplus").setLevel(logging.ERROR)
    display = AuditDisplay(ci_mode=config.ci.enabled)
    context = _launch_context(config)
    launch = _decided_launch(target, context, display)
    display.print_header(launch.target, launch.regime)

    audit = Audit(
        config=config,
        execution=TargetExecution(launch, context.runtime),
        analysts=_hired_analysts(display),
        display=display,
    )
    report = await audit.run()
    if report is not None:
        _deliver(report, config, display)


def _deliver(report: AuditReport, config: AuditConfig, display: AuditDisplay) -> None:
    display.print_summary(report)
    display.print_findings_recap(report)
    write_reports(report, config.report_paths, display)
    exit_code = ci_exit_code(report, config.ci)
    if exit_code != 0:
        raise SystemExit(exit_code)


def ci_exit_code(report: AuditReport, ci: CIOptions) -> int:
    if not ci.enabled:
        return 0
    if report.has_findings_at_or_above(ci.severity_threshold):
        return 1
    return 0 if report.is_complete else 3


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


def _decided_launch(
    target: tuple[str, ...], context: LaunchContext, display: AuditDisplay
) -> ServerLaunch:
    try:
        decision = decide_launch(target[0], list(target[1:]), context)
    except LaunchRefused as refusal:
        display.print_error(str(refusal))
        raise SystemExit(1) from refusal
    for warning in decision.warnings:
        display.print_warning(warning)
    return decision.launch


# Hired after the launch decision, never before: a target the auditor refuses to launch is
# refused the same way on a machine that holds an API key and on one that does not.
def _hired_analysts(display: AuditDisplay) -> Analysts:
    try:
        return Analysts.hired()
    except (KeyError, ValueError) as exc:
        display.print_error(f"could not initialize LLM: {exc}")
        raise SystemExit(1) from exc


def main() -> None:
    cli()
