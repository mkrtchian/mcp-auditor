"""One audit of one admitted server on its patched image, with the suite's retry policy: a
refused or unreadable step is kept and counted downstream, a launch failure or a throttled
attempt is retried."""

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.console import Console
from rich.markup import escape

from evals.cve_audit import INCOMPLETE_ATTEMPTS, Auditor, RunOverrides, describe_miss_causes
from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve_planting_base import (
    SymbolicUser,
    confinement_args,
    host_user_args,
    no_network_args,
    unprivileged_user_args,
)
from evals.metrics import missed_steps
from evals.nuisance_admission import AdmittedServer, BenignCall
from evals.nuisance_counter import flagged_tools
from evals.nuisance_counting import counted_flaws, counted_tools
from evals.nuisance_images import image_tag
from evals.nuisance_results import NotRunCause
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, MissCause
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.builder import build_graph

console = Console()

NUISANCE_INFRA_ATTEMPTS = 3  # one try, two retries

_INCOMPLETE_CAUSES = frozenset({MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER})


def nuisance_launch(server: AdmittedServer) -> Launch:
    """The patched image under the acceptance confinement, with no mount, no layout and no
    planting. The user, working directory and network come from `server.host`. A networked host
    gets the plain default bridge with egress: no sidecar, holder or planted endpoint, since
    nothing is planted."""
    host = server.host
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *_user_args(host.user),
            "-w",
            host.working_directory,
            *_network_args(host.has_network),
            image_tag(server.service),
            *server.launch,
        ],
    )


def _user_args(user: SymbolicUser) -> list[str]:
    match user:
        case SymbolicUser.HOST:
            return host_user_args()
        case SymbolicUser.UNPRIVILEGED:
            return unprivileged_user_args()


def _network_args(has_network: bool) -> list[str]:
    return ["--network", "bridge"] if has_network else no_network_args()


async def benign_call_failure(server: AdmittedServer, mcp_client: MCPClientPort) -> str | None:
    counted = counted_tools(server)
    calls: dict[str, BenignCall] = {}
    for flaw in counted_flaws(server):
        for call in flaw.benign_calls:
            if call.tool in counted:
                calls.setdefault(call.tool, call)
    for tool, call in calls.items():
        try:
            response = await mcp_client.call_tool(tool, call.arguments)
        except Exception as exc:
            return f"benign call of {tool!r} failed: {exc}"
        if response.is_error:
            return f"benign call of {tool!r} returned an error: {response.content}"
    return None


@dataclass(frozen=True)
class LaunchFailed:
    reason: str


@dataclass(frozen=True)
class DroppedRun:
    """A run that never produced a report, which drops its server from the nuisance run."""

    cause: NotRunCause


async def audit_once(
    server: AdmittedServer, auditor: Auditor, overrides: RunOverrides
) -> AuditReport | LaunchFailed:
    launch = nuisance_launch(server)
    try:
        report = await _audit(launch, auditor, overrides)
    except Exception as exc:
        return LaunchFailed(str(exc))
    _print_incidents(server, report)
    return report


async def _audit(launch: Launch, auditor: Auditor, overrides: RunOverrides) -> AuditReport:
    timeout = _either(overrides.tool_call_timeout, TOOL_CALL_TIMEOUT)
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull, tool_call_timeout=timeout) as client:
            graph = build_graph(
                auditor.llm, AuditedServer(client), judge_llm=auditor.judge_llm, tools_filter=None
            )
            with one_audit():
                result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                    {
                        "target": f"{launch.command} {' '.join(launch.args)}",
                        "test_budget": auditor.budget,
                        "attack_context": AttackContext(),
                        "chain_budget": _either(overrides.chain_budget, launch.chain_budget),
                        "max_chain_steps": _either(
                            overrides.max_chain_steps, launch.max_chain_steps
                        ),
                    }
                )
            return result["audit_report"]


def _either(forced: int | None, own: int) -> int:
    return own if forced is None else forced


def _print_incidents(server: AdmittedServer, report: AuditReport) -> None:
    for missed in missed_steps(report):
        console.print(f"[yellow]{server.server_package}: {escape(missed)}[/yellow]")
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{server.server_package}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def nuisance_audit(
    server: AdmittedServer, attempt: Callable[[], Awaitable[AuditReport | LaunchFailed]]
) -> AuditReport | DroppedRun:
    """One run of one server, at most `NUISANCE_INFRA_ATTEMPTS` calls. A report with no
    throttled step stands, an alarm in it whatever step was refused. A throttled report or a
    launch failure is retried, and the run drops as throttled when any attempt was."""
    throttled = False
    for number in range(1, NUISANCE_INFRA_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, AuditReport) and not _is_throttled(outcome):
            return outcome
        throttled = throttled or isinstance(outcome, AuditReport)
        failure = (
            "throttled by the model provider past every retry"
            if isinstance(outcome, AuditReport)
            else f"run failed to launch ({escape(outcome.reason)})"
        )
        console.print(
            f"[yellow]{server.server_package}: {failure},"
            f" attempt {number}/{NUISANCE_INFRA_ATTEMPTS}[/yellow]"
        )
    return DroppedRun(NotRunCause.THROTTLED if throttled else NotRunCause.LAUNCH_FAILURE)


def _is_throttled(report: AuditReport) -> bool:
    return any(missed.cause is MissCause.PROVIDER_THROTTLED for missed in report.missed_steps)


@dataclass(frozen=True)
class GateRun:
    flagged: bool
    report: AuditReport


async def gate_run(
    server: AdmittedServer, audit: Callable[[], Awaitable[AuditReport | DroppedRun]]
) -> GateRun | None:
    """One run of the nuisance gate, at most `INCOMPLETE_ATTEMPTS` audits: the acceptance gate's
    policy on an incomplete attempt, with an alarm in place of a detection, unlike the nuisance
    run's. A counted alarm stands whatever step was refused, an incomplete audit without one is
    attempted again, and the run does not complete when every attempt stays incomplete."""
    causes: frozenset[MissCause] = frozenset()
    for number in range(1, INCOMPLETE_ATTEMPTS + 1):
        outcome = await audit()
        if isinstance(outcome, DroppedRun):
            return None
        flagged = bool(flagged_tools(outcome, counted_tools(server)))
        if flagged or not is_incomplete(outcome):
            return GateRun(flagged=flagged, report=outcome)
        attempt_causes = _incomplete_causes(outcome)
        causes |= attempt_causes
        console.print(
            f"[yellow]{server.server_package}: attempt {number}/{INCOMPLETE_ATTEMPTS}:"
            f" {describe_miss_causes(attempt_causes)}, no counted alarm, attempted again[/yellow]"
        )
    console.print(
        f"[yellow]{server.server_package} run did not complete:[/yellow] a step missed at all"
        f" {INCOMPLETE_ATTEMPTS} attempts ({describe_miss_causes(causes)})"
    )
    return None


def _incomplete_causes(report: AuditReport) -> frozenset[MissCause]:
    return frozenset(
        missed.cause for missed in report.missed_steps if missed.cause in _INCOMPLETE_CAUSES
    )


def is_incomplete(report: AuditReport) -> bool:
    return any(missed.cause in _INCOMPLETE_CAUSES for missed in report.missed_steps)
