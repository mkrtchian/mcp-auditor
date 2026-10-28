"""One audit of one admitted server on its patched image, with the suite's retry policy: a
refused or unreadable step is kept and counted downstream, a launch failure, a throttled attempt
or a transient provider error is retried, and a fatal provider error stops the run."""

import os
from collections.abc import Awaitable, Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from rich.markup import escape

from evals.audit_attempts import INCOMPLETE_ATTEMPTS, describe_miss_causes
from evals.concurrency import entered_in_thread
from evals.cve_audit import Auditor, RunOverrides
from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve_planting_base import confinement_args, no_network_args
from evals.cve_recording_client import RecordingClient
from evals.doris_backend import user_args
from evals.eval_display import console
from evals.failure_text import ReportDetail
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer, BenignCall
from evals.nuisance_backends import BACKENDS, RegisteredBackend
from evals.nuisance_counter import flagged_tools
from evals.nuisance_counting import counted_flaws, counted_tools
from evals.nuisance_images import image_tag
from evals.nuisance_results import NotRunCause
from evals.provider_errors import (
    AuditFailed,
    ProviderErrorKind,
    ProviderFatal,
    audit_failures_unwrapped,
    classified,
    describe_provider_error,
)
from evals.server_health import ServerHealth, health_of
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, MissCause
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.builder import build_graph

NUISANCE_INFRA_ATTEMPTS = 3  # one try, two retries

_INCOMPLETE_CAUSES = frozenset({MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER})


@contextmanager
def nuisance_environment(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend] = BACKENDS
) -> Generator[Launch]:
    """The launch of one server on its patched image. With no backend fixture it is the current
    single-container launch; with one it delegates to the registered provisioner, which brings
    the backend up and yields the server launch wired to it. The provisioner owns the network, so
    a backend server's launch never goes through `_network_args`."""
    if server.backend is None:
        yield _single_container_launch(server)
    else:
        with backends[server.backend.provisioner].provisioner(server) as launch:
            yield launch


def _single_container_launch(server: AdmittedServer) -> Launch:
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
            *user_args(host.user),
            "-w",
            host.working_directory,
            *_network_args(host.has_network),
            image_tag(server.service),
            *server.launch,
        ],
    )


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
class ProviderError:
    """A transient provider error, its reason the error's type and status, never its message."""

    reason: str


@dataclass(frozen=True)
class DroppedRun:
    """A run that never produced a report, which drops its server from the nuisance run."""

    cause: NotRunCause


@dataclass(frozen=True)
class NuisanceAudit:
    report: AuditReport
    health: ServerHealth


@dataclass(frozen=True)
class NuisanceAuditor:
    auditor: Auditor
    overrides: RunOverrides
    throttles: SessionThrottles


async def audit_once(
    server: AdmittedServer,
    auditor: NuisanceAuditor,
    *,
    backends: Mapping[str, RegisteredBackend] = BACKENDS,
) -> NuisanceAudit | LaunchFailed | ProviderError:
    """Raises `ProviderFatal` on a provider error no retry cures."""
    # The provisioner blocks for minutes and `DORIS_LAUNCH_LOCK` is a thread lock, so a plain
    # `with` inside the coroutine would freeze the loop and deadlock the server's gathered runs.
    try:
        with audit_failures_unwrapped():
            async with entered_in_thread(nuisance_environment(server, backends)) as launch:
                audit = await _audit(launch, auditor.auditor, auditor.overrides)
    except AuditFailed as failure:
        if failure.kind is ProviderErrorKind.FATAL:
            raise ProviderFatal(failure.cause) from failure.cause
        return ProviderError(describe_provider_error(failure.cause))
    except Exception as exc:
        return LaunchFailed(auditor.auditor.report_detail.describe(exc))
    auditor.throttles.count(audit.report)
    _print_incidents(server, audit.report, auditor.auditor.report_detail)
    _print_lost_connections(server, audit.health)
    return audit


async def _audit(launch: Launch, auditor: Auditor, overrides: RunOverrides) -> NuisanceAudit:
    timeout = _either(overrides.tool_call_timeout, TOOL_CALL_TIMEOUT)
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull, tool_call_timeout=timeout) as client:
            recorder = RecordingClient(client)
            graph = build_graph(
                auditor.llm, AuditedServer(recorder), judge_llm=auditor.judge_llm, tools_filter=None
            )
            with one_audit():
                result = await classified(
                    graph.ainvoke(  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
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
                )
            return NuisanceAudit(result["audit_report"], health_of(client, recorder.exchanges))


def _either(forced: int | None, own: int) -> int:
    return own if forced is None else forced


def _print_lost_connections(server: AdmittedServer, health: ServerHealth) -> None:
    if health.lost_connection_responses > 0:
        console.print(
            f"[yellow]{server.server_package}: server connection lost on"
            f" {health.lost_connection_responses} call(s)[/yellow]"
        )


def _print_incidents(server: AdmittedServer, report: AuditReport, detail: ReportDetail) -> None:
    for missed in report.missed_steps:
        line = escape(detail.missed_detail(missed))
        console.print(f"[yellow]{server.server_package}: {line}[/yellow]")
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{server.server_package}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def nuisance_audit(
    server: AdmittedServer,
    attempt: Callable[[], Awaitable[NuisanceAudit | LaunchFailed | ProviderError]],
) -> NuisanceAudit | DroppedRun:
    """One run of one server, at most `NUISANCE_INFRA_ATTEMPTS` calls. A report with no
    throttled step stands, an alarm in it whatever step was refused. A throttled report, a
    launch failure or a provider error is retried. The run drops as throttled when any attempt
    was, else as a provider error when any attempt met one, else as a launch failure."""
    causes: set[NotRunCause] = set()
    for number in range(1, NUISANCE_INFRA_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, NuisanceAudit) and not _is_throttled(outcome.report):
            return outcome
        causes.add(_cause_of(outcome))
        console.print(
            f"[yellow]{server.server_package}: {_failure(outcome)},"
            f" attempt {number}/{NUISANCE_INFRA_ATTEMPTS}[/yellow]"
        )
    return DroppedRun(next(cause for cause in _DROP_PRECEDENCE if cause in causes))


_DROP_PRECEDENCE = (NotRunCause.THROTTLED, NotRunCause.PROVIDER_ERROR, NotRunCause.LAUNCH_FAILURE)


def _cause_of(outcome: NuisanceAudit | LaunchFailed | ProviderError) -> NotRunCause:
    if isinstance(outcome, NuisanceAudit):
        return NotRunCause.THROTTLED
    if isinstance(outcome, ProviderError):
        return NotRunCause.PROVIDER_ERROR
    return NotRunCause.LAUNCH_FAILURE


def _failure(outcome: NuisanceAudit | LaunchFailed | ProviderError) -> str:
    if isinstance(outcome, NuisanceAudit):
        return "throttled by the model provider past every retry"
    if isinstance(outcome, ProviderError):
        return f"provider error ({outcome.reason})"
    return f"run failed to launch ({escape(outcome.reason)})"


def _is_throttled(report: AuditReport) -> bool:
    return any(missed.cause is MissCause.PROVIDER_THROTTLED for missed in report.missed_steps)


@dataclass(frozen=True)
class GateRun:
    flagged: bool
    report: AuditReport


async def gate_run(
    server: AdmittedServer, audit: Callable[[], Awaitable[NuisanceAudit | DroppedRun]]
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
        report = outcome.report
        flagged = bool(flagged_tools(report, counted_tools(server)))
        if flagged or not is_incomplete(report):
            return GateRun(flagged=flagged, report=report)
        attempt_causes = incomplete_causes(report)
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


def incomplete_causes(report: AuditReport) -> frozenset[MissCause]:
    return frozenset(
        missed.cause for missed in report.missed_steps if missed.cause in _INCOMPLETE_CAUSES
    )


def is_incomplete(report: AuditReport) -> bool:
    return any(missed.cause in _INCOMPLETE_CAUSES for missed in report.missed_steps)
