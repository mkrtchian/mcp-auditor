"""One audit of one admitted server on its patched image, with the suite's retry policy: a
refused or unreadable step is kept and counted downstream, a launch failure, a throttled attempt
or a transient provider error is retried, and a fatal provider error stops the run."""

from collections.abc import Awaitable, Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from rich.markup import escape

from evals.concurrency import entered_in_thread
from evals.cve.audit_attempts import INCOMPLETE_ATTEMPTS, describe_missed_call_causes
from evals.cve.detection.audit import RunOverrides
from evals.cve.failure_text import ReportDetail
from evals.cve.launch_audit import Auditor, AuditShape, audit_launch, print_lost_connections
from evals.cve.provider_errors import (
    AuditFailed,
    ProviderErrorKind,
    ProviderFatal,
    describe_provider_error,
)
from evals.cve.server_health import ServerHealth
from evals.cve_environments import Launch
from evals.eval_display import console
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_backends import BACKENDS, RegisteredBackend
from evals.nuisance_confinement import single_container_launch_args
from evals.nuisance_counter import flagged_tools
from evals.nuisance_counting import counted_tools
from evals.nuisance_images import image_tag
from evals.nuisance_provisioners import provisioner_of
from evals.nuisance_results import NotRunCause
from mcp_auditor.domain.models import AuditReport, MissCause

NUISANCE_INFRA_ATTEMPTS = 3  # one try, two retries

_INCOMPLETE_CAUSES = frozenset({MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER})


@contextmanager
def nuisance_environment(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend] = BACKENDS
) -> Generator[Launch]:
    """The launch of one server on its patched image. With no backend fixture it is the
    single-container launch under the nuisance confinement, with no mount and no network, its
    public names served by a holder when it declares some; with one it delegates to the
    provisioner of the registered lifecycle, which brings the backend up and yields the server
    launch wired to it. The lifecycle owns the closed network that joins the server to its
    backend and to nothing else."""
    if server.backend is None:
        with single_container_launch_args(
            image_tag(server.service), server.host, server.launch
        ) as args:
            yield Launch(command="docker", args=args)
    else:
        with provisioner_of(backends[server.backend.provisioner].lifecycle)(server) as launch:
            yield launch


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
    overrides = auditor.overrides
    shape = AuditShape(
        None, overrides.chain_budget, overrides.max_chain_steps, overrides.tool_call_timeout
    )
    try:
        async with entered_in_thread(nuisance_environment(server, backends)) as launch:
            audit = await audit_launch(launch, auditor.auditor, shape)
    except AuditFailed as failure:
        if failure.kind is ProviderErrorKind.FATAL:
            raise ProviderFatal(failure.cause) from failure.cause
        return ProviderError(describe_provider_error(failure.cause))
    except Exception as exc:
        return LaunchFailed(auditor.auditor.report_detail.describe(exc))
    auditor.throttles.count(audit.report)
    _print_incidents(server, audit.report, auditor.auditor.report_detail)
    print_lost_connections(server.server_package, audit.health)
    return NuisanceAudit(audit.report, audit.health)


def _print_incidents(server: AdmittedServer, report: AuditReport, detail: ReportDetail) -> None:
    for missed in report.missed_model_calls:
        line = escape(detail.missed_call_detail(missed))
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
    return any(missed.cause is MissCause.PROVIDER_THROTTLED for missed in report.missed_model_calls)


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
            f" {describe_missed_call_causes(attempt_causes)}, no counted alarm,"
            " attempted again[/yellow]"
        )
    console.print(
        f"[yellow]{server.server_package} run did not complete:[/yellow] a model call missed at all"
        f" {INCOMPLETE_ATTEMPTS} attempts ({describe_missed_call_causes(causes)})"
    )
    return None


def incomplete_causes(report: AuditReport) -> frozenset[MissCause]:
    return frozenset(
        missed.cause for missed in report.missed_model_calls if missed.cause in _INCOMPLETE_CAUSES
    )


def is_incomplete(report: AuditReport) -> bool:
    return any(missed.cause in _INCOMPLETE_CAUSES for missed in report.missed_model_calls)
