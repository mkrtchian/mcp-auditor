"""One audit of one admitted server on its patched image, with the suite's retry policy: a
refused or unreadable model call, or one whose prompt was longer than the model's context window, is
kept and counted downstream, a launch failure, a throttled attempt or a transient provider error
is retried, and a fatal provider error stops the run."""

from collections.abc import Awaitable, Callable, Collection, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from rich.markup import escape

from evals.concurrency import entered_in_thread
from evals.cve.audit_attempts import ProviderErrorAttempt
from evals.cve.environments import Launch
from evals.cve.launch_audit import (
    SessionAuditor,
    UndecidableLaunch,
    audit_launch,
    print_lost_connections,
    print_report_incidents,
)
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.backend_registry import BACKENDS, RegisteredBackend
from evals.cve.nuisance.confinement import single_container_launch_args
from evals.cve.nuisance.images import image_tag
from evals.cve.nuisance.provisioners import provisioned_launch
from evals.cve.nuisance.results import NotRunCause
from evals.cve.server_health import ServerHealth
from evals.eval_display import console
from evals.model_provider_errors import (
    AuditFailed,
    ProviderErrorKind,
    ProviderFatal,
    describe_provider_error,
)
from evals.session_usage import throttled_model_calls
from mcp_auditor.domain.models import AuditReport

NUISANCE_INFRA_ATTEMPTS = 3  # one try, two retries


@dataclass(frozen=True)
class LaunchFailed:
    reason: str


@dataclass(frozen=True)
class DroppedRun:
    """A run that never produced a report, which drops its server from the nuisance holdout run."""

    cause: NotRunCause

    @classmethod
    def from_causes(cls, causes: Collection[NotRunCause]) -> "DroppedRun":
        """Throttled, else provider error, else launch failure."""
        return cls(next(cause for cause in _DROP_PRECEDENCE if cause in causes))


@dataclass(frozen=True)
class NuisanceAudit:
    report: AuditReport
    health: ServerHealth


async def audit_once(
    server: AdmittedServer,
    auditor: SessionAuditor,
    *,
    backends: Mapping[str, RegisteredBackend] = BACKENDS,
) -> NuisanceAudit | LaunchFailed | ProviderErrorAttempt:
    """Raises `ProviderFatal` on a provider error no retry cures, and `UndecidableLaunch`, a
    configuration error that stops the run as a `planting_spec` refusal does. A server taken as
    down is a launch failure."""
    # The provisioner blocks for minutes and `DORIS_LAUNCH_LOCK` is a thread lock, so a plain
    # `with` inside the coroutine would freeze the loop and deadlock the server's gathered runs.
    try:
        async with entered_in_thread(nuisance_environment(server, backends)) as launch:
            audit = await audit_launch(launch, auditor.auditor, auditor.overrides.shape(None))
    except AuditFailed as failure:
        if failure.kind is ProviderErrorKind.FATAL:
            raise ProviderFatal(failure.cause) from failure.cause
        return ProviderErrorAttempt(describe_provider_error(failure.cause))
    except UndecidableLaunch:
        raise
    except Exception as exc:
        return LaunchFailed(auditor.auditor.report_detail.describe(exc))
    auditor.throttles.count(audit.report)
    print_report_incidents(server.server_package, audit.report, auditor.auditor.report_detail)
    print_lost_connections(server.server_package, audit.health)
    return NuisanceAudit(audit.report, audit.health)


@contextmanager
def nuisance_environment(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend] = BACKENDS
) -> Generator[Launch]:
    """The launch of one server on its patched image. With no backend fixture it is the
    single-container launch under the confinement, with no mount and no network, its
    public names served by a holder when it declares some; with one it delegates to the
    provisioner of the registered lifecycle, which brings the backend up, shared or for this
    launch alone, and yields the server launch wired to it. The lifecycle owns the closed network
    that joins the server to its backend and to nothing else, if it joins one."""
    if server.backend is None:
        with single_container_launch_args(
            image_tag(server.service), server.host, server.launch
        ) as args:
            yield Launch(command="docker", args=args)
    else:
        with provisioned_launch(backends[server.backend.provisioner].lifecycle, server) as launch:
            yield launch


async def nuisance_audit(
    server: AdmittedServer,
    attempt: Callable[[], Awaitable[NuisanceAudit | LaunchFailed | ProviderErrorAttempt]],
) -> NuisanceAudit | DroppedRun:
    """One run of one server, at most `NUISANCE_INFRA_ATTEMPTS` calls. A report with no
    throttled model call stands, an alarm in it whatever model call was refused. A throttled
    report, a launch failure or a provider error is retried. The run drops as throttled when any
    attempt was, else as a provider error when any attempt met one, else as a launch failure."""
    causes: set[NotRunCause] = set()
    for number in range(1, NUISANCE_INFRA_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, NuisanceAudit) and not throttled_model_calls(outcome.report):
            return outcome
        causes.add(_cause_of(outcome))
        console.print(
            f"[yellow]{server.server_package}: {_failure(outcome)},"
            f" attempt {number}/{NUISANCE_INFRA_ATTEMPTS}[/yellow]"
        )
    return DroppedRun.from_causes(causes)


_DROP_PRECEDENCE = (NotRunCause.THROTTLED, NotRunCause.PROVIDER_ERROR, NotRunCause.LAUNCH_FAILURE)


def _cause_of(outcome: NuisanceAudit | LaunchFailed | ProviderErrorAttempt) -> NotRunCause:
    if isinstance(outcome, NuisanceAudit):
        return NotRunCause.THROTTLED
    if isinstance(outcome, ProviderErrorAttempt):
        return NotRunCause.PROVIDER_ERROR
    return NotRunCause.LAUNCH_FAILURE


def _failure(outcome: NuisanceAudit | LaunchFailed | ProviderErrorAttempt) -> str:
    if isinstance(outcome, NuisanceAudit):
        return "throttled by the model provider past every retry"
    if isinstance(outcome, ProviderErrorAttempt):
        return f"provider error ({outcome.description})"
    return f"run failed to launch ({escape(outcome.reason)})"
