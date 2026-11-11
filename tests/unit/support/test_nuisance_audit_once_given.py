import threading
from dataclasses import replace

from evals.backend_lifecycle import BackendLifecycle
from evals.cve_audit import RunOverrides
from evals.failure_text import FULL_DETAIL, ReportDetail
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_audit import NuisanceAuditor
from mcp_auditor.domain.models import AuditReport, MissCause, MissedModelCall, ModelCallKind
from tests.unit.support import test_audit_launch_given as launch_given
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support.test_nuisance_admission_given import (
    a_fake_lifecycle,
    an_admitted_server,
    with_a_backend,
)

NO_OVERRIDES = RunOverrides(None, None, None)


def an_auditor(
    report_detail: ReportDetail = FULL_DETAIL,
    graphs: launch_given.FakeGraphs | None = None,
    connect: launch_given.FakeConnect | None = None,
    overrides: RunOverrides = NO_OVERRIDES,
) -> NuisanceAuditor:
    return NuisanceAuditor(
        launch_given.an_auditor(report_detail, graphs, connect), overrides, SessionThrottles()
    )


def an_auditor_on_a_noisy_server(lost_calls: int) -> NuisanceAuditor:
    """The graph sends one call per lost connection, each answered "Connection closed", to a
    client that read two lines it could not parse."""
    return an_auditor(
        graphs=launch_given.graph_calling(lost_calls),
        connect=launch_given.FakeConnect(launch_given.a_noisy_client(non_protocol_lines=2)),
    )


def an_auditor_raising(error: Exception, *, grouped: bool) -> NuisanceAuditor:
    return an_auditor(
        graphs=launch_given.graph_raising(error), connect=launch_given.FakeConnect(grouped=grouped)
    )


def a_server_backed_by(lifecycle: BackendLifecycle) -> AdmittedServer:
    """A server whose backend fixture names the lifecycle, as `a_backend_registry` registers it."""
    fixture = BackendFixture(
        provisioner=lifecycle.key, image="fake/backend:1.0", network="fake-net"
    )
    return with_a_backend(an_admitted_server(), fixture)


def a_lifecycle_raising(error: Exception) -> BackendLifecycle:
    def fail() -> None:
        raise error

    return replace(a_fake_lifecycle("fail"), ensure=fail)


def a_lifecycle_holding_one_lock() -> BackendLifecycle:
    """`ensure` takes one lock and the server's removal releases it, so the lock is held across
    a whole audit. A second audit standing up on the event loop's own thread would block the
    first one from ever releasing it: it times out instead of hanging."""
    held = threading.Lock()

    def hold() -> None:
        if not held.acquire(timeout=1):
            raise RuntimeError("the launch lock stayed held")

    def release(_name: str) -> None:
        held.release()

    return replace(a_fake_lifecycle("block"), ensure=hold, remove=release)


def a_report_refused_with_detail(detail: str) -> AuditReport:
    refused = MissedModelCall(
        tool_name="read_file",
        kind=ModelCallKind.JUDGMENT,
        cause=MissCause.PROVIDER_REFUSAL,
        detail=detail,
    )
    return grammar.a_report().model_copy(update={"missed_model_calls": [refused]})
