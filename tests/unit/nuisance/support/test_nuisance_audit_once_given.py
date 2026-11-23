import threading
from dataclasses import replace

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.launch_audit import NO_OVERRIDES, RunOverrides
from evals.cve.nuisance.admission.admission import AdmittedServer, BackendFixture
from evals.cve.nuisance.audit import NuisanceAuditor
from evals.session_usage import SessionThrottles
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport
from tests.unit.support.admission_mutations import with_a_backend
from tests.unit.support.nuisance_admissions import a_fake_lifecycle, an_admitted_server


def an_auditor_on_a_noisy_server(lost_calls: int) -> NuisanceAuditor:
    """The graph sends one call per lost connection, each answered "Connection closed", to a
    client that read two lines it could not parse."""
    return an_auditor(
        graphs=launch_audit_fakes.graph_calling(lost_calls),
        connect=launch_audit_fakes.FakeConnect(
            launch_audit_fakes.a_noisy_client(non_protocol_lines=2)
        ),
    )


def an_auditor(
    report_detail: ReportDetail = FULL_DETAIL,
    graphs: launch_audit_fakes.FakeGraphs | None = None,
    connect: launch_audit_fakes.FakeConnect | None = None,
    overrides: RunOverrides = NO_OVERRIDES,
) -> NuisanceAuditor:
    return NuisanceAuditor(
        launch_audit_fakes.an_auditor(report_detail, graphs, connect), overrides, SessionThrottles()
    )


def an_auditor_raising(error: Exception, *, grouped: bool) -> NuisanceAuditor:
    return an_auditor(
        graphs=launch_audit_fakes.graph_raising(error),
        connect=launch_audit_fakes.FakeConnect(grouped=grouped),
    )


def an_auditor_taking_the_server_as_down(audits: int = 1) -> NuisanceAuditor:
    """Each of the `audits` reports holds a relaunch that failed."""
    reports = [launch_audit_fakes.a_report_with_relaunches(False) for _ in range(audits)]
    return an_auditor(graphs=launch_audit_fakes.graph_reporting(reports))


def a_lifecycle_launching_an_unreadable_name() -> BackendLifecycle:
    """The server's `docker run` puts an option no table knows before the image."""

    def unreadable(_name: str, _image: str, _host: object, _launch: object) -> list[str]:
        return ["run", "--an-unknown-option", "value", "image"]

    return replace(a_fake_lifecycle("unreadable"), server_args=unreadable)


def a_server_backed_by(lifecycle: BackendLifecycle) -> AdmittedServer:
    """A server whose backend fixture names the lifecycle, as `a_backend_registry` registers it."""
    fixture = BackendFixture(
        provisioner=lifecycle.key, images=["fake/backend:1.0"], network="fake-net"
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
        cause=MissedCallCause.PROVIDER_REFUSAL,
        detail=detail,
    )
    return grammar.a_report().model_copy(update={"missed_model_calls": [refused]})
