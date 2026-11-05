import asyncio
import os
import threading
from dataclasses import replace
from typing import Any

import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

import tests.unit.support.test_eval_display_given as display_given
from evals import launch_audit
from evals import nuisance_audit as nuisance_audit_module
from evals.concurrency import entered_in_thread
from evals.cve_audit import RunOverrides
from evals.cve_environments import Launch
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.failure_text import FULL_DETAIL, TYPES_ONLY, ReportDetail
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_audit import (
    BACKENDS,
    NUISANCE_INFRA_ATTEMPTS,
    DroppedRun,
    LaunchFailed,
    NuisanceAudit,
    NuisanceAuditor,
    ProviderError,
    audit_once,
    gate_run,
    is_incomplete,
    nuisance_audit,
    nuisance_environment,
)
from evals.nuisance_backends import RegisteredBackend
from evals.nuisance_confinement import single_container_run_args
from evals.nuisance_images import image_tag
from evals.nuisance_results import NotRunCause
from evals.provider_errors import ProviderFatal
from evals.server_health import NO_INCIDENTS, ServerHealth
from mcp_auditor.domain.models import (
    AuditReport,
    AuditStep,
    MissCause,
    MissedStep,
    ProviderUsage,
)
from tests.unit.support import test_audit_launch_given as launch_given
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support import test_nuisance_run_given as run_given
from tests.unit.support.docker_argv import value_after
from tests.unit.support.test_nuisance_admission_given import (
    FIRST_FLAW,
    SECOND_FLAW,
    a_backend_registry,
    a_fake_lifecycle,
    a_flaw_record,
    a_server,
    with_a_backend,
    with_host,
)

SERVER = a_server(
    [
        a_flaw_record(FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, "1.2.0"),
        a_flaw_record(SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, "1.2.0"),
    ]
)
_PROVIDER_ERROR = ProviderError("ModelAPIError, status 500")


def test_the_crafted_server_launches_unprivileged_at_the_root_with_no_network():
    args = _launch_args(SERVER)

    assert value_after(args, "--network") == "none"
    assert "bridge" not in args
    assert value_after(args, "--user") == "65534:65534"
    assert value_after(args, "-w") == "/"


def test_a_backend_less_server_launches_with_no_network_even_on_a_networked_host():
    server = with_host(SERVER, PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True))

    args = _launch_args(server)

    assert value_after(args, "--network") == "none"
    assert "bridge" not in args


def test_a_host_user_launches_as_the_invoking_user_in_its_working_directory():
    server = with_host(SERVER, PlantingHost(SymbolicUser.HOST, "/srv", has_network=False))

    args = _launch_args(server)

    assert value_after(args, "--user") == f"{os.getuid()}:{os.getgid()}"
    assert value_after(args, "-w") == "/srv"


def test_the_launch_runs_the_patched_image_confined_with_no_mount():
    with nuisance_environment(SERVER) as launch:
        assert launch.command == "docker"
        assert launch.args[-3:] == [f"mcp-auditor-nuisance-{SERVER.service}:local", *SERVER.launch]
        assert value_after(launch.args, "--cap-drop") == "ALL"
        assert "-v" not in launch.args
        assert "--mount" not in launch.args


def test_a_backend_less_server_launches_under_the_nuisance_confinement_with_the_memory_bound():
    args = _launch_args(SERVER)

    assert args == single_container_run_args(image_tag(SERVER.service), SERVER.host, SERVER.launch)
    assert "--memory" in args


def test_a_backend_server_launches_through_its_registered_provisioner():
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="fake", image="fake/backend:1.0", network="fake-net")
    )

    with nuisance_environment(server, backends=a_backend_registry()) as launch:
        assert launch == Launch("docker", ["run", "fake"])


async def test_a_provisioner_failing_on_enter_is_a_launch_failure():
    server, registry = _a_server_whose_provisioner_raises(RuntimeError("cluster never healthy"))

    outcome = await audit_once(server, _an_auditor(), backends=registry)

    assert isinstance(outcome, LaunchFailed)
    assert "cluster never healthy" in outcome.reason


async def test_a_launch_failure_on_a_nuisance_run_carries_the_error_type_without_its_message():
    server, registry = _a_server_whose_provisioner_raises(RuntimeError("secret-nonce"))

    outcome = await audit_once(server, _an_auditor(TYPES_ONLY), backends=registry)

    assert isinstance(outcome, LaunchFailed)
    assert "RuntimeError" in outcome.reason
    assert "secret-nonce" not in outcome.reason


async def test_a_missed_step_on_a_nuisance_run_prints_its_cause_without_the_provider_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    refused = _missing_a_step(_a_report_throttled(0), MissCause.PROVIDER_REFUSAL, "secret-nonce")
    auditor = _an_auditor(TYPES_ONLY, launch_given.graph_reporting([refused]))

    await audit_once(SERVER, auditor)

    assert "Refused by the model provider" in output.getvalue()
    assert "secret-nonce" not in output.getvalue()


async def test_a_throttled_attempt_retried_then_a_clean_one_counts_both_throttled_requests(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    throttled = _missing_a_step(_a_report_throttled(3), MissCause.PROVIDER_THROTTLED)
    clean = _a_report_throttled(2)
    auditor = _an_auditor(graphs=launch_given.graph_reporting([throttled, clean]))

    outcome = await nuisance_audit(SERVER, lambda: audit_once(SERVER, auditor))

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.report is clean
    assert auditor.throttles.requests == 5


async def test_an_audit_carries_its_server_health_and_warns_of_a_lost_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    auditor = _an_auditor_on_a_noisy_server(lost_calls=1)

    outcome = await audit_once(SERVER, auditor)

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.health == ServerHealth(2, 1)
    assert f"{SERVER.server_package}: server connection lost on 1 call(s)" in output.getvalue()


async def test_an_audit_with_no_lost_connection_says_nothing_of_one(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    auditor = _an_auditor_on_a_noisy_server(lost_calls=0)

    await audit_once(SERVER, auditor)

    assert "connection lost" not in output.getvalue()


async def test_two_concurrent_environments_of_one_backend_server_both_complete():
    held = threading.Lock()

    def hold() -> None:
        held.acquire()

    def release(name: str) -> None:
        held.release()

    blocking = replace(a_fake_lifecycle("block"), ensure=hold, remove=release)
    registry = {"block": RegisteredBackend(blocking, "fake-net", "fake/backend:1.0", (), ())}
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="block", image="fake/backend:1.0", network="fake-net")
    )

    async def enter_once() -> None:
        async with entered_in_thread(nuisance_environment(server, backends=registry)):
            await asyncio.sleep(0.01)

    await asyncio.wait_for(asyncio.gather(enter_once(), enter_once()), timeout=5)


async def test_a_clean_report_stands_at_the_first_call(monkeypatch: pytest.MonkeyPatch):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    audit = _audited(grammar.a_report())
    attempt = _ScriptedAttempts([audit])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is audit
    assert attempt.calls == 1


async def test_a_refused_step_with_a_fail_is_kept(monkeypatch: pytest.MonkeyPatch):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    report = _missing_a_step(grammar.a_report([grammar.a_case()]), MissCause.PROVIDER_REFUSAL)
    audit = _audited(report)
    attempt = _ScriptedAttempts([audit])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is audit
    assert attempt.calls == 1


async def test_an_unreadable_step_with_no_fail_is_kept_as_incomplete(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    report = _missing_a_step(grammar.a_report(), MissCause.UNREADABLE_ANSWER)

    audit = _audited(report)

    outcome = await nuisance_audit(SERVER, _ScriptedAttempts([audit]))

    assert outcome is audit
    assert is_incomplete(report)


def test_a_report_with_no_missed_step_is_complete():
    assert not is_incomplete(grammar.a_report())


async def test_a_launch_failing_at_every_attempt_drops_the_run(monkeypatch: pytest.MonkeyPatch):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    attempt = _ScriptedAttempts([LaunchFailed("no image")] * 3)

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS == 3


async def test_a_run_throttled_at_any_attempt_drops_as_throttled(monkeypatch: pytest.MonkeyPatch):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    throttled = _missing_a_step(grammar.a_report(), MissCause.PROVIDER_THROTTLED)

    attempt = _ScriptedAttempts([_PROVIDER_ERROR, LaunchFailed("no image"), _audited(throttled)])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome == DroppedRun(NotRunCause.THROTTLED)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert f"attempt 1/{NUISANCE_INFRA_ATTEMPTS}" in output.getvalue()


async def test_a_launch_failure_is_retried_and_a_later_report_stands(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    audit = _audited(grammar.a_report())
    attempt = _ScriptedAttempts([LaunchFailed("no image"), audit])

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome is audit
    assert attempt.calls == 2


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_server_failing_inside_the_graph_is_a_launch_failure(grouped: bool):
    auditor = _an_auditor_raising(TimeoutError("list_tools timed out"), grouped=grouped)

    outcome = await audit_once(SERVER, auditor)

    assert isinstance(outcome, LaunchFailed)


@_SHAPES
async def test_a_fatal_provider_error_stops_the_run(grouped: bool):
    error = ModelAuthenticationError("invalid key")
    auditor = _an_auditor_raising(error, grouped=grouped)

    with pytest.raises(ProviderFatal) as stopped:
        await audit_once(SERVER, auditor)

    assert stopped.value.cause is error


@_SHAPES
async def test_a_transient_provider_error_is_named_without_its_message(grouped: bool):
    auditor = _an_auditor_raising(ModelAPIError("secret-nonce"), grouped=grouped)

    outcome = await audit_once(SERVER, auditor)

    assert isinstance(outcome, ProviderError)
    assert "ModelAPIError" in outcome.reason
    assert "secret-nonce" not in outcome.reason


async def test_a_fatal_provider_error_of_an_attempt_stops_the_run_at_once(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    attempt = _ScriptedAttempts([ProviderFatal(ModelAuthenticationError("invalid key"))])

    with pytest.raises(ProviderFatal):
        await nuisance_audit(SERVER, attempt)

    assert attempt.calls == 1


async def test_a_provider_error_at_every_attempt_drops_the_run_as_a_provider_error(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    attempt = _ScriptedAttempts([_PROVIDER_ERROR] * NUISANCE_INFRA_ATTEMPTS)

    outcome = await nuisance_audit(SERVER, attempt)

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)
    assert attempt.calls == NUISANCE_INFRA_ATTEMPTS
    assert "provider error (ModelAPIError, status 500), attempt 1/3" in output.getvalue()


async def test_a_provider_error_is_retried_and_a_later_report_stands(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    audit = _audited(grammar.a_report())

    outcome = await nuisance_audit(SERVER, _ScriptedAttempts([_PROVIDER_ERROR, audit]))

    assert outcome is audit


async def test_a_run_failing_on_a_provider_error_and_a_launch_drops_as_a_provider_error(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    no_image = LaunchFailed("no image")

    outcome = await nuisance_audit(SERVER, _ScriptedAttempts([no_image, _PROVIDER_ERROR, no_image]))

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)


async def test_a_gate_run_with_a_counted_alarm_stands_despite_a_refused_step(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    report = run_given.a_report(True, missed=MissCause.PROVIDER_REFUSAL)
    audit = _ScriptedAudits([_audited(report)])

    run = await gate_run(run_given.a_server(), audit)

    assert run is not None
    assert run.flagged
    assert run.report is report
    assert audit.calls == 1


async def test_a_gate_run_incomplete_without_an_alarm_is_attempted_again(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    clean = run_given.a_report(False)
    unreadable = run_given.a_report(False, missed=MissCause.UNREADABLE_ANSWER)
    audit = _ScriptedAudits([_audited(unreadable), _audited(clean)])

    run = await gate_run(run_given.a_server(), audit)

    assert run is not None
    assert not run.flagged
    assert run.report is clean
    assert audit.calls == 2
    assert "attempt 1/3" in output.getvalue()


async def test_a_gate_run_incomplete_at_every_attempt_does_not_complete(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    incomplete = run_given.a_report(False, missed=MissCause.PROVIDER_REFUSAL)
    audit = _ScriptedAudits([_audited(incomplete)] * 3)

    run = await gate_run(run_given.a_server(), audit)

    assert run is None
    assert audit.calls == 3
    assert "all 3 attempts" in output.getvalue()


async def test_a_dropped_gate_run_does_not_complete_at_once(monkeypatch: pytest.MonkeyPatch):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    audit = _ScriptedAudits([DroppedRun(NotRunCause.THROTTLED)])

    run = await gate_run(run_given.a_server(), audit)

    assert run is None
    assert audit.calls == 1


def _an_auditor(
    report_detail: ReportDetail = FULL_DETAIL,
    graphs: launch_given.FakeGraphs | None = None,
    connect: launch_given.FakeConnect | None = None,
) -> NuisanceAuditor:
    return NuisanceAuditor(
        launch_given.an_auditor(report_detail, graphs, connect),
        RunOverrides(None, None, None),
        SessionThrottles(),
    )


def _an_auditor_on_a_noisy_server(lost_calls: int) -> NuisanceAuditor:
    """The graph sends one call per lost connection, each answered "Connection closed", to a
    client that read two lines it could not parse."""
    return _an_auditor(
        graphs=launch_given.graph_calling(lost_calls),
        connect=launch_given.FakeConnect(launch_given.a_noisy_client(non_protocol_lines=2)),
    )


def _an_auditor_raising(error: Exception, *, grouped: bool) -> NuisanceAuditor:
    return _an_auditor(
        graphs=launch_given.graph_raising(error), connect=launch_given.FakeConnect(grouped=grouped)
    )


def _a_server_whose_provisioner_raises(
    error: Exception,
) -> tuple[AdmittedServer, dict[str, RegisteredBackend]]:
    def fail() -> None:
        raise error

    failing = replace(a_fake_lifecycle("fail"), ensure=fail)
    registry = {"fail": RegisteredBackend(failing, "fake-net", "fake/backend:1.0", (), ())}
    server = with_a_backend(
        SERVER, BackendFixture(provisioner="fail", image="fake/backend:1.0", network="fake-net")
    )
    return server, registry


def _a_report_throttled(requests: int) -> AuditReport:
    usage = ProviderUsage(throttled_requests=requests)
    return grammar.a_report().model_copy(update={"provider_usage": usage})


def _launch_args(server: AdmittedServer, backends: Any = BACKENDS) -> list[str]:
    with nuisance_environment(server, backends=backends) as launch:
        return launch.args


def _audited(report: AuditReport) -> NuisanceAudit:
    return NuisanceAudit(report, NO_INCIDENTS)


def _missing_a_step(report: AuditReport, cause: MissCause, detail: str = "") -> AuditReport:
    missed = MissedStep(tool_name="read_file", step=AuditStep.JUDGMENT, cause=cause, detail=detail)
    return report.model_copy(update={"missed_steps": [missed]})


class _ScriptedAttempts:
    def __init__(
        self, outcomes: list[NuisanceAudit | LaunchFailed | ProviderError | ProviderFatal]
    ) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> NuisanceAudit | LaunchFailed | ProviderError:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, ProviderFatal):
            raise outcome
        return outcome


class _ScriptedAudits:
    def __init__(self, outcomes: list[NuisanceAudit | DroppedRun]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> NuisanceAudit | DroppedRun:
        self.calls += 1
        return self._outcomes.pop(0)
