import asyncio

import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

import tests.unit.nuisance.support.test_nuisance_audit_once_given as given
import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.audit_attempts import ProviderErrorAttempt
from evals.cve.environments import Launch
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.launch_audit import RunOverrides, UndecidableLaunch
from evals.cve.nuisance.audit import (
    NUISANCE_INFRA_ATTEMPTS,
    DroppedRun,
    LaunchFailed,
    NuisanceAudit,
    audit_once,
    nuisance_audit,
    nuisance_environment,
)
from evals.cve.nuisance.confinement import single_container_run_args
from evals.cve.nuisance.results import NotRunCause
from evals.cve.server_health import ServerHealth
from evals.model_provider_errors import ProviderFatal
from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import ProviderUsage
from tests.unit.support.captured_console import a_captured_console
from tests.unit.support.nuisance_admissions import (
    a_backend_registry,
    a_fake_lifecycle,
    an_admitted_server,
)


def test_a_backend_less_server_runs_its_patched_image_as_a_single_container_with_no_mount():
    server = an_admitted_server()
    patched_image = f"mcp-auditor-nuisance-{server.service}:local"

    with nuisance_environment(server) as launch:
        assert launch == Launch(
            "docker", single_container_run_args(patched_image, server.host, server.launch)
        )
        assert "-v" not in launch.args
        assert "--mount" not in launch.args


def test_a_backend_server_launches_through_its_registered_provisioner():
    lifecycle = a_fake_lifecycle()

    with nuisance_environment(
        given.a_server_backed_by(lifecycle), backends=a_backend_registry(lifecycle)
    ) as launch:
        assert launch == Launch("docker", ["run", "fake"])


async def test_a_provisioner_failing_on_enter_is_a_launch_failure():
    lifecycle = given.a_lifecycle_raising(RuntimeError("cluster never healthy"))

    outcome = await audit_once(
        given.a_server_backed_by(lifecycle),
        given.an_auditor(),
        backends=a_backend_registry(lifecycle),
    )

    assert isinstance(outcome, LaunchFailed)
    assert "cluster never healthy" in outcome.reason


async def test_a_server_taken_as_down_is_a_launch_failure():
    outcome = await audit_once(an_admitted_server(), given.an_auditor_taking_the_server_as_down())

    assert isinstance(outcome, LaunchFailed)
    assert "failed to relaunch the server" in outcome.reason


async def test_a_server_taken_as_down_at_every_attempt_drops_as_a_launch_failure(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    auditor = given.an_auditor_taking_the_server_as_down(audits=NUISANCE_INFRA_ATTEMPTS)
    server = an_admitted_server()

    outcome = await nuisance_audit(server, lambda: audit_once(server, auditor))

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)


async def test_a_launch_whose_container_name_cannot_be_read_stops_the_run():
    lifecycle = given.a_lifecycle_launching_an_unreadable_name()

    with pytest.raises(UndecidableLaunch):
        await audit_once(
            given.a_server_backed_by(lifecycle),
            given.an_auditor(),
            backends=a_backend_registry(lifecycle),
        )


async def test_a_launch_failure_on_a_nuisance_holdout_run_keeps_the_error_type_not_its_message():
    lifecycle = given.a_lifecycle_raising(RuntimeError("secret-nonce"))

    outcome = await audit_once(
        given.a_server_backed_by(lifecycle),
        given.an_auditor(TYPES_ONLY),
        backends=a_backend_registry(lifecycle),
    )

    assert isinstance(outcome, LaunchFailed)
    assert "RuntimeError" in outcome.reason
    assert "secret-nonce" not in outcome.reason


async def test_a_missed_model_call_on_a_nuisance_holdout_run_prints_its_cause_not_the_provider_text(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    refused = given.a_report_refused_with_detail("secret-nonce")
    auditor = given.an_auditor(TYPES_ONLY, launch_audit_fakes.graph_reporting([refused]))

    await audit_once(an_admitted_server(), auditor)

    assert "Refused by the model provider" in output.getvalue()
    assert "secret-nonce" not in output.getvalue()


async def test_the_run_overrides_reach_the_graph_and_the_client(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])
    connect = launch_audit_fakes.FakeConnect()
    auditor = given.an_auditor(graphs=graphs, connect=connect, overrides=RunOverrides(7, 9, 11))

    await audit_once(an_admitted_server(), auditor)

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (7, 9)
    assert connect.timeouts == [11]


async def test_a_throttled_attempt_retried_then_a_clean_one_counts_both_throttled_requests(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    throttled = holdout_runs.a_report(
        False,
        missed=MissedCallCause.PROVIDER_THROTTLED,
        provider=ProviderUsage(throttled_requests=3),
    )
    clean = holdout_runs.a_report(False, provider=ProviderUsage(throttled_requests=2))
    auditor = given.an_auditor(graphs=launch_audit_fakes.graph_reporting([throttled, clean]))
    server = an_admitted_server()

    outcome = await nuisance_audit(server, lambda: audit_once(server, auditor))

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.report is clean
    assert auditor.throttles.requests == 5


async def test_an_audit_carries_its_server_health_and_warns_of_a_lost_connection(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    server = an_admitted_server()

    outcome = await audit_once(server, given.an_auditor_on_a_noisy_server(lost_calls=1))

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.health == ServerHealth(2, 1)
    assert f"{server.server_package}: server connection lost on 1 call(s)" in output.getvalue()


async def test_an_audit_with_no_lost_connection_says_nothing_of_one(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    await audit_once(an_admitted_server(), given.an_auditor_on_a_noisy_server(lost_calls=0))

    assert "connection lost" not in output.getvalue()


async def test_two_concurrent_audits_of_one_backend_server_both_complete():
    lifecycle = given.a_lifecycle_holding_one_lock()
    server = given.a_server_backed_by(lifecycle)
    registry = a_backend_registry(lifecycle)
    auditor = given.an_auditor(
        graphs=launch_audit_fakes.graph_reporting([grammar.a_report(), grammar.a_report()])
    )

    outcomes = await asyncio.gather(
        audit_once(server, auditor, backends=registry),
        audit_once(server, auditor, backends=registry),
    )

    assert all(isinstance(outcome, NuisanceAudit) for outcome in outcomes)


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_server_failing_inside_the_graph_is_a_launch_failure(grouped: bool):
    auditor = given.an_auditor_raising(TimeoutError("list_tools timed out"), grouped=grouped)

    outcome = await audit_once(an_admitted_server(), auditor)

    assert isinstance(outcome, LaunchFailed)


@_SHAPES
async def test_a_fatal_provider_error_stops_the_run(grouped: bool):
    error = ModelAuthenticationError("invalid key")
    auditor = given.an_auditor_raising(error, grouped=grouped)

    with pytest.raises(ProviderFatal) as stopped:
        await audit_once(an_admitted_server(), auditor)

    assert stopped.value.cause is error


@_SHAPES
async def test_a_transient_provider_error_is_named_without_its_message(grouped: bool):
    auditor = given.an_auditor_raising(ModelAPIError("secret-nonce"), grouped=grouped)

    outcome = await audit_once(an_admitted_server(), auditor)

    assert isinstance(outcome, ProviderErrorAttempt)
    assert "ModelAPIError" in outcome.description
    assert "secret-nonce" not in outcome.description
