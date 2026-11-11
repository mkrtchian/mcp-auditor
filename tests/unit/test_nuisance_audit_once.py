import asyncio

import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

import tests.unit.support.test_eval_display_given as display_given
import tests.unit.support.test_nuisance_audit_once_given as given
from evals.cve import launch_audit
from evals.cve.detection.audit import RunOverrides
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.nuisance import audit as nuisance_audit_module
from evals.cve.nuisance.audit import (
    LaunchFailed,
    NuisanceAudit,
    ProviderError,
    audit_once,
    nuisance_audit,
    nuisance_environment,
)
from evals.cve.provider_errors import ProviderFatal
from evals.cve.server_health import ServerHealth
from evals.cve_environments import Launch
from evals.nuisance_confinement import single_container_run_args
from mcp_auditor.domain.models import MissCause, ProviderUsage
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support import test_cve_launch_audit_given as launch_given
from tests.unit.support import test_nuisance_run_given as run_given
from tests.unit.support.test_nuisance_admission_given import (
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


async def test_a_launch_failure_on_a_nuisance_run_carries_the_error_type_without_its_message():
    lifecycle = given.a_lifecycle_raising(RuntimeError("secret-nonce"))

    outcome = await audit_once(
        given.a_server_backed_by(lifecycle),
        given.an_auditor(TYPES_ONLY),
        backends=a_backend_registry(lifecycle),
    )

    assert isinstance(outcome, LaunchFailed)
    assert "RuntimeError" in outcome.reason
    assert "secret-nonce" not in outcome.reason


async def test_a_missed_step_on_a_nuisance_run_prints_its_cause_without_the_provider_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    refused = given.a_report_refused_with_detail("secret-nonce")
    auditor = given.an_auditor(TYPES_ONLY, launch_given.graph_reporting([refused]))

    await audit_once(an_admitted_server(), auditor)

    assert "Refused by the model provider" in output.getvalue()
    assert "secret-nonce" not in output.getvalue()


async def test_the_run_overrides_reach_the_graph_and_the_client(monkeypatch: pytest.MonkeyPatch):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    graphs = launch_given.graph_reporting([grammar.a_report()])
    connect = launch_given.FakeConnect()
    auditor = given.an_auditor(graphs=graphs, connect=connect, overrides=RunOverrides(7, 9, 11))

    await audit_once(an_admitted_server(), auditor)

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (7, 9)
    assert connect.timeouts == [11]


async def test_a_throttled_attempt_retried_then_a_clean_one_counts_both_throttled_requests(
    monkeypatch: pytest.MonkeyPatch,
):
    display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    throttled = run_given.a_report(
        False, missed=MissCause.PROVIDER_THROTTLED, provider=ProviderUsage(throttled_requests=3)
    )
    clean = run_given.a_report(False, provider=ProviderUsage(throttled_requests=2))
    auditor = given.an_auditor(graphs=launch_given.graph_reporting([throttled, clean]))
    server = an_admitted_server()

    outcome = await nuisance_audit(server, lambda: audit_once(server, auditor))

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.report is clean
    assert auditor.throttles.requests == 5


async def test_an_audit_carries_its_server_health_and_warns_of_a_lost_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)
    server = an_admitted_server()

    outcome = await audit_once(server, given.an_auditor_on_a_noisy_server(lost_calls=1))

    assert isinstance(outcome, NuisanceAudit)
    assert outcome.health == ServerHealth(2, 1)
    assert f"{server.server_package}: server connection lost on 1 call(s)" in output.getvalue()


async def test_an_audit_with_no_lost_connection_says_nothing_of_one(
    monkeypatch: pytest.MonkeyPatch,
):
    output = display_given.a_captured_console(monkeypatch, nuisance_audit_module, launch_audit)

    await audit_once(an_admitted_server(), given.an_auditor_on_a_noisy_server(lost_calls=0))

    assert "connection lost" not in output.getvalue()


async def test_two_concurrent_audits_of_one_backend_server_both_complete():
    lifecycle = given.a_lifecycle_holding_one_lock()
    server = given.a_server_backed_by(lifecycle)
    registry = a_backend_registry(lifecycle)
    auditor = given.an_auditor(
        graphs=launch_given.graph_reporting([grammar.a_report(), grammar.a_report()])
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

    assert isinstance(outcome, ProviderError)
    assert "ModelAPIError" in outcome.reason
    assert "secret-nonce" not in outcome.reason
