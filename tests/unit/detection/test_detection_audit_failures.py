"""The attempts `attempt_once` throws away (a run skipped at launch or on a server taken as down, a
provider error, a throttled attempt, a launch whose container name cannot be read), the run a
failed teardown keeps, and what each prints under the report detail of either layer."""

import subprocess

import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.audit_attempts import ProviderErrorAttempt, ThrottledAttempt
from evals.cve.detection.audit import LaunchError, attempt_once
from evals.cve.detection.holdout_audit import HOLDOUT_INFRA_ATTEMPTS, DroppedRun, holdout_audit
from evals.cve.detection.holdout_results import NotRunCause
from evals.cve.detection.session_model import GradedAudit
from evals.cve.environments import Launch
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.launch_audit import UndecidableLaunch
from evals.model_provider_errors import ProviderFatal
from mcp_auditor.domain.model_calls import MissedCallCause
from tests.unit.detection.support import test_detection_audit_failures_given as given
from tests.unit.detection.support.detection_audits import (
    TARGET,
    a_report_missing,
    a_target_launching,
    an_auditor_reporting,
    in_session,
)
from tests.unit.support.captured_console import a_captured_console


async def test_a_run_skipped_on_a_detection_holdout_run_prints_the_error_type_without_its_message(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, in_session(launch_audit_fakes.an_auditor(TYPES_ONLY)), {})

    printed = output.getvalue()
    assert f"{target.flaw_id} run skipped" in printed
    assert "LaunchError" in printed
    assert "secret-nonce" not in printed


async def test_a_run_skipped_on_the_acceptance_layer_prints_the_error_message(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, in_session(launch_audit_fakes.an_auditor()), {})

    assert f"{target.flaw_id} run skipped: secret-nonce" in output.getvalue()


async def test_a_teardown_failing_after_the_audit_keeps_the_completed_run(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    target = given.a_target_failing_at_teardown(subprocess.CalledProcessError(1, "docker rm"))
    auditor = an_auditor_reporting(grammar.a_report())

    outcome = await attempt_once(target, in_session(auditor), {})

    assert isinstance(outcome, GradedAudit)
    printed = output.getvalue()
    assert f"{target.flaw_id} teardown failed" in printed
    assert "run skipped" not in printed


async def test_a_missed_model_call_on_a_detection_holdout_run_shows_its_cause_not_the_provider_text(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    refused = a_report_missing(MissedCallCause.PROVIDER_REFUSAL)
    auditor = an_auditor_reporting(refused, report_detail=TYPES_ONLY)

    await attempt_once(a_target_launching(), in_session(auditor), {})

    printed = output.getvalue()
    assert "Refused by the model provider" in printed
    assert "Invalid prompt" not in printed


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_server_failing_inside_the_graph_is_a_run_skipped(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_raising(TimeoutError("list_tools timed out"), grouped=grouped)

    outcome = await attempt_once(a_target_launching(), in_session(auditor), {})

    assert outcome is None
    assert f"{TARGET.flaw_id} run skipped" in output.getvalue()


async def test_a_server_taken_as_down_is_a_run_skipped(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_taking_the_server_as_down()

    outcome = await attempt_once(a_target_launching(), in_session(auditor), {})

    assert outcome is None
    assert f"{TARGET.flaw_id} run skipped" in output.getvalue()


async def test_a_server_taken_as_down_on_a_detection_holdout_run_drops_the_run_as_a_launch_failure(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_taking_the_server_as_down(audits=HOLDOUT_INFRA_ATTEMPTS)
    target = a_target_launching()

    outcome = await holdout_audit(target, lambda: attempt_once(target, in_session(auditor), {}))

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)


async def test_a_launch_whose_container_name_cannot_be_read_stops_the_run(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    target = a_target_launching(Launch("docker", ["run", "--an-unknown-option", "v", "x"]))

    with pytest.raises(UndecidableLaunch):
        await attempt_once(target, in_session(launch_audit_fakes.an_auditor()), {})


@_SHAPES
async def test_a_fatal_provider_error_stops_the_run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    a_captured_console(capsys, monkeypatch)
    error = ModelAuthenticationError("invalid key")
    auditor = given.an_audit_raising(error, grouped=grouped)

    with pytest.raises(ProviderFatal) as stopped:
        await attempt_once(a_target_launching(), in_session(auditor), {})

    assert stopped.value.cause is error


@_SHAPES
async def test_a_transient_provider_error_throws_the_attempt_away_naming_it_without_its_message(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = given.an_audit_raising(ModelAPIError("secret-nonce"), grouped=grouped)

    outcome = await attempt_once(a_target_launching(), in_session(auditor), {})

    assert isinstance(outcome, ProviderErrorAttempt)
    printed = output.getvalue()
    assert f"{TARGET.flaw_id} run skipped" in printed
    assert "ModelAPIError" in printed
    assert "secret-nonce" not in printed


async def test_an_attempt_holding_a_throttled_model_call_is_thrown_away_before_any_grading(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    auditor = an_auditor_reporting(a_report_missing(MissedCallCause.PROVIDER_THROTTLED))
    target = a_target_launching()

    outcome = await attempt_once(target, in_session(auditor), places={})

    assert isinstance(outcome, ThrottledAttempt)
    printed = " ".join(output.getvalue().split())
    assert f"{target.flaw_id} run skipped: throttled by the model provider past every retry" in (
        printed
    )


async def test_an_attempt_throttled_and_refused_reads_as_throttled(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    report = a_report_missing(MissedCallCause.PROVIDER_REFUSAL, MissedCallCause.PROVIDER_THROTTLED)
    auditor = an_auditor_reporting(report)

    outcome = await attempt_once(a_target_launching(), in_session(auditor), places={})

    assert isinstance(outcome, ThrottledAttempt)
