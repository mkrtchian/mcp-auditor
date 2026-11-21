"""The attempt outcomes a detection holdout run drops a run on (a run skipped, a throttled attempt,
a provider error), and what each prints under the report detail of either layer."""

import pytest
from langchain_core.exceptions import ModelAPIError, ModelAuthenticationError

from evals.cve.audit_attempts import (
    ProviderErrorAttempt,
    ThrottledAttempt,
    graded_despite_missed_model_calls,
)
from evals.cve.detection.audit import LaunchError, attempt_once
from evals.cve.detection.holdout_audit import HOLDOUT_INFRA_ATTEMPTS, DroppedRun, holdout_audit
from evals.cve.detection.holdout_results import NotRunCause
from evals.cve.detection.session_model import GradedAudit
from evals.cve.environments import Launch
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.launch_audit import UndecidableLaunch
from evals.cve.provider_errors import ProviderFatal
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import MissCause
from tests.unit.cve.support import test_cve_launch_audit_given as launch_given
from tests.unit.detection.support import test_detection_audit_holdout_given as given
from tests.unit.detection.support.detection_audits import (
    TARGET,
    ScriptedAttempts,
    a_report_missing,
    a_target_launching,
    an_auditor_reporting,
    captured_console,
)


async def test_a_run_skipped_on_a_detection_holdout_run_prints_the_error_type_without_its_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = captured_console(monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, launch_given.an_auditor(TYPES_ONLY), SessionThrottles(), {})

    printed = output.getvalue()
    assert f"{target.flaw_id} run skipped" in printed
    assert "LaunchError" in printed
    assert "secret-nonce" not in printed


async def test_a_run_skipped_on_the_acceptance_layer_prints_the_error_message(
    monkeypatch: pytest.MonkeyPatch,
):
    output = captured_console(monkeypatch)
    target = given.a_target_failing_to_launch(LaunchError("secret-nonce"))

    await attempt_once(target, launch_given.an_auditor(), SessionThrottles(), {})

    assert f"{target.flaw_id} run skipped: secret-nonce" in output.getvalue()


async def test_a_missed_model_call_on_a_detection_holdout_run_shows_its_cause_not_the_provider_text(
    monkeypatch: pytest.MonkeyPatch,
):
    output = captured_console(monkeypatch)
    refused = a_report_missing(MissCause.PROVIDER_REFUSAL)
    auditor = an_auditor_reporting(refused, report_detail=TYPES_ONLY)

    await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    printed = output.getvalue()
    assert "Refused by the model provider" in printed
    assert "Invalid prompt" not in printed


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_server_failing_inside_the_graph_is_a_run_skipped(
    monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = captured_console(monkeypatch)
    auditor = given.an_audit_raising(TimeoutError("list_tools timed out"), grouped=grouped)

    outcome = await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert outcome is None
    assert f"{TARGET.flaw_id} run skipped" in output.getvalue()


async def test_a_server_taken_as_down_is_a_run_skipped(monkeypatch: pytest.MonkeyPatch):
    output = captured_console(monkeypatch)
    auditor = given.an_audit_taking_the_server_as_down()

    outcome = await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert outcome is None
    assert f"{TARGET.flaw_id} run skipped" in output.getvalue()


async def test_a_server_taken_as_down_on_a_detection_holdout_run_drops_the_run_as_a_launch_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    captured_console(monkeypatch)
    auditor = given.an_audit_taking_the_server_as_down(audits=HOLDOUT_INFRA_ATTEMPTS)
    target = a_target_launching()

    outcome = await holdout_audit(
        target, lambda: attempt_once(target, auditor, SessionThrottles(), {})
    )

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)


async def test_a_launch_whose_container_name_cannot_be_read_stops_the_run(
    monkeypatch: pytest.MonkeyPatch,
):
    captured_console(monkeypatch)
    target = a_target_launching(Launch("docker", ["run", "--an-unknown-option", "v", "x"]))

    with pytest.raises(UndecidableLaunch):
        await attempt_once(target, launch_given.an_auditor(), SessionThrottles(), {})


@_SHAPES
async def test_a_fatal_provider_error_stops_the_run(monkeypatch: pytest.MonkeyPatch, grouped: bool):
    captured_console(monkeypatch)
    error = ModelAuthenticationError("invalid key")
    auditor = given.an_audit_raising(error, grouped=grouped)

    with pytest.raises(ProviderFatal) as stopped:
        await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert stopped.value.cause is error


@_SHAPES
async def test_a_transient_provider_error_throws_the_attempt_away_naming_it_without_its_message(
    monkeypatch: pytest.MonkeyPatch, grouped: bool
):
    output = captured_console(monkeypatch)
    auditor = given.an_audit_raising(ModelAPIError("secret-nonce"), grouped=grouped)

    outcome = await attempt_once(a_target_launching(), auditor, SessionThrottles(), {})

    assert isinstance(outcome, ProviderErrorAttempt)
    printed = output.getvalue()
    assert f"{TARGET.flaw_id} run skipped" in printed
    assert "ModelAPIError" in printed
    assert "secret-nonce" not in printed


async def test_a_provider_error_attempt_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    captured_console(monkeypatch)
    attempt = ScriptedAttempts[GradedAudit]([ProviderErrorAttempt("ModelAPIError")])

    grade = await graded_despite_missed_model_calls(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


async def test_a_throttled_attempt_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    captured_console(monkeypatch)
    attempt = ScriptedAttempts[GradedAudit]([ThrottledAttempt()])

    grade = await graded_despite_missed_model_calls(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


async def test_an_attempt_holding_a_throttled_model_call_is_thrown_away_before_any_grading(
    monkeypatch: pytest.MonkeyPatch,
):
    output = captured_console(monkeypatch)
    auditor = an_auditor_reporting(a_report_missing(MissCause.PROVIDER_THROTTLED))
    target = a_target_launching()

    outcome = await attempt_once(target, auditor, SessionThrottles(), places={})

    assert isinstance(outcome, ThrottledAttempt)
    printed = " ".join(output.getvalue().split())
    assert f"{target.flaw_id} run skipped: throttled by the model provider past every retry" in (
        printed
    )


async def test_an_attempt_throttled_and_refused_reads_as_throttled(
    monkeypatch: pytest.MonkeyPatch,
):
    captured_console(monkeypatch)
    report = a_report_missing(MissCause.PROVIDER_REFUSAL, MissCause.PROVIDER_THROTTLED)
    auditor = an_auditor_reporting(report)

    outcome = await attempt_once(a_target_launching(), auditor, SessionThrottles(), places={})

    assert isinstance(outcome, ThrottledAttempt)
