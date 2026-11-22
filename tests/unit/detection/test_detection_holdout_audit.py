from collections.abc import Sequence

import pytest
from langchain_core.exceptions import ModelAuthenticationError

import tests.unit.support.grammar_inputs as grammar
from evals.cve.audit_attempts import (
    AttemptOutcome,
    IncompleteAttempt,
    ProviderErrorAttempt,
    ThrottledAttempt,
)
from evals.cve.detection.holdout_audit import (
    HOLDOUT_INFRA_ATTEMPTS,
    DroppedRun,
    IncompleteRun,
    holdout_audit,
)
from evals.cve.detection.holdout_results import NotRunCause
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.provider_errors import ProviderFatal
from evals.cve.server_health import ServerHealth
from mcp_auditor.domain.model_calls import MissedCallCause
from tests.unit.detection.support.detection_reports import a_detected_grade
from tests.unit.support.captured_console import a_captured_console

TARGET = ACCEPTANCE_TARGETS[0]
_PROVIDER_ERROR = ProviderErrorAttempt("ModelAPIError, status 500")


async def test_a_graded_audit_passes_through(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 1


@pytest.mark.parametrize(
    "causes",
    [
        frozenset({MissedCallCause.UNREADABLE_ANSWER}),
        frozenset({MissedCallCause.PROVIDER_REFUSAL}),
        frozenset({MissedCallCause.PROVIDER_REFUSAL, MissedCallCause.UNREADABLE_ANSWER}),
    ],
)
async def test_an_incomplete_attempt_is_not_retried(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    causes: frozenset[MissedCallCause],
):
    a_captured_console(capsys, monkeypatch)
    report = grammar.a_report()
    attempt = _ScriptedAttempts([IncompleteAttempt(report, causes)])

    outcome = await holdout_audit(TARGET, attempt)

    assert isinstance(outcome, IncompleteRun)
    assert outcome.report is report
    assert attempt.calls == 1


async def test_an_incomplete_run_carries_the_server_health_of_its_attempt(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    refused = frozenset({MissedCallCause.PROVIDER_REFUSAL})
    health = ServerHealth(2, 1, relaunches=1, unsent_calls=4)
    incomplete = IncompleteAttempt(grammar.a_report(), refused, health)

    outcome = await holdout_audit(TARGET, _ScriptedAttempts([incomplete]))

    assert isinstance(outcome, IncompleteRun)
    assert outcome.health == health


async def test_an_attempt_missing_steps_names_their_causes(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    causes = frozenset({MissedCallCause.PROVIDER_REFUSAL, MissedCallCause.UNREADABLE_ANSWER})

    await holdout_audit(TARGET, _ScriptedAttempts([IncompleteAttempt(grammar.a_report(), causes)]))

    assert (
        f"{TARGET.flaw_id}: refused by the model provider and unreadable model answer,"
        " counted as not detected"
    ) in output.getvalue()


async def test_an_infra_failure_is_retried_and_a_later_graded_attempt_stands(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([None, graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_infra_failure_is_retried_twice_then_gives_up(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    attempt = _ScriptedAttempts([None, None, None])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == HOLDOUT_INFRA_ATTEMPTS == 3


async def test_a_throttled_attempt_is_retried_and_a_later_graded_attempt_stands(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([ThrottledAttempt(), graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2
    assert (
        f"{TARGET.flaw_id}: throttled by the model provider past every retry,"
        f" attempt 1/{HOLDOUT_INFRA_ATTEMPTS}"
    ) in output.getvalue()


@pytest.mark.parametrize(
    "outcomes",
    [
        [ThrottledAttempt()] * HOLDOUT_INFRA_ATTEMPTS,
        [None, ThrottledAttempt(), None],
        [_PROVIDER_ERROR, ThrottledAttempt(), None],
    ],
)
async def test_a_run_throttled_at_any_attempt_is_dropped_as_throttled(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[AttemptOutcome[GradedAudit]],
):
    a_captured_console(capsys, monkeypatch)

    outcome = await holdout_audit(TARGET, _ScriptedAttempts([*outcomes]))

    assert outcome == DroppedRun(NotRunCause.THROTTLED)


async def test_a_fatal_provider_error_stops_the_run_at_once(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    a_captured_console(capsys, monkeypatch)
    attempt = _ScriptedAttempts([ProviderFatal(ModelAuthenticationError("invalid key"))])

    with pytest.raises(ProviderFatal):
        await holdout_audit(TARGET, attempt)

    assert attempt.calls == 1


async def test_a_provider_error_at_every_attempt_drops_the_run_as_a_provider_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    attempt = _ScriptedAttempts([_PROVIDER_ERROR] * HOLDOUT_INFRA_ATTEMPTS)

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)
    assert attempt.calls == HOLDOUT_INFRA_ATTEMPTS
    assert f"{TARGET.flaw_id}: provider error (ModelAPIError, status 500), attempt 1/3" in (
        output.getvalue()
    )


async def test_a_provider_error_is_retried_and_a_later_graded_attempt_stands(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())

    outcome = await holdout_audit(TARGET, _ScriptedAttempts([_PROVIDER_ERROR, graded]))

    assert outcome is graded


async def test_a_run_failing_on_a_provider_error_and_a_launch_drops_as_a_provider_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)

    outcome = await holdout_audit(TARGET, _ScriptedAttempts([None, _PROVIDER_ERROR, None]))

    assert outcome == DroppedRun(NotRunCause.PROVIDER_ERROR)


class _ScriptedAttempts:
    def __init__(self, outcomes: Sequence[AttemptOutcome[GradedAudit] | ProviderFatal]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def __call__(self) -> AttemptOutcome[GradedAudit]:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, ProviderFatal):
            raise outcome
        return outcome
