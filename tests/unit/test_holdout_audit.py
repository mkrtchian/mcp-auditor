from io import StringIO

import pytest
from rich.console import Console

from evals import holdout_audit as holdout_audit_module
from evals.cve_audit import IncompleteAttempt, ThrottledAttempt
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVE_TARGETS
from evals.holdout_audit import (
    HOLDOUT_INFRA_ATTEMPTS,
    DroppedRun,
    IncompleteRun,
    holdout_audit,
)
from evals.holdout_results import NotRunCause
from mcp_auditor.domain.models import MissCause
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support.test_cve_oracle_given import a_detected_grade

TARGET = CVE_TARGETS[0]


async def test_a_graded_audit_passes_through(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 1


@pytest.mark.parametrize(
    "causes",
    [
        frozenset({MissCause.UNREADABLE_ANSWER}),
        frozenset({MissCause.PROVIDER_REFUSAL}),
        frozenset({MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER}),
    ],
)
async def test_an_incomplete_attempt_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, causes: frozenset[MissCause]
):
    _captured_console(monkeypatch)
    report = grammar.a_report()
    attempt = _ScriptedAttempts([IncompleteAttempt(report, causes)])

    outcome = await holdout_audit(TARGET, attempt)

    assert isinstance(outcome, IncompleteRun)
    assert outcome.report is report
    assert attempt.calls == 1


async def test_an_attempt_missing_steps_names_their_causes(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)
    causes = frozenset({MissCause.PROVIDER_REFUSAL, MissCause.UNREADABLE_ANSWER})

    await holdout_audit(TARGET, _ScriptedAttempts([IncompleteAttempt(grammar.a_report(), causes)]))

    assert (
        f"{TARGET.cve_id}: refused by the model provider and unreadable model answer,"
        " counted as not detected"
    ) in output.getvalue()


async def test_an_infra_failure_is_retried_and_a_later_graded_attempt_stands(
    monkeypatch: pytest.MonkeyPatch,
):
    _captured_console(monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([None, graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_infra_failure_is_retried_twice_then_gives_up(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([None, None, None])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome == DroppedRun(NotRunCause.LAUNCH_FAILURE)
    assert attempt.calls == HOLDOUT_INFRA_ATTEMPTS == 3


async def test_a_throttled_attempt_is_retried_and_a_later_graded_attempt_stands(
    monkeypatch: pytest.MonkeyPatch,
):
    output = _captured_console(monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([ThrottledAttempt(), graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2
    assert (
        f"{TARGET.cve_id}: throttled by the model provider past every retry,"
        f" attempt 1/{HOLDOUT_INFRA_ATTEMPTS}"
    ) in output.getvalue()


@pytest.mark.parametrize(
    "outcomes",
    [
        [ThrottledAttempt()] * HOLDOUT_INFRA_ATTEMPTS,
        [None, ThrottledAttempt(), None],
    ],
)
async def test_a_run_throttled_at_any_attempt_is_dropped_as_throttled(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[ThrottledAttempt | None]
):
    _captured_console(monkeypatch)

    outcome = await holdout_audit(TARGET, _ScriptedAttempts([*outcomes]))

    assert outcome == DroppedRun(NotRunCause.THROTTLED)


class _ScriptedAttempts:
    def __init__(
        self, outcomes: list[GradedAudit | IncompleteAttempt | ThrottledAttempt | None]
    ) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> GradedAudit | IncompleteAttempt | ThrottledAttempt | None:
        self.calls += 1
        return self._outcomes.pop(0)


def _captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(holdout_audit_module, "console", Console(file=output, width=200))
    return output
