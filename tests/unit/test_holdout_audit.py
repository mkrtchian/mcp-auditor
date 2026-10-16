from io import StringIO

import pytest
from rich.console import Console

from evals import holdout_audit as holdout_audit_module
from evals.cve_audit import RefusedAttempt
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVE_TARGETS
from evals.holdout_audit import HOLDOUT_INFRA_ATTEMPTS, RefusedRun, holdout_audit
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


async def test_a_detection_with_a_refused_step_passes_through(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    detection = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([detection])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is detection
    assert attempt.calls == 1


async def test_a_refused_attempt_is_not_retried(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    report = grammar.a_report()
    attempt = _ScriptedAttempts([RefusedAttempt(report)])

    outcome = await holdout_audit(TARGET, attempt)

    assert isinstance(outcome, RefusedRun)
    assert outcome.report is report
    assert attempt.calls == 1


async def test_an_infra_failure_is_retried_twice_then_gives_up(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([None, None, None])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is None
    assert attempt.calls == HOLDOUT_INFRA_ATTEMPTS == 3


async def test_a_raised_error_is_retried_then_the_success_stands(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = _ScriptedAttempts([RuntimeError("transport died"), graded])

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_always_raising_audit_gives_up_after_the_attempts(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([RuntimeError("boom")] * HOLDOUT_INFRA_ATTEMPTS)

    outcome = await holdout_audit(TARGET, attempt)

    assert outcome is None
    assert attempt.calls == HOLDOUT_INFRA_ATTEMPTS == 3


async def test_a_raised_error_prints_its_class_not_its_message(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([_LeakyError("SENTINEL_PROOF_abc123")] * HOLDOUT_INFRA_ATTEMPTS)

    await holdout_audit(TARGET, attempt)

    printed = output.getvalue()
    assert "SENTINEL_PROOF_abc123" not in printed
    assert "_LeakyError" in printed


class _LeakyError(Exception):
    """An error whose message echoes server output, which a holdout run must never print."""


class _ScriptedAttempts:
    def __init__(self, outcomes: list[GradedAudit | RefusedAttempt | Exception | None]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> GradedAudit | RefusedAttempt | None:
        self.calls += 1
        item = self._outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(holdout_audit_module, "console", Console(file=output, width=200))
    return output
