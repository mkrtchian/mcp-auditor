from io import StringIO

import pytest
from rich.console import Console

from evals import cve_audit
from evals.cve_audit import REFUSAL_ATTEMPTS, RefusedAttempt, audit_target, graded_despite_refusals
from evals.cve_grammar import RunGrade
from evals.cve_targets import CVE_TARGETS
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.unit.support.test_cve_oracle_given import a_detected_grade

TARGET = CVE_TARGETS[0]


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(budget=10, concurrency=1, throttles=SessionThrottles())


def test_a_throttled_audit_is_reported_with_its_count(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)

    cve_audit._print_incidents(TARGET, _report_throttled(2))  # pyright: ignore[reportPrivateUsage]

    line = f"{TARGET.cve_id}: throttled 2 time(s) by the model provider (HTTP 429)"
    assert line in output.getvalue()


def test_an_audit_never_throttled_says_nothing_of_throttling(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)

    cve_audit._print_incidents(TARGET, _report_throttled(0))  # pyright: ignore[reportPrivateUsage]

    assert "throttled" not in output.getvalue()


async def test_a_refused_audit_is_audited_again_and_graded_by_the_first_attempt_not_refused(
    monkeypatch: pytest.MonkeyPatch,
):
    _captured_console(monkeypatch)
    detected = a_detected_grade()
    attempt = _ScriptedAttempts([RefusedAttempt(), detected])

    grade = await graded_despite_refusals(TARGET, attempt)

    assert grade == detected
    assert attempt.calls == 2


async def test_an_audit_refused_at_every_attempt_is_a_run_not_completed(
    monkeypatch: pytest.MonkeyPatch,
):
    output = _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([RefusedAttempt()] * REFUSAL_ATTEMPTS)

    grade = await graded_despite_refusals(TARGET, attempt)

    assert grade is None
    assert attempt.calls == REFUSAL_ATTEMPTS
    assert f"{TARGET.cve_id} run skipped" in output.getvalue()


async def test_a_run_skipped_on_launch_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts([None])

    grade = await graded_despite_refusals(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


class _ScriptedAttempts:
    def __init__(self, outcomes: list[RunGrade | RefusedAttempt | None]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> RunGrade | RefusedAttempt | None:
        self.calls += 1
        return self._outcomes.pop(0)


def _captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(cve_audit, "console", Console(file=output, width=200))
    return output


def _report_throttled(times: int) -> AuditReport:
    return AuditReport(
        target="test", tool_reports=[], provider_usage=ProviderUsage(throttled_requests=times)
    )
