from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from io import StringIO

import pytest
from rich.console import Console

from evals import cve_audit, cve_environments
from evals.cve_audit import (
    INCOMPLETE_ATTEMPTS,
    Auditor,
    IncompleteAttempt,
    RunOverrides,
    audit_target,
    graded_despite_refusals,
    graded_or_incomplete,
)
from evals.cve_environments import Launch
from evals.cve_grammar import CreditCheck, CVEStatus, MissClass, PlantedTarget, RunGrade, grade_run
from evals.cve_proofs import UnitPlace
from evals.cve_replay import RunToCheck
from evals.cve_report_units import units_of
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVE_TARGETS
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep, ProviderUsage
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.support import test_cve_grammar_given as grammar
from tests.unit.support.test_cve_oracle_given import a_detected_grade

TARGET = CVE_TARGETS[0]
_REFUSED = frozenset({MissCause.PROVIDER_REFUSAL})


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(budget=10, throttles=SessionThrottles(), places={})


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
    graded = GradedAudit(a_detected_grade(), grammar.a_report(target="second attempt"))
    attempt = _ScriptedAttempts([IncompleteAttempt(grammar.a_report(), _REFUSED), graded])

    outcome = await graded_despite_refusals(TARGET, attempt)

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_audit_refused_at_every_attempt_is_a_run_not_completed(
    monkeypatch: pytest.MonkeyPatch,
):
    output = _captured_console(monkeypatch)
    attempt = _ScriptedAttempts[GradedAudit](
        [IncompleteAttempt(grammar.a_report(), _REFUSED)] * INCOMPLETE_ATTEMPTS
    )

    grade = await graded_despite_refusals(TARGET, attempt)

    assert grade is None
    assert attempt.calls == INCOMPLETE_ATTEMPTS
    assert f"{TARGET.cve_id} run skipped" in output.getvalue()


async def test_a_run_skipped_on_launch_is_not_audited_again(monkeypatch: pytest.MonkeyPatch):
    _captured_console(monkeypatch)
    attempt = _ScriptedAttempts[GradedAudit]([None])

    grade = await graded_despite_refusals(TARGET, attempt)

    assert grade is None
    assert attempt.calls == 1


def test_a_detection_is_kept_whatever_step_the_provider_refused():
    outcome = graded_or_incomplete(a_detected_grade(), _refused(grammar.a_report()))

    assert isinstance(outcome, RunGrade)
    assert outcome.status == CVEStatus.DETECTED


def test_a_miss_with_a_refused_step_is_not_graded():
    missed = grammar.a_missed_run(MissClass.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, _refused(grammar.a_report()))

    assert isinstance(outcome, IncompleteAttempt)


def test_a_miss_with_no_refused_step_is_graded_a_miss():
    missed = grammar.a_missed_run(MissClass.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, grammar.a_report())

    assert isinstance(outcome, RunGrade)
    assert outcome.status == CVEStatus.MISSED


def test_a_struck_only_credit_with_a_refused_step_reads_as_refused():
    # The replay struck the run's only credit, so the final grade is a miss. A refused step then
    # makes it a refusal, not a genuine miss, so a refusal never poisons the gate or the baseline.
    struck = RunGrade(
        status=CVEStatus.MISSED,
        miss_class=MissClass.AIMED_NO_PROOF,
        struck_places=frozenset({grammar.PLACE}),
    )

    outcome = graded_or_incomplete(struck, _refused(grammar.a_report()))

    assert isinstance(outcome, IncompleteAttempt)


async def test_a_non_detecting_run_is_graded_without_replaying():
    run = _a_run(grammar.a_report(cases=[grammar.a_case(verdict=grammar.PASS)]))

    grade = await cve_audit._checked_grade(run, replay=_replay_that_must_not_run)  # pyright: ignore[reportPrivateUsage]

    assert grade.status == grade_run(run.run_target, units_of(run.report)).status


async def test_a_detecting_run_is_regraded_on_the_credits_the_replay_strikes():
    report = grammar.a_report(
        cases=[
            grammar.a_case(
                response=f"leaked {grammar.SENTINEL}", arguments={"path": grammar.AIMED_PATH}
            )
        ]
    )
    run = _a_run(report, {grammar.PLACE: grammar.SENTINEL})
    struck = CreditCheck(frozenset({UnitPlace(0, grammar.PLACE)}), unchecked=False)

    grade = await cve_audit._checked_grade(run, replay=_replay_returning(struck))  # pyright: ignore[reportPrivateUsage]

    assert grade.status == CVEStatus.MISSED


async def test_run_overrides_replace_the_launch_chain_settings_in_the_graph_input(
    monkeypatch: pytest.MonkeyPatch,
):
    recorded = _capture_graph_input(monkeypatch)
    launch = Launch(command="x", args=[], chain_budget=3, max_chain_steps=5)
    overrides = RunOverrides(chain_budget=7, max_chain_steps=9, tool_call_timeout=11)

    await cve_audit._audit(launch, TARGET, _an_auditor(), overrides)  # pyright: ignore[reportPrivateUsage]

    assert recorded["chain_budget"] == 7
    assert recorded["max_chain_steps"] == 9


async def test_no_overrides_keeps_the_launch_chain_settings_in_the_graph_input(
    monkeypatch: pytest.MonkeyPatch,
):
    recorded = _capture_graph_input(monkeypatch)
    launch = Launch(command="x", args=[], chain_budget=3, max_chain_steps=5)

    await cve_audit._audit(launch, TARGET, _an_auditor(), None)  # pyright: ignore[reportPrivateUsage]

    assert recorded["chain_budget"] == 3
    assert recorded["max_chain_steps"] == 5


async def test_run_overrides_pass_the_timeout_to_the_client(monkeypatch: pytest.MonkeyPatch):
    seen = _capture_connect_timeout(monkeypatch)
    overrides = RunOverrides(chain_budget=1, max_chain_steps=1, tool_call_timeout=17)

    async with cve_audit._silent_client(Launch("x", []), overrides):  # pyright: ignore[reportPrivateUsage]
        pass

    assert seen["timeout"] == 17


async def test_no_overrides_leaves_the_client_default_timeout(monkeypatch: pytest.MonkeyPatch):
    seen = _capture_connect_timeout(monkeypatch)

    async with cve_audit._silent_client(Launch("x", []), None):  # pyright: ignore[reportPrivateUsage]
        pass

    assert seen["timeout"] == cve_environments.TOOL_CALL_TIMEOUT


def _an_auditor() -> Auditor:
    return Auditor(FakeLLM([]), FakeLLM([]), budget=10)


def _capture_graph_input(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    recorded: dict[str, object] = {}

    class _FakeGraph:
        async def ainvoke(self, graph_input: dict[str, object]) -> dict[str, object]:
            recorded.update(graph_input)
            return {"audit_report": grammar.a_report()}

    def _fake_build_graph(*_args: object, **_kwargs: object) -> _FakeGraph:
        return _FakeGraph()

    @asynccontextmanager
    async def _fake_client(_launch: Launch, _overrides: RunOverrides | None):
        yield FakeMCPClient([])

    monkeypatch.setattr(cve_audit, "build_graph", _fake_build_graph)
    monkeypatch.setattr(cve_audit, "_silent_client", _fake_client)
    return recorded


def _capture_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    seen: dict[str, int] = {}

    @asynccontextmanager
    async def _fake_connect(
        _launch: Launch,
        _stderr: object,
        *,
        tool_call_timeout: int = cve_environments.TOOL_CALL_TIMEOUT,
    ):
        seen["timeout"] = tool_call_timeout
        yield FakeMCPClient([])

    monkeypatch.setattr(cve_audit, "connect", _fake_connect)
    return seen


def _a_run(report: AuditReport, nonces: dict[str, str] | None = None) -> RunToCheck:
    return RunToCheck(
        target=TARGET,
        run_target=PlantedTarget(TARGET.mechanism, TARGET.aim, nonces or {}),
        report=report,
        recorded_calls=[],
        records=(),
    )


async def _replay_that_must_not_run(_run: RunToCheck) -> CreditCheck:
    raise AssertionError("a non-detecting run must be graded without replaying")


def _replay_returning(check: CreditCheck) -> Callable[[RunToCheck], Awaitable[CreditCheck]]:
    async def replay(_run: RunToCheck) -> CreditCheck:
        return check

    return replay


def _refused(report: AuditReport) -> AuditReport:
    refusal = MissedStep(
        tool_name="git_init",
        step=AuditStep.CHAIN_PLANNING,
        cause=MissCause.PROVIDER_REFUSAL,
        detail="Invalid prompt",
    )
    return report.model_copy(update={"missed_steps": [refusal]})


class _ScriptedAttempts[T]:
    def __init__(self, outcomes: list[T | IncompleteAttempt | None]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> T | IncompleteAttempt | None:
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
