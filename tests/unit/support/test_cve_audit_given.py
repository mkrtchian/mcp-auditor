import dataclasses
from collections.abc import Awaitable, Callable, Generator
from contextlib import asynccontextmanager, contextmanager
from io import StringIO

import pytest
from rich.console import Console

from evals import cve_audit, cve_environments
from evals.cve_audit import Auditor, IncompleteAttempt, RunOverrides, ThrottledAttempt
from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import CreditCheck, PlantedTarget
from evals.cve_planting_base import PlantingSpec
from evals.cve_replay import RecordedCall, RunToCheck
from evals.cve_targets import CVE_TARGETS, CVETarget
from mcp_auditor.adapters.llm_throttling import ThrottleBreaker, current_breaker
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep, ProviderUsage
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.support import test_cve_grammar_given as grammar

TARGET = CVE_TARGETS[0]


def captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(cve_audit, "console", Console(file=output, width=200))
    return output


def an_auditor() -> Auditor:
    return Auditor(FakeLLM([]), FakeLLM([]), budget=10)


def a_target_launching_nothing() -> CVETarget:
    """The first target, planting nothing and launching no container."""

    @contextmanager
    def no_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield Launch("x", [])

    return dataclasses.replace(TARGET, kept_places=(), builder=no_container)


def an_audit_reporting(monkeypatch: pytest.MonkeyPatch, report: AuditReport) -> None:
    async def audit(*_args: object) -> tuple[AuditReport, list[RecordedCall]]:
        return report, []

    monkeypatch.setattr(cve_audit, "_audit", audit)


def a_grading_that_must_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    async def grade(_run: RunToCheck) -> object:
        raise AssertionError("a throttled attempt must be thrown away before any grading")

    monkeypatch.setattr(cve_audit, "_checked_grade", grade)


def a_report_missing(*causes: MissCause) -> AuditReport:
    missed = [
        MissedStep(
            tool_name="git_init",
            step=AuditStep.CHAIN_PLANNING,
            cause=cause,
            detail="Invalid prompt",
        )
        for cause in causes
    ]
    return grammar.a_report().model_copy(update={"missed_steps": missed})


def a_report_throttled(times: int) -> AuditReport:
    return AuditReport(
        target="test", tool_reports=[], provider_usage=ProviderUsage(throttled_requests=times)
    )


def a_run(report: AuditReport, nonces: dict[str, str] | None = None) -> RunToCheck:
    return RunToCheck(
        target=TARGET,
        run_target=PlantedTarget(TARGET.mechanism, TARGET.aim, nonces or {}),
        report=report,
        recorded_calls=[],
        records=(),
    )


async def a_replay_that_must_not_run(_run: RunToCheck) -> CreditCheck:
    raise AssertionError("a non-detecting run must be graded without replaying")


def a_replay_returning(check: CreditCheck) -> Callable[[RunToCheck], Awaitable[CreditCheck]]:
    async def replay(_run: RunToCheck) -> CreditCheck:
        return check

    return replay


def captured_graph_input(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    recorded: dict[str, object] = {}
    _a_graph_running(monkeypatch, lambda graph_input: recorded.update(graph_input))
    return recorded


def breakers_seen_by_the_graph(monkeypatch: pytest.MonkeyPatch) -> list[ThrottleBreaker | None]:
    seen: list[ThrottleBreaker | None] = []
    _a_graph_running(monkeypatch, lambda _graph_input: seen.append(current_breaker()))
    return seen


def _a_graph_running(
    monkeypatch: pytest.MonkeyPatch, observe: Callable[[dict[str, object]], object]
) -> None:
    class _FakeGraph:
        async def ainvoke(self, graph_input: dict[str, object]) -> dict[str, object]:
            observe(graph_input)
            return {"audit_report": grammar.a_report()}

    def _fake_build_graph(*_args: object, **_kwargs: object) -> _FakeGraph:
        return _FakeGraph()

    @asynccontextmanager
    async def _fake_client(_launch: Launch, _overrides: RunOverrides | None):
        yield FakeMCPClient([])

    monkeypatch.setattr(cve_audit, "build_graph", _fake_build_graph)
    monkeypatch.setattr(cve_audit, "_silent_client", _fake_client)


def captured_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
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


class ScriptedAttempts[T]:
    def __init__(self, outcomes: list[T | IncompleteAttempt | ThrottledAttempt | None]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> T | IncompleteAttempt | ThrottledAttempt | None:
        self.calls += 1
        return self._outcomes.pop(0)
