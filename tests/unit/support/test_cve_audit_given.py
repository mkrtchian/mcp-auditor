import dataclasses
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import AbstractAsyncContextManager, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from io import StringIO
from typing import Any

import pytest
from rich.console import Console

from evals import cve_audit
from evals.cve_audit import AttemptOutcome, Auditor
from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import CreditCheck, PlantedTarget
from evals.cve_planting_base import PlantingSpec
from evals.cve_replay import RunToCheck
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.failure_text import FULL_DETAIL, ReportDetail
from mcp_auditor.adapters.llm_throttling import ThrottleBreaker, current_breaker
from mcp_auditor.domain.models import AuditReport, AuditStep, MissCause, MissedStep, ProviderUsage
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.support import test_cve_grammar_given as grammar

(TARGET,) = [target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109"]
A_LAUNCH = Launch("x", [])


def captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(cve_audit, "console", Console(file=output, width=200))
    return output


def an_auditor(report_detail: ReportDetail = FULL_DETAIL) -> Auditor:
    return Auditor(FakeLLM([]), FakeLLM([]), budget=10, report_detail=report_detail)


def a_target_launching(launch: Launch = A_LAUNCH) -> CVETarget:
    """A target planting nothing and launching no container, handing its graph launch."""

    @contextmanager
    def no_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield launch

    return dataclasses.replace(TARGET, kept_places=(), builder=no_container)


def a_target_failing_to_launch(error: Exception) -> CVETarget:
    @contextmanager
    def failing_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        raise error
        yield A_LAUNCH

    return dataclasses.replace(TARGET, kept_places=(), builder=failing_container)


@dataclass
class AuditWiringSeen:
    graph_inputs: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    tools_filters: list[frozenset[str] | None] = field(default_factory=list[frozenset[str] | None])
    breakers: list[ThrottleBreaker | None] = field(default_factory=list[ThrottleBreaker | None])
    timeouts: list[int] = field(default_factory=list[int])


def an_audit_reporting(
    monkeypatch: pytest.MonkeyPatch, report: AuditReport | None = None
) -> AuditWiringSeen:
    """Fakes the two imported collaborators, build_graph and connect, and records what they were
    given."""
    seen = AuditWiringSeen()

    class FakeGraph:
        async def ainvoke(self, graph_input: dict[str, object]) -> dict[str, object]:
            seen.graph_inputs.append(graph_input)
            seen.breakers.append(current_breaker())
            return {"audit_report": report or grammar.a_report()}

    def fake_build_graph(*_args: object, **kwargs: Any) -> FakeGraph:
        seen.tools_filters.append(kwargs["tools_filter"])
        return FakeGraph()

    monkeypatch.setattr(cve_audit, "build_graph", fake_build_graph)
    monkeypatch.setattr(cve_audit, "connect", _a_fake_connect(seen.timeouts))
    return seen


def an_audit_raising(
    monkeypatch: pytest.MonkeyPatch, error: Exception, *, grouped: bool = True
) -> None:
    """The graph raises `error`, which leaves the client wrapped in nested groups as the MCP
    SDK's task groups wrap it, or bare as it leaves a server noisy at shutdown."""

    class RaisingGraph:
        async def ainvoke(self, _graph_input: dict[str, object]) -> dict[str, object]:
            raise error

    def raising_build_graph(*_args: object, **_kwargs: object) -> RaisingGraph:
        return RaisingGraph()

    monkeypatch.setattr(cve_audit, "build_graph", raising_build_graph)
    monkeypatch.setattr(cve_audit, "connect", _a_fake_connect([], grouped=grouped))


def _a_fake_connect(
    timeouts: list[int], *, grouped: bool = True
) -> Callable[..., AbstractAsyncContextManager[FakeMCPClient]]:
    @asynccontextmanager
    async def fake_connect(
        _launch: Launch, _stderr: object, *, tool_call_timeout: int
    ) -> AsyncGenerator[FakeMCPClient]:
        timeouts.append(tool_call_timeout)
        try:
            yield FakeMCPClient([])
        except Exception as exc:
            if not grouped:
                raise
            raise ExceptionGroup("client", [ExceptionGroup("session", [exc])]) from None

    return fake_connect


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
    usage = ProviderUsage(throttled_requests=times)
    return grammar.a_report().model_copy(update={"provider_usage": usage})


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


def a_report_billed(input_tokens: int, output_tokens: int) -> AuditReport:
    usage = ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    return grammar.a_report().model_copy(update={"provider_usage": usage})


class ScriptedAttempts[T]:
    def __init__(self, outcomes: list[AttemptOutcome[T]]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> AttemptOutcome[T]:
        self.calls += 1
        return self._outcomes.pop(0)
