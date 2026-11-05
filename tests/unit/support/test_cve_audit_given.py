import dataclasses
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from io import StringIO

import pytest

import tests.unit.support.test_audit_launch_given as launch_given
import tests.unit.support.test_eval_display_given as display_given
from evals import audit_attempts, cve_audit, launch_audit
from evals.audit_attempts import AttemptOutcome
from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import PlantedTarget
from evals.cve_planting_base import PlantingSpec
from evals.cve_replay import ReplayOutcome, RunToCheck
from evals.cve_targets import CVE_TARGETS, CVETarget
from evals.failure_text import FULL_DETAIL, ReportDetail
from evals.launch_audit import Auditor
from mcp_auditor.domain.models import (
    AuditReport,
    AuditStep,
    MissCause,
    MissedStep,
    ProviderUsage,
)
from tests.unit.support import test_cve_grammar_given as grammar

(TARGET,) = [target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109"]
A_LAUNCH = Launch("x", [])


def captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(monkeypatch, cve_audit, audit_attempts, launch_audit)


def an_auditor_reporting(
    *reports: AuditReport, report_detail: ReportDetail = FULL_DETAIL
) -> Auditor:
    return launch_given.an_auditor(report_detail, launch_given.graph_reporting(list(reports)))


def a_target_launching() -> CVETarget:
    """A target planting nothing and launching no container."""

    @contextmanager
    def no_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield A_LAUNCH

    return dataclasses.replace(TARGET, kept_places=(), builder=no_container)


def a_target_failing_to_launch(error: Exception) -> CVETarget:
    @contextmanager
    def failing_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        raise error
        yield A_LAUNCH

    return dataclasses.replace(TARGET, kept_places=(), builder=failing_container)


def an_audit_on_a_noisy_server(*, non_protocol_lines: int, lost_calls: int) -> Auditor:
    """The graph sends one call per lost connection, each answered "Connection closed", to a
    client that read `non_protocol_lines` lines it could not parse."""
    return launch_given.an_auditor(
        graphs=launch_given.graph_calling(lost_calls),
        connect=launch_given.FakeConnect(launch_given.a_noisy_client(non_protocol_lines)),
    )


def an_audit_raising(error: Exception, *, grouped: bool = True) -> Auditor:
    return launch_given.an_auditor(
        graphs=launch_given.graph_raising(error),
        connect=launch_given.FakeConnect(grouped=grouped),
    )


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
        run_target=PlantedTarget(TARGET.mechanisms, TARGET.aim, nonces or {}),
        report=report,
        recorded_calls=[],
        records=(),
    )


def a_detecting_run() -> RunToCheck:
    report = grammar.a_report(
        cases=[
            grammar.a_case(
                response=f"leaked {grammar.SENTINEL}", arguments={"path": grammar.AIMED_PATH}
            )
        ]
    )
    return a_run(report, {grammar.PLACE: grammar.SENTINEL})


async def a_replay_that_must_not_run(_run: RunToCheck) -> ReplayOutcome:
    raise AssertionError("a non-detecting run must be graded without replaying")


def a_replay_returning(
    outcome: ReplayOutcome,
) -> Callable[[RunToCheck], Awaitable[ReplayOutcome]]:
    async def replay(_run: RunToCheck) -> ReplayOutcome:
        return outcome

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
