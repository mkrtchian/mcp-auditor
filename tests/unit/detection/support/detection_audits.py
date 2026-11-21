import dataclasses
from collections.abc import Generator
from contextlib import contextmanager
from io import StringIO

import pytest

import tests.unit.cve.support.test_cve_launch_audit_given as launch_given
import tests.unit.evals.support.test_eval_display_given as display_given
from evals.cve import audit_attempts, launch_audit
from evals.cve.audit_attempts import AttemptOutcome
from evals.cve.detection import audit as detection_audit
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.launch_audit import Auditor
from evals.cve.planting_base import PlantingSpec
from mcp_auditor.domain.models import AuditReport, MissCause, MissedModelCall, ModelCallKind
from tests.unit.cve.support import test_cve_grammar_given as grammar
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target

TARGET = an_acceptance_target(FILESYSTEM)
A_LAUNCH = Launch("docker", ["run", "x"])


def captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(
        monkeypatch, detection_audit, audit_attempts, launch_audit
    )


def an_auditor_reporting(
    *reports: AuditReport, report_detail: ReportDetail = FULL_DETAIL
) -> Auditor:
    return launch_given.an_auditor(report_detail, launch_given.graph_reporting(list(reports)))


def a_target_launching(launch: Launch = A_LAUNCH) -> Target:
    """A target planting nothing and launching no container."""

    @contextmanager
    def no_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield launch

    return dataclasses.replace(TARGET, kept_places=(), builder=no_container)


def a_report_missing(*causes: MissCause) -> AuditReport:
    missed = [
        MissedModelCall(
            tool_name="git_init",
            kind=ModelCallKind.CHAIN_PLANNING,
            cause=cause,
            detail="Invalid prompt",
        )
        for cause in causes
    ]
    return grammar.a_report().model_copy(update={"missed_model_calls": missed})


class ScriptedAttempts[T]:
    def __init__(self, outcomes: list[AttemptOutcome[T]]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> AttemptOutcome[T]:
        self.calls += 1
        return self._outcomes.pop(0)
