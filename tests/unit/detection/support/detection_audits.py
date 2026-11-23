import dataclasses
from collections.abc import Generator, Sequence
from contextlib import contextmanager

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.audit_attempts import AttemptOutcome
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.launch_audit import NO_OVERRIDES, Auditor, RunOverrides, SessionAuditor
from evals.cve.planting_base import PlantingSpec
from evals.session_usage import SessionThrottles
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditReport
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target

TARGET = an_acceptance_target(FILESYSTEM)
A_LAUNCH = Launch("docker", ["run", "x"])


def an_auditor_reporting(
    *reports: AuditReport, report_detail: ReportDetail = FULL_DETAIL
) -> Auditor:
    return launch_audit_fakes.an_auditor(
        report_detail, launch_audit_fakes.graph_reporting(list(reports))
    )


def in_session(
    auditor: Auditor,
    overrides: RunOverrides = NO_OVERRIDES,
    throttles: SessionThrottles | None = None,
) -> SessionAuditor:
    return SessionAuditor(
        auditor, overrides, SessionThrottles() if throttles is None else throttles
    )


def a_target_launching(launch: Launch = A_LAUNCH) -> Target:
    """A target planting nothing and launching no container."""

    @contextmanager
    def no_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield launch

    return dataclasses.replace(TARGET, kept_places=(), builder=no_container)


def a_report_missing(*causes: MissedCallCause) -> AuditReport:
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
    def __init__(self, outcomes: Sequence[AttemptOutcome[T] | BaseException]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def __call__(self) -> AttemptOutcome[T]:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome
