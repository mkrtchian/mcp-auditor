from dataclasses import replace

import pytest

from evals.cve.detection.command_deps import AuditTargetFactory, DetectionCommandDeps
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.cve.detection.survey import TargetSurvey
from evals.cve.detection.targets import Target
from evals.session_usage import SessionThrottles
from tests.fakes import FakeContainerSweep
from tests.unit.detection.support.calibration_check_deps import deps_with
from tests.unit.detection.support.run_detection_cli import (
    a_billing_audit_target,
    a_session_auditing_nothing,
    a_session_under_priced_models,
    deps_reaching_nothing,
)


def a_calibration_check(
    *,
    sweep: FakeContainerSweep | None = None,
    raises: bool = False,
    checked: list[str] | None = None,
) -> DetectionCommandDeps:
    """Past the preflight, every target live and fixed, or a configuration error. The flaw IDs
    it checks are appended to checked."""
    return replace(
        deps_reaching_nothing(sweep),
        calibration_check=lambda concurrency, ci: deps_with(raises=raises, checked=checked),
    )


def a_survey(
    *,
    sweep: FakeContainerSweep | None = None,
    raises: bool = False,
    surveyed: list[str] | None = None,
) -> DetectionCommandDeps:
    """Past the preflight, a survey finding no candidate place, or a configuration error. The flaw
    IDs it surveys are appended to surveyed."""

    async def survey_one(target: Target, places: object) -> TargetSurvey:
        if surveyed is not None:
            surveyed.append(target.flaw_id)
        if raises:
            raise ValueError("a kept id with no record")
        return TargetSurvey(target.flaw_id, facts=[], not_plantable=[], not_surveyed=[])

    return replace(deps_reaching_nothing(sweep), survey_one=survey_one)


def a_session_recording_options(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[DetectionCommandDeps, list[DetectionOptions]]:
    """A graded session auditing nothing, under priced models, that keeps the options it gets."""
    received: list[DetectionOptions] = []

    async def session(
        options: DetectionOptions, harness: DetectionHarness
    ) -> DetectionSessionResult:
        received.append(options)
        return await a_session_auditing_nothing(options, harness)

    return replace(a_session_under_priced_models(monkeypatch), session=session), received


def an_audit_target_recording(forced: list[object]) -> AuditTargetFactory:
    def audit_target(
        budget: int, throttles: SessionThrottles, places: object, overrides: object = None
    ) -> AuditTarget:
        forced.append(overrides)
        return a_billing_audit_target(budget, throttles, places)

    return audit_target


async def a_session_that_crashes_if_started(
    options: DetectionOptions, harness: DetectionHarness
) -> DetectionSessionResult:
    # main turns any exception into exit 4, so an exit 3 proves the session never started.
    raise AssertionError("the session must not start")
