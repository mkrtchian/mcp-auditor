from collections.abc import Callable

import pytest

from evals import run_detection
from evals.cve.detection import no_llm_modes
from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.metrics import SessionThrottles
from tests.unit.detection.support.run_detection_cli import (
    a_billing_audit_target,
    a_session_auditing_nothing,
    a_session_under_priced_models,
)
from tests.unit.detection.support.test_detection_calibration_check_exit_given import deps_with


def a_calibration(
    monkeypatch: pytest.MonkeyPatch, *, raises: bool = False, checked: list[str] | None = None
) -> None:
    """Past the preflight, every fixture admitted and live, or a configuration error. The flaw
    IDs it checks are appended to checked."""
    monkeypatch.setattr(run_detection, "preflight_ok", lambda: True)

    def default_calibration_check_deps(*_args: object, **_kwargs: object) -> CalibrationCheckDeps:
        return deps_with(raises=raises, checked=checked)

    monkeypatch.setattr(
        no_llm_modes, "default_calibration_check_deps", default_calibration_check_deps
    )


def a_survey(monkeypatch: pytest.MonkeyPatch, *, raises: bool = False) -> None:
    monkeypatch.setattr(run_detection, "preflight_ok", lambda: True)

    async def survey_all(*_args: object, **_kwargs: object) -> None:
        if raises:
            raise ValueError("a kept id with no record")

    monkeypatch.setattr(no_llm_modes, "survey_all", survey_all)


def a_session_recording_options(monkeypatch: pytest.MonkeyPatch) -> list[DetectionOptions]:
    """A graded session auditing nothing, under priced models, that keeps the options it gets."""
    a_session_under_priced_models(monkeypatch)
    received: list[DetectionOptions] = []

    async def session(
        options: DetectionOptions, harness: DetectionHarness
    ) -> DetectionSessionResult:
        received.append(options)
        return await a_session_auditing_nothing(options, harness)

    monkeypatch.setattr(run_detection, "run_gated", session)
    return received


def an_audit_target_recording(forced: list[object]) -> Callable[..., AuditTarget]:
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
