"""What the run_detection command reaches outside the process: Docker, git, the auditor and the
session. Building it does no I/O. It must not import the holdout target module, so that no holdout
target can reach the detection gate's command."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from evals.cve.detection.audit import RunOverrides, audit_target
from evals.cve.detection.calibration_check_exit import (
    CalibrationCheckDeps,
    default_calibration_check_deps,
)
from evals.cve.detection.session import DetectionSessionResult, run_gated
from evals.cve.detection.session_model import AuditTarget, DetectionHarness, DetectionOptions
from evals.cve.detection.survey import TargetSurvey, survey_one
from evals.cve.detection.targets import Target
from evals.cve.places import Places
from evals.cve.run_images import DOCKER_SWEEP, ContainerSweep
from evals.detection_preflight import preflight_ok
from evals.eval_session import TreeState, read_tree
from evals.metrics import SessionThrottles


class AuditTargetFactory(Protocol):
    def __call__(
        self,
        budget: int,
        throttles: SessionThrottles,
        places: Places,
        overrides: RunOverrides | None = None,
        /,
    ) -> AuditTarget: ...


class RunSession(Protocol):
    def __call__(
        self, options: DetectionOptions, harness: DetectionHarness, /
    ) -> Awaitable[DetectionSessionResult]: ...


class CalibrationCheckFactory(Protocol):
    def __call__(self, concurrency: int, ci: bool, /) -> CalibrationCheckDeps: ...


class SurveyOne(Protocol):
    def __call__(self, target: Target, places: Places, /) -> Awaitable[TargetSurvey]: ...


@dataclass(frozen=True)
class DetectionCommandDeps:
    preflight: Callable[[], bool] = preflight_ok
    sweep: ContainerSweep = DOCKER_SWEEP
    read_tree: Callable[[], TreeState] = read_tree
    audit_target: AuditTargetFactory = audit_target
    session: RunSession = run_gated
    calibration_check: CalibrationCheckFactory = default_calibration_check_deps
    survey_one: SurveyOne = survey_one
