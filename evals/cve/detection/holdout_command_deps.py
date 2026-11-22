"""What the run_detection_holdout command reaches outside the process: the drawn targets, Docker,
the committed run conditions, the run orchestrator, git and the report files. Building it does no
I/O. A module apart from `command_deps`, so that no module run_detection imports reaches the
holdout targets."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from evals.cve.detection.calibration_check_exit import default_calibration_check_deps
from evals.cve.detection.command_deps import CalibrationCheckFactory
from evals.cve.detection.holdout_run import (
    HoldoutDepsFactory,
    RunHoldoutTargets,
    default_deps,
    run_holdout_targets,
)
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target
from evals.cve.holdout_conditions import HoldoutConditions, committed_conditions
from evals.cve.run_files import ReportWriter, write_report
from evals.cve.run_images import RunDocker
from evals.eval_session import last_commit


@dataclass(frozen=True)
class HoldoutCommandDeps:
    drawn: Sequence[Target] = HOLDOUT_TARGETS
    docker: RunDocker = field(default_factory=RunDocker)
    calibration_check: CalibrationCheckFactory = default_calibration_check_deps
    conditions: Callable[[], HoldoutConditions] = committed_conditions
    holdout_deps: HoldoutDepsFactory = default_deps
    run_targets: RunHoldoutTargets = run_holdout_targets
    last_commit: Callable[[Path], str] = last_commit
    write_report: ReportWriter = write_report
