"""What the run_detection_holdout command reaches outside the process: the drawn targets, Docker,
the committed run conditions, the run orchestrator and its live dependencies, git and the report
files. Building it does no I/O. A module apart from `command_deps`, so that no module
run_detection imports reaches the holdout targets."""

import dataclasses
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from evals.concurrency import bounded
from evals.cve.closed_network import check_closed_network_support
from evals.cve.detection.audit import attempt_once
from evals.cve.detection.calibration_check import CheckOptions, check_target
from evals.cve.detection.calibration_check_exit import (
    CalibrationCheckFactory,
    default_calibration_check_deps,
)
from evals.cve.detection.holdout_audit import DroppedRun, IncompleteRun, holdout_audit
from evals.cve.detection.holdout_run import HoldoutDeps, RunHoldoutTargets, run_holdout_targets
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.layout_observation import observe_layout
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.holdout_conditions import (
    HOLDOUT_TEST_BUDGET,
    HoldoutConditions,
    committed_conditions,
)
from evals.cve.images import backend_image_ids, image_ids
from evals.cve.launch_audit import RunOverrides, SessionAuditor, build_auditor
from evals.cve.places import Places
from evals.cve.run_files import ReportWriter, write_report
from evals.cve.run_images import DOCKER_SWEEP, RunDocker, rebuild_images
from evals.eval_session import last_commit, read_tree
from evals.session_usage import SessionThrottles


class HoldoutDepsFactory(Protocol):
    def __call__(
        self, places: Places, overrides: RunOverrides, concurrency: int, /
    ) -> HoldoutDeps: ...


def default_deps(places: Places, overrides: RunOverrides, concurrency: int) -> HoldoutDeps:
    auditor = dataclasses.replace(build_auditor(HOLDOUT_TEST_BUDGET), report_detail=TYPES_ONLY)
    throttles = SessionThrottles()
    session = SessionAuditor(auditor, overrides, throttles)

    async def audit(target: Target) -> GradedAudit | IncompleteRun | DroppedRun:
        return await holdout_audit(target, lambda: attempt_once(target, session, places))

    async def check(target: Target) -> list[str]:
        return await check_target(target, places, options=CheckOptions(report_detail=TYPES_ONLY))

    async def layout(target: Target) -> LayoutCheck:
        return await observe_layout(target, places, report_detail=TYPES_ONLY)

    return HoldoutDeps(
        bounded(audit, concurrency),
        bounded(check, concurrency),
        bounded(layout, concurrency),
        rebuild_images,
        image_ids,
        backend_image_ids,
        read_tree,
        lambda: datetime.now(UTC).isoformat(),
        lambda audits: None,
        lambda: throttles.requests,
        DOCKER_SWEEP,
        check_closed_network_support,
    )


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
