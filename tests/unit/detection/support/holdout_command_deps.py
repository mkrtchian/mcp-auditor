import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from evals.cve.detection.holdout_command_deps import HoldoutCommandDeps
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_run import HoldoutDeps, RunHoldoutTargets
from evals.cve.detection.targets import Target
from evals.cve.run_files import write_report
from evals.cve.run_images import RunDocker
from tests.fakes import FakeContainerSweep
from tests.fakes.image_store import FakeImageStore
from tests.unit.support import censuses, detection_holdout_runs, holdout_run_conditions
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target
from tests.unit.support.census_draws import a_census_drawing

DRAWN_FLAW = "CVE-2026-0001"


def a_run_result() -> DetectionHoldoutRunResult:
    target = detection_holdout_runs.a_target(FILESYSTEM)
    audit = detection_holdout_runs.scripted(
        {target.flaw_id: detection_holdout_runs.three_detections()}
    )
    return asyncio.run(
        detection_holdout_runs.run([target], detection_holdout_runs.deps_auditing(audit))
    )


def a_drawn_run_ending_in(
    outcome: DetectionHoldoutRunResult | BaseException,
) -> HoldoutCommandDeps:
    """A drawn target with a ready card whose run, past the CLI's own checks, returns or raises
    `outcome`, reaching no Docker and no LLM."""

    async def orchestrator(*_: object, **__: object) -> DetectionHoldoutRunResult:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return a_drawn_run_through(orchestrator)


def a_drawn_run_through(run_targets: RunHoldoutTargets) -> HoldoutCommandDeps:
    """A drawn target with a ready card whose run, past the CLI's own checks, goes through
    `run_targets`, every Docker and LLM dependency reaching nothing."""
    return replace(
        a_drawn_run_reaching_nothing(),
        holdout_deps=_holdout_deps_reaching_nothing,
        run_targets=run_targets,
        last_commit=lambda _census: "cafe",
        write_report=write_report,
    )


def _holdout_deps_reaching_nothing(*_: object) -> HoldoutDeps:
    return detection_holdout_runs.deps_reaching_nothing()


def a_drawn_run_reaching_nothing() -> HoldoutCommandDeps:
    """A drawn target under ready run conditions, its run and every Docker call unreached."""
    return replace(a_command_reaching_nothing(), conditions=holdout_run_conditions.ready_conditions)


def a_command_reaching_nothing() -> HoldoutCommandDeps:
    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run was reached")

    return HoldoutCommandDeps(
        drawn=(a_drawn_target(tools_filter=None),),
        docker=RunDocker(unreached, FakeImageStore({}), FakeContainerSweep().sweep),
        calibration_check=unreached,
        conditions=unreached,
        holdout_deps=unreached,
        run_targets=unreached,
        last_commit=unreached,
        write_report=unreached,
    )


def a_drawn_target(**changes: Any) -> Target:
    """An acceptance target under a flaw ID the test census draws: `load_census` refuses an
    acceptance flaw ID, which is no draw-order candidate, as a draw."""
    return replace(an_acceptance_target(FILESYSTEM, **changes), flaw_id=DRAWN_FLAW)


def a_census_with_a_ready_card(tmp_path: Path) -> Path:
    return censuses.written(tmp_path, a_census_drawing([DRAWN_FLAW]))


def a_ready_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "openai")
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
