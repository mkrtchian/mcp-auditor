from pathlib import Path

from pydantic import BaseModel

from evals.cve.detection.holdout_command_deps import HoldoutCommandDeps
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_run import HoldoutDeps, HoldoutRunInputs
from tests.unit.detection.support import holdout_command_deps
from tests.unit.detection.support.holdout_command_deps import DRAWN_FLAW
from tests.unit.support import censuses
from tests.unit.support.census_draws import a_census_drawing


def a_failing_report_write(_path: Path, _report: BaseModel, _markdown: str) -> None:
    raise RuntimeError("the report failed to write")


def a_census_with_no_draw(tmp_path: Path) -> Path:
    return censuses.written(
        tmp_path, a_census_drawing([DRAWN_FLAW]).model_copy(update={"draw": None})
    )


def a_drawn_run_capturing_its_inputs() -> tuple[HoldoutCommandDeps, list[HoldoutRunInputs]]:
    captured: list[HoldoutRunInputs] = []
    result = holdout_command_deps.a_run_result()

    async def orchestrator(
        inputs: HoldoutRunInputs, /, *, deps: HoldoutDeps
    ) -> DetectionHoldoutRunResult:
        captured.append(inputs)
        return result

    return holdout_command_deps.a_drawn_run_through(orchestrator), captured
