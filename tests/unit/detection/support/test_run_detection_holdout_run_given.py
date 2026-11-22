from pathlib import Path

from pydantic import BaseModel

from tests.unit.detection.support.holdout_command_deps import DRAWN_FLAW
from tests.unit.support.census_draws import a_census_drawing


def a_failing_report_write(_path: Path, _report: BaseModel, _markdown: str) -> None:
    raise RuntimeError("the report failed to write")


def a_census_with_no_draw(tmp_path: Path) -> Path:
    census = a_census_drawing([DRAWN_FLAW]).model_copy(update={"draw": None})
    path = tmp_path / "census.json"
    path.write_text(census.model_dump_json())
    return path
