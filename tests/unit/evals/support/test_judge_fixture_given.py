import json
from pathlib import Path
from typing import Any

from evals.judge.fixture import JudgeCase
from tests.unit.evals.support.judge_cases import A_DRAW, a_fixture


def a_file_holding(tmp_path: Path, *cases: JudgeCase) -> Path:
    path = tmp_path / "judge_cases.json"
    path.write_text(a_fixture(*cases).model_dump_json())
    return path


def a_file_with_raw_cases(tmp_path: Path, *raw_cases: dict[str, Any]) -> Path:
    path = tmp_path / "judge_cases.json"
    path.write_text(json.dumps({"draw": A_DRAW.model_dump(mode="json"), "cases": list(raw_cases)}))
    return path
