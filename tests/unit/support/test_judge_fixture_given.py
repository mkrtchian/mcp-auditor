import json
from pathlib import Path
from typing import Any

from evals.judge_fixture import (
    CaseLabel,
    CaseSource,
    DrawRecord,
    JudgeCase,
    JudgeFixture,
    JudgeInputs,
    case_id,
)
from mcp_auditor.domain.models import AuditCategory

_A_DRAW = DrawRecord(seed=1, quotas={}, sources=[], shortfalls=[])


def some_inputs(**overrides: Any) -> JudgeInputs:
    fields: dict[str, Any] = {
        "tool_name": "get_user",
        "tool_description": "Look up a user by their numeric ID.",
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "Negative user_id",
        "arguments": {"user_id": -1, "verbose": True},
        "response": None,
        "error": "Invalid user_id",
        **overrides,
    }
    return JudgeInputs(**fields)


def a_case(
    label: CaseLabel | None = CaseLabel.PASS,
    clause: str | None = None,
    **input_overrides: Any,
) -> JudgeCase:
    inputs = some_inputs(**input_overrides)
    return JudgeCase(
        id=case_id(inputs),
        source=CaseSource.HONEYPOT,
        origin="cell get_user/input_validation",
        inputs=inputs,
        label=label,
        clause=clause,
    )


def a_fixture(*cases: JudgeCase) -> JudgeFixture:
    return JudgeFixture(draw=_A_DRAW, cases=list(cases))


def a_file_holding(tmp_path: Path, *cases: JudgeCase) -> Path:
    path = tmp_path / "judge_cases.json"
    path.write_text(a_fixture(*cases).model_dump_json())
    return path


def a_file_with_raw_cases(tmp_path: Path, *raw_cases: dict[str, Any]) -> Path:
    path = tmp_path / "judge_cases.json"
    path.write_text(json.dumps({"draw": _A_DRAW.model_dump(mode="json"), "cases": list(raw_cases)}))
    return path
