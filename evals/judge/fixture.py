import hashlib
import json
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.models import AuditCategory, EvalVerdict


class CaseLabel(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNSPECIFIED = "unspecified"


class CaseSource(StrEnum):
    HONEYPOT = "honeypot"
    CVE = "cve"


class JudgeInputs(BaseModel):
    """Exactly what `build_judge_prompt` reads of a tool and a test case."""

    tool_name: str
    tool_description: str | None
    category: AuditCategory
    description: str
    arguments: dict[str, Any]
    response: str | dict[str, Any] | None
    error: str | None


class JudgeCase(BaseModel):
    id: str
    source: CaseSource
    origin: str
    inputs: JudgeInputs
    label: CaseLabel | None
    clause: str | None


class SourceRun(BaseModel):
    path: str
    sha256: str
    commit: str
    conditions: dict[str, str | int | None]


class DrawRecord(BaseModel):
    seed: int
    quotas: dict[str, int]
    sources: list[SourceRun]
    shortfalls: list[str]
    complement_seed: int | None = None


class JudgeFixture(BaseModel):
    draw: DrawRecord
    cases: list[JudgeCase]


def case_id(inputs: JudgeInputs) -> str:
    canonical = json.dumps(inputs.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def load_fixture(path: Path) -> JudgeFixture:
    fixture = load_drawn(path)
    unlabeled = [case.id for case in fixture.cases if case.label is None]
    if unlabeled:
        raise ValueError(f"unlabeled cases in {path}: {', '.join(unlabeled)}")
    return fixture


def load_drawn(path: Path) -> JudgeFixture:
    fixture = JudgeFixture.model_validate_json(path.read_text())
    problems = _identity_problems(fixture.cases)
    if problems:
        raise ValueError(f"invalid judge fixture {path}: {'; '.join(problems)}")
    return fixture


def _identity_problems(cases: list[JudgeCase]) -> list[str]:
    mismatched = [
        f"case {case.id} does not match its inputs"
        for case in cases
        if case.id != case_id(case.inputs)
    ]
    counts = Counter(case.id for case in cases)
    duplicated = [f"case {id_} appears {count} times" for id_, count in counts.items() if count > 1]
    return mismatched + duplicated


def ground_truth_of(fixture: JudgeFixture) -> dict[str, EvalVerdict]:
    return {
        case.id: EvalVerdict(case.label)
        for case in fixture.cases
        if case.label in (CaseLabel.PASS, CaseLabel.FAIL)
    }


def inputs_fingerprint(fixture: JudgeFixture) -> str:
    joined = "".join(sorted(case.id for case in fixture.cases))
    return hashlib.sha256(joined.encode()).hexdigest()
