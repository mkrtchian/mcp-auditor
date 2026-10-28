import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_holdout_run_given as run_given
from evals import run_holdout
from evals.holdout_results import HoldoutRunResult
from evals.holdout_run import HoldoutDeps

# The report's no-proof guarantee, held by the result file too.
PROOF_FIELDS = {"evidence", "category", "judge_input", "judge", "verdict", "status", "miss_class"}


def a_run_result() -> HoldoutRunResult:
    target = run_given.a_target(run_given.FILESYSTEM)
    audit = run_given.scripted({target.cve_id: run_given.three_detections()})
    return asyncio.run(run_given.run([target], run_given.deps_auditing(audit)))


def a_drawn_run_ending_in(
    monkeypatch: pytest.MonkeyPatch, outcome: HoldoutRunResult | BaseException
) -> None:
    """A drawn target whose run, past the CLI's own checks, returns or raises `outcome`, reaching
    no Docker and no LLM."""

    async def orchestrator(*_: object, **__: object) -> HoldoutRunResult:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    a_ready_run(monkeypatch)
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (object(),))

    def deps(*_: object) -> HoldoutDeps:
        return run_given.deps_reaching_nothing()

    monkeypatch.setattr(run_holdout, "default_deps", deps)
    monkeypatch.setattr(run_holdout, "run_holdout", orchestrator)


def a_ready_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")


def a_run_reaching_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run was reached")

    a_ready_run(monkeypatch)
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (object(),))
    monkeypatch.setattr(run_holdout, "load_conditions", unreached)
    monkeypatch.setattr(run_holdout, "default_deps", unreached)
    monkeypatch.setattr(run_holdout, "run_holdout", unreached)


def result_keys(path: Path) -> set[str]:
    return _keys(json.loads(path.read_text()))


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        entries: dict[str, Any] = value  # pyright: ignore[reportUnknownVariableType]
        return set(entries).union(*(_keys(item) for item in entries.values()))
    if isinstance(value, list):
        items: list[Any] = value  # pyright: ignore[reportUnknownVariableType]
        return set[str]().union(*(_keys(item) for item in items))
    return set()
