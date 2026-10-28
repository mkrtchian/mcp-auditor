from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_report_given as report_given
import tests.unit.support.test_nuisance_run_given as run_given
from evals import run_nuisance
from evals.nuisance_results import NuisanceRunResult
from evals.nuisance_run import NuisanceDeps
from tests.unit.support.test_nuisance_statistic_given import a_server_result


def a_run_result() -> NuisanceRunResult:
    return report_given.a_run([a_server_result()])


def a_run_command(tmp_path: Path) -> list[str]:
    """The `run` arguments of a census with a draw walk and an admission of one server."""
    census = census_given.written(tmp_path, draw_given.a_census_with_draw(draw_given.a_draw()))
    admitted = admission_given.written(tmp_path, admission_given.an_admission())
    report = tmp_path / "nuisance_report.json"
    return ["run", "--census", str(census), "--admission", str(admitted), "--report", str(report)]


def an_admitted_run_ending_in(
    monkeypatch: pytest.MonkeyPatch, outcome: NuisanceRunResult | BaseException
) -> None:
    """An admitted server whose run, past the CLI's own checks, returns or raises `outcome`,
    reaching no Docker and no LLM."""

    async def orchestrator(*_: object, **__: object) -> NuisanceRunResult:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    a_ready_run(monkeypatch)

    def deps(*_: object) -> NuisanceDeps:
        return run_given.deps_reaching_nothing()

    def census_commit(*_: object) -> str:  # the census lives in tmp_path, out of git
        return "cafe"

    monkeypatch.setattr(run_nuisance, "default_deps", deps)
    monkeypatch.setattr(run_nuisance, "run_nuisance", orchestrator)
    monkeypatch.setattr(run_nuisance, "last_commit", census_commit)


def a_run_reaching_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run was reached")

    a_ready_run(monkeypatch)
    for name in ("load_conditions", "load_census", "default_deps", "run_nuisance"):
        monkeypatch.setattr(run_nuisance, name, unreached)


def a_ready_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
