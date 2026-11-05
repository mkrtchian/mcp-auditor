import dataclasses
from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_report_given as report_given
import tests.unit.support.test_nuisance_run_given as run_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals import run_nuisance
from evals.nuisance_admission import NuisanceAdmission
from evals.nuisance_results import NuisanceRunResult
from evals.nuisance_run import NuisanceDeps, RunProvenance
from tests.unit.support.test_nuisance_statistic_given import a_server_result


def a_run_result() -> NuisanceRunResult:
    return report_given.a_run([a_server_result()])


def a_run_command(tmp_path: Path, admission: NuisanceAdmission | None = None) -> list[str]:
    """The `run` arguments of a census with a draw walk, an empty walk record and `admission`, by
    default the admission of one fully recorded server."""
    census = census_given.written(tmp_path, draw_given.a_census_with_draw(draw_given.a_draw()))
    admitted = admission_given.written(tmp_path, admission or admission_given.an_admission())
    report = tmp_path / "nuisance_report.json"
    return [
        "run",
        *walk_given.committed_census_arguments(tmp_path, census),
        "--admission",
        str(admitted),
        "--report",
        str(report),
    ]


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

    def file_commit(path: Path) -> str:  # the census and the record live in tmp_path, out of git
        return f"commit-of-{path.name}"

    monkeypatch.setattr(run_nuisance, "default_deps", deps)
    monkeypatch.setattr(run_nuisance, "run_nuisance", orchestrator)
    monkeypatch.setattr(run_nuisance, "last_commit", file_commit)


def an_admitted_run_keeping_its_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    """An admitted run whose result carries the provenance the CLI handed the orchestrator, each
    file's commit named after the file."""

    async def orchestrator(*args: object, **__: object) -> NuisanceRunResult:
        provenance = next(arg for arg in args if isinstance(arg, RunProvenance))
        return dataclasses.replace(
            a_run_result(),
            census_commit=provenance.census_commit,
            walk_record_commit=provenance.walk_record_commit,
        )

    an_admitted_run_ending_in(monkeypatch, a_run_result())
    monkeypatch.setattr(run_nuisance, "run_nuisance", orchestrator)


def a_run_reaching_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run was reached")

    a_ready_run(monkeypatch)
    for name in ("load_conditions", "committed_nuisance_census", "default_deps", "run_nuisance"):
        monkeypatch.setattr(run_nuisance, name, unreached)


def a_run_refused_before_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run that reads its census and admission, and fails the test past them."""

    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run read its settings")

    a_ready_run(monkeypatch)
    for name in ("load_settings", "default_deps", "run_nuisance"):
        monkeypatch.setattr(run_nuisance, name, unreached)


def a_ready_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
