import dataclasses
from pathlib import Path
from typing import Any

from pydantic import BaseModel

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
import tests.unit.nuisance.admission.support.test_nuisance_walk_given as walk_given
import tests.unit.nuisance.support.test_nuisance_holdout_run_given as run_given
from evals.cve.nuisance.admission.admission import NuisanceAdmission
from evals.cve.nuisance.holdout_run import NuisanceDeps, RunProvenance
from evals.cve.nuisance.holdout_run_command import RunCommandDeps
from evals.cve.nuisance.results import NuisanceHoldoutRunResult
from evals.cve.run_files import write_report
from evals.run_nuisance import NuisanceCommandDeps
from mcp_auditor.config import Settings
from tests.unit.nuisance.support.nuisance_report_runs import a_run
from tests.unit.nuisance.support.test_nuisance_statistic_given import a_server_result
from tests.unit.support import census_draws, censuses
from tests.unit.support.detection_holdout_runs import ready_conditions


def a_run_command(tmp_path: Path, admission: NuisanceAdmission | None = None) -> list[str]:
    """The `run` arguments of a census with a draw walk, an empty walk record and `admission`, by
    default the admission of one fully recorded server."""
    census = censuses.written(tmp_path, census_draws.a_census_with_draw(census_draws.a_draw()))
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


def an_admitted_run_keeping_its_provenance() -> NuisanceCommandDeps:
    """An admitted run whose result carries the provenance the CLI handed the orchestrator, each
    file's commit named after the file."""

    async def orchestrator(*args: object, **__: object) -> NuisanceHoldoutRunResult:
        provenance = next(arg for arg in args if isinstance(arg, RunProvenance))
        return dataclasses.replace(
            a_run_result(),
            census_commit=provenance.census_commit,
            walk_record_commit=provenance.walk_record_commit,
            admission_commit=provenance.admission_commit,
        )

    run = dataclasses.replace(_an_admitted_run(a_run_result()), orchestrate=orchestrator)
    return _run_with(run)


def a_run_result() -> NuisanceHoldoutRunResult:
    return a_run([a_server_result()])


def an_admitted_run_ending_in(
    outcome: NuisanceHoldoutRunResult | BaseException,
) -> NuisanceCommandDeps:
    """An admitted server whose run, past the CLI's own checks, returns or raises `outcome`,
    reaching no Docker and no LLM."""
    return _run_with(_an_admitted_run(outcome))


def an_admitted_run_failing_its_report_write() -> NuisanceCommandDeps:
    def failing_report(_path: Path, _report: BaseModel, _markdown: str) -> None:
        raise RuntimeError("the report failed to write")

    run = dataclasses.replace(_an_admitted_run(a_run_result()), write_report=failing_report)
    return _run_with(run)


def _an_admitted_run(outcome: NuisanceHoldoutRunResult | BaseException) -> RunCommandDeps:
    async def orchestrator(*_: object, **__: object) -> NuisanceHoldoutRunResult:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def deps(*_: object) -> NuisanceDeps:
        return run_given.deps_reaching_nothing()

    def file_commit(path: Path) -> str:  # the census and the record live in tmp_path, out of git
        return f"commit-of-{path.name}"

    return RunCommandDeps(
        conditions=ready_conditions,
        settings=_ready_settings,
        run_deps=deps,
        orchestrate=orchestrator,
        file_commit=file_commit,
        write_report=write_report,
    )


def a_run_reaching_nothing() -> NuisanceCommandDeps:
    return _run_with(_a_run_reaching_nothing())


def a_run_refused_before_its_settings() -> NuisanceCommandDeps:
    """A run that reads its conditions, census and admission, and fails the test past them."""
    return _run_with(dataclasses.replace(_a_run_reaching_nothing(), conditions=ready_conditions))


def _a_run_reaching_nothing() -> RunCommandDeps:
    def unreached(*_: object, **__: object) -> Any:
        raise AssertionError("the run was reached")

    return RunCommandDeps(unreached, unreached, unreached, unreached, unreached, unreached)


def _run_with(run: RunCommandDeps) -> NuisanceCommandDeps:
    return NuisanceCommandDeps(run=run)


def _ready_settings() -> Settings:
    return Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="")
