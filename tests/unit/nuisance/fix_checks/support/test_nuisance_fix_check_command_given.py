import dataclasses
from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import Any

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals.cve.closed_network import ClosedNetworkUnsupported
from evals.cve.kit.fix_check import FixCheckFixture, FixCheckResult
from evals.cve.nuisance.admission.admission import FixCheckRecord, NuisanceAdmission
from evals.cve.nuisance.fix_check_command import FixCheckCommandDeps, FixCheckDeps
from evals.run_nuisance import NuisanceCommandDeps
from tests.fakes import FakeContainerSweep
from tests.unit.support import census_draws, censuses


class FakeFixCheck:
    """Records the services it is asked to build and the backend services it is asked to bring
    up to date, raising `build_error` instead of building when one is given, answers every fix
    check with `result`, and finds the containers of `running` left running, on a daemon that
    creates closed networks."""

    def __init__(
        self,
        result: FixCheckResult | Exception,
        build_error: Exception | None = None,
        running: Sequence[str] = (),
    ) -> None:
        self.built: list[str] = []
        self.refreshed: list[str] = []
        self.containers = FakeContainerSweep(list(running))
        self._result = result
        self._build_error = build_error

    @property
    def deps(self) -> FixCheckDeps:
        return FixCheckDeps(
            build_images=self._build,
            refresh_backend_images=self.refreshed.extend,
            check_fix=self._check_fix,
            check_networks=_closes_networks,
            sweep=self.containers.sweep,
        )

    def _build(self, services: Sequence[str]) -> None:
        if self._build_error is not None:
            raise self._build_error
        self.built.extend(services)

    async def _check_fix(self, _fixture: FixCheckFixture) -> FixCheckResult:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class Networks(Enum):
    CLOSABLE = "the daemon creates closed networks"
    UNSUPPORTED = "the daemon cannot create a closed network"


def a_fix_check_ready(
    fixture: FixCheckFixture, fix_check: FakeFixCheck, networks: Networks = Networks.CLOSABLE
) -> NuisanceCommandDeps:
    """The `fix-check` command on `fixture` alone, its Docker work answered by `fix_check`."""
    deps = dataclasses.replace(fix_check.deps, check_networks=_CHECKS[networks])

    def fix_check_deps(_concurrency: int) -> FixCheckDeps:
        return deps

    return NuisanceCommandDeps(
        fix_check=FixCheckCommandDeps(fixtures=(fixture,), fix_check_deps=fix_check_deps)
    )


def _closes_networks() -> None:
    pass


def _cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


_CHECKS = {Networks.CLOSABLE: _closes_networks, Networks.UNSUPPORTED: _cannot_close_a_network}


def a_result_matching(record: FixCheckRecord, **overrides: Any) -> FixCheckResult:
    fields = record.model_dump(include={field.name for field in dataclasses.fields(FixCheckResult)})
    return FixCheckResult(**{**fields, **overrides})


def a_fix_check_command(tmp_path: Path, admission: NuisanceAdmission | None) -> list[str]:
    """The `fix-check` arguments of a census with a detection walk, an empty walk record and
    `admission`, written to a file, or a path to no file when it is None."""
    census = censuses.written(tmp_path, census_draws.a_census_with_draw(census_draws.a_draw()))
    admitted = (
        tmp_path / "absent.json" if admission is None else admissions.written(tmp_path, admission)
    )
    return [
        "fix-check",
        *walks.census_and_walk_record_arguments(tmp_path, census),
        "--admission",
        str(admitted),
    ]


def an_admission_on_the_ckan_backend() -> NuisanceAdmission:
    return mutations.admitting(mutations.on_the_ckan_backend(admissions.an_admitted_server()))
