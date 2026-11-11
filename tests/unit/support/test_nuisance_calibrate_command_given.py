from collections.abc import Sequence
from pathlib import Path
from typing import Any

import tests.unit.support.test_census_given as census_given
import tests.unit.support.test_detection_draw_record_given as draw_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.holdout_kit.fix_check import FixCheckResult, FixCheckTarget
from evals.nuisance_admission import BackendFixture, FixCheckRecord, NuisanceAdmission
from evals.nuisance_backends import BACKENDS
from evals.nuisance_calibrate_command import FixCheckCalibrationDeps


class FakeFixCheckCalibration:
    """Records the services it is asked to build, raising `build_error` instead when one is
    given, and answers every fix check with `result`."""

    def __init__(
        self, result: FixCheckResult | Exception, build_error: Exception | None = None
    ) -> None:
        self.built: list[str] = []
        self._result = result
        self._build_error = build_error

    @property
    def deps(self) -> FixCheckCalibrationDeps:
        return FixCheckCalibrationDeps(build_images=self._build, check_fix=self._check_fix)

    def _build(self, services: Sequence[str]) -> None:
        if self._build_error is not None:
            raise self._build_error
        self.built.extend(services)

    async def _check_fix(self, _target: FixCheckTarget) -> FixCheckResult:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def a_result_matching(record: FixCheckRecord, **overrides: Any) -> FixCheckResult:
    fields = record.model_dump(exclude={"relies_on_relaying_stand_in", "holdout_fingerprint"})
    return FixCheckResult(**{**fields, **overrides})


def a_calibrate_command(tmp_path: Path, admission: NuisanceAdmission | None) -> list[str]:
    """The `calibrate` arguments of a census with a draw walk, an empty walk record and
    `admission`, written to a file, or a path to no file when it is None."""
    census = census_given.written(tmp_path, draw_given.a_census_with_draw(draw_given.a_draw()))
    admitted = (
        tmp_path / "absent.json"
        if admission is None
        else admission_given.written(tmp_path, admission)
    )
    return [
        "calibrate",
        *walk_given.committed_census_arguments(tmp_path, census),
        "--admission",
        str(admitted),
    ]


def an_admission_on_the_ckan_backend() -> NuisanceAdmission:
    ckan = BACKENDS["ckan"]
    backend = BackendFixture(provisioner="ckan", image=ckan.image, network=ckan.network)
    admission = admission_given.an_admission()
    server = admission_given.with_a_backend(admission.servers[0], backend)
    return admission.model_copy(update={"servers": [server]})


def an_admission_with_no_servers() -> NuisanceAdmission:
    return admission_given.an_admission().model_copy(update={"servers": []})
