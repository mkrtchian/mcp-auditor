import pytest

from evals.admission_calibration import calibrate_admitted
from evals.cve_places import HOLDOUT_PLACES, load_places
from tests.unit.support import test_holdout_run_given as run_given
from tests.unit.support.test_admission_calibration_given import deps_with

TARGETS = [run_given.a_target(run_given.FILESYSTEM)]
PLACES = load_places(HOLDOUT_PLACES)


async def test_every_target_live_and_admitted_exits_zero():
    assert await calibrate_admitted(TARGETS, PLACES, deps_with()) == 0


async def test_an_admission_failure_exits_one_though_every_target_is_live():
    deps = deps_with(failures=["CVE-0000-00000: kept layout place p has no route"])

    assert await calibrate_admitted(TARGETS, PLACES, deps) == 1


async def test_a_target_calibrating_dead_exits_one():
    assert await calibrate_admitted(TARGETS, PLACES, deps_with(all_live=False)) == 1


async def test_a_fixture_config_error_propagates():
    with pytest.raises(ValueError):
        await calibrate_admitted(TARGETS, PLACES, deps_with(raises=True))
