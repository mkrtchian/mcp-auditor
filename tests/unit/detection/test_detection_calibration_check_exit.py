import pytest

from evals.cve.detection.calibration_check_exit import run_calibration_check
from evals.cve.places import DETECTION_PLACES, load_places
from tests.unit.detection.support.test_detection_calibration_check_exit_given import deps_with
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target

TARGETS = [an_acceptance_target(FILESYSTEM, tools_filter=None)]
PLACES = load_places(DETECTION_PLACES)


async def test_every_target_in_calibration_exits_zero():
    assert await run_calibration_check(TARGETS, PLACES, deps_with()) == 0


async def test_a_layout_or_route_failure_exits_one_though_every_exploit_passes():
    deps = deps_with(failures=["CVE-0000-00000: kept layout place p has no route"])

    assert await run_calibration_check(TARGETS, PLACES, deps) == 1


async def test_a_target_out_of_calibration_exits_one():
    assert await run_calibration_check(TARGETS, PLACES, deps_with(all_pass=False)) == 1


async def test_a_fixture_config_error_propagates():
    with pytest.raises(ValueError):
        await run_calibration_check(TARGETS, PLACES, deps_with(raises=True))
