"""The fix-check calibration core on fake deps, and the `calibrate` subcommand driven through
run_nuisance's main, with no Docker."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_calibrate_command_given as given
from evals import nuisance_calibrate_command, run_nuisance
from evals.closed_network import ClosedNetworkUnsupported
from evals.cve.detection import targets as detection_targets
from evals.cve.kit import launch as kit_launch
from evals.nuisance_admission import NuisanceAdmission
from evals.nuisance_backends import BACKENDS
from evals.nuisance_calibrate_command import calibrate_fixtures, fix_check_mismatches
from evals.nuisance_commands import CRASHED_EXIT
from tests.fakes import FakeContainerSweep
from tests.unit.support.test_kit_fix_check_given import a_fix_check_target
from tests.unit.support.test_nuisance_admission_given import a_passing_fix_check, an_admission

TARGET = a_fix_check_target(server_patched_service="server-patched")
RECORD = a_passing_fix_check()


@pytest.fixture(autouse=True)
def _no_docker_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    _leftovers(monkeypatch)


def _leftovers(monkeypatch: pytest.MonkeyPatch, *running: str) -> FakeContainerSweep:
    containers = FakeContainerSweep(list(running))
    monkeypatch.setattr(nuisance_calibrate_command, "DOCKER_SWEEP", containers.sweep)
    return containers


async def test_a_result_matching_its_record_calibrates_green():
    calibration = given.FakeFixCheckCalibration(given.a_result_matching(RECORD))

    assert await calibrate_fixtures([TARGET], {TARGET.flaw: RECORD}, calibration.deps) == 0


async def test_a_result_departing_from_its_record_fails_the_calibration():
    calibration = given.FakeFixCheckCalibration(
        given.a_result_matching(RECORD, patched_benign_errored=True)
    )

    assert await calibrate_fixtures([TARGET], {TARGET.flaw: RECORD}, calibration.deps) == 1


async def test_a_crashed_fix_check_exits_as_a_crash():
    calibration = given.FakeFixCheckCalibration(RuntimeError("the launch failed"))

    code = await calibrate_fixtures([TARGET], {TARGET.flaw: RECORD}, calibration.deps)

    assert code == CRASHED_EXIT


async def test_the_calibration_builds_every_service_of_its_targets():
    calibration = given.FakeFixCheckCalibration(given.a_result_matching(RECORD))

    await calibrate_fixtures([TARGET], {TARGET.flaw: RECORD}, calibration.deps)

    assert calibration.built == ["vuln", "patched", "server-patched"]


@pytest.mark.parametrize(
    "admission", [None, given.an_admission_with_no_servers()], ids=["absent", "no servers"]
)
def test_calibrate_with_no_admitted_server_prints_nothing_is_drawn(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, admission: NuisanceAdmission | None
):
    code = run_nuisance.main(given.a_calibrate_command(tmp_path, admission))

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out


def test_calibrate_with_empty_targets_prints_nothing_is_drawn(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(nuisance_calibrate_command, "FIX_CHECK_TARGETS", ())

    code = run_nuisance.main(given.a_calibrate_command(tmp_path, an_admission()))

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out


def test_calibrate_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(nuisance_calibrate_command, "FIX_CHECK_TARGETS", (TARGET,))
    monkeypatch.setattr(
        nuisance_calibrate_command, "check_closed_network_support", _cannot_close_a_network
    )
    never_built = AssertionError("the fix-check images were built")
    _calibrating_with(
        monkeypatch, given.FakeFixCheckCalibration(RuntimeError("unused"), never_built)
    )

    code = run_nuisance.main(given.a_calibrate_command(tmp_path, an_admission()))

    assert code == run_nuisance.REFUSED_EXIT
    assert "Docker Engine 28.0 or later is required" in capsys.readouterr().out


def _cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


@pytest.mark.parametrize("build_fails", [False, True])
def test_calibrate_removes_the_kit_and_built_backend_containers_left_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, build_fails: bool
):
    containers = _leftovers(monkeypatch, "leftover_kit", "leftover_responder")
    monkeypatch.setattr(nuisance_calibrate_command, "FIX_CHECK_TARGETS", (TARGET,))
    monkeypatch.setattr(nuisance_calibrate_command, "check_closed_network_support", lambda: None)
    build_error = RuntimeError("docker build failed") if build_fails else None
    _calibrating_with(
        monkeypatch, given.FakeFixCheckCalibration(given.a_result_matching(RECORD), build_error)
    )
    command = given.a_calibrate_command(tmp_path, given.an_admission_on_the_ckan_backend())

    if build_fails:
        with pytest.raises(RuntimeError):
            run_nuisance.main(command)
    else:
        run_nuisance.main(command)

    assert containers.removed == ["leftover_kit", "leftover_responder"]
    kit_tags = [kit_launch.image_tag(service) for service in ("vuln", "patched", "server-patched")]
    ckan_tags = [
        detection_targets.image_tag(service) for service in BACKENDS["ckan"].built_services
    ]
    assert containers.listed_tags == [[*kit_tags, *ckan_tags]]


def _calibrating_with(
    monkeypatch: pytest.MonkeyPatch, calibration: given.FakeFixCheckCalibration
) -> None:
    def default_deps(_concurrency: int) -> nuisance_calibrate_command.FixCheckCalibrationDeps:
        return calibration.deps

    monkeypatch.setattr(
        nuisance_calibrate_command, "default_fix_check_calibration_deps", default_deps
    )


def test_a_matching_result_and_record_have_no_mismatch():
    assert fix_check_mismatches(given.a_result_matching(RECORD), RECORD) == []


def test_a_differing_field_is_reported():
    record = RECORD.model_copy(update={"patched_surfaces": True})

    mismatches = fix_check_mismatches(given.a_result_matching(RECORD), record)

    assert len(mismatches) == 1
    assert "patched_surfaces" in mismatches[0]


def test_a_holdout_calibration_record_excludes_the_source_field():
    record = RECORD.model_copy(update={"source": "holdout_calibration"})

    assert fix_check_mismatches(given.a_result_matching(record, source="fix_check"), record) == []


def test_a_source_difference_on_a_fix_check_record_is_a_mismatch():
    result = given.a_result_matching(RECORD, source="holdout_calibration")

    mismatches = fix_check_mismatches(result, RECORD)

    assert len(mismatches) == 1
    assert "source" in mismatches[0]


def test_a_record_judging_a_relaying_stand_in_matches_a_result_that_cannot_carry_it():
    record = RECORD.model_copy(update={"relies_on_relaying_stand_in": True})

    assert fix_check_mismatches(given.a_result_matching(record), record) == []


def test_a_record_carrying_a_holdout_fingerprint_matches_a_result_that_cannot_carry_it():
    record = RECORD.model_copy(
        update={"source": "holdout_calibration", "holdout_fingerprint": "f" * 64}
    )

    assert fix_check_mismatches(given.a_result_matching(record), record) == []


def test_a_differing_witness_nonce_is_not_a_mismatch():
    # check_fix plants a fresh random nonce each run, so the result's witness never equals the one
    # the admission recorded; only the reproducible fields are compared.
    record = RECORD.model_copy(update={"witness": "MCPAUDIT-recordednonce"})

    result = given.a_result_matching(record, witness="MCPAUDIT-freshnonce")

    assert fix_check_mismatches(result, record) == []
