"""The fix check core on fake deps, and the `fix-check` subcommand driven through run_nuisance's
main, with no Docker."""

import dataclasses
from pathlib import Path

import pytest

import tests.unit.nuisance.fix_checks.support.test_nuisance_fix_check_command_given as given
from evals import run_nuisance
from evals.cve import images as cve_images
from evals.cve.kit import launch as kit_launch
from evals.cve.nuisance.admission.admission import NuisanceAdmission
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.commands import CRASHED_EXIT
from evals.cve.nuisance.fix_check_command import (
    UNKNOWN_FLAW_EXIT,
    check_fixes,
    fix_check_mismatches,
)
from evals.cve.run_images import DOCKER_REQUIREMENT
from tests.unit.support.admission_mutations import admitting
from tests.unit.support.fix_check_fixtures import a_fix_check_fixture
from tests.unit.support.nuisance_admissions import a_passing_fix_check, an_admission

FIXTURE = a_fix_check_fixture(server_patched_service="server-patched")
FIXTURE_OF_NO_ADMITTED_FLAW = dataclasses.replace(FIXTURE, flaw="CVE-2099-0002")
RECORD = a_passing_fix_check()


async def test_a_result_matching_its_record_passes_the_fix_check():
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))

    assert await check_fixes([FIXTURE], {FIXTURE.flaw: RECORD}, fake.deps) == 0


async def test_a_result_departing_from_its_record_fails_the_fix_check():
    fake = given.FakeFixCheck(given.a_result_matching(RECORD, patched_benign_errored=True))

    assert await check_fixes([FIXTURE], {FIXTURE.flaw: RECORD}, fake.deps) == 1


async def test_a_crashed_fix_check_exits_as_a_crash():
    fake = given.FakeFixCheck(RuntimeError("the launch failed"))

    code = await check_fixes([FIXTURE], {FIXTURE.flaw: RECORD}, fake.deps)

    assert code == CRASHED_EXIT


async def test_the_fix_check_builds_every_service_of_its_fixtures():
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))

    await check_fixes([FIXTURE], {FIXTURE.flaw: RECORD}, fake.deps)

    assert fake.built == ["vuln", "patched", "server-patched"]


@pytest.mark.parametrize("admission", [None, admitting()], ids=["absent", "no servers"])
def test_a_fix_check_with_no_admitted_server_says_so(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, admission: NuisanceAdmission | None
):
    code = run_nuisance.main(given.a_fix_check_command(tmp_path, admission))

    assert code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_a_fix_check_of_a_flaw_no_fixture_matches_exits_naming_it(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
):
    deps = given.a_fix_check_ready(FIXTURE, given.FakeFixCheck(RuntimeError("unused")))
    command = [*given.a_fix_check_command(tmp_path, an_admission()), "--flaw", "CVE-2099-9999"]

    code = run_nuisance.main(command, deps)

    assert code == UNKNOWN_FLAW_EXIT
    assert "CVE-2099-9999 matches no fix-check fixture" in capsys.readouterr().err


def test_the_fix_check_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
):
    never_built = AssertionError("the fix-check images were built")
    fake = given.FakeFixCheck(RuntimeError("unused"), never_built)
    deps = given.a_fix_check_ready(FIXTURE, fake, given.Networks.UNSUPPORTED)

    code = run_nuisance.main(given.a_fix_check_command(tmp_path, an_admission()), deps)

    assert code == 3
    assert DOCKER_REQUIREMENT in capsys.readouterr().out


@pytest.mark.parametrize("build_fails", [False, True])
def test_the_fix_check_removes_the_kit_and_built_backend_containers_left_running(
    tmp_path: Path, build_fails: bool
):
    build_error = RuntimeError("docker build failed") if build_fails else None
    running = ("leftover_kit", "leftover_responder")
    fake = given.FakeFixCheck(given.a_result_matching(RECORD), build_error, running)
    deps = given.a_fix_check_ready(FIXTURE, fake)
    command = given.a_fix_check_command(tmp_path, given.an_admission_on_the_ckan_backend())

    if build_fails:
        with pytest.raises(RuntimeError):
            run_nuisance.main(command, deps)
    else:
        run_nuisance.main(command, deps)

    assert fake.containers.removed == list(running)
    kit_tags = [kit_launch.image_tag(service) for service in ("vuln", "patched", "server-patched")]
    ckan_tags = [cve_images.image_tag(service) for service in BACKENDS["ckan"].built_services]
    assert fake.containers.listed_tags == [[*kit_tags, *ckan_tags]]


def test_the_fix_check_removes_the_containers_left_running_of_the_backend_services_it_names(
    tmp_path: Path,
):
    fixture = dataclasses.replace(FIXTURE, backend_services=("its-responder",))
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))
    deps = given.a_fix_check_ready(fixture, fake)
    command = given.a_fix_check_command(tmp_path, given.an_admission_on_the_ckan_backend())

    run_nuisance.main(command, deps)

    assert cve_images.image_tag("its-responder") in fake.containers.listed_tags[0]


def test_a_fixture_naming_no_backend_services_refreshes_the_run_backends_of_its_servers(
    tmp_path: Path,
):
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))
    deps = given.a_fix_check_ready(FIXTURE, fake)
    command = given.a_fix_check_command(tmp_path, given.an_admission_on_the_ckan_backend())

    run_nuisance.main(command, deps)

    assert fake.refreshed == list(BACKENDS["ckan"].built_services)


def test_a_fixture_naming_its_backend_services_refreshes_those_and_not_the_run_backends(
    tmp_path: Path,
):
    fixture = dataclasses.replace(FIXTURE, backend_services=("its-responder",))
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))
    deps = given.a_fix_check_ready(fixture, fake)
    command = given.a_fix_check_command(tmp_path, given.an_admission_on_the_ckan_backend())

    run_nuisance.main(command, deps)

    assert fake.refreshed == ["its-responder"]


def test_the_fix_check_leaves_alone_the_backends_of_servers_carrying_none_of_its_flaws(
    tmp_path: Path,
):
    fake = given.FakeFixCheck(given.a_result_matching(RECORD))
    deps = given.a_fix_check_ready(FIXTURE_OF_NO_ADMITTED_FLAW, fake)
    command = given.a_fix_check_command(tmp_path, given.an_admission_on_the_ckan_backend())

    run_nuisance.main(command, deps)

    assert fake.refreshed == []


def test_a_matching_result_and_record_have_no_mismatch():
    assert fix_check_mismatches(given.a_result_matching(RECORD), RECORD) == {}


def test_a_differing_field_is_reported():
    record = RECORD.model_copy(update={"patched_surfaces": True})

    mismatches = fix_check_mismatches(given.a_result_matching(RECORD), record)

    assert list(mismatches) == ["patched_surfaces"]


def test_a_holdout_calibration_copy_excludes_the_source_field():
    record = RECORD.model_copy(update={"source": "detection_holdout_calibration"})

    assert fix_check_mismatches(given.a_result_matching(record, source="fix_check"), record) == {}


def test_a_source_difference_on_a_fix_check_record_is_a_mismatch():
    result = given.a_result_matching(RECORD, source="detection_holdout_calibration")

    mismatches = fix_check_mismatches(result, RECORD)

    assert list(mismatches) == ["source"]


def test_a_record_judging_a_relaying_stand_in_matches_a_result_that_cannot_carry_it():
    record = RECORD.model_copy(update={"relies_on_relaying_stand_in": True})

    assert fix_check_mismatches(given.a_result_matching(record), record) == {}


def test_a_record_carrying_a_holdout_fingerprint_matches_a_result_that_cannot_carry_it():
    record = RECORD.model_copy(
        update={"source": "detection_holdout_calibration", "holdout_fingerprint": "f" * 64}
    )

    assert fix_check_mismatches(given.a_result_matching(record), record) == {}


def test_a_differing_witness_is_not_a_mismatch():
    # check_fix plants a fresh random witness each run, so the result's witness never equals the
    # one the admission recorded. Only the reproducible fields are compared.
    record = RECORD.model_copy(update={"witness": "MCPAUDIT-recordedwitness"})

    result = given.a_result_matching(record, witness="MCPAUDIT-freshwitness")

    assert fix_check_mismatches(result, record) == {}
