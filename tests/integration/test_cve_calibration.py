import os
from collections.abc import Awaitable, Callable

import pytest

import tests.integration.support.test_cve_calibration_given as given
from evals.concurrency import bounded
from evals.cve_calibration import calibrate_all, calibrate_one
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_layout_check import confirm_admission
from evals.cve_places import Places
from evals.cve_survey import TargetSurvey, survey_all, survey_one
from evals.cve_targets import CVETarget


def _calibrate(places: Places, limit: int) -> Callable[[CVETarget], Awaitable[bool]]:
    return bounded(lambda target: calibrate_one(target, places), limit)


def _survey(places: Places, limit: int) -> Callable[[CVETarget], Awaitable[TargetSurvey]]:
    return bounded(lambda target: survey_one(target, places), limit)


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_server_dead_at_startup_fails_calibration_and_the_next_target_still_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    targets = [
        given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered"),
        given.a_live_target("CVE-LIVE"),
    ]

    all_live = await calibrate_all(targets, _calibrate(given.a_places_mapping(), 2))

    output = capsys.readouterr().out
    assert not all_live
    assert "CVE-DEAD calibration error" in output
    assert "no tools registered" in output
    assert "live  CVE-LIVE" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_target_whose_exploit_surfaces_the_nonce_and_whose_benign_call_is_clean_is_live(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all(
        [given.a_live_target("CVE-LIVE")], _calibrate(given.a_places_mapping(), 1)
    )

    assert all_live
    assert "live  CVE-LIVE" in capsys.readouterr().out


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_benign_call_that_leaks_the_nonce_fails_the_negative_control(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all(
        [given.a_target_whose_benign_call_leaks("CVE-LEAK")],
        _calibrate(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "negative control: benign call surfaces planted_nonce" in output
    assert "dead  CVE-LEAK" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_an_aim_that_matches_no_call_leaves_the_target_dead(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all(
        [given.a_target_whose_aim_matches_nothing("CVE-NOAIM")],
        _calibrate(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "exploit 0 not aimed" in output
    assert "dead  CVE-NOAIM" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_kept_place_the_exploit_misses_reads_dead(capsys: pytest.CaptureFixture[str]):
    all_live = await calibrate_all(
        [given.a_target_whose_exploit_misses("CVE-MISS")], _calibrate(given.a_places_mapping(), 1)
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "exploit surfaces no nonce for fict-flag" in output
    assert "dead  CVE-MISS" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_target_with_no_kept_place_reads_dead(capsys: pytest.CaptureFixture[str]):
    all_live = await calibrate_all(
        [given.a_target_with_no_kept_place("CVE-EMPTY")], _calibrate(given.a_places_mapping(), 1)
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "keeps no place" in output
    assert "dead  CVE-EMPTY" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_patched_version_that_still_surfaces_a_nonce_reads_dead(
    capsys: pytest.CaptureFixture[str],
):
    all_live = await calibrate_all(
        [given.a_target_whose_patched_version_still_surfaces("CVE-UNPATCHED")],
        _calibrate(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "patched: exploit 0 still surfaces fict-flag" in output
    assert "dead  CVE-UNPATCHED" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_patched_benign_call_that_errors_reads_dead(capsys: pytest.CaptureFixture[str]):
    all_live = await calibrate_all(
        [given.a_target_whose_patched_benign_errors("CVE-BENIGN-ERR")],
        _calibrate(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "patched: benign call errored" in output
    assert "dead  CVE-BENIGN-ERR" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_confirm_admission_reports_a_break_when_the_layout_breaks_either_version(
    capsys: pytest.CaptureFixture[str],
):
    targets = [
        given.a_target_whose_layout_breaks_the_patched_version("CVE-BREAK"),
        given.a_live_target("CVE-LIVE"),
    ]

    failures = await confirm_admission(targets, given.a_places_mapping())

    output = capsys.readouterr().out
    assert failures == []
    assert "layout break  CVE-BREAK" in output
    assert "no break  CVE-LIVE" in output


async def test_the_git_target_starts_on_the_valid_reference_arm(capsys: pytest.CaptureFixture[str]):
    missing = given.missing_docker()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    target = given.the_git_target()
    try:
        ensure_images([target.server_image, target.patched_image], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))

    failures = await confirm_admission([target], given.the_holdout_places())

    output = capsys.readouterr().out
    assert "admission launch error" not in output
    assert "no break  CVE-2025-68143" in output
    assert failures == []


@pytest.mark.usefixtures("docker_on_the_host")
async def test_survey_reports_the_three_facts_per_candidate_without_a_verdict(
    capsys: pytest.CaptureFixture[str],
):
    places = given.a_survey_places_mapping()

    await survey_all([given.a_survey_target("CVE-SURVEY")], _survey(places, 1))

    output = capsys.readouterr().out
    assert "fict-inside (fictional): exploit no, benign yes, patched no" in output
    assert "fict-outside (fictional): exploit yes, benign no, patched yes" in output
    assert "live" not in output and "dead" not in output
