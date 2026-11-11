import os
import pathlib
from collections.abc import Awaitable, Callable

import pytest

import tests.integration.support.test_detection_calibration_check_given as given
from evals.concurrency import bounded
from evals.cve.detection.calibration_check import (
    check_calibrations,
    check_target,
    passes_calibration_check,
)
from evals.cve.detection.layout_check import check_layouts_and_routes, observe_versions
from evals.cve.detection.survey import TargetSurvey, survey_all, survey_one
from evals.cve.detection.targets import Target, TargetVersion
from evals.cve.failure_text import TYPES_ONLY
from evals.cve.images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_places import Places


def _check(places: Places, limit: int) -> Callable[[Target], Awaitable[bool]]:
    return bounded(lambda target: passes_calibration_check(target, places), limit)


def _survey(places: Places, limit: int) -> Callable[[Target], Awaitable[TargetSurvey]]:
    return bounded(lambda target: survey_one(target, places), limit)


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_server_dead_at_startup_fails_calibration_and_the_next_target_still_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    targets = [
        given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered"),
        given.a_live_target("CVE-LIVE"),
    ]

    all_live = await check_calibrations(targets, _check(given.a_places_mapping(), 2))

    output = capsys.readouterr().out
    assert not all_live
    assert "CVE-DEAD calibration check error" in output
    assert "no tools registered" in output
    assert "ok  CVE-LIVE" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_target_whose_exploit_surfaces_the_nonce_and_whose_benign_call_is_clean_is_live(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await check_calibrations(
        [given.a_live_target("CVE-LIVE")], _check(given.a_places_mapping(), 1)
    )

    assert all_live
    assert "ok  CVE-LIVE" in capsys.readouterr().out


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_benign_call_that_leaks_the_nonce_fails_the_negative_control(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await check_calibrations(
        [given.a_target_whose_benign_call_leaks("CVE-LEAK")],
        _check(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    # The longer label wraps the reason at the console's width.
    assert "negative control: benign call surfaces planted_nonce" in " ".join(output.split())
    assert "out of calibration  CVE-LEAK" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_an_aim_that_matches_no_call_leaves_the_target_out_of_calibration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await check_calibrations(
        [given.a_target_whose_aim_matches_nothing("CVE-NOAIM")],
        _check(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "exploit 0 not aimed" in output
    assert "out of calibration  CVE-NOAIM" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_kept_place_the_exploit_misses_is_out_of_calibration(
    capsys: pytest.CaptureFixture[str],
):
    all_live = await check_calibrations(
        [given.a_target_whose_exploit_misses("CVE-MISS")], _check(given.a_places_mapping(), 1)
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "exploit surfaces no nonce for fict-flag" in output
    assert "CVE-MISS exploit 0, tool exchanges" in output
    assert "out of calibration  CVE-MISS" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_target_with_no_kept_place_is_out_of_calibration(
    capsys: pytest.CaptureFixture[str],
):
    all_live = await check_calibrations(
        [given.a_target_with_no_kept_place("CVE-EMPTY")], _check(given.a_places_mapping(), 1)
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "keeps no place" in output
    assert "out of calibration  CVE-EMPTY" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_patched_version_that_still_surfaces_a_nonce_is_out_of_calibration(
    capsys: pytest.CaptureFixture[str],
):
    all_live = await check_calibrations(
        [given.a_target_whose_patched_version_still_surfaces("CVE-UNPATCHED")],
        _check(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "patched: exploit 0 still surfaces fict-flag" in output
    assert "out of calibration  CVE-UNPATCHED" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_patched_benign_call_that_errors_is_out_of_calibration(
    capsys: pytest.CaptureFixture[str],
):
    all_live = await check_calibrations(
        [given.a_target_whose_patched_benign_errors("CVE-BENIGN-ERR")],
        _check(given.a_places_mapping(), 1),
    )

    output = capsys.readouterr().out
    assert not all_live
    assert "patched: benign call errored" in output
    assert "out of calibration  CVE-BENIGN-ERR" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_vulnerable_launch_that_fails_twice_then_serves_reads_live(tmp_path: pathlib.Path):
    target = given.a_target_whose_vulnerable_launch_fails("CVE-FLAKY", tmp_path, times=2)

    conditions = await check_target(target, given.a_places_mapping())

    assert conditions == []
    assert given.launches_of(tmp_path, TargetVersion.VULNERABLE) == 3


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_vulnerable_launch_that_fails_three_times_did_not_launch(tmp_path: pathlib.Path):
    target = given.a_target_whose_vulnerable_launch_fails("CVE-FLAKY", tmp_path, times=3)

    conditions = await check_target(target, given.a_places_mapping())

    assert conditions == ["the vulnerable version did not launch"]
    assert given.launches_of(tmp_path, TargetVersion.VULNERABLE) == 3


@pytest.mark.usefixtures("docker_on_the_host")
async def test_an_out_of_calibration_reason_read_from_a_launch_is_not_retried(
    tmp_path: pathlib.Path,
):
    target = given.a_counted_target_whose_exploit_misses("CVE-MISS", tmp_path)

    conditions = await check_target(target, given.a_places_mapping())

    assert conditions == ["exploit surfaces no nonce for fict-flag"]
    assert given.launches_of(tmp_path, TargetVersion.VULNERABLE) == 1
    assert given.launches_of(tmp_path, TargetVersion.PATCHED) == 1


@pytest.mark.usefixtures("docker_on_the_host")
async def test_the_types_only_check_prints_the_out_of_calibration_reasons_and_no_server_text(
    capsys: pytest.CaptureFixture[str],
):
    places = given.a_places_mapping()
    exits = given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered")
    misses = given.a_target_whose_exploit_misses("CVE-MISS")

    await check_target(exits, places, report_detail=TYPES_ONLY)
    await check_target(misses, places, report_detail=TYPES_ONLY)

    output = capsys.readouterr().out
    assert "CVE-DEAD calibration check error" in output
    assert "CVE-MISS out of calibration: exploit surfaces no nonce for fict-flag" in output
    assert "no tools registered" not in output
    assert "Connection closed" not in output
    assert "tool exchanges" not in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_layout_launch_that_fails_twice_then_serves_is_observed(tmp_path: pathlib.Path):
    target = given.a_target_whose_reference_launch_fails("CVE-FLAKY", tmp_path, times=2)

    vulnerable, _ = await observe_versions(target, given.a_places_mapping())

    assert vulnerable.reference.tools_list_succeeded
    assert vulnerable.planted.tools_list_succeeded


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_layout_launch_that_fails_three_times_is_a_failed_observation(
    tmp_path: pathlib.Path,
):
    target = given.a_target_whose_reference_launch_fails("CVE-FLAKY", tmp_path, times=3)

    vulnerable, _ = await observe_versions(target, given.a_places_mapping())

    assert not vulnerable.reference.tools_list_succeeded
    assert vulnerable.planted.tools_list_succeeded


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_launched_server_whose_tools_list_fails_is_observed_once(tmp_path: pathlib.Path):
    target = given.a_counted_target_whose_tools_list_breaks("CVE-NOLIST", tmp_path)

    vulnerable, _ = await observe_versions(target, given.a_places_mapping())

    assert not vulnerable.reference.tools_list_succeeded
    assert given.launches_of(tmp_path, TargetVersion.VULNERABLE) == 2


@pytest.mark.usefixtures("docker_on_the_host")
async def test_the_types_only_layout_check_prints_no_stderr_line(
    capsys: pytest.CaptureFixture[str],
):
    target = given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered")

    await observe_versions(target, given.a_places_mapping(), report_detail=TYPES_ONLY)

    output = capsys.readouterr().out
    assert "CVE-DEAD layout check launch error" in output
    assert "no tools registered" not in output
    assert "unhandled errors" not in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_check_layouts_and_routes_reports_a_break_when_the_layout_breaks_either_version(
    capsys: pytest.CaptureFixture[str],
):
    targets = [
        given.a_target_whose_layout_breaks_the_patched_version("CVE-BREAK"),
        given.a_live_target("CVE-LIVE"),
    ]

    failures = await check_layouts_and_routes(targets, given.a_places_mapping())

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

    failures = await check_layouts_and_routes([target], given.the_holdout_places())

    output = capsys.readouterr().out
    assert "layout check launch error" not in output
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
