from dataclasses import replace
from pathlib import Path

import pytest

import tests.unit.detection.support.holdout_command_deps as command_deps
import tests.unit.detection.support.test_run_detection_holdout_given as given
from evals import run_detection_holdout
from evals.cve.detection.targets import target_services
from evals.cve.images import image_tag
from tests.fakes import FakeContainerSweep
from tests.fakes.image_store import FakeImageStore
from tests.unit.detection.support.calibration_check_deps import deps_with
from tests.unit.support import censuses
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, an_acceptance_target


def test_the_calibration_check_without_a_drawn_target_exits_zero_and_says_so(
    capsys: pytest.CaptureFixture[str],
):
    deps = replace(command_deps.a_command_reaching_nothing(), drawn=())

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_the_calibration_check_crashes_to_four_on_a_fixture_config_error(
    capsys: pytest.CaptureFixture[str],
):
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(raises=True))

    assert run_detection_holdout.main(["calibration-check"], deps) == (
        run_detection_holdout.CRASHED_EXIT
    )
    assert (
        "Crashed: a detection fixture of a holdout target is misconfigured."
        in capsys.readouterr().out
    )


@pytest.mark.parametrize("flag", [[], ["--show-exploit-responses"]], ids=["default", "flag"])
def test_the_calibration_check_shows_exploit_responses_only_when_asked(flag: list[str]):
    factory = given.FlagRecordingFactory(deps_with())
    deps = replace(given.a_drawn_command(FILESYSTEM, checks=deps_with()), calibration_check=factory)

    run_detection_holdout.main(["calibration-check", *flag], deps)

    assert factory.shown == [bool(flag)]


def test_the_calibration_check_removes_the_containers_of_its_images_left_running():
    containers = FakeContainerSweep(["leftover_filesystem"])
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(), sweep=containers)

    run_detection_holdout.main(["calibration-check"], deps)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [list(given.current_labels(FILESYSTEM))]


def test_a_calibration_check_that_raises_still_removes_the_containers_left_running():
    containers = FakeContainerSweep(["leftover_filesystem"])
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(raises=True), sweep=containers)

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == run_detection_holdout.CRASHED_EXIT
    assert containers.removed == ["leftover_filesystem"]


def test_the_calibration_check_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    capsys: pytest.CaptureFixture[str],
):
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(raises=True))
    deps = replace(
        deps, docker=replace(deps.docker, check_networks=given.a_daemon_that_cannot_close_a_network)
    )

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == 3
    assert "Docker Engine 28.0 or later is required" in capsys.readouterr().out


def test_the_calibration_check_takes_one_flaw():
    checked: list[str] = []
    deps = given.a_drawn_command(FILESYSTEM, GIT, checks=deps_with(checked=checked))

    exit_code = run_detection_holdout.main(["calibration-check", "--flaw", FILESYSTEM], deps)

    assert exit_code == 0
    assert checked == [FILESYSTEM]


def test_the_calibration_check_on_a_flaw_not_drawn_exits_zero_and_says_so(
    capsys: pytest.CaptureFixture[str],
):
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(raises=True))

    exit_code = run_detection_holdout.main(["calibration-check", "--flaw", "CVE-2099-9999"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_the_calibration_check_refuses_with_exit_three_on_a_stale_or_absent_image(
    capsys: pytest.CaptureFixture[str],
):
    stale, absent = target_services([an_acceptance_target(FILESYSTEM)])[:2]
    labels = given.current_labels(FILESYSTEM) | {image_tag(stale): "an-older-fingerprint"}
    del labels[image_tag(absent)]
    store = FakeImageStore(labels)
    deps = given.a_drawn_command(FILESYSTEM, checks=deps_with(raises=True))
    deps = replace(deps, docker=replace(deps.docker, images=store))

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == 3
    out = capsys.readouterr().out
    assert f"image of {stale} is stale or absent" in out
    assert f"image of {absent} is stale or absent" in out
    assert "docker compose -f evals/docker/compose.yml build" in out
    assert store.builds == []


def test_calibration_dossier_on_an_unknown_flaw_refuses_with_exit_three(tmp_path: Path):
    census = censuses.written(tmp_path, censuses.a_census())

    exit_code = run_detection_holdout.main(
        [
            "calibration-dossier",
            "--census",
            str(census),
            "--flaw",
            "CVE-2099-9999",
            "--out",
            str(tmp_path / "kit"),
        ]
    )

    assert exit_code == 3
    assert not (tmp_path / "kit").exists()


def test_calibration_dossier_writes_an_isolated_kit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = censuses.written(tmp_path, censuses.a_census())
    out = tmp_path / "kit"

    exit_code = run_detection_holdout.main(
        [
            "calibration-dossier",
            "--census",
            str(census),
            "--flaw",
            censuses.FLAW_WITH_A_CVE,
            "--out",
            str(out),
        ]
    )

    assert exit_code == 0
    assert (out / "README.md").exists()
    assert f"Calibration kit for {censuses.FLAW_WITH_A_CVE} written to {out}" in (
        capsys.readouterr().out
    )
