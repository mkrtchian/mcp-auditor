import os
import pathlib

import pytest

import tests.integration.support.test_cve_calibration_given as given
from evals.cve_calibration import calibrate_all


@pytest.fixture
def docker_on_the_host(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    docker_dir = given.a_docker_that_runs_its_command_on_the_host(tmp_path)
    monkeypatch.setenv("PATH", f"{docker_dir}{os.pathsep}{os.environ['PATH']}")


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_server_dead_at_startup_fails_calibration_and_the_next_target_still_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    targets = [
        given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered"),
        given.a_live_target("CVE-LIVE"),
    ]

    all_live = await calibrate_all(targets)

    output = capsys.readouterr().out
    assert not all_live
    assert "CVE-DEAD calibration error" in output
    assert "no tools registered" in output
    assert "live  CVE-LIVE" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_target_whose_exploit_surfaces_the_nonce_and_whose_benign_call_is_clean_is_live(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all([given.a_live_target("CVE-LIVE")])

    assert all_live
    assert "live  CVE-LIVE" in capsys.readouterr().out


@pytest.mark.usefixtures("docker_on_the_host")
async def test_a_benign_call_that_leaks_the_nonce_fails_the_negative_control(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all([given.a_target_whose_benign_call_leaks("CVE-LEAK")])

    output = capsys.readouterr().out
    assert not all_live
    assert "negative control: benign call surfaces planted_nonce" in output
    assert "dead  CVE-LEAK" in output


@pytest.mark.usefixtures("docker_on_the_host")
async def test_an_aim_that_matches_no_call_leaves_the_target_dead(
    capsys: pytest.CaptureFixture[str],
) -> None:
    all_live = await calibrate_all([given.a_target_whose_aim_matches_nothing("CVE-NOAIM")])

    output = capsys.readouterr().out
    assert not all_live
    assert "exploit not aimed" in output
    assert "dead  CVE-NOAIM" in output
