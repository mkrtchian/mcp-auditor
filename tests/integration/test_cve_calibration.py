import os
import pathlib

import pytest

import evals.run_cve_benchmark as bench
import tests.integration.support.test_cve_calibration_given as given


async def test_a_server_dead_at_startup_fails_calibration_and_the_next_target_still_runs(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    docker_dir = given.a_docker_that_runs_its_command_on_the_host(tmp_path)
    monkeypatch.setenv("PATH", f"{docker_dir}{os.pathsep}{os.environ['PATH']}")
    targets = [
        given.a_target_whose_server_exits_at_startup("CVE-DEAD", "no tools registered"),
        given.a_live_target("CVE-LIVE"),
    ]

    all_live = await bench.calibrate_all(targets)

    output = capsys.readouterr().out
    assert not all_live
    assert "CVE-DEAD calibration error" in output
    assert "no tools registered" in output
    assert "live  CVE-LIVE" in output
