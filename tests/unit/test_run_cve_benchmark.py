from pathlib import Path

import pytest

from evals import run_cve_benchmark


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--ungated"],
        ["--calibrate", "--ungated"],
        ["--calibrate", "--record-baseline"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3


def test_a_calibration_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--calibrate"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 4
