from dataclasses import replace

import pytest

from evals import run_detection
from evals.cve.detection.measurement import MEASUREMENT_NEEDS_NO_BASELINE, STEPS_WITHOUT_CHAINS
from tests.unit.detection.support import run_detection_cli as cli


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--no-baseline"],
        ["--calibration-check", "--no-baseline"],
        ["--calibration-check", "--record-baseline"],
        ["--survey", "--calibration-check"],
        ["--survey", "--record-baseline"],
        ["--survey", "--no-baseline"],
        ["--show-exploit-responses"],
        ["--show-exploit-responses", "--no-baseline"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(flags: list[str]):
    assert cli.exit_code_of(cli.deps_reaching_nothing(), *flags) == 3


@pytest.mark.parametrize(
    "flags",
    [
        ["--chains", "3"],
        ["--chain-steps", "3"],
        ["--tool-call-timeout", "30"],
        ["--no-tools-filter"],
        ["--record-baseline", "--tool-call-timeout", "30"],
    ],
)
def test_a_measurement_flag_outside_a_no_baseline_run_is_refused(
    capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = cli.exit_code_of(cli.deps_reaching_nothing(), *flags)

    assert code == 3
    assert MEASUREMENT_NEEDS_NO_BASELINE in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize(
    "flags",
    [
        ["--no-baseline", "--chain-steps", "3"],
        ["--no-baseline", "--chains", "0", "--chain-steps", "3"],
    ],
)
def test_chain_steps_without_chains_are_refused(
    capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = cli.exit_code_of(cli.deps_reaching_nothing(), *flags)

    assert code == 3
    assert STEPS_WITHOUT_CHAINS in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize("mode", ["--calibration-check", "--survey"])
def test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason(
    capsys: pytest.CaptureFixture[str], mode: str
):
    code = cli.exit_code_of(cli.deps_reaching_nothing(), mode, "--chains", "3")

    assert code == 3
    assert "run no audit" in "".join(capsys.readouterr())


def test_a_negative_chain_count_is_refused_by_the_parser(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exit_:
        run_detection.main(["--no-baseline", "--chains", "-1"], cli.deps_reaching_nothing())

    assert exit_.value.code == 2
    assert "--chains: expected at least 0" in capsys.readouterr().err


def test_an_unknown_flaw_id_is_refused_before_the_preflight(capsys: pytest.CaptureFixture[str]):
    deps = replace(cli.deps_reaching_nothing(), preflight=_a_preflight_that_must_not_run)

    with pytest.raises(SystemExit) as exit_:
        run_detection.main(["--flaw", "CVE-0000-0000"], deps)

    assert exit_.value.code == 2
    assert "CVE-0000-0000" in capsys.readouterr().out


def _a_preflight_that_must_not_run() -> bool:
    raise AssertionError("the preflight must not run")


def test_a_concurrency_below_one_is_refused_by_the_parser(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exit_:
        run_detection.main(["--concurrency", "0"], cli.deps_reaching_nothing())

    assert exit_.value.code == 2
    assert "--concurrency: expected at least 1" in capsys.readouterr().err
