"""The nuisance `gate` command: what it refuses or reports before any audit, and the
recording messages around a gate run that audits nothing. No Docker, no LLM."""

from pathlib import Path

import pytest

import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_walk_given as walk_given
import tests.unit.support.test_run_nuisance_gate_given as given
from evals import run_nuisance
from evals.baseline import BaselineStatus


def _census_arguments(tmp_path: Path, census: Path) -> list[str]:
    record = walk_given.a_written_empty_record(tmp_path)
    return ["--census", str(census), "--walk-record", str(record)]


_KUBERNETES = admission.ACCEPTANCE_PACKAGE


def _no_llm_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def _a_census_with_a_kubernetes_target(tmp_path: Path) -> Path:
    return census_given.written(tmp_path, admission.a_census_with_an_acceptance_server())


def test_gate_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = census_given.written(tmp_path, admission.a_census())
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        ["gate", *_census_arguments(tmp_path, census), "--admission", str(missing)]
    )

    assert exit_code == 0
    assert "no acceptance server is admitted" in capsys.readouterr().out


def test_gate_with_only_a_non_current_server_admitted_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = _a_census_with_a_kubernetes_target(tmp_path)
    path = admission.written(tmp_path, admission.an_admission())

    exit_code = run_nuisance.main(
        ["gate", *_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    assert exit_code == 0
    assert "no acceptance server is admitted" in capsys.readouterr().out


def test_gate_with_no_admitted_server_able_to_launch_exits_zero_naming_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = _a_census_with_a_kubernetes_target(tmp_path)
    admitted = admission.admitting_the_server_of(
        "CVE-2025-53355", _KUBERNETES, "kubernetes-nuisance"
    )
    [server] = admitted.servers
    no_stdio = admitted.model_copy(
        update={"servers": [server.model_copy(update={"runs_over_stdio": False})]}
    )
    path = admission.written(tmp_path, no_stdio)

    exit_code = run_nuisance.main(
        ["gate", *_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "no acceptance server is admitted" not in out
    assert "no admitted acceptance server can run in the gate" in out
    assert f"{_KUBERNETES}: does not run over stdio" in out


def test_gate_on_a_server_outside_the_gate_set_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = _a_census_with_a_kubernetes_target(tmp_path)
    admitted = admission.admitting_the_server_of(
        "CVE-2025-53355", _KUBERNETES, "kubernetes-nuisance"
    )
    path = admission.written(tmp_path, admitted)

    exit_code = run_nuisance.main(
        [
            "gate",
            *_census_arguments(tmp_path, census),
            "--admission",
            str(path),
            "--server",
            "npm:other",
        ]
    )

    assert exit_code == 2
    assert "unknown gate server: npm:other" in capsys.readouterr().err


def test_an_exploratory_gate_recording_names_the_command_that_confirms_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    exit_code = run_nuisance.main(["gate", "--record-baseline", *gate_set])

    assert exit_code == 0
    assert (
        "Run uv run python -m evals.run_nuisance gate --record-baseline again now, at this commit"
        " and on these images, to confirm it. Commit evals/baselines/nuisance/ by hand once"
        " confirmed."
    ) in output.getvalue()


def test_the_confirming_gate_command_repeats_the_server_and_a_non_default_run_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = given.a_gate_set_of_one_server(tmp_path)
    server = given.GATE_SERVER

    run_nuisance.main(["gate", "--record-baseline", "--server", server, "--runs", "5", *gate_set])

    assert (
        "Run uv run python -m evals.run_nuisance gate --record-baseline"
        f" --server {server} --runs 5 again now"
    ) in output.getvalue()


def test_the_confirming_gate_command_leaves_the_default_run_count_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", "--runs", "3", *gate_set])

    assert "--runs" not in output.getvalue()


def test_a_recorded_gate_baseline_prints_once_after_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.CONFIRMED)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", *gate_set])

    printed = output.getvalue()
    assert printed.count("recorded (confirmed)") == 1
    assert printed.index("Gate green.") < printed.index("Baseline recorded (confirmed)")
    assert "Commit evals/baselines/nuisance/ by hand." in printed
    assert "again now" not in printed
