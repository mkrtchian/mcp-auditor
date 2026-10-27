from pathlib import Path

import pytest

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as given
import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_run_nuisance_given as run_given
from evals import run_nuisance
from evals.baseline import BaselineStatus


def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


def test_walk_prints_the_population_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = draw_given.a_census_with_draw(draw_given.a_draw())
    path = given.written(tmp_path, census)

    exit_code = run_nuisance.main(["walk", "--census", str(path)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "servers reached by the walk" in out
    assert "npm:@acme/files" in out
    assert "reached by CVE-2025-0001 (drawn)" in out


def test_a_malformed_census_exits_three(tmp_path: Path):
    path = tmp_path / "holdout_census.json"
    path.write_text("{ not valid json")

    assert run_nuisance.main(["walk", "--census", str(path)]) == 3


def test_nuisance_dossier_writes_and_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            "--census",
            str(census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
        ]
    )

    assert exit_code == 0
    assert out.exists()
    assert "Admission dossier for npm:@acme/files written to" in capsys.readouterr().out


def test_nuisance_dossier_with_a_backend_writes_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            "--census",
            str(census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
            "--backend",
            "doris",
        ]
    )

    assert exit_code == 0
    assert out.exists()


def test_nuisance_dossier_with_an_unknown_backend_exits_three(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            "--census",
            str(census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
            "--backend",
            "ghost",
        ]
    )

    assert exit_code == 3
    assert not out.exists()


def test_nuisance_dossier_on_an_unknown_server_exits_three(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        ["nuisance-dossier", "--census", str(census), "--server", "npm:ghost", "--out", str(out)]
    )

    assert exit_code == 3
    assert not out.exists()


def test_run_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_tracing(monkeypatch)
    census = given.written(tmp_path, given.a_census())
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(["run", "--census", str(census), "--admission", str(missing)])

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_run_on_an_admission_with_no_server_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_tracing(monkeypatch)
    census = given.written(tmp_path, given.a_census())
    empty = admission.an_admission().model_copy(update={"servers": []})
    path = admission.written(tmp_path, empty)

    exit_code = run_nuisance.main(["run", "--census", str(census), "--admission", str(path)])

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_run_refuses_tracing_before_reading_the_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    census = given.written(tmp_path, given.a_census())
    malformed = tmp_path / "nuisance_admission.json"
    malformed.write_text("{ not json")

    exit_code = run_nuisance.main(["run", "--census", str(census), "--admission", str(malformed)])

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "nuisance run refused" in out
    assert "malformed" not in out


def test_run_on_a_stale_admission_exits_three_naming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_tracing(monkeypatch)
    census = given.written(tmp_path, given.a_census())
    stale = admission.with_a_stale_grammar_fingerprint(admission.an_admission())
    path = admission.written(tmp_path, stale)

    exit_code = run_nuisance.main(["run", "--census", str(census), "--admission", str(path)])

    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "the census or the admission is malformed" in capsys.readouterr().out


_KUBERNETES = "npm:mcp-server-kubernetes"


def _no_llm_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def _a_census_with_a_kubernetes_target(tmp_path: Path) -> Path:
    return given.written(
        tmp_path, given.with_a_cve_of(given.a_census(), "CVE-2025-53355", _KUBERNETES)
    )


def test_gate_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = given.written(tmp_path, given.a_census())
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(["gate", "--census", str(census), "--admission", str(missing)])

    assert exit_code == 0
    assert "no acceptance server is admitted" in capsys.readouterr().out


def test_gate_with_only_a_non_current_server_admitted_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_llm_key(monkeypatch)
    census = _a_census_with_a_kubernetes_target(tmp_path)
    path = admission.written(tmp_path, admission.an_admission())

    exit_code = run_nuisance.main(["gate", "--census", str(census), "--admission", str(path)])

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

    exit_code = run_nuisance.main(["gate", "--census", str(census), "--admission", str(path)])

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
        ["gate", "--census", str(census), "--admission", str(path), "--server", "npm:other"]
    )

    assert exit_code == 2
    assert "unknown gate server: npm:other" in capsys.readouterr().err


def test_an_exploratory_gate_recording_names_the_command_that_confirms_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = run_given.a_captured_console(monkeypatch)
    run_given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = run_given.a_gate_set_of_one_server(tmp_path)

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
    output = run_given.a_captured_console(monkeypatch)
    run_given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = run_given.a_gate_set_of_one_server(tmp_path)
    server = run_given.GATE_SERVER

    run_nuisance.main(["gate", "--record-baseline", "--server", server, "--runs", "5", *gate_set])

    assert (
        "Run uv run python -m evals.run_nuisance gate --record-baseline"
        f" --server {server} --runs 5 again now"
    ) in output.getvalue()


def test_the_confirming_gate_command_leaves_the_default_run_count_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = run_given.a_captured_console(monkeypatch)
    run_given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.EXPLORATORY)
    gate_set = run_given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", "--runs", "3", *gate_set])

    assert "--runs" not in output.getvalue()


def test_a_recorded_gate_baseline_prints_once_after_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = run_given.a_captured_console(monkeypatch)
    run_given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.CONFIRMED)
    gate_set = run_given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", *gate_set])

    printed = output.getvalue()
    assert printed.count("recorded (confirmed)") == 1
    assert printed.index("Gate green.") < printed.index("Baseline recorded (confirmed)")
    assert "Commit evals/baselines/nuisance/ by hand." in printed
    assert "again now" not in printed
