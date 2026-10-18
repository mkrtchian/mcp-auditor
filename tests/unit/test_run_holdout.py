import importlib.util
from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_holdout_census_given as given
from evals import run_holdout
from evals.cve_targets import CVE_TARGETS


def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


def test_run_without_a_drawn_target_exits_zero_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _no_tracing(monkeypatch)
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", ())

    exit_code = run_holdout.main(["run"])

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_run_refuses_when_tracing_is_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    assert run_holdout.main(["run"]) == run_holdout.REFUSED_EXIT


def test_run_refuses_an_acceptance_target_for_its_tools_filter(
    monkeypatch: pytest.MonkeyPatch,
):
    _no_tracing(monkeypatch)
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (CVE_TARGETS[0],))

    assert run_holdout.main(["run"]) == run_holdout.REFUSED_EXIT


def test_draw_order_exits_zero_and_prints_a_per_side_tally(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, given.a_census())

    exit_code = run_holdout.main(["draw-order", "--census", str(census), "--cutoff", "2026-05-18"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "pre_cutoff:" in output
    assert "post_cutoff:" in output


def test_draw_order_without_a_cutoff_is_an_argparse_error(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())

    with pytest.raises(SystemExit) as exit_info:
        run_holdout.main(["draw-order", "--census", str(census)])

    assert exit_info.value.code == 2


def test_draw_order_on_a_malformed_census_exits_three(tmp_path: Path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid census}")

    exit_code = run_holdout.main(
        ["draw-order", "--census", str(malformed), "--cutoff", "2026-05-18"]
    )

    assert exit_code == 3


def test_calibration_dossier_on_an_unknown_cve_refuses_with_exit_three(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())

    exit_code = run_holdout.main(
        [
            "calibration-dossier",
            "--census",
            str(census),
            "--cve",
            "CVE-2099-9999",
            "--out",
            str(tmp_path / "kit"),
        ]
    )

    assert exit_code == 3
    assert not (tmp_path / "kit").exists()


def test_calibration_dossier_writes_an_isolated_kit(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "kit"

    exit_code = run_holdout.main(
        [
            "calibration-dossier",
            "--census",
            str(census),
            "--cve",
            given.FLAW_WITH_A_CVE,
            "--out",
            str(out),
        ]
    )

    assert exit_code == 0
    for relative in (
        f"advisories/{given.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        "evals/cve_grammar.py",
        "evals/holdout_places.json",
        "evals/holdout_kit/kit_driver.py",
        "docker/Dockerfile.sentinel",
        "README.md",
        "fixture_format.md",
        "layout.md",
        "grammar_classes.md",
    ):
        assert (out / relative).exists(), relative
    assert iso.scan_tree(out) == {}


def test_calibration_dossier_places_file_loads_through_the_copied_loader(tmp_path: Path):
    census = given.written(tmp_path, given.a_census())
    out = tmp_path / "kit"
    run_holdout.main(
        [
            "calibration-dossier",
            "--census",
            str(census),
            "--cve",
            given.FLAW_WITH_A_CVE,
            "--out",
            str(out),
        ]
    )

    places = _load_copied_places(out / "evals" / "cve_places.py")

    assert places


def _load_copied_places(module_path: Path) -> dict[str, object]:
    spec = importlib.util.spec_from_file_location("kit_cve_places", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_places(module.HOLDOUT_PLACES)
