import importlib.util
from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_holdout_census_given as given
from evals import run_holdout
from evals.cve_planting_base import SENTINEL_SERVICE
from evals.cve_targets import CVE_TARGETS
from evals.holdout_draw import draw_order
from evals.holdout_kit import kit_launch


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


def test_calibrate_without_a_drawn_target_exits_zero_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", ())

    exit_code = run_holdout.main(["calibrate"])

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_calibrate_exits_zero_when_every_target_is_live_and_routed(
    monkeypatch: pytest.MonkeyPatch,
):
    _a_drawn_target(monkeypatch)
    _fake_admission(monkeypatch, failures=[])
    _fake_calibration(monkeypatch, all_live=True)

    assert run_holdout.main(["calibrate"]) == 0


def test_calibrate_exits_one_when_a_fixture_calibrates_dead(monkeypatch: pytest.MonkeyPatch):
    _a_drawn_target(monkeypatch)
    _fake_admission(monkeypatch, failures=[])
    _fake_calibration(monkeypatch, all_live=False)

    assert run_holdout.main(["calibrate"]) == 1


def test_calibrate_exits_one_when_a_kept_place_has_no_route(monkeypatch: pytest.MonkeyPatch):
    _a_drawn_target(monkeypatch)
    _fake_admission(monkeypatch, failures=["CVE-0000-00000: kept layout place p has no route"])
    _fake_calibration(monkeypatch, all_live=True)

    assert run_holdout.main(["calibrate"]) == 1


def test_calibrate_crashes_to_four_on_a_fixture_config_error(monkeypatch: pytest.MonkeyPatch):
    _a_drawn_target(monkeypatch)
    _fake_admission(monkeypatch, failures=[])

    async def _raises(*_: object) -> bool:
        raise ValueError("unknown kept place id")

    monkeypatch.setattr(run_holdout, "calibrate_all", _raises)

    assert run_holdout.main(["calibrate"]) == run_holdout.CRASHED_EXIT


def _a_drawn_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (object(),))


def _fake_admission(monkeypatch: pytest.MonkeyPatch, failures: list[str]) -> None:
    async def _confirm(*_: object, **__: object) -> list[str]:
        return failures

    monkeypatch.setattr(run_holdout, "confirm_admission", _confirm)


def _fake_calibration(monkeypatch: pytest.MonkeyPatch, all_live: bool) -> None:
    async def _calibrate_all(*_: object, **__: object) -> bool:
        return all_live

    monkeypatch.setattr(run_holdout, "calibrate_all", _calibrate_all)


def test_run_refuses_an_acceptance_target_for_its_tools_filter(
    monkeypatch: pytest.MonkeyPatch,
):
    _no_tracing(monkeypatch)
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
    monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (CVE_TARGETS[0],))

    assert run_holdout.main(["run"]) == run_holdout.REFUSED_EXIT


def test_draw_order_prints_each_candidate_with_its_digest_and_disclosure_date(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.a_census()
    entries = draw_order(census)

    exit_code = run_holdout.main(["draw-order", "--census", str(given.written(tmp_path, census))])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert f"{len(entries)} candidates in draw order:" in output
    for entry in entries:
        assert f"  {entry.digest[:12]}  {entry.identifier}  {entry.disclosure_date}" in output
    assert "pre_cutoff" not in output
    assert "post_cutoff" not in output


def test_draw_order_on_a_malformed_census_exits_three(tmp_path: Path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid census}")

    exit_code = run_holdout.main(["draw-order", "--census", str(malformed)])

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
    readme = (out / "README.md").read_text()
    assert "mcp-auditor-kit-<service>:local" in readme
    for service in _acceptance_services():
        assert f"`{service}`" in readme, service


def _acceptance_services() -> set[str]:
    services = {name for target in CVE_TARGETS for name in (*target.images, target.patched_image)}
    return services | {SENTINEL_SERVICE}


def test_the_kit_tags_its_images_outside_the_acceptance_namespace():
    assert kit_launch.image_tag("x") == "mcp-auditor-kit-x:local"


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
