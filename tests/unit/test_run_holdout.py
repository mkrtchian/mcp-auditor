from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_census_given as given
import tests.unit.support.test_holdout_run_given as holdout_given
import tests.unit.support.test_run_holdout_run_given as run_given
from evals import run_holdout
from evals.admission_calibration import CalibrationDeps
from evals.closed_network import ClosedNetworkUnsupported
from evals.cve_planting_base import SENTINEL_SERVICE
from evals.cve_targets import CVE_TARGETS, image_tag
from evals.holdout_kit import kit_launch
from evals.run_images import target_services
from tests.fakes import FakeContainerSweep
from tests.unit.support.test_admission_calibration_given import deps_with


@pytest.fixture(autouse=True)
def _no_docker_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    _leftovers(monkeypatch)


def _leftovers(monkeypatch: pytest.MonkeyPatch, *running: str) -> FakeContainerSweep:
    containers = FakeContainerSweep(list(running))
    monkeypatch.setattr(run_holdout, "DOCKER_SWEEP", containers.sweep)
    return containers


def test_run_without_a_drawn_target_exits_zero_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(run_holdout, "HOLDOUT_TARGETS", ())

    exit_code = run_holdout.main(["run"])

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_run_refuses_when_tracing_is_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    assert run_holdout.main(["run"]) == run_holdout.REFUSED_EXIT


def test_calibrate_without_a_drawn_target_exits_zero_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(run_holdout, "HOLDOUT_TARGETS", ())

    exit_code = run_holdout.main(["calibrate"])

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_calibrate_crashes_to_four_on_a_fixture_config_error(monkeypatch: pytest.MonkeyPatch):
    _a_drawn_target(monkeypatch)
    _a_calibration(monkeypatch, deps_with(raises=True))

    assert run_holdout.main(["calibrate"]) == run_holdout.CRASHED_EXIT


def test_calibrate_removes_the_containers_of_its_images_left_running(
    monkeypatch: pytest.MonkeyPatch,
):
    containers = _leftovers(monkeypatch, "leftover_filesystem")
    _a_drawn_target(monkeypatch)
    _a_calibration(monkeypatch, deps_with())

    run_holdout.main(["calibrate"])

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_drawn_target_tags()]


def test_a_calibration_that_raises_still_removes_the_containers_left_running(
    monkeypatch: pytest.MonkeyPatch,
):
    containers = _leftovers(monkeypatch, "leftover_filesystem")
    _a_drawn_target(monkeypatch)
    _a_calibration(monkeypatch, deps_with(raises=True))

    assert run_holdout.main(["calibrate"]) == run_holdout.CRASHED_EXIT
    assert containers.removed == ["leftover_filesystem"]


def test_calibrate_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _a_drawn_target(monkeypatch)
    monkeypatch.setattr(run_holdout, "check_closed_network_support", _cannot_close_a_network)
    _a_calibration(monkeypatch, deps_with(failures=["the admission was reached"]))

    exit_code = run_holdout.main(["calibrate"])

    assert exit_code == run_holdout.REFUSED_EXIT
    assert "Docker Engine 28.0 or later is required" in capsys.readouterr().out


def _a_drawn_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        run_holdout, "HOLDOUT_TARGETS", (holdout_given.a_target(holdout_given.FILESYSTEM),)
    )
    monkeypatch.setattr(run_holdout, "check_closed_network_support", lambda: None)


def _drawn_target_tags() -> list[str]:
    return [
        image_tag(service)
        for service in target_services([holdout_given.a_target(holdout_given.FILESYSTEM)])
    ]


def _cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


def _a_calibration(monkeypatch: pytest.MonkeyPatch, deps: CalibrationDeps) -> None:
    def default_calibration_deps(*_: object, **__: object) -> CalibrationDeps:
        return deps

    monkeypatch.setattr(run_holdout, "default_calibration_deps", default_calibration_deps)


def test_run_refuses_an_acceptance_target_for_its_tools_filter(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_MODEL", "gpt-6-luna")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")  # the auditor is built, never called
    monkeypatch.setattr(run_holdout, "HOLDOUT_TARGETS", (CVE_TARGETS[0],))
    run_given.cards_reporting(monkeypatch, [])

    assert run_holdout.main(["run"]) == run_holdout.REFUSED_EXIT


def test_draw_order_is_no_longer_a_command_of_the_holdout_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, given.a_census())

    with pytest.raises(SystemExit) as refused:
        run_holdout.main(["draw-order", "--census", str(census)])

    assert refused.value.code == 2
    assert "invalid choice: 'draw-order'" in capsys.readouterr().err


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
        "docker/Dockerfile.stand-in",
        "evals/stand_ins/tls/fixture-authority.pem",
        *(f"evals/stand_ins/{capture.name}" for capture in _COMMITTED_CAPTURES),
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


_COMMITTED_CAPTURES = sorted((iso.REPO_ROOT / "evals" / "stand_ins").glob("*.json"))


def _acceptance_services() -> set[str]:
    services = {name for target in CVE_TARGETS for name in (*target.images, target.patched_image)}
    return services | {SENTINEL_SERVICE}


def test_the_kit_tags_its_images_outside_the_acceptance_namespace():
    assert kit_launch.image_tag("x") == "mcp-auditor-kit-x:local"
