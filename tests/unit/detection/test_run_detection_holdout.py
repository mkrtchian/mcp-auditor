from dataclasses import replace
from pathlib import Path

import pytest

import tests.unit.detection.support.holdout_command_deps as command_deps
import tests.unit.support.kit_isolation as iso
from evals import run_detection_holdout
from evals.cve.closed_network import ClosedNetworkUnsupported
from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.holdout_command_deps import HoldoutCommandDeps
from evals.cve.detection.holdout_run import run_holdout_targets
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, image_tag
from evals.cve.images import dockerfile_fingerprint
from evals.cve.kit import launch as kit_launch
from evals.cve.planting_base import SENTINEL_SERVICE
from evals.cve.run_images import RunDocker, target_services
from evals.repository import REPO_ROOT
from tests.fakes import FakeContainerSweep
from tests.fakes.image_store import FakeImageStore
from tests.unit.detection.support.calibration_check_deps import deps_with
from tests.unit.support import censuses
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, an_acceptance_target


def test_run_without_a_drawn_target_exits_zero_and_says_so(capsys: pytest.CaptureFixture[str]):
    deps = replace(command_deps.a_drawn_run_reaching_nothing(), drawn=())

    exit_code = run_detection_holdout.main(["run"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_run_refuses_when_tracing_is_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    exit_code = run_detection_holdout.main(["run"], command_deps.a_command_reaching_nothing())

    assert exit_code == run_detection_holdout.REFUSED_EXIT


def test_run_refuses_an_acceptance_target_for_its_tools_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    command_deps.a_ready_run(monkeypatch)
    deps = replace(
        command_deps.a_drawn_run_ending_in(command_deps.a_run_result()),
        drawn=(command_deps.a_drawn_target(),),
        run_targets=run_holdout_targets,
    )
    census = command_deps.a_census_with_a_ready_card(tmp_path)

    exit_code = run_detection_holdout.main(["run", "--census", str(census)], deps)

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    assert (
        f"the rule runs with no tools filter, but {command_deps.DRAWN_FLAW} carries one"
        in capsys.readouterr().out
    )


def test_the_calibration_check_without_a_drawn_target_exits_zero_and_says_so(
    capsys: pytest.CaptureFixture[str],
):
    deps = replace(command_deps.a_command_reaching_nothing(), drawn=())

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_the_calibration_check_crashes_to_four_on_a_fixture_config_error():
    deps = _drawn(FILESYSTEM, checks=deps_with(raises=True))

    assert run_detection_holdout.main(["calibration-check"], deps) == (
        run_detection_holdout.CRASHED_EXIT
    )


def test_the_calibration_check_removes_the_containers_of_its_images_left_running():
    containers = FakeContainerSweep(["leftover_filesystem"])
    deps = _drawn(FILESYSTEM, checks=deps_with(), sweep=containers)

    run_detection_holdout.main(["calibration-check"], deps)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_drawn_target_tags()]


def test_a_calibration_check_that_raises_still_removes_the_containers_left_running():
    containers = FakeContainerSweep(["leftover_filesystem"])
    deps = _drawn(FILESYSTEM, checks=deps_with(raises=True), sweep=containers)

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == run_detection_holdout.CRASHED_EXIT
    assert containers.removed == ["leftover_filesystem"]


def test_the_calibration_check_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    capsys: pytest.CaptureFixture[str],
):
    deps = _drawn(FILESYSTEM, checks=deps_with(failures=["the admission was reached"]))
    deps = replace(deps, docker=replace(deps.docker, check_networks=_cannot_close_a_network))

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    assert "Docker Engine 28.0 or later is required" in capsys.readouterr().out


def test_the_calibration_check_takes_one_flaw():
    checked: list[str] = []
    deps = _drawn(FILESYSTEM, GIT, checks=deps_with(checked=checked))

    exit_code = run_detection_holdout.main(["calibration-check", "--flaw", FILESYSTEM], deps)

    assert exit_code == 0
    assert checked == [FILESYSTEM]


def test_the_calibration_check_on_a_flaw_not_drawn_exits_zero_and_says_so(
    capsys: pytest.CaptureFixture[str],
):
    deps = _drawn(FILESYSTEM, checks=deps_with(raises=True))

    exit_code = run_detection_holdout.main(["calibration-check", "--flaw", "CVE-2099-9999"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_the_calibration_check_refuses_with_exit_three_on_a_stale_or_absent_image(
    capsys: pytest.CaptureFixture[str],
):
    stale, absent = target_services([an_acceptance_target(FILESYSTEM)])[:2]
    labels = _current_labels(FILESYSTEM) | {image_tag(stale): "an-older-fingerprint"}
    del labels[image_tag(absent)]
    store = FakeImageStore(labels)
    deps = _drawn(FILESYSTEM, checks=deps_with(raises=True))
    deps = replace(deps, docker=replace(deps.docker, images=store))

    exit_code = run_detection_holdout.main(["calibration-check"], deps)

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    out = capsys.readouterr().out
    assert f"image of {stale} is stale or absent" in out
    assert f"image of {absent} is stale or absent" in out
    assert "docker compose -f evals/docker/compose.yml build" in out
    assert store.builds == []


def _drawn(
    *flaw_ids: str, checks: CalibrationCheckDeps, sweep: FakeContainerSweep | None = None
) -> HoldoutCommandDeps:
    """Drawn, with a closed network and current images for each, and these calibration checks."""
    targets = tuple(an_acceptance_target(flaw_id, tools_filter=None) for flaw_id in flaw_ids)
    docker = RunDocker(
        lambda: None,
        FakeImageStore(_current_labels(*flaw_ids)),
        (sweep or FakeContainerSweep()).sweep,
    )
    return replace(
        command_deps.a_command_reaching_nothing(),
        drawn=targets,
        docker=docker,
        calibration_check=lambda _concurrency, _ci: checks,
    )


def _current_labels(*flaw_ids: str) -> dict[str, str | None]:
    services = target_services([an_acceptance_target(flaw_id) for flaw_id in flaw_ids])
    return {image_tag(service): dockerfile_fingerprint(service) for service in services}


def _drawn_target_tags() -> list[str]:
    return [image_tag(service) for service in target_services([an_acceptance_target(FILESYSTEM)])]


def _cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


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


def test_calibration_dossier_writes_an_isolated_kit(tmp_path: Path):
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
    for relative in (
        f"advisories/{censuses.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        "evals/cve/grammar.py",
        "evals/detection_places.json",
        "evals/cve/kit/driver.py",
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


_COMMITTED_CAPTURES = sorted((REPO_ROOT / "evals" / "stand_ins").glob("*.json"))


def _acceptance_services() -> set[str]:
    services = {
        name for target in ACCEPTANCE_TARGETS for name in (*target.images, target.patched_image)
    }
    return services | {SENTINEL_SERVICE}


def test_the_kit_tags_its_images_outside_the_acceptance_namespace():
    assert kit_launch.image_tag("x") == "mcp-auditor-kit-x:local"
