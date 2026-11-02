"""The `calibrate` subcommand driven through run_nuisance's main, with no Docker."""

import pytest

from evals import nuisance_calibrate_command, nuisance_fixtures, run_nuisance
from evals.ckan_backend import CKAN_RESPONDER_IMAGE
from evals.closed_network import ClosedNetworkUnsupported
from evals.holdout_kit import kit_launch
from evals.holdout_kit.fix_check import FixCheckResult, FixCheckTarget
from evals.nuisance_admission import ADMISSION_PATH, BackendFixture, NuisanceAdmission
from evals.nuisance_backends import BACKENDS
from evals.run_images import ContainerSweep
from tests.unit.support.test_holdout_run_given import RunningContainers
from tests.unit.support.test_nuisance_admission_given import an_admission, with_a_backend


@pytest.fixture(autouse=True)
def _no_docker_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    _leftovers(monkeypatch)


def _leftovers(monkeypatch: pytest.MonkeyPatch, *running: str) -> RunningContainers:
    containers = RunningContainers(list(running))
    sweep = ContainerSweep(containers.running, containers.remove)
    monkeypatch.setattr(nuisance_calibrate_command, "DOCKER_SWEEP", sweep)
    return containers


def test_calibrate_with_no_admission_prints_nothing_is_drawn(capsys: pytest.CaptureFixture[str]):
    if ADMISSION_PATH.exists():
        pytest.skip("an admission is committed")

    code = run_nuisance.main(["calibrate"])

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out


def test_calibrate_with_empty_targets_prints_nothing_is_drawn(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(nuisance_fixtures, "FIX_CHECK_TARGETS", ())

    code = run_nuisance.main(["calibrate"])

    assert code == 0
    assert "nothing is drawn" in capsys.readouterr().out


def test_calibrate_refuses_with_exit_three_on_a_daemon_that_cannot_close_a_network(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    if not ADMISSION_PATH.exists():
        pytest.skip("no admission is committed")
    monkeypatch.setattr(
        nuisance_calibrate_command, "check_closed_network_support", _cannot_close_a_network
    )
    monkeypatch.setattr(kit_launch, "build_images", _a_build_never_reached)

    code = run_nuisance.main(["calibrate"])

    assert code == run_nuisance.REFUSED_EXIT
    assert "Docker Engine 28.0 or later is required" in capsys.readouterr().out


def _cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")


def _a_build_never_reached(*_: object) -> None:
    raise AssertionError("the fix-check images were built")


@pytest.mark.parametrize("build_fails", [False, True])
def test_calibrate_removes_the_kit_and_built_backend_containers_left_running(
    monkeypatch: pytest.MonkeyPatch, build_fails: bool
):
    containers = _leftovers(monkeypatch, "leftover_kit", "leftover_responder")
    target = nuisance_fixtures.FIX_CHECK_TARGETS[0]
    _one_target_admitted_on_the_ckan_backend(monkeypatch, target)
    monkeypatch.setattr(kit_launch, "build_images", _a_failing_build if build_fails else _no_build)

    if build_fails:
        with pytest.raises(RuntimeError):
            run_nuisance.main(["calibrate"])
    else:
        run_nuisance.main(["calibrate"])

    assert containers.removed == ["leftover_kit", "leftover_responder"]
    kit_tags = [
        kit_launch.image_tag(target.vulnerable_service),
        kit_launch.image_tag(target.patched_service),
    ]
    assert containers.listed_tags == [[*kit_tags, CKAN_RESPONDER_IMAGE]]


def _one_target_admitted_on_the_ckan_backend(
    monkeypatch: pytest.MonkeyPatch, target: FixCheckTarget
) -> None:
    ckan = BACKENDS["ckan"]
    backend = BackendFixture(provisioner="ckan", image=ckan.image, network=ckan.network)
    server = with_a_backend(an_admission().servers[0], backend)
    admission = an_admission().model_copy(update={"servers": [server]})
    monkeypatch.setattr(nuisance_calibrate_command, "committed_nuisance_census", _no_census)

    def committed_admission(*_: object) -> NuisanceAdmission:
        return admission

    monkeypatch.setattr(nuisance_calibrate_command, "committed_admission", committed_admission)
    monkeypatch.setattr(nuisance_fixtures, "FIX_CHECK_TARGETS", (target,))
    monkeypatch.setattr(nuisance_calibrate_command, "check_closed_network_support", lambda: None)
    monkeypatch.setattr(nuisance_calibrate_command, "check_fix", _a_fix_check)


def _no_census(*_: object) -> None:
    return None


async def _a_fix_check(_target: FixCheckTarget) -> FixCheckResult:
    return FixCheckResult(
        source="fix_check",
        witness="MCPAUDIT-nonce",
        exploit_calls=[],
        vulnerable_surfaces=True,
        patched_surfaces=False,
        server_patched_surfaces=None,
        patched_benign_errored=False,
    )


def _no_build(*_: object) -> None:
    return None


def _a_failing_build(*_: object) -> None:
    raise RuntimeError("docker build failed")
