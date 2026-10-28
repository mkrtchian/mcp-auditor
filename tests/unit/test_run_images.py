"""The image rebuild, the compose services and the container sweep both run orchestrators share."""

import subprocess
from collections.abc import Sequence

import pytest

import tests.unit.support.test_holdout_run_given as targets
import tests.unit.support.test_run_images_given as given
from evals.run_images import rebuild_images, sweep_containers, target_services


def test_target_services_dedups_images_and_patched_twins():
    first = targets.a_target(images=("app",), patched_image="app-patched")
    second = targets.a_target(images=("app", "sentinel"), patched_image="other-patched")

    services = target_services([first, second])

    assert services == ["app", "app-patched", "sentinel", "other-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []


def test_a_failed_image_build_raises_with_the_tail_of_its_output(
    monkeypatch: pytest.MonkeyPatch,
):
    stdout = "\n".join(f"step {index}" for index in range(50))
    given.a_build_exiting(monkeypatch, 1, stdout, "failed to solve: no such file")

    with pytest.raises(RuntimeError) as raised:
        rebuild_images(["app", "app-patched"])

    message = str(raised.value)
    assert "app, app-patched" in message
    assert "step 49" in message
    assert "step 10" in message
    assert "step 9\n" not in message
    assert "failed to solve: no such file" in message


def test_a_successful_image_build_prints_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.a_build_exiting(monkeypatch, 0, "built app")

    rebuild_images(["app"])

    assert capsys.readouterr() == ("", "")


def test_a_sweep_whose_listing_fails_warns_and_removes_nothing(
    capsys: pytest.CaptureFixture[str],
):
    removed: list[str] = []

    def failing_listing(tags: Sequence[str]) -> list[str]:
        raise subprocess.CalledProcessError(1, ["docker", "ps"])

    sweep_containers(["app"], failing_listing, removed.extend)

    assert removed == []
    assert "could not list" in capsys.readouterr().out
