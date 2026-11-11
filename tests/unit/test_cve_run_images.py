"""The image rebuild, the compose services and the container sweep both run orchestrators share."""

import subprocess
from collections.abc import Sequence

import pytest

import tests.unit.support.test_cve_run_images_given as given
import tests.unit.support.test_holdout_run_given as targets
from evals.cve.run_images import (
    rebuild_images,
    remove_containers,
    sweep_containers,
    target_services,
)
from tests.unit.support.recorded_subprocess import recorded_commands


def test_target_services_dedups_images_and_patched_images():
    first = targets.a_target(images=("app",), patched_image="app-patched")
    second = targets.a_target(images=("app", "sentinel"), patched_image="other-patched")

    services = target_services([first, second])

    assert services == ["app", "app-patched", "sentinel", "other-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []


def test_a_failed_image_build_raises_with_the_tail_of_its_output():
    stdout = "\n".join(f"step {index}" for index in range(50))
    build = given.a_build_exiting(1, stdout, "failed to solve: no such file")

    with pytest.raises(RuntimeError) as raised:
        rebuild_images(["app", "app-patched"], run_batch=build)

    message = str(raised.value)
    assert "app, app-patched" in message
    assert "step 49" in message
    assert "step 10" in message
    assert "step 9\n" not in message
    assert "failed to solve: no such file" in message


def test_a_successful_image_build_prints_nothing(capsys: pytest.CaptureFixture[str]):
    rebuild_images(["app"], run_batch=given.a_build_exiting(0, "built app"))

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


def test_a_sweep_removes_the_listed_containers_and_says_how_many(
    capsys: pytest.CaptureFixture[str],
):
    removed: list[str] = []

    sweep_containers(["app"], lambda _tags: ["a", "b"], removed.extend)

    assert removed == ["a", "b"]
    assert "removed 2 containers of the run's images left running" in capsys.readouterr().out


def test_the_sweep_removes_the_containers_with_their_anonymous_volumes(
    monkeypatch: pytest.MonkeyPatch,
):
    commands = recorded_commands(monkeypatch)

    remove_containers(["a", "b"])

    assert commands == [["docker", "rm", "-f", "-v", "a", "b"]]
