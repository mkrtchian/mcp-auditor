"""The image rebuild, the compose services and the container sweep both run orchestrators share."""

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from evals.cve.run_images import (
    remove_containers,
    sweep_containers,
    target_services,
)
from tests.fakes import ScriptedDockerExecutable
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target


def test_target_services_dedups_images_and_patched_images():
    first = an_acceptance_target(FILESYSTEM, images=("app",), patched_image="app-patched")
    second = an_acceptance_target(
        FILESYSTEM, images=("app", "sentinel"), patched_image="other-patched"
    )

    services = target_services([first, second])

    assert services == ["app", "app-patched", "sentinel", "other-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []


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
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = ScriptedDockerExecutable({}).installed(monkeypatch, tmp_path)

    remove_containers(["a", "b"])

    assert docker.commands == [["docker", "rm", "-f", "-v", "a", "b"]]
