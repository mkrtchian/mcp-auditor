"""The container sweep both run orchestrators share."""

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from evals.cve.run_images import ContainerSweep, remove_containers, sweep_containers
from tests.fakes import ScriptedDockerExecutable


def test_a_sweep_whose_listing_fails_warns_and_removes_nothing(
    capsys: pytest.CaptureFixture[str],
):
    removed: list[str] = []

    def failing_listing(tags: Sequence[str]) -> list[str]:
        raise subprocess.CalledProcessError(1, ["docker", "ps"])

    sweep_containers(["app"], ContainerSweep(failing_listing, removed.extend))

    assert removed == []
    assert "could not list" in capsys.readouterr().out


def test_a_sweep_removes_the_listed_containers_and_says_how_many(
    capsys: pytest.CaptureFixture[str],
):
    removed: list[str] = []

    sweep_containers(["app"], ContainerSweep(lambda _tags: ["a", "b"], removed.extend))

    assert removed == ["a", "b"]
    assert "removed 2 containers of the run's images left running" in capsys.readouterr().out


def test_the_sweep_removes_the_containers_with_their_anonymous_volumes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = ScriptedDockerExecutable({}).installed(monkeypatch, tmp_path)

    remove_containers(["a", "b"])

    assert docker.commands == [["docker", "rm", "-f", "-v", "a", "b"]]
