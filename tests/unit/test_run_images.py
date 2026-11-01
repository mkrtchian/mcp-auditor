"""The image rebuild, the compose services and the container sweep both run orchestrators share."""

import subprocess
from collections.abc import Sequence

import pytest

import tests.unit.support.test_holdout_run_given as targets
import tests.unit.support.test_run_images_given as given
from evals.cve_images import COMPOSE_BUILD_BATCH_SIZE
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


def test_a_large_rebuild_builds_every_service_in_bounded_batches(
    monkeypatch: pytest.MonkeyPatch,
):
    builds = given.builds_recorded(monkeypatch)
    services = [f"server-{index}" for index in range(3 * COMPOSE_BUILD_BATCH_SIZE + 1)]

    rebuild_images(services)

    assert sorted(service for build in builds for service in build) == sorted(services)
    assert all(len(build) <= COMPOSE_BUILD_BATCH_SIZE for build in builds)


def test_a_failing_batch_raises_with_its_services_and_builds_no_later_batch(
    monkeypatch: pytest.MonkeyPatch,
):
    services = [f"server-{index}" for index in range(3 * COMPOSE_BUILD_BATCH_SIZE)]
    builds = given.builds_recorded(monkeypatch, failing="server-0")

    with pytest.raises(RuntimeError) as raised:
        rebuild_images(services)

    assert builds == [services[:COMPOSE_BUILD_BATCH_SIZE]]
    assert ", ".join(services[:COMPOSE_BUILD_BATCH_SIZE]) in str(raised.value)
    assert "server-0 deadline" in str(raised.value)


def test_a_service_named_twice_is_built_once(monkeypatch: pytest.MonkeyPatch):
    builds = given.builds_recorded(monkeypatch)

    rebuild_images(["app", "app-patched", "app"])

    assert [service for build in builds for service in build] == ["app", "app-patched"]


def test_no_service_builds_nothing(monkeypatch: pytest.MonkeyPatch):
    builds = given.builds_recorded(monkeypatch)

    rebuild_images([])

    assert builds == []


def test_a_sweep_whose_listing_fails_warns_and_removes_nothing(
    capsys: pytest.CaptureFixture[str],
):
    removed: list[str] = []

    def failing_listing(tags: Sequence[str]) -> list[str]:
        raise subprocess.CalledProcessError(1, ["docker", "ps"])

    sweep_containers(["app"], failing_listing, removed.extend)

    assert removed == []
    assert "could not list" in capsys.readouterr().out
