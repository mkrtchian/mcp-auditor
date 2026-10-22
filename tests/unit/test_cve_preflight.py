from pathlib import Path

import pytest

from evals.cve_images import dockerfile_fingerprint
from evals.cve_planting import SENTINEL_SERVICE
from evals.cve_preflight import expected_services, preflight_ok, vulnerable_services
from evals.cve_targets import CVE_TARGETS, image_tag
from tests.fakes.image_store import FakeImageStore

FETCH_ID = "CVE-2025-65513"


def _a_docker_answering_only_info(directory: Path) -> Path:
    """A `docker` shim first on PATH, answering `info` and `info --format`, so the daemon and
    pids-limit probes run their real subprocess calls without reaching the host's Docker."""
    docker = directory / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "info" ]; then\n'
        '  [ "$2" = "--format" ] && echo 256\n'
        "  exit 0\n"
        "fi\n"
        "exit 1\n"
    )
    docker.chmod(0o755)
    return directory


def _a_store_with_one_stale(stale: str, *, build_error: str | None = None) -> FakeImageStore:
    labels: dict[str, str | None] = {
        image_tag(service): dockerfile_fingerprint(service)
        for service in expected_services(CVE_TARGETS)
    }
    labels[image_tag(stale)] = "a-foreign-fingerprint"
    return FakeImageStore(labels, build_error=build_error)


def test_the_preflight_rebuilds_a_stale_image_and_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("PATH", str(_a_docker_answering_only_info(tmp_path)))
    stale = CVE_TARGETS[0].patched_image
    store = _a_store_with_one_stale(stale)

    ok = preflight_ok(store)

    assert ok
    assert store.label_of(image_tag(stale)) == dockerfile_fingerprint(stale)
    assert stale in capsys.readouterr().out


def test_the_preflight_fails_and_names_the_service_whose_rebuild_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("PATH", str(_a_docker_answering_only_info(tmp_path)))
    stale = CVE_TARGETS[0].patched_image
    store = _a_store_with_one_stale(stale, build_error="no space left on device")

    ok = preflight_ok(store)

    assert not ok
    assert stale in capsys.readouterr().out


def test_expected_services_keeps_the_sentinel_with_the_fetch_target_filtered_out():
    without_fetch = [target for target in CVE_TARGETS if target.cve_id != FETCH_ID]

    assert SENTINEL_SERVICE in expected_services(without_fetch)
    assert SENTINEL_SERVICE not in vulnerable_services(without_fetch)
