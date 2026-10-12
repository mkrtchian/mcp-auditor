from pathlib import Path

import pytest

from evals.cve_planting import SENTINEL_IMAGE
from evals.cve_preflight import (
    VULNERABLE_IMAGES,
    expected_images,
    preflight_ok,
    vulnerable_images,
)
from evals.cve_targets import CVE_TARGETS

FETCH_ID = "CVE-2025-65513"


def _a_docker_answering_only(directory: Path, tags: tuple[str, ...]) -> Path:
    """A `docker` shim first on PATH: `info` succeeds, `image inspect` succeeds for the given
    tags only. No probe is monkeypatched, so the preflight runs its real subprocess calls."""
    known = " ".join(tags)
    docker = directory / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "info" ]; then\n'
        '  [ "$2" = "--format" ] && echo 256\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then\n'
        f"  for tag in {known}; do\n"
        '    [ "$3" = "$tag" ] && exit 0\n'
        "  done\n"
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    )
    docker.chmod(0o755)
    return directory


def test_the_preflight_names_a_missing_patched_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _a_docker_answering_only(tmp_path, VULNERABLE_IMAGES)
    monkeypatch.setenv("PATH", str(tmp_path))

    ok = preflight_ok()

    assert not ok
    output = capsys.readouterr().out
    assert "patched" in output


def test_expected_images_keeps_the_sentinel_with_the_fetch_target_filtered_out():
    without_fetch = [target for target in CVE_TARGETS if target.cve_id != FETCH_ID]

    assert SENTINEL_IMAGE in expected_images(without_fetch)
    assert SENTINEL_IMAGE not in vulnerable_images(without_fetch)
