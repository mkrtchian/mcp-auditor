import subprocess
import sys
from collections.abc import Sequence

import pytest

from evals import cve_images, run_images


def a_build_exiting(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str = ""
) -> None:
    def run(command: Sequence[str], **options: object) -> subprocess.CompletedProcess[str]:
        if not options.get("capture_output"):
            print(stdout)
            print(stderr, file=sys.stderr)
            return subprocess.CompletedProcess(command, returncode)
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(run_images.subprocess, "run", run)


def builds_recorded(monkeypatch: pytest.MonkeyPatch, failing: str | None = None) -> list[list[str]]:
    """The services of each `docker compose build` call, the batch naming `failing` exiting 1."""
    builds: list[list[str]] = []

    def run(command: Sequence[str], **options: object) -> subprocess.CompletedProcess[str]:
        services = list(command[command.index("build") + 1 :])
        builds.append(services)
        returncode = 1 if failing in services else 0
        return subprocess.CompletedProcess(command, returncode, "", f"{failing} deadline")

    monkeypatch.setattr(cve_images.subprocess, "run", run)
    return builds
