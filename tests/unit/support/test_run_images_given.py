import subprocess
import sys
from collections.abc import Sequence

import pytest

from evals import run_images


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
