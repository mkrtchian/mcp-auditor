import subprocess
from collections.abc import Sequence

from evals.cve_images import RunBatch


def a_build_exiting(returncode: int, stdout: str, stderr: str = "") -> RunBatch:
    def run_batch(batch: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["docker", "compose", "build", *batch], returncode, stdout, stderr
        )

    return run_batch
