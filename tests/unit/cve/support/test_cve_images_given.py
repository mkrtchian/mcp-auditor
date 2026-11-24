import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

_FAILURE_OUTPUT_LINES = 40


@dataclass
class ScriptedComposeBuild:
    """A `run_batch` recording each batch it receives. The batch naming `failing` exits 1 with a
    long stdout whose last line is the failing step's output, and a long stderr whose last line
    names that service."""

    failing: str | None = None
    batches: list[list[str]] = field(default_factory=list[list[str]])

    def __call__(self, batch: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.batches.append(list(batch))
        command = ["docker", "compose", "build", *batch]
        if self.failing not in batch:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(
            command,
            1,
            _long_output("stdout", self.failing_step_line()),
            _long_output("stderr", self.failure_line()),
        )

    def failing_step_line(self) -> str:
        return f"{self.failing} npm error code E404"

    def failure_line(self) -> str:
        return f"{self.failing} context deadline exceeded"


def _long_output(stream: str, last_line: str) -> str:
    lines = [f"{stream} {index}" for index in range(_FAILURE_OUTPUT_LINES)]
    return "\n".join([*lines, last_line])
