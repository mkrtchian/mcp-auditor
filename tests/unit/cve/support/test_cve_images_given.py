import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

_FAILURE_OUTPUT_LINES = 40


@dataclass
class ScriptedComposeBuild:
    """A `run_batch` recording each batch it receives. The batch naming `failing` exits 1 with
    a long stderr whose last line names that service."""

    failing: str | None = None
    batches: list[list[str]] = field(default_factory=list[list[str]])

    def __call__(self, batch: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.batches.append(list(batch))
        command = ["docker", "compose", "build", *batch]
        if self.failing not in batch:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 1, "", self.failure_output())

    def failure_output(self) -> str:
        steps = [f"step {index}" for index in range(_FAILURE_OUTPUT_LINES)]
        return "\n".join([*steps, self.failure_line()])

    def failure_line(self) -> str:
        return f"{self.failing} context deadline exceeded"
