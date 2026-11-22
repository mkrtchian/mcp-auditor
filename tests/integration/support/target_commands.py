import subprocess
from dataclasses import dataclass

from evals.cve.planting import PlantedArgs, confinement_args
from evals.cve.planting_base import LABEL

# wget's own 5 s bound plus the start-up of the fresh container each read runs in.
READ_TIMEOUT = 10.0


@dataclass(frozen=True)
class TargetCommand:
    image: str
    entrypoint: str
    command: tuple[str, ...]


def run_as_target(
    args: PlantedArgs, command: TargetCommand, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            *confinement_args(),
            *args.run_args(),
            "--entrypoint",
            command.entrypoint,
            command.image,
            *command.command,
        ],
        capture_output=True,
        text=True,
        timeout=READ_TIMEOUT,
        check=check,
    )
