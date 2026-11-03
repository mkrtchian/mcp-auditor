import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from evals.cve_images import dockerfile_instructions
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, load_admission
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_walk_record import load_walk_record
from evals.run_census import CENSUS_PATH


def admitted_servers() -> list[AdmittedServer]:
    census = load_census(CENSUS_PATH)
    return list(load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, census)).servers)


def the_admitted_server(service: str) -> AdmittedServer:
    return next(server for server in admitted_servers() if server.service == service)


def the_benign_argument(service: str, name: str) -> Any:
    server = the_admitted_server(service)
    calls = [call for flaw in server.flaws for call in flaw.benign_calls]
    return next(call.arguments[name] for call in calls if name in call.arguments)


def dockerfile_env(name: str) -> dict[str, str]:
    return _env_values(DOCKER_DIRECTORY / f"Dockerfile.{name}")


def run_dockerfile_env(server: AdmittedServer) -> dict[str, str]:
    return _env_values(image_dockerfile(server.service, DOCKER_DIRECTORY))


def benign_argument_values(server: AdmittedServer) -> list[str]:
    calls = [
        call
        for flaw in server.flaws
        for benign in flaw.benign_calls
        for call in [*(benign.before or []), benign]
    ]
    return [value for call in calls for value in _strings(call.arguments)]


def _env_values(dockerfile: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for instruction in _joined_continuations(dockerfile_instructions(dockerfile)):
        keyword, _, rest = instruction.partition(" ")
        # case-sensitive: a heredoc body line such as `env = ...` is not an instruction
        if keyword != "ENV":
            continue
        words = shlex.split(rest)
        if "=" not in words[0]:
            values[words[0]] = " ".join(words[1:])
            continue
        values |= dict(word.split("=", 1) for word in words)
    return values


def _joined_continuations(instructions: list[str]) -> Iterator[str]:
    pending = ""
    for line in instructions:
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        yield pending + line
        pending = ""


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in cast(dict[str, Any], value).values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            yield from _strings(item)
    else:
        yield str(value)
