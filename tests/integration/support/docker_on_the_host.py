"""A `docker` executable that runs a declared container's command on the host."""

import pathlib

REMOVALS = "docker-rm-calls"

_DOCKER_ON_THE_HOST = """#!/bin/sh
if [ "$1" = rm ]; then
    shift
    echo "$*" >> "$(dirname "$0")/{removals}"
    exit 0
fi
shift
if [ "$1" = --name ]; then
    shift 2
fi
exec "$@"
"""


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run [--name NAME] <command...>` execs the command itself, so a declared container
    runs without Docker. `docker rm` removes nothing and appends its arguments, one call per
    line, to the file `REMOVALS` beside it, which `removals` reads."""
    docker = directory / "docker"
    docker.write_text(_DOCKER_ON_THE_HOST.format(removals=REMOVALS))
    docker.chmod(0o755)
    return directory


def removals(directory: pathlib.Path) -> list[str]:
    calls = directory / REMOVALS
    return calls.read_text().splitlines() if calls.exists() else []
