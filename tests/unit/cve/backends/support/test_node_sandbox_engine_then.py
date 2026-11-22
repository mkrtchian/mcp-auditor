from collections.abc import Sequence
from pathlib import Path

from evals.cve.backends.node_sandbox_engine import ENGINE_IMAGE, ENGINE_SOCKET_DIRECTORY
from tests.fakes import ScriptedDockerExecutable
from tests.unit.support.docker_argv import environment, mount_of, value_after

DOCKER_SOCKET = "/var/run/docker.sock"


def the_server_mounts_the_socket_of_the_engine(
    server_args: Sequence[str], engine: ScriptedDockerExecutable
) -> None:
    source = mount_of(server_args, DOCKER_SOCKET).split(":")[0]
    assert source == str(_socket_directories(engine)[-1] / "docker.sock")


def _socket_directories(engine: ScriptedDockerExecutable) -> list[Path]:
    return [
        Path(mount_of(started, ENGINE_SOCKET_DIRECTORY).split(":")[0])
        for started in engine.started()
    ]


def the_server_has_no_docker_host(server_args: Sequence[str]) -> None:
    assert "DOCKER_HOST" not in environment(server_args)


def the_engine_runs_as_root_with_no_network(engine_args: Sequence[str]) -> None:
    assert value_after(engine_args, "--network") == "none"
    assert "--user" not in engine_args
    assert engine_args[-1] == ENGINE_IMAGE
    assert mount_of(engine_args, ENGINE_SOCKET_DIRECTORY)


def the_two_servers_mount_two_sockets(first: Sequence[str], second: Sequence[str]) -> None:
    assert mount_of(first, DOCKER_SOCKET) != mount_of(second, DOCKER_SOCKET)


def the_server_and_the_engine_were_removed(engine: ScriptedDockerExecutable, server: str) -> None:
    removed = engine.removed()
    assert server in removed
    assert value_after(engine.started()[0], "--name") in removed


def no_socket_directory_is_left(engine: ScriptedDockerExecutable) -> None:
    directories = _socket_directories(engine)
    assert directories
    assert not any(directory.exists() for directory in directories)
