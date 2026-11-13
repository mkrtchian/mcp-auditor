from collections.abc import Sequence

from evals.cve.backends.node_sandbox_engine import ENGINE_IMAGE, ENGINE_SOCKET_DIRECTORY
from evals.cve.nuisance.confinement import memory_bound_args
from evals.cve.planting_base import unprivileged_user_args
from tests.unit.support.docker_argv import carries, count, environment, mount_of, value_after
from tests.unit.support.test_node_sandbox_engine_given import FakeEngineDocker

DOCKER_SOCKET = "/var/run/docker.sock"


def the_server_mounts_the_socket_of_the_engine(
    server_args: Sequence[str], engine: FakeEngineDocker
) -> None:
    source = mount_of(server_args, DOCKER_SOCKET).split(":")[0]
    assert source == str(engine.socket_directories[-1] / "docker.sock")


def the_server_has_no_network_and_no_docker_host(server_args: Sequence[str]) -> None:
    assert value_after(server_args, "--network") == "none"
    assert "DOCKER_HOST" not in environment(server_args)


def the_server_runs_its_image_as_the_hosts_user(
    server_args: Sequence[str], image: str, server_launch: list[str]
) -> None:
    assert carries(server_args, unprivileged_user_args())
    assert list(server_args[-1 - len(server_launch) :]) == [image, *server_launch]


def the_engine_is_confined_and_bounded_as_root_with_no_network(engine_args: Sequence[str]) -> None:
    carries_the_hardening_with_no_capability(engine_args)
    assert carries(engine_args, memory_bound_args())
    assert value_after(engine_args, "--network") == "none"
    assert "--user" not in engine_args
    assert engine_args[-1] == ENGINE_IMAGE
    assert mount_of(engine_args, ENGINE_SOCKET_DIRECTORY)


def carries_the_hardening_with_no_capability(engine_args: Sequence[str]) -> None:
    assert carries(engine_args, ["--cap-drop", "ALL"])
    assert carries(engine_args, ["--security-opt", "no-new-privileges"])
    assert int(value_after(engine_args, "--pids-limit")) > 0
    assert count(engine_args, ["--cap-add"]) == 0


def the_two_servers_mount_two_sockets(first: Sequence[str], second: Sequence[str]) -> None:
    assert mount_of(first, DOCKER_SOCKET) != mount_of(second, DOCKER_SOCKET)


def the_server_and_the_engine_were_removed(engine: FakeEngineDocker, server: str) -> None:
    engine_name = value_after(engine.started[0], "--name")
    removed = [command[-1] for command in engine.commands if command[1:3] == ["rm", "-f"]]
    assert server in removed
    assert engine_name in removed


def no_socket_directory_is_left(engine: FakeEngineDocker) -> None:
    assert engine.socket_directories
    assert not any(directory.exists() for directory in engine.socket_directories)
