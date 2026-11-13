import pytest

import tests.unit.support.test_node_sandbox_engine_given as given
import tests.unit.support.test_node_sandbox_engine_then as then
from evals.cve.backends.node_sandbox_engine import LIFECYCLE, engine_run_args


def test_the_server_mounts_the_backends_socket_at_the_docker_socket_and_has_no_network(
    monkeypatch: pytest.MonkeyPatch,
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server_args:
        then.the_server_mounts_the_socket_of_the_engine(server_args, engine)
        then.the_server_has_no_network_and_no_docker_host(server_args)
        then.the_server_runs_its_image_as_the_hosts_user(server_args, "image", ["serve"])


def test_the_backend_carries_the_confinement_and_the_memory_bound_as_root_with_no_network(
    monkeypatch: pytest.MonkeyPatch,
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_engine_is_confined_and_bounded_as_root_with_no_network(engine.started[0])


def test_the_backend_drops_every_capability_and_bounds_its_processes():
    then.carries_the_hardening_with_no_capability(engine_run_args("engine", given.a_directory()))


def test_two_launches_get_two_sockets(monkeypatch: pytest.MonkeyPatch):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch)

    with (
        LIFECYCLE.launch("first", "image", given.a_host(), []) as first,
        LIFECYCLE.launch("second", "image", given.a_host(), []) as second,
    ):
        then.the_two_servers_mount_two_sockets(first, second)

    assert len(engine.started) == 2


def test_the_server_its_backend_and_the_socket_directory_are_removed_on_exit(
    monkeypatch: pytest.MonkeyPatch,
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), []):
        pass

    then.the_server_and_the_engine_were_removed(engine, "server")
    then.no_socket_directory_is_left(engine)


def test_the_backend_is_removed_when_the_body_raises(monkeypatch: pytest.MonkeyPatch):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch)

    with (
        pytest.raises(RuntimeError),
        LIFECYCLE.launch("server", "image", given.a_host(), []),
    ):
        raise RuntimeError("the probe failed")

    then.the_server_and_the_engine_were_removed(engine, "server")
    then.no_socket_directory_is_left(engine)
