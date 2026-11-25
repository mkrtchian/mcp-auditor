from pathlib import Path

import pytest

import tests.unit.cve.backends.support.test_node_sandbox_engine_given as given
import tests.unit.cve.backends.support.test_node_sandbox_engine_then as then
from evals.cve.backends.node_sandbox_engine import LIFECYCLE
from tests.unit.support.docker_argv import environment, mount_of


def test_the_server_reaches_the_backend_through_its_socket_mounted_at_the_docker_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server_args:
        then.the_server_mounts_the_socket_of_the_engine(server_args, engine)
        assert "DOCKER_HOST" not in environment(server_args)


def test_the_socket_directory_is_open_to_every_account(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), []):
        then.the_socket_directory_is_open_to_every_account(engine)


def test_the_backend_runs_as_root_with_no_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_engine_runs_as_root_with_no_network(engine.started()[0])


def test_two_launches_get_two_sockets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with (
        LIFECYCLE.launch("first", "image", given.a_host(), []) as first,
        LIFECYCLE.launch("second", "image", given.a_host(), []) as second,
    ):
        assert mount_of(first, then.DOCKER_SOCKET) != mount_of(second, then.DOCKER_SOCKET)

    assert len(engine.started()) == 2


def test_the_server_its_backend_and_the_socket_directory_are_removed_on_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), []):
        pass

    then.the_server_and_the_engine_were_removed(engine, "server")
    then.no_socket_directory_is_left(engine)


def test_the_backend_is_removed_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    engine = given.a_docker_whose_engine_opens_its_socket(monkeypatch, tmp_path)

    with (
        pytest.raises(RuntimeError),
        LIFECYCLE.launch("server", "image", given.a_host(), []),
    ):
        raise RuntimeError("the probe failed")

    then.the_server_and_the_engine_were_removed(engine, "server")
    then.no_socket_directory_is_left(engine)
