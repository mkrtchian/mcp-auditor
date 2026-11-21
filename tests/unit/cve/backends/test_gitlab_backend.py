import pytest

import tests.unit.cve.backends.support.test_gitlab_backend_given as given
import tests.unit.cve.backends.support.test_gitlab_backend_then as then
from evals.cve.backends.gitlab import LIFECYCLE
from tests.unit.support.docker_argv import value_after


def test_the_backend_carries_the_memory_bound_the_hardening_and_the_gitlab_example_com_host(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_backend_is_bounded_hardened_and_named_gitlab_example_com(docker.started()[0])


def test_the_server_joins_the_closed_network_of_its_backend(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        then.the_server_joins_the_closed_network_created_for_its_backend(docker, server)


def test_the_token_the_stand_up_created_reaches_the_server(monkeypatch: pytest.MonkeyPatch):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        then.the_server_takes_the_token_the_seed_created(docker, server)


def test_two_launches_stand_two_backends(monkeypatch: pytest.MonkeyPatch):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch)

    with (
        LIFECYCLE.launch("first", "image", given.a_host(), []) as first,
        LIFECYCLE.launch("second", "image", given.a_host(), []) as second,
    ):
        then.the_two_servers_join_two_networks(first, second)

    assert len(docker.started()) == 2


def test_the_server_its_backend_and_its_network_are_removed_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch)

    with pytest.raises(RuntimeError), LIFECYCLE.launch("server", "image", given.a_host(), []):
        raise RuntimeError("the probe failed")

    then.the_server_its_backend_and_its_network_were_removed(docker, "server")


def test_a_failed_reconfigure_is_refused_and_its_backend_removed(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_gitlab_fails_to_reconfigure(monkeypatch)

    with (
        pytest.raises(RuntimeError, match="reconfigure"),
        LIFECYCLE.launch("server", "image", given.a_host(), []),
    ):
        pass

    assert value_after(docker.started()[0], "--name") in docker.removed()
