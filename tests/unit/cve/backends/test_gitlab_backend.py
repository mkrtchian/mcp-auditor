from pathlib import Path

import pytest

import tests.unit.cve.backends.support.test_gitlab_backend_given as given
import tests.unit.cve.backends.support.test_gitlab_backend_then as then
from evals.cve.backends.gitlab import GITLAB_HOST, LIFECYCLE
from tests.unit.support.docker_argv import carries, value_after


def test_the_backend_carries_its_hardening_and_the_gitlab_example_com_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_backend_is_hardened_and_named_gitlab_example_com(docker.started()[0])


def test_the_server_joins_the_closed_network_of_its_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        then.the_server_joins_the_closed_network_created_for_its_backend(docker, server)


def test_the_token_the_stand_up_created_reaches_the_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        then.the_server_takes_the_token_the_seed_created(docker, server)


def test_two_launches_stand_two_backends(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch, tmp_path)

    with (
        LIFECYCLE.launch("first", "image", given.a_host(), []) as first,
        LIFECYCLE.launch("second", "image", given.a_host(), []) as second,
    ):
        assert value_after(first, "--network") != value_after(second, "--network")

    assert len(docker.started()) == 2


def test_the_server_its_backend_and_its_network_are_removed_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_gitlab_comes_up(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError), LIFECYCLE.launch("server", "image", given.a_host(), []):
        raise RuntimeError("the probe failed")

    then.the_server_its_backend_and_its_network_were_removed(docker, "server")


def test_a_failed_reconfigure_is_refused_and_its_backend_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_gitlab_fails_to_reconfigure(monkeypatch, tmp_path)

    with (
        pytest.raises(RuntimeError, match="reconfigure"),
        LIFECYCLE.launch("server", "image", given.a_host(), []),
    ):
        pass

    assert value_after(docker.started()[0], "--name") in docker.removed()


# The fix check's responder answers where the run image sends the server, which its `-e` overrides.
def test_the_gitlab_responder_answers_at_the_host_its_run_image_bakes():
    responder = given.the_gitlab_responder()

    assert carries(responder.singleton_run_args(), ["--network-alias", GITLAB_HOST])
