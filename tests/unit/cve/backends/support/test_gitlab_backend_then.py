from collections.abc import Sequence

from evals.cve.backends.gitlab import (
    GITLAB_HOST,
    GITLAB_IMAGE,
    GITLAB_NETWORK,
    GITLAB_PIDS_LIMIT,
    GITLAB_SHM_SIZE,
)
from tests.fakes import ScriptedDocker
from tests.unit.support.docker_argv import carries, environment, value_after, values_after

# Measured in the GitLab CE stand-up: what Omnibus needs to reconfigure and run under no new
# privileges, and a process bound some fifteen times its peak.
HARDENING = ["--security-opt", "no-new-privileges", "--cap-drop", "ALL"]
CAPABILITIES = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID"]


def the_backend_is_hardened_and_named_gitlab_example_com(backend: Sequence[str]) -> None:
    assert carries(backend, HARDENING)
    assert sorted(values_after(backend, "--cap-add")) == CAPABILITIES
    assert value_after(backend, "--pids-limit") == GITLAB_PIDS_LIMIT
    assert value_after(backend, "--hostname") == GITLAB_HOST
    assert value_after(backend, "--network-alias") == GITLAB_HOST
    assert value_after(backend, "--shm-size") == GITLAB_SHM_SIZE
    assert backend[-1] == GITLAB_IMAGE


def the_server_joins_the_closed_network_created_for_its_backend(
    docker: ScriptedDocker, server: Sequence[str]
) -> None:
    network = value_after(server, "--network")
    assert network.startswith(f"{GITLAB_NETWORK}-")
    assert docker.created_networks() == [network]
    assert value_after(docker.started()[0], "--network") == network


def the_server_takes_the_token_the_seed_created(
    docker: ScriptedDocker, server: Sequence[str]
) -> None:
    token = environment(server)["GITLAB_PERSONAL_ACCESS_TOKEN"]
    assert any(
        command[1:3] == ["exec", "-i"]
        and environment(command).get("SEED_TOKEN") == token
        and script is not None
        and "set_token" in script
        for command, script in zip(docker.commands, docker.inputs, strict=True)
    )


def the_two_servers_join_two_networks(first: Sequence[str], second: Sequence[str]) -> None:
    assert value_after(first, "--network") != value_after(second, "--network")


def the_server_its_backend_and_its_network_were_removed(
    docker: ScriptedDocker, server: str
) -> None:
    removed = docker.removed()
    assert server in removed
    assert value_after(docker.started()[0], "--name") in removed
    assert docker.created_networks()[0] in removed
