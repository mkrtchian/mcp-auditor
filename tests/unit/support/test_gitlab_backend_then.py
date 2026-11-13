from collections.abc import Sequence

from evals.cve.backends.gitlab import GITLAB_HOST, GITLAB_IMAGE, GITLAB_NETWORK
from evals.cve.nuisance.confinement import memory_bound_args, nuisance_confinement_args
from evals.cve.planting_base import resolver_args, unprivileged_user_args
from tests.unit.support.docker_argv import carries, environment, value_after, values_after
from tests.unit.support.test_gitlab_backend_given import FakeGitLabDocker

# Measured in the GitLab CE stand-up: what Omnibus needs to reconfigure and run under no new
# privileges, and a process bound some fifteen times its peak.
HARDENING = ["--security-opt", "no-new-privileges", "--cap-drop", "ALL"]
CAPABILITIES = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID"]


def the_backend_is_bounded_hardened_and_named_gitlab_example_com(backend: Sequence[str]) -> None:
    assert carries(backend, memory_bound_args())
    assert carries(backend, HARDENING)
    assert sorted(values_after(backend, "--cap-add")) == CAPABILITIES
    assert value_after(backend, "--pids-limit") == "4096"
    assert value_after(backend, "--hostname") == GITLAB_HOST
    assert value_after(backend, "--network-alias") == GITLAB_HOST
    assert value_after(backend, "--shm-size") == "256m"
    assert carries(backend, resolver_args())
    assert backend[-1] == GITLAB_IMAGE


def the_server_joins_the_closed_network_created_for_its_backend(
    docker: FakeGitLabDocker, server: Sequence[str]
) -> None:
    network = value_after(server, "--network")
    assert network.startswith(f"{GITLAB_NETWORK}-")
    assert docker.created_networks() == [network]
    assert value_after(docker.started()[0], "--network") == network


def the_server_is_confined_as_the_hosts_user(
    server: Sequence[str], image: str, server_launch: list[str]
) -> None:
    assert carries(server, nuisance_confinement_args())
    assert carries(server, unprivileged_user_args())
    assert list(server[-1 - len(server_launch) :]) == [image, *server_launch]


def the_server_takes_the_token_the_seed_created(
    docker: FakeGitLabDocker, server: Sequence[str]
) -> None:
    token = environment(server)["GITLAB_PERSONAL_ACCESS_TOKEN"]
    seeds = docker.seed_commands()
    assert any(
        environment(command).get("SEED_TOKEN") == token
        and script is not None
        and "set_token" in script
        for command, script in seeds
    )
    assert len(token) == 20


def the_two_servers_join_two_networks(first: Sequence[str], second: Sequence[str]) -> None:
    assert value_after(first, "--network") != value_after(second, "--network")


def the_server_its_backend_and_its_network_were_removed(
    docker: FakeGitLabDocker, server: str
) -> None:
    removed = docker.removed()
    assert server in removed
    assert value_after(docker.started()[0], "--name") in removed
    assert docker.created_networks()[0] in removed
