# The CVE fixtures build their own `docker run` argv from the planting arguments. This pins
# the invariant that `ServerLaunch.declared_container` accepts them, without Docker or the
# built images: an empty spec on a no-network host plants nothing, so neither builder below
# makes a Docker call.
from evals.cve_environments import command_injection_env, filesystem_env
from evals.cve_planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime


def _empty_spec() -> PlantingSpec:
    return planting_spec((), PlantingHost(SymbolicUser.HOST, "/", has_network=False), RANDOM_NONCES)


def test_the_filesystem_fixture_launches_as_a_declared_container():
    with filesystem_env("img", _empty_spec()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


def test_the_command_injection_fixture_launches_as_a_declared_container():
    with command_injection_env("img", _empty_spec()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )
