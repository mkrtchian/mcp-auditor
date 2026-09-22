# The CVE fixtures build their own `docker run` argv. This pins the invariant that
# `ServerLaunch.declared_container` accepts them, without Docker or the built images.
from evals.cve_environments import command_injection_env, filesystem_env
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime


def test_the_filesystem_fixture_launches_as_a_declared_container():
    with filesystem_env("sentinel") as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


def test_the_command_injection_fixture_launches_as_a_declared_container():
    with command_injection_env("img", "sentinel") as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )
