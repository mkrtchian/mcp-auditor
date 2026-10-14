# The CVE fixtures build their own `docker run` argv from the planting arguments. This pins
# the invariant that `ServerLaunch.declared_container` accepts them, and the per-host mount
# mode, without Docker or the built images: an empty spec on a no-network host plants nothing,
# so no builder here makes a Docker call. Each builder does call `build_layout`, which shells
# out to host `git` (init, clone, commit) under a temp root even on an empty spec (the tree is
# universal), a test-environment dependency that needs no Docker and plants no nonce.
from pathlib import Path

from evals.cve_environments import (
    Launch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    ssrf_env,
)
from evals.cve_layout import NEUTRAL_TOKEN
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


def _mount(launch: Launch) -> str:
    return launch.args[launch.args.index("-v") + 1]


def _root(launch: Launch) -> Path:
    return Path(_mount(launch).split(":")[0])


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


def test_the_git_hosts_mount_the_tree_read_write():
    for builder in (git_init_traversal_env,):
        with builder("img", _empty_spec()) as launch:
            assert _mount(launch).endswith(":/srv")


def test_the_other_hosts_mount_the_tree_read_only():
    for builder in (filesystem_env, command_injection_env, ssrf_env):
        with builder("img", _empty_spec()) as launch:
            assert _mount(launch).endswith(":/srv:ro")


def test_an_empty_spec_still_materialises_the_universal_tree_with_neutral_content():
    with filesystem_env("img", _empty_spec()) as launch:
        root = _root(launch)
        assert (root / "app.git").is_dir()
        assert (root / "app" / ".git").is_dir()
        assert NEUTRAL_TOKEN in (root / ".env").read_text()
