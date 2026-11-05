# The CVE fixtures build their own `docker run` argv from the planting arguments. This pins
# the invariant that `ServerLaunch.declared_container` accepts them, the per-host mount mode,
# and the layout's hand-over and removal, without Docker or the built images: every builder is
# given the fake port, and an empty spec on a no-network host plants nothing, so no builder
# here makes a Docker call. Each builder does call `build_layout`, which shells out to host
# `git` (init, clone, commit) under a temp root even on an empty spec (the tree is universal),
# a test-environment dependency that needs no Docker and plants no nonce.
import itertools
from pathlib import Path

import pytest

import tests.unit.support.test_cve_launches_given as given
from evals.cve_environments import (
    Launch,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    ssrf_env,
)
from evals.cve_layout import NEUTRAL_TOKEN, owned_layout
from evals.cve_planting import PlantingFailed
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime
from tests.fakes.planting_docker import FakePlantingDocker


def _mount(launch: Launch) -> str:
    mounts = [value for flag, value in itertools.pairwise(launch.args) if flag == "-v"]
    return next(mount for mount in mounts if mount.split(":")[1] == "/srv")


def _root(launch: Launch) -> Path:
    return Path(_mount(launch).split(":")[0])


def test_the_filesystem_fixture_launches_as_a_declared_container():
    with filesystem_env("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


def test_the_command_injection_fixture_launches_as_a_declared_container():
    with command_injection_env("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


def test_the_git_hosts_mount_the_tree_read_write():
    for builder in (git_init_traversal_env,):
        with builder("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
            assert _mount(launch).endswith(":/srv")


def test_the_other_hosts_mount_the_tree_read_only():
    for builder in (filesystem_env, command_injection_env, ssrf_env):
        with builder("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
            assert _mount(launch).endswith(":/srv:ro")


def test_an_empty_spec_still_materialises_the_universal_tree_with_neutral_content():
    with filesystem_env("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
        root = _root(launch)
        assert (root / "app.git").is_dir()
        assert (root / "app" / ".git").is_dir()
        assert NEUTRAL_TOKEN in (root / ".env").read_text()


def test_the_tree_is_handed_over_once_complete_its_leak_links_included():
    docker = FakePlantingDocker()

    with filesystem_env("img", given.a_spec_with_a_file_place(), docker=docker) as launch:
        assert list(docker.layouts) == [str(_root(launch))]
        assert {".env", "app.git/config", "app/leak0/report"} <= docker.layouts[str(_root(launch))]


def test_no_handed_over_tree_remains_and_its_outer_directory_is_gone_after_the_launch():
    docker = FakePlantingDocker()

    with filesystem_env("img", given.an_empty_spec(), docker=docker) as launch:
        outer = _root(launch).parent

    assert docker.layouts == {}
    assert not outer.exists()


def test_no_handed_over_tree_remains_and_its_outer_directory_is_gone_when_the_body_raises():
    docker = FakePlantingDocker()
    outers: list[Path] = []

    with (
        pytest.raises(RuntimeError),
        git_init_traversal_env("img", given.an_empty_spec(), docker=docker) as launch,
    ):
        outers.append(_root(launch).parent)
        raise RuntimeError("the body fails")

    assert docker.layouts == {}
    assert not outers[0].exists()


def test_a_failing_hand_over_raises_planting_failed_and_leaves_no_outer_directory():
    docker = FakePlantingDocker(fail={"hand_over_layout": 0})

    with pytest.raises(PlantingFailed), ssrf_env("img", given.an_empty_spec(), docker=docker):
        pass

    assert not Path(docker.hand_overs[0]).parent.exists()


def test_the_removal_refuses_any_directory_but_the_outer_one_the_layout_made(tmp_path: Path):
    docker = FakePlantingDocker()

    with owned_layout(docker, lambda root: root.mkdir()) as root:
        with given.paths_the_removal_refuses(tmp_path, root) as refused:
            for path in refused:
                with pytest.raises(PlantingFailed):
                    docker.remove_layout(path)
                assert list(docker.layouts) == [str(root)], path

        docker.remove_layout(str(root.parent))
        assert docker.layouts == {}
