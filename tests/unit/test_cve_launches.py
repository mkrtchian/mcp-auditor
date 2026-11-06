# The CVE fixtures build their own `docker run` argv from the planting arguments. This pins
# the invariant that `ServerLaunch.declared_container` accepts them, the per-host mount mode,
# and the layout's hand-over and removal, without Docker or the built images: every builder is
# given the fake port, and an empty spec on a no-network host plants nothing, so no builder
# here makes a Docker call. Each builder does call `build_layout`, which shells out to host
# `git` (init, clone, commit) under a temp root even on an empty spec (the tree is universal),
# a test-environment dependency that needs no Docker and plants no nonce.
import tempfile
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
from evals.cve_layout import NEUTRAL_TOKEN
from evals.cve_planting import PlantingFailed
from evals.cve_planting_base import LAYOUT_PREFIX, LayoutMount, check_layout_outer
from evals.holdout_environments import arcadedb_mcp_env, mysql_db_env, ssrf_redirect_env
from evals.holdout_kit import kit_launch
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of


def _root(launch: Launch) -> Path:
    return Path(mount_of(launch.args, "/srv").split(":")[0])


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


_LAYOUT_BUILDERS = {
    "filesystem": filesystem_env,
    "git_init_traversal": git_init_traversal_env,
    "command_injection": command_injection_env,
    "ssrf": ssrf_env,
    "arcadedb_mcp": arcadedb_mcp_env,
    "ssrf_redirect": ssrf_redirect_env,
    "mysql_db": mysql_db_env,
    "kit filesystem": kit_launch.filesystem_env,
    "kit git_init_traversal": kit_launch.git_init_traversal_env,
    "kit command_injection": kit_launch.command_injection_env,
    "kit ssrf": kit_launch.ssrf_env,
    "kit arcadedb": kit_launch.arcadedb_env,
}


@pytest.mark.parametrize("builder", _LAYOUT_BUILDERS.values(), ids=list(_LAYOUT_BUILDERS))
def test_every_builder_mounts_the_tree_read_only_under_a_default_host(builder: given.Builder):
    with builder("img", given.an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert mount_of(launch.args, "/srv").endswith(":/srv:ro")


@pytest.mark.parametrize("builder", _LAYOUT_BUILDERS.values(), ids=list(_LAYOUT_BUILDERS))
def test_every_builder_mounts_the_tree_read_write_under_a_read_write_host(builder: given.Builder):
    spec = given.an_empty_spec(LayoutMount.READ_WRITE)

    with builder("img", spec, docker=FakePlantingDocker()) as launch:
        assert mount_of(launch.args, "/srv").endswith(":/srv")


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


def test_the_removal_guard_refuses_any_directory_but_a_layout_outer_one(tmp_path: Path):
    with given.paths_the_removal_refuses(tmp_path) as refused:
        for path in refused:
            with pytest.raises(PlantingFailed):
                check_layout_outer(path)

    with tempfile.TemporaryDirectory(prefix=LAYOUT_PREFIX) as outer:
        check_layout_outer(outer)
