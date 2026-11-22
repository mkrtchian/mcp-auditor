# The detection fixtures build their own `docker run` argv from the planting arguments. This pins
# the invariant that `ServerLaunch.declared_container` accepts them, what every builder's launch
# carries (each built on fakes by `tests/unit/support/audited_launch_builders.py`, so none makes a
# Docker call), the per-host mount mode, and the layout's hand-over and removal, without Docker or
# the built images. Each builder does call `build_layout`, which shells out to host `git` (init,
# clone, commit) under a temp root even on an empty spec (the tree is universal), a
# test-environment dependency that needs no Docker and plants no nonce.
import tempfile
from pathlib import Path

import pytest

import tests.unit.cve.support.test_cve_launches_given as given
from evals.cve.detection.holdout_environments import (
    command_injection_checkout_env,
    filesystem_scope_env,
    houtini_lm_env,
)
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.environments import (
    Launch,
    LaunchShape,
    command_injection_env,
    filesystem_env,
    git_init_traversal_env,
    ssrf_env,
)
from evals.cve.layout import NEUTRAL_TOKEN
from evals.cve.planting import PlantingFailed
from evals.cve.planting_base import (
    LAYOUT_PREFIX,
    LayoutMount,
    check_layout_outer,
    confinement_args,
    memory_bound_args,
    unprivileged_user_args,
)
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.audited_launch_builders import (
    AUDITED_LAUNCH_BUILDERS,
    KIT_BUILDERS,
    Builder,
    SpecBuilder,
    an_empty_spec,
)
from tests.unit.support.docker_argv import carries, environment, mount_of, value_after


def test_the_filesystem_fixture_launches_as_a_declared_container():
    with filesystem_env("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


def test_the_command_injection_fixture_launches_as_a_declared_container():
    with command_injection_env("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert ServerLaunch.declared_container(launch.command, launch.args, {}).regime == (
            ExecutionRegime.DECLARED_CONTAINER
        )


_TABLE = AUDITED_LAUNCH_BUILDERS
_TARGET_BUILDERS = list(_TABLE)
_TARGET_IDS = [builder.__name__ for builder in _TABLE]
_ON_AN_EMPTY_SPEC: dict[str, SpecBuilder] = {
    **{builder.__name__: builder for builder, entry in _TABLE.items() if entry.takes_an_empty_spec},
    **KIT_BUILDERS,
}


def test_every_builder_a_target_names_is_in_the_table():
    assert {target.builder for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)} <= set(_TABLE)


@pytest.mark.parametrize("builder", _TARGET_BUILDERS, ids=_TARGET_IDS)
def test_every_target_builder_mounts_the_tree_read_only_under_a_default_host(
    builder: Builder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with _TABLE[builder].launched(tmp_path, monkeypatch) as built:
        assert mount_of(built.args, "/srv").endswith(":/srv:ro")


@pytest.mark.parametrize("builder", KIT_BUILDERS.values(), ids=list(KIT_BUILDERS))
def test_every_kit_builder_mounts_the_tree_read_only_under_a_default_host(builder: SpecBuilder):
    with builder("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert mount_of(launch.args, "/srv").endswith(":/srv:ro")


@pytest.mark.parametrize("builder", _ON_AN_EMPTY_SPEC.values(), ids=list(_ON_AN_EMPTY_SPEC))
def test_every_builder_mounts_the_tree_read_write_under_a_read_write_host(builder: SpecBuilder):
    spec = an_empty_spec(LayoutMount.READ_WRITE)

    with builder("img", spec, docker=FakePlantingDocker()) as launch:
        assert mount_of(launch.args, "/srv").endswith(":/srv")


@pytest.mark.parametrize("builder", _TARGET_BUILDERS, ids=_TARGET_IDS)
def test_every_target_builder_runs_its_server_confined_under_the_memory_bound(
    builder: Builder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with _TABLE[builder].launched(tmp_path, monkeypatch) as built:
        assert carries(built.args, confinement_args())
        assert carries(built.args, memory_bound_args())


@pytest.mark.parametrize("builder", _TARGET_BUILDERS, ids=_TARGET_IDS)
def test_every_target_builder_runs_its_server_unprivileged_from_its_hosts_working_directory(
    builder: Builder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with _TABLE[builder].launched(tmp_path, monkeypatch) as built:
        assert carries(built.args, unprivileged_user_args())
        assert value_after(built.args, "-w") == built.host.working_directory


def test_an_empty_spec_still_materialises_the_universal_tree_with_neutral_content():
    with filesystem_env("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        root = _root(launch)
        assert (root / "app.git").is_dir()
        assert (root / "app" / ".git").is_dir()
        assert NEUTRAL_TOKEN in (root / ".env").read_text()


def _root(launch: Launch) -> Path:
    return Path(mount_of(launch.args, "/srv").split(":")[0])


def test_the_tree_is_handed_over_once_complete_its_report_links_included():
    docker = FakePlantingDocker()

    with filesystem_env("img", given.a_spec_with_a_file_place(), docker=docker) as launch:
        assert list(docker.layouts) == [str(_root(launch))]
        assert {".env", "app.git/config", "app/archive0/report"} <= docker.layouts[
            str(_root(launch))
        ]


def test_the_scope_fixture_hands_over_a_tree_without_report_links():
    docker = FakePlantingDocker()

    with filesystem_scope_env("img", given.a_spec_with_a_file_place(), docker=docker) as launch:
        handed_over = docker.layouts[str(_root(launch))]
        assert ".env" in handed_over
        assert not any(path.startswith("app/archive") for path in handed_over)


def test_the_scope_fixture_launches_with_the_checkout_as_scope():
    with filesystem_scope_env("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        assert launch.scope == "/srv/app"
        assert launch.args[-1] == "/srv/app"


@pytest.mark.parametrize("shape", list(LaunchShape))
def test_the_checkout_fixture_hands_over_an_empty_captures_directory_in_the_checkout(
    shape: LaunchShape,
):
    docker = FakePlantingDocker()
    spec = an_empty_spec()

    with command_injection_checkout_env("img", spec, shape, docker=docker) as launch:
        handed_over = docker.layouts[str(_root(launch))]
        assert "app/captures" in handed_over
        assert not any(path.startswith("app/captures/") for path in handed_over)


def test_the_houtini_fixture_puts_its_two_environment_variables_before_the_image():
    with houtini_lm_env("img", an_empty_spec(), docker=FakePlantingDocker()) as launch:
        image = launch.args.index("img")
        assert environment(launch.args[:image]).items() >= {
            ("HOUTINI_LM_FILE_ROOTS", "/srv/app"),
            ("HOUTINI_LM_ENDPOINT_URL", "http://127.0.0.1:1234"),
        }


def test_no_handed_over_tree_remains_and_its_outer_directory_is_gone_after_the_launch():
    docker = FakePlantingDocker()

    with filesystem_env("img", an_empty_spec(), docker=docker) as launch:
        outer = _root(launch).parent

    assert docker.layouts == {}
    assert not outer.exists()


def test_no_handed_over_tree_remains_and_its_outer_directory_is_gone_when_the_body_raises():
    docker = FakePlantingDocker()
    outers: list[Path] = []

    with (
        pytest.raises(RuntimeError),
        git_init_traversal_env("img", an_empty_spec(), docker=docker) as launch,
    ):
        outers.append(_root(launch).parent)
        raise RuntimeError("the body fails")

    assert docker.layouts == {}
    assert not outers[0].exists()


def test_a_failing_hand_over_raises_planting_failed_and_leaves_no_outer_directory():
    docker = FakePlantingDocker(fail={"hand_over_layout": 0})

    with pytest.raises(PlantingFailed), ssrf_env("img", an_empty_spec(), docker=docker):
        pass

    assert not Path(docker.hand_overs[0]).parent.exists()


def test_the_removal_guard_refuses_any_directory_but_a_layout_outer_one(tmp_path: Path):
    with given.paths_the_removal_refuses(tmp_path) as refused:
        for path in refused:
            with pytest.raises(PlantingFailed):
                check_layout_outer(path)

    with tempfile.TemporaryDirectory(prefix=LAYOUT_PREFIX) as outer:
        check_layout_outer(outer)
