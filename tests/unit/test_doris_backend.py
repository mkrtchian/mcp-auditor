import pytest

import tests.unit.support.test_doris_serialization_given as given
from evals import holdout_environments
from evals.cve_planting_base import unprivileged_user_args
from evals.doris_backend import DORIS_SERVER_LAUNCH, doris_server_args
from evals.nuisance_confinement import memory_bound_args
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries, mount_of, value_after


def _strip_pair(args: list[str], flag: str) -> list[str]:
    i = args.index(flag)
    return args[:i] + args[i + 2 :]


def _without(args: list[str], segment: list[str]) -> list[str]:
    for i in range(len(args) - len(segment) + 1):
        if args[i : i + len(segment)] == segment:
            return args[:i] + args[i + len(segment) :]
    raise AssertionError(f"{segment} not found in {args}")


def test_the_holdout_launch_runs_unprivileged_from_its_checkout_on_the_read_only_layout(
    monkeypatch: pytest.MonkeyPatch,
):
    given.doris_helpers_faked(monkeypatch, given.an_overlap_recorder())
    spec = given.a_minimal_doris_spec()

    with holdout_environments.doris_db_env("image", spec, docker=FakePlantingDocker()) as launch:
        assert carries(launch.args, unprivileged_user_args())
        assert value_after(launch.args, "-w") == "/srv/app"
        assert mount_of(launch.args, "/srv").endswith(":/srv:ro")


# The nuisance launch mounts no layout (the nuisance suite has none) and takes the memory bound;
# past those two, the holdout launch must not drift from it.
def test_the_helper_and_the_holdout_env_differ_only_by_the_layout_and_the_memory_bound(
    monkeypatch: pytest.MonkeyPatch,
):
    given.doris_helpers_faked(monkeypatch, given.an_overlap_recorder())
    spec = given.a_minimal_doris_spec()

    with holdout_environments.doris_db_env("image", spec, docker=FakePlantingDocker()) as launch:
        env_args = _strip_pair(launch.args, "-v")
    helper = doris_server_args("server-name", "image", spec.host, DORIS_SERVER_LAUNCH)

    helper = _without(helper, memory_bound_args())

    assert _strip_pair(helper, "--name") == _strip_pair(env_args, "--name")
