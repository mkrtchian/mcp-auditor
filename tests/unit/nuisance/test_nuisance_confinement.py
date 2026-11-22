from pathlib import Path

import pytest

import tests.unit.nuisance.support.test_nuisance_confinement_given as given
import tests.unit.support.fictional_stand_ins as stand_ins
from evals.cve.nuisance.confinement import (
    labelled_run_args,
    launch_digest,
    launch_matches,
    single_container_run_args,
    user_args,
)
from evals.cve.planting_base import (
    PlantingHost,
    PublicNames,
    SymbolicUser,
    confinement_args,
    memory_bound_args,
    no_network_args,
)
from tests.unit.support.docker_argv import carries, environment, value_after

BACKEND_RUN = ["run", "-d", "--name", "backend", *memory_bound_args(), "backend:image"]


def test_equal_launches_have_the_same_digest():
    assert launch_digest(list(BACKEND_RUN)) == launch_digest(tuple(BACKEND_RUN))


def test_a_launch_differing_by_one_option_has_another_digest():
    other = [*BACKEND_RUN[:-1], "--dns-search", ".", BACKEND_RUN[-1]]

    assert launch_digest(other) != launch_digest(BACKEND_RUN)


def test_the_launch_label_goes_right_after_run_detached_and_the_rest_keeps_its_order():
    assert labelled_run_args(BACKEND_RUN) == [
        "run",
        "-d",
        "--label",
        f"mcp-auditor-cve-launch={launch_digest(BACKEND_RUN)}",
        *BACKEND_RUN[2:],
    ]


def test_only_a_detached_run_is_labelled():
    with pytest.raises(ValueError, match="run -d"):
        labelled_run_args(["run", "-i", "--rm", "image"])


def test_a_running_container_with_the_launch_digest_matches():
    assert launch_matches(f"true {launch_digest(BACKEND_RUN)}\n", BACKEND_RUN)


@pytest.mark.parametrize(
    "inspected",
    [
        f"false {launch_digest(BACKEND_RUN)}",
        "true",
        "true <no value>",
        f"true {launch_digest(['run', '-d', 'other:image'])}",
    ],
    ids=["stopped", "unlabelled", "no label map", "another launch"],
)
def test_a_container_not_running_this_launch_does_not_match(inspected: str):
    assert not launch_matches(inspected, BACKEND_RUN)


def test_an_unprivileged_user_runs_as_nobody():
    assert user_args(SymbolicUser.UNPRIVILEGED) == ["--user", "65534:65534", "-e", "HOME=/tmp"]


def test_the_single_container_run_ends_with_the_image_then_the_launch():
    args = single_container_run_args(given.IMAGE, given.HOST, given.LAUNCH)

    assert args[:3] == ["run", "-i", "--rm"]
    assert args[-3:] == [given.IMAGE, *given.LAUNCH]


def test_the_single_container_run_is_confined_bounded_and_without_network():
    args = single_container_run_args(given.IMAGE, given.HOST, given.LAUNCH)

    assert carries(args, confinement_args())
    assert carries(args, no_network_args())
    assert carries(args, user_args(given.HOST.user))
    assert carries(args, ["-w", given.HOST.working_directory])


def test_the_single_container_run_has_no_network_even_on_a_networked_host():
    networked = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

    args = single_container_run_args(given.IMAGE, networked, given.LAUNCH)

    assert carries(args, no_network_args())
    assert args.count("--network") == 1


def test_a_launch_with_no_public_names_is_the_single_container_argv_and_starts_nothing(
    tmp_path: Path,
):
    with given.a_launch_serving(tmp_path, PublicNames()) as launch:
        assert launch.args == single_container_run_args(given.IMAGE, given.HOST, given.LAUNCH)
        docker = launch.docker
        assert (docker.holders, docker.stand_ins, docker.host_files) == ({}, {}, {})


def test_a_launch_with_a_public_name_joins_the_holder_serving_it_under_the_confinement(
    tmp_path: Path,
):
    names = PublicNames(stand_ins=(stand_ins.HOST,))

    with given.a_launch_serving(tmp_path, names) as launch:
        (holder,) = launch.docker.holders
        assert len(launch.docker.stand_ins) == 1
        assert launch.args[:3] == ["run", "-i", "--rm"]
        assert launch.args[3 : 3 + len(confinement_args())] == confinement_args()
        assert value_after(launch.args, "--network") == f"container:{holder}"
        assert launch.args[-3:] == [given.IMAGE, *given.LAUNCH]
    assert (launch.docker.holders, launch.docker.stand_ins) == ({}, {})


def test_a_trust_setting_carries_its_variable(tmp_path: Path):
    names = PublicNames(stand_ins=(stand_ins.HOST,), trust=("NODE_EXTRA_CA_CERTS",))

    with given.a_launch_serving(tmp_path, names) as launch:
        assert "NODE_EXTRA_CA_CERTS" in environment(launch.args)


def test_a_launch_with_a_public_name_keeps_the_project_baked_into_its_work_directory(
    tmp_path: Path,
):
    names = PublicNames(stand_ins=(stand_ins.HOST,))

    with given.a_launch_serving(tmp_path, names, working_directory="/work") as launch:
        assert "--tmpfs" not in launch.args
        assert carries(launch.args, ["-w", "/work"])
