import dataclasses
import os
from pathlib import Path

import pytest

import tests.unit.support.test_cve_planting_stand_ins_given as stand_ins_given
from evals.cve_planting_base import (
    PlantingHost,
    PublicNames,
    SymbolicUser,
    confinement_args,
    no_network_args,
)
from evals.nuisance_confinement import (
    labelled_run_args,
    launch_digest,
    launch_matches,
    nuisance_confinement_args,
    single_container_launch_args,
    single_container_run_args,
    user_args,
)

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)
LAUNCH = ["node", "dist/index.js"]
BACKEND_RUN = ["run", "-d", "--name", "backend", "--memory", "4g", "backend:image"]


def test_the_nuisance_confinement_is_the_acceptance_one_then_the_memory_bound():
    assert nuisance_confinement_args() == [
        *confinement_args(),
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
    ]


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


def test_a_host_user_runs_as_the_invoking_user():
    assert user_args(SymbolicUser.HOST) == [
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "HOME=/tmp",
    ]


def test_an_unprivileged_user_runs_as_nobody():
    assert user_args(SymbolicUser.UNPRIVILEGED) == ["--user", "65534:65534", "-e", "HOME=/tmp"]


def test_the_single_container_run_ends_with_the_image_then_the_launch():
    args = single_container_run_args("image:local", HOST, LAUNCH)

    assert args[:3] == ["run", "-i", "--rm"]
    assert args[-3:] == ["image:local", *LAUNCH]


@pytest.mark.parametrize(
    "host",
    [HOST, PlantingHost(SymbolicUser.HOST, "/", has_network=False)],
    ids=["unprivileged", "host user"],
)
def test_the_single_container_run_is_confined_bounded_and_without_network(host: PlantingHost):
    args = single_container_run_args("image:local", host, LAUNCH)

    assert _holds(args, nuisance_confinement_args())
    assert _holds(args, no_network_args())
    assert _holds(args, user_args(host.user))
    assert _holds(args, ["-w", host.working_directory])


def test_the_single_container_run_has_no_network_even_on_a_networked_host():
    networked = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

    args = single_container_run_args("image:local", networked, LAUNCH)

    assert _holds(args, no_network_args())
    assert args.count("--network") == 1


def _holds(args: list[str], segment: list[str]) -> bool:
    return any(args[i : i + len(segment)] == segment for i in range(len(args)))


def test_a_launch_with_no_public_names_is_the_single_container_argv_and_starts_nothing(
    tmp_path: Path,
):
    docker = stand_ins_given.FakePlantingDocker()

    with single_container_launch_args(
        "image:local", HOST, LAUNCH, docker=docker, stand_ins_directory=tmp_path / "absent"
    ) as args:
        assert args == single_container_run_args("image:local", HOST, LAUNCH)
        assert (docker.holders, docker.stand_ins, docker.host_files) == ({}, {}, {})


def test_a_launch_with_a_public_name_joins_the_holder_serving_it_under_the_confinement(
    tmp_path: Path,
):
    directory = stand_ins_given.a_stand_ins_directory(tmp_path)
    docker = stand_ins_given.FakePlantingDocker()
    host = dataclasses.replace(HOST, public_names=PublicNames(stand_ins=(stand_ins_given.HOST,)))

    with single_container_launch_args(
        "image:local", host, LAUNCH, docker=docker, stand_ins_directory=directory
    ) as args:
        (holder,) = docker.holders
        assert len(docker.stand_ins) == 1
        assert args[:3] == ["run", "-i", "--rm"]
        assert args[3 : 3 + len(nuisance_confinement_args())] == nuisance_confinement_args()
        assert args[args.index("--network") + 1] == f"container:{holder}"
        assert args[-3:] == ["image:local", *LAUNCH]
    assert (docker.holders, docker.stand_ins) == ({}, {})


def test_a_trust_setting_points_its_variable_at_the_mounted_fixture_authority(tmp_path: Path):
    directory = stand_ins_given.a_stand_ins_directory(tmp_path)
    names = PublicNames(stand_ins=(stand_ins_given.HOST,), trust=("NODE_EXTRA_CA_CERTS",))
    host = dataclasses.replace(HOST, public_names=names)

    with single_container_launch_args(
        "image:local",
        host,
        LAUNCH,
        docker=stand_ins_given.FakePlantingDocker(),
        stand_ins_directory=directory,
    ) as args:
        assert any(arg.startswith("NODE_EXTRA_CA_CERTS=") for arg in args)
