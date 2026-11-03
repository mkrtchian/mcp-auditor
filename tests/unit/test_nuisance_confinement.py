import os

import pytest

from evals.cve_planting_base import (
    PlantingHost,
    SymbolicUser,
    confinement_args,
    no_network_args,
)
from evals.nuisance_confinement import (
    LAUNCH_LABEL,
    labelled_run_args,
    launch_digest,
    launch_matches,
    nuisance_confinement_args,
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
    assert LAUNCH_LABEL == "mcp-auditor-cve-launch"


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


def test_the_single_container_run_is_confined_bounded_and_without_network():
    args = single_container_run_args("image:local", HOST, LAUNCH)

    assert _holds(args, nuisance_confinement_args())
    assert _holds(args, no_network_args())
    assert _holds(args, user_args(HOST.user))
    assert _holds(args, ["-w", "/srv"])


def _holds(args: list[str], segment: list[str]) -> bool:
    return any(args[i : i + len(segment)] == segment for i in range(len(args)))
