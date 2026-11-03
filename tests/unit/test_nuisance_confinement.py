import os

import pytest

from evals.cve_planting_base import PlantingHost, SymbolicUser, confinement_args
from evals.nuisance_confinement import (
    MEMORY_BOUND,
    MEMORY_BOUND_BYTES,
    carries_memory_bound,
    nuisance_confinement_args,
    single_container_run_args,
    user_args,
)

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)
LAUNCH = ["node", "dist/index.js"]


def test_the_nuisance_confinement_is_the_acceptance_one_then_the_memory_bound():
    assert nuisance_confinement_args() == [
        *confinement_args(),
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
    ]


def test_the_bound_in_bytes_is_the_binary_value_of_the_bound():
    assert MEMORY_BOUND == "4g"
    assert MEMORY_BOUND_BYTES == 4_294_967_296


@pytest.mark.parametrize(
    ("inspected", "carries"), [("4294967296", True), ("0", False), ("2147483648", False)]
)
def test_a_container_carries_the_bound_only_at_its_byte_value(inspected: str, carries: bool):
    assert carries_memory_bound(inspected) is carries


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
    assert _holds(args, ["--network", "none"])
    assert _holds(args, user_args(HOST.user))
    assert _holds(args, ["-w", "/srv"])


def _holds(args: list[str], segment: list[str]) -> bool:
    return any(args[i : i + len(segment)] == segment for i in range(len(args)))
