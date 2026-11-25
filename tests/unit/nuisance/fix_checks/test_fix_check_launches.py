from collections.abc import Callable

import pytest

from evals.cve.planting_base import confinement_args, resolver_args, unprivileged_user_args
from tests.unit.nuisance.fix_checks.support.test_fix_check_launches_given import (
    CONFINED_LAUNCHES,
    HAND_BUILT_LAUNCHES,
    PART_LAUNCHES,
    SERVER_LAUNCHES,
)
from tests.unit.support.docker_argv import carries, count, values_after

_SERVERS_AND_PARTS = SERVER_LAUNCHES | PART_LAUNCHES


@pytest.mark.parametrize(
    "builder", list(HAND_BUILT_LAUNCHES.values()), ids=list(HAND_BUILT_LAUNCHES)
)
def test_a_fix_check_container_with_its_own_network_carries_the_resolver_option_once(
    builder: Callable[[], list[str]],
):
    assert count(builder(), resolver_args()) == 1


@pytest.mark.parametrize("builder", list(CONFINED_LAUNCHES.values()), ids=list(CONFINED_LAUNCHES))
def test_a_confined_container_carries_the_confinement_and_at_most_net_bind_service(
    builder: Callable[[], list[str]],
):
    args = builder()

    assert carries(args, confinement_args())
    assert set(values_after(args, "--cap-add")) <= {"NET_BIND_SERVICE"}


@pytest.mark.parametrize("builder", list(_SERVERS_AND_PARTS.values()), ids=list(_SERVERS_AND_PARTS))
def test_a_fix_check_server_or_backend_part_grants_no_capability(
    builder: Callable[[], list[str]],
):
    assert values_after(builder(), "--cap-add") == []


@pytest.mark.parametrize("builder", list(SERVER_LAUNCHES.values()), ids=list(SERVER_LAUNCHES))
def test_a_fix_check_server_runs_unprivileged(builder: Callable[[], list[str]]):
    assert carries(builder(), unprivileged_user_args())
