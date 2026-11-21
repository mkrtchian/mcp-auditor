from collections.abc import Callable

import pytest

from evals.cve.planting_base import confinement_args, resolver_args, unprivileged_user_args
from tests.unit.nuisance.fix_checks.support.test_fix_check_launches_given import (
    HAND_BUILT_LAUNCHES,
)
from tests.unit.support.docker_argv import carries, count, values_after

# The neo4j database runs unconfined, which test_neo4j_fix_check_builder.py pins.
_UNCONFINED = {"neo4j-database"}


@pytest.mark.parametrize(
    "builder", list(HAND_BUILT_LAUNCHES.values()), ids=list(HAND_BUILT_LAUNCHES)
)
def test_a_fix_check_container_with_its_own_network_carries_the_resolver_option_once(
    builder: Callable[[], list[str]],
):
    assert count(builder(), resolver_args()) == 1


@pytest.mark.parametrize("name", [name for name in HAND_BUILT_LAUNCHES if name not in _UNCONFINED])
def test_every_hand_built_fix_check_container_carries_the_confinement(name: str):
    args = HAND_BUILT_LAUNCHES[name]()
    granted = set(values_after(args, "--cap-add"))

    assert carries(args, confinement_args())
    assert granted <= {"NET_BIND_SERVICE"}
    if name.endswith(("-server", "-part")):
        assert not granted
    if name.endswith("-server"):
        assert carries(args, unprivileged_user_args())
