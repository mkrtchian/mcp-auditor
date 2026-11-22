import pytest

import tests.unit.support.fictional_planting as planting
from evals.cve.planting import planted
from evals.cve.planting_base import (
    MEMORY_BOUND,
    confinement_args,
    memory_bound_args,
    no_network_args,
    own_network_args,
    resolver_args,
)
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries, count, value_after


def test_the_user_working_directory_and_network_args_follow_an_unprivileged_host():
    spec = planting.spec_of([], host=planting.unprivileged_host(working_directory="/srv/fictional"))

    with planted(spec, "image:tag", FakePlantingDocker()) as args:
        assert args.user == ("--user", "65534:65534", "-e", "HOME=/tmp")
        assert args.working_directory == ("-w", "/srv/fictional")
        assert args.network == tuple(no_network_args())


# --- the resolver option ---------------------------------------------------------------


def test_the_resolver_option_sets_no_search_domain_and_stays_out_of_the_confinement_joiners_take():
    assert resolver_args() == ["--dns-search", "."]
    assert "--dns-search" not in confinement_args()


@pytest.mark.parametrize("has_network", [False, True], ids=["no_network", "network"])
def test_only_the_holder_carries_the_resolver_option_on_a_launch_with_a_holder(has_network: bool):
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5")],
        host=planting.unprivileged_host(has_network=has_network),
    )
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        holder = docker.holders[planting.only(docker.holders)]
        joiners = [
            list(args.network),
            *docker.probes,
            *docker.sentinels.values(),
            *docker.stand_ins.values(),
            *docker.address_setups,
        ]
        assert docker.probes and docker.sentinels
        assert [count(joiner, resolver_args()) for joiner in joiners] == [0] * len(joiners)
        assert count(holder, resolver_args()) == 1


def test_the_target_its_probe_and_a_bridge_alias_sentinel_each_carry_the_resolver_option():
    spec = planting.spec_of(
        [planting.endpoint_place(host="fictional-service")],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        network = next(iter(docker.networks))
        assert args.network == tuple(own_network_args(network))
        own_stacks = [*docker.probes, *docker.sentinels.values()]
        assert docker.probes and docker.sentinels
        assert [count(argv, resolver_args()) for argv in own_stacks] == [1] * len(own_stacks)


def test_a_launch_with_no_network_and_no_holder_takes_the_no_network_args():
    spec = planting.spec_of([planting.file_place()])
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert docker.holders == {}
        assert args.network == tuple(no_network_args())


# --- the memory bound ----------------------------------------------------------------


def test_the_confinement_bounds_memory_with_no_swap():
    args = confinement_args()

    assert MEMORY_BOUND == "4g"
    assert (value_after(args, "--memory"), value_after(args, "--memory-swap")) == (
        MEMORY_BOUND,
        MEMORY_BOUND,
    )


def test_the_holder_and_a_sentinel_run_under_the_memory_bound():
    spec = planting.spec_of(
        [planting.endpoint_place(host="198.51.100.5")],
        host=planting.unprivileged_host(has_network=True),
    )
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        holder = docker.holders[planting.only(docker.holders)]
        sentinel = docker.sentinels[planting.only(docker.sentinels)]
        assert carries(holder, memory_bound_args())
        assert carries(sentinel, memory_bound_args())
