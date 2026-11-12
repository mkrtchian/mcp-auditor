import subprocess

import tests.integration.support.test_cve_closed_networks_given as given
from evals.cve.closed_network import DOCKER_NETWORKS, is_closed

# The musl resolver gives up after 5 to 10 s, glibc in milliseconds: a hang would pass this.
_UNPINNED_LOOKUP_BOUND = 15.0


def unreachable(container: str, listener_port: int) -> None:
    targets = [(address, listener_port) for address in given.host_ipv4_addresses()]
    targets += [("1.1.1.1", 443), ("169.254.169.254", 80)]
    reached = [target for target in targets if given.reaches(container, *target)]
    assert reached == [], f"reached from a closed network: {reached}"


def no_default_route(container: str) -> None:
    routes = given.routes(container)
    assert "default" not in routes, routes


def pinned_name_resolves_and_unpinned_fails_fast(container: str) -> None:
    assert given.reaches(container, given.PINNED_NAME, 80)
    reached, elapsed = given.timed_reach(container, given.UNPINNED_NAME, 80)
    assert not reached
    assert elapsed < _UNPINNED_LOOKUP_BOUND, f"the unpinned lookup took {elapsed:.1f} s"


def closed_without(network: str, container: str) -> None:
    facts = DOCKER_NETWORKS.inspect(network)
    assert facts is not None
    assert is_closed(facts), facts
    assert facts.containers == ()
    listed = subprocess.run(
        ["docker", "ps", "-a", "-q", "--filter", f"name=^{container}$"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert listed.stdout.strip() == "", f"{container} survived the recreation"
