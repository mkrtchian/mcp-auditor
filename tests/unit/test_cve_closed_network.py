import copy

import pytest

import tests.unit.support.test_cve_closed_network_given as given
import tests.unit.support.test_cve_closed_network_then as then
from evals.cve.closed_network import (
    DOCKER_NETWORKS,
    ClosedNetworkUnsupported,
    ForeignNetwork,
    NetworkFacts,
    check_closed_network_support,
    create_closed_network,
    ensure_closed_network,
    network_facts,
)
from tests.fakes.network_docker import FakeNetworkDocker
from tests.unit.support.recorded_subprocess import recorded_commands


def test_an_absent_network_is_created_closed():
    docker = FakeNetworkDocker()

    ensure_closed_network(given.NAME, docker=docker)

    then.closed_with(docker, given.NAME, [])


def test_a_closed_network_is_kept_with_its_containers():
    docker = given.a_closed_network_with("mcp-auditor-cve-backend")

    ensure_closed_network(given.NAME, docker=docker)

    then.closed_with(docker, given.NAME, ["mcp-auditor-cve-backend"])


def test_an_open_labelled_network_ends_closed_under_its_name_without_its_containers():
    docker = given.an_open_labelled_network_with("mcp-auditor-cve-backend")

    ensure_closed_network(given.NAME, docker=docker)

    then.closed_with(docker, given.NAME, [])


def test_an_unlabelled_network_of_the_name_refuses_and_is_left_as_it_was():
    docker = given.an_unlabelled_network_with("someone-elses-container")
    before = copy.deepcopy(docker.networks)

    with pytest.raises(ForeignNetwork, match=given.NAME):
        ensure_closed_network(given.NAME, docker=docker)

    assert docker.networks == before


def test_a_daemon_rejecting_the_isolated_mode_names_the_engine_version_and_its_message():
    docker = FakeNetworkDocker(rejects_isolated=given.OLD_DAEMON_MESSAGE)

    with pytest.raises(ClosedNetworkUnsupported) as raised:
        create_closed_network(given.NAME, docker=docker)

    assert "Docker Engine 28.0" in str(raised.value)
    assert given.OLD_DAEMON_MESSAGE in str(raised.value)
    assert docker.networks == {}


def test_a_daemon_leaving_the_network_open_raises_and_leaves_no_network():
    docker = FakeNetworkDocker(ignores_isolated=True)

    with pytest.raises(ClosedNetworkUnsupported, match=r"Docker Engine 28\.0"):
        create_closed_network(given.NAME, docker=docker)

    assert docker.networks == {}


def test_a_network_created_with_ipv6_enabled_raises():
    docker = FakeNetworkDocker(enables_ipv6=True)

    with pytest.raises(ClosedNetworkUnsupported):
        create_closed_network(given.NAME, docker=docker)

    assert docker.networks == {}


def test_the_support_check_leaves_no_network_behind_on_success():
    docker = FakeNetworkDocker()

    check_closed_network_support(docker)

    assert docker.networks == {}


@pytest.mark.parametrize(
    "docker",
    [
        FakeNetworkDocker(rejects_isolated=given.OLD_DAEMON_MESSAGE),
        FakeNetworkDocker(ignores_isolated=True),
    ],
    ids=["rejected", "ignored"],
)
def test_the_support_check_leaves_no_network_behind_on_failure(docker: FakeNetworkDocker):
    with pytest.raises(ClosedNetworkUnsupported):
        check_closed_network_support(docker)

    assert docker.networks == {}


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [
        (given.CLOSED_INSPECT, NetworkFacts(True, True, "isolated", False, ())),
        (given.OPEN_INSPECT, NetworkFacts(True, False, None, False, ("mcp-auditor-cve-rec-box",))),
    ],
    ids=["closed", "open"],
)
def test_a_recorded_inspect_output_is_read_into_its_facts(recorded: str, expected: NetworkFacts):
    assert network_facts(recorded) == expected


def test_the_containers_of_an_open_network_go_with_their_anonymous_volumes(
    monkeypatch: pytest.MonkeyPatch,
):
    commands = recorded_commands(monkeypatch)

    DOCKER_NETWORKS.remove_containers(["mcp-auditor-cve-backend"])

    assert commands == [["docker", "rm", "-f", "-v", "mcp-auditor-cve-backend"]]
