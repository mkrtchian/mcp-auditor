from evals.cve.closed_network import is_closed
from tests.fakes.network_docker import FakeNetworkDocker


def closed_with(docker: FakeNetworkDocker, name: str, containers: list[str]) -> None:
    facts = docker.inspect(name)
    assert facts is not None, f"{name} does not exist"
    assert facts.labelled
    assert is_closed(facts), facts
    assert list(facts.containers) == containers
