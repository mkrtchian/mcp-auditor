"""`FakeNetworkDocker` holds networks in memory and reads the options it is created with as
Docker does: `--label`, `--internal` and the IPv4 gateway mode. It refuses, as Docker does, to
create over an existing name or to remove a network a container is attached to. Configured, it
plays an old daemon that rejects the `isolated` mode, one that accepts it and leaves the network
open, or one whose default network options enable IPv6.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from evals.cve.closed_network import NetworkCommandFailed, NetworkFacts
from evals.cve.planting_base import LABEL

_GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"


@dataclass
class FakeNetwork:
    labelled: bool
    internal: bool
    gateway_mode: str | None
    ipv6: bool = False
    containers: list[str] = field(default_factory=list[str])


@dataclass
class FakeNetworkDocker:
    networks: dict[str, FakeNetwork] = field(default_factory=dict[str, FakeNetwork])
    rejects_isolated: str | None = None  # the daemon's message
    ignores_isolated: bool = False
    enables_ipv6: bool = False

    def inspect(self, name: str) -> NetworkFacts | None:
        network = self.networks.get(name)
        if network is None:
            return None
        return NetworkFacts(
            labelled=network.labelled,
            internal=network.internal,
            gateway_mode=network.gateway_mode,
            ipv6=network.ipv6,
            containers=tuple(network.containers),
        )

    def create(self, name: str, options: Sequence[str]) -> None:
        if name in self.networks:
            raise NetworkCommandFailed(f"network with name {name} already exists")
        gateway_mode = _option_value(options, _GATEWAY_MODE)
        if gateway_mode == "isolated" and self.rejects_isolated is not None:
            raise NetworkCommandFailed(self.rejects_isolated)
        if self.ignores_isolated:
            gateway_mode = None
        self.networks[name] = FakeNetwork(
            labelled=_flag_value(options, "--label") == LABEL,
            internal="--internal" in options,
            gateway_mode=gateway_mode,
            ipv6=self.enables_ipv6,
        )

    def remove(self, name: str) -> None:
        network = self.networks.get(name)
        if network is None:
            raise NetworkCommandFailed(f"network {name} not found")
        if network.containers:
            raise NetworkCommandFailed(f"error while removing network: {name} has active endpoints")
        del self.networks[name]

    def remove_containers(self, names: Sequence[str]) -> None:
        for network in self.networks.values():
            network.containers = [name for name in network.containers if name not in names]


def _flag_value(options: Sequence[str], flag: str) -> str | None:
    for index, option in enumerate(options[:-1]):
        if option == flag:
            return options[index + 1]
    return None


def _option_value(options: Sequence[str], key: str) -> str | None:
    for index, option in enumerate(options[:-1]):
        if option == "-o" and options[index + 1].startswith(f"{key}="):
            return options[index + 1].split("=", 1)[1]
    return None
