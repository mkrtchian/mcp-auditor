"""Closed fixture networks: internal, with an isolated IPv4 gateway and IPv6 off.

`--internal` alone keeps an address on the host's bridge device, which a container on the
network reaches. With the gateway mode `isolated` (Docker Engine 28.0 or later, internal networks
only) the bridge carries no host address, so a container finds no route to the host, its local
network or the Internet. An IPv6 gateway would reopen the host, hence IPv6 off.

Every creation inspects what it made, since a daemon could accept the option and ignore it, and
never falls back to an open network. A persistent network of our name left open by an older run
is recreated closed, its containers removed first by `docker rm -f -v`, their anonymous volumes
with them. One with no `mcp-auditor-cve` label is not ours and is never touched.

Clean: copied into the calibration kits and admission dossiers, it imports nothing from
`mcp_auditor`.
"""

import json
import logging
import secrets
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from evals.cve.planting_base import LABEL

logger = logging.getLogger(__name__)

_GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
CLOSED_OPTIONS = ("--internal", "-o", f"{_GATEWAY_MODE}=isolated")
_ALREADY_EXISTS = "already exists"


class ClosedNetworkUnsupported(RuntimeError): ...


class ForeignNetwork(RuntimeError): ...


class NetworkCommandFailed(RuntimeError):
    """A `docker network` command the daemon refused, carrying the daemon's message."""


@dataclass(frozen=True)
class NetworkFacts:
    labelled: bool
    internal: bool
    gateway_mode: str | None
    ipv6: bool
    containers: tuple[str, ...]


class NetworkDocker(Protocol):
    def inspect(self, name: str) -> NetworkFacts | None: ...
    def create(self, name: str, options: Sequence[str]) -> None: ...
    def remove(self, name: str) -> None: ...
    def remove_containers(self, names: Sequence[str]) -> None: ...


def is_closed(facts: NetworkFacts) -> bool:
    return facts.internal and facts.gateway_mode == "isolated" and not facts.ipv6


def network_facts(inspect_json: str) -> NetworkFacts:
    network = cast(dict[str, Any], json.loads(inspect_json))
    options = cast(dict[str, str], network.get("Options") or {})
    labels = cast(dict[str, str], network.get("Labels") or {})
    containers = cast(dict[str, dict[str, str]], network.get("Containers") or {})
    return NetworkFacts(
        labelled=LABEL in labels,
        internal=bool(network.get("Internal")),
        gateway_mode=options.get(_GATEWAY_MODE),
        ipv6=bool(network.get("EnableIPv6")),
        containers=tuple(container["Name"] for container in containers.values()),
    )


class _DockerNetworks:
    def inspect(self, name: str) -> NetworkFacts | None:
        result = _docker("network", "inspect", "-f", "{{json .}}", name)
        if result.returncode != 0:
            if "not found" in result.stderr:
                return None
            raise NetworkCommandFailed(result.stderr.strip())
        return network_facts(result.stdout)

    def create(self, name: str, options: Sequence[str]) -> None:
        _checked("network", "create", *options, name)

    def remove(self, name: str) -> None:
        _checked("network", "rm", name)

    def remove_containers(self, names: Sequence[str]) -> None:
        if names:
            _checked("rm", "-f", "-v", *names)


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *arguments], check=False, capture_output=True, text=True)


def _checked(*arguments: str) -> None:
    result = _docker(*arguments)
    if result.returncode != 0:
        raise NetworkCommandFailed(result.stderr.strip())


DOCKER_NETWORKS: NetworkDocker = _DockerNetworks()


def create_closed_network(
    name: str, *options: str, docker: NetworkDocker = DOCKER_NETWORKS
) -> None:
    try:
        docker.create(name, ("--label", LABEL, *CLOSED_OPTIONS, *options))
    except NetworkCommandFailed as error:
        if _ALREADY_EXISTS in str(error):
            raise
        raise ClosedNetworkUnsupported(_unsupported(str(error))) from error
    facts = docker.inspect(name)
    if facts is None or not is_closed(facts):
        if facts is not None:
            docker.remove(name)
        raise ClosedNetworkUnsupported(_unsupported(f"{name} was created open: {facts}"))


def _unsupported(daemon_message: str) -> str:
    return (
        "the Docker daemon cannot create a closed network (internal, gateway mode isolated, "
        f"IPv6 off), Docker Engine 28.0 or later is required: {daemon_message}"
    )


def ensure_closed_network(
    name: str, *options: str, docker: NetworkDocker = DOCKER_NETWORKS
) -> None:
    with _lock_for(name):
        facts = docker.inspect(name)
        if facts is None:
            try:
                create_closed_network(name, *options, docker=docker)
                return
            except NetworkCommandFailed:
                # Another process created it between the inspect and the create.
                facts = docker.inspect(name)
                if facts is None:
                    raise
        _settle(name, facts, options, docker)


def _settle(name: str, facts: NetworkFacts, options: Sequence[str], docker: NetworkDocker) -> None:
    if not facts.labelled:
        raise ForeignNetwork(f"network {name} exists without the {LABEL} label: not ours")
    if is_closed(facts):
        return
    for container in facts.containers:
        logger.warning("removing %s to recreate the open network %s closed", container, name)
    docker.remove_containers(facts.containers)
    docker.remove(name)
    create_closed_network(name, *options, docker=docker)


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(name: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(name, threading.Lock())


def check_closed_network_support(docker: NetworkDocker = DOCKER_NETWORKS) -> None:
    name = f"{LABEL}-closed-check-{secrets.token_hex(6)}"
    try:
        create_closed_network(name, docker=docker)
    finally:
        if docker.inspect(name) is not None:
            docker.remove(name)
