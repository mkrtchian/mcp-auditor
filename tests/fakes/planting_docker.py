"""`FakePlantingDocker` is stateful: it keeps the networks, holders, sentinels and host files it
is told to make until they are removed, and refuses, as Docker does, to remove a network a
container is still attached to, so a test reads the state left after setup, teardown or a
failed setup rather than the order of the calls.
"""

import itertools
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlsplit

from evals.cve_planting_base import ImageAccounts

IMAGE_PASSWD = (
    "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
)
IMAGE_GROUP = "root:x:0:\nnobody:x:65534:\n"
# Names Docker writes into every container's /etc/hosts as the container itself.
_OWN_LOOPBACK_NAMES = ("ip6-localhost", "ip6-loopback")


@dataclass
class HostFile:
    content: str
    mode: int


@dataclass
class FakePlantingDocker:
    accounts: ImageAccounts = field(
        default_factory=lambda: ImageAccounts(IMAGE_PASSWD, IMAGE_GROUP)
    )
    fail: Mapping[str, int] = field(default_factory=dict[str, int])
    fail_errors: Mapping[str, Exception] = field(default_factory=dict[str, Exception])
    fail_teardown: frozenset[str] = frozenset()
    dead_sentinels: frozenset[str] = frozenset()  # keyed by the alias, else the BIND_ADDR
    host_files: dict[str, HostFile] = field(default_factory=dict[str, HostFile])
    networks: set[str] = field(default_factory=set[str])
    holders: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    sentinels: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    address_setups: list[list[str]] = field(default_factory=list[list[str]])

    def __post_init__(self) -> None:
        self._fail = dict(self.fail)
        self._attached: dict[str, str] = {}
        self._counter = 0

    def image_accounts(self, image_tag: str) -> ImageAccounts:
        self._maybe_fail("image_accounts")
        return self.accounts

    def write_host_file(self, content: str, mode: int) -> str:
        self._maybe_fail("write_host_file", OSError("cannot write host file"))
        path = self._fresh("hostfile")
        self.host_files[path] = HostFile(content, mode)
        return path

    def remove_host_file(self, path: str) -> None:
        self._maybe_fail_teardown("remove_host_file")
        self.host_files.pop(path, None)

    def create_network(self) -> str:
        self._maybe_fail("create_network")
        name = self._fresh("network")
        self.networks.add(name)
        return name

    def remove_network(self, name: str) -> None:
        self._maybe_fail_teardown("remove_network")
        if name in self._attached.values():
            raise RuntimeError(f"network {name} still has a container attached")
        self.networks.discard(name)

    def start_holder(self, run_args: Sequence[str]) -> str:
        return self._start("holder", self.holders, run_args)

    def remove_holder(self, name: str) -> None:
        self._maybe_fail_teardown("remove_holder")
        self.holders.pop(name, None)
        self._attached.pop(name, None)

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        return self._start("sentinel", self.sentinels, run_args)

    def remove_sentinel(self, name: str) -> None:
        self._maybe_fail_teardown("remove_sentinel")
        self.sentinels.pop(name, None)
        self._attached.pop(name, None)

    def probe_endpoint(self, target_args: Sequence[str], url: str) -> str | None:
        host = (urlsplit(url).hostname or "").lower()
        if host in _OWN_LOOPBACK_NAMES or self._unresolved(target_args, host):
            return None
        sentinel = self._reached(target_args, host)
        return None if sentinel is None else _env_value(sentinel, "FLAG")

    def _unresolved(self, target_args: Sequence[str], host: str) -> bool:
        if _is_ipv4(host):
            return False
        mounted = [mount.split(":")[1] for mount in _all_after(target_args, "-v")]
        hosts_shadowed = _shadows(mounted, "/etc/hosts")
        resolv_shadowed = _shadows(mounted, "/etc/resolv.conf")
        if host == "localhost":
            # On a launch with a network Docker's embedded DNS still answers localhost through
            # the host's resolver, which this fake models as answering.
            return hosts_shadowed and (resolv_shadowed or not self._has_network(target_args))
        if host in self._added_names(target_args):
            return hosts_shadowed
        return resolv_shadowed

    def _has_network(self, target_args: Sequence[str]) -> bool:
        network = _first_after(target_args, "--network") or "none"
        if network.startswith("container:"):
            network = _first_after(self._holder_of(target_args), "--network") or "none"
        return network != "none"

    def _added_names(self, target_args: Sequence[str]) -> set[str]:
        entries = _all_after(self._holder_of(target_args), "--add-host")
        return {entry.partition(":")[0].lower() for entry in entries}

    def _holder_of(self, target_args: Sequence[str]) -> list[str]:
        network = _first_after(target_args, "--network") or ""
        return self.holders.get(network.removeprefix("container:"), [])

    def _reached(self, target_args: Sequence[str], host: str) -> list[str] | None:
        network = _first_after(target_args, "--network") or "none"
        if network.startswith("container:"):
            bound = self._bound_sentinel(network, self._address_in(target_args, host))
            if bound is not None:
                return bound
            network = _first_after(self._holder_of(target_args), "--network") or "none"
        return self._aliased_sentinel(network, host)

    def _address_in(self, target_args: Sequence[str], host: str) -> str | None:
        # The order a joined namespace resolves a name in: a literal, Docker's own localhost
        # line, then the holder's --add-host lines, all case-insensitively.
        if _is_ipv4(host):
            return host
        if host == "localhost":
            return "127.0.0.1"
        for entry in _all_after(self._holder_of(target_args), "--add-host"):
            name, _, address = entry.partition(":")
            if name.lower() == host:
                return address
        return None

    def _bound_sentinel(self, network: str, address: str | None) -> list[str] | None:
        if address is None or address in self.dead_sentinels:
            return None
        for run_args in self.sentinels.values():
            if (
                _first_after(run_args, "--network") == network
                and _env_value(run_args, "BIND_ADDR") == address
            ):
                return run_args
        return None

    def _aliased_sentinel(self, network: str, host: str) -> list[str] | None:
        for run_args in self.sentinels.values():
            alias = _first_after(run_args, "--network-alias")
            if (
                alias is not None
                and alias not in self.dead_sentinels
                and _first_after(run_args, "--network") == network
                and alias.lower() == host
            ):
                return run_args
        return None

    def run_address_setup(self, run_args: Sequence[str]) -> None:
        self._maybe_fail("run_address_setup")
        self.address_setups.append(list(run_args))

    def _start(self, kind: str, registry: dict[str, list[str]], run_args: Sequence[str]) -> str:
        self._maybe_fail(f"start_{kind}")
        name = self._fresh(kind)
        registry[name] = list(run_args)
        attached = _attached_network(run_args)
        if attached is not None:
            self._attached[name] = attached
        return name

    def _fresh(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def _maybe_fail(self, operation: str, error: Exception | None = None) -> None:
        remaining = self._fail.get(operation)
        if remaining is None:
            return
        if remaining > 0:
            self._fail[operation] = remaining - 1
            return
        raise (
            self.fail_errors.get(operation)
            or error
            or subprocess.CalledProcessError(1, ["docker", operation])
        )

    def _maybe_fail_teardown(self, operation: str) -> None:
        if operation in self.fail_teardown:
            raise RuntimeError(f"teardown {operation} failed")


def _attached_network(run_args: Sequence[str]) -> str | None:
    for flag, value in itertools.pairwise(run_args):
        if flag == "--network" and not value.startswith("container:"):
            return value
    return None


def _env_value(run_args: Sequence[str], name: str) -> str | None:
    prefix = f"{name}="
    return next((arg[len(prefix) :] for arg in run_args if arg.startswith(prefix)), None)


def _first_after(run_args: Sequence[str], flag: str) -> str | None:
    return next(iter(_all_after(run_args, flag)), None)


def _all_after(run_args: Sequence[str], flag: str) -> list[str]:
    return [value for option, value in itertools.pairwise(run_args) if option == flag]


def _shadows(mounted: Sequence[str], path: str) -> bool:
    return any(path == target or path.startswith(f"{target.rstrip('/')}/") for target in mounted)


def _is_ipv4(host: str) -> bool:
    try:
        IPv4Address(host)
    except AddressValueError:
        return False
    return True
