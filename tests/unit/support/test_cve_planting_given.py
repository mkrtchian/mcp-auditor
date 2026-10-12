"""Fictional places and the two planting fakes. No real coordinate appears here: every path,
host and name is invented, and the IP literals are drawn from the documentation ranges, so
nothing can be mistaken for the imported data.

`FakePlantingDocker` is stateful: it keeps the networks, holders, sentinels and host files it
is told to make until they are removed, and refuses, as Docker does, to remove a network a
container is still attached to, so a test reads the state left after setup, teardown or a
failed setup rather than the order of the calls.
"""

import itertools
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import (
    NonceSource,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from evals.cve_planting_base import ImageAccounts

IMAGE_PASSWD = (
    "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
)
IMAGE_GROUP = "root:x:0:\nnobody:x:65534:\n"


def spec_of(
    places: list[Place], host: PlantingHost | None = None, nonces: NonceSource | None = None
) -> PlantingSpec:
    return planting_spec(places, host or unprivileged_host(), nonces or FakeNonces())


def unprivileged_host(
    *, has_network: bool = False, working_directory: str = "/srv/fictional"
) -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, working_directory, has_network)


def host_user_host(*, has_network: bool = False, working_directory: str = "/work") -> PlantingHost:
    return PlantingHost(SymbolicUser.HOST, working_directory, has_network)


def file_place(
    entry_id: str = "file-1",
    *,
    path: str = "/etc/fictional/secret",
    paths: Sequence[str] | None = None,
) -> Place:
    coordinates = Coordinates(
        PlantKind.FILE,
        path=None if paths is not None else path,
        paths=tuple(paths) if paths is not None else None,
    )
    return _place(entry_id, PlantKind.FILE, coordinates)


def env_place(entry_id: str = "env-1", *, name: str = "FICTIONAL_TOKEN") -> Place:
    return _place(entry_id, PlantKind.ENV, Coordinates(PlantKind.ENV, name=name))


def account_place(entry_id: str = "account-1") -> Place:
    return _place(entry_id, PlantKind.ACCOUNT, Coordinates(PlantKind.ACCOUNT))


def hostname_place(entry_id: str = "hostname-1") -> Place:
    return _place(entry_id, PlantKind.HOSTNAME, Coordinates(PlantKind.HOSTNAME))


def endpoint_place(
    entry_id: str = "endpoint-1",
    *,
    host: str = "fictional-service",
    path: str = "/fictional/secret",
) -> Place:
    return _place(
        entry_id,
        PlantKind.HTTP_ENDPOINT,
        Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path),
    )


def unplaceable_place(entry_id: str = "unplaceable-1") -> Place:
    return _place(entry_id, PlantKind.UNPLACEABLE, Coordinates(PlantKind.UNPLACEABLE))


def _place(entry_id: str, kind: PlantKind, coordinates: Coordinates) -> Place:
    return Place(
        id=entry_id,
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=coordinates,
    )


class FakeNonces:
    """A deterministic source: each draw is distinct, so two locations never share a value."""

    def __init__(self) -> None:
        self._tokens = 0
        self._accounts = 0

    def token(self) -> str:
        self._tokens += 1
        return f"nonce-{self._tokens}"

    def account_name(self) -> str:
        self._accounts += 1
        return f"acct-{self._accounts}"


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

    def sentinel_body(self, name: str, host: str, request_target: str) -> str | None:
        run_args = self.sentinels.get(name)
        if run_args is None or not self._answers(run_args, host):
            return None
        return _env_value(run_args, "FLAG")

    def _answers(self, run_args: Sequence[str], host: str) -> bool:
        alias = _first_after(run_args, "--network-alias")
        if alias is not None:
            return alias not in self.dead_sentinels and host.lower() == alias.lower()
        bind_address = _env_value(run_args, "BIND_ADDR")
        if bind_address is None or bind_address in self.dead_sentinels:
            return False
        return self._resolved(run_args, host) == bind_address

    def _resolved(self, run_args: Sequence[str], host: str) -> str | None:
        # The order a joined namespace resolves a name in: a literal, Docker's own localhost
        # line, then the holder's --add-host lines, all case-insensitively.
        if _is_ipv4(host):
            return host
        if host.lower() == "localhost":
            return "127.0.0.1"
        holder = (_first_after(run_args, "--network") or "").removeprefix("container:")
        for entry in _all_after(self.holders.get(holder, []), "--add-host"):
            name, _, address = entry.partition(":")
            if name.lower() == host.lower():
                return address
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


def only(registry: dict[str, list[str]]) -> str:
    assert len(registry) == 1
    return next(iter(registry))


def only_list(items: list[list[str]]) -> list[str]:
    assert len(items) == 1
    return items[0]


def following(args: list[str] | tuple[str, ...], flag: str, *, prefix: str | None = None) -> str:
    args = list(args)
    if prefix is not None:
        return next(value for value in args if value.startswith(prefix))
    return args[args.index(flag) + 1]


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


def _is_ipv4(host: str) -> bool:
    try:
        IPv4Address(host)
    except AddressValueError:
        return False
    return True
