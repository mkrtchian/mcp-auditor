"""The pure planting spec: one `Place` list, one planting host, one nonce per location.

`planting_spec` dispatches each place to a small per-kind helper that records its
container-side intent and draws its nonce from the injected `NonceSource`. It refuses a
place a launch cannot hold with a `ValueError` naming the entry id and the property, never
the value, so a caller can validate a kept list without reading a coordinate. No coordinate
value is hard-coded: the generic placeholder a `<segment>` resolves to and the private block
a name host without a network is served on are harness constants, fingerprinted here.
"""

import posixpath
from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv4Network

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting_base import (
    AccountIntent,
    EnvIntent,
    FileIntent,
    NonceSource,
    PlantingHost,
    PlantingSpec,
    SentinelIntent,
    SymbolicUser,
)

# The home of the account every launch runs as (matching the user arguments), the uid and
# gid an `account` place runs under (high, so no stock image names them), the placeholder a
# `<segment>` resolves to, and the private /24 a name host without a network is served on:
# inside 10.0.0.0/8, outside Docker's default pools and outside 169.254.0.0/16.
_HOME = "/tmp"
_ACCOUNT_UID = 60123
_ACCOUNT_GID = 60123
_PLACEHOLDER = "mcpaudit-placeholder"
_ACCOUNT_RESERVED_PATHS = ("/etc/passwd", "/etc/group")  # the mounts an account place adds
RESERVED_NAME_BLOCK = IPv4Network("10.255.255.0/24")
_LOOPBACK = IPv4Network("127.0.0.0/8")
_NON_UNICAST_BLOCKS = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
)


def planting_spec(
    to_plant: Sequence[Place], host: PlantingHost, nonces: NonceSource
) -> PlantingSpec:
    draft = _SpecDraft(host)
    for place in to_plant:
        _PLANTERS[place.kind](place, host, nonces, draft)
    return draft.finish(to_plant)


@dataclass
class _SpecDraft:
    host: PlantingHost
    files: list[FileIntent] = field(default_factory=list[FileIntent])
    file_paths: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    env: list[EnvIntent] = field(default_factory=list[EnvIntent])
    account: AccountIntent | None = None
    hostname: str | None = None
    sentinels: list[SentinelIntent] = field(default_factory=list[SentinelIntent])
    address_setups: list[str] = field(default_factory=list[str])
    host_entries: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    endpoint_hosts: set[str] = field(default_factory=set[str])
    bind_addresses: set[str] = field(default_factory=set[str])
    env_names: set[str] = field(default_factory=set[str])
    nonces: dict[str, str] = field(default_factory=dict[str, str])
    unplaceable: int = 0
    reserved_index: int = 0

    def finish(self, to_plant: Sequence[Place]) -> PlantingSpec:
        self._reject_account_mounts()
        return PlantingSpec(
            host=self.host,
            places=tuple(place for place in to_plant if place.id in self.nonces),
            nonces=dict(self.nonces),
            files=tuple(self.files),
            env=tuple(self.env),
            account=self.account,
            hostname=self.hostname,
            sentinels=tuple(self.sentinels),
            address_setups=tuple(self.address_setups),
            host_entries=tuple(self.host_entries),
            needs_network=self.host.has_network,
            needs_holder=any(sentinel.bind_address is not None for sentinel in self.sentinels),
            unplaceable=self.unplaceable,
        )

    def _reject_account_mounts(self) -> None:
        # Order-independent: an account place may follow a colliding file place in the list.
        if self.account is None:
            return
        for entry_id, path in self.file_paths:
            if any(_overlaps(path, reserved) for reserved in _ACCOUNT_RESERVED_PATHS):
                raise ValueError(f"{entry_id}: a file path over the account passwd or group mount")


def _plant_file(place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft) -> None:
    content = nonces.token()
    draft.nonces[place.id] = content
    for raw in _coordinate_paths(place.coordinates):
        container_path = _resolve_container_path(raw, host)
        _reject_overlap(place.id, container_path, draft)
        draft.files.append(FileIntent(container_path, content))
        draft.file_paths.append((place.id, container_path))


def _plant_env(place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft) -> None:
    name = _require(place.coordinates.name)
    if name == "HOME":
        raise ValueError(f"{place.id}: an env place named HOME would move the planted home")
    if name in draft.env_names:
        raise ValueError(f"{place.id}: a second env place with the same name")
    draft.env_names.add(name)
    content = nonces.token()
    draft.nonces[place.id] = content
    draft.env.append(EnvIntent(name, content))


def _plant_account(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    if host.user is SymbolicUser.HOST:
        raise ValueError(f"{place.id}: an account place on a host-user launch")
    if draft.account is not None:
        raise ValueError(f"{place.id}: a second account place in one launch")
    name = nonces.account_name()
    draft.nonces[place.id] = name
    draft.account = AccountIntent(name, _ACCOUNT_UID, _ACCOUNT_GID, _HOME)


def _plant_hostname(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    if draft.hostname is not None:
        raise ValueError(f"{place.id}: a second hostname place in one launch")
    content = nonces.token()
    draft.nonces[place.id] = content
    draft.hostname = content


def _plant_http_endpoint(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    endpoint_host = _require(place.coordinates.host)
    if endpoint_host in draft.endpoint_hosts:
        raise ValueError(f"{place.id}: a second http_endpoint place on the same host")
    draft.endpoint_hosts.add(endpoint_host)
    content = nonces.token()
    bind_address = _endpoint_bind_address(place.id, endpoint_host, host, draft)
    if bind_address is not None:  # a holder-bound sentinel: two hosts can share one address
        if bind_address in draft.bind_addresses:
            raise ValueError(f"{place.id}: a second http_endpoint place on the same bind address")
        draft.bind_addresses.add(bind_address)
    draft.nonces[place.id] = content
    draft.sentinels.append(
        SentinelIntent(endpoint_host, _require(place.coordinates.path), content, bind_address)
    )


def _plant_unplaceable(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    draft.unplaceable += 1


_PLANTERS = {
    PlantKind.FILE: _plant_file,
    PlantKind.ENV: _plant_env,
    PlantKind.ACCOUNT: _plant_account,
    PlantKind.HOSTNAME: _plant_hostname,
    PlantKind.HTTP_ENDPOINT: _plant_http_endpoint,
    PlantKind.UNPLACEABLE: _plant_unplaceable,
}


def _endpoint_bind_address(
    entry_id: str, endpoint_host: str, host: PlantingHost, draft: _SpecDraft
) -> str | None:
    if endpoint_host == "localhost":
        return "127.0.0.1"  # a loopback name: served on the holder's lo, no address setup
    literal = _as_ipv4(endpoint_host)
    if literal is not None:
        return _literal_bind_address(entry_id, literal, draft)
    if host.has_network:
        return None  # a DNS name on a launch with a network: a bridge alias, no holder
    return _name_host_bind_address(endpoint_host, draft)


def _literal_bind_address(entry_id: str, literal: IPv4Address, draft: _SpecDraft) -> str:
    if literal in RESERVED_NAME_BLOCK:
        raise ValueError(f"{entry_id}: an http_endpoint IP literal inside the reserved block")
    if any(literal in block for block in _NON_UNICAST_BLOCKS):
        raise ValueError(f"{entry_id}: an http_endpoint IP literal is not a unicast host address")
    if literal not in _LOOPBACK:
        draft.address_setups.append(str(literal))
    return str(literal)


def _name_host_bind_address(endpoint_host: str, draft: _SpecDraft) -> str:
    draft.reserved_index += 1
    address = str(RESERVED_NAME_BLOCK.network_address + draft.reserved_index)
    draft.address_setups.append(address)
    draft.host_entries.append((endpoint_host, address))
    return address


def _coordinate_paths(coordinates: Coordinates) -> tuple[str, ...]:
    if coordinates.paths is not None:
        return coordinates.paths
    return (_require(coordinates.path),)


def _resolve_container_path(path: str, host: PlantingHost) -> str:
    segments = [_PLACEHOLDER if _is_placeholder(part) else part for part in path.split("/")]
    resolved = "/".join(segments)
    if resolved.startswith("~/"):
        absolute = f"{_HOME}/{resolved[2:]}"
    elif resolved.startswith("$HOME/"):
        absolute = f"{_HOME}/{resolved[len('$HOME/') :]}"
    elif resolved.startswith("/"):
        absolute = resolved
    else:
        absolute = f"{host.working_directory}/{resolved}"
    # normpath preserves exactly two leading slashes (POSIX), so collapse the run first: a
    # coordinate `//a/b` means the same mount as `/a/b` and must read as equal to it.
    return posixpath.normpath("/" + absolute.lstrip("/"))


def _is_placeholder(segment: str) -> bool:
    return segment.startswith("<") and segment.endswith(">")


def _reject_overlap(entry_id: str, path: str, draft: _SpecDraft) -> None:
    for existing in draft.files:
        if _overlaps(path, existing.container_path):
            raise ValueError(f"{entry_id}: a file path equal to or nested with another planted one")


def _overlaps(path: str, other: str) -> bool:
    return path == other or path.startswith(f"{other}/") or other.startswith(f"{path}/")


def _as_ipv4(host: str) -> IPv4Address | None:
    try:
        return IPv4Address(host)
    except AddressValueError:
        return None


def _require[T](value: T | None) -> T:
    if value is None:  # the loader guarantees the coordinate key its kind requires
        raise ValueError("a coordinate is missing a key its kind requires")
    return value
