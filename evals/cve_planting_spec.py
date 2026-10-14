"""The pure planting spec: one `Place` list, one planting host, one nonce per location.

`planting_spec` dispatches each place to a small per-kind helper that records its
container-side intent and draws its nonce from the injected `NonceSource`. It refuses a
place a launch cannot hold with a `ValueError` naming the entry id and the property, never
the value, so a caller can validate a kept list without reading a coordinate. No coordinate
value is hard-coded: the generic placeholder a `<segment>` resolves to is a harness constant,
fingerprinted here, and the endpoint bind-address resolution lives in `cve_endpoint_address`.
"""

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

from evals.cve_endpoint_address import claim_bind_address, endpoint_bind_address
from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting_base import (
    AccountIntent,
    EnvIntent,
    FileIntent,
    LayoutNode,
    NonceSource,
    PlantingHost,
    PlantingSpec,
    SentinelIntent,
    SymbolicUser,
)

# The home of the account every launch runs as (matching the user arguments), the uid and
# gid an `account` place runs under (high, so no stock image names them), and the placeholder
# a `<segment>` resolves to. The endpoint bind-address constants live in the sibling module.
_HOME = "/tmp"
_ACCOUNT_UID = 60123
_ACCOUNT_GID = 60123
_PLACEHOLDER = "mcpaudit-placeholder"
_ACCOUNT_RESERVED_PATHS = ("/etc/passwd", "/etc/group")  # the mounts an account place adds
# A git_remote_url nonce is planted in the userinfo of a remote URL, so it must carry no byte
# that would end or split the userinfo. The production token (MCPAUDIT-<hex>) is unreserved.
URL_SAFE_USERINFO = re.compile(r"[A-Za-z0-9._~-]+")


def planting_spec(
    to_plant: Sequence[Place], host: PlantingHost, nonces: NonceSource
) -> PlantingSpec:
    draft = _SpecDraft(host)
    for place in to_plant:
        _PLANTERS[place.kind](place, host, nonces, draft)
    return draft.finish(to_plant)


def served_file(path: str) -> str:
    """The file under the doc root busybox `httpd` maps a request for `path` to."""
    decoded = unquote(path.partition("#")[0].partition("?")[0])
    return f"{decoded}index.html" if decoded.endswith("/") else decoded


def request_target(path: str) -> str:
    """What a client puts on the request line for `path`: no fragment, unsafe bytes escaped."""
    return quote(path.partition("#")[0], safe="/?=&;:@!$'()*+,%")


@dataclass
class _SpecDraft:
    host: PlantingHost
    files: list[tuple[str, FileIntent]] = field(default_factory=list[tuple[str, FileIntent]])
    env: list[EnvIntent] = field(default_factory=list[EnvIntent])
    account: AccountIntent | None = None
    hostname: str | None = None
    sentinels: list[SentinelIntent] = field(default_factory=list[SentinelIntent])
    layout: list[LayoutNode] = field(default_factory=list[LayoutNode])
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
            files=tuple(intent for _, intent in self.files),
            env=tuple(self.env),
            account=self.account,
            hostname=self.hostname,
            sentinels=tuple(self.sentinels),
            address_setups=tuple(self.address_setups),
            host_entries=tuple(self.host_entries),
            needs_network=self.host.has_network,
            needs_holder=any(sentinel.bind_address is not None for sentinel in self.sentinels),
            unplaceable=self.unplaceable,
            layout=tuple(self.layout),
        )

    def _reject_account_mounts(self) -> None:
        # Order-independent: an account place may follow a colliding file place in the list.
        if self.account is None:
            return
        for entry_id, intent in self.files:
            path = intent.container_path
            if any(_overlaps(path, reserved) for reserved in _ACCOUNT_RESERVED_PATHS):
                raise ValueError(f"{entry_id}: a file path over the account passwd or group mount")


def _plant_file(place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft) -> None:
    content = nonces.token()
    draft.nonces[place.id] = content
    for raw in _coordinate_paths(place.coordinates):
        container_path = resolve_container_path(raw, host.working_directory)
        _reject_overlap(place.id, container_path, draft)
        draft.files.append((place.id, FileIntent(container_path, content)))


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
    path = _require(place.coordinates.path)
    _reject_unservable_path(place.id, path)
    endpoint_host = _require(place.coordinates.host)
    if endpoint_host in draft.endpoint_hosts:
        raise ValueError(f"{place.id}: a second http_endpoint place on the same host")
    draft.endpoint_hosts.add(endpoint_host)
    content = nonces.token()
    bind_address = endpoint_bind_address(place.id, endpoint_host, host, draft)
    claim_bind_address(place.id, bind_address, draft)
    draft.nonces[place.id] = content
    draft.sentinels.append(
        SentinelIntent(
            host=endpoint_host,
            path=path,
            served_file=served_file(path),
            request_target=request_target(path),
            content=content,
            bind_address=bind_address,
        )
    )


def _reject_unservable_path(entry_id: str, path: str) -> None:
    if _unservable(path):
        raise ValueError(f"{entry_id}: an http_endpoint path the sentinel cannot serve")


def _unservable(path: str) -> bool:
    # A NUL crashes the sentinel's launch, a climb writes the nonce outside the doc root, and
    # busybox `httpd` answers an encoded slash with 404.
    served = served_file(path)
    raw = path.partition("#")[0].partition("?")[0]
    return "\0" in served or _climbs_above_root(served) or "%2f" in raw.lower()


def _climbs_above_root(served: str) -> bool:
    depth = 0
    for segment in served.split("/"):
        if segment == "..":
            depth -= 1
        elif segment not in ("", "."):
            depth += 1
        if depth < 0:
            return True
    return False


def _plant_unplaceable(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    draft.unplaceable += 1


def _plant_git_remote_url(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    content = nonces.token()
    if URL_SAFE_USERINFO.fullmatch(content) is None:
        raise ValueError(f"{place.id}: a git_remote_url nonce that is not URL-safe in a userinfo")
    _record_layout_node(place, content, draft)


def _plant_git_history(
    place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft
) -> None:
    _record_layout_node(place, nonces.token(), draft)


def _plant_dotenv(place: Place, host: PlantingHost, nonces: NonceSource, draft: _SpecDraft) -> None:
    _record_layout_node(place, nonces.token(), draft)


def _record_layout_node(place: Place, content: str, draft: _SpecDraft) -> None:
    anchor = _require(place.coordinates.anchor)
    relpath = _require(place.coordinates.relpath)
    draft.nonces[place.id] = content
    draft.layout.append(LayoutNode(anchor, relpath, content))


_PLANTERS = {
    PlantKind.FILE: _plant_file,
    PlantKind.ENV: _plant_env,
    PlantKind.ACCOUNT: _plant_account,
    PlantKind.HOSTNAME: _plant_hostname,
    PlantKind.HTTP_ENDPOINT: _plant_http_endpoint,
    PlantKind.UNPLACEABLE: _plant_unplaceable,
    PlantKind.GIT_REMOTE_URL: _plant_git_remote_url,
    PlantKind.GIT_HISTORY: _plant_git_history,
    PlantKind.DOTENV: _plant_dotenv,
}


def _coordinate_paths(coordinates: Coordinates) -> tuple[str, ...]:
    if coordinates.paths is not None:
        return coordinates.paths
    return (_require(coordinates.path),)


def resolve_container_path(path: str, working_directory: str = "/") -> str:
    """The container path a coordinate mounts at. Shared with the kubernetes exploit so the
    planted path and the swept path cannot drift. A command-execution coordinate is absolute or
    `$HOME`-rooted, so the exploit needs no working directory; the planter passes the host's."""
    segments = [_PLACEHOLDER if _is_placeholder(part) else part for part in path.split("/")]
    resolved = "/".join(segments)
    if resolved.startswith("~/"):
        absolute = f"{_HOME}/{resolved[2:]}"
    elif resolved.startswith("$HOME/"):
        absolute = f"{_HOME}/{resolved[len('$HOME/') :]}"
    elif resolved.startswith("/"):
        absolute = resolved
    else:
        absolute = f"{working_directory}/{resolved}"
    # normpath preserves exactly two leading slashes (POSIX), so collapse the run first: a
    # coordinate `//a/b` means the same mount as `/a/b` and must read as equal to it.
    return posixpath.normpath("/" + absolute.lstrip("/"))


def _is_placeholder(segment: str) -> bool:
    return segment.startswith("<") and segment.endswith(">")


def _reject_overlap(entry_id: str, path: str, draft: _SpecDraft) -> None:
    for _, existing in draft.files:
        if _overlaps(path, existing.container_path):
            raise ValueError(f"{entry_id}: a file path equal to or nested with another planted one")


def _overlaps(path: str, other: str) -> bool:
    return path == other or path.startswith(f"{other}/") or other.startswith(f"{path}/")


def _require[T](value: T | None) -> T:
    if value is None:  # the loader guarantees the coordinate key its kind requires
        raise ValueError("a coordinate is missing a key its kind requires")
    return value
