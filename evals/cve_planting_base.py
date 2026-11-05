"""Planting vocabulary: the value objects, the ports and the container launch profile.

`PlantingSpec` is what `planting_spec` computes and `planted` carries out: container-side
intents only (a file and its content, an environment pair, an account entry, a hostname, a
sentinel serving a nonce, a stand-in `planted` loads for the host's `PublicNames`), never a
host path, a container or network name, or an argv.
`PlantedArgs` is the `docker run` arguments a planted launch takes. `PlantingDocker` and
`NonceSource` are the two injected ports. `RANDOM_NONCES` draws the production nonces.
`PlantingDocker` also hands the `/srv` layout over to the unprivileged account and removes it,
under `check_layout_outer`, the guard that keeps the removal on a layout's own directory.

`confinement_args` stays public so each builder carries the same container profile. The user
and network helpers stay public for `planted` to resolve the launch's host into arguments. A
builder no longer emits them itself, it takes them from the `PlantedArgs` planting yields.
"""

import logging
import os
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from evals.cve_places import LayoutAnchor, Place

logger = logging.getLogger(__name__)

LABEL = "mcp-auditor-cve"
SENTINEL_SERVICE = "sentinel"  # the sentinel's compose service, image_tag(SENTINEL_SERVICE)
SENTINEL_IMAGE = "mcp-auditor-cve-sentinel:local"
STAND_IN_SERVICE = "stand-in"
STAND_IN_IMAGE = "mcp-auditor-cve-stand-in:local"
UNPRIVILEGED_UID = 65534
UNPRIVILEGED_GID = 65534
LAYOUT_PREFIX = "mcp-auditor-layout-"  # the outer directory holding a layout, in the temp dir
LAYOUT_ROOT = "srv"  # the layout root's name inside its outer directory


class SymbolicUser(StrEnum):
    UNPRIVILEGED = "unprivileged"
    HOST = "host"


@dataclass(frozen=True)
class PublicNames:
    stand_ins: tuple[str, ...] = ()  # hosts served by a stand-in under their real name
    trust: tuple[str, ...] = ()  # env names pointed at the fixture authority
    ip_label_domains: tuple[str, ...] = ()  # wildcard-DNS domains answering a dashed IPv4 label


@dataclass(frozen=True)
class PlantingHost:
    user: SymbolicUser
    working_directory: str
    has_network: bool
    public_names: PublicNames = PublicNames()


@dataclass(frozen=True)
class StandIn:
    host: str
    address: str  # the IPv4 the real name resolved to at capture
    capture: str  # the capture file's text, replayed verbatim
    certificate: str  # the leaf for host, from the fixture authority
    key: str
    authority: str  # the fixture authority's certificate


class NonceSource(Protocol):
    def token(self) -> str: ...
    def account_name(self) -> str: ...


class _RandomNonces:
    def token(self) -> str:
        return f"MCPAUDIT-{secrets.token_hex(16)}"

    def account_name(self) -> str:
        return f"mcpaudit-{secrets.token_hex(11)}"


RANDOM_NONCES: NonceSource = _RandomNonces()


class PlantingFailed(Exception):
    """A planting setup step failed. Its undo has run and the launch is skipped."""


@dataclass(frozen=True)
class ImageAccounts:
    passwd: str
    group: str


@dataclass(frozen=True)
class FileIntent:
    container_path: str
    content: str


@dataclass(frozen=True)
class EnvIntent:
    name: str
    content: str


@dataclass(frozen=True)
class AccountIntent:
    name: str
    uid: int
    gid: int
    home: str


@dataclass(frozen=True)
class SentinelIntent:
    host: str
    path: str  # the coordinate, for messages
    served_file: str
    request_target: str
    content: str
    bind_address: str | None  # None => a DNS alias on the bridge, else bound inside a holder


@dataclass(frozen=True)
class LayoutNode:
    anchor: LayoutAnchor
    relpath: str
    content: str  # the nonce for a kept node, built into the frozen /srv tree


@dataclass(frozen=True)
class PlantingSpec:
    host: PlantingHost
    places: tuple[Place, ...]
    nonces: Mapping[str, str]
    files: tuple[FileIntent, ...]
    env: tuple[EnvIntent, ...]
    account: AccountIntent | None
    hostname: str | None
    sentinels: tuple[SentinelIntent, ...]
    address_setups: tuple[str, ...]
    host_entries: tuple[tuple[str, str], ...]
    needs_network: bool
    needs_holder: bool
    unplaceable: int
    layout: tuple[LayoutNode, ...] = ()
    stand_ins: tuple[StandIn, ...] = ()  # loaded by `planted`, never by `planting_spec`


@dataclass(frozen=True)
class PlantedArgs:
    user: tuple[str, ...]
    working_directory: tuple[str, ...]
    env: tuple[str, ...]
    mounts: tuple[str, ...]
    hostname: tuple[str, ...]
    network: tuple[str, ...]

    def run_args(self) -> list[str]:
        return [
            *self.user,
            *self.working_directory,
            *self.env,
            *self.mounts,
            *self.hostname,
            *self.network,
        ]


class PlantingDocker(Protocol):
    def image_accounts(self, image_tag: str) -> ImageAccounts: ...
    def write_host_file(self, content: str, mode: int) -> str: ...
    def remove_host_file(self, path: str) -> None: ...
    def create_network(self) -> str: ...
    def remove_network(self, name: str) -> None: ...
    def start_holder(self, run_args: Sequence[str]) -> str: ...
    def remove_holder(self, name: str) -> None: ...
    def start_sentinel(self, run_args: Sequence[str]) -> str: ...
    def remove_sentinel(self, name: str) -> None: ...
    def probe_endpoint(self, target_args: Sequence[str], url: str) -> str | None: ...
    def run_address_setup(self, run_args: Sequence[str]) -> None: ...
    def start_stand_in(self, run_args: Sequence[str]) -> str: ...
    def remove_stand_in(self, name: str, host: str) -> None: ...
    def probe_listener(self, target_args: Sequence[str], host: str, port: int) -> bool: ...
    def hand_over_layout(self, root: str) -> None: ...
    def remove_layout(self, outer: str) -> None: ...


def check_layout_outer(outer: str) -> None:
    # The removal runs as a root able to delete anything it is pointed at, so it is pointed only
    # at a layout's own outer directory, never at a broader host directory.
    path = Path(outer).resolve()
    if not (
        outer
        and path.is_dir()
        and path.parent == Path(tempfile.gettempdir()).resolve()
        and path.name.startswith(LAYOUT_PREFIX)
    ):
        raise PlantingFailed(f"refusing to remove {outer!r}: not a layout's outer directory")


def quiet(action: object, *args: object) -> None:
    try:
        action(*args)  # type: ignore[operator]
    except Exception as error:
        logger.warning("planting teardown failed: %s", error)


def confinement_args() -> list[str]:
    # The process bound is about twenty times what these servers run at rest, and it fails
    # gracefully: fork returns EAGAIN and the server survives, so the bound cannot turn a run
    # into a false miss the way a memory kill would.
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256"]


def no_network_args() -> list[str]:
    return own_network_args("none")


def own_network_args(network: str) -> list[str]:
    # For a container with its own network stack. A container that joins a holder
    # (`--network container:<holder>`) takes no resolver option, it reads the holder's
    # resolv.conf, and Docker ignores `--dns-search` there and refuses `--dns`.
    return ["--network", network, *resolver_args()]


def resolver_args() -> list[str]:
    # `.` sets no search domain, so a container does not inherit the host's.
    return ["--dns-search", "."]


def unprivileged_user_args() -> list[str]:
    # An image without a USER runs as root inside the container. Behind an empty capability
    # bounding set that root is disarmed, but an escape that lands as nobody on the host is
    # still better than one that lands as root.
    return ["--user", f"{UNPRIVILEGED_UID}:{UNPRIVILEGED_GID}", "-e", "HOME=/tmp"]


def host_user_args() -> list[str]:
    # The host user, kept for the holdout fixtures and nuisance hosts that still run as it until
    # their campaign rewrites them. HOME is set because git needs a writable home for a uid
    # absent from the image's passwd file.
    return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]
